//! This crate contains connectors for the Glock transaction graph.

pub mod claim_contest;
pub mod claim_payout;
pub mod contest_counterproof;
pub mod cpfp;
pub mod n_of_n;
pub mod p2a;
pub mod prelude;
pub mod timelocked;
pub mod unstaking_intent;

#[cfg(any(test, feature = "test_utils"))]
pub mod test_utils;

use bitcoin::{
    hashes::Hash,
    key::TapTweak,
    opcodes,
    psbt::Input,
    script,
    sighash::{Prevouts, SighashCache},
    taproot::{LeafVersion, TapLeafHash, TaprootSpendInfo},
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, TapNodeHash, TapSighashType,
    Transaction, TxOut,
};
use secp256k1::{schnorr, Keypair, Message, XOnlyPublicKey, SECP256K1};
use strata_bridge_primitives::scripts::{
    prelude::{
        create_key_spend_hash, create_script_spend_hash, create_taproot_addr, finalize_input,
        SpendPath,
    },
    taproot::TaprootTweak,
};
use strata_crypto::keys::constants::UNSPENDABLE_PUBLIC_KEY;

/// A Taproot connector output.
pub trait Connector {
    /// Names of available spending paths.
    type SpendPath: Copy;
    /// Witness data that is required to spend the connector.
    type Witness;

    /// Returns the network of the connector.
    fn network(&self) -> Network;

    /// Returns the internal key of the connector.
    ///
    /// The key will be unspendable for connectors without a key path spend.
    fn internal_key(&self) -> XOnlyPublicKey {
        *UNSPENDABLE_PUBLIC_KEY
    }

    /// Generates the vector of leaf scripts of the connector.
    ///
    /// The vector will be empty for connectors without script path spends.
    fn leaf_scripts(&self) -> Vec<ScriptBuf> {
        Vec::new()
    }

    /// Returns the value of the connector.
    fn value(&self) -> Amount;

    /// Converts the given spend path into a leaf index.
    ///
    /// This method returns `None` for a key-path spend.
    fn to_leaf_index(&self, spend_path: Self::SpendPath) -> Option<usize>;

    /// Returns an iterator over all `OP_CODESEPARATOR` positions in the leaf script
    /// at the given index.
    ///
    /// The iterator starts with the default position `u32::MAX`,
    /// followed by the position of each code separator in order.
    /// The iterator is never empty.
    ///
    /// # Panics
    ///
    /// This method panics if the leaf index is out of bounds.
    ///
    /// # See
    ///
    /// [BIP 342](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki#common-signature-message-extension).
    fn code_separator_positions(&self, leaf_index: usize) -> impl IntoIterator<Item = u32> {
        // NOTE: (@uncomputable)
        // The default position u32::MAX is included to facilitate signing.
        // Using the return value of code_separator_positions() for signing always works.
        // It generalizes nicely; we don't have to remind callers to include u32::MAX.
        let script = &self.leaf_scripts()[leaf_index];
        let mut positions = vec![u32::MAX];

        for (opcode_index, instruction) in script.instructions().enumerate() {
            if let Ok(script::Instruction::Op(opcodes::all::OP_CODESEPARATOR)) = instruction {
                // Cast safety: script will not be larger than u32::MAX
                positions.push(opcode_index as u32);
            }
        }

        positions
    }

    /// Generates the address of the connector.
    fn address(&self) -> Address {
        create_taproot_addr(
            &self.network(),
            SpendPath::Both {
                internal_key: self.internal_key(),
                scripts: self.leaf_scripts().as_slice(),
            },
        )
        .expect("tap tree is valid")
        .0
    }

    /// Generates the script pubkey of the connector.
    fn script_pubkey(&self) -> ScriptBuf {
        self.address().script_pubkey()
    }

    /// Generates the transaction output of the connector.
    fn tx_out(&self) -> TxOut {
        TxOut {
            value: self.value(),
            script_pubkey: self.address().script_pubkey(),
        }
    }

    /// Generates the taproot spend info of the connector.
    fn spend_info(&self) -> TaprootSpendInfo {
        // NOTE: (@uncomputable)
        // It seems wasteful to have almost the same function body as [`Connector::address`],
        // but in practice we only ever need one of the two: the address or the spend info.
        // We may want to reimplement `create_taproot_addr` to reduce code duplication.
        create_taproot_addr(
            &self.network(),
            SpendPath::Both {
                internal_key: self.internal_key(),
                scripts: self.leaf_scripts().as_slice(),
            },
        )
        .expect("tap tree is valid")
        .1
    }

    /// Returns the tap tweak that transforms the internal key into the output key.
    ///
    /// The tap tweak is equal to the merkle root of the tap tree.
    fn tweak(&self) -> Option<TapNodeHash> {
        self.spend_info().merkle_root()
    }

    /// Returns the sequence number for the given spend path.
    fn sequence(&self, _spend_path: Self::SpendPath) -> Sequence {
        // NOTE: (@uncomputable)
        // Since we have TRUC + full RBF, we don't need to enable RBF via the sequence number.
        // Since we don't use absolute locktime anywhere, we don't need to enable it either.
        Sequence::MAX
    }

    /// Computes the signing info of an input that spends the connector
    /// via the given spending path.
    fn get_signing_info(
        &self,
        cache: &mut SighashCache<&Transaction>,
        prevouts: Prevouts<'_, TxOut>,
        spend_path: Self::SpendPath,
        input_index: usize,
    ) -> SigningInfo {
        // NOTE: (@uncomputable)
        // All of our transactions use SIGHASH_ALL aka SIGHASH_DEFAULT.
        // There is no reason to make the sighash type variable.
        let sighash_type = TapSighashType::Default;
        let leaf_index = self.to_leaf_index(spend_path);
        let sighash = match leaf_index {
            None => create_key_spend_hash(cache, prevouts, sighash_type, input_index),
            Some(leaf_index) => {
                let leaf_script = &self.leaf_scripts()[leaf_index];
                create_script_spend_hash(cache, leaf_script, prevouts, sighash_type, input_index)
            }
        }
        .expect("should be able to compute the sighash");

        let tweak = if leaf_index.is_none() {
            TaprootTweak::Key {
                tweak: self.tweak(),
            }
        } else {
            TaprootTweak::Script
        };

        SigningInfo { sighash, tweak }
    }

    /// Returns an iterator over the sighashes for each code separator position.
    ///
    /// The signing key doesn't need to be tweaked, since this is a script-path spend.
    ///
    /// # Panics
    ///
    /// This method panics if the chosen spending path is a key-path spend.
    ///
    /// # Code separator positions
    ///
    /// Each `OP_CHECKSIG(VERIFY)` operation checks a signature based on a sighash.
    /// The sighash is computed based on the position of the last executed `OP_CODESEPARATOR`.
    ///
    /// - All `OP_CHECKSIG(VERIFY)` operations in front of the first `OP_CODESEPARATOR` use the
    ///   default position `u32::MAX`.
    /// - All `OP_CHECKSIG(VERIFY)` operations between the first and the second `OP_CODESEPARATOR`
    ///   use the position of the first `OP_CODESEPARATOR`.
    /// - ...
    /// - All `OP_CHECKSIG(VERIFY)` operations after the last `OP_CODESEPARATOR` use the position of
    ///   the last `OP_CODESEPARATOR`.
    ///
    /// # Choosing the right sighash
    ///
    /// When multiple `OP_CHECKSIG(VERIFY)` operations are between the same code separators,
    /// then they use the same sighash.
    ///
    /// In the following trivial example, `#1` and `#2` use the same sighash.
    ///
    /// ```text
    /// OP_CHECKSIGVERIFY #1
    /// OP_CHECKSIG #2
    /// ```
    ///
    /// In the following more elaborate example, `#2` and `#3` use the same sighash.
    /// `#1` uses a different sighash.
    ///
    /// ```text
    /// OP_CHECKSIGVERIFY #1
    /// OP_CODESEPARATOR
    /// OP_CHECKSIGVERIFY #2
    /// OP_CHECKSIG #3
    /// ```
    ///
    /// # See
    ///
    /// [BIP 342](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki#common-signature-message-extension).
    fn get_sighashes_with_code_separator(
        &self,
        cache: &mut SighashCache<&Transaction>,
        prevouts: Prevouts<'_, TxOut>,
        spend_path: Self::SpendPath,
        input_index: usize,
    ) -> impl IntoIterator<Item = Message> {
        // NOTE: (@uncomputable)
        // All of our transactions use SIGHASH_ALL aka SIGHASH_DEFAULT.
        // There is no reason to make the sighash type variable.
        let sighash_type = TapSighashType::Default;
        let leaf_index = self
            .to_leaf_index(spend_path)
            .expect("spend path must be a script-path spend");
        let leaf_script = &self.leaf_scripts()[leaf_index];
        let leaf_hash = TapLeafHash::from_script(leaf_script, LeafVersion::TapScript);
        self.code_separator_positions(leaf_index)
            .into_iter()
            .map(move |pos| Some((leaf_hash, pos)))
            .map(move |leaf_hash_code_separator| {
                let sighash = cache
                    .taproot_signature_hash(
                        input_index,
                        &prevouts,
                        None,
                        leaf_hash_code_separator,
                        sighash_type,
                    )
                    .expect("should be able to compute the sighash");

                Message::from_digest(sighash.to_raw_hash().to_byte_array())
            })
    }

    /// Converts the witness into a generic taproot witness.
    fn get_taproot_witness(&self, witness: &Self::Witness) -> TaprootWitness;

    /// Finalizes the PSBT `input` where the connector is used, using the provided `witness`.
    ///
    /// # Warning
    ///
    /// If the connector uses relative timelocks,
    /// then the **sequence** field of the transaction input must be updated accordingly.
    ///
    /// # Panics
    ///
    /// This method panics if the leaf index in the `witness` is out of bounds.
    fn finalize_input(&self, input: &mut Input, witness: &Self::Witness) {
        match self.get_taproot_witness(witness) {
            TaprootWitness::Key {
                output_key_signature,
            } => {
                finalize_input(input, [output_key_signature.serialize().to_vec()]);
            }
            TaprootWitness::Script {
                leaf_index,
                script_inputs,
            } => {
                let mut leaf_scripts = self.leaf_scripts();
                assert!(
                    leaf_index < leaf_scripts.len(),
                    "leaf index should be within bounds"
                );
                let leaf_script = leaf_scripts.swap_remove(leaf_index);
                let script_ver = (leaf_script, LeafVersion::TapScript);
                let taproot_spend_info = self.spend_info();
                let control_block = taproot_spend_info
                    .control_block(&script_ver)
                    .expect("leaf script exists");
                let leaf_script = script_ver.0;

                let mut witness = script_inputs;
                witness.push(leaf_script.to_bytes());
                witness.push(control_block.serialize());
                finalize_input(input, witness);
            }
        }
    }
}

/// Generic Taproot witness data.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaprootWitness {
    /// Key-path spend.
    Key {
        /// Signature of the output key.
        output_key_signature: schnorr::Signature,
    },
    /// Script-path spend.
    ///
    /// The leaf script and control block are supplied by the connector.
    Script {
        /// Leaf index.
        leaf_index: usize,
        /// Inputs to the leaf script.
        script_inputs: Vec<Vec<u8>>,
    },
}

/// Information that is required to make a signature for a Taproot transaction input.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct SigningInfo {
    /// Sighash of the transaction input.
    ///
    /// All inputs implicitly use SIGHASH_DEFAULT (aka SIGHASH_ALL).
    pub sighash: Message,
    /// Tap tweak of the signing key:
    pub tweak: TaprootTweak,
}

impl SigningInfo {
    /// Create a signature for the given signing info.
    pub fn sign(self, keypair: &Keypair) -> schnorr::Signature {
        match self.tweak {
            TaprootTweak::Key { tweak } => keypair
                .tap_tweak(SECP256K1, tweak)
                .to_keypair()
                .sign_schnorr(self.sighash),
            TaprootTweak::Script => keypair.sign_schnorr(self.sighash),
        }
    }
}

// NOTE: (@uncomputable) The trait lives here because crate::test_utils uses it.
// If the trait lived in tx-graph, then there would be a cyclic dependency between
// connectors and tx-graph.
/// Bitcoin transaction that is the parent in a CPFP fee-bumping scheme.
pub trait ParentTx {
    /// Returns the output that is spent by the CPFP child.
    fn cpfp_tx_out(&self) -> TxOut;

    /// Returns the outpoint that is spent by the CPFP child.
    fn cpfp_outpoint(&self) -> OutPoint;
}
