//! Provides some common, standalone utilities and wrappers over [`bitcoin`] to create
//! scripts, addresses and transactions.

use std::collections::BTreeMap;

use arbitrary::Arbitrary;
use bitcoin::{
    hashes::Hash,
    key::UntweakedPublicKey,
    psbt::Input,
    secp256k1::SECP256K1,
    sighash::{Prevouts, SighashCache},
    taproot::{ControlBlock, LeafVersion, TaprootBuilder, TaprootMerkleBranch, TaprootSpendInfo},
    Address, Network, ScriptBuf, TapLeafHash, TapNodeHash, TapSighashType, Transaction, TxOut,
    Witness, XOnlyPublicKey,
};
use bitvm::treepp::*;
use secp256k1::{rand::rngs::OsRng, Keypair, Message, Parity, SecretKey};

// use secp256k1::SECP256K1;
use crate::{
    errors::{BridgeTxBuilderError, BridgeTxBuilderResult},
    params::prelude::UNSPENDABLE_INTERNAL_KEY,
};

/// Different spending paths for a taproot.
///
/// It can be a key path spend, a script path spend or both.
#[derive(Debug, Clone)]
pub enum SpendPath<'path> {
    /// Key path spend that requires just an untweaked (internal) public key.
    KeySpend {
        /// The internal key used to construct the taproot.
        internal_key: UntweakedPublicKey,
    },
    /// Script path spend that only allows spending via scripts in the taproot tree, with the
    /// internal key being the [`static@UNSPENDABLE_INTERNAL_KEY`].
    ScriptSpend {
        /// The scripts that live in the leaves of the taproot tree.
        scripts: &'path [ScriptBuf],
    },
    /// Allows spending via either a provided internal key or via scripts in the taproot tree.
    Both {
        /// The internal key used to construct the taproot.
        internal_key: UntweakedPublicKey,

        /// The scripts that live in the leaves of the taproot tree.
        scripts: &'path [ScriptBuf],
    },
}

/// Create a taproot address for the given `scripts` and `internal_key`.
///
/// # Errors
///
/// If the scripts is empty in [`SpendPath::ScriptSpend`].
pub fn create_taproot_addr<'creator>(
    network: &'creator Network,
    spend_path: SpendPath<'creator>,
) -> BridgeTxBuilderResult<(Address, TaprootSpendInfo)> {
    match spend_path {
        SpendPath::KeySpend { internal_key } => build_taptree(internal_key, *network, &[]),
        SpendPath::ScriptSpend { scripts } => {
            if scripts.is_empty() {
                return Err(BridgeTxBuilderError::EmptyTapscript);
            }

            build_taptree(*UNSPENDABLE_INTERNAL_KEY, *network, scripts)
        }
        SpendPath::Both {
            internal_key,
            scripts,
        } => build_taptree(internal_key, *network, scripts),
    }
}

/// Constructs the taptree for the given scripts.
///
/// A taptree is a merkle tree made up of various scripts. Each script is a leaf in the merkle tree.
/// If the number of scripts is a power of 2, all the scripts lie at the deepest level (depth = n)
/// in the tree. If the number is not a power of 2, there are some scripts that will exist at the
/// penultimate level (depth = n - 1).
///
/// This function adds the scripts to the taptree after it computes the depth for each script.
fn build_taptree(
    internal_key: UntweakedPublicKey,
    network: Network,
    scripts: &[ScriptBuf],
) -> BridgeTxBuilderResult<(Address, TaprootSpendInfo)> {
    let mut taproot_builder = TaprootBuilder::new();

    let num_scripts = scripts.len();

    // Compute the height of the taptree required to fit in all the scripts.
    // If the script count <= 1, the depth should be 0. Otherwise, we compute the log. For example,
    // 2 scripts can fit in a height of 1 (0 being the root node). 4 can fit in a height of 2 and so
    // on.
    let max_depth = if num_scripts > 1 {
        (num_scripts - 1).ilog2() + 1
    } else {
        0
    };

    // Compute the maximum number of scripts that can fit in the taproot. For example, at a depth of
    // 3, we can fit 8 scripts.
    //              [Root Hash]
    //              /          \
    //             /            \
    //        [Hash 0]           [Hash 1]
    //       /        \          /      \
    //      /          \        /        \
    // [Hash 00]   [Hash 01] [Hash 10] [Hash 11]
    //   /   \       /   \     /   \     /   \
    // S0    S1    S2    S3  S4    S5   S6    S7
    let max_num_scripts = 2usize.pow(max_depth);

    // But we may be given say 5 scripts, in which case the tree would not be fully complete and we
    // need to add leaves at a shallower point in a way that minimizes the overall height (to reduce
    // the size of the merkle proof). So, we need to compute how many such scripts exist and add
    // these, at the appropriate depth.
    //
    //              [Root Hash]
    //              /          \
    //             /            \
    //        [Hash 0]          [Hash 1]
    //       /        \          /    \
    //      /          \        /      \
    // [Hash 00]        S2    S4        S5  ---> penultimate depth has 3 scripts
    //   /   \
    // S0    S1   ---------> max depth has 2 scripts
    let num_penultimate_scripts = max_num_scripts.saturating_sub(num_scripts);
    let num_deepest_scripts = num_scripts.saturating_sub(num_penultimate_scripts);

    for (script_idx, script) in scripts.iter().enumerate() {
        let depth = if script_idx < num_deepest_scripts {
            max_depth as u8
        } else {
            // if the deepest node is not filled, use the node at the upper level instead
            (max_depth - 1) as u8
        };

        taproot_builder = taproot_builder.add_leaf(depth, script.clone())?;
    }

    let spend_info = taproot_builder.finalize(SECP256K1, internal_key)?;

    let merkle_root = spend_info.merkle_root();

    Ok((
        Address::p2tr(SECP256K1, internal_key, merkle_root, network),
        spend_info,
    ))
}

pub fn taproot_witness_signatures(script: Script) -> Vec<Vec<u8>> {
    let result = execute_script(script);

    (0..result.final_stack.len())
        .map(|index| result.final_stack.get(index))
        .collect::<Vec<_>>()
}

/// Finalizes a [`bitcoin::Psbt`] input.
///
/// This done as per
/// <https://github.com/rust-bitcoin/rust-bitcoin/blob/bitcoin-0.32.1/bitcoin/examples/taproot-psbt.rs#L315-L327>.
pub fn finalize_input<D>(input: &mut Input, witnesses: impl IntoIterator<Item = D>)
where
    D: AsRef<[u8]>,
{
    let mut witness_stack = Witness::new();

    witnesses
        .into_iter()
        .for_each(|witness| witness_stack.push(witness));

    // Finalize the psbt as per <https://github.com/rust-bitcoin/rust-bitcoin/blob/bitcoin-0.32.1/bitcoin/examples/taproot-psbt.rs#L315-L327>
    // NOTE: their ecdsa example states that we should use `miniscript` to finalize
    // PSBTs in production but they don't mention this for taproot.

    // Set final witness
    input.final_script_witness = Some(witness_stack);

    // And clear all other fields as per the spec
    input.partial_sigs = BTreeMap::new();
    input.sighash_type = None;
    input.redeem_script = None;
    input.witness_script = None;
    input.bip32_derivation = BTreeMap::new();
}

/// The components required in the witness stack to spend a taproot output.
///
/// If a script-path path is being used, the witness stack needs the script being spent and the
/// control block in addition to the signature.
/// See [BIP 341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaprootWitness {
    /// Use the keypath spend.
    ///
    /// This only requires the signature for the tweaked internal key and nothing else.
    Key,

    /// Use the script path spend.
    ///
    /// This requires the script being spent from as well as the [`ControlBlock`] in addition to
    /// the elements that fulfill the spending condition in the script.
    Script {
        script_buf: ScriptBuf,
        control_block: ControlBlock,
    },
}

impl<'a> Arbitrary<'a> for TaprootWitness {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=1)?;

        match choice {
            0 => Ok(TaprootWitness::Key),
            1 => {
                let script_len = usize::arbitrary(u)? % 100; // Limit the length of the script for practicality
                let script_bytes = u.bytes(script_len)?; // Generate random bytes for the script
                let script_buf = ScriptBuf::from(script_bytes.to_vec());

                // Now we will manually generate the fields of the ControlBlock struct

                // Leaf version
                let leaf_version = bitcoin::taproot::LeafVersion::TapScript;

                // Output key parity (Even or Odd)
                let output_key_parity = if bool::arbitrary(u)? {
                    Parity::Even
                } else {
                    Parity::Odd
                };

                // Generate a random secret key and derive the internal key
                let secret_key = SecretKey::new(&mut OsRng);
                let keypair = Keypair::from_secret_key(SECP256K1, &secret_key);
                let (internal_key, _) = XOnlyPublicKey::from_keypair(&keypair);

                // Arbitrary Taproot merkle branch (vector of 32-byte hashes)
                const BRANCH_LENGTH: usize = 10;
                let mut tapnode_hashes: Vec<TapNodeHash> = Vec::with_capacity(BRANCH_LENGTH);
                for _ in 0..BRANCH_LENGTH {
                    let hash = TapNodeHash::from_slice(&<[u8; 32]>::arbitrary(u)?)
                        .map_err(|_e| arbitrary::Error::IncorrectFormat)?;
                    tapnode_hashes.push(hash);
                }

                let tapnode_hashes: &[TapNodeHash; BRANCH_LENGTH] =
                    &tapnode_hashes[..BRANCH_LENGTH].try_into().unwrap();

                let merkle_branch = TaprootMerkleBranch::from(*tapnode_hashes);

                // Construct the ControlBlock manually
                let control_block = ControlBlock {
                    leaf_version,
                    output_key_parity,
                    internal_key,
                    merkle_branch,
                };

                Ok(TaprootWitness::Script {
                    script_buf,
                    control_block,
                })
            }
            _ => unreachable!(),
        }
    }
}

/// Get the message hash for signing.
///
/// This hash may be for the key path spend or the script path spend depending upon the
/// `spend_path`.
pub fn create_message_hash(
    sighash_cache: &mut SighashCache<&Transaction>,
    prevouts: Prevouts<'_, TxOut>,
    witness_type: &TaprootWitness,
    sighash_type: TapSighashType,
    input_index: usize,
) -> anyhow::Result<Message> {
    if let TaprootWitness::Script {
        script_buf,
        control_block: _,
    } = witness_type
    {
        return create_script_spend_hash(
            sighash_cache,
            script_buf,
            prevouts,
            sighash_type,
            input_index,
        );
    }

    create_key_spend_hash(sighash_cache, prevouts, sighash_type, input_index)
}

/// Generate a sighash message for a taproot `script` spending path at the `input_index` of
/// all `prevouts`.
pub fn create_script_spend_hash(
    sighash_cache: &mut SighashCache<&Transaction>,
    script: &ScriptBuf,
    prevouts: Prevouts<'_, TxOut>,
    sighash_type: TapSighashType,
    input_index: usize,
) -> anyhow::Result<Message> {
    let leaf_hash = TapLeafHash::from_script(script, LeafVersion::TapScript);

    let sighash = sighash_cache.taproot_script_spend_signature_hash(
        input_index,
        &prevouts,
        leaf_hash,
        sighash_type,
    )?;

    let message =
        Message::from_digest_slice(sighash.as_byte_array()).expect("TapSigHash is a hash");

    Ok(message)
}

/// Generate a sighash message for a taproot `key` spending path at the `input_index` of
/// all `prevouts`.
pub fn create_key_spend_hash(
    sighash_cache: &mut SighashCache<&Transaction>,
    prevouts: Prevouts<'_, TxOut>,
    sighash_type: TapSighashType,
    input_index: usize,
) -> anyhow::Result<Message> {
    let sighash =
        sighash_cache.taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)?;

    let message =
        Message::from_digest_slice(sighash.as_byte_array()).expect("TapSigHash is a hash");

    Ok(message)
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        key::Keypair,
        secp256k1::{rand, SecretKey},
    };
    use rand::rngs::OsRng;
    use secp256k1::XOnlyPublicKey;

    use super::*;

    #[test]
    fn test_create_taproot_addr() {
        // create a bunch of dummy scripts to add to the taptree
        let max_scripts = 10;
        let scripts: Vec<ScriptBuf> = vec![ScriptBuf::from_bytes(vec![2u8; 32]); max_scripts];

        let network = Network::Regtest;

        let spend_path = SpendPath::ScriptSpend {
            scripts: &scripts[0..1],
        };
        assert!(
            create_taproot_addr(&network, spend_path).is_ok(),
            "should work if the number of scripts is exactly 1 i.e., only root node exists"
        );

        let spend_path = SpendPath::ScriptSpend {
            scripts: &scripts[0..4],
        };
        assert!(
            create_taproot_addr(&network, spend_path).is_ok(),
            "should work if the number of scripts is an exact power of 2"
        );

        let spend_path = SpendPath::ScriptSpend {
            scripts: &scripts[..],
        };
        assert!(
            create_taproot_addr(&network, spend_path).is_ok(),
            "should work if the number of scripts is not an exact power of 2"
        );

        let secret_key = SecretKey::new(&mut OsRng);
        let keypair = Keypair::from_secret_key(SECP256K1, &secret_key);
        let (x_only_public_key, _) = XOnlyPublicKey::from_keypair(&keypair);

        let spend_path = SpendPath::KeySpend {
            internal_key: x_only_public_key,
        };
        assert!(
            create_taproot_addr(&network, spend_path).is_ok(),
            "should support empty scripts with some internal key"
        );

        let spend_path = SpendPath::Both {
            internal_key: x_only_public_key,
            scripts: &scripts[..3],
        };
        assert!(
            create_taproot_addr(&network, spend_path).is_ok(),
            "should support scripts with some internal key"
        );
    }
}
