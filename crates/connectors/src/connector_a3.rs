//! This module contains the connector from the first output of the PostAssert transaction.
//!
//! This connector is spent by the Disprove transaction to disprove the proof committed in the
//! AssertData transactions and the Claim transaction by the operator.
use bitcoin::{
    hashes::Hash,
    psbt::Input,
    taproot::{ControlBlock, LeafVersion, TaprootSpendInfo},
    Address, Network, ScriptBuf, Txid,
};
use bitvm::{
    groth16::g16::{self, N_TAPLEAVES},
    hash::sha256::sha256,
    pseudo::NMUL,
    signatures::wots_api::{wots256, SignatureImpl},
    treepp::*,
};
use secp256k1::{schnorr, XOnlyPublicKey};
use strata_bridge_primitives::{
    params::prelude::PAYOUT_TIMELOCK,
    scripts::prelude::*,
    wots::{self, Groth16PublicKeys},
};

use crate::partial_verification_scripts::PARTIAL_VERIFIER_SCRIPTS;

/// Possible spending paths for the [`ConnectorA31`].
#[derive(Debug, Clone)]
#[expect(clippy::large_enum_variant)]
pub enum ConnectorA3Leaf {
    /// The leaf used in the Payout transaction if there is no disprove.
    Payout(Option<schnorr::Signature>),

    /// The leaf used to disprove the proof committed in the AssertData transactions.
    DisproveProof {
        /// The locking script corresponding to the faulty proof execution.
        disprove_script: Script,
        /// The witness script used in the disprove that shows a faulty execution i.e., an
        /// execution segment where the f(z_k) != z_{k+1}.
        witness_script: Option<Script>,
    },

    /// The leaf used to disprove the proof public params committed in the AssertData transactions.
    DisprovePublicInputsCommitment {
        /// The deposit transaction ID for which the current tx graph has been constructed and
        /// signed.
        deposit_txid: Txid,
        /// The witness data for the disprove script.
        ///
        /// This is the same data that is committed in the public inputs of the proof by the
        /// operator making the claim.
        witness: Option<DisprovePublicInputsCommitmentWitness>,
    },
}

/// The witness used to disprove the public inputs commitment.
#[derive(Debug, Clone, Copy)]
pub struct DisprovePublicInputsCommitmentWitness {
    /// The WOTS value for the withdrawal fulfillment txid committed by the assigned operator in
    /// the Claim Transaction.
    pub sig_withdrawal_fulfillment_txid: wots256::Signature,
    /// The WOTS value for the public inputs hash committed by the assigned operator in one of the
    /// AssertData transactions.
    pub sig_public_inputs_hash: wots256::Signature,
}

impl ConnectorA3Leaf {
    /// Generate the locking script for the leaf.
    pub(crate) fn generate_locking_script(
        &self,
        public_keys: wots::PublicKeys,
        n_of_n_agg_pubkey: XOnlyPublicKey,
    ) -> Script {
        let wots::PublicKeys {
            withdrawal_fulfillment_pk,
            groth16: Groth16PublicKeys(([public_inputs_hash_public_key], _, _)),
        } = public_keys;
        match self {
            ConnectorA3Leaf::Payout(_) => n_of_n_with_timelock(&n_of_n_agg_pubkey, PAYOUT_TIMELOCK),

            ConnectorA3Leaf::DisprovePublicInputsCommitment { deposit_txid, .. } => {
                script! {
                    // first, verify that the WOTS for withdrawal fulfillment txid is correct.
                    { wots256::compact::checksig_verify(withdrawal_fulfillment_pk.0) }

                    // `checksig_verify` pushes the committed data onto the stack as nibbles in big-endian form.
                    // so, first `swap` to reverse the order of the nibbles.
                    // then, multiply each nibble by 16 and add them to together to get the byte.
                    // finally, push the byte to the ALTSTACK.
                    for _ in 0..32 { OP_SWAP { NMUL(1 << 4) } OP_ADD OP_TOALTSTACK }

                    // second, verify that the WOTS for public inputs hash is correct.
                    { wots256::compact::checksig_verify(public_inputs_hash_public_key) }
                    // same as above but the public inputs hash is in the reverse order.
                    for _ in 0..32 { { NMUL(1 << 4) } OP_ADD OP_TOALTSTACK }

                    // get the committed public inputs hash from the altstack.
                    for _ in 0..32 { OP_FROMALTSTACK }
                    // get the committed withdrawal fulfillment txid from the altstack.
                    for _ in 0..32 { OP_FROMALTSTACK }

                    // include the deposit txid in the script to couple proofs with deposits.
                    // this is part of the commitment to the public inputs (along with the
                    // withdrawal_fulfillment txid.
                    for &b in deposit_txid.to_byte_array().iter().rev() { { b } } // add_bincode_padding_bytes32

                    // hash the deposit txid and the withdrawal fulfillment txid to get the public
                    // inputs hash
                    { sha256(2 * 32) }
                    // convert the hash to a bn254 field element
                    hash_to_bn254_fq

                    // verify that the computed hash and the committed inputs hash don't match
                    for i in (1..32).rev() {
                        // compare the last bytes first
                        {i + 1} OP_ROLL
                        // check if they are equal and push the result to the altstack
                        OP_EQUAL OP_TOALTSTACK
                    }
                    // check the first bytes (this serves as the accumulator of the boolean fold)
                    OP_EQUAL
                    // fold all the comparison result with `AND`
                    for _ in 1..32 { OP_FROMALTSTACK OP_BOOLAND }
                    // if the result is true, the public inputs hash is not committed correctly
                    // which is cause for a disprove so invert the result.
                    OP_NOT
                }
            }
            ConnectorA3Leaf::DisproveProof {
                disprove_script, ..
            } => disprove_script.clone(),
        }
    }

    /// Generate the witness script for the leaf.
    pub fn generate_witness_script(&self) -> Script {
        match self {
            ConnectorA3Leaf::DisprovePublicInputsCommitment {
                witness:
                    Some(DisprovePublicInputsCommitmentWitness {
                        sig_withdrawal_fulfillment_txid,
                        sig_public_inputs_hash,
                    }),
                ..
            } => {
                script! {
                    { sig_public_inputs_hash.to_compact_script() }
                    { sig_withdrawal_fulfillment_txid.to_compact_script() }
                }
            }
            ConnectorA3Leaf::DisproveProof {
                witness_script: Some(witness_script),
                ..
            } => witness_script.clone(),
            _ => panic!("no data provided to finalize input"),
        }
    }
}

/// Connector from the PostAssert transaction to the Disprove transaction.
#[derive(Debug, Clone, Copy)]
pub struct ConnectorA3 {
    network: Network,

    deposit_txid: Txid,

    wots_public_keys: wots::PublicKeys,

    n_of_n_agg_pubkey: XOnlyPublicKey,
}

impl ConnectorA3 {
    /// Constructs a new instance of the connector.
    pub fn new(
        network: Network,
        deposit_txid: Txid,
        wots_public_keys: wots::PublicKeys,
        n_of_n_agg_pubkey: XOnlyPublicKey,
    ) -> Self {
        Self {
            network,
            deposit_txid,
            wots_public_keys,
            n_of_n_agg_pubkey,
        }
    }

    /// Generates the locking script for this connector.
    pub fn generate_locking_script(&self, deposit_txid: Txid) -> ScriptBuf {
        let (address, _) = self.generate_taproot_address(deposit_txid);

        address.script_pubkey()
    }

    /// Generates the taproot spend info for this connector.
    pub fn generate_spend_info(
        &self,
        tapleaf: ConnectorA3Leaf,
        deposit_txid: Txid,
    ) -> (ScriptBuf, ControlBlock) {
        let (_, taproot_spend_info) = self.generate_taproot_address(deposit_txid);

        let script = tapleaf
            .generate_locking_script(self.wots_public_keys, self.n_of_n_agg_pubkey)
            .compile();
        let control_block = taproot_spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("script is always present in the address");

        (script, control_block)
    }

    /// Generates the disprove scripts for this connector.
    pub fn generate_disprove_scripts(&self) -> [Script; N_TAPLEAVES] {
        let partial_disprove_scripts = &PARTIAL_VERIFIER_SCRIPTS;

        let groth16_pks = self.wots_public_keys.groth16.0;

        g16::generate_disprove_scripts(groth16_pks, partial_disprove_scripts)
    }

    fn generate_taproot_address(&self, deposit_txid: Txid) -> (Address, TaprootSpendInfo) {
        let scripts = [
            ConnectorA3Leaf::Payout(None),
            ConnectorA3Leaf::DisprovePublicInputsCommitment {
                deposit_txid,
                witness: None,
            },
        ]
        .map(|leaf| {
            leaf.generate_locking_script(self.wots_public_keys, self.n_of_n_agg_pubkey)
                .compile()
        })
        .into_iter();

        let disprove_scripts = self.generate_disprove_scripts();
        let invalidate_proof_tapleaves = disprove_scripts
            .map(|disprove_script| ConnectorA3Leaf::DisproveProof {
                disprove_script,
                witness_script: None,
            })
            .map(|leaf| {
                leaf.generate_locking_script(self.wots_public_keys, self.n_of_n_agg_pubkey)
                    .compile()
            });

        let scripts = scripts
            .chain(invalidate_proof_tapleaves)
            .collect::<Vec<ScriptBuf>>();

        create_taproot_addr(&self.network, SpendPath::ScriptSpend { scripts: &scripts })
            .expect("should be able to create taproot address")
    }

    /// Finalizes the input for the psbt that spends this connector.
    pub fn finalize_input(&self, input: &mut Input, tapleaf: ConnectorA3Leaf) {
        let (script, control_block) = self.generate_spend_info(tapleaf.clone(), self.deposit_txid);

        let witness_script = tapleaf.generate_witness_script();

        let mut witness_stack = taproot_witness_signatures(witness_script);

        witness_stack.push(script.to_bytes());
        witness_stack.push(control_block.serialize());

        finalize_input(input, witness_stack);
    }
}

#[cfg(test)]
mod tests {
    use sp1_verifier::hash_public_inputs;
    use strata_bridge_primitives::scripts::parse_witness::parse_wots256_signatures;
    use strata_bridge_proof_protocol::BridgeProofPublicOutput;
    use strata_bridge_test_utils::prelude::{generate_keypair, generate_txid};

    use super::*;

    #[test]
    fn test_disprove_public_inputs() {
        let deposit_txid = generate_txid();
        let withdrawal_fulfillment_txid = generate_txid();

        let public_inputs = BridgeProofPublicOutput {
            deposit_txid: deposit_txid.into(),
            withdrawal_fulfillment_txid: withdrawal_fulfillment_txid.into(),
        };

        let serialized_public_inputs = borsh::to_vec(&public_inputs).unwrap();
        let committed_public_inputs_hash = hash_public_inputs(&serialized_public_inputs);

        let msk: &str = "test-disprove-public-inputs-hash";

        let invalid_disprove_leaf = get_disprove_leaf(
            msk,
            deposit_txid,
            withdrawal_fulfillment_txid,
            committed_public_inputs_hash,
        );

        let result = execute_disprove(msk, deposit_txid, invalid_disprove_leaf);
        assert!(
            !result.success,
            "must not be able to disprove with matching input hash"
        );
        assert!(
            result.error.is_none(),
            "disprove script must not error but got: {:?}",
            result.error
        );

        let faulty_public_inputs = BridgeProofPublicOutput {
            withdrawal_fulfillment_txid: generate_txid().into(),
            deposit_txid: deposit_txid.into(),
        };
        let faulty_inputs_hash = hash_public_inputs(&borsh::to_vec(&faulty_public_inputs).unwrap());

        let valid_disprove_leaf = get_disprove_leaf(
            msk,
            deposit_txid,
            withdrawal_fulfillment_txid,
            faulty_inputs_hash,
        );

        let result = execute_disprove(msk, deposit_txid, valid_disprove_leaf);
        assert!(
            result.success,
            "must be able to disprove with different withdrawal fulfillment txid"
        );
        assert!(
            result.error.is_none(),
            "disprove script must not error but got: {:?}",
            result.error
        );

        let faulty_public_inputs = BridgeProofPublicOutput {
            deposit_txid: generate_txid().into(),
            withdrawal_fulfillment_txid: withdrawal_fulfillment_txid.into(),
        };
        let faulty_inputs_hash = hash_public_inputs(&borsh::to_vec(&faulty_public_inputs).unwrap());

        let valid_disprove_leaf = get_disprove_leaf(
            msk,
            deposit_txid,
            withdrawal_fulfillment_txid,
            faulty_inputs_hash,
        );

        let result = execute_disprove(msk, deposit_txid, valid_disprove_leaf);
        assert!(
            result.success,
            "must be able to disprove with different deposit txid"
        );
        assert!(
            result.error.is_none(),
            "disprove script must not error but got: {:?}",
            result.error
        );

        let faulty_msk = msk.to_owned() + "faulty";
        let invalid_disprove_leaf = get_disprove_leaf(
            &faulty_msk,
            deposit_txid,
            withdrawal_fulfillment_txid,
            faulty_inputs_hash,
        );

        let result = execute_disprove(msk, deposit_txid, invalid_disprove_leaf);
        assert!(
            result.error.is_some(),
            "disprove script must error if signature (commitment) is invalid",
        );
    }

    fn execute_disprove(
        msk: &str,
        deposit_txid: Txid,
        invalid_disprove_leaf: ConnectorA3Leaf,
    ) -> bitvm::ExecuteInfo {
        let wots_public_keys = wots::PublicKeys::new(msk, deposit_txid);

        let n_of_n_keypair = generate_keypair();
        let n_of_n_agg_pubkey = n_of_n_keypair.public_key().x_only_public_key().0;
        let locking_script =
            invalid_disprove_leaf.generate_locking_script(wots_public_keys, n_of_n_agg_pubkey);
        let witness_script = invalid_disprove_leaf.generate_witness_script();
        let witness_script = taproot_witness_signatures(witness_script);
        let full_script = script! {
            { witness_script }
            { locking_script }
        };

        execute_script(full_script)
    }

    fn get_disprove_leaf(
        msk: &str,
        deposit_txid: Txid,
        withdrawal_fulfillment_txid: Txid,
        committed_public_inputs_hash: [u8; 32],
    ) -> ConnectorA3Leaf {
        let deposit_msk = get_deposit_master_secret_key(msk, deposit_txid);

        let withdrawal_fulfillment_txid_sk = secret_key_for_bridge_out_txid(&deposit_msk);
        let sig_withdrawal_fulfillment_txid = wots256::get_signature(
            &withdrawal_fulfillment_txid_sk,
            &withdrawal_fulfillment_txid.to_byte_array()[..],
        )
        .to_script();
        let sig_withdrawal_fulfillment_txid =
            parse_wots256_signatures::<1>(sig_withdrawal_fulfillment_txid).unwrap()[0];

        let public_inputs_hash_sk = secret_key_for_public_inputs_hash(&deposit_msk);
        // FIXME: fix and remove nibble flipping
        let committed_public_inputs_hash =
            committed_public_inputs_hash.map(|b| ((b & 0xf0) >> 4) | ((b & 0x0f) << 4));

        let sig_public_inputs_hash =
            wots256::get_signature(&public_inputs_hash_sk, &committed_public_inputs_hash[..])
                .to_script();
        let sig_public_inputs_hash =
            parse_wots256_signatures::<1>(sig_public_inputs_hash).unwrap()[0];

        ConnectorA3Leaf::DisprovePublicInputsCommitment {
            deposit_txid,
            witness: Some(DisprovePublicInputsCommitmentWitness {
                sig_withdrawal_fulfillment_txid,
                sig_public_inputs_hash,
            }),
        }
    }
}
