//! Builders related to building deposit-related transactions.
//!
//! Contains types, traits and implementations related to creating various transactions used in the
//! bridge-in dataflow.

use alpen_bridge_params::prelude::PegOutGraphParams;
use bitcoin::{
    key::TapTweak,
    secp256k1::SECP256K1,
    taproot::{self, ControlBlock, LeafVersion},
    Amount, OutPoint, Psbt, ScriptBuf, TapNodeHash, Transaction, TxOut, XOnlyPublicKey,
};
use serde::{Deserialize, Serialize};
use strata_primitives::params::RollupParams;

use crate::{
    build_context::BuildContext,
    constants::UNSPENDABLE_INTERNAL_KEY,
    errors::{BridgeTxBuilderError, BridgeTxBuilderResult, DepositTransactionError},
    scripts::{
        general::{create_tx, create_tx_ins, create_tx_outs},
        prelude::*,
        taproot::{create_taproot_addr, SpendPath, TaprootWitness},
    },
    types::TxSigningData,
};

/// The deposit information  required to create the Deposit Transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositInfo {
    /// The deposit request transaction outpoints from the users.
    deposit_request_outpoint: OutPoint,

    /// The stake index that will be tied to this deposit.
    ///
    /// This is required in order to make sure that the at withdrawal time, deposit UTXOs are
    /// assigned in the same order that the stake transactions were linked during setup time
    ///
    /// # Note
    ///
    /// The stake index must be encoded in 4-byte big-endian.
    stake_index: u32,

    /// The execution environment address to mint the equivalent tokens to.
    /// As of now, this is just the 20-byte EVM address.
    ee_address: Vec<u8>,

    /// The amount in bitcoins that the user is sending.
    ///
    /// This amount should be greater than the bridge denomination for the deposit to be
    /// confirmed on bitcoin. The excess amount is used as miner fees for the Deposit Transaction.
    total_amount: Amount,

    /// The [`XOnlyPublicKey`] in the Deposit Request Transaction (DRT) as provided by the
    /// user in their `OP_RETURN` output.
    x_only_public_key: XOnlyPublicKey,

    /// The original script_pubkey in the Deposit Request Transaction (DRT) output used to sanity
    /// check computation internally i.e., whether the known information (n/n script spend path,
    /// [`static@UNSPENDABLE_INTERNAL_KEY`]) + the [`Self::take_back_leaf_hash`] yields the same
    /// P2TR address.
    original_script_pubkey: ScriptBuf,
}

impl DepositInfo {
    /// Create a new deposit info with all the necessary data required to create a deposit
    /// transaction.
    pub fn new(
        deposit_request_outpoint: OutPoint,
        stake_index: u32,
        el_address: Vec<u8>,
        total_amount: Amount,
        x_only_public_key: XOnlyPublicKey,
        original_script_pubkey: ScriptBuf,
    ) -> Self {
        Self {
            deposit_request_outpoint,
            stake_index,
            ee_address: el_address,
            total_amount,
            x_only_public_key,
            original_script_pubkey,
        }
    }

    /// Get the total deposit amount that needs to be bridged-in.
    pub fn total_amount(&self) -> &Amount {
        &self.total_amount
    }

    /// Get the stake index.
    pub fn stake_index(&self) -> u32 {
        self.stake_index
    }

    /// Get the address in EL to mint tokens to.
    pub fn el_address(&self) -> &[u8] {
        &self.ee_address
    }

    /// Get the outpoint of the Deposit Request Transaction (DRT) that is to spent in the Deposit
    /// Transaction (DT).
    pub fn deposit_request_outpoint(&self) -> &OutPoint {
        &self.deposit_request_outpoint
    }

    /// Get the x-only public key of the user-takes-back leaf in the taproot of the Deposit Request
    /// Transaction (DRT).
    pub fn x_only_public_key(&self) -> &XOnlyPublicKey {
        &self.x_only_public_key
    }

    /// Constructs the data required to construct the Deposit Transaction.
    ///
    /// In other words, this function converts the [`DepositInfo`] to an actual (unsigned) Deposit
    /// Transaction.
    pub fn construct_signing_data<C: BuildContext>(
        &self,
        build_context: &C,
        pegout_graph_params: &PegOutGraphParams,
        sidesystem_params: &RollupParams,
    ) -> BridgeTxBuilderResult<TxSigningData> {
        let PegOutGraphParams {
            tag,
            deposit_amount,
            ..
        } = pegout_graph_params;
        let prevouts = self.compute_prevouts();
        let spend_info =
            self.compute_spend_infos(build_context, pegout_graph_params.refund_delay)?;
        let unsigned_tx = self.create_unsigned_tx(
            build_context,
            *deposit_amount,
            tag.as_bytes(),
            sidesystem_params.address_length as usize,
        )?;

        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)?;

        for (i, input) in psbt.inputs.iter_mut().enumerate() {
            input.witness_utxo = Some(prevouts[i].clone());
        }

        Ok(TxSigningData {
            psbt,
            spend_path: spend_info,
        })
    }

    /// Computes the witness data for spending the Deposit Request Transaction (DRT) and in the
    /// process, also validates the following:
    ///
    /// 1. The taproot address computed from the x-only public key in the DRT and the bridge
    ///    multisig address is the same as the output address in the DRT.
    /// 1. The control block computed from the DRT commits to the multisig script that the Deposit
    ///    Transaction (DT) spends.
    pub fn compute_spend_infos(
        &self,
        build_context: &impl BuildContext,
        refund_delay: u16,
    ) -> BridgeTxBuilderResult<TaprootWitness> {
        // The Deposit Transaction (DT) spends the n-of-n multisig leaf
        let spend_script = n_of_n_script(&build_context.aggregated_pubkey()).compile();

        // Compute the merkle root using the x-only public key in the OP_RETURN
        let recovery_xonly_pubkey = self.x_only_public_key();
        let takeback_script = drt_take_back(*recovery_xonly_pubkey, refund_delay);
        let takeback_script_hash =
            TapNodeHash::from_script(&takeback_script, LeafVersion::TapScript);

        let spend_path = SpendPath::ScriptSpend {
            scripts: &[spend_script.clone(), takeback_script],
        };

        let (address, spend_info) =
            create_taproot_addr(&build_context.network(), spend_path).unwrap();
        let merkle_root = spend_info.merkle_root();

        let expected_spk = &self.original_script_pubkey;

        if address.script_pubkey() != *expected_spk {
            return Err(BridgeTxBuilderError::DepositTransaction(
                DepositTransactionError::InvalidTapLeafHash,
            ));
        }

        let (output_key, parity) = UNSPENDABLE_INTERNAL_KEY.tap_tweak(SECP256K1, merkle_root);

        let control_block = ControlBlock {
            leaf_version: taproot::LeafVersion::TapScript,
            internal_key: *UNSPENDABLE_INTERNAL_KEY,
            merkle_branch: vec![takeback_script_hash].try_into().map_err(|_| {
                BridgeTxBuilderError::DepositTransaction(
                    DepositTransactionError::InvalidTapLeafHash,
                )
            })?,
            output_key_parity: parity,
        };

        if !control_block.verify_taproot_commitment(SECP256K1, output_key.into(), &spend_script) {
            return Err(BridgeTxBuilderError::DepositTransaction(
                DepositTransactionError::InvalidTapLeafHash,
            ));
        }

        let spend_info = TaprootWitness::Script {
            script_buf: spend_script,
            control_block,
        };

        Ok(spend_info)
    }

    fn compute_prevouts(&self) -> Vec<TxOut> {
        vec![TxOut {
            script_pubkey: self.original_script_pubkey.clone(),
            value: self.total_amount,
        }]
    }

    fn create_unsigned_tx(
        &self,
        build_context: &impl BuildContext,
        deposit_amt: Amount,
        tag: &[u8],
        ee_address_size: usize,
    ) -> BridgeTxBuilderResult<Transaction> {
        // First, create the inputs
        let outpoint = self.deposit_request_outpoint();
        let tx_ins = create_tx_ins([*outpoint]);

        // Second, create the `OP_RETURN` output:
        // <magic_bytes>  (the `tag` argument)
        // <stake_index> (4-byte big-endian)
        // <ee_address> (from the DRT)
        if self.ee_address.len() != ee_address_size {
            return Err(DepositTransactionError::InvalidEeAddressSize(
                self.ee_address.len(),
                ee_address_size,
            )
            .into());
        }

        let metadata = AuxiliaryData {
            tag,
            metadata: DepositMetadata::DepositTx {
                stake_index: self.stake_index(),
                ee_address: self.ee_address.to_vec(),
                takeback_pubkey: self.x_only_public_key,
                input_amount: self.total_amount,
            },
        };
        let metadata_script = metadata_script(metadata);
        let metadata_amount = Amount::from_int_btc(0);

        // Then create the taproot script pubkey with keypath spend for the actual deposit
        let spend_path = SpendPath::KeySpend {
            internal_key: build_context.aggregated_pubkey(),
        };

        let (bridge_addr, _) = create_taproot_addr(&build_context.network(), spend_path)?;

        let bridge_in_script_pubkey = bridge_addr.script_pubkey();

        let tx_outs = create_tx_outs([
            (bridge_in_script_pubkey, deposit_amt),
            (metadata_script, metadata_amount),
        ]);

        let unsigned_tx = create_tx(tx_ins, tx_outs);

        Ok(unsigned_tx)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use bitcoin::{script::Instruction, Network};
    use secp256k1::PublicKey;
    use strata_primitives::{operator::OperatorPubkeys, params::OperatorConfig};

    use super::*;
    use crate::{
        build_context::TxBuildContext,
        errors::{BridgeTxBuilderError, DepositTransactionError},
        test_utils::{
            create_drt_taproot_output, generate_keypairs, generate_pubkey_table,
            generate_xonly_pubkey,
        },
    };

    /// Loads the sidesystem params from the test file.
    ///
    /// If pubkeys are supplied, it updates the operator config in the params with the provided
    /// pubkeys as `wallet_pk`.
    fn test_sidesystem_params<Pks>(pubkeys: Option<Pks>) -> RollupParams
    where
        Pks: IntoIterator<Item = PublicKey>,
    {
        let test_rollup_params = fs::read_to_string("../../test-data/rollup_params.json")
            .expect("could not read test rollup params");

        let mut params = serde_json::from_str::<RollupParams>(&test_rollup_params)
            .expect("rollup-params in test-data must have valid structure");

        if let Some(pubkeys) = pubkeys {
            params.operator_config = OperatorConfig::Static(
                pubkeys
                    .into_iter()
                    .map(|wallet_pk| {
                        let wallet_pk = wallet_pk.x_only_public_key().0;
                        OperatorPubkeys::new([2u8; 32].into(), wallet_pk.serialize().into())
                    })
                    .collect(),
            );
        }

        params
    }

    #[test]
    fn test_create_spend_infos() {
        let (operator_pubkeys, _) = generate_keypairs(10);
        let operator_pubkeys = generate_pubkey_table(&operator_pubkeys);

        let deposit_request_outpoint = OutPoint::null();
        let recovery_xonly_pk = generate_xonly_pubkey();

        let refund_delay = 1008;
        let (drt_output_address, _take_back_leaf_hash) =
            create_drt_taproot_output(operator_pubkeys.clone(), recovery_xonly_pk, refund_delay);
        let self_index = 0;

        let tx_builder = TxBuildContext::new(Network::Regtest, operator_pubkeys, self_index);
        let deposit_amt = Amount::from_int_btc(1);

        // Correct merkle proof
        let deposit_info = DepositInfo::new(
            deposit_request_outpoint,
            1,
            [0u8; 20].to_vec(),
            deposit_amt,
            recovery_xonly_pk,
            drt_output_address.address().script_pubkey(),
        );

        let result = deposit_info.compute_spend_infos(&tx_builder, refund_delay);
        assert!(
            result.is_ok(),
            "should build the prevout for DT from the deposit info, error: {:?}",
            result.err().unwrap()
        );

        // Handles incorrect merkle proof
        let random_xonly_pubkey = generate_xonly_pubkey();
        let deposit_info = DepositInfo::new(
            deposit_request_outpoint,
            1,
            [0u8; 20].to_vec(),
            deposit_amt,
            random_xonly_pubkey,
            drt_output_address.address().script_pubkey(),
        );

        let result = deposit_info.compute_spend_infos(&tx_builder, refund_delay);

        assert!(result.as_ref().err().is_some());
        assert!(
            matches!(
                result.unwrap_err(),
                BridgeTxBuilderError::DepositTransaction(
                    DepositTransactionError::InvalidTapLeafHash
                ),
            ),
            "should handle the case where the supplied merkle proof is wrong"
        );
    }

    #[test]
    fn test_create_unsigned_tx() {
        let (operator_pubkeys, _) = generate_keypairs(10);
        let operator_pubkeys = generate_pubkey_table(&operator_pubkeys);

        let deposit_request_outpoint = OutPoint::null();
        let recovery_xonly_pk = generate_xonly_pubkey();

        let refuned_delay = 1008;
        let (drt_output_address, _take_back_leaf_hash) =
            create_drt_taproot_output(operator_pubkeys.clone(), recovery_xonly_pk, refuned_delay);
        let self_index = 0;

        let tx_builder = TxBuildContext::new(Network::Regtest, operator_pubkeys, self_index);
        let deposit_amt = Amount::from_int_btc(1);

        let deposit_info = DepositInfo::new(
            deposit_request_outpoint,
            1,
            [0u8; 20].to_vec(),
            deposit_amt,
            recovery_xonly_pk,
            drt_output_address.address().script_pubkey(),
        );

        let tag = b"alpen";
        let deposit_amt = Amount::from_int_btc(1);
        let result = deposit_info.create_unsigned_tx(&tx_builder, deposit_amt, tag, 20);
        assert!(
            result.is_ok(),
            "should build the prevout for DT from the deposit info, error: {:?}",
            result.err().unwrap()
        );

        let unsigned_tx = result.unwrap();
        assert_eq!(unsigned_tx.input.len(), 1);
        assert_eq!(unsigned_tx.output.len(), 2);
    }

    #[test]
    fn test_construct_signing_data() {
        let (operator_pubkeys, _) = generate_keypairs(10);
        let operator_pubkeys = generate_pubkey_table(&operator_pubkeys);

        let deposit_request_outpoint = OutPoint::null();
        let recovery_xonly_pk = generate_xonly_pubkey();

        let refund_delay = 1008;
        let (drt_output_address, _take_back_leaf_hash) =
            create_drt_taproot_output(operator_pubkeys.clone(), recovery_xonly_pk, refund_delay);
        let self_index = 0;

        let tx_builder = TxBuildContext::new(Network::Regtest, operator_pubkeys, self_index);
        let deposit_amt = Amount::from_int_btc(1);

        let deposit_info = DepositInfo::new(
            deposit_request_outpoint,
            1,
            [0u8; 20].to_vec(),
            deposit_amt,
            recovery_xonly_pk,
            drt_output_address.address().script_pubkey(),
        );

        let deposit_amt = Amount::from_int_btc(1);
        let result = deposit_info.construct_signing_data(
            &tx_builder,
            &PegOutGraphParams::default(),
            &test_sidesystem_params::<Vec<_>>(None),
        );
        assert!(
            result.is_ok(),
            "should build the prevout for DT from the deposit info, error: {:?}",
            result.err().unwrap()
        );

        let signing_data = result.unwrap();
        assert_eq!(signing_data.psbt.unsigned_tx.input.len(), 1);
        assert_eq!(signing_data.psbt.unsigned_tx.output.len(), 2);

        // test with invalid EL address
        const INVALID_LENGTH: usize = 21;
        let deposit_info = DepositInfo::new(
            deposit_request_outpoint,
            1,
            [0u8; 21].to_vec(),
            deposit_amt,
            recovery_xonly_pk,
            drt_output_address.address().script_pubkey(),
        );

        let result = deposit_info.construct_signing_data(
            &tx_builder,
            &PegOutGraphParams::default(),
            &test_sidesystem_params::<Vec<_>>(None),
        );
        assert!(
            result.is_err_and(|e| matches!(
                e,
                BridgeTxBuilderError::DepositTransaction(
                    DepositTransactionError::InvalidEeAddressSize(INVALID_LENGTH, 20)
                )
            )),
            "should handle the case where the EL address is invalid"
        );

        // test with invalid x-only pk
        let random_xonly_pk = generate_xonly_pubkey();

        let deposit_info = DepositInfo::new(
            deposit_request_outpoint,
            1,
            [0u8; 20].to_vec(),
            deposit_amt,
            random_xonly_pk,
            drt_output_address.address().script_pubkey(),
        );

        let result = deposit_info.construct_signing_data(
            &tx_builder,
            &PegOutGraphParams::default(),
            &test_sidesystem_params::<Vec<_>>(None),
        );
        assert!(
            result.is_err_and(|e| matches!(
                e,
                BridgeTxBuilderError::DepositTransaction(
                    DepositTransactionError::InvalidTapLeafHash
                )
            )),
            "should handle the case where the supplied merkle proof is wrong"
        );
    }

    #[test]
    fn test_deposit_tx_metadata() {
        let network = Network::Regtest;

        let (operator_pubkeys, _) = generate_keypairs(5);
        let operator_pubkeys = generate_pubkey_table(&operator_pubkeys);
        let sidesystem_params = test_sidesystem_params(Some(operator_pubkeys.0.values().copied()));

        let tx_build_context = TxBuildContext::new(network, operator_pubkeys, 0);

        let recovery_xonly_pubkey = generate_xonly_pubkey();
        let pegout_graph_params = PegOutGraphParams::default();

        let n_of_n_script = n_of_n_script(&tx_build_context.aggregated_pubkey()).compile();
        let take_back_script =
            drt_take_back(recovery_xonly_pubkey, pegout_graph_params.refund_delay);

        let spend_path = SpendPath::ScriptSpend {
            scripts: &[n_of_n_script, take_back_script],
        };

        let (deposit_request_addr, _) = create_taproot_addr(&network, spend_path)
            .expect("must be able to generate taproot address for drt");

        let stake_index = 1;
        let ee_address = [0u8; 20];
        let total_amount = Amount::from_int_btc(11);
        let deposit_info = DepositInfo::new(
            OutPoint::null(),
            stake_index,
            ee_address.to_vec(),
            total_amount,
            recovery_xonly_pubkey,
            deposit_request_addr.script_pubkey(),
        );

        let signing_data = deposit_info
            .construct_signing_data(&tx_build_context, &pegout_graph_params, &sidesystem_params)
            .expect("must be able to construct signing data");
        let deposit_tx = signing_data.psbt.unsigned_tx;

        let expected_metadata = [
            pegout_graph_params.tag.as_bytes(),
            &stake_index.to_be_bytes(),
            &ee_address,
            &recovery_xonly_pubkey.serialize(),
            &total_amount.to_sat().to_be_bytes(),
        ]
        .concat();

        let Some(op_return_out) = deposit_tx.output.get(1) else {
            panic!("must have a second output");
        };
        let script_pubkey = &op_return_out.script_pubkey;

        assert!(
            script_pubkey.is_op_return(),
            "second output must be an OP_RETURN"
        );

        let mut instructions = script_pubkey.instructions();
        instructions.next(); // consume the OP_RETURN instruction

        let Some(Ok(Instruction::PushBytes(data))) = instructions.next() else {
            panic!("the second output must have some PushBytes instruction and data");
        };

        assert_eq!(
            data.as_bytes(),
            expected_metadata,
            "the metadata in the second output must be equal to the expected metadata"
        );
    }
}
