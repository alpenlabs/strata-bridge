//! Builders related to building deposit-related transactions.
//!
//! Contains types, traits and implementations related to creating various transactions used in the
//! bridge-in dataflow.

use alpen_bridge_params::prelude::PegOutGraphParams;
use bitcoin::{
    sighash::Prevouts, taproot::LeafVersion, Amount, OutPoint, Psbt, ScriptBuf, TapNodeHash,
    TapSighashType, TxOut, XOnlyPublicKey,
};
use serde::{Deserialize, Serialize};
use strata_bridge_primitives::{
    build_context::BuildContext,
    errors::{BridgeTxBuilderError, BridgeTxBuilderResult, DepositTransactionError},
    scripts::{
        general::{create_tx, create_tx_ins, create_tx_outs},
        prelude::*,
        taproot::{create_taproot_addr, SpendPath},
    },
};
use strata_primitives::params::RollupParams;

use super::prelude::CovenantTx;

/// The deposit information  required to create the Deposit Transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositRequestData {
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

impl DepositRequestData {
    /// Create a new deposit info with all the necessary data required to create a deposit
    /// transaction.
    pub const fn new(
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
    pub const fn total_amount(&self) -> &Amount {
        &self.total_amount
    }

    /// Get the stake index.
    pub const fn stake_index(&self) -> u32 {
        self.stake_index
    }

    /// Get the address in EL to mint tokens to.
    pub fn el_address(&self) -> &[u8] {
        &self.ee_address
    }

    /// Get the outpoint of the Deposit Request Transaction (DRT) that is to spent in the Deposit
    /// Transaction (DT).
    pub const fn deposit_request_outpoint(&self) -> &OutPoint {
        &self.deposit_request_outpoint
    }

    /// Get the x-only public key of the user-takes-back leaf in the taproot of the Deposit Request
    /// Transaction (DRT).
    pub const fn x_only_public_key(&self) -> &XOnlyPublicKey {
        &self.x_only_public_key
    }
}

impl DepositRequestData {
    /// Validates that the taproot address computed from the x-only public key in the DRT and the
    /// MuSig2 aggregated bridge public key is the same as the output address in the DRT.
    pub fn validate(
        &self,
        build_context: &impl BuildContext,
        refund_delay: u16,
    ) -> BridgeTxBuilderResult<()> {
        // Compute the merkle root using the x-only public key in the OP_RETURN
        let recovery_xonly_pubkey = self.x_only_public_key();
        let takeback_script = drt_take_back(*recovery_xonly_pubkey, refund_delay);

        let spend_path = SpendPath::Both {
            internal_key: build_context.aggregated_pubkey(),
            scripts: &[takeback_script],
        };

        let (address, _spend_info) =
            create_taproot_addr(&build_context.network(), spend_path).unwrap();

        let expected_spk = &self.original_script_pubkey;

        if address.script_pubkey() != *expected_spk {
            return Err(BridgeTxBuilderError::DepositTransaction(
                DepositTransactionError::InvalidTapLeafHash,
            ));
        }

        Ok(())
    }
}

/// The Deposit Transaction constructed off of the information in the Deposit Request Transaction
/// (aka [`DepositRequestData`]).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DepositTx {
    psbt: Psbt,
    prevouts: [TxOut; 1],
    witnesses: [TaprootWitness; 1],
}

impl DepositTx {
    /// Constructs the psbt for the Deposit Transaction.
    ///
    /// In other words, this function converts the [`DepositRequestData`] to an actual (unsigned)
    /// Deposit Transaction.
    pub fn new<C: BuildContext>(
        data: &DepositRequestData,
        build_context: &C,
        pegout_graph_params: &PegOutGraphParams,
        sidesystem_params: &RollupParams,
    ) -> BridgeTxBuilderResult<Self> {
        let PegOutGraphParams {
            tag,
            deposit_amount,
            refund_delay,
            ..
        } = pegout_graph_params;

        data.validate(build_context, pegout_graph_params.refund_delay)?;
        let prevouts = [TxOut {
            script_pubkey: data.original_script_pubkey.clone(),
            value: data.total_amount,
        }];
        // First, create the inputs
        let outpoint = data.deposit_request_outpoint();
        let tx_ins = create_tx_ins([*outpoint]);

        // Create and validate the OP_RETURN metadata
        let takeback_script = drt_take_back(*data.x_only_public_key(), *refund_delay);
        let takeback_script_hash =
            TapNodeHash::from_script(&takeback_script, LeafVersion::TapScript);

        let deposit_metadata = DepositMetadata::DepositTx {
            stake_index: data.stake_index(),
            ee_address: data.ee_address.to_vec(),
            takeback_hash: takeback_script_hash,
            input_amount: data.total_amount,
        };

        // Validate EE address size
        if data.el_address().len() != sidesystem_params.address_length as usize {
            return Err(DepositTransactionError::InvalidEeAddressSize(
                data.el_address().len(),
                sidesystem_params.address_length as usize,
            )
            .into());
        }

        let metadata = AuxiliaryData::new(*tag, deposit_metadata);

        let metadata_script = metadata_script(metadata);
        let metadata_amount = Amount::from_int_btc(0);

        // Then create the taproot script pubkey with keypath spend for the actual deposit
        let spend_path = SpendPath::KeySpend {
            internal_key: build_context.aggregated_pubkey(),
        };

        let (bridge_addr, _) = create_taproot_addr(&build_context.network(), spend_path)?;

        let bridge_in_script_pubkey = bridge_addr.script_pubkey();

        let tx_outs = create_tx_outs([
            (bridge_in_script_pubkey, *deposit_amount),
            (metadata_script, metadata_amount),
        ]);

        let unsigned_tx = create_tx(tx_ins, tx_outs);

        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)?;

        for (i, input) in psbt.inputs.iter_mut().enumerate() {
            input.witness_utxo = Some(prevouts[i].clone());
            input.sighash_type = Some(TapSighashType::Default.into());
        }

        let witnesses = [TaprootWitness::Tweaked {
            tweak: takeback_script_hash,
        }];

        Ok(Self {
            psbt,
            prevouts,
            witnesses,
        })
    }
}

impl CovenantTx<1> for DepositTx {
    fn psbt(&self) -> &Psbt {
        &self.psbt
    }

    fn psbt_mut(&mut self) -> &mut Psbt {
        &mut self.psbt
    }

    fn prevouts(&self) -> bitcoin::sighash::Prevouts<'_, TxOut> {
        Prevouts::All(&self.prevouts)
    }

    fn witnesses(&self) -> &[TaprootWitness; 1] {
        &self.witnesses
    }

    fn input_amount(&self) -> Amount {
        self.psbt
            .inputs
            .iter()
            .map(|input| {
                input
                    .witness_utxo
                    .as_ref()
                    .expect("should have witness utxo")
                    .value
            })
            .sum()
    }

    fn compute_txid(&self) -> bitcoin::Txid {
        self.psbt.unsigned_tx.compute_txid()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use bitcoin::{script::Instruction, Network};
    use secp256k1::PublicKey;
    use strata_bridge_primitives::{
        build_context::TxBuildContext,
        errors::{BridgeTxBuilderError, DepositTransactionError},
    };
    use strata_bridge_test_utils::prelude::{
        create_drt_taproot_output, generate_keypairs, generate_pubkey_table, generate_xonly_pubkey,
    };
    use strata_primitives::{operator::OperatorPubkeys, params::OperatorConfig};

    use super::*;

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
        let deposit_info = DepositRequestData::new(
            deposit_request_outpoint,
            1,
            [0u8; 20].to_vec(),
            deposit_amt,
            recovery_xonly_pk,
            drt_output_address.address().script_pubkey(),
        );

        let result = deposit_info.validate(&tx_builder, refund_delay);
        assert!(
            result.is_ok(),
            "should build the prevout for DT from the deposit info, error: {:?}",
            result.err().unwrap()
        );

        // Handles incorrect merkle proof
        let random_xonly_pubkey = generate_xonly_pubkey();
        let deposit_info = DepositRequestData::new(
            deposit_request_outpoint,
            1,
            [0u8; 20].to_vec(),
            deposit_amt,
            random_xonly_pubkey,
            drt_output_address.address().script_pubkey(),
        );

        let result = deposit_info.validate(&tx_builder, refund_delay);

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
    fn test_construct_psbt() {
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

        let deposit_request_data = DepositRequestData::new(
            deposit_request_outpoint,
            1,
            [0u8; 20].to_vec(),
            deposit_amt,
            recovery_xonly_pk,
            drt_output_address.address().script_pubkey(),
        );

        let deposit_amt = Amount::from_int_btc(1);
        let result = DepositTx::new(
            &deposit_request_data,
            &tx_builder,
            &PegOutGraphParams::default(),
            &test_sidesystem_params::<Vec<_>>(None),
        );
        assert!(
            result.is_ok(),
            "should build the prevout for DT from the deposit info, error: {:?}",
            result.err().unwrap()
        );

        let deposit_tx = result.unwrap();
        assert_eq!(deposit_tx.psbt().unsigned_tx.input.len(), 1);
        assert_eq!(deposit_tx.psbt().unsigned_tx.output.len(), 2);

        // test with invalid EL address
        const INVALID_LENGTH: usize = 21;
        let deposit_request_data = DepositRequestData::new(
            deposit_request_outpoint,
            1,
            [0u8; 21].to_vec(),
            deposit_amt,
            recovery_xonly_pk,
            drt_output_address.address().script_pubkey(),
        );

        let result = DepositTx::new(
            &deposit_request_data,
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

        let deposit_request_data = DepositRequestData::new(
            deposit_request_outpoint,
            1,
            [0u8; 20].to_vec(),
            deposit_amt,
            random_xonly_pk,
            drt_output_address.address().script_pubkey(),
        );

        let result = DepositTx::new(
            &deposit_request_data,
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

        let take_back_script =
            drt_take_back(recovery_xonly_pubkey, pegout_graph_params.refund_delay);
        let take_back_script_hash =
            TapNodeHash::from_script(&take_back_script, LeafVersion::TapScript);

        let spend_path = SpendPath::Both {
            internal_key: tx_build_context.aggregated_pubkey(),
            scripts: &[take_back_script],
        };

        let (deposit_request_addr, _) = create_taproot_addr(&network, spend_path)
            .expect("must be able to generate taproot address for drt");

        let stake_index = 1;
        let ee_address = [0u8; 20];
        let total_amount = Amount::from_int_btc(11);
        let deposit_request_data = DepositRequestData::new(
            OutPoint::null(),
            stake_index,
            ee_address.to_vec(),
            total_amount,
            recovery_xonly_pubkey,
            deposit_request_addr.script_pubkey(),
        );

        let deposit_tx = DepositTx::new(
            &deposit_request_data,
            &tx_build_context,
            &pegout_graph_params,
            &sidesystem_params,
        )
        .expect("must be able to construct signing data");
        let deposit_tx = deposit_tx.psbt.unsigned_tx;

        let expected_metadata = [
            pegout_graph_params.tag.as_bytes(),
            &stake_index.to_be_bytes(),
            &ee_address,
            take_back_script_hash.as_ref(),
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

/// Property tests for the deposit transaction.
pub mod prop_tests {

    use bitcoin::{hashes::sha256d, Amount, Network, OutPoint, Txid, XOnlyPublicKey};
    use proptest::{prelude::*, prop_compose};
    use strata_bridge_primitives::{
        operator_table::prop_test_generators::arb_btc_key,
        scripts::{
            prelude::drt_take_back,
            taproot::{create_taproot_addr, SpendPath},
        },
    };

    use super::DepositRequestData;

    prop_compose! {
        fn arb_txid()(bs in any::<[u8; 32]>()) -> Txid {
            Txid::from_raw_hash(*sha256d::Hash::from_bytes_ref(&bs))
        }
    }

    prop_compose! {
        /// Generates a random deposit request data.
        pub fn arb_deposit_request_data(
            deposit_amount: Amount,
            refund_delay: u16,
            aggregated_pubkey: XOnlyPublicKey
        )(
            deposit_request_txid in arb_txid(),
            stake_index in 1..100u32,
            ee_address in proptest::collection::vec(any::<u8>(), 20),
            excess_deposit_amount in 100_000..500_000u64,
            x_only_public_key in arb_btc_key().prop_map(|x|x.x_only_public_key().0),
        ) -> DepositRequestData {

            let take_back_script = drt_take_back(x_only_public_key, refund_delay);

            let spend_path = SpendPath::Both {
                internal_key: aggregated_pubkey,
                scripts: &[take_back_script],
            };

            let (deposit_request_addr, _) = create_taproot_addr(&Network::Regtest, spend_path)
                .expect("must be able to generate taproot address for drt");

            DepositRequestData {
                deposit_request_outpoint: OutPoint::new(deposit_request_txid, 0),
                stake_index,
                ee_address,
                total_amount: deposit_amount + Amount::from_sat(excess_deposit_amount),
                x_only_public_key,
                original_script_pubkey: deposit_request_addr.script_pubkey(),
            }
        }
    }
}
