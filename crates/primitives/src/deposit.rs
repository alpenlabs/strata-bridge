//! Builders related to building deposit-related transactions.
//!
//! Contains types, traits and implementations related to creating various transactions used in the
//! bridge-in dataflow.

use alpen_bridge_params::prelude::{BRIDGE_DENOMINATION, UNSPENDABLE_INTERNAL_KEY};
use bitcoin::{
    key::TapTweak,
    secp256k1::SECP256K1,
    taproot::{self, ControlBlock},
    Address, Amount, OutPoint, Psbt, ScriptBuf, TapNodeHash, Transaction, TxOut,
};
use serde::{Deserialize, Serialize};

use crate::{
    build_context::{BuildContext, TxKind},
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

    /// The execution layer address to mint the equivalent tokens to.
    /// As of now, this is just the 20-byte EVM address.
    el_address: Vec<u8>,

    /// The amount in bitcoins that the user is sending.
    ///
    /// This amount should be greater than the [`BRIDGE_DENOMINATION`] for the deposit to be
    /// confirmed on bitcoin. The excess amount is used as miner fees for the Deposit Transaction.
    total_amount: Amount,

    /// The hash of the take back leaf in the Deposit Request Transaction (DRT) as provided by the
    /// user in their `OP_RETURN` output.
    take_back_leaf_hash: TapNodeHash,

    /// The original script_pubkey in the Deposit Request Transaction (DRT) output used to sanity
    /// check computation internally i.e., whether the known information (n/n script spend path,
    /// [`static@UNSPENDABLE_INTERNAL_KEY`]) + the [`Self::take_back_leaf_hash`] yields the same
    /// P2TR address.
    original_script_pubkey: ScriptBuf,
}

impl TxKind for DepositInfo {
    fn construct_signing_data<C: BuildContext>(
        &self,
        build_context: &C,
        tag: Option<&[u8]>,
    ) -> BridgeTxBuilderResult<TxSigningData> {
        let prevouts = self.compute_prevouts();
        let spend_info = self.compute_spend_infos(build_context)?;
        let unsigned_tx = self.create_unsigned_tx(
            build_context,
            tag.expect("deposit tx must have a tag in the metadata"),
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
}

impl DepositInfo {
    /// Create a new deposit info with all the necessary data required to create a deposit
    /// transaction.
    pub fn new(
        deposit_request_outpoint: OutPoint,
        el_address: Vec<u8>,
        total_amount: Amount,
        take_back_leaf_hash: TapNodeHash,
        original_script_pubkey: ScriptBuf,
    ) -> Self {
        Self {
            deposit_request_outpoint,
            el_address,
            total_amount,
            take_back_leaf_hash,
            original_script_pubkey,
        }
    }

    /// Get the total deposit amount that needs to be bridged-in.
    pub fn total_amount(&self) -> &Amount {
        &self.total_amount
    }

    /// Get the address in EL to mint tokens to.
    pub fn el_address(&self) -> &[u8] {
        &self.el_address
    }

    /// Get the outpoint of the Deposit Request Transaction (DRT) that is to spent in the Deposit
    /// Transaction (DT).
    pub fn deposit_request_outpoint(&self) -> &OutPoint {
        &self.deposit_request_outpoint
    }

    /// Get the hash of the user-takes-back leaf in the taproot of the Deposit Request Transaction
    /// (DRT).
    pub fn take_back_leaf_hash(&self) -> &TapNodeHash {
        &self.take_back_leaf_hash
    }

    fn compute_spend_infos(
        &self,
        build_context: &impl BuildContext,
    ) -> BridgeTxBuilderResult<TaprootWitness> {
        // The Deposit Request (DT) spends the n-of-n multisig leaf
        let spend_script = n_of_n_script(&build_context.aggregated_pubkey()).compile();
        let spend_script_hash =
            TapNodeHash::from_script(&spend_script, taproot::LeafVersion::TapScript);

        let takeback_script_hash = self.take_back_leaf_hash();

        let merkle_root = TapNodeHash::from_node_hashes(spend_script_hash, *takeback_script_hash);

        let address = Address::p2tr(
            SECP256K1,
            *UNSPENDABLE_INTERNAL_KEY,
            Some(merkle_root),
            build_context.network(),
        )
        .script_pubkey();

        let expected_addr = &self.original_script_pubkey;

        if address != *expected_addr {
            return Err(BridgeTxBuilderError::DepositTransaction(
                DepositTransactionError::InvalidTapLeafHash,
            ));
        }

        let (output_key, parity) = UNSPENDABLE_INTERNAL_KEY.tap_tweak(SECP256K1, Some(merkle_root));

        let control_block = ControlBlock {
            leaf_version: taproot::LeafVersion::TapScript,
            internal_key: *UNSPENDABLE_INTERNAL_KEY,
            merkle_branch: vec![*takeback_script_hash].try_into().map_err(|_| {
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
        tag: &[u8],
    ) -> BridgeTxBuilderResult<Transaction> {
        // First, create the inputs
        let outpoint = self.deposit_request_outpoint();
        let tx_ins = create_tx_ins([*outpoint]);

        // Then, create the outputs:

        // First, create the `OP_RETURN <el_address>` output
        let el_addr = self.el_address();
        let el_addr: &[u8; 20] = el_addr.try_into().map_err(|_| {
            BridgeTxBuilderError::DepositTransaction(DepositTransactionError::InvalidElAddressSize(
                el_addr.len(),
            ))
        })?;

        let metadata_script = metadata_script(el_addr, tag);
        let metadata_amount = Amount::from_int_btc(0);

        // Then create the taproot script pubkey with keypath spend for the actual deposit
        let spend_path = SpendPath::KeySpend {
            internal_key: build_context.aggregated_pubkey(),
        };

        let (bridge_addr, _) = create_taproot_addr(&build_context.network(), spend_path)?;

        let bridge_in_script_pubkey = bridge_addr.script_pubkey();

        let tx_outs = create_tx_outs([
            (bridge_in_script_pubkey, BRIDGE_DENOMINATION),
            (metadata_script, metadata_amount),
        ]);

        let unsigned_tx = create_tx(tx_ins, tx_outs);

        Ok(unsigned_tx)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alpen_bridge_params::tx::BRIDGE_DENOMINATION;
    use bitcoin::{
        hashes::{sha256, Hash},
        hex::{Case, DisplayHex},
        Network,
    };

    use super::*;
    use crate::{
        build_context::TxBuildContext,
        errors::{BridgeTxBuilderError, DepositTransactionError},
        test_utils::{create_drt_taproot_output, generate_keypairs, generate_pubkey_table},
    };

    #[test]
    fn test_create_spend_infos() {
        let (operator_pubkeys, _) = generate_keypairs(10);
        let operator_pubkeys = generate_pubkey_table(&operator_pubkeys);

        let deposit_request_outpoint = OutPoint::null();

        let (drt_output_address, take_back_leaf_hash) =
            create_drt_taproot_output(operator_pubkeys.clone());
        let self_index = 0;

        let tx_builder = TxBuildContext::new(Network::Regtest, operator_pubkeys, self_index);

        // Correct merkle proof
        let deposit_info = DepositInfo::new(
            deposit_request_outpoint,
            [0u8; 20].to_vec(),
            BRIDGE_DENOMINATION,
            take_back_leaf_hash,
            drt_output_address.address().script_pubkey(),
        );

        let result = deposit_info.compute_spend_infos(&tx_builder);
        assert!(
            result.is_ok(),
            "should build the prevout for DT from the deposit info, error: {:?}",
            result.err().unwrap()
        );

        // Handles incorrect merkle proof
        let random_hash = sha256::Hash::hash(b"random_hash")
            .to_byte_array()
            .to_hex_string(Case::Lower);
        let deposit_info = DepositInfo::new(
            deposit_request_outpoint,
            [0u8; 20].to_vec(),
            BRIDGE_DENOMINATION,
            TapNodeHash::from_str(&random_hash).unwrap(),
            drt_output_address.address().script_pubkey(),
        );

        let result = deposit_info.compute_spend_infos(&tx_builder);

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

        let (drt_output_address, take_back_leaf_hash) =
            create_drt_taproot_output(operator_pubkeys.clone());
        let self_index = 0;

        let tx_builder = TxBuildContext::new(Network::Regtest, operator_pubkeys, self_index);

        let deposit_info = DepositInfo::new(
            deposit_request_outpoint,
            [0u8; 20].to_vec(),
            BRIDGE_DENOMINATION,
            take_back_leaf_hash,
            drt_output_address.address().script_pubkey(),
        );

        let tag = b"alpen";
        let result = deposit_info.create_unsigned_tx(&tx_builder, tag);
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

        let (drt_output_address, take_back_leaf_hash) =
            create_drt_taproot_output(operator_pubkeys.clone());
        let self_index = 0;

        let tx_builder = TxBuildContext::new(Network::Regtest, operator_pubkeys, self_index);

        let deposit_info = DepositInfo::new(
            deposit_request_outpoint,
            [0u8; 20].to_vec(),
            BRIDGE_DENOMINATION,
            take_back_leaf_hash,
            drt_output_address.address().script_pubkey(),
        );

        let tag = b"alpen";
        let result = deposit_info.construct_signing_data(&tx_builder, Some(&tag[..]));
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
            [0u8; 21].to_vec(),
            BRIDGE_DENOMINATION,
            take_back_leaf_hash,
            drt_output_address.address().script_pubkey(),
        );

        let result = deposit_info.construct_signing_data(&tx_builder, Some(&tag[..]));
        assert!(
            result.is_err_and(|e| matches!(
                e,
                BridgeTxBuilderError::DepositTransaction(
                    DepositTransactionError::InvalidElAddressSize(INVALID_LENGTH)
                )
            )),
            "should handle the case where the EL address is invalid"
        );

        // test with invalid tapleaf hash
        let random_hash = sha256::Hash::hash(b"random_hash")
            .to_byte_array()
            .to_hex_string(Case::Lower);

        let deposit_info = DepositInfo::new(
            deposit_request_outpoint,
            [0u8; 20].to_vec(),
            BRIDGE_DENOMINATION,
            TapNodeHash::from_str(&random_hash).unwrap(),
            drt_output_address.address().script_pubkey(),
        );

        let result = deposit_info.construct_signing_data(&tx_builder, Some(&tag[..]));
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
}
