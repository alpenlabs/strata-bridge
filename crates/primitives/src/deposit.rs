//! Builders related to building deposit-related transactions.
//!
//! Contains types, traits and implementations related to creating various transactions used in the
//! bridge-in dataflow.

#![expect(deprecated)]

use alpen_bridge_params::{prelude::PegOutGraphParams, types::Tag};
use bitcoin::{
    taproot::LeafVersion, Amount, OutPoint, Psbt, ScriptBuf, TapNodeHash, Transaction, TxOut,
    XOnlyPublicKey,
};
use serde::{Deserialize, Serialize};
use strata_primitives::params::RollupParams;

use crate::{
    build_context::BuildContext,
    errors::{BridgeTxBuilderError, BridgeTxBuilderResult, DepositTransactionError},
    scripts::{
        general::{create_tx, create_tx_ins, create_tx_outs},
        prelude::*,
        taproot::{create_taproot_addr, SpendPath},
    },
};

/// The deposit information  required to create the Deposit Transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[deprecated = "this has been moved to strata_bridge-tx-graph as `DepositRequestData` and will be removed along with the `strata-bridge-agent` crate in the future"]
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

    /// Constructs the data required to construct the Deposit Transaction.
    ///
    /// In other words, this function converts the [`DepositInfo`] to an actual (unsigned) Deposit
    /// Transaction.
    pub fn construct_psbt<C: BuildContext>(
        &self,
        build_context: &C,
        pegout_graph_params: &PegOutGraphParams,
        sidesystem_params: &RollupParams,
    ) -> BridgeTxBuilderResult<Psbt> {
        let PegOutGraphParams {
            tag,
            deposit_amount,
            ..
        } = pegout_graph_params;

        self.validate(build_context, pegout_graph_params.refund_delay)?;

        let prevouts = self.compute_prevouts();
        let unsigned_tx = self.create_unsigned_tx(
            build_context,
            *deposit_amount,
            *tag,
            sidesystem_params.address_length as usize,
            pegout_graph_params.refund_delay,
        )?;

        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)?;

        for (i, input) in psbt.inputs.iter_mut().enumerate() {
            input.witness_utxo = Some(prevouts[i].clone());
        }

        Ok(psbt)
    }

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
        tag: Tag,
        ee_address_size: usize,
        refund_delay: u16,
    ) -> BridgeTxBuilderResult<Transaction> {
        // First, create the inputs
        let outpoint = self.deposit_request_outpoint();
        let tx_ins = create_tx_ins([*outpoint]);

        // Create and validate the OP_RETURN metadata
        let takeback_script = drt_take_back(*self.x_only_public_key(), refund_delay);
        let takeback_script_hash =
            TapNodeHash::from_script(&takeback_script, LeafVersion::TapScript);

        let deposit_metadata = DepositMetadata::DepositTx {
            stake_index: self.stake_index(),
            ee_address: self.ee_address.to_vec(),
            takeback_hash: takeback_script_hash,
            input_amount: self.total_amount,
        };

        // Validate EE address size
        if self.ee_address.len() != ee_address_size {
            return Err(DepositTransactionError::InvalidEeAddressSize(
                self.ee_address.len(),
                ee_address_size,
            )
            .into());
        }

        let metadata = AuxiliaryData::new(tag, deposit_metadata);

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
