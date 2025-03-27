use bitcoin::{Amount, OutPoint, TapNodeHash};
use bitcoin_bosd::Descriptor;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use serde::{Deserialize, Serialize};
use strata_bridge_primitives::{
    bitcoin::BitcoinAddress,
    types::{BitcoinBlockHeight, OperatorIdx},
};

// HACK: convert from `strata` type to `strata-bridge` type
// to avoid having to use all the deposit/withdrawal types from
// `strata`. This is fine for now since these duties will be generated
// by `strata-bridge` directly in the immediate future.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositInfoInterop {
    /// The deposit request transaction outpoints from the users.
    pub deposit_request_outpoint: OutPoint,

    /// The execution layer address to mint the equivalent tokens to.
    /// As of now, this is just the 20-byte EVM address.
    pub el_address: Vec<u8>,

    /// The amount in bitcoins that the user is sending.
    ///
    /// This amount should be greater than the `BRIDGE_DENOMINATION`
    /// for the deposit to be confirmed
    /// on bitcoin. The excess amount is used as miner fees for the
    /// Deposit Transaction.
    pub total_amount: Amount,

    /// The hash of the take back leaf in the Deposit Request
    /// Transaction (DRT) as provided by the
    /// user in their `OP_RETURN` output.
    pub take_back_leaf_hash: TapNodeHash,

    /// The original taproot address in the Deposit Request Transaction
    /// (DRT) output used to
    /// sanity check computation internally i.e., whether the known
    /// information (n/n script spend
    /// path, `static@UNSPENDABLE_INTERNAL_KEY`) + the
    /// [`Self::take_back_leaf_hash`] yields the
    /// same P2TR address.
    pub original_taproot_addr: BitcoinAddress,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CooperativeWithdrawalInfoInterop {
    /// The [`OutPoint`] of the UTXO in the Bridge Address that is to
    /// be used to service the
    /// withdrawal request.
    pub deposit_outpoint: OutPoint,

    /// The BOSD [`Descriptor`] supplied by the user.
    pub user_destination: Descriptor,

    /// The index of the operator that is assigned the withdrawal.
    pub assigned_operator_idx: OperatorIdx,

    /// The bitcoin block height before which the withdrawal has to be
    /// processed.
    ///
    /// Any withdrawal request whose `exec_deadline` is before the
    /// current bitcoin block height is
    /// considered stale and must be ignored.
    pub exec_deadline: BitcoinBlockHeight,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum BridgeDutyInterop {
    SignDeposit(DepositInfoInterop),
    FulfillWithdrawal(CooperativeWithdrawalInfoInterop),
}

/// The duties assigned to an operator within a given range.
///
/// # Note
///
/// The `index`'s are only relevant for Deposit duties as those are stored off-chain in a database.
/// The withdrawal duties are fetched from the current chain state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcBridgeDutiesInterop {
    /// The actual [`BridgeDutyInterop`]'s assigned to an operator which includes both the deposit
    /// and withdrawal duties.
    pub duties: Vec<BridgeDutyInterop>,

    /// The starting index (inclusive) from which the duties are fetched.
    pub start_index: u64,

    /// The last block index (inclusive) upto which the duties are feched.
    pub stop_index: u64,
}

#[cfg_attr(not(feature = "client"), rpc(server, namespace = "strata"))]
#[cfg_attr(feature = "client", rpc(server, client, namespace = "strata"))]
pub trait BridgeDutyInteropTrait {
    #[method(name = "getBridgeDuties")]
    async fn get_bridge_duties(
        &self,
        operator_idx: OperatorIdx,
        start_index: u64,
    ) -> RpcResult<RpcBridgeDutiesInterop>;
}
