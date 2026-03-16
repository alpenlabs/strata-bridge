//! Configuration shared across all graph state machines.

use bitcoin::{Amount, XOnlyPublicKey};
use bitcoin_bosd::Descriptor;
use strata_bridge_tx_graph::game_graph::ProtocolParams;

/// Bridge-wide configuration shared across all graph state machines.
///
/// These configurations are static over the lifetime of the bridge protocol
/// and apply uniformly to all graph state machine instances.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GraphSMCfg {
    /// Parameters of the Game Graph that are inherent to the protocol.
    pub game_graph_params: ProtocolParams,

    /// Fees paid to the operator for fronting a user.
    pub operator_fee: Amount,

    /// Key used in the locking script of a contest transaction.
    // NOTE: (@Rajil1213) we might need to get this from `Mosaic` per deposit at runtime instead.
    // Until mosaic is developed, use the same adaptor key for all operators to facilitate
    // mosaic-less demo.
    pub operator_adaptor_keys: Vec<XOnlyPublicKey>,

    /// Key that locks the payout connector output.
    ///
    /// Signature corresponding to this key can be used to block payouts to the operator.
    pub admin_pubkey: XOnlyPublicKey,

    /// Key used to lock the counterproof-nack output.
    ///
    /// Signature corresponding to this key can be used by an operator to defend against a
    /// counterproof. This signature is produced by Mosaic as a result of a successful GC
    /// evaluation.
    // NOTE: (@Rail1213) we might need to get this from `Mosaic` per deposit at runtime instead.
    pub watchtower_fault_pubkeys: Vec<XOnlyPublicKey>,

    /// Descriptor to which payouts are to be sent in case of a successful peg out.
    pub payout_descs: Vec<Descriptor>,
}
