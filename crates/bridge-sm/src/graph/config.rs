//! Configuration shared across all graph state machines.

use bitcoin::Amount;
use bitcoin_bosd::Descriptor;
use strata_bridge_tx_graph::game_graph::{AdminMultisig, ProtocolParams};
use strata_predicate::PredicateKey;

/// Bridge-wide configuration shared across all graph state machines.
///
/// These configurations are static over the lifetime of the bridge protocol
/// and apply uniformly to all graph state machine instances.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphSMCfg {
    /// Parameters of the Game Graph that are inherent to the protocol.
    pub game_graph_params: ProtocolParams,

    /// Fees paid to the operator for fronting a user.
    pub operator_fee: Amount,

    /// Admin multisig that locks the payout connector output.
    ///
    /// Signatures satisfying this threshold can be used to block payouts to the operator.
    pub admin: AdminMultisig,

    /// Descriptor to which payouts are to be sent in case of a successful peg out.
    pub payout_descs: Vec<Descriptor>,

    /// Predicate key used to verify bridge proof.
    pub bridge_proof_predicate: PredicateKey,

    /// Predicate key used to verify bridge counterproof.
    pub counterproof_predicate: PredicateKey,
}
