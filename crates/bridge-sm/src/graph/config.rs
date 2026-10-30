//! Configuration shared across all graph state machines.

use std::collections::BTreeMap;

use bitcoin::Amount;
use bitcoin_bosd::Descriptor;
use strata_bridge_primitives::types::OperatorIdx;
use strata_bridge_tx_graph::game_graph::{AdminMultisig, ProtocolParams};
use strata_predicate::PredicateKey;

/// Configuration shared across all graph state machines of this node.
///
/// Apart from [`Self::bridge_proof_delay_blocks`], which is local to this operator, these values
/// are protocol-wide and static over the lifetime of the bridge.
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

    /// Each registered operator's payout descriptor, keyed by permanent operator index.
    ///
    /// Registrations are never removed and their descriptors never change, so a graph built
    /// from this map keeps the same scripts as registrations are added.
    pub payout_descs: BTreeMap<OperatorIdx, Descriptor>,

    /// Predicate key used to verify bridge proof.
    pub bridge_proof_predicate: PredicateKey,

    /// Predicate key used to verify bridge counterproof.
    pub counterproof_predicate: PredicateKey,

    /// Number of blocks the graph owner waits past the contest confirmation before anchoring and
    /// generating the bridge proof.
    ///
    /// Operator-local: it may differ between operators and between restarts. `0` anchors at the
    /// contest block itself. A larger value commits more accumulated work in
    /// the proof; together with the bury depth it should stay well below `proof_timelock`.
    pub bridge_proof_delay_blocks: u16,
}
