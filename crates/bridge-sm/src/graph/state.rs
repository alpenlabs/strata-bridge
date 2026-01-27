//! The States for the Graph State Machine.

/// The state of a pegout graph associated with a particular deposit.
/// Each graph is uniquely identified by the two-tuple (depositIdx, operatorIdx)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GraphState {
    /// A new deposit request has been identified
    Created,
    /// The pegout graph for this deposit and operator has been generated
    GraphGenerated,
    /// All adaptors for this pegout graph have been verified
    AdaptorsVerified,
    /// All required nonces for this pegout graph have been collected
    NoncesCollected,
    /// All required aggregate signatures for this pegout graph have been collected
    GraphSigned,
    /// The deposit associated with this pegout graph has been assigned
    Assigned,
    /// The pegout graph has been activated to initiate reimbursement (this is redundant w.r.t.
    /// to the DSM's `Fulfilled` state, but is included here in order to preserve relative
    /// independence of GSM to recognize faulty claims)
    Fulfilled,
    /// The claim transaction has been posted on chain
    Claimed,
    /// The contest transaction has been posted on chain
    Contested,
    /// The bridge proof transaction has been posted on chain
    BridgeProofPosted,
    /// The bridge proof timeout transaction has been posted on chain
    BridgeProofTimedout,
    /// A counterproof transaction has been posted on chain
    CounterProofPosted,
    /// All possible counterproof transactions have been NACK'd on chain
    AllNackd,
    /// A counterproof has been ACK'd on chain
    Acked,
    /// The deposit output has been spent by either uncontested or contested payout
    Withdrawn,
    /// The operator has been slashed on chain
    Slashed,
}

impl GraphState {
    /// Constructs a new [`GraphState`] in the [`GraphState::Created`] variant.
    pub const fn new() -> Self {
        GraphState::Created
    }
}

impl Default for GraphState {
    fn default() -> Self {
        Self::new()
    }
}
