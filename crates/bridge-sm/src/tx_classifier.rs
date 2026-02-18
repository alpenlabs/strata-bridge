//! Defines a trait for all state machines to accept transaction IDs and classify them into
//! acceptable events if relevant.

use bitcoin::Transaction;
use strata_bridge_primitives::types::BitcoinBlockHeight;

use crate::state_machine::StateMachine;

/// Classifies raw Bitcoin transactions into typed State Machine Events.
///
/// Implementers use their own internal state (known txids, graph summaries,
/// current state, etc.) to decide relevance and produce the correct event variant
/// in a single pass.
pub trait TxClassifier: StateMachine {
    /// Classifies a transaction ID into an event if relevant to this state machine.
    ///
    /// Returns `None` if the transaction is not relevant to this state machine, or `Some(event)` if
    /// it is.
    fn classify_tx(
        &self,
        config: &Self::Config,
        tx: &Transaction,
        height: BitcoinBlockHeight,
    ) -> Option<Self::Event>;
}
