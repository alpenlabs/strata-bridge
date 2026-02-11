//! The duties that need to be performed in the Graph State Machine in response to the state
//! transitions.

use bitcoin::Txid;
use musig2::AggNonce;
use strata_bridge_primitives::types::OperatorIdx;
use zkaleido::ProofReceipt;

/// The duties that need to be performed to drive the Graph State Machine forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphDuty {}
