//! The States for the Graph State Machine.

use std::{collections::BTreeMap, fmt::Display};

use bitcoin::{Txid, taproot::Signature};
use bitcoin_bosd::Descriptor;
use musig2::{AggNonce, PubNonce};
use strata_bridge_primitives::types::{BitcoinBlockHeight, OperatorIdx};
use strata_bridge_tx_graph2::game_graph::{GameGraph, GameGraphSummary};
use zkaleido::ProofReceipt;

/// The state of a pegout graph associated with a particular deposit.
/// Each graph is uniquely identified by the two-tuple (depositIdx, operatorIdx)
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphState {}
