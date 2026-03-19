//! Duties for the Stake State Machine.

use bitcoin::Transaction;
use musig2::AggNonce;
use strata_bridge_primitives::types::OperatorIdx;
use strata_bridge_tx_graph::stake_graph::{StakeData, StakeGraph};

/// A duty of a Stake State Machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StakeDuty {
    /// Publish the stake data for a given operator.
    PublishStakeData {
        /// The operator who owns the stake graph.
        operator_idx: OperatorIdx,
    },
    /// Publish the stake transaction.
    PublishStake {
        /// The unsigned stake transaction.
        tx: Transaction,
    },
    /// Publish the nonces for a given operator.
    PublishUnstakingNonces {
        /// Data that is required to construct the stake graph.
        stake_data: StakeData,
    },
    /// Publish the partial signatures for a given operator.
    PublishUnstakingPartials {
        /// Data that is required to construct the stake graph.
        stake_data: StakeData,
        /// 1 aggregated per musig transaction input.
        agg_nonces: Box<[AggNonce; StakeGraph::N_MUSIG_INPUTS]>,
    },
    /// Publish the unstaking intent transaction.
    PublishUnstakingIntent {
        /// Data that is required to construct the stake graph.
        stake_data: StakeData,
    },
    /// Publish the unstaking transaction.
    PublishUnstakingTx {
        /// Data that is required to construct the stake graph.
        stake_data: StakeData,
    },
    /// Nag a given operator to provide missing data.
    Nag(NagDuty),
}

/// A nag duty of a Stake State Machine.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NagDuty {
    /// Nag an operator for missing stake data.
    NagStakeData {
        /// The operator who is nagged.
        operator_idx: OperatorIdx,
    },
    /// Nag an operator for missing nonces.
    NagUnstakingNonces {
        /// The operator who is nagged.
        operator_idx: OperatorIdx,
    },
    /// Nag an operator for missing partial signatures.
    NagUnstakingPartials {
        /// The operator who is nagged.
        operator_idx: OperatorIdx,
    },
}

impl std::fmt::Display for StakeDuty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let display = match self {
            Self::PublishStakeData { operator_idx } => {
                format!("PublishStakeData (operator_idx: {operator_idx})")
            }
            Self::PublishStake { .. } => "PublishStake".to_string(),
            Self::PublishUnstakingNonces { .. } => "PublishUnstakingNonces".to_string(),
            Self::PublishUnstakingPartials { .. } => "PublishUnstakingPartials".to_string(),
            Self::PublishUnstakingIntent { .. } => "PublishUnstakingIntent".to_string(),
            Self::PublishUnstakingTx { .. } => "PublishUnstakingTx".to_string(),
            Self::Nag(duty) => format!("Nag ({duty})"),
        };

        write!(f, "{display}")
    }
}

impl std::fmt::Display for NagDuty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NagStakeData { operator_idx } => {
                write!(f, "NagStakeData (operator_idx: {operator_idx})")
            }
            Self::NagUnstakingNonces { operator_idx } => {
                write!(f, "NagUnstakingNonces (operator_idx: {operator_idx})")
            }
            Self::NagUnstakingPartials { operator_idx } => {
                write!(f, "NagUnstakingPartials (operator_idx: {operator_idx})")
            }
        }
    }
}
