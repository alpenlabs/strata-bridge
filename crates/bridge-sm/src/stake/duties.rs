//! Duties for the Stake State Machine.

use bitcoin::{
    OutPoint, Transaction,
    secp256k1::{Message, XOnlyPublicKey, schnorr},
};
use musig2::AggNonce;
use strata_bridge_primitives::{
    scripts::taproot::TaprootTweak,
    types::{OperatorIdx, P2POperatorPubKey},
};
use strata_bridge_tx_graph::{
    musig_functor::StakeFunctor, transactions::prelude::UnstakingIntentTx,
};

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
        /// The index of the operator that owns the stake.
        operator_idx: OperatorIdx,
        /// The unsigned stake transaction.
        tx: Transaction,
    },
    /// Publish the nonces for a given operator.
    PublishUnstakingNonces {
        /// The index of the operator that owns the stake.
        operator_idx: OperatorIdx,

        /// The inpoints of the unstaking transaction graph used to retrieve the musig2 session
        /// from the secret-service.
        graph_inpoints: Box<StakeFunctor<OutPoint>>,

        /// The tweak required for taproot spend per input being signed.
        graph_tweaks: Box<StakeFunctor<TaprootTweak>>,

        /// The ordered public keys of all operators for MuSig2 aggregation.
        ordered_pubkeys: Vec<XOnlyPublicKey>,
    },
    /// Publish the partial signatures for a given operator.
    PublishUnstakingPartials {
        /// The index of the operator that owns the stake.
        operator_idx: OperatorIdx,

        /// The inpoints of the unstaking transaction graph used to retrieve the musig2 session
        /// from the secret-service.
        graph_inpoints: Box<StakeFunctor<OutPoint>>,

        /// The tweak required for taproot spend per input being signed.
        graph_tweaks: Box<StakeFunctor<TaprootTweak>>,

        /// Sighashes that need to signed.
        sighashes: Box<StakeFunctor<Message>>,

        /// The ordered public keys of all operators for MuSig2 aggregation.
        ordered_pubkeys: Vec<XOnlyPublicKey>,

        /// 1 aggregated per musig transaction input.
        agg_nonces: Box<StakeFunctor<AggNonce>>,
    },
    /// Publish the unstaking intent transaction.
    PublishUnstakingIntent {
        /// The unsigned unstaking intent transaction.
        unsigned_tx: Box<UnstakingIntentTx>,

        /// The stake funding outpoint used to seed the preimage generation in secret-service.
        stake_funds: OutPoint,

        /// The N/N signature for the unstaking intent transaction.
        n_of_n_signature: schnorr::Signature,
    },
    /// Publish the unstaking transaction.
    PublishUnstakingTx {
        /// The signed unstaking transaction.
        signed_tx: Transaction,
    },
    /// Nag a given operator to provide missing data.
    Nag(NagDuty),
}

/// A nag duty of a Stake State Machine.
///
/// Every variant carries two fields with a fixed interpretation:
///
/// - `operator_idx` is the owner of the stake graph this nag is about. Consumers must apply the nag
///   to the receiver's state machine for that stake graph.
/// - `operator_pubkey` is the p2p key of the peer to address: the operator we expect to send the
///   missing data back.
///
/// For [`NagDuty::NagUnstakingData`] the stake graph's owner is also the only peer that can
/// produce the data, so the two fields refer to the same operator. For nonces and partials, the
/// missing peer can be any operator that contributes to the stake graph, so they differ.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NagDuty {
    /// Nag an operator for missing stake data.
    NagUnstakingData {
        /// The owner of the stake graph this nag is about.
        operator_idx: OperatorIdx,
        /// The p2p key of the peer to address.
        operator_pubkey: P2POperatorPubKey,
    },
    /// Nag a peer for their missing nonce contribution to our stake graph.
    NagUnstakingNonces {
        /// The owner of the stake graph this nag is about.
        operator_idx: OperatorIdx,
        /// The p2p key of the peer to address.
        operator_pubkey: P2POperatorPubKey,
    },
    /// Nag a peer for their missing partial signature contribution to our stake graph.
    NagUnstakingPartials {
        /// The owner of the stake graph this nag is about.
        operator_idx: OperatorIdx,
        /// The p2p key of the peer to address.
        operator_pubkey: P2POperatorPubKey,
    },
}

impl std::fmt::Display for StakeDuty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let display = match self {
            Self::PublishStakeData { operator_idx } => {
                format!("PublishStakeData (operator_idx: {operator_idx})")
            }
            Self::PublishStake { operator_idx, .. } => {
                format!("PublishStake (operator_idx: {operator_idx})")
            }
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
            Self::NagUnstakingData { operator_idx, .. } => {
                write!(f, "NagUnstakingData (operator_idx: {operator_idx})")
            }
            Self::NagUnstakingNonces { operator_idx, .. } => {
                write!(f, "NagUnstakingNonces (operator_idx: {operator_idx})")
            }
            Self::NagUnstakingPartials { operator_idx, .. } => {
                write!(f, "NagUnstakingPartials (operator_idx: {operator_idx})")
            }
        }
    }
}
