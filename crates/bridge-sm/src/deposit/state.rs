//! The States for the Deposit State Machine.
//!
//! This module defines the various states that a deposit can be in during its lifecycle
//! with respect to the multisig. Each state represents a specific point in the process
//! of handling a deposit, from the initial request to the final spend.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
};

use bitcoin::{Amount, Network, Transaction, Txid, XOnlyPublicKey, relative::LockTime};
use bitcoin_bosd::Descriptor;
use musig2::{AggNonce, PartialSignature, PubNonce};
use serde::{Deserialize, Serialize};
use strata_bridge_connectors2::{n_of_n::NOfNConnector, prelude::DepositRequestConnector};
use strata_bridge_primitives::types::{BitcoinBlockHeight, OperatorIdx};
use strata_bridge_tx_graph2::transactions::{deposit::DepositTx, prelude::DepositData};

/// The state of a Deposit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DepositState {
    /// This state represents the initial phase after deposit request confirmation.
    ///
    /// This happens from the confirmation of the deposit request transaction until all operators
    /// have generated and linked their graphs for this deposit.
    Created {
        /// The unsigned deposit transaction derived from the deposit request.
        deposit_transaction: DepositTx,

        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Operators whose pegout graphs have been generated for this deposit transaction.
        linked_graphs: BTreeSet<OperatorIdx>,
    },
    /// This state represents the phase where all operator graphs have been generated.
    ///
    /// This happens from the point where all operator graphs are generated until all public nonces
    /// required to sign the deposit transaction are collected.
    GraphGenerated {
        /// The unsigned deposit transaction to be signed.
        deposit_transaction: DepositTx,

        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Public nonces provided by each operator for signing.
        pubnonces: BTreeMap<OperatorIdx, PubNonce>,
    },
    /// This state represents the phase where all deposit public nonces have been collected.
    ///
    /// This happens from the collection of all deposit public nonces until all partial signatures
    /// have been received or, possibly, when the deposit transaction appears on chain.
    DepositNoncesCollected {
        /// The deposit transaction being signed.
        deposit_transaction: DepositTx,

        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// Aggregated nonce used to validate partial signatures.
        agg_nonce: AggNonce,

        /// Public nonces provided by each operator for signing.
        pubnonces: BTreeMap<OperatorIdx, PubNonce>,

        /// Partial signatures from operators for the deposit transaction.
        partial_signatures: BTreeMap<OperatorIdx, PartialSignature>,
    },
    /// This state represents the phase where all partial signatures have been collected.
    ///
    /// This happens from the collection of all partial signatures until the deposit transaction
    /// is broadcast and confirmed.
    DepositPartialsCollected {
        /// Latest Bitcoin block height observed by the state machine.
        last_block_height: BitcoinBlockHeight,

        /// The fully signed deposit transaction.
        deposit_transaction: Transaction,
    },
    /// This state indicates that the deposit transaction has been confirmed on-chain.
    Deposited {
        /// The last block height observed by this state machine.
        last_block_height: u64,
    },
    /// This state indicates that this deposit has been assigned for withdrawal.
    Assigned {
        /// The last block height observed by this state machine.
        last_block_height: u64,
        /// The index of the operator assigned to fulfill the withdrawal request.
        assignee: OperatorIdx,
        /// The block height by which the operator must fulfill the withdrawal request.
        deadline: BitcoinBlockHeight,
        /// The user's descriptor where funds are to be sent by the operator.
        recipient_desc: Descriptor,
    },
    /// This state indicates that the operator has fronted the user.
    Fulfilled {
        /// The last block height observed by this state machine.
        last_block_height: u64,
        /// The index of the operator assigned to fulfill the withdrawal request.
        assignee: OperatorIdx,
        /// The txid of the fulfillment transaction.
        fulfillment_txid: Txid,
        /// The block height where the fulfillment transaction was confirmed.
        fulfillment_height: BitcoinBlockHeight,
        /// The block height by which the cooperative payout is attempted.
        cooperative_payout_deadline: BitcoinBlockHeight,
    },
    /// This state indicates that the descriptor of the operator for the cooperative payout has been
    /// received.
    PayoutDescriptorReceived {
        /// The last block height observed by this state machine.
        last_block_height: u64,
        /// The index of the operator assigned to fulfill the withdrawal request.
        assignee: OperatorIdx,
        /// The block height by which the cooperative payout must be completed.
        cooperative_payment_deadline: BitcoinBlockHeight,
        /// The operator's descriptor to send the funds via the cooperative path.
        /// This can only be set once and needs to be provided by the assigned operator.
        operator_desc: Descriptor,
        /// The pubnonces, indexed by operator, required to sign the cooperative payout
        /// transaction.
        payout_nonces: BTreeMap<OperatorIdx, PubNonce>,
    },
    /// This state indicates that all pubnonces required for the cooperative payout have been
    /// collected.
    PayoutNoncesCollected {
        /// The last block height observed by this state machine.
        last_block_height: u64,
        /// The index of the operator assigned to fulfill the withdrawal request.
        assignee: OperatorIdx,
        /// The operator's descriptor where they want the funds in the cooperative path.
        operator_desc: Descriptor,
        /// The block height by which the cooperative payout must be completed.
        cooperative_payment_deadline: BitcoinBlockHeight,
        /// The pubnonces, indexed by operator, required to sign the cooperative payout
        /// transaction.
        payout_nonces: BTreeMap<OperatorIdx, PubNonce>,
        /// The aggregated nonce for signing the cooperative payout transaction.
        payout_aggregated_nonce: AggNonce,
        /// The partial signatures, indexed by operator, for signing the cooperative payout
        /// transaction.
        payout_partial_signatures: BTreeMap<OperatorIdx, PartialSignature>,
    },
    /// This state represents the scenario where the cooperative payout path has failed.
    ///
    /// This happens if the assignee was not able to collect the requisite nonces/partials for
    /// the cooperative payout transaction.
    CooperativePathFailed {
        /// The height of the latest block that this state machine is aware of.
        last_block_height: u64,
    },
    /// This represents the terminal state where the deposit has been spent.
    Spent,
    /// TODO: (@Rajil1213)
    Aborted,
}

impl Display for DepositState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let display_str = match self {
            DepositState::Created { .. } => "Created".to_string(),
            DepositState::GraphGenerated { .. } => "GraphGenerated".to_string(),
            DepositState::DepositNoncesCollected { .. } => "DepositNoncesCollected".to_string(),
            DepositState::DepositPartialsCollected { .. } => "DepositPartialsCollected".to_string(),
            DepositState::Deposited { .. } => "Deposited".to_string(),
            DepositState::Assigned { .. } => "Assigned".to_string(),
            DepositState::Fulfilled { .. } => "Fulfilled".to_string(),
            DepositState::PayoutDescriptorReceived { .. } => "PayoutDescriptorReceived".to_string(),
            DepositState::PayoutNoncesCollected { .. } => "PayoutNoncesCollected".to_string(),
            DepositState::CooperativePathFailed { .. } => "CooperativePathFailed".to_string(),
            DepositState::Spent => "Spent".to_string(),
            DepositState::Aborted => "Aborted".to_string(),
        };
        write!(f, "{}", display_str)
    }
}

impl DepositState {
    /// Constructs a new [`DepositState`] in the [`DepositState::Created`] variant.
    ///
    /// Initializes the required connectors and builds the deposit transaction from the provided
    /// deposit parameters, recording the current `block_height`.
    pub fn new(
        deposit_ammount: Amount,
        deposit_time_lock: LockTime,
        network: Network,
        deposit_data: DepositData,
        depositor_pubkey: XOnlyPublicKey,
        n_of_n_pubkey: XOnlyPublicKey,
        block_height: BitcoinBlockHeight,
    ) -> Self {
        let deposit_request_connetor = DepositRequestConnector::new(
            network,
            n_of_n_pubkey,
            depositor_pubkey,
            deposit_time_lock,
            deposit_ammount,
        );
        let non_connector = NOfNConnector::new(network, n_of_n_pubkey, deposit_ammount);

        let deposit_transaction =
            DepositTx::new(deposit_data, non_connector, deposit_request_connetor);

        DepositState::Created {
            deposit_transaction,
            last_block_height: block_height,
            linked_graphs: BTreeSet::new(),
        }
    }

    /// Returns the height of the last processed Bitcoin block for this deposit state.
    pub const fn last_processed_block_height(&self) -> Option<&BitcoinBlockHeight> {
        match self {
            DepositState::Created {
                last_block_height: block_height,
                ..
            }
            | DepositState::GraphGenerated {
                last_block_height: block_height,
                ..
            }
            | DepositState::DepositNoncesCollected {
                last_block_height: block_height,
                ..
            }
            | DepositState::DepositPartialsCollected {
                last_block_height: block_height,
                ..
            }
            | DepositState::Deposited {
                last_block_height: block_height,
                ..
            }
            | DepositState::Assigned {
                last_block_height: block_height,
                ..
            }
            | DepositState::Fulfilled {
                last_block_height: block_height,
                ..
            }
            | DepositState::PayoutDescriptorReceived {
                last_block_height: block_height,
                ..
            }
            | DepositState::PayoutNoncesCollected {
                last_block_height: block_height,
                ..
            }
            | DepositState::CooperativePathFailed {
                last_block_height: block_height,
                ..
            } => Some(block_height),
            DepositState::Spent | DepositState::Aborted => {
                // Terminal states do not track block height
                None
            }
        }
    }
}
