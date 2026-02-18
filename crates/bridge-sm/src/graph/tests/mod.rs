//! Testing utilities specific to the Graph State Machine.
mod uncontested;

use std::{num::NonZero, sync::Arc};

use bitcoin::{
    Amount, Network, OutPoint,
    hashes::{Hash, sha256},
    relative,
};
use bitcoin_bosd::Descriptor;
use strata_bridge_primitives::types::{GraphIdx, OperatorIdx};
use strata_bridge_test_utils::bitcoin::generate_xonly_pubkey;
use strata_bridge_tx_graph2::game_graph::ProtocolParams;

use crate::{
    graph::{
        config::GraphSMCfg, context::GraphSMCtx, errors::GSMError, events::GraphEvent,
        machine::GraphSM, state::GraphState,
    },
    testing::{
        fixtures::test_operator_table,
        transition::{InvalidTransition, test_invalid_transition},
    },
};

// ===== Test Constants =====
/// Block height used as the initial state in tests.
pub(super) const INITIAL_BLOCK_HEIGHT: u64 = 100;
/// Deposit index used in tests.
pub(super) const TEST_DEPOSIT_IDX: u32 = 0;
/// Operator index of the POV (point of view) operator in tests.
/// This is the operator running the state machine.
pub(super) const TEST_POV_IDX: OperatorIdx = 0;
/// Operator index representing a non-POV operator in tests.
pub(super) const TEST_NONPOV_IDX: OperatorIdx = 1;
// Compile-time assertion: TEST_NONPOV_IDX must differ from TEST_POV_IDX
const _: () = assert!(TEST_NONPOV_IDX != TEST_POV_IDX);
/// Deposit amount used in test fixtures.
pub(super) const TEST_DEPOSIT_AMOUNT: Amount = Amount::from_sat(10_000_000);
/// Operator fee used in test fixtures.
pub(super) const TEST_OPERATOR_FEE: Amount = Amount::from_sat(10_000);

/// Number of operators used in test fixtures.
pub(super) const N_TEST_OPERATORS: usize = 5;
const CONTEST_TIMELOCK: relative::LockTime = relative::LockTime::from_height(10);
const PROOF_TIMELOCK: relative::LockTime = relative::LockTime::from_height(5);
const ACK_TIMELOCK: relative::LockTime = relative::LockTime::from_height(10);
const NACK_TIMELOCK: relative::LockTime = relative::LockTime::from_height(5);
const CONTESTED_PAYOUT_TIMELOCK: relative::LockTime = relative::LockTime::from_height(15);
const STAKE_AMOUNT: Amount = Amount::from_sat(100_000_000);

// ===== Configuration Helpers =====

/// Creates a test bridge-wide GSM configuration.
pub(super) fn test_graph_sm_cfg() -> Arc<GraphSMCfg> {
    let watchtower_pubkeys = (0..N_TEST_OPERATORS - 1)
        .map(|_| generate_xonly_pubkey())
        .collect();
    let watchtower_fault_pubkeys = (0..N_TEST_OPERATORS - 1)
        .map(|_| generate_xonly_pubkey())
        .collect();
    let slash_watchtower_descriptors = (0..N_TEST_OPERATORS - 1)
        .map(|_| random_p2tr_desc())
        .collect();

    Arc::new(GraphSMCfg {
        game_graph_params: ProtocolParams {
            network: Network::Regtest,
            magic_bytes: (*b"ALPN").into(),
            contest_timelock: CONTEST_TIMELOCK,
            proof_timelock: PROOF_TIMELOCK,
            ack_timelock: ACK_TIMELOCK,
            nack_timelock: NACK_TIMELOCK,
            contested_payout_timelock: CONTESTED_PAYOUT_TIMELOCK,
            counterproof_n_bytes: NonZero::new(128).unwrap(),
            deposit_amount: TEST_DEPOSIT_AMOUNT,
            stake_amount: STAKE_AMOUNT,
        },
        operator_adaptor_key: generate_xonly_pubkey(),
        watchtower_pubkeys,
        admin_pubkey: generate_xonly_pubkey(),
        operator_fee: TEST_OPERATOR_FEE,
        watchtower_fault_pubkeys,
        payout_desc: random_p2tr_desc(),
        slash_watchtower_descriptors,
    })
}

/// Creates a GraphSM for a POV operator.
pub(super) fn test_sm_ctx() -> GraphSMCtx {
    GraphSMCtx {
        graph_idx: GraphIdx {
            deposit: TEST_DEPOSIT_IDX,
            operator: TEST_POV_IDX,
        },
        deposit_outpoint: OutPoint::default(),
        stake_outpoint: OutPoint::default(),
        unstaking_image: sha256::Hash::all_zeros(),
        operator_table: test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX),
    }
}

/// Creates a random P2TR descriptor for use in tests.
pub(super) fn random_p2tr_desc() -> Descriptor {
    Descriptor::new_p2tr(&generate_xonly_pubkey().serialize())
        .expect("Failed to generate descriptor")
}

// ===== State Machine Helpers =====

/// Creates a GraphSM from a given state for a POV operator.
pub(super) fn create_sm(state: GraphState) -> GraphSM {
    GraphSM {
        context: test_sm_ctx(),
        state,
    }
}

/// Creates a GraphSM for a non-POV operator
pub(super) fn create_nonpov_sm(state: GraphState) -> GraphSM {
    GraphSM {
        context: GraphSMCtx {
            graph_idx: GraphIdx {
                deposit: TEST_DEPOSIT_IDX,
                operator: TEST_POV_IDX,
            },
            deposit_outpoint: OutPoint::default(),
            stake_outpoint: OutPoint::default(),
            unstaking_image: sha256::Hash::all_zeros(),
            operator_table: test_operator_table(N_TEST_OPERATORS, TEST_NONPOV_IDX),
        },
        state,
    }
}

/// Gets the state from a GraphSM.
pub(super) const fn get_state(sm: &GraphSM) -> &GraphState {
    sm.state()
}

// ===== Test Transition Helpers =====

/// Type alias for invalid GraphSM transitions.
pub(super) type GraphInvalidTransition = InvalidTransition<GraphState, GraphEvent, GSMError>;

/// Test an invalid GraphSM transition with pre-configured test helpers.
pub(super) fn test_graph_invalid_transition(invalid: GraphInvalidTransition) {
    test_invalid_transition::<GraphSM, _, _, _, _, _, _>(create_sm, test_graph_sm_cfg(), invalid);
}
