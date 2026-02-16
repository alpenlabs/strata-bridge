//! Testing utilities specific to the Graph State Machine.

use std::{num::NonZero, sync::Arc};

use bitcoin::{
    Amount, Network, OutPoint,
    hashes::{Hash, sha256},
    relative,
};
use bitcoin_bosd::Descriptor;
use secp256k1::{SECP256K1, SecretKey};
use strata_bridge_p2p_types::P2POperatorPubKey;
use strata_bridge_primitives::{
    operator_table::OperatorTable,
    secp::EvenSecretKey,
    types::{GraphIdx, OperatorIdx},
};
use strata_bridge_test_utils::bitcoin::generate_xonly_pubkey;
use strata_bridge_tx_graph2::game_graph::ProtocolParams;
use strata_l1_txfmt::MagicBytes;

use crate::{
    graph::{
        config::GraphSMCfg, context::GraphSMCtx, duties::GraphDuty, errors::GSMError,
        events::GraphEvent, machine::GraphSM, state::GraphState,
    },
    signals::GraphSignal,
    testing::transition::{
        InvalidTransition, Transition, test_invalid_transition, test_transition,
    },
};

mod uncontested;

// ===== Test Constants =====
/// Block height used as the initial state in tests.
pub(super) const INITIAL_BLOCK_HEIGHT: u64 = 100;
/// Deposit index used in tests.
pub(super) const TEST_DEPOSIT_IDX: u32 = 0;
/// Operator index of the POV (point of view) operator in tests.
/// This is the operator running the state machine.
pub(super) const TEST_POV_IDX: OperatorIdx = 0;

// ===== Configuration Helpers =====

/// Creates a test bridge-wide GSM configuration.
pub(super) fn test_deposit_sm_cfg() -> Arc<GraphSMCfg> {
    Arc::new(GraphSMCfg {
        game_graph_params: ProtocolParams {
            network: Network::Regtest,
            magic_bytes: MagicBytes::from([0x54, 0x45, 0x53, 0x54]), // "TEST"
            contest_timelock: relative::LockTime::from_height(10),
            proof_timelock: relative::LockTime::from_height(5),
            ack_timelock: relative::LockTime::from_height(10),
            nack_timelock: relative::LockTime::from_height(5),
            contested_payout_timelock: relative::LockTime::from_height(15),
            counterproof_n_bytes: NonZero::new(128).unwrap(),
            deposit_amount: Amount::from_sat(100_000_000),
            stake_amount: Amount::from_sat(100_000_000),
        },
        operator_adaptor_key: generate_xonly_pubkey(),
        watchtower_pubkeys: vec![generate_xonly_pubkey(), generate_xonly_pubkey()],
        admin_pubkey: generate_xonly_pubkey(),
        watchtower_fault_pubkeys: vec![generate_xonly_pubkey(), generate_xonly_pubkey()],
        payout_desc: random_p2tr_desc(),
        slash_watchtower_descriptors: vec![random_p2tr_desc(), random_p2tr_desc()],
    })
}

/// Creates a test per-instance context for GraphSM.
pub(super) fn test_sm_ctx() -> GraphSMCtx {
    GraphSMCtx {
        graph_idx: GraphIdx {
            deposit: TEST_DEPOSIT_IDX,
            operator: TEST_POV_IDX,
        },
        deposit_outpoint: OutPoint::default(),
        stake_outpoint: OutPoint::default(),
        unstaking_image: sha256::Hash::all_zeros(),
        operator_table: test_operator_table(),
    }
}

/// Creates a minimal test operator table with 3 operators.
pub(super) fn test_operator_table() -> OperatorTable {
    let sk1 = EvenSecretKey::from(SecretKey::from_slice(&[1u8; 32]).unwrap());
    let sk2 = EvenSecretKey::from(SecretKey::from_slice(&[2u8; 32]).unwrap());
    let sk3 = EvenSecretKey::from(SecretKey::from_slice(&[3u8; 32]).unwrap());

    let operators = vec![
        (
            0,
            P2POperatorPubKey::from(sk1.public_key(SECP256K1).serialize().to_vec()),
            sk1.public_key(SECP256K1),
        ),
        (
            1,
            P2POperatorPubKey::from(sk2.public_key(SECP256K1).serialize().to_vec()),
            sk2.public_key(SECP256K1),
        ),
        (
            2,
            P2POperatorPubKey::from(sk3.public_key(SECP256K1).serialize().to_vec()),
            sk3.public_key(SECP256K1),
        ),
    ];

    OperatorTable::new(operators, |entry| entry.0 == TEST_POV_IDX)
        .expect("Failed to create test operator table")
}

/// Creates a random P2TR descriptor for use in tests.
pub(super) fn random_p2tr_desc() -> Descriptor {
    Descriptor::new_p2tr(&generate_xonly_pubkey().serialize())
        .expect("Failed to generate descriptor")
}

// ===== State Machine Helpers =====

/// Creates a GraphSM from a given state.
pub(super) fn create_sm(state: GraphState) -> GraphSM {
    GraphSM {
        context: test_sm_ctx(),
        state,
    }
}

/// Gets the state from a GraphSM.
pub(super) const fn get_state(sm: &GraphSM) -> &GraphState {
    sm.state()
}

// ===== Test Transition Helpers =====

/// Type alias for GraphSM transitions.
pub(super) type GraphTransition = Transition<GraphState, GraphEvent, GraphDuty, GraphSignal>;

/// Type alias for invalid GraphSM transitions.
pub(super) type GraphInvalidTransition = InvalidTransition<GraphState, GraphEvent, GSMError>;

/// Test a valid GraphSM transition with pre-configured test helpers.
pub(super) fn test_graph_transition(transition: GraphTransition) {
    test_transition::<GraphSM, _, _, _, _, _, _, _>(
        create_sm,
        get_state,
        test_deposit_sm_cfg(),
        transition,
    );
}

/// Test an invalid GraphSM transition with pre-configured test helpers.
pub(super) fn test_graph_invalid_transition(invalid: GraphInvalidTransition) {
    test_invalid_transition::<GraphSM, _, _, _, _, _, _>(create_sm, test_deposit_sm_cfg(), invalid);
}
