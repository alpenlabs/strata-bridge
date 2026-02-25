//! Testing utilities specific to the Graph State Machine.
pub(super) mod mock_states;
mod uncontested;
pub(super) mod utils;

mod deposit_signal;
mod notify_new_block;
mod process_payout;
mod tx_classifier;

use std::{num::NonZero, sync::Arc};

use bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Transaction,
    hashes::{Hash, sha256},
    relative,
};
use musig2::secp256k1::schnorr::Signature;
use secp256k1::SecretKey;
use strata_bridge_primitives::{
    secp::EvenSecretKey,
    types::{GraphIdx, OperatorIdx},
};
use strata_bridge_test_utils::{
    bitcoin::{generate_spending_tx, generate_xonly_pubkey},
    prelude::generate_signature,
};
use strata_bridge_tx_graph2::{
    game_graph::{
        CounterproofGraphSummary, DepositParams, GameGraph, GameGraphSummary, ProtocolParams,
    },
    transactions::prelude::{ClaimTx, ContestTx, CounterproofTx},
};
use zkaleido::{Proof, ProofReceipt, PublicValues};

pub(super) use crate::testing::fixtures::{
    LATER_BLOCK_HEIGHT, TEST_ASSIGNEE, TEST_DEPOSIT_AMOUNT, TEST_DEPOSIT_IDX, TEST_OPERATOR_FEE,
    random_p2tr_desc, test_fulfillment_tx, test_operator_table, test_recipient_desc,
};
use crate::{
    graph::{
        config::GraphSMCfg,
        context::GraphSMCtx,
        duties::GraphDuty,
        errors::GSMError,
        events::GraphEvent,
        machine::{self, GraphSM},
        state::GraphState,
    },
    signals::GraphSignal,
    testing::{
        Transition,
        fixtures::TEST_MAGIC_BYTES,
        signer::TestMusigSigner,
        test_transition,
        transition::{InvalidTransition, test_invalid_transition},
    },
};

// ===== Dummy Values =====

pub(super) fn dummy_proof_receipt() -> ProofReceipt {
    ProofReceipt::new(Proof::new(vec![]), PublicValues::new(vec![]))
}

// ===== Test Constants =====
/// Block height used as the initial state in tests.
pub(super) const INITIAL_BLOCK_HEIGHT: u64 = 100;
/// Operator index of the POV (point of view) operator in tests.
/// This is the operator running the state machine.
pub(super) const TEST_POV_IDX: OperatorIdx = 0;
/// Operator index representing a non-POV operator in tests.
pub(super) const TEST_NONPOV_IDX: OperatorIdx = 1;
// Compile-time assertion: TEST_NONPOV_IDX must differ from TEST_POV_IDX
const _: () = assert!(TEST_NONPOV_IDX != TEST_POV_IDX);

/// Number of operators used in test fixtures.
pub(super) const N_TEST_OPERATORS: usize = 5;
/// Block height at which the claim transaction was confirmed in tests.
pub(super) const CLAIM_BLOCK_HEIGHT: u64 = 150;
/// Block height at which the fulfillment transaction was confirmed in tests.
pub(super) const FULFILLMENT_BLOCK_HEIGHT: u64 = 150;
/// A block height used for assignment deadlines in tests.
pub(super) const ASSIGNMENT_DEADLINE: u64 = 200;
/// Contest timelock value in blocks.
pub(super) const CONTEST_TIMELOCK_BLOCKS: u64 = 10;
const CONTEST_TIMELOCK: relative::LockTime =
    relative::LockTime::from_height(CONTEST_TIMELOCK_BLOCKS as u16);
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
            magic_bytes: TEST_MAGIC_BYTES.into(),
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
pub(super) fn test_graph_sm_ctx() -> GraphSMCtx {
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

// ===== Context =====

pub(super) fn test_deposit_outpoint() -> OutPoint {
    OutPoint {
        vout: 100,
        ..OutPoint::default()
    }
}

// ===== Graph Data =====

pub(super) fn test_deposit_params() -> DepositParams {
    DepositParams {
        game_index: NonZero::new(1u32).unwrap(),
        claim_funds: OutPoint::default(),
        deposit_outpoint: test_deposit_outpoint(),
    }
}

pub(super) fn test_graph_data(cfg: &Arc<GraphSMCfg>) -> (DepositParams, GameGraph) {
    let ctx = test_graph_sm_ctx();
    let deposit_params = test_deposit_params();

    let graph = machine::generate_game_graph(cfg, &ctx, deposit_params);

    (deposit_params, graph)
}

pub(super) enum TestGraphTxKind {
    Claim = 0,
    Contest = 1,
    BridgeProofTimeout = 2,
    Counterproof = 3,
    CounterproofAck = 4,
    Slash = 5,
    UncontestedPayout = 6,
    ContestedPayout = 7,
}

impl From<TestGraphTxKind> for Transaction {
    fn from(kind: TestGraphTxKind) -> Self {
        generate_spending_tx(
            OutPoint {
                vout: kind as u32,
                ..OutPoint::default()
            },
            &[],
        )
    }
}

pub(super) fn test_graph_summary() -> GameGraphSummary {
    GameGraphSummary {
        claim: Transaction::from(TestGraphTxKind::Claim).compute_txid(),
        contest: Transaction::from(TestGraphTxKind::Contest).compute_txid(),
        bridge_proof_timeout: Transaction::from(TestGraphTxKind::BridgeProofTimeout).compute_txid(),
        counterproofs: vec![CounterproofGraphSummary {
            counterproof: Transaction::from(TestGraphTxKind::Counterproof).compute_txid(),
            counterproof_ack: Transaction::from(TestGraphTxKind::CounterproofAck).compute_txid(),
        }],
        slash: Transaction::from(TestGraphTxKind::Slash).compute_txid(),
        uncontested_payout: Transaction::from(TestGraphTxKind::UncontestedPayout).compute_txid(),
        contested_payout: Transaction::from(TestGraphTxKind::ContestedPayout).compute_txid(),
    }
}

// ===== Test Transactions =====

pub(super) fn test_bridge_proof_tx() -> Transaction {
    let mut tx = generate_spending_tx(
        OutPoint {
            txid: test_graph_summary().contest,
            vout: ContestTx::PROOF_VOUT,
        },
        &[],
    );

    let proof_output = ScriptBuf::new_op_return([0x01; 10]);
    tx.output.push(bitcoin::TxOut {
        value: Amount::from_sat(0),
        script_pubkey: proof_output,
    });

    tx
}

pub(super) fn test_counterproof_nack_tx() -> Transaction {
    generate_spending_tx(
        OutPoint {
            txid: test_graph_summary().counterproofs[0].counterproof,
            vout: CounterproofTx::ACK_NACK_VOUT,
        },
        &[],
    )
}

pub(super) fn test_deposit_spend_tx() -> Transaction {
    generate_spending_tx(test_deposit_outpoint(), &[])
}

pub(super) fn test_payout_connector_spent_tx() -> Transaction {
    generate_spending_tx(
        OutPoint {
            txid: test_graph_summary().claim,
            vout: ClaimTx::PAYOUT_VOUT,
        },
        &[],
    )
}

// ===== State Machine Helpers =====

/// Creates a GraphSM from a given state for a POV operator.
pub(super) fn create_sm(state: GraphState) -> GraphSM {
    GraphSM {
        context: test_graph_sm_ctx(),
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

/// Type alias for GraphSM transitions.
pub(super) type GraphTransition = Transition<GraphState, GraphEvent, GraphDuty, GraphSignal>;

/// Test a valid GraphSM transition with pre-configured test helpers.
pub(super) fn test_graph_transition(transition: GraphTransition) {
    test_transition::<GraphSM, _, _, _, _, _, _, _>(
        create_sm,
        get_state,
        test_graph_sm_cfg(),
        transition,
    );
}

/// Type alias for invalid GraphSM transitions.
pub(super) type GraphInvalidTransition = InvalidTransition<GraphState, GraphEvent, GSMError>;

/// Test an invalid GraphSM transition with pre-configured test helpers.
pub(super) fn test_graph_invalid_transition(invalid: GraphInvalidTransition) {
    test_invalid_transition::<GraphSM, _, _, _, _, _, _>(create_sm, test_graph_sm_cfg(), invalid);
}

/// Creates a packed vector of mock signatures whose layout matches
/// the game graph's signing info structure.
pub(super) fn mock_game_signatures(game_graph: &GameGraph) -> Vec<Signature> {
    game_graph
        .musig_signing_info()
        .map(|_| generate_signature())
        .pack()
}

/// Creates test musig signers for the operators.
pub(super) fn test_operator_signers(num_signers: usize) -> Vec<TestMusigSigner> {
    (0..num_signers)
        .map(|i| {
            let sk = EvenSecretKey::from(SecretKey::from_slice(&[(i + 1) as u8; 32]).unwrap());
            TestMusigSigner::new((i) as u32, *sk)
        })
        .collect()
}
