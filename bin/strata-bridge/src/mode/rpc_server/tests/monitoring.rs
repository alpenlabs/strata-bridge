//! Tests for monitoring response conversion helpers.

use std::{collections::BTreeMap, num::NonZero, sync::Arc};

use bitcoin::{
    Amount, Network, OutPoint, PublicKey, Txid,
    hashes::{Hash, sha256},
    relative,
};
use musig2::AggNonce;
use secp256k1::schnorr::Signature;
use strata_bridge_connectors::prelude::NOfNConnector;
use strata_bridge_orchestrator::sm_registry::{SMConfig, SMRegistry};
use strata_bridge_primitives::{
    covenant::CovenantId,
    operator_table::OperatorTable,
    types::{DepositIdx, GraphIdx, OperatorIdx},
};
use strata_bridge_rpc::types::{
    RpcBridgeDutyStatus, RpcClaimPhase, RpcPayoutBlock, RpcPayoutKind, RpcReimbursementStatus,
    RpcWithdrawalStatus,
};
use strata_bridge_sm::{
    deposit::{
        config::DepositSMCfg, context::DepositSMCtx, machine::DepositSM, state::DepositState,
    },
    graph::{
        config::GraphSMCfg,
        context::GraphSMCtx,
        state::{AbortReason, CounterproofData, GraphState, PayoutBlockData, PayoutKind},
    },
    stake::config::StakeSMCfg,
};
use strata_bridge_test_utils::{
    bitcoin::{generate_spending_tx, generate_tx, generate_xonly_pubkey},
    bridge_fixtures::{
        TEST_DEPOSIT_AMOUNT, TEST_MAGIC_BYTES, TEST_OPERATOR_FEE, TEST_POV_IDX,
        TEST_RECOVERY_DELAY, TEST_SWEEP_FEE_RATE, random_p2tr_desc, test_operator_table,
    },
    musig2::{generate_agg_nonce, generate_partial_signature, generate_pubnonce},
    prelude::generate_txid,
};
use strata_bridge_tx_graph::{
    game_graph::{
        AdminMultisig, DepositParams, GameData, GameGraph, GameGraphSummary, ProtocolParams,
    },
    stake_graph::ProtocolParams as StakeProtocolParams,
    transactions::{
        claim::ClaimTx,
        contest::ContestTx,
        cooperative_payout::{CooperativePayoutData, CooperativePayoutTx},
        deposit::{DepositData, DepositTx, build_test_deposit_tx},
        sweep::{SweepData, SweepTx},
    },
};
use strata_predicate::PredicateKey;
use zkaleido::{Proof, ProofReceipt, PublicValues};

use super::super::monitoring::{
    active_claim_from_state, aggregate_signatures_response, bridge_duties_for_deposit,
    bridge_duties_for_operator_pk, cooperative_reimbursement_status, duty_applies_to_operator,
    get_pending_assigned_operator, get_reimbursement_operator, graph_data_response,
    reimbursement_status, withdrawal_status,
};

const DEPOSIT_IDX: DepositIdx = 3;
const OPERATOR_IDX: OperatorIdx = 1;

fn test_graph_idx() -> GraphIdx {
    GraphIdx {
        deposit: DEPOSIT_IDX,
        operator: OPERATOR_IDX,
    }
}

fn test_graph_data() -> DepositParams {
    DepositParams {
        game_index: NonZero::new(DEPOSIT_IDX + 1).expect("non-zero"),
        claim_funds: OutPoint::new(bitcoin::Txid::all_zeros(), 1),
        deposit_outpoint: OutPoint::new(bitcoin::Txid::all_zeros(), 1),
        adaptor_pubkeys: (0..2).map(|_| generate_xonly_pubkey()).collect(),
        fault_pubkeys: (0..2).map(|_| generate_xonly_pubkey()).collect(),
    }
}

fn test_graph_ctx() -> GraphSMCtx {
    let operator_table = test_operator_table(3, TEST_POV_IDX);
    GraphSMCtx {
        covenant: CovenantId::from_operator_table(&operator_table, 100).unwrap(),
        graph_idx: test_graph_idx(),
        deposit_outpoint: OutPoint::new(bitcoin::Txid::all_zeros(), 7),
        stake_outpoint: OutPoint::new(bitcoin::Txid::all_zeros(), 8),
        unstaking_image: sha256::Hash::hash(b"test"),
        operator_table,
    }
}

fn test_graph_cfg() -> GraphSMCfg {
    GraphSMCfg {
        game_graph_params: ProtocolParams {
            network: Network::Regtest,
            magic_bytes: TEST_MAGIC_BYTES.into(),
            contest_timelock: relative::Height::from_height(10),
            proof_timelock: relative::Height::from_height(5),
            ack_timelock: relative::Height::from_height(5),
            nack_timelock: relative::Height::from_height(5),
            contested_payout_timelock: relative::Height::from_height(10),
            counterproof_n_data: NonZero::new(128).expect("non-zero"),
            deposit_amount: TEST_DEPOSIT_AMOUNT,
            stake_amount: Amount::from_sat(20_000),
        },
        operator_fee: TEST_OPERATOR_FEE,
        admin: AdminMultisig {
            pubkeys: vec![generate_xonly_pubkey()],
            threshold: 1,
        },
        payout_descs: (0..3).map(|idx| (idx, random_p2tr_desc())).collect(),
        bridge_proof_predicate: PredicateKey::always_accept(),
        counterproof_predicate: PredicateKey::always_accept(),
    }
}

fn test_deposit_tx() -> DepositTx {
    build_test_deposit_tx(
        &test_operator_table(3, TEST_POV_IDX),
        DepositData {
            deposit_idx: DEPOSIT_IDX,
            deposit_request_outpoint: OutPoint::new(Txid::all_zeros(), 0),
            magic_bytes: TEST_MAGIC_BYTES.into(),
        },
        TEST_DEPOSIT_AMOUNT,
    )
}

fn test_cooperative_payout_tx() -> CooperativePayoutTx {
    let deposit_connector = NOfNConnector::new(
        Network::Regtest,
        generate_xonly_pubkey(),
        TEST_DEPOSIT_AMOUNT,
    );

    CooperativePayoutTx::new(
        CooperativePayoutData {
            deposit_outpoint: OutPoint::new(Txid::all_zeros(), 1),
        },
        deposit_connector,
        random_p2tr_desc(),
    )
}

fn test_sweep_tx() -> SweepTx {
    let deposit_connector = NOfNConnector::new(
        Network::Regtest,
        generate_xonly_pubkey(),
        TEST_DEPOSIT_AMOUNT,
    );

    SweepTx::new(
        SweepData {
            deposit_outpoint: OutPoint::new(Txid::all_zeros(), 1),
        },
        deposit_connector,
        random_p2tr_desc(),
        vec![generate_xonly_pubkey()],
        TEST_SWEEP_FEE_RATE,
    )
}

fn test_sm_config() -> SMConfig {
    SMConfig {
        deposit: Arc::new(DepositSMCfg {
            network: Network::Regtest,
            cooperative_payout_timeout_blocks: 144,
            deposit_amount: TEST_DEPOSIT_AMOUNT,
            operator_fee: TEST_OPERATOR_FEE,
            magic_bytes: TEST_MAGIC_BYTES.into(),
            recovery_delay: TEST_RECOVERY_DELAY,
            sweep_fee_rate: TEST_SWEEP_FEE_RATE,
        }),
        graph: Arc::new(test_graph_cfg()),
        stake: Arc::new(StakeSMCfg {
            protocol_params: StakeProtocolParams {
                network: Network::Regtest,
                magic_bytes: TEST_MAGIC_BYTES.into(),
                unstaking_timelock: relative::Height::from_height(144),
                stake_amount: Amount::from_sat(20_000),
            },
        }),
        max_active_deposits: None,
        deposit_index_offset: 0,
    }
}

fn test_deposit_sm(deposit_idx: DepositIdx, operator_table: OperatorTable) -> DepositSM {
    DepositSM {
        context: DepositSMCtx {
            covenant: CovenantId::from_operator_table(&operator_table, 100).unwrap(),
            deposit_idx,
            deposit_request_outpoint: OutPoint::new(Txid::all_zeros(), 1),
            deposit_outpoint: OutPoint::new(Txid::all_zeros(), 2),
            operator_table,
        },
        cfg: test_sm_config().deposit,
        state: DepositState::Deposited {
            last_block_height: 100,
        },
    }
}

fn dummy_proof_receipt() -> ProofReceipt {
    ProofReceipt::new(Proof::new(vec![]), PublicValues::new(vec![]))
}

fn test_graph_summary() -> GameGraphSummary {
    GameGraphSummary {
        claim: generate_txid(),
        contest: generate_txid(),
        bridge_proof_timeout: generate_txid(),
        counterproofs: vec![],
        slash: generate_txid(),
        uncontested_payout: generate_txid(),
        contested_payout: generate_txid(),
    }
}

#[test]
fn graph_data_response_returns_graph_data_for_matching_claim() {
    let graph_ctx = test_graph_ctx();
    let graph_cfg = test_graph_cfg();
    let graph_data = test_graph_data();
    let graph_summary = test_graph_summary();
    let state = GraphState::GraphGenerated {
        last_block_height: 100,
        graph_data: graph_data.clone(),
        graph_summary: graph_summary.clone(),
    };

    let response =
        graph_data_response(&graph_ctx, &state, &graph_cfg).expect("graph data should be returned");

    assert_eq!(response.context, graph_ctx);
    assert_eq!(
        response.setup,
        graph_ctx.generate_setup_params(&graph_cfg, &graph_data)
    );
    assert_eq!(response.deposit, graph_data);
}

#[test]
fn graph_data_response_returns_none_before_graph_is_generated() {
    let state = GraphState::Created {
        last_block_height: 100,
    };

    let response = graph_data_response(&test_graph_ctx(), &state, &test_graph_cfg());

    assert!(response.is_none());
}

#[test]
fn aggregate_signatures_response_returns_hex_signatures_for_matching_claim() {
    let graph_idx = test_graph_idx();
    let graph_summary = test_graph_summary();
    let signatures = vec![
        Signature::from_slice(&[0x0a; 64]).expect("valid signature"),
        Signature::from_slice(&[0x0b; 64]).expect("valid signature"),
    ];
    let expected_signatures = signatures.clone();
    let state = GraphState::GraphSigned {
        last_block_height: 100,
        graph_data: test_graph_data(),
        graph_summary: graph_summary.clone(),
        agg_nonces: Some(vec![]),
        signatures,
        stake_spent: None,
    };

    let response =
        aggregate_signatures_response(graph_idx, &state).expect("signatures should be returned");

    assert_eq!(response.graph_idx, graph_idx);
    assert_eq!(response.signatures, expected_signatures);
}

#[test]
fn aggregate_signatures_response_returns_none_before_graph_is_signed() {
    let state = GraphState::NoncesCollected {
        last_block_height: 100,
        graph_data: test_graph_data(),
        graph_summary: test_graph_summary(),
        pubnonces: BTreeMap::new(),
        agg_nonces: vec![],
        partial_signatures: BTreeMap::new(),
        stake_spent: None,
    };

    let response = aggregate_signatures_response(test_graph_idx(), &state);

    assert!(response.is_none());
}

#[test]
fn active_claim_from_state_returns_fulfilled_claim_in_claimed_state() {
    let graph_summary = test_graph_summary();
    let state = GraphState::Claimed {
        last_block_height: 100,
        graph_data: test_graph_data(),
        graph_summary: graph_summary.clone(),
        signatures: vec![],
        fulfillment_txid: Some(generate_txid()),
        fulfillment_block_height: Some(90),
        claim_block_height: 100,
        stake_spent: None,
        payout_connector_spent: None,
        payout_block_data: Default::default(),
    };

    let claim = active_claim_from_state(OPERATOR_IDX, &state)
        .expect("valid claim")
        .expect("claim should be returned");

    assert_eq!(claim.operator, OPERATOR_IDX);
    assert_eq!(claim.claim_txid, graph_summary.claim);
    assert!(claim.fulfilled);
    assert_eq!(claim.phase, RpcClaimPhase::Claimed);
}

#[test]
fn active_claim_from_state_returns_unfulfilled_claim_in_claimed_state() {
    let graph_summary = test_graph_summary();
    let state = GraphState::Claimed {
        last_block_height: 100,
        graph_data: test_graph_data(),
        graph_summary: graph_summary.clone(),
        signatures: vec![],
        fulfillment_txid: None,
        fulfillment_block_height: None,
        claim_block_height: 100,
        stake_spent: None,
        payout_connector_spent: None,
        payout_block_data: Default::default(),
    };

    let claim = active_claim_from_state(OPERATOR_IDX, &state)
        .expect("valid claim")
        .expect("claim should be returned");

    assert!(!claim.fulfilled);
    assert_eq!(claim.phase, RpcClaimPhase::Claimed);
}

#[test]
fn active_claim_from_state_returns_none_before_claim() {
    let state = GraphState::Fulfilled {
        last_block_height: 100,
        graph_data: test_graph_data(),
        graph_summary: test_graph_summary(),
        coop_payout_failed: false,
        assignee: OPERATOR_IDX,
        signatures: vec![],
        fulfillment_txid: generate_txid(),
        fulfillment_block_height: 90,
        stake_spent: None,
    };

    let claim = active_claim_from_state(OPERATOR_IDX, &state).expect("valid pre-claim state");

    assert!(claim.is_none());
}

#[test]
fn active_claim_from_state_returns_contested_phase() {
    let graph_summary = test_graph_summary();
    let state = GraphState::Contested {
        last_block_height: 100,
        graph_data: test_graph_data(),
        graph_summary: graph_summary.clone(),
        signatures: vec![],
        fulfillment_txid: Some(generate_txid()),
        fulfillment_block_height: Some(90),
        contest_block_height: 100,
        stake_spent: None,
        payout_connector_spent: None,
        payout_block_data: Default::default(),
    };

    let claim = active_claim_from_state(OPERATOR_IDX, &state)
        .expect("valid claim")
        .expect("claim should be returned");

    assert!(claim.fulfilled);
    assert_eq!(
        claim.phase,
        RpcClaimPhase::Contested {
            contest_txid: graph_summary.contest
        }
    );
}

#[test]
fn bridge_duties_for_deposit_reports_each_deposit_state() {
    let collected_nonces: BTreeMap<_, _> = test_operator_table(3, TEST_POV_IDX)
        .operator_idxs()
        .into_iter()
        .map(|idx| (idx, generate_pubnonce()))
        .collect();
    let collected_aggregated_nonce = AggNonce::sum(collected_nonces.values().cloned());
    let deposit_request_txid = generate_txid();
    let claim_txids = BTreeMap::from([(OPERATOR_IDX, generate_txid())]);
    let pubnonces = BTreeMap::from([(OPERATOR_IDX, generate_pubnonce())]);
    let partial_signatures = BTreeMap::from([(OPERATOR_IDX, generate_partial_signature())]);
    let deposit_duty = vec![RpcBridgeDutyStatus::Deposit {
        deposit_idx: DEPOSIT_IDX,
        deposit_request_txid,
    }];
    let withdrawal_duty = vec![RpcBridgeDutyStatus::Withdrawal {
        deposit_idx: DEPOSIT_IDX,
        assigned_operator_idx: OPERATOR_IDX,
    }];
    let no_duties = Vec::<RpcBridgeDutyStatus>::new();

    let cases = vec![
        (
            "Created",
            DepositState::Created {
                deposit_transaction: test_deposit_tx(),
                last_block_height: 100,
                claim_txids: claim_txids.clone(),
            },
            deposit_duty.clone(),
        ),
        (
            "GraphGenerated",
            DepositState::GraphGenerated {
                deposit_transaction: test_deposit_tx(),
                last_block_height: 100,
                claim_txids: claim_txids.clone(),
                pubnonces: pubnonces.clone(),
            },
            deposit_duty.clone(),
        ),
        (
            "DepositNoncesCollected",
            DepositState::DepositNoncesCollected {
                deposit_transaction: test_deposit_tx(),
                last_block_height: 100,
                claim_txids,
                agg_nonce: generate_agg_nonce(),
                pubnonces: pubnonces.clone(),
                partial_signatures: partial_signatures.clone(),
            },
            deposit_duty.clone(),
        ),
        (
            "DepositPartialsCollected",
            DepositState::DepositPartialsCollected {
                last_block_height: 100,
                deposit_transaction: generate_tx(1, 1),
            },
            deposit_duty,
        ),
        (
            "Deposited",
            DepositState::Deposited {
                last_block_height: 100,
            },
            no_duties.clone(),
        ),
        (
            "Assigned",
            DepositState::Assigned {
                last_block_height: 100,
                assignee: OPERATOR_IDX,
                deadline: 120,
                recipient_desc: random_p2tr_desc(),
            },
            withdrawal_duty,
        ),
        (
            "Fulfilled",
            DepositState::Fulfilled {
                last_block_height: 100,
                assignee: OPERATOR_IDX,
                fulfillment_txid: generate_txid(),
                fulfillment_height: 95,
                cooperative_payout_deadline: 120,
            },
            no_duties.clone(),
        ),
        (
            "PayoutDescriptorReceived",
            DepositState::PayoutDescriptorReceived {
                last_block_height: 100,
                assignee: OPERATOR_IDX,
                fulfillment_txid: generate_txid(),
                cooperative_payment_deadline: 120,
                cooperative_payout_tx: test_cooperative_payout_tx(),
                payout_nonces: pubnonces.clone(),
            },
            no_duties.clone(),
        ),
        (
            "PayoutNoncesCollected",
            DepositState::PayoutNoncesCollected {
                last_block_height: 100,
                assignee: OPERATOR_IDX,
                fulfillment_txid: generate_txid(),
                cooperative_payout_tx: test_cooperative_payout_tx(),
                cooperative_payment_deadline: 120,
                payout_nonces: collected_nonces.clone(),
                payout_aggregated_nonce: collected_aggregated_nonce.clone(),
                payout_partial_signatures: partial_signatures,
            },
            no_duties.clone(),
        ),
        (
            "CooperativePathFailed",
            DepositState::CooperativePathFailed {
                assignee: OPERATOR_IDX,
                fulfillment_txid: generate_txid(),
                last_block_height: 100,
                expected_cooperative_payout_txid: None,
            },
            no_duties.clone(),
        ),
        (
            "Spent",
            DepositState::Spent {
                fulfillment_txid: Some(generate_txid()),
                assignee: Some(OPERATOR_IDX),
                cooperative_payout_txid: None,
            },
            no_duties.clone(),
        ),
        ("Aborted", DepositState::Aborted, no_duties.clone()),
        (
            "SweepNoncesPending",
            DepositState::SweepNoncesPending {
                last_block_height: 100,
                sweep_tx: test_sweep_tx(),
                sweep_nonces: BTreeMap::new(),
                cooperative_payout_data: None,
            },
            no_duties.clone(),
        ),
        (
            "SweepNoncesCollected",
            DepositState::SweepNoncesCollected {
                last_block_height: 100,
                sweep_tx: test_sweep_tx(),
                sweep_agg_nonce: collected_aggregated_nonce,
                sweep_nonces: collected_nonces.clone(),
                sweep_partials: BTreeMap::new(),
                cooperative_payout_data: None,
            },
            no_duties,
        ),
    ];

    for (state_name, state, expected_duties) in cases {
        assert_eq!(
            bridge_duties_for_deposit(DEPOSIT_IDX, &state, deposit_request_txid),
            expected_duties,
            "unexpected duties for {state_name}",
        );
    }
}

#[test]
fn bridge_duties_for_operator_pk_filters_deposit_duties_by_each_operator_table() {
    let mut registry = SMRegistry::new(test_sm_config());
    let table_without_operator = test_operator_table(1, TEST_POV_IDX);
    let table_with_operator = test_operator_table(3, TEST_POV_IDX);
    let operator_pk = PublicKey::from(
        table_with_operator
            .idx_to_btc_key(&OPERATOR_IDX)
            .expect("operator should be in test operator table"),
    );

    let mut inactive_deposit = test_deposit_sm(0, table_without_operator);
    inactive_deposit.state = DepositState::Created {
        deposit_transaction: test_deposit_tx(),
        last_block_height: 100,
        claim_txids: BTreeMap::new(),
    };
    let mut active_deposit = test_deposit_sm(1, table_with_operator);
    active_deposit.state = DepositState::Created {
        deposit_transaction: test_deposit_tx(),
        last_block_height: 100,
        claim_txids: BTreeMap::new(),
    };

    registry
        .insert_deposit(0, inactive_deposit)
        .expect("inactive test deposit should be inserted");
    registry
        .insert_deposit(1, active_deposit)
        .expect("active test deposit should be inserted");

    let duties = bridge_duties_for_operator_pk(&registry, &operator_pk)
        .expect("operator key should be found in at least one deposit");

    assert_eq!(
        duties,
        vec![RpcBridgeDutyStatus::Deposit {
            deposit_idx: 1,
            deposit_request_txid: Txid::all_zeros(),
        }]
    );
}

#[test]
fn bridge_duties_for_operator_pk_does_not_overproduce_deposit_duties() {
    let mut registry = SMRegistry::new(test_sm_config());
    let table_without_operator = test_operator_table(1, TEST_POV_IDX);
    let table_with_operator = test_operator_table(3, TEST_POV_IDX);
    let operator_pk = PublicKey::from(
        table_with_operator
            .idx_to_btc_key(&OPERATOR_IDX)
            .expect("operator should be in test operator table"),
    );

    let mut inactive_deposit_with_duty = test_deposit_sm(0, table_without_operator);
    inactive_deposit_with_duty.state = DepositState::Created {
        deposit_transaction: test_deposit_tx(),
        last_block_height: 100,
        claim_txids: BTreeMap::new(),
    };
    let active_deposit_without_duty = test_deposit_sm(1, table_with_operator);

    registry
        .insert_deposit(0, inactive_deposit_with_duty)
        .expect("inactive test deposit should be inserted");
    registry
        .insert_deposit(1, active_deposit_without_duty)
        .expect("active test deposit should be inserted");

    let duties = bridge_duties_for_operator_pk(&registry, &operator_pk)
        .expect("operator key should be found in at least one deposit");

    assert_eq!(duties, vec![]);
}

#[test]
fn duty_applies_to_operator_matches_withdrawal_assignee() {
    let deposit_duty = RpcBridgeDutyStatus::Deposit {
        deposit_idx: DEPOSIT_IDX,
        deposit_request_txid: generate_txid(),
    };
    let withdrawal_duty = RpcBridgeDutyStatus::Withdrawal {
        deposit_idx: DEPOSIT_IDX,
        assigned_operator_idx: OPERATOR_IDX,
    };

    assert!(duty_applies_to_operator(&deposit_duty, OPERATOR_IDX));
    assert!(duty_applies_to_operator(&withdrawal_duty, OPERATOR_IDX));
    assert!(!duty_applies_to_operator(
        &withdrawal_duty,
        OPERATOR_IDX + 1
    ));
}

#[test]
fn reimbursement_operator_uses_terminal_spent_assignee_without_marking_it_pending() {
    let state = DepositState::Spent {
        fulfillment_txid: Some(generate_txid()),
        assignee: Some(OPERATOR_IDX),
        cooperative_payout_txid: None,
    };

    assert_eq!(get_reimbursement_operator(&state), Some(OPERATOR_IDX));
    assert_eq!(get_pending_assigned_operator(&state), None);

    // A deposit swept out of `Assigned` terminates with an assignee but no fulfillment; the
    // assignee still backs the reimbursement view without being marked pending.
    let swept_from_assigned = DepositState::Spent {
        fulfillment_txid: None,
        assignee: Some(OPERATOR_IDX),
        cooperative_payout_txid: None,
    };

    assert_eq!(
        get_reimbursement_operator(&swept_from_assigned),
        Some(OPERATOR_IDX)
    );
    assert_eq!(get_pending_assigned_operator(&swept_from_assigned), None);
}

#[test]
fn withdrawal_status_reports_each_deposit_state() {
    let collected_nonces: BTreeMap<_, _> = test_operator_table(3, TEST_POV_IDX)
        .operator_idxs()
        .into_iter()
        .map(|idx| (idx, generate_pubnonce()))
        .collect();
    let collected_aggregated_nonce = AggNonce::sum(collected_nonces.values().cloned());
    let claim_txids = BTreeMap::from([(OPERATOR_IDX, generate_txid())]);
    let pubnonces = BTreeMap::from([(OPERATOR_IDX, generate_pubnonce())]);
    let partial_signatures = BTreeMap::from([(OPERATOR_IDX, generate_partial_signature())]);
    let fulfillment_txid = generate_txid();

    let cases = vec![
        (
            "Created",
            DepositState::Created {
                deposit_transaction: test_deposit_tx(),
                last_block_height: 100,
                claim_txids: claim_txids.clone(),
            },
        ),
        (
            "GraphGenerated",
            DepositState::GraphGenerated {
                deposit_transaction: test_deposit_tx(),
                last_block_height: 100,
                claim_txids: claim_txids.clone(),
                pubnonces: pubnonces.clone(),
            },
        ),
        (
            "DepositNoncesCollected",
            DepositState::DepositNoncesCollected {
                deposit_transaction: test_deposit_tx(),
                last_block_height: 100,
                claim_txids,
                agg_nonce: generate_agg_nonce(),
                pubnonces: pubnonces.clone(),
                partial_signatures: partial_signatures.clone(),
            },
        ),
        (
            "DepositPartialsCollected",
            DepositState::DepositPartialsCollected {
                last_block_height: 100,
                deposit_transaction: generate_tx(1, 1),
            },
        ),
        (
            "Deposited",
            DepositState::Deposited {
                last_block_height: 100,
            },
        ),
        (
            "Assigned",
            DepositState::Assigned {
                last_block_height: 100,
                assignee: OPERATOR_IDX,
                deadline: 120,
                recipient_desc: random_p2tr_desc(),
            },
        ),
        (
            "Fulfilled",
            DepositState::Fulfilled {
                last_block_height: 100,
                assignee: OPERATOR_IDX,
                fulfillment_txid,
                fulfillment_height: 95,
                cooperative_payout_deadline: 120,
            },
        ),
        (
            "PayoutDescriptorReceived",
            DepositState::PayoutDescriptorReceived {
                last_block_height: 100,
                assignee: OPERATOR_IDX,
                fulfillment_txid: generate_txid(),
                cooperative_payment_deadline: 120,
                cooperative_payout_tx: test_cooperative_payout_tx(),
                payout_nonces: pubnonces.clone(),
            },
        ),
        (
            "PayoutNoncesCollected",
            DepositState::PayoutNoncesCollected {
                last_block_height: 100,
                assignee: OPERATOR_IDX,
                fulfillment_txid: generate_txid(),
                cooperative_payout_tx: test_cooperative_payout_tx(),
                cooperative_payment_deadline: 120,
                payout_nonces: collected_nonces.clone(),
                payout_aggregated_nonce: collected_aggregated_nonce.clone(),
                payout_partial_signatures: partial_signatures,
            },
        ),
        (
            "CooperativePathFailed",
            DepositState::CooperativePathFailed {
                assignee: OPERATOR_IDX,
                fulfillment_txid: generate_txid(),
                last_block_height: 100,
                expected_cooperative_payout_txid: None,
            },
        ),
        (
            "Spent",
            DepositState::Spent {
                fulfillment_txid: Some(fulfillment_txid),
                assignee: Some(OPERATOR_IDX),
                cooperative_payout_txid: None,
            },
        ),
        (
            "SpentWithoutFulfillmentTxid",
            DepositState::Spent {
                fulfillment_txid: None,
                assignee: None,
                cooperative_payout_txid: None,
            },
        ),
        (
            "SpentSweptFromAssigned",
            DepositState::Spent {
                fulfillment_txid: None,
                assignee: Some(OPERATOR_IDX),
                cooperative_payout_txid: None,
            },
        ),
        ("Aborted", DepositState::Aborted),
        (
            "SweepNoncesPending",
            DepositState::SweepNoncesPending {
                last_block_height: 100,
                sweep_tx: test_sweep_tx(),
                sweep_nonces: BTreeMap::new(),
                cooperative_payout_data: None,
            },
        ),
        (
            "SweepNoncesCollected",
            DepositState::SweepNoncesCollected {
                last_block_height: 100,
                sweep_tx: test_sweep_tx(),
                sweep_agg_nonce: collected_aggregated_nonce,
                sweep_nonces: collected_nonces.clone(),
                sweep_partials: BTreeMap::new(),
                cooperative_payout_data: None,
            },
        ),
    ];

    for (state_name, state) in cases {
        let expected_status = match &state {
            DepositState::Assigned { .. } => Some(RpcWithdrawalStatus::InProgress),
            DepositState::Fulfilled {
                fulfillment_txid, ..
            }
            | DepositState::PayoutDescriptorReceived {
                fulfillment_txid, ..
            }
            | DepositState::PayoutNoncesCollected {
                fulfillment_txid, ..
            }
            | DepositState::CooperativePathFailed {
                fulfillment_txid, ..
            }
            | DepositState::Spent {
                fulfillment_txid: Some(fulfillment_txid),
                ..
            } => Some(RpcWithdrawalStatus::Complete {
                fulfillment_txid: *fulfillment_txid,
            }),
            _ => None,
        };

        assert_eq!(
            withdrawal_status(&state),
            expected_status,
            "unexpected withdrawal status for {state_name}",
        );
    }
}

#[test]
fn reimbursement_status_reports_each_graph_state() {
    // Derive transaction IDs and signing-vector lengths from the same graph.
    let graph_cfg = test_graph_cfg();
    let graph_ctx = test_graph_ctx();
    let mut graph_data = test_graph_data();
    graph_data.deposit_outpoint = graph_ctx.deposit_outpoint;
    let (graph, _) = GameGraph::new(GameData {
        protocol: graph_cfg.game_graph_params,
        setup: graph_ctx.generate_setup_params(&graph_cfg, &graph_data),
        deposit: graph_data.clone(),
    });
    let graph_summary = graph.summarize();
    let contest_height = 100;
    let proof_height = contest_height + 1;
    let timeout_height =
        contest_height + u64::from(graph_cfg.game_graph_params.proof_timelock.value());
    let counterproof_height = contest_height + 1;
    let ack_height =
        counterproof_height + u64::from(graph_cfg.game_graph_params.nack_timelock.value());
    let proof = dummy_proof_receipt();
    let claim_txid = graph_summary.claim;
    let fulfillment_txid = generate_txid();
    let signing_count = graph.musig_signing_info().pack().len();
    let signatures =
        vec![Signature::from_slice(&[0x0c; 64]).expect("valid signature"); signing_count];
    let pubnonces: BTreeMap<_, Vec<_>> = graph_ctx
        .operator_table
        .operator_idxs()
        .into_iter()
        .map(|idx| {
            (
                idx,
                (0..signing_count).map(|_| generate_pubnonce()).collect(),
            )
        })
        .collect();
    // Each aggregate combines one transaction's nonce from every operator.
    let agg_nonces: Vec<_> = (0..signing_count)
        .map(|i| AggNonce::sum(pubnonces.values().map(|nonces| nonces[i].clone())))
        .collect();
    let partial_signatures = BTreeMap::from([(
        OPERATOR_IDX,
        (0..signing_count)
            .map(|_| generate_partial_signature())
            .collect(),
    )]);
    let not_started = RpcReimbursementStatus::NotStarted;

    // Each case is an independent snapshot, not a sequence of transitions.
    let cases = vec![
        (
            "Created",
            GraphState::Created {
                last_block_height: 100,
            },
            not_started.clone(),
        ),
        (
            "GraphGenerated",
            GraphState::GraphGenerated {
                last_block_height: 100,
                graph_data: graph_data.clone(),
                graph_summary: graph_summary.clone(),
            },
            not_started.clone(),
        ),
        (
            "AdaptorsVerified",
            GraphState::AdaptorsVerified {
                last_block_height: 100,
                graph_data: graph_data.clone(),
                graph_summary: graph_summary.clone(),
                pubnonces: BTreeMap::from([(OPERATOR_IDX, pubnonces[&OPERATOR_IDX].clone())]),
            },
            not_started.clone(),
        ),
        (
            "NoncesCollected",
            GraphState::NoncesCollected {
                last_block_height: 100,
                graph_data: graph_data.clone(),
                graph_summary: graph_summary.clone(),
                pubnonces: pubnonces.clone(),
                agg_nonces: agg_nonces.clone(),
                partial_signatures: partial_signatures.clone(),
                stake_spent: None,
            },
            not_started.clone(),
        ),
        (
            "GraphSigned",
            GraphState::GraphSigned {
                last_block_height: 100,
                graph_data: graph_data.clone(),
                graph_summary: graph_summary.clone(),
                agg_nonces: Some(agg_nonces),
                signatures: signatures.clone(),
                stake_spent: None,
            },
            not_started.clone(),
        ),
        (
            "Assigned",
            GraphState::Assigned {
                last_block_height: 100,
                graph_data: graph_data.clone(),
                graph_summary: graph_summary.clone(),
                signatures: signatures.clone(),
                assignee: OPERATOR_IDX,
                deadline: 120,
                recipient_desc: random_p2tr_desc(),
                stake_spent: None,
            },
            not_started.clone(),
        ),
        (
            "Fulfilled",
            GraphState::Fulfilled {
                last_block_height: 100,
                graph_data: graph_data.clone(),
                graph_summary: graph_summary.clone(),
                coop_payout_failed: false,
                assignee: OPERATOR_IDX,
                signatures: signatures.clone(),
                fulfillment_txid,
                fulfillment_block_height: 95,
                stake_spent: None,
            },
            not_started,
        ),
        (
            "Claimed",
            GraphState::Claimed {
                last_block_height: 100,
                graph_data: graph_data.clone(),
                graph_summary: graph_summary.clone(),
                signatures: signatures.clone(),
                fulfillment_txid: Some(fulfillment_txid),
                fulfillment_block_height: Some(95),
                claim_block_height: 100,
                stake_spent: None,
                payout_connector_spent: None,
                payout_block_data: Default::default(),
            },
            RpcReimbursementStatus::InProgress {
                claim_txid,
                phase: RpcClaimPhase::Claimed,
            },
        ),
        (
            "Contested",
            GraphState::Contested {
                last_block_height: 100,
                graph_data: graph_data.clone(),
                graph_summary: graph_summary.clone(),
                signatures: signatures.clone(),
                fulfillment_txid: Some(fulfillment_txid),
                fulfillment_block_height: Some(95),
                contest_block_height: contest_height,
                stake_spent: None,
                payout_connector_spent: None,
                payout_block_data: Default::default(),
            },
            RpcReimbursementStatus::InProgress {
                claim_txid,
                phase: RpcClaimPhase::Contested {
                    contest_txid: graph_summary.contest,
                },
            },
        ),
        (
            "BridgeProofPosted",
            GraphState::BridgeProofPosted {
                last_block_height: proof_height,
                graph_data: graph_data.clone(),
                graph_summary: graph_summary.clone(),
                signatures: signatures.clone(),
                fulfillment_txid: Some(fulfillment_txid),
                contest_block_height: contest_height,
                bridge_proof_tx: generate_spending_tx(
                    OutPoint::new(graph_summary.contest, ContestTx::PROOF_VOUT),
                    &[],
                ),
                bridge_proof_block_height: proof_height,
                proof,
                stake_spent: None,
                payout_connector_spent: None,
                payout_block_data: Default::default(),
            },
            RpcReimbursementStatus::InProgress {
                claim_txid,
                phase: RpcClaimPhase::BridgeProofPosted {
                    contest_txid: graph_summary.contest,
                },
            },
        ),
        (
            "BridgeProofTimedout",
            GraphState::BridgeProofTimedout {
                last_block_height: timeout_height,
                graph_data: graph_data.clone(),
                graph_summary: graph_summary.clone(),
                signatures: signatures.clone(),
                fulfillment_txid: Some(fulfillment_txid),
                contest_block_height: contest_height,
                expected_slash_txid: graph_summary.slash,
                claim_txid,
                payout_block_data: Default::default(),
            },
            RpcReimbursementStatus::InProgress {
                claim_txid,
                phase: RpcClaimPhase::BridgeProofTimedout {
                    contest_txid: graph_summary.contest,
                },
            },
        ),
        (
            "CounterProofPosted",
            GraphState::CounterProofPosted {
                last_block_height: counterproof_height,
                graph_data: graph_data.clone(),
                graph_summary: graph_summary.clone(),
                signatures: signatures.clone(),
                fulfillment_txid: Some(fulfillment_txid),
                contest_block_height: contest_height,
                refuted_bridge_proof: None,
                counterproofs_and_confs: BTreeMap::from([(
                    0,
                    CounterproofData {
                        txid: graph_summary.counterproofs[0].counterproof,
                        conf_height: counterproof_height,
                        completed_signatures: std::array::from_fn(|_| {
                            Signature::from_slice(&[0x0c; 64]).expect("valid signature")
                        }),
                    },
                )]),
                counterproof_nacks: BTreeMap::new(),
                stake_spent: None,
                payout_connector_spent: None,
                payout_block_data: Default::default(),
            },
            RpcReimbursementStatus::InProgress {
                claim_txid,
                phase: RpcClaimPhase::CounterProofPosted {
                    contest_txid: graph_summary.contest,
                },
            },
        ),
        (
            "AllNackd",
            GraphState::AllNackd {
                last_block_height: ack_height,
                graph_data: graph_data.clone(),
                signatures: signatures.clone(),
                claim_txid,
                contest_txid: Some(graph_summary.contest),
                fulfillment_txid: Some(fulfillment_txid),
                contest_block_height: contest_height,
                expected_payout_txid: graph_summary.contested_payout,
                possible_slash_txid: graph_summary.slash,
            },
            RpcReimbursementStatus::InProgress {
                claim_txid,
                phase: RpcClaimPhase::AllNackd {
                    contest_txid: graph_summary.contest,
                },
            },
        ),
        (
            "Acked",
            GraphState::Acked {
                last_block_height: ack_height,
                graph_data,
                signatures,
                contest_block_height: contest_height,
                expected_slash_txid: graph_summary.slash,
                claim_txid,
                contest_txid: Some(graph_summary.contest),
                fulfillment_txid: Some(fulfillment_txid),
                payout_block_data: Default::default(),
            },
            RpcReimbursementStatus::InProgress {
                claim_txid,
                phase: RpcClaimPhase::Acked {
                    contest_txid: graph_summary.contest,
                },
            },
        ),
        (
            "Withdrawn",
            GraphState::Withdrawn {
                claim_txid,
                payout_txid: graph_summary.uncontested_payout,
                payout_kind: Some(PayoutKind::Uncontested),
            },
            RpcReimbursementStatus::Complete {
                claim_txid: Some(claim_txid),
                payout_txid: graph_summary.uncontested_payout,
                payout_kind: Some(RpcPayoutKind::Uncontested),
            },
        ),
        (
            "WithdrawnContested",
            GraphState::Withdrawn {
                claim_txid,
                payout_txid: graph_summary.contested_payout,
                payout_kind: Some(PayoutKind::Contested),
            },
            RpcReimbursementStatus::Complete {
                claim_txid: Some(claim_txid),
                payout_txid: graph_summary.contested_payout,
                payout_kind: Some(RpcPayoutKind::Contested),
            },
        ),
        (
            "Slashed",
            GraphState::Slashed {
                claim_txid,
                contest_txid: graph_summary.contest,
                slash_txid: graph_summary.slash,
            },
            RpcReimbursementStatus::Slashed {
                claim_txid,
                contest_txid: graph_summary.contest,
                slash_txid: graph_summary.slash,
            },
        ),
        (
            "Aborted",
            GraphState::Aborted {
                claim_txid: Some(claim_txid),
                reason: AbortReason::PayoutConnectorSpent {
                    spending_txid: generate_txid(),
                },
            },
            RpcReimbursementStatus::Aborted { claim_txid },
        ),
        (
            "AbortedWithoutClaim",
            GraphState::Aborted {
                claim_txid: None,
                reason: AbortReason::DepositRequestTakenBack {
                    spending_txid: generate_txid(),
                },
            },
            RpcReimbursementStatus::NotStarted,
        ),
    ];

    // Both monitoring views must agree on the phase; terminal states have no active claim.
    for (state_name, state, expected_status) in cases {
        let active = active_claim_from_state(OPERATOR_IDX, &state).expect(state_name);
        match &expected_status {
            RpcReimbursementStatus::InProgress { claim_txid, phase } => {
                let active = active.expect("active claim");
                assert_eq!(active.claim_txid, *claim_txid);
                assert_eq!(&active.phase, phase);
            }
            _ => assert!(active.is_none()),
        }
        assert_eq!(
            reimbursement_status(&state).expect(state_name),
            expected_status,
            "unexpected reimbursement status for {state_name}",
        );
        if let GraphState::Withdrawn { payout_kind, .. } = &state {
            let wire = serde_json::to_value(&expected_status).unwrap();
            assert_eq!(
                wire["payout_kind"],
                match payout_kind.unwrap() {
                    PayoutKind::Uncontested => "uncontested",
                    PayoutKind::Contested => "contested",
                }
            );
            // Missing evidence must produce an error rather than a guessed payout kind.
            let mut missing_kind = state.clone();
            if let GraphState::Withdrawn { payout_kind, .. } = &mut missing_kind {
                *payout_kind = None;
            }
            assert!(reimbursement_status(&missing_kind).is_err());
        }
        // Retained connector spends override the active phase. For ACK/timeout
        // states, this evidence was accepted before entering that state.
        if matches!(
            state,
            GraphState::Claimed { .. }
                | GraphState::Contested { .. }
                | GraphState::BridgeProofPosted { .. }
                | GraphState::CounterProofPosted { .. }
                | GraphState::BridgeProofTimedout { .. }
                | GraphState::Acked { .. }
        ) {
            let admin_txid =
                generate_spending_tx(OutPoint::new(claim_txid, ClaimTx::ADMIN_PAYOUT_VOUT), &[])
                    .compute_txid();
            let unstaking_txid = generate_spending_tx(
                OutPoint::new(claim_txid, ClaimTx::UNSTAKING_PAYOUT_VOUT),
                &[],
            )
            .compute_txid();
            for (retained_payout_block_data, reason) in [
                (
                    PayoutBlockData {
                        admin_block_txid: Some(admin_txid),
                        unstaking_block_txid: None,
                    },
                    RpcPayoutBlock::Admin,
                ),
                (
                    PayoutBlockData {
                        admin_block_txid: None,
                        unstaking_block_txid: Some(unstaking_txid),
                    },
                    RpcPayoutBlock::Unstaking,
                ),
                (
                    PayoutBlockData {
                        admin_block_txid: Some(admin_txid),
                        unstaking_block_txid: Some(unstaking_txid),
                    },
                    RpcPayoutBlock::AdminAndUnstaking,
                ),
            ] {
                let mut blocked = state.clone();
                match &mut blocked {
                    GraphState::Claimed {
                        payout_connector_spent,
                        payout_block_data,
                        ..
                    }
                    | GraphState::Contested {
                        payout_connector_spent,
                        payout_block_data,
                        ..
                    }
                    | GraphState::BridgeProofPosted {
                        payout_connector_spent,
                        payout_block_data,
                        ..
                    }
                    | GraphState::CounterProofPosted {
                        payout_connector_spent,
                        payout_block_data,
                        ..
                    } => {
                        *payout_connector_spent = retained_payout_block_data
                            .admin_block_txid
                            .or(retained_payout_block_data.unstaking_block_txid);
                        *payout_block_data = retained_payout_block_data;
                    }
                    GraphState::BridgeProofTimedout {
                        payout_block_data, ..
                    }
                    | GraphState::Acked {
                        payout_block_data, ..
                    } => {
                        *payout_block_data = retained_payout_block_data;
                    }
                    _ => unreachable!(),
                }
                let phase = RpcClaimPhase::Blocked {
                    contest_txid: (!matches!(state, GraphState::Claimed { .. }))
                        .then_some(graph_summary.contest),
                    reason,
                };
                assert_eq!(
                    reimbursement_status(&blocked).unwrap(),
                    RpcReimbursementStatus::InProgress {
                        claim_txid,
                        phase: phase.clone()
                    }
                );
                assert_eq!(
                    active_claim_from_state(OPERATOR_IDX, &blocked)
                        .unwrap()
                        .unwrap()
                        .phase,
                    phase
                );
            }
        }
        // These states discard the graph summary, so they require the retained contest ID.
        let mut missing_contest = state.clone();
        if let GraphState::AllNackd { contest_txid, .. } | GraphState::Acked { contest_txid, .. } =
            &mut missing_contest
        {
            *contest_txid = None;
            assert!(reimbursement_status(&missing_contest).is_err());
            assert!(active_claim_from_state(OPERATOR_IDX, &missing_contest).is_err());
        }
    }
}

#[test]
fn cooperative_reimbursement_status_requires_confirmed_payout() {
    let fulfillment_txid = generate_txid();
    let payout_txid = test_cooperative_payout_tx().as_ref().compute_txid();
    let cases = [
        (
            DepositState::CooperativePathFailed {
                assignee: OPERATOR_IDX,
                fulfillment_txid,
                last_block_height: 100
                    + test_sm_config().deposit.cooperative_payout_timeout_blocks(),
                expected_cooperative_payout_txid: Some(payout_txid),
            },
            None,
        ),
        (
            DepositState::Spent {
                fulfillment_txid: Some(fulfillment_txid),
                assignee: Some(OPERATOR_IDX),
                cooperative_payout_txid: None,
            },
            None,
        ),
        (
            DepositState::Spent {
                fulfillment_txid: Some(fulfillment_txid),
                assignee: Some(OPERATOR_IDX),
                cooperative_payout_txid: Some(payout_txid),
            },
            Some(RpcReimbursementStatus::Complete {
                claim_txid: None,
                payout_txid,
                payout_kind: None,
            }),
        ),
    ];
    for (state, expected) in cases {
        assert_eq!(cooperative_reimbursement_status(&state), expected);
    }
}

#[test]
fn claim_phase_requires_contest_for_challenged_variants() {
    let contest_txid = generate_txid();
    for phase in [
        "contested",
        "bridge_proof_posted",
        "bridge_proof_timedout",
        "counter_proof_posted",
        "all_nackd",
        "acked",
    ] {
        let wire = serde_json::json!({"phase": phase, "contest_txid": contest_txid});
        let decoded: RpcClaimPhase = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), wire);
        assert!(
            serde_json::from_value::<RpcClaimPhase>(serde_json::json!({"phase": phase})).is_err()
        );
    }
    assert_eq!(
        serde_json::to_value(RpcClaimPhase::Claimed).unwrap(),
        serde_json::json!({"phase": "claimed"})
    );
}

#[test]
fn blocked_claim_phase_reports_reason_with_optional_contest() {
    for (reason, label) in [
        (RpcPayoutBlock::Admin, "admin"),
        (RpcPayoutBlock::Unstaking, "unstaking"),
        (RpcPayoutBlock::AdminAndUnstaking, "admin_and_unstaking"),
    ] {
        for contest_txid in [None, Some(generate_txid())] {
            let phase = RpcClaimPhase::Blocked {
                contest_txid,
                reason,
            };
            let wire = serde_json::json!({"phase": "blocked", "contest_txid": contest_txid, "reason": label});
            assert_eq!(serde_json::to_value(&phase).unwrap(), wire);
            assert_eq!(
                serde_json::from_value::<RpcClaimPhase>(wire).unwrap(),
                phase
            );
        }
    }
}
