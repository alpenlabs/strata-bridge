//! Tests for monitoring response conversion helpers.

use std::{collections::BTreeMap, num::NonZero, sync::Arc};

use bitcoin::{
    Amount, Network, OutPoint, PublicKey, Txid,
    hashes::{Hash, sha256},
    relative,
};
use secp256k1::schnorr::Signature;
use strata_bridge_connectors::prelude::{DepositRequestConnector, NOfNConnector};
use strata_bridge_orchestrator::sm_registry::{SMConfig, SMRegistry};
use strata_bridge_primitives::{
    operator_table::OperatorTable,
    types::{DepositIdx, GraphIdx, OperatorIdx},
};
use strata_bridge_rpc::types::{
    RpcBridgeDutyStatus, RpcClaimPhase, RpcReimbursementStatus, RpcWithdrawalStatus,
};
use strata_bridge_sm::{
    deposit::{
        config::DepositSMCfg, context::DepositSMCtx, machine::DepositSM, state::DepositState,
    },
    graph::{config::GraphSMCfg, context::GraphSMCtx, state::GraphState},
    stake::config::StakeSMCfg,
};
use strata_bridge_test_utils::{
    bitcoin::{generate_tx, generate_xonly_pubkey},
    bridge_fixtures::{
        TEST_DEPOSIT_AMOUNT, TEST_MAGIC_BYTES, TEST_OPERATOR_FEE, TEST_POV_IDX,
        TEST_RECOVERY_DELAY, random_p2tr_desc, test_operator_table,
    },
    musig2::{generate_agg_nonce, generate_partial_signature, generate_pubnonce},
    prelude::generate_txid,
};
use strata_bridge_tx_graph::{
    game_graph::{DepositParams, GameGraphSummary, ProtocolParams},
    stake_graph::ProtocolParams as StakeProtocolParams,
    transactions::{
        cooperative_payout::{CooperativePayoutData, CooperativePayoutTx},
        deposit::{DepositData, DepositTx},
    },
};
use strata_predicate::PredicateKey;
use zkaleido::{Proof, ProofReceipt, PublicValues};

use super::super::monitoring::{
    active_claim_from_state, aggregate_signatures_response, bridge_duties_for_deposit,
    duty_applies_to_operator, graph_data_response, operator_idx_from_registry,
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
    GraphSMCtx {
        graph_idx: test_graph_idx(),
        deposit_outpoint: OutPoint::new(bitcoin::Txid::all_zeros(), 7),
        stake_outpoint: OutPoint::new(bitcoin::Txid::all_zeros(), 8),
        unstaking_image: sha256::Hash::hash(b"test"),
        operator_table: test_operator_table(3, TEST_POV_IDX),
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
        admin_pubkey: generate_xonly_pubkey(),
        payout_descs: (0..3).map(|_| random_p2tr_desc()).collect(),
        bridge_proof_predicate: PredicateKey::always_accept(),
    }
}

fn test_deposit_tx() -> DepositTx {
    let n_of_n_pubkey = generate_xonly_pubkey();
    let deposit_connector =
        NOfNConnector::new(Network::Regtest, n_of_n_pubkey, TEST_DEPOSIT_AMOUNT);
    let deposit_request_connector = DepositRequestConnector::new(
        Network::Regtest,
        n_of_n_pubkey,
        generate_xonly_pubkey(),
        relative::Height::from_height(144),
        DepositTx::drt_required(TEST_DEPOSIT_AMOUNT),
    );

    DepositTx::new(
        DepositData {
            deposit_idx: DEPOSIT_IDX,
            deposit_request_outpoint: OutPoint::new(Txid::all_zeros(), 0),
            magic_bytes: TEST_MAGIC_BYTES.into(),
        },
        deposit_connector,
        deposit_request_connector,
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

fn test_sm_config() -> SMConfig {
    SMConfig {
        deposit: Arc::new(DepositSMCfg {
            network: Network::Regtest,
            cooperative_payout_timeout_blocks: 144,
            deposit_amount: TEST_DEPOSIT_AMOUNT,
            operator_fee: TEST_OPERATOR_FEE,
            magic_bytes: TEST_MAGIC_BYTES.into(),
            recovery_delay: TEST_RECOVERY_DELAY,
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
    }
}

fn test_deposit_sm(deposit_idx: DepositIdx, operator_table: OperatorTable) -> DepositSM {
    DepositSM {
        context: DepositSMCtx {
            deposit_idx,
            deposit_request_outpoint: OutPoint::new(Txid::all_zeros(), 1),
            deposit_outpoint: OutPoint::new(Txid::all_zeros(), 2),
            operator_table,
        },
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
    };

    let claim = active_claim_from_state(OPERATOR_IDX, &state).expect("claim should be returned");

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
    };

    let claim = active_claim_from_state(OPERATOR_IDX, &state).expect("claim should be returned");

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
    };

    let claim = active_claim_from_state(OPERATOR_IDX, &state);

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
    };

    let claim = active_claim_from_state(OPERATOR_IDX, &state).expect("claim should be returned");

    assert!(claim.fulfilled);
    assert_eq!(claim.phase, RpcClaimPhase::Contested);
}

#[test]
fn bridge_duties_for_deposit_reports_each_deposit_state() {
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
                payout_nonces: pubnonces,
                payout_aggregated_nonce: generate_agg_nonce(),
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
            },
            no_duties.clone(),
        ),
        (
            "Spent",
            DepositState::Spent {
                fulfillment_txid: Some(generate_txid()),
            },
            no_duties.clone(),
        ),
        ("Aborted", DepositState::Aborted, no_duties),
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
fn operator_idx_from_registry_checks_until_btc_key_is_found() {
    let mut registry = SMRegistry::new(test_sm_config());
    let table_without_operator = test_operator_table(1, TEST_POV_IDX);
    let table_with_operator = test_operator_table(3, TEST_POV_IDX);
    let operator_pk = PublicKey::from(
        table_with_operator
            .idx_to_btc_key(&OPERATOR_IDX)
            .expect("operator should be in test operator table"),
    );

    registry
        .insert_deposit(0, test_deposit_sm(0, table_without_operator))
        .expect("first test deposit should be inserted");
    registry
        .insert_deposit(1, test_deposit_sm(1, table_with_operator))
        .expect("second test deposit should be inserted");

    let operator_idx = operator_idx_from_registry(&registry, &operator_pk);

    assert_eq!(operator_idx, Some(OPERATOR_IDX));
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
fn withdrawal_status_reports_each_deposit_state() {
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
                payout_nonces: pubnonces,
                payout_aggregated_nonce: generate_agg_nonce(),
                payout_partial_signatures: partial_signatures,
            },
        ),
        (
            "CooperativePathFailed",
            DepositState::CooperativePathFailed {
                assignee: OPERATOR_IDX,
                last_block_height: 100,
                fulfillment_txid: generate_txid(),
            },
        ),
        (
            "Spent",
            DepositState::Spent {
                fulfillment_txid: Some(fulfillment_txid),
            },
        ),
        (
            "SpentWithoutFulfillmentTxid",
            DepositState::Spent {
                fulfillment_txid: None,
            },
        ),
        ("Aborted", DepositState::Aborted),
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
    let graph_data = test_graph_data();
    let graph_summary = test_graph_summary();
    let claim_txid = graph_summary.claim;
    let fulfillment_txid = generate_txid();
    let payout_txid = generate_txid();
    let slash_txid = generate_txid();
    let signatures = vec![Signature::from_slice(&[0x0c; 64]).expect("valid signature")];
    let pubnonces = BTreeMap::from([(OPERATOR_IDX, vec![generate_pubnonce()])]);
    let partial_signatures = BTreeMap::from([(OPERATOR_IDX, vec![generate_partial_signature()])]);
    let not_started = RpcReimbursementStatus::NotStarted;

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
                pubnonces: pubnonces.clone(),
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
                agg_nonces: vec![generate_agg_nonce()],
                partial_signatures: partial_signatures.clone(),
            },
            not_started.clone(),
        ),
        (
            "GraphSigned",
            GraphState::GraphSigned {
                last_block_height: 100,
                graph_data: graph_data.clone(),
                graph_summary: graph_summary.clone(),
                agg_nonces: Some(vec![generate_agg_nonce()]),
                signatures: signatures.clone(),
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
                contest_block_height: 100,
            },
            RpcReimbursementStatus::InProgress {
                claim_txid,
                phase: RpcClaimPhase::Contested,
            },
        ),
        (
            "BridgeProofPosted",
            GraphState::BridgeProofPosted {
                last_block_height: 100,
                graph_data: graph_data.clone(),
                graph_summary: graph_summary.clone(),
                signatures: signatures.clone(),
                fulfillment_txid: Some(fulfillment_txid),
                contest_block_height: 100,
                bridge_proof_tx: generate_tx(1, 1),
                bridge_proof_block_height: 101,
                proof: dummy_proof_receipt(),
            },
            RpcReimbursementStatus::InProgress {
                claim_txid,
                phase: RpcClaimPhase::BridgeProofPosted,
            },
        ),
        (
            "BridgeProofTimedout",
            GraphState::BridgeProofTimedout {
                last_block_height: 100,
                graph_data: graph_data.clone(),
                graph_summary: graph_summary.clone(),
                signatures: signatures.clone(),
                fulfillment_txid: Some(fulfillment_txid),
                contest_block_height: 100,
                expected_slash_txid: slash_txid,
                claim_txid,
            },
            RpcReimbursementStatus::InProgress {
                claim_txid,
                phase: RpcClaimPhase::BridgeProofTimedout,
            },
        ),
        (
            "CounterProofPosted",
            GraphState::CounterProofPosted {
                last_block_height: 100,
                graph_data: graph_data.clone(),
                graph_summary: graph_summary.clone(),
                signatures: signatures.clone(),
                fulfillment_txid: Some(fulfillment_txid),
                contest_block_height: 100,
                refuted_bridge_proof: None,
                counterproofs_and_confs: BTreeMap::new(),
                counterproof_nacks: BTreeMap::new(),
            },
            RpcReimbursementStatus::InProgress {
                claim_txid,
                phase: RpcClaimPhase::CounterProofPosted,
            },
        ),
        (
            "AllNackd",
            GraphState::AllNackd {
                last_block_height: 100,
                graph_data: graph_data.clone(),
                signatures: signatures.clone(),
                claim_txid,
                fulfillment_txid: Some(fulfillment_txid),
                contest_block_height: 100,
                expected_payout_txid: payout_txid,
                possible_slash_txid: slash_txid,
            },
            RpcReimbursementStatus::InProgress {
                claim_txid,
                phase: RpcClaimPhase::AllNackd,
            },
        ),
        (
            "Acked",
            GraphState::Acked {
                last_block_height: 100,
                graph_data,
                signatures,
                contest_block_height: 100,
                expected_slash_txid: slash_txid,
                claim_txid,
                fulfillment_txid: Some(fulfillment_txid),
            },
            RpcReimbursementStatus::InProgress {
                claim_txid,
                phase: RpcClaimPhase::Acked,
            },
        ),
        (
            "Withdrawn",
            GraphState::Withdrawn {
                claim_txid,
                payout_txid,
            },
            RpcReimbursementStatus::Complete {
                claim_txid,
                payout_txid,
            },
        ),
        (
            "Slashed",
            GraphState::Slashed {
                claim_txid,
                slash_txid,
            },
            RpcReimbursementStatus::Slashed { claim_txid },
        ),
        (
            "Aborted",
            GraphState::Aborted {
                claim_txid,
                payout_connector_spend_txid: generate_txid(),
                reason: "Payout connector spent".to_string(),
            },
            RpcReimbursementStatus::Aborted { claim_txid },
        ),
    ];

    for (state_name, state, expected_status) in cases {
        assert_eq!(
            reimbursement_status(&state),
            expected_status,
            "unexpected reimbursement status for {state_name}",
        );
    }
}
