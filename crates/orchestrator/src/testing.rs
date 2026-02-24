//! Shared test helpers for the orchestrator crate.
//!
//! Crate-agnostic fixtures (operator tables, descriptors, shared constants) are imported from
//! [`strata_bridge_test_utils::bridge_fixtures`]. This module adds orchestrator-specific SM config
//! construction and registry helpers on top.

use std::{num::NonZero, sync::Arc};

use bitcoin::{
    Amount, Network, OutPoint,
    hashes::{Hash, sha256},
    relative,
};
use strata_bridge_primitives::types::{DepositIdx, GraphIdx, OperatorIdx};
use strata_bridge_sm::{
    deposit::{config::DepositSMCfg, machine::DepositSM},
    graph::{config::GraphSMCfg, context::GraphSMCtx, machine::GraphSM},
};
// Re-export shared bridge fixtures so other test modules in this crate can use them.
pub(crate) use strata_bridge_test_utils::bridge_fixtures::{
    TEST_DEPOSIT_AMOUNT, TEST_MAGIC_BYTES, TEST_OPERATOR_FEE, TEST_POV_IDX, random_p2tr_desc,
    test_operator_table,
};
use strata_bridge_test_utils::{
    bitcoin::generate_xonly_pubkey, bridge_fixtures::TEST_RECOVERY_DELAY,
};
use strata_bridge_tx_graph2::{game_graph::ProtocolParams, transactions::prelude::DepositData};

use crate::sm_registry::{SMConfig, SMRegistry};

/// Number of operators used in orchestrator test fixtures.
pub(crate) const N_TEST_OPERATORS: usize = 3;

/// Initial block height used when constructing test SMs.
pub(crate) const INITIAL_BLOCK_HEIGHT: u64 = 100;

// ===== Config helpers =====

/// Creates a test `DepositSMCfg`, mirroring `bridge-sm/deposit/tests::test_deposit_sm_cfg`.
pub(crate) fn test_deposit_sm_cfg() -> Arc<DepositSMCfg> {
    Arc::new(DepositSMCfg {
        network: Network::Regtest,
        cooperative_payout_timeout_blocks: 144,
        deposit_amount: TEST_DEPOSIT_AMOUNT,
        operator_fee: TEST_OPERATOR_FEE,
        magic_bytes: TEST_MAGIC_BYTES.into(),
        recovery_delay: TEST_RECOVERY_DELAY,
    })
}

/// Creates a test `GraphSMCfg`, mirroring `bridge-sm/graph/tests::test_graph_sm_cfg`.
pub(crate) fn test_graph_sm_cfg() -> Arc<GraphSMCfg> {
    let n_watchtowers = N_TEST_OPERATORS - 1;
    let watchtower_pubkeys = (0..n_watchtowers)
        .map(|_| generate_xonly_pubkey())
        .collect();
    let watchtower_fault_pubkeys = (0..n_watchtowers)
        .map(|_| generate_xonly_pubkey())
        .collect();
    let slash_watchtower_descriptors = (0..n_watchtowers).map(|_| random_p2tr_desc()).collect();

    Arc::new(GraphSMCfg {
        game_graph_params: ProtocolParams {
            network: Network::Regtest,
            magic_bytes: TEST_MAGIC_BYTES.into(),
            contest_timelock: relative::LockTime::from_height(10),
            proof_timelock: relative::LockTime::from_height(5),
            ack_timelock: relative::LockTime::from_height(10),
            nack_timelock: relative::LockTime::from_height(5),
            contested_payout_timelock: relative::LockTime::from_height(15),
            counterproof_n_bytes: NonZero::new(128).unwrap(),
            deposit_amount: TEST_DEPOSIT_AMOUNT,
            stake_amount: Amount::from_sat(100_000_000),
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

/// Creates a combined `SMConfig` from the test deposit and graph configs.
pub(crate) fn test_sm_config() -> SMConfig {
    SMConfig {
        deposit: test_deposit_sm_cfg(),
        graph: test_graph_sm_cfg(),
    }
}

/// Creates an empty `SMRegistry` with test config.
pub(crate) fn test_empty_registry() -> SMRegistry {
    SMRegistry::new(test_sm_config())
}

// ===== Registry population helpers =====

/// Inserts one deposit SM and `N_TEST_OPERATORS` graph SMs for the given deposit index.
pub(crate) fn insert_deposit_with_graphs(registry: &mut SMRegistry, deposit_idx: DepositIdx) {
    let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
    let cfg = test_deposit_sm_cfg();
    let depositor_pubkey = operator_table.pov_btc_key().x_only_public_key().0;

    let data = DepositData {
        deposit_idx,
        deposit_request_outpoint: OutPoint::default(),
        magic_bytes: cfg.magic_bytes(),
    };

    // Use the public DepositSM::new constructor
    let dsm = DepositSM::new(
        cfg,
        operator_table.clone(),
        data,
        depositor_pubkey,
        INITIAL_BLOCK_HEIGHT,
    );
    let deposit_outpoint = dsm.context().deposit_outpoint();

    registry
        .insert_deposit(deposit_idx, dsm)
        .expect("test helper must not insert duplicate deposit index");

    // Insert one GraphSM per operator
    for op_idx in 0..N_TEST_OPERATORS as OperatorIdx {
        let graph_idx = GraphIdx {
            deposit: deposit_idx,
            operator: op_idx,
        };
        let gsm_ctx = GraphSMCtx {
            graph_idx,
            deposit_outpoint,
            stake_outpoint: OutPoint::default(),
            unstaking_image: sha256::Hash::all_zeros(),
            operator_table: operator_table.clone(),
        };
        let (gsm, _duty) = GraphSM::new(gsm_ctx, INITIAL_BLOCK_HEIGHT);
        registry
            .insert_graph(graph_idx, gsm)
            .expect("test helper must not insert duplicate graph index");
    }
}

/// Creates a pre-populated registry with `n_deposits` deposits, each with `N_TEST_OPERATORS` graph
/// SMs.
pub(crate) fn test_populated_registry(n_deposits: usize) -> SMRegistry {
    let mut registry = test_empty_registry();
    for i in 0..n_deposits {
        insert_deposit_with_graphs(&mut registry, i as DepositIdx);
    }
    registry
}
