//! Classification of on-chain events (buried blocks) into state-machine-specific events.
//!
//!
//! This module handles:
//! - Detecting new deposit requests and spawning SMs
//! - Running [`TxClassifier::classify_tx()`] per SM per transaction
//! - Appending `NewBlock` cursor events for all active SMs
//!
//! [`TxClassifier::classify_tx()`]: strata_bridge_sm::tx_classifier::TxClassifier::classify_tx

use std::{collections::BTreeMap, sync::Arc};

use bitcoin::{
    OutPoint, Transaction,
    hashes::{Hash, sha256},
    hex::DisplayHex,
    secp256k1::XOnlyPublicKey,
};
use btc_tracker::event::BlockEvent;
use strata_asm_txs_bridge_v1::deposit_request::parse_drt;
use strata_bridge_p2p_types2::GraphIdx;
use strata_bridge_primitives::{
    operator_table::OperatorTable,
    types::{BitcoinBlockHeight, DepositIdx, OperatorIdx},
};
use strata_bridge_sm::{
    deposit::{
        config::DepositSMCfg,
        events::{DepositEvent, NewBlockEvent as DepositNewBlockEvent},
        machine::DepositSM,
    },
    graph::{
        config::GraphSMCfg,
        context::GraphSMCtx,
        events::{GraphEvent, NewBlockEvent as GraphNewBlockEvent},
        machine::GraphSM,
    },
    tx_classifier::TxClassifier,
};
use strata_bridge_tx_graph2::transactions::prelude::DepositData;
use tracing::error;

use crate::{
    sm_registry::SMRegistry,
    sm_types::{SMEvent, SMId, UnifiedDuty},
};

/// Classifies a buried block into a list of ([`SMId`], [`SMEvent`]) targets and a list of new
/// [`UnifiedDuty`]'s.
pub(crate) fn classify_block(
    initial_operator_table: &OperatorTable,
    registry: &mut SMRegistry,
    block_event: &BlockEvent,
) -> (Vec<(SMId, SMEvent)>, Vec<UnifiedDuty>) {
    let (cur_stakes, cur_unstaking_images) = get_mocked_stake_data(initial_operator_table);

    let deposit_cfg = registry.cfg().deposit.clone();
    let graph_cfg = registry.cfg().graph.clone();
    let height = block_event
        .block
        .bip34_block_height()
        .expect("must have a valid block height");

    // Snapshot pre-existing SM IDs: newly created SMs already know the current block height,
    // so only pre-existing ones need a NewBlock cursor event.
    let existing_deposits = registry.get_deposit_ids();
    let existing_graphs = registry.get_graph_ids();

    let mut targets = Vec::new();
    let mut initial_duties = Vec::new();

    for tx in &block_event.block.txdata {
        // If this tx is a DRT, register new DepositSM + per-operator GraphSMs
        initial_duties.extend(try_register_deposit(
            &deposit_cfg,
            initial_operator_table,
            &cur_stakes,
            &cur_unstaking_images,
            registry,
            tx,
            height,
        ));

        // Classify this tx against every active SM via TxClassifier
        targets.extend(classify_tx_for_all_sms(
            &deposit_cfg,
            &graph_cfg,
            registry,
            tx,
            height,
        ));
    }

    // Append NewBlock cursor events only for pre-existing SMs
    targets.extend(new_block_events(
        &existing_deposits,
        &existing_graphs,
        height,
    ));

    (targets, initial_duties)
}

/// Generates mocked stake data for the given operator table.
fn get_mocked_stake_data(
    initial_operator_table: &OperatorTable,
) -> (BTreeMap<u32, OutPoint>, BTreeMap<u32, sha256::Hash>) {
    // TODO: (@Rajil1213) query Operator and Stake SMs for operator table and stake data
    // For now, use static values.

    let mock_outpoint = OutPoint::default(); // dummy outpoint
    let stake_outpoints = initial_operator_table
        .operator_idxs()
        .into_iter()
        .map(|idx| (idx, mock_outpoint))
        .collect();

    let mock_hash = sha256::Hash::from_slice(&[0u8; 32]).expect("dummy hash must be valid");
    let unstaking_images = initial_operator_table
        .operator_idxs()
        .into_iter()
        .map(|idx| (idx, mock_hash))
        .collect();
    // dummy stake images
    (stake_outpoints, unstaking_images)
}

/// If `tx` is a valid deposit request transaction, registers a [`DepositSM`] and per-operator
/// [`GraphSM`]s into the registry.
///
/// Returns initial duties emitted by [`GraphSM`] constructors (e.g., `GenerateGraphData`).
/// Returns an empty vec if the transaction is not a DRT.
fn try_register_deposit(
    deposit_cfg: &Arc<DepositSMCfg>,
    cur_operator_table: &OperatorTable,
    cur_stakes: &BTreeMap<OperatorIdx, OutPoint>,
    cur_unstaking_images: &BTreeMap<OperatorIdx, sha256::Hash>,
    registry: &mut SMRegistry,
    tx: &Transaction,
    height: BitcoinBlockHeight,
) -> Vec<UnifiedDuty> {
    let Ok(drt_info) = parse_drt(tx) else {
        return Vec::new();
    };

    let depositor_pubkey = drt_info.header_aux().recovery_pk();
    let Ok(depositor_pubkey) = XOnlyPublicKey::from_slice(depositor_pubkey) else {
        error!(pk=%depositor_pubkey.to_lower_hex_string(), "invalid depositor pubkey in DRT, ignoring");
        return Vec::new();
    };

    let drt_txid = tx.compute_txid();
    let magic_bytes = deposit_cfg.magic_bytes;

    // cast safety: number of deposits will always be < u32::MAX
    let deposit_idx = registry.num_deposits() as DepositIdx;

    // always second output for now
    let deposit_request_outpoint = OutPoint::new(drt_txid, 1);
    let deposit_data = DepositData {
        deposit_idx,
        deposit_request_outpoint,
        magic_bytes,
    };

    let dsm = DepositSM::new(
        deposit_cfg.clone(),
        cur_operator_table.clone(),
        deposit_data,
        depositor_pubkey,
        height,
    );

    let deposit_outpoint = dsm.context().deposit_outpoint();
    registry.insert_deposit(deposit_idx, dsm);

    // Register one GraphSM per operator, collecting initial duties
    cur_operator_table
        .operator_idxs()
        .iter()
        .filter_map(|&op_idx| {
            let graph_idx = GraphIdx {
                deposit: deposit_idx,
                operator: op_idx,
            };

            let stake_outpoint = *cur_stakes
                .get(&op_idx)
                .expect("must have stake for operator idx");

            let unstaking_image = *cur_unstaking_images
                .get(&op_idx)
                .expect("must have unstaking image for operator idx");

            let gsm_ctx = GraphSMCtx {
                graph_idx,
                deposit_outpoint,
                stake_outpoint,
                unstaking_image,
                operator_table: cur_operator_table.clone(),
            };

            let (gsm, duty) = GraphSM::new(gsm_ctx, height);
            registry.insert_graph(gsm.context().graph_idx(), gsm);

            duty.map(UnifiedDuty::from)
        })
        .collect()
}

/// Runs [`TxClassifier::classify_tx()`] on every active SM for a single transaction.
///
/// Returns ([`SMId`], [`SMEvent`]) pairs for each SM that recognized the transaction.
fn classify_tx_for_all_sms(
    deposit_cfg: &Arc<DepositSMCfg>,
    graph_cfg: &Arc<GraphSMCfg>,
    registry: &SMRegistry,
    tx: &Transaction,
    height: BitcoinBlockHeight,
) -> Vec<(SMId, SMEvent)> {
    registry
        .deposits()
        .filter_map(|(&deposit_idx, sm)| {
            sm.classify_tx(deposit_cfg, tx, height)
                .map(|ev| (deposit_idx.into(), ev.into()))
        })
        .chain(registry.graphs().filter_map(|(&graph_idx, sm)| {
            sm.classify_tx(graph_cfg, tx, height)
                .map(|ev| (graph_idx.into(), ev.into()))
        }))
        .collect()
}

/// Appends a `NewBlock` cursor event for provided SMs.
///
/// This lets each SM track the latest block height for timelock-related state transitions.
fn new_block_events(
    deposit_ids: &[DepositIdx],
    graph_ids: &[GraphIdx],
    height: BitcoinBlockHeight,
) -> Vec<(SMId, SMEvent)> {
    let deposit_event = DepositEvent::NewBlock(DepositNewBlockEvent {
        block_height: height,
    });
    let graph_event = GraphEvent::NewBlock(GraphNewBlockEvent {
        block_height: height,
    });

    deposit_ids
        .iter()
        .map(|&idx| (idx.into(), deposit_event.clone().into()))
        .chain(
            graph_ids
                .iter()
                .map(|&idx| (idx.into(), graph_event.clone().into())),
        )
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use bitcoin::{Amount, Network, absolute, transaction};
    use strata_bridge_test_utils::bridge_fixtures::{TEST_MAGIC_BYTES, TEST_RECOVERY_DELAY};

    use super::*;
    use crate::testing::{
        N_TEST_OPERATORS, TEST_POV_IDX, test_operator_table, test_populated_registry,
    };

    const TEST_HEIGHT: BitcoinBlockHeight = 200;

    // ===== new_block_events tests =====

    #[test]
    fn new_block_events_empty_ids() {
        let events = new_block_events(&[], &[], TEST_HEIGHT);
        assert!(events.is_empty());
    }

    #[test]
    fn new_block_events_deposits_only() {
        let deposit_ids = vec![0u32, 1, 2];
        let events = new_block_events(&deposit_ids, &[], TEST_HEIGHT);

        assert_eq!(events.len(), 3);
        for (id, _event) in &events {
            assert!(matches!(id, SMId::Deposit(_)));
        }
    }

    #[test]
    fn new_block_events_graphs_only() {
        let graph_ids = vec![
            GraphIdx {
                deposit: 0,
                operator: 0,
            },
            GraphIdx {
                deposit: 0,
                operator: 1,
            },
        ];
        let events = new_block_events(&[], &graph_ids, TEST_HEIGHT);

        assert_eq!(events.len(), 2);
        for (id, _event) in &events {
            assert!(matches!(id, SMId::Graph(_)));
        }
    }

    #[test]
    fn new_block_events_mixed() {
        let deposit_ids = vec![0u32, 1];
        let graph_ids = vec![
            GraphIdx {
                deposit: 0,
                operator: 0,
            },
            GraphIdx {
                deposit: 1,
                operator: 0,
            },
            GraphIdx {
                deposit: 1,
                operator: 1,
            },
        ];
        let events = new_block_events(&deposit_ids, &graph_ids, TEST_HEIGHT);

        assert_eq!(events.len(), 5);
    }

    #[test]
    fn new_block_events_correct_height() {
        let deposit_ids = vec![0u32];
        let graph_ids = vec![GraphIdx {
            deposit: 0,
            operator: 0,
        }];
        let events = new_block_events(&deposit_ids, &graph_ids, TEST_HEIGHT);

        for (_id, event) in events {
            match event {
                SMEvent::Deposit(boxed) => match *boxed {
                    DepositEvent::NewBlock(ref nb) => assert_eq!(nb.block_height, TEST_HEIGHT),
                    other => panic!("expected NewBlock, got {other}"),
                },
                SMEvent::Graph(boxed) => match *boxed {
                    GraphEvent::NewBlock(ref nb) => assert_eq!(nb.block_height, TEST_HEIGHT),
                    other => panic!("expected NewBlock, got {other}"),
                },
            }
        }
    }

    // ===== try_register_deposit tests =====

    #[test]
    fn try_register_deposit_non_drt() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let deposit_cfg = Arc::new(DepositSMCfg {
            network: Network::Regtest,
            cooperative_payout_timeout_blocks: 144,
            deposit_amount: Amount::from_sat(10_000_000),
            operator_fee: Amount::from_sat(10_000),
            magic_bytes: TEST_MAGIC_BYTES.into(),
            recovery_delay: TEST_RECOVERY_DELAY,
        });

        let mut registry = test_populated_registry(0);

        // A random transaction that is not a DRT
        let random_tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let duties = try_register_deposit(
            &deposit_cfg,
            &operator_table,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &mut registry,
            &random_tx,
            100,
        );

        assert!(duties.is_empty());
        assert_eq!(registry.num_deposits(), 0);
    }
}
