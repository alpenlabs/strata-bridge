//! Classification of on-chain events (buried blocks) into state-machine-specific events.
//!
//!
//! This module handles:
//! - Detecting new deposit requests and spawning SMs
//! - Running [`TxClassifier::classify_tx()`] per SM per transaction
//! - Appending `NewBlock` cursor events for all active SMs
//!
//! [`TxClassifier::classify_tx()`]: strata_bridge_sm::tx_classifier::TxClassifier::classify_tx

use std::{sync::Arc, time::Instant};

use bitcoin::{OutPoint, Transaction};
use btc_tracker::event::BlockEvent;
use strata_asm_proto_bridge_v1_txs::deposit_request::DRT_OUTPUT_INDEX;
use strata_bridge_primitives::{
    operator_table::OperatorTable,
    types::{BitcoinBlockHeight, DepositIdx, GraphIdx, OperatorIdx},
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
    stake::{
        config::StakeSMCfg,
        events::{NewBlockEvent as StakeNewBlockEvent, StakeEvent},
    },
    tx_classifier::TxClassifier,
};
use strata_bridge_tx_graph::transactions::prelude::DepositData;
use tracing::{Level, info, warn};

use super::drt;
use crate::{
    applicator::Applicator,
    errors::{PipelineError, ProcessError},
    observability,
    sm_registry::{ActiveOperatorSnapshot, SMRegistry},
    sm_types::{SMEvent, SMId, UnifiedDuty},
};

/// Processes a buried block by iterating its transactions in chain order.
///
/// For each transaction, seed events are classified and applied as a fixed-point batch via the
/// [`Applicator`]. This ensures that state changes from earlier transactions (e.g., stake
/// confirmations) are visible when classifying later transactions (e.g., DRTs) in the same block.
///
/// After all transactions are processed, `NewBlock` cursor events are emitted for all SMs that
/// existed before the block was processed.
pub(crate) fn process_block(
    applicator: &mut Applicator<'_>,
    initial_operator_table: &OperatorTable,
    block_event: &BlockEvent,
) -> Result<(), PipelineError> {
    let started = Instant::now();
    let transaction_count = block_event.block.txdata.len();
    let result = process_block_inner(applicator, initial_operator_table, block_event);
    observability::record_block(
        if result.is_ok() { "success" } else { "error" },
        transaction_count,
        started.elapsed(),
    );
    result
}

fn process_block_inner(
    applicator: &mut Applicator<'_>,
    initial_operator_table: &OperatorTable,
    block_event: &BlockEvent,
) -> Result<(), PipelineError> {
    let deposit_cfg = applicator.registry().cfg().deposit.clone();
    let graph_cfg = applicator.registry().cfg().graph.clone();
    let stake_cfg = applicator.registry().cfg().stake.clone();
    let height = block_event
        .block
        .bip34_block_height()
        .expect("must have a valid block height");

    // Snapshot pre-existing SM IDs: newly created SMs already know the current block height,
    // so only pre-existing ones need a NewBlock cursor event.
    let existing_deposits = applicator.registry().get_deposit_ids();
    let existing_graphs = applicator.registry().get_graph_ids();
    let existing_stakes = applicator.registry().get_stake_ids();

    for tx in &block_event.block.txdata {
        // If this tx is a DRT, register new DepositSM + per-operator GraphSMs using the currently
        // active operator snapshot. Because stake SM state transitions settle between transaction
        // batches via the Applicator, a stake transition that removes an operator from the active
        // set in an earlier transaction will be reflected here for a DRT appearing later in the
        // same block.
        let initial_duties =
            try_register_deposit(&deposit_cfg, initial_operator_table, applicator, tx, height)?;

        // Classify this tx against every active SM via TxClassifier
        // PERF: (Rajil1213) this needs benchmarking to make sure that classifying every tx
        // against every SM is not too expensive. If it is, we can optimize by maintaining a
        // cache of all relevant txids/outpoints per SM and only running TxClassifier if the tx
        // contains a relevant txid/outpoint and do it only on the relevant SM. It is too
        // expensive if for a saturated bitcoin block (~3000 txs) and ~1000*15 SMs (45M
        // lookups), we are unable to classify the block within ~5 minutes (half the average
        // block time) on a reasonably powerful machine.
        let state_machine_count = applicator.registry().active_sm_count();
        let classification_started = Instant::now();
        let seed_events = classify_tx_for_all_sms(
            &deposit_cfg,
            &graph_cfg,
            &stake_cfg,
            applicator.registry(),
            tx,
            height,
        );
        observability::record_block_tx_classification(
            state_machine_count,
            seed_events.len(),
            classification_started.elapsed(),
        );

        // Apply seed events as one fixed-point batch per transaction
        applicator.apply_batch(seed_events)?;

        // Add initial duties from newly created SMs (produced by SM constructors, not the STF)
        applicator.add_duties(initial_duties);
    }

    // Append NewBlock cursor events for pre-existing SMs as the final batch
    let new_block = new_block_events(
        &existing_deposits,
        &existing_graphs,
        &existing_stakes,
        height,
    );
    applicator.apply_batch(new_block)?;

    Ok(())
}

/// If `tx` is a valid deposit request transaction, registers a [`DepositSM`] and per-operator
/// [`GraphSM`]s into the registry.
///
/// Returns initial duties emitted by [`GraphSM`] constructors (e.g., `GenerateGraphData`).
/// Returns `Ok(Vec::new())` if the registry is not yet ready (no stakes confirmed, or this
/// node's operator is not in the active set) or if the transaction fails DRT validation.
fn try_register_deposit(
    deposit_cfg: &Arc<DepositSMCfg>,
    full_operator_table: &OperatorTable,
    applicator: &mut Applicator<'_>,
    tx: &Transaction,
    height: BitcoinBlockHeight,
) -> Result<Vec<UnifiedDuty>, ProcessError> {
    // Cheapest filter first: skip the ~99% of block transactions that don't carry our SPS-50
    // envelope. Subsequent gates allocate (snapshot) or parse the full DRT, so we want to
    // avoid them on non-DRT traffic.
    if !drt::is_our_drt_envelope(tx, deposit_cfg) {
        return Ok(Vec::new());
    }

    // Activation rule: before any DSM / GSM may become active, one stake state machine must exist
    // for every configured operator and all of them must have reached `Confirmed` or higher.
    if !applicator
        .registry()
        .all_operators_have_staked(full_operator_table)
    {
        return Ok(Vec::new());
    }

    let snapshot = match applicator
        .registry()
        .active_operator_snapshot(full_operator_table)
    {
        Ok(snap) => snap,
        Err(err) => {
            warn!(%err, "skipping DRT check: could not derive active operator snapshot");
            return Ok(Vec::new());
        }
    };

    let ActiveOperatorSnapshot {
        operator_table: active_operator_table,
        stake_inputs,
        unstaking_images,
    } = snapshot;

    let valid = match drt::validate_candidate(tx, deposit_cfg, &active_operator_table) {
        Ok(valid) => valid,
        Err(err) => {
            warn!(%err, txid=%tx.compute_txid(), "rejecting DRT candidate");
            return Ok(Vec::new());
        }
    };

    let drt_txid = tx.compute_txid();
    let span = tracing::span!(Level::INFO, "registering new deposit", drt_txid=%drt_txid);
    let _entered = span.entered();
    info!(
        active_operator_count = active_operator_table.operator_idxs().len(),
        "passed validation; registering DSM / GSMs from active operator snapshot"
    );

    let deposit_idx = applicator.registry().next_deposit_idx()?;
    let deposit_request_outpoint = OutPoint::new(drt_txid, DRT_OUTPUT_INDEX as u32);
    let deposit_data = DepositData {
        deposit_idx,
        deposit_request_outpoint,
        magic_bytes: deposit_cfg.magic_bytes,
    };

    let dsm = DepositSM::new(
        deposit_cfg.clone(),
        active_operator_table.clone(),
        deposit_data,
        valid.depositor_pubkey,
        valid.drt_output_amount,
        height,
    );

    let deposit_outpoint = dsm.context().deposit_outpoint();
    info!(%deposit_outpoint, %deposit_idx, "registering new DepositSM for detected DRT");
    applicator.insert_deposit(deposit_idx, dsm)?;

    // Register one GraphSM per active operator, collecting initial duties.
    let mut duties = Vec::new();
    for &op_idx in active_operator_table.operator_idxs().iter() {
        let graph_idx = GraphIdx {
            deposit: deposit_idx,
            operator: op_idx,
        };

        let stake_outpoint = *stake_inputs
            .get(&op_idx)
            .expect("snapshot must contain stake input for active operator");
        let unstaking_image = *unstaking_images
            .get(&op_idx)
            .expect("snapshot must contain unstaking image for active operator");

        let gsm_ctx = GraphSMCtx {
            graph_idx,
            deposit_outpoint,
            stake_outpoint,
            unstaking_image,
            operator_table: active_operator_table.clone(),
        };

        let (gsm, duty) = GraphSM::new(gsm_ctx, height);

        info!(%graph_idx, "registering new GraphSM for detected DRT");
        applicator.insert_graph(gsm.context().graph_idx(), gsm)?;
        if let Some(duty) = duty {
            duties.push(duty.into());
        }
    }

    Ok(duties)
}

/// Runs [`TxClassifier::classify_tx()`] on every active SM for a single transaction.
///
/// Returns ([`SMId`], [`SMEvent`]) pairs for each SM that recognized the transaction.
fn classify_tx_for_all_sms(
    deposit_cfg: &Arc<DepositSMCfg>,
    graph_cfg: &Arc<GraphSMCfg>,
    stake_cfg: &Arc<StakeSMCfg>,
    registry: &SMRegistry,
    tx: &Transaction,
    height: BitcoinBlockHeight,
) -> Vec<(SMId, SMEvent)> {
    registry
        .deposits()
        .filter_map(|(&deposit_idx, sm)| {
            sm.classify_tx(deposit_cfg, tx, height)
                .map(|ev| (SMId::Deposit(deposit_idx), ev.into()))
        })
        .chain(registry.graphs().filter_map(|(&graph_idx, sm)| {
            sm.classify_tx(graph_cfg, tx, height)
                .map(|ev| (graph_idx.into(), ev.into()))
        }))
        .chain(registry.stakes().filter_map(|(&operator_idx, sm)| {
            sm.classify_tx(stake_cfg, tx, height).map(|ev| {
                info!(
                    %operator_idx,
                    txid = %tx.compute_txid(),
                    event = %ev,
                    "stake SM recognized transaction"
                );
                (SMId::Stake(operator_idx), ev.into())
            })
        }))
        .collect()
}

/// Appends a `NewBlock` cursor event for provided SMs.
///
/// This lets each SM track the latest block height for timelock-related state transitions.
fn new_block_events(
    deposit_ids: &[DepositIdx],
    graph_ids: &[GraphIdx],
    stake_ids: &[OperatorIdx],
    height: BitcoinBlockHeight,
) -> Vec<(SMId, SMEvent)> {
    let deposit_event = DepositEvent::NewBlock(DepositNewBlockEvent {
        block_height: height,
    });
    let graph_event = GraphEvent::NewBlock(GraphNewBlockEvent {
        block_height: height,
    });
    let stake_event = StakeEvent::NewBlock(StakeNewBlockEvent {
        block_height: height,
    });

    deposit_ids
        .iter()
        .map(|&idx| (SMId::Deposit(idx), deposit_event.clone().into()))
        .chain(
            graph_ids
                .iter()
                .map(|&idx| (idx.into(), graph_event.clone().into())),
        )
        .chain(
            stake_ids
                .iter()
                .map(|&idx| (SMId::Stake(idx), stake_event.clone().into())),
        )
        .collect()
}

#[cfg(test)]
mod tests {
    use bitcoin::{absolute, transaction};
    use strata_bridge_sm::graph::duties::GraphDuty;
    use strata_bridge_test_utils::bitcoin::generate_txid;

    use super::*;
    use crate::{
        sm_registry::SMRegistry,
        testing::{
            DrtBuilder, N_TEST_OPERATORS, TEST_POV_IDX, insert_confirmed_stake,
            test_deposit_sm_cfg, test_operator_table, test_populated_registry,
        },
    };

    const TEST_HEIGHT: BitcoinBlockHeight = 200;

    // ===== new_block_events tests =====

    #[test]
    fn new_block_events_empty_ids() {
        let events = new_block_events(&[], &[], &[], TEST_HEIGHT);
        assert!(events.is_empty());
    }

    #[test]
    fn new_block_events_deposits_only() {
        let deposit_ids = vec![0u32, 1, 2];
        let events = new_block_events(&deposit_ids, &[], &[], TEST_HEIGHT);

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
        let events = new_block_events(&[], &graph_ids, &[], TEST_HEIGHT);

        assert_eq!(events.len(), 2);
        for (id, _event) in &events {
            assert!(matches!(id, SMId::Graph(_)));
        }
    }

    #[test]
    fn new_block_events_stakes_only() {
        let stake_ids = vec![0u32, 1, 2];
        let events = new_block_events(&[], &[], &stake_ids, TEST_HEIGHT);

        assert_eq!(events.len(), 3);
        for (id, _event) in &events {
            assert!(matches!(id, SMId::Stake(_)));
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
        let stake_ids = vec![0u32, 1];
        let events = new_block_events(&deposit_ids, &graph_ids, &stake_ids, TEST_HEIGHT);

        assert_eq!(events.len(), 7);
    }

    #[test]
    fn new_block_events_correct_height() {
        let deposit_ids = vec![0u32];
        let graph_ids = vec![GraphIdx {
            deposit: 0,
            operator: 0,
        }];
        let stake_ids = vec![0u32];
        let events = new_block_events(&deposit_ids, &graph_ids, &stake_ids, TEST_HEIGHT);

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
                SMEvent::Stake(boxed) => match *boxed {
                    StakeEvent::NewBlock(ref nb) => assert_eq!(nb.block_height, TEST_HEIGHT),
                    other => panic!("expected NewBlock, got {other}"),
                },
            }
        }
    }

    // ===== try_register_deposit tests =====

    /// Pre-populates `registry` with one Confirmed stake per operator so that the
    /// stake-readiness gate in [`try_register_deposit`] passes.
    fn confirm_all_stakes(registry: &mut SMRegistry, operator_table: &OperatorTable) {
        for op_idx in operator_table.operator_idxs() {
            insert_confirmed_stake(registry, op_idx, operator_table.clone(), generate_txid());
        }
    }

    #[test]
    fn try_register_deposit_silent_when_stakes_not_ready() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let mut registry = test_populated_registry(0); // no stakes

        let tx = DrtBuilder::aligned(&operator_table, &cfg).build();

        let mut applicator = Applicator::new(&mut registry);
        let duties =
            try_register_deposit(&cfg, &operator_table, &mut applicator, &tx, TEST_HEIGHT).unwrap();
        let (_, tracker) = applicator.finish();

        assert!(
            duties.is_empty(),
            "stake-readiness gate must not emit duties",
        );
        assert_eq!(
            registry.num_deposits(),
            0,
            "stake-readiness gate must not register a DSM",
        );
        assert!(
            tracker.into_batches().is_empty(),
            "stake-readiness gate must not record any SMs",
        );
    }

    #[test]
    fn try_register_deposit_silent_on_validate_rejection() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let mut registry = test_populated_registry(0);
        confirm_all_stakes(&mut registry, &operator_table);

        // A random transaction fails the envelope pre-filter inside try_register_deposit.
        let random_tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let mut applicator = Applicator::new(&mut registry);
        let duties = try_register_deposit(
            &cfg,
            &operator_table,
            &mut applicator,
            &random_tx,
            TEST_HEIGHT,
        )
        .unwrap();
        let _ = applicator.finish();

        assert!(
            duties.is_empty(),
            "validate-rejected DRT must not emit duties",
        );
        assert_eq!(
            registry.num_deposits(),
            0,
            "validate-rejected DRT must not register a DSM",
        );
    }

    #[test]
    fn try_register_deposit_registers_dsm_for_aligned_drt() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let mut registry = test_populated_registry(0);
        confirm_all_stakes(&mut registry, &operator_table);

        let tx = DrtBuilder::aligned(&operator_table, &cfg).build();

        let mut applicator = Applicator::new(&mut registry);
        let duties =
            try_register_deposit(&cfg, &operator_table, &mut applicator, &tx, TEST_HEIGHT).unwrap();
        let _ = applicator.finish();

        assert_eq!(
            registry.num_deposits(),
            1,
            "aligned DRT must register exactly one DSM"
        );
        assert_eq!(
            registry.get_graph_ids().len(),
            N_TEST_OPERATORS,
            "one GraphSM per active operator is expected"
        );
        assert_eq!(
            duties.len(),
            1,
            "exactly one GenerateGraphData duty is emitted, for the POV operator only"
        );
        let UnifiedDuty::Graph(GraphDuty::GenerateGraphData {
            operator_table: duty_operator_table,
            ..
        }) = &duties[0]
        else {
            panic!("expected GenerateGraphData duty, got {:?}", duties[0]);
        };
        assert_eq!(
            duty_operator_table, &operator_table,
            "initial graph duty must carry the active operator-table snapshot"
        );
    }
}
