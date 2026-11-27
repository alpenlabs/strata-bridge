//! Classification of on-chain events (buried blocks) into state-machine-specific events.
//!
//!
//! This module handles:
//! - Detecting new deposit requests and spawning SMs
//! - Running [`TxClassifier::classify_tx()`] per SM per transaction
//! - Appending `NewBlock` cursor events for all active SMs
//!
//! [`TxClassifier::classify_tx()`]: strata_bridge_sm::tx_classifier::TxClassifier::classify_tx

use std::sync::Arc;

use bitcoin::{OutPoint, Transaction};
use btc_tracker::event::BlockEvent;
use strata_asm_proto_bridge_txs::deposit_request::DRT_OUTPUT_INDEX;
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
use tracing::{Level, debug, info, warn};

use super::drt;
use crate::{
    applicator::Applicator,
    errors::{PipelineError, ProcessError},
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
        // Classify this tx against every active SM via TxClassifier
        // PERF: (Rajil1213) this needs benchmarking to make sure that classifying every tx
        // against every SM is not too expensive. If it is, we can optimize by maintaining a
        // cache of all relevant txids/outpoints per SM and only running TxClassifier if the tx
        // contains a relevant txid/outpoint and do it only on the relevant SM. It is too
        // expensive if for a saturated bitcoin block (~3000 txs) and ~1000*15 SMs (45M
        // lookups), we are unable to classify the block within ~5 minutes (half the average
        // block time) on a reasonably powerful machine.
        let seed_events = classify_tx_for_all_sms(
            &deposit_cfg,
            &graph_cfg,
            &stake_cfg,
            applicator.registry(),
            tx,
            height,
        );

        // Apply seed events as one fixed-point batch per transaction
        applicator.apply_batch(seed_events)?;

        // If this tx is a DRT, register new DepositSM + per-operator GraphSMs using the currently
        // active operator snapshot. Admission is checked after earlier transactions and this
        // one's own spends have settled: a stake transition that removes an operator from the
        // active set is reflected for a DRT appearing later in the same block, and a take-back
        // rolled into a new request frees its deposit-cap slot first.
        let initial_duties =
            try_register_deposit(&deposit_cfg, initial_operator_table, applicator, tx, height)?;

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
/// node's operator is not in the active set), if the transaction fails DRT validation, or if the
/// deposit cap is reached (the deposit is then registered as skipped and never acted on).
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

    // Safe harbour halts new deposits. Best-effort: a DRT admitted before the latch is caught
    // by the sweep once it reaches `Deposited`.
    if applicator.registry().safe_harbour_active() {
        debug!(txid=%tx.compute_txid(), "safe harbour active; refusing to admit new deposit");
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

    // Apply the deposit cap. The request is still registered, as skipped, so the deposit index
    // stays in step with the other operators; this node just never acts on it.
    if applicator.registry().deposit_cap_reached() {
        warn!(
            %drt_txid,
            %deposit_idx,
            "deposit cap reached; registering deposit request as skipped"
        );
        applicator.insert_deposit(deposit_idx, dsm.into_skipped())?;
        return Ok(Vec::new());
    }

    let span = tracing::span!(Level::INFO, "registering new deposit", drt_txid=%drt_txid);
    let _entered = span.entered();
    info!(
        active_operator_count = active_operator_table.operator_idxs().len(),
        "passed validation; registering DSM / GSMs from active operator snapshot"
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
    use std::collections::BTreeSet;

    use bitcoin::{absolute, transaction};
    use btc_tracker::event::BlockStatus;
    use strata_bridge_sm::{
        deposit::{events::UserTakeBackEvent, state::DepositState},
        graph::duties::GraphDuty,
    };
    use strata_bridge_test_utils::bitcoin::{generate_block_with_height, generate_txid};

    use super::*;
    use crate::{
        sm_registry::SMRegistry,
        testing::{
            DrtBuilder, N_TEST_OPERATORS, TEST_POV_IDX, insert_confirmed_stake,
            insert_deposit_with_graphs, takeback_tx, test_deposit_sm_cfg, test_operator_table,
            test_populated_registry, test_registry_with_cap, test_safe_harbour_address,
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
    fn try_register_deposit_silent_when_safe_harbour_active() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let mut registry = test_populated_registry(0);
        confirm_all_stakes(&mut registry, &operator_table);
        registry.activate_safe_harbour(test_safe_harbour_address());

        // An otherwise-admissible DRT: without the latch it would register a DSM.
        let tx = DrtBuilder::aligned(&operator_table, &cfg).build();

        let mut applicator = Applicator::new(&mut registry);
        let duties =
            try_register_deposit(&cfg, &operator_table, &mut applicator, &tx, TEST_HEIGHT).unwrap();
        let (_, tracker) = applicator.finish();

        assert!(duties.is_empty(), "halt gate must not emit duties");
        assert_eq!(
            registry.num_deposits(),
            0,
            "halt gate must not register a DSM",
        );
        assert!(
            registry.get_graph_ids().is_empty(),
            "halt gate must not register GraphSMs",
        );
        assert!(
            tracker.into_batches().is_empty(),
            "halt gate must not record any SMs",
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

    // ===== deposit cap tests =====

    /// Runs `drt` through [`try_register_deposit`] and returns the duties it emitted.
    fn register_drt(
        registry: &mut SMRegistry,
        operator_table: &OperatorTable,
        cfg: &Arc<DepositSMCfg>,
        drt: &Transaction,
    ) -> Vec<UnifiedDuty> {
        let mut applicator = Applicator::new(registry);
        let duties =
            try_register_deposit(cfg, operator_table, &mut applicator, drt, TEST_HEIGHT).unwrap();
        let _ = applicator.finish();
        duties
    }

    /// Spends the deposit-request output of `drt` on the take-back path.
    fn takeback_of(drt: &Transaction) -> Transaction {
        takeback_tx(OutPoint::new(drt.compute_txid(), DRT_OUTPUT_INDEX as u32))
    }

    /// Runs `txs` as one buried block through [`process_block`].
    fn process_buried_block(
        registry: &mut SMRegistry,
        operator_table: &OperatorTable,
        txs: Vec<Transaction>,
    ) {
        let mut block = generate_block_with_height(TEST_HEIGHT);
        block.txdata.extend(txs);
        let block_event = BlockEvent {
            block,
            status: BlockStatus::Buried,
        };
        let mut applicator = Applicator::new(registry);
        process_block(&mut applicator, operator_table, &block_event).unwrap();
        let _ = applicator.finish();
    }

    fn graph_ids_of(registry: &SMRegistry, deposit_idx: DepositIdx) -> usize {
        registry
            .get_graph_ids()
            .into_iter()
            .filter(|graph_idx| graph_idx.deposit == deposit_idx)
            .count()
    }

    #[test]
    fn try_register_deposit_skips_drt_at_cap() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let mut registry = test_registry_with_cap(Some(1));
        confirm_all_stakes(&mut registry, &operator_table);
        let first = DrtBuilder::aligned(&operator_table, &cfg).build();
        let second = DrtBuilder::aligned(&operator_table, &cfg).build();
        assert_eq!(
            register_drt(&mut registry, &operator_table, &cfg, &first).len(),
            1,
            "the first DRT takes the only slot"
        );

        let mut applicator = Applicator::new(&mut registry);
        let duties =
            try_register_deposit(&cfg, &operator_table, &mut applicator, &second, TEST_HEIGHT)
                .unwrap();
        let (_, tracker) = applicator.finish();
        let persisted: BTreeSet<SMId> = tracker.into_batches().into_iter().flatten().collect();

        assert!(duties.is_empty(), "a skipped deposit emits no duties");
        assert_eq!(
            registry.num_deposits(),
            2,
            "the deposit is registered all the same"
        );
        assert_eq!(
            registry.get_deposit(&1).unwrap().state(),
            &DepositState::Skipped,
            "the DRT over the cap is recorded as skipped"
        );
        assert_eq!(
            graph_ids_of(&registry, 1),
            0,
            "no graphs for a skipped deposit"
        );
        assert_eq!(
            registry.next_deposit_idx(),
            Ok(2),
            "the skipped deposit consumed its index"
        );
        assert!(
            persisted.contains(&SMId::Deposit(1)),
            "the skipped deposit is persisted"
        );
        assert_eq!(
            registry.num_active_deposits(),
            1,
            "skipped deposits do not count"
        );
    }

    #[test]
    fn try_register_deposit_admits_under_cap() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let mut registry = test_registry_with_cap(Some(2));
        confirm_all_stakes(&mut registry, &operator_table);

        for _ in 0..2 {
            let drt = DrtBuilder::aligned(&operator_table, &cfg).build();
            assert_eq!(
                register_drt(&mut registry, &operator_table, &cfg, &drt).len(),
                1,
                "each DRT under the cap emits the POV operator's GenerateGraphData duty"
            );
        }

        assert_eq!(
            registry.num_active_deposits(),
            2,
            "both DRTs under the cap are admitted"
        );
    }

    #[test]
    fn try_register_deposit_unlimited_without_cap() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let mut registry = test_populated_registry(5);
        confirm_all_stakes(&mut registry, &operator_table);
        let drt = DrtBuilder::aligned(&operator_table, &cfg).build();

        assert_eq!(
            register_drt(&mut registry, &operator_table, &cfg, &drt).len(),
            1,
            "without a cap the DRT is admitted"
        );
        assert_eq!(
            registry.num_active_deposits(),
            6,
            "the new deposit joins the five existing ones"
        );
    }

    #[test]
    fn try_register_deposit_cap_zero_skips_every_drt() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let mut registry = test_registry_with_cap(Some(0));
        confirm_all_stakes(&mut registry, &operator_table);
        let drt = DrtBuilder::aligned(&operator_table, &cfg).build();

        assert!(
            register_drt(&mut registry, &operator_table, &cfg, &drt).is_empty(),
            "a cap of zero emits no GenerateGraphData duty"
        );
        assert_eq!(
            registry.get_deposit(&0).unwrap().state(),
            &DepositState::Skipped,
            "a cap of zero records the DRT as skipped"
        );
        assert_eq!(
            graph_ids_of(&registry, 0),
            0,
            "a cap of zero registers no graphs"
        );
    }

    #[test]
    fn try_register_deposit_counts_only_live_deposits() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let mut registry = test_registry_with_cap(Some(1));
        confirm_all_stakes(&mut registry, &operator_table);
        let drt_a = DrtBuilder::aligned(&operator_table, &cfg).build();
        let drt_b = DrtBuilder::aligned(&operator_table, &cfg).build();
        let drt_c = DrtBuilder::aligned(&operator_table, &cfg).build();
        register_drt(&mut registry, &operator_table, &cfg, &drt_a);
        assert!(
            register_drt(&mut registry, &operator_table, &cfg, &drt_b).is_empty(),
            "B arrives at the cap and is skipped"
        );

        // The user takes A back: its slot is free again, but B stays skipped for good.
        let mut applicator = Applicator::new(&mut registry);
        applicator
            .apply_batch(vec![(
                SMId::Deposit(0),
                SMEvent::Deposit(Box::new(DepositEvent::UserTakeBack(UserTakeBackEvent {
                    tx: takeback_of(&drt_a),
                }))),
            )])
            .unwrap();
        let _ = applicator.finish();
        assert_eq!(
            registry.get_deposit(&0).unwrap().state(),
            &DepositState::Aborted,
            "taking A back aborts its deposit"
        );

        assert_eq!(
            register_drt(&mut registry, &operator_table, &cfg, &drt_c).len(),
            1,
            "the next DRT takes the freed slot"
        );
        assert_eq!(
            registry.get_deposit(&1).unwrap().state(),
            &DepositState::Skipped,
            "a freed slot does not revive an already skipped deposit"
        );
        assert_eq!(
            registry.next_deposit_idx(),
            Ok(3),
            "every DRT consumed an index"
        );
    }

    #[test]
    fn process_block_takeback_frees_slot_for_later_drt_in_same_block() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let mut registry = test_registry_with_cap(Some(1));
        confirm_all_stakes(&mut registry, &operator_table);
        let drt_a = DrtBuilder::aligned(&operator_table, &cfg).build();
        let drt_b = DrtBuilder::aligned(&operator_table, &cfg).build();

        process_buried_block(
            &mut registry,
            &operator_table,
            vec![drt_a.clone(), takeback_of(&drt_a), drt_b],
        );

        assert_eq!(
            registry.get_deposit(&0).unwrap().state(),
            &DepositState::Aborted,
            "the take-back earlier in the block aborts A"
        );
        assert!(
            matches!(
                registry.get_deposit(&1).unwrap().state(),
                DepositState::Created { .. }
            ),
            "the slot freed earlier in the block admits the later DRT"
        );
        assert_eq!(
            graph_ids_of(&registry, 1),
            N_TEST_OPERATORS,
            "the admitted DRT gets one graph per operator"
        );
    }

    #[test]
    fn process_block_admits_drt_rolled_from_a_takeback_in_the_same_tx() {
        // A wallet may spend a recovered DRT output straight into a new request; the spend
        // settles before the new request is counted against the cap.
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let mut registry = test_registry_with_cap(Some(1));
        confirm_all_stakes(&mut registry, &operator_table);
        let drt_a = DrtBuilder::aligned(&operator_table, &cfg).build();
        let mut drt_b = DrtBuilder::aligned(&operator_table, &cfg).build();
        drt_b.input.push(takeback_of(&drt_a).input[0].clone());

        process_buried_block(&mut registry, &operator_table, vec![drt_a, drt_b]);

        assert_eq!(
            registry.get_deposit(&0).unwrap().state(),
            &DepositState::Aborted,
            "B's take-back input aborts A"
        );
        assert!(
            matches!(
                registry.get_deposit(&1).unwrap().state(),
                DepositState::Created { .. }
            ),
            "B is admitted into the slot its own input freed"
        );
        assert_eq!(
            graph_ids_of(&registry, 1),
            N_TEST_OPERATORS,
            "the admitted DRT gets one graph per operator"
        );
    }

    #[test]
    fn process_block_skips_later_drt_when_one_slot_is_left() {
        // Every operator replays the same block, so the slot goes to the earlier transaction.
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let mut registry = test_registry_with_cap(Some(1));
        confirm_all_stakes(&mut registry, &operator_table);
        let drt_a = DrtBuilder::aligned(&operator_table, &cfg).build();
        let drt_b = DrtBuilder::aligned(&operator_table, &cfg).build();

        process_buried_block(&mut registry, &operator_table, vec![drt_a.clone(), drt_b]);

        assert!(
            matches!(
                registry.get_deposit(&0).unwrap().state(),
                DepositState::Created { .. }
            ),
            "the earlier DRT takes the last slot"
        );
        assert_eq!(
            registry
                .get_deposit(&0)
                .unwrap()
                .context()
                .deposit_request_outpoint()
                .txid,
            drt_a.compute_txid(),
            "deposit 0 is the earlier DRT"
        );
        assert_eq!(
            registry.get_deposit(&1).unwrap().state(),
            &DepositState::Skipped,
            "the later DRT is skipped"
        );
        assert_eq!(
            graph_ids_of(&registry, 1),
            0,
            "the skipped DRT gets no graphs"
        );
    }

    #[test]
    fn takeback_of_skipped_drt_is_harmless() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let mut registry = test_registry_with_cap(Some(0));
        confirm_all_stakes(&mut registry, &operator_table);
        let drt = DrtBuilder::aligned(&operator_table, &cfg).build();
        register_drt(&mut registry, &operator_table, &cfg, &drt);

        process_buried_block(&mut registry, &operator_table, vec![takeback_of(&drt)]);

        assert_eq!(
            registry.get_deposit(&0).unwrap().state(),
            &DepositState::Skipped,
            "a skipped deposit ignores its take-back"
        );
    }

    #[test]
    fn lowered_cap_skips_new_drts_but_evicts_nothing() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let mut registry = test_registry_with_cap(Some(1));
        for deposit_idx in 0..3 {
            insert_deposit_with_graphs(&mut registry, deposit_idx);
        }
        confirm_all_stakes(&mut registry, &operator_table);
        let drt = DrtBuilder::aligned(&operator_table, &cfg).build();

        assert!(
            register_drt(&mut registry, &operator_table, &cfg, &drt).is_empty(),
            "a DRT over a lowered cap emits no duties"
        );
        assert_eq!(
            registry.get_deposit(&3).unwrap().state(),
            &DepositState::Skipped,
            "a DRT over a lowered cap is skipped"
        );
        assert_eq!(registry.num_active_deposits(), 3, "nothing is evicted");
    }
}
