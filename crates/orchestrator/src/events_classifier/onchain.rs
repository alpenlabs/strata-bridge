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
    covenant::{CovenantId, StakeKey},
    operator_table::OperatorTable,
    types::{BitcoinBlockHeight, DepositIdx, GraphIdx},
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
use strata_bridge_tx_graph::transactions::{prelude::DepositData, stake::StakeTx};
use tracing::{Level, debug, info, warn};

use super::drt;
use crate::{
    applicator::Applicator,
    errors::{PipelineError, ProcessError},
    sm_registry::{ActiveOperatorSnapshot, SMRegistry, SnapshotError},
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
    covenant: CovenantId,
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
        // Readiness is checked after earlier transactions have settled. An unavailable
        // covenant member closes admission for later DRTs in the same block.
        let initial_duties = try_register_deposit(
            &deposit_cfg,
            initial_operator_table,
            covenant,
            applicator,
            tx,
            height,
        )?;

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
/// Returns `Ok(Vec::new())` unless every requested covenant member has an available stake,
/// or if the transaction is already registered or fails DRT validation.
fn try_register_deposit(
    deposit_cfg: &Arc<DepositSMCfg>,
    full_operator_table: &OperatorTable,
    covenant: CovenantId,
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

    let drt_txid = tx.compute_txid();
    let deposit_request_outpoint = OutPoint::new(drt_txid, DRT_OUTPUT_INDEX as u32);
    // Independent persistence groups can leave the recovery cursor behind an already committed
    // deposit. Terminal deposits must also retain their registration when this block is replayed.
    if applicator
        .registry()
        .deposits()
        .any(|(_, sm)| sm.context().deposit_request_outpoint() == deposit_request_outpoint)
    {
        return Ok(Vec::new());
    }

    // Safe harbour halts new deposits. Best-effort: a DRT admitted before the latch is caught
    // by the sweep once it reaches `Deposited`.
    if applicator.registry().safe_harbour_active() {
        debug!(txid=%tx.compute_txid(), "safe harbour active; refusing to admit new deposit");
        return Ok(Vec::new());
    }

    let snapshot = match applicator
        .registry()
        .active_operator_snapshot(covenant, full_operator_table)
    {
        Ok(snap) => snap,
        Err(err @ (SnapshotError::MissingStakeSM(_) | SnapshotError::StakeUnavailable(_))) => {
            debug!(%err, "covenant stakes are not ready; refusing to admit new deposit");
            return Ok(Vec::new());
        }
        Err(err) => {
            warn!(%err, "skipping DRT check: could not derive active operator snapshot");
            return Ok(Vec::new());
        }
    };

    let ActiveOperatorSnapshot {
        covenant,
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

    let span = tracing::span!(Level::INFO, "registering new deposit", drt_txid=%drt_txid);
    let _entered = span.entered();
    info!(
        active_operator_count = active_operator_table.operator_idxs().len(),
        "passed validation; registering DSM / GSMs from active operator snapshot"
    );

    let deposit_idx = applicator.registry().next_deposit_idx()?;
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
            covenant,
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
        .chain(registry.stakes().filter_map(|(&stake_key, sm)| {
            sm.classify_tx(stake_cfg, tx, height).and_then(|ev| {
                let stake_txid = sm.state().stake_txid()?;
                let source = OutPoint::new(stake_txid, StakeTx::STAKE_VOUT);
                if registry.resolve_stake_outpoint(&source) != Some(stake_key) {
                    warn!(
                        %stake_key,
                        %source,
                        txid = %tx.compute_txid(),
                        event = %ev,
                        "dropping recognized stake transaction: source does not resolve to a unique stake instance"
                    );
                    return None;
                }
                info!(
                    %stake_key,
                    txid = %tx.compute_txid(),
                    event = %ev,
                    "stake SM recognized transaction"
                );
                Some((SMId::Stake(stake_key), ev.into()))
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
    stake_ids: &[StakeKey],
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
    use std::{
        collections::BTreeSet,
        iter::once,
        time::{SystemTime, UNIX_EPOCH},
    };

    use bitcoin::{absolute, transaction};
    use btc_tracker::event::BlockStatus;
    use strata_bridge_db::fdb::{cfg::Config, client::FdbClient};
    use strata_bridge_sm::{
        deposit::state::DepositState, graph::duties::GraphDuty, stake::state::StakeState,
    };
    use strata_bridge_test_utils::{
        bitcoin::{
            generate_block_with_height, generate_signature, generate_spending_tx, generate_txid,
        },
        musig2::generate_agg_nonce,
    };
    use strata_bridge_tx_graph::musig_functor::StakeFunctor;

    use super::*;
    use crate::{
        persister::Persister,
        sm_registry::SMRegistry,
        testing::{
            DrtBuilder, INITIAL_BLOCK_HEIGHT, N_TEST_OPERATORS, TEST_POV_IDX,
            insert_confirmed_stake, make_confirmed_stake_sm, test_deposit_sm_cfg,
            test_operator_table, test_populated_registry, test_safe_harbour_address,
            test_stake_key,
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
        let stake_ids = (0..3).map(test_stake_key).collect::<Vec<_>>();
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
        let stake_ids = (0..2).map(test_stake_key).collect::<Vec<_>>();
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
        let stake_ids = vec![test_stake_key(0)];
        let events = new_block_events(&deposit_ids, &graph_ids, &stake_ids, TEST_HEIGHT);

        for (_id, event) in events {
            match event {
                SMEvent::OperatorSet(_) => panic!("membership must be finalized by the pre-pass"),
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
        let duties = try_register_deposit(
            &cfg,
            &operator_table,
            CovenantId::from_operator_table(&operator_table, INITIAL_BLOCK_HEIGHT).unwrap(),
            &mut applicator,
            &tx,
            TEST_HEIGHT,
        )
        .unwrap();
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
    fn try_register_deposit_rejects_unavailable_covenant_member() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let confirmed =
            make_confirmed_stake_sm(TEST_POV_IDX, operator_table.clone(), generate_txid());
        let StakeState::Confirmed {
            last_block_height,
            stake_data,
            summary,
            signatures,
        } = confirmed.state().clone()
        else {
            panic!("fixture must supply a confirmed stake");
        };
        let preimage = [0x42; 32];
        let unstaking_txid = summary.unstaking;
        let unavailable_states = [
            StakeState::Created { last_block_height },
            StakeState::PreimageRevealed {
                last_block_height,
                stake_data,
                summary,
                preimage,
                unstaking_intent_block_height: TEST_HEIGHT,
                signatures,
            },
            StakeState::Unstaked {
                preimage,
                unstaking_txid,
            },
            StakeState::Slashed {
                summary,
                slash_txid: generate_txid(),
                preimage: None,
            },
        ];
        let covenant = confirmed.context().stake_key().covenant;
        let tx = DrtBuilder::aligned(&operator_table, &cfg).build();
        for state in unavailable_states {
            let mut registry = test_populated_registry(0);
            for operator in operator_table.operator_idxs() {
                let mut stake =
                    make_confirmed_stake_sm(operator, operator_table.clone(), generate_txid());
                if operator == TEST_POV_IDX {
                    stake.state = state.clone();
                }
                registry.insert_stake(stake).unwrap();
            }
            let mut applicator = Applicator::new(&mut registry);
            let duties = try_register_deposit(
                &cfg,
                &operator_table,
                covenant,
                &mut applicator,
                &tx,
                TEST_HEIGHT,
            )
            .unwrap();
            let (applied_duties, tracker) = applicator.finish();
            assert!(
                duties.is_empty(),
                "A member in {state} must prevent initial duties"
            );
            assert!(
                applied_duties.is_empty(),
                "A member in {state} must prevent applied duties"
            );
            assert_eq!(
                registry.num_deposits(),
                0,
                "A member in {state} must prevent deposit registration"
            );
            assert!(
                registry.get_graph_ids().is_empty(),
                "A member in {state} must prevent graph registration"
            );
            assert!(
                tracker.into_batches().is_empty(),
                "A member in {state} must leave persistence batches empty"
            );
        }
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
            CovenantId::from_operator_table(&operator_table, INITIAL_BLOCK_HEIGHT).unwrap(),
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
        let duties = try_register_deposit(
            &cfg,
            &operator_table,
            CovenantId::from_operator_table(&operator_table, INITIAL_BLOCK_HEIGHT).unwrap(),
            &mut applicator,
            &tx,
            TEST_HEIGHT,
        )
        .unwrap();
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
    fn replayed_drt_does_not_register_live_or_terminal_deposit_again() {
        let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let covenant = CovenantId::from_operator_table(&table, INITIAL_BLOCK_HEIGHT).unwrap();
        let tx = DrtBuilder::aligned(&table, &cfg).build();
        let mut registry = test_populated_registry(0);
        confirm_all_stakes(&mut registry, &table);
        let mut applicator = Applicator::new(&mut registry);
        assert_eq!(
            try_register_deposit(&cfg, &table, covenant, &mut applicator, &tx, TEST_HEIGHT)
                .unwrap()
                .len(),
            1
        );
        applicator.finish();
        let original = registry.get_deposit(&0).unwrap().clone();
        for state in [original.state.clone(), DepositState::Aborted] {
            let mut restored = test_populated_registry(0);
            confirm_all_stakes(&mut restored, &table);
            let mut deposit = original.clone();
            deposit.state = state;
            restored.insert_deposit(0, deposit.clone()).unwrap();
            for (id, graph) in registry.graphs() {
                restored.insert_graph(*id, graph.clone()).unwrap();
            }
            let ids = restored.get_all_ids();
            let mut applicator = Applicator::new(&mut restored);
            let duties =
                try_register_deposit(&cfg, &table, covenant, &mut applicator, &tx, TEST_HEIGHT)
                    .unwrap();
            let (_, tracker) = applicator.finish();
            assert!(duties.is_empty(), "replay must not emit constructor duties");
            assert!(tracker.into_batches().is_empty());
            assert_eq!(restored.get_all_ids(), ids);
            assert_eq!(restored.get_deposit(&0), Some(&deposit));
        }
    }

    #[tokio::test]
    async fn deposit_registration_recovers_from_any_committed_batch_subset() {
        let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let covenant = CovenantId::from_operator_table(&table, INITIAL_BLOCK_HEIGHT).unwrap();
        let mut registry = test_populated_registry(0);
        confirm_all_stakes(&mut registry, &table);
        let initial = registry.clone();
        let mut block = generate_block_with_height(INITIAL_BLOCK_HEIGHT + 1);
        for _ in 0..2 {
            block
                .txdata
                .push(DrtBuilder::aligned(&table, &registry.cfg().deposit).build());
        }
        let event = BlockEvent {
            block,
            status: BlockStatus::Buried,
        };
        let mut applicator = Applicator::new(&mut registry);
        process_block(&mut applicator, &table, covenant, &event).unwrap();
        let (_, tracker) = applicator.finish();
        let batches = tracker.into_batches();
        for deposit in 0..2 {
            let group = batches
                .iter()
                .find(|group| group.contains(&SMId::Deposit(deposit)))
                .unwrap();
            let expected: BTreeSet<_> = once(SMId::Deposit(deposit))
                .chain(
                    table
                        .operator_idxs()
                        .into_iter()
                        .map(|operator| SMId::Graph(GraphIdx { deposit, operator })),
                )
                .collect();
            assert_eq!(
                *group, expected,
                "each deposit and its graphs must commit together"
            );
        }
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let (client, guard) = FdbClient::setup(Config {
            root_directory: format!("test-drt-boundary-{suffix}"),
            ..Default::default()
        })
        .await
        .unwrap();
        let db = Arc::new(client);
        let persister = Persister::new(db.clone());
        let expected_requests: BTreeSet<_> = registry
            .deposits()
            .map(|(_, sm)| sm.context().deposit_request_outpoint())
            .collect();
        // Every subset is a possible interrupted write sequence when groups are unordered.
        for committed_mask in 0..(1 << batches.len()) {
            for id in initial.get_all_ids() {
                persister
                    .persist_batch(BTreeSet::from([id]), &initial)
                    .await
                    .unwrap();
            }
            for (position, batch) in batches.iter().enumerate() {
                if committed_mask & (1 << position) != 0 {
                    persister
                        .persist_batch(batch.clone(), &registry)
                        .await
                        .unwrap();
                }
            }
            let mut restored = persister
                .recover_registry(registry.cfg().clone())
                .await
                .unwrap();
            let committed_deposits: Vec<_> = restored
                .deposits()
                .map(|(id, sm)| (*id, sm.clone()))
                .collect();
            let committed_graphs: Vec<_> = restored
                .graphs()
                .map(|(id, sm)| (*id, sm.clone()))
                .collect();
            let start_height = restored.earliest_processed_block_height().unwrap();
            assert!(start_height <= INITIAL_BLOCK_HEIGHT + 1);
            let mut emitted_duties = Vec::new();
            for height in start_height..=INITIAL_BLOCK_HEIGHT + 1 {
                let replay = if height == INITIAL_BLOCK_HEIGHT + 1 {
                    event.clone()
                } else {
                    BlockEvent {
                        block: generate_block_with_height(height),
                        status: BlockStatus::Buried,
                    }
                };
                let mut applicator = Applicator::new(&mut restored);
                process_block(&mut applicator, &table, covenant, &replay).unwrap();
                let (duties, tracker) = applicator.finish();
                emitted_duties.extend(duties);
                for batch in tracker.into_batches() {
                    persister.persist_batch(batch, &restored).await.unwrap();
                }
            }
            assert_eq!(emitted_duties.len(), 2 - committed_deposits.len());
            let recovered = persister
                .recover_registry(registry.cfg().clone())
                .await
                .unwrap();
            assert_eq!(recovered.num_deposits(), 2);
            assert_eq!(recovered.get_graph_ids().len(), 2 * N_TEST_OPERATORS);
            assert_eq!(
                recovered
                    .deposits()
                    .map(|(_, sm)| sm.context().deposit_request_outpoint())
                    .collect::<BTreeSet<_>>(),
                expected_requests
            );
            // Replay preserves committed identities even if an earlier uncommitted request
            // receives the next available local index. Canonical indexing belongs to STR-3670.
            for (id, deposit) in committed_deposits {
                assert_eq!(recovered.get_deposit(&id), Some(&deposit));
            }
            for (id, graph) in committed_graphs {
                assert_eq!(recovered.get_graph(&id), Some(&graph));
            }
            for id in recovered.get_deposit_ids() {
                for operator in table.operator_idxs() {
                    assert!(
                        recovered
                            .get_graph(&GraphIdx {
                                deposit: id,
                                operator
                            })
                            .is_some()
                    );
                }
            }
            assert_eq!(
                recovered.earliest_processed_block_height(),
                Some(INITIAL_BLOCK_HEIGHT + 1)
            );
            for deposit in recovered.get_deposit_ids() {
                db.delete_deposit_cascade(deposit).await.unwrap();
            }
        }
        drop(persister);
        drop(db);
        drop(guard);
    }

    // TODO: <https://alpenlabs.atlassian.net/browse/STR-3622>
    // This fixture deliberately records the single-pass admission discrepancy: only DRT2 is
    // admitted initially, but replay also admits DRT1 using recovered stake readiness. With
    // the OSM/SSM first pass, both must be admitted on the initial run, regardless of their
    // positions relative to stake confirmation; replay must create neither deposit again.
    // TODO: <https://alpenlabs.atlassian.net/browse/STR-4398>
    // Extend this to assert admission equivalence across the two-pass persistence boundaries.
    #[tokio::test]
    async fn boundary_replay_admits_pre_confirmation_drt_without_duplicating_existing_deposit() {
        let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let covenant = CovenantId::from_operator_table(&table, INITIAL_BLOCK_HEIGHT).unwrap();
        let mut registry = test_populated_registry(0);
        let stake_tx = generate_spending_tx(OutPoint::new(generate_txid(), 0), &[]);
        for operator in table.operator_idxs() {
            let mut sm = make_confirmed_stake_sm(operator, table.clone(), generate_txid());
            if operator == TEST_POV_IDX {
                let StakeState::Confirmed {
                    last_block_height,
                    stake_data,
                    mut summary,
                    ..
                } = sm.state
                else {
                    unreachable!();
                };
                summary.stake = stake_tx.compute_txid();
                let fields = StakeFunctor {
                    unstaking_intent: [()],
                    unstaking: [(), ()],
                };
                sm.state = StakeState::UnstakingSigned {
                    last_block_height,
                    stake_data,
                    summary,
                    agg_nonces: fields.map(|_| generate_agg_nonce()).boxed(),
                    signatures: fields.map(|_| generate_signature()).boxed(),
                };
            }
            registry.insert_stake(sm).unwrap();
        }
        let skipped = DrtBuilder::aligned(&table, &registry.cfg().deposit).build();
        let skipped_outpoint = OutPoint::new(skipped.compute_txid(), DRT_OUTPUT_INDEX as u32);
        let admitted = DrtBuilder::aligned(&table, &registry.cfg().deposit).build();
        let admitted_outpoint = OutPoint::new(admitted.compute_txid(), DRT_OUTPUT_INDEX as u32);
        let mut block = generate_block_with_height(INITIAL_BLOCK_HEIGHT + 1);
        block.txdata.extend([skipped, stake_tx, admitted]);
        let event = BlockEvent {
            block,
            status: BlockStatus::Buried,
        };
        let mut applicator = Applicator::new(&mut registry);
        process_block(&mut applicator, &table, covenant, &event).unwrap();
        let (duties, tracker) = applicator.finish();
        assert_eq!(duties.len(), 1);
        assert_eq!(registry.num_deposits(), 1);
        assert_eq!(
            registry
                .get_deposit(&0)
                .unwrap()
                .context()
                .deposit_request_outpoint(),
            admitted_outpoint
        );

        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let (client, guard) = FdbClient::setup(Config {
            root_directory: format!("test-drt-readiness-{suffix}"),
            ..Default::default()
        })
        .await
        .unwrap();
        let db = Arc::new(client);
        let persister = Persister::new(db.clone());
        for batch in tracker.into_batches() {
            persister.persist_batch(batch, &registry).await.unwrap();
        }
        let mut restored = persister
            .recover_registry(registry.cfg().clone())
            .await
            .unwrap();
        assert_eq!(
            restored.earliest_processed_block_height(),
            Some(INITIAL_BLOCK_HEIGHT + 1)
        );
        assert_eq!(restored.num_deposits(), 1);
        assert_eq!(restored.get_deposit(&0), registry.get_deposit(&0));
        assert!(restored.active_operator_snapshot(covenant, &table).is_ok());
        let original = restored.get_deposit(&0).unwrap().clone();
        let mut applicator = Applicator::new(&mut restored);
        process_block(&mut applicator, &table, covenant, &event).unwrap();
        let (duties, tracker) = applicator.finish();
        assert_eq!(
            duties.len(),
            1,
            "only the formerly unready request is admitted"
        );
        assert_eq!(restored.num_deposits(), 2);
        assert_eq!(restored.get_deposit(&0), Some(&original));
        assert_eq!(
            restored
                .get_deposit(&1)
                .unwrap()
                .context()
                .deposit_request_outpoint(),
            skipped_outpoint
        );
        for batch in tracker.into_batches() {
            persister.persist_batch(batch, &restored).await.unwrap();
        }
        let mut recovered = persister
            .recover_registry(registry.cfg().clone())
            .await
            .unwrap();
        let ids = recovered.get_all_ids();
        let mut applicator = Applicator::new(&mut recovered);
        process_block(&mut applicator, &table, covenant, &event).unwrap();
        let (duties, tracker) = applicator.finish();
        assert!(duties.is_empty());
        assert!(tracker.into_batches().is_empty());
        assert_eq!(recovered.get_all_ids(), ids);
        drop(persister);
        drop(db);
        drop(guard);
    }

    #[test]
    fn try_register_deposit_registers_dsm_for_aligned_drt() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let mut registry = test_populated_registry(0);
        confirm_all_stakes(&mut registry, &operator_table);

        let tx = DrtBuilder::aligned(&operator_table, &cfg).build();

        let mut applicator = Applicator::new(&mut registry);
        let duties = try_register_deposit(
            &cfg,
            &operator_table,
            CovenantId::from_operator_table(&operator_table, INITIAL_BLOCK_HEIGHT).unwrap(),
            &mut applicator,
            &tx,
            TEST_HEIGHT,
        )
        .unwrap();
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
            covenant: duty_covenant,
            operator_table: duty_operator_table,
            ..
        }) = &duties[0]
        else {
            panic!("expected GenerateGraphData duty, got {:?}", duties[0]);
        };
        assert_eq!(
            *duty_covenant,
            CovenantId::from_operator_table(&operator_table, INITIAL_BLOCK_HEIGHT).unwrap()
        );
        assert_eq!(
            duty_operator_table, &operator_table,
            "initial graph duty must carry the active operator-table snapshot"
        );
    }
}

#[cfg(test)]
mod covenant_routing_tests {
    use strata_bridge_sm::stake::context::StakeSMCtx;
    use strata_bridge_test_utils::bitcoin::{generate_spending_tx, generate_txid};
    use strata_bridge_tx_graph::transactions::stake::StakeTx;

    use super::*;
    use crate::testing::{
        N_TEST_OPERATORS, TEST_POV_IDX, make_confirmed_stake_sm, test_empty_registry,
        test_operator_table,
    };

    #[test]
    fn source_outpoint_routes_only_its_historical_stake() {
        let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let historical = make_confirmed_stake_sm(TEST_POV_IDX, table.clone(), generate_txid());
        let old_key = historical.context().stake_key();
        let mut successor = make_confirmed_stake_sm(TEST_POV_IDX, table.clone(), generate_txid());
        successor.context = StakeSMCtx::new(TEST_POV_IDX, table, 200);
        let new_key = successor.context().stake_key();
        let source = OutPoint::new(
            historical.state().stake_txid().unwrap(),
            StakeTx::STAKE_VOUT,
        );
        let mut registry = test_empty_registry();
        registry.insert_stake(historical).unwrap();
        registry.insert_stake(successor.clone()).unwrap();
        assert_eq!(registry.resolve_stake_outpoint(&source), Some(old_key));
        let tx = generate_spending_tx(source, &[]);
        let cfg = registry.cfg().clone();
        let events =
            classify_tx_for_all_sms(&cfg.deposit, &cfg.graph, &cfg.stake, &registry, &tx, 201);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, SMId::Stake(old_key));
        for (key, event) in events {
            registry.process_event(&key, event).unwrap();
        }
        assert!(registry.get_stake(&old_key).unwrap().state().is_slashed());
        assert_eq!(registry.get_stake(&new_key), Some(&successor));
        assert_eq!(registry.resolve_stake_outpoint(&source), Some(old_key));
        assert!(registry.resolve_stake_outpoint(&OutPoint::null()).is_none());
    }

    #[test]
    fn duplicate_source_outpoints_are_not_routed_to_multiple_covenants() {
        let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let first = make_confirmed_stake_sm(TEST_POV_IDX, table.clone(), generate_txid());
        let source = OutPoint::new(first.state().stake_txid().unwrap(), StakeTx::STAKE_VOUT);
        let mut second = first.clone();
        second.context = StakeSMCtx::new(TEST_POV_IDX, table, 200);
        let mut registry = test_empty_registry();
        registry.insert_stake(first).unwrap();
        registry.insert_stake(second).unwrap();
        assert!(registry.resolve_stake_outpoint(&source).is_none());
        let tx = generate_spending_tx(source, &[]);
        let cfg = registry.cfg();
        assert!(
            classify_tx_for_all_sms(&cfg.deposit, &cfg.graph, &cfg.stake, &registry, &tx, 201)
                .is_empty()
        );
    }
}
