//! Classification of on-chain events (buried blocks) into state-machine-specific events.
//!
//!
//! This module handles:
//! - Detecting new deposit requests and spawning SMs
//! - Running [`TxClassifier::classify_tx()`] per SM per transaction
//! - Appending `NewBlock` cursor events for all active SMs
//!
//! [`TxClassifier::classify_tx()`]: strata_bridge_sm::tx_classifier::TxClassifier::classify_tx

use std::{collections::BTreeSet, sync::Arc};

use bitcoin::{OutPoint, Transaction};
use bitcoind_async_client::Client as BitcoinClient;
use btc_tracker::event::BlockEvent;
use strata_asm_proto_bridge_txs::deposit_request::DRT_OUTPUT_INDEX;
use strata_bridge_primitives::{
    covenant::{CovenantId, StakeKey},
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
    operator_set::{BlockCovenant, OperatorSetEvent},
    stake::{
        config::StakeSMCfg,
        events::{NewBlockEvent as StakeNewBlockEvent, StakeEvent},
    },
    tx_classifier::TxClassifier,
};
use strata_bridge_tx_graph::transactions::{prelude::DepositData, stake::StakeTx};
use tracing::{Level, debug, info, warn};

use super::{drt, exits::resolve_exit_observation};
use crate::{
    applicator::Applicator,
    errors::{PipelineError, ProcessError},
    sm_registry::{ActiveOperatorSnapshot, RegistryInsertError, SMRegistry, SnapshotError},
    sm_types::{SMEvent, SMId, UnifiedDuty},
};

/// Applies stake transitions and finalizes the block's operator membership.
///
/// States that have already processed the block are left unchanged.
pub(crate) async fn process_stake_pass(
    applicator: &mut Applicator<'_>,
    block_event: &BlockEvent,
    bitcoin_client: &BitcoinClient,
) -> Result<(), PipelineError> {
    let height = block_event
        .block
        .bip34_block_height()
        .expect("must have a valid block height");

    let eligible: BTreeSet<_> = applicator
        .registry()
        .stakes()
        .filter(|(_, sm)| {
            sm.state()
                .last_processed_block_height()
                .is_some_and(|processed| processed < height)
        })
        .map(|(&key, _)| SMId::Stake(key))
        .collect();

    let stake_cfg = applicator.registry().cfg().stake.clone();
    let magic = applicator.registry().cfg().deposit.magic_bytes;

    // Authenticate exits only when membership needs to advance. Recovery replays blocks
    // at or below its cursor to catch up lagging stakes; revalidating their public exits
    // would require Bitcoin RPC and signing history that may not exist at that height.
    let observe_exits = applicator
        .registry()
        .get_operator_set()
        .is_none_or(|membership| membership.last_block_height() < height);

    let mut observations = Vec::new();
    for (tx_index, tx) in block_event.block.txdata.iter().enumerate() {
        if observe_exits
            && let Some(observation) =
                resolve_exit_observation(bitcoin_client, magic, tx, tx_index).await?
        {
            observations.push(observation);
        }

        let events = classify_stake_tx(&stake_cfg, applicator.registry(), tx, height)
            .into_iter()
            .filter(|(id, _)| eligible.contains(id));

        applicator.apply_batch(events)?;
    }

    let exits = match applicator.registry().get_operator_set() {
        Some(membership) if observe_exits => membership
            .validate_exits(height, &observations)
            .map_err(ProcessError::from)?,
        Some(_) => vec![],
        None if observations.is_empty() => vec![],
        None => return Err(ProcessError::SMNotFound(SMId::OperatorSet).into()),
    };

    let stakes: Vec<_> = applicator
        .registry()
        .stakes()
        .filter(|(_, sm)| {
            sm.state()
                .last_processed_block_height()
                .is_some_and(|processed| processed < height)
        })
        .map(|(&key, _)| key)
        .collect();

    applicator.apply_batch(new_block_events(&[], &[], &stakes, height))?;

    if applicator
        .registry()
        .get_operator_set()
        .is_some_and(|membership| membership.last_block_height() < height)
    {
        applicator.apply_batch([(
            SMId::OperatorSet,
            OperatorSetEvent::NewBlock {
                block_height: height,
                exits,
            }
            .into(),
        )])?;
    }

    Ok(())
}

/// Applies a block's deposit and graph transitions.
///
/// The block's membership and stake state must be finalized before calling this function.
/// Set `block_reaches_gate` to false for blocks older than the retained membership/stake state;
/// those blocks only advance existing deposits and graphs.
pub(crate) fn process_deposit_graph_pass(
    applicator: &mut Applicator<'_>,
    operator_table: &OperatorTable,
    covenant: CovenantId,
    block_reaches_gate: bool,
    block_event: &BlockEvent,
) -> Result<(), PipelineError> {
    let height = block_event
        .block
        .bip34_block_height()
        .expect("valid block height");

    // TODO: <https://alpenlabs.atlassian.net/browse/STR-4398>
    // Replace the restriction to the supplied covenant with block-final stake readiness.
    // Keep readiness and replay checks independent of covenant/address validation.
    let block_covenant = match applicator.registry().get_operator_set() {
        Some(membership)
            if block_reaches_gate
                && membership.last_block_height() == height
                && membership.current_covenant() == covenant =>
        {
            Some(membership.covenant_at(height).map_err(ProcessError::from)?)
        }
        _ => None,
    };

    let completed: BTreeSet<_> = applicator
        .registry()
        .deposits()
        .filter(|(_, sm)| {
            sm.state()
                .last_processed_block_height()
                .is_none_or(|h| *h >= height)
        })
        .map(|(&id, _)| SMId::Deposit(id))
        .chain(
            applicator
                .registry()
                .graphs()
                .filter(|(_, sm)| {
                    sm.state()
                        .last_processed_block_height()
                        .is_none_or(|h| *h >= height)
                })
                .map(|(&id, _)| SMId::Graph(id)),
        )
        .collect();

    let deposit_cfg = applicator.registry().cfg().deposit.clone();
    let graph_cfg = applicator.registry().cfg().graph.clone();
    for tx in &block_event.block.txdata {
        if let Some(block_covenant) = &block_covenant {
            let duties = try_register_deposit(
                &deposit_cfg,
                block_covenant,
                operator_table.pov_idx(),
                applicator,
                tx,
                height,
            )?;
            applicator.add_duties(duties);
        }

        let events =
            classify_deposit_graph_tx(&deposit_cfg, &graph_cfg, applicator.registry(), tx, height)
                .into_iter()
                .filter(|(id, _)| !completed.contains(id));

        applicator.apply_batch(events)?;
    }

    let deposits: Vec<_> = applicator
        .registry()
        .deposits()
        .filter(|(_, sm)| {
            sm.state()
                .last_processed_block_height()
                .is_some_and(|h| *h < height)
        })
        .map(|(&id, _)| id)
        .collect();

    let graphs: Vec<_> = applicator
        .registry()
        .graphs()
        .filter(|(_, sm)| {
            sm.state()
                .last_processed_block_height()
                .is_some_and(|h| *h < height)
        })
        .map(|(&id, _)| id)
        .collect();

    applicator.apply_batch(new_block_events(&deposits, &graphs, &[], height))?;

    Ok(())
}

/// If `tx` is a valid deposit request addressed to `block_covenant`, registers a [`DepositSM`]
/// and per-operator [`GraphSM`]s into the registry.
///
/// `block_covenant` must be the covenant finalized for the block containing `tx`.
///
/// Returns initial duties emitted by [`GraphSM`] constructors (e.g., `GenerateGraphData`).
/// Returns `Ok(Vec::new())` unless `local_operator` belongs to the covenant and every member has
/// an available stake, or if the transaction is already registered or fails DRT validation.
fn try_register_deposit(
    deposit_cfg: &Arc<DepositSMCfg>,
    block_covenant: &BlockCovenant,
    local_operator: OperatorIdx,
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

    let Some(local_table) = block_covenant
        .operator_table
        .clone()
        .with_pov(local_operator)
    else {
        debug!(%drt_txid, covenant=%block_covenant.covenant, "skipping DRT for a covenant without the local operator");
        return Ok(Vec::new());
    };

    let snapshot = match applicator
        .registry()
        .active_operator_snapshot(block_covenant.covenant, &local_table)
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

    let valid = match drt::validate_candidate(tx, deposit_cfg, &block_covenant.operator_table) {
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

    // TODO: <https://alpenlabs.atlassian.net/browse/STR-4398>
    // Supply the progress of the request's covenant sequence once admission is no longer
    // limited to the initial covenant. Until then, every registered deposit shares one sequence.
    let previous = applicator.registry().last_deposit_idx();
    let deposit_idx = match applicator.registry().next_deposit_idx(
        previous,
        &block_covenant.operator_table,
        local_operator,
    ) {
        Ok(deposit_idx) => deposit_idx,
        // An incorrect starting height can replay requests from before this node joined.
        Err(err @ RegistryInsertError::OffsetOutsideLocalCovenant(_)) => {
            warn!(%err, %drt_txid, "skipping DRT for a covenant without the local operator");
            return Ok(Vec::new());
        }
        Err(err) => return Err(err.into()),
    };
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

/// Returns the deposit and graph events recognized in a transaction.
fn classify_deposit_graph_tx(
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
                .map(|ev| (SMId::Deposit(deposit_idx), ev.into()))
        })
        .chain(registry.graphs().filter_map(|(&graph_idx, sm)| {
            sm.classify_tx(graph_cfg, tx, height)
                .map(|ev| (graph_idx.into(), ev.into()))
        }))
        .collect()
}

/// Returns stake lifecycle events whose source identifies a unique tracked stake.
fn classify_stake_tx(
    stake_cfg: &Arc<StakeSMCfg>,
    registry: &SMRegistry,
    tx: &Transaction,
    height: BitcoinBlockHeight,
) -> Vec<(SMId, SMEvent)> {
    registry.stakes().filter_map(|(&stake_key, sm)| {
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
        })
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
    use strata_bridge_primitives::operator_table::PublicOperatorTable;
    use strata_bridge_sm::{
        deposit::state::DepositState,
        graph::duties::GraphDuty,
        operator_set::{ConfirmedExit, ExitKind},
        stake::state::StakeState,
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
        applicator::BatchOutput,
        persister::Persister,
        pipeline::process_block,
        sm_registry::{SMConfig, SMRegistry},
        testing::{
            DrtBuilder, INITIAL_BLOCK_HEIGHT, N_TEST_OPERATORS, TEST_POV_IDX,
            insert_confirmed_stake, insert_deposit_with_graphs, insert_test_membership,
            make_confirmed_stake_sm, test_deposit_sm_cfg, test_empty_registry, test_fdb_config,
            test_membership, test_membership_table, test_operator_table, test_populated_registry,
            test_safe_harbour_address, test_sm_config, test_stake_key, unavailable_bitcoin_client,
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
                SMEvent::InitializeStake { .. } => {
                    panic!("block advancement must not initialize stakes")
                }
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

    /// Returns `table`'s covenant at [`INITIAL_BLOCK_HEIGHT`] as finalized for a block.
    fn block_covenant_for(table: &OperatorTable) -> BlockCovenant {
        BlockCovenant {
            covenant: CovenantId::from_operator_table(table, INITIAL_BLOCK_HEIGHT).unwrap(),
            operator_table: table.clone().into_public(),
        }
    }

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

        let mut applicator = Applicator::new(&mut registry, None);
        let duties = try_register_deposit(
            &cfg,
            &block_covenant_for(&operator_table),
            TEST_POV_IDX,
            &mut applicator,
            &tx,
            TEST_HEIGHT,
        )
        .unwrap();
        let BatchOutput { tracker, .. } = applicator.finish();

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
            let mut applicator = Applicator::new(&mut registry, None);
            let duties = try_register_deposit(
                &cfg,
                &block_covenant_for(&operator_table),
                TEST_POV_IDX,
                &mut applicator,
                &tx,
                TEST_HEIGHT,
            )
            .unwrap();
            let BatchOutput {
                duties: applied_duties,
                tracker,
            } = applicator.finish();
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

        let mut applicator = Applicator::new(&mut registry, None);
        let duties = try_register_deposit(
            &cfg,
            &block_covenant_for(&operator_table),
            TEST_POV_IDX,
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

        let mut applicator = Applicator::new(&mut registry, None);
        let duties = try_register_deposit(
            &cfg,
            &block_covenant_for(&operator_table),
            TEST_POV_IDX,
            &mut applicator,
            &tx,
            TEST_HEIGHT,
        )
        .unwrap();
        let BatchOutput { tracker, .. } = applicator.finish();

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
        let tx = DrtBuilder::aligned(&table, &cfg).build();
        let mut registry = test_populated_registry(0);
        confirm_all_stakes(&mut registry, &table);
        let mut applicator = Applicator::new(&mut registry, None);
        assert_eq!(
            try_register_deposit(
                &cfg,
                &block_covenant_for(&table),
                TEST_POV_IDX,
                &mut applicator,
                &tx,
                TEST_HEIGHT,
            )
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
            let mut applicator = Applicator::new(&mut restored, None);
            let duties = try_register_deposit(
                &cfg,
                &block_covenant_for(&table),
                TEST_POV_IDX,
                &mut applicator,
                &tx,
                TEST_HEIGHT,
            )
            .unwrap();
            let BatchOutput { tracker, .. } = applicator.finish();
            assert!(duties.is_empty(), "replay must not emit constructor duties");
            assert!(tracker.into_batches().is_empty());
            assert_eq!(restored.get_all_ids(), ids);
            assert_eq!(restored.get_deposit(&0), Some(&deposit));
        }
    }

    #[tokio::test]
    async fn deposit_registration_recovers_from_any_committed_batch_subset() {
        let bitcoin_client = unavailable_bitcoin_client();
        let table = test_membership_table();
        let covenant = CovenantId::from_operator_table(&table, INITIAL_BLOCK_HEIGHT).unwrap();
        let mut registry = test_populated_registry(0);
        insert_test_membership(&mut registry, INITIAL_BLOCK_HEIGHT + 1);
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
        let mut applicator = Applicator::new(&mut registry, None);
        process_deposit_graph_pass(&mut applicator, &table, covenant, true, &event).unwrap();
        let BatchOutput { tracker, .. } = applicator.finish();
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
            ..test_fdb_config()
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
                let batch =
                    process_block(&bitcoin_client, &mut restored, &table, covenant, &replay)
                        .await
                        .unwrap();
                persister
                    .persist_batches(batch.tracker, &restored)
                    .await
                    .unwrap();
                let duties = batch.duties;
                emitted_duties.extend(duties);
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

    // TODO: <https://alpenlabs.atlassian.net/browse/STR-4398>
    // Extend this single-covenant fixture to canonical ledger/admission integration.
    #[tokio::test]
    async fn block_final_stake_confirmation_admits_both_drts_without_replay_duplicates() {
        let bitcoin_client = unavailable_bitcoin_client();
        let table = test_membership_table();
        let covenant = CovenantId::from_operator_table(&table, INITIAL_BLOCK_HEIGHT).unwrap();
        let mut registry = test_populated_registry(0);
        insert_test_membership(&mut registry, INITIAL_BLOCK_HEIGHT);
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
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let (client, guard) = FdbClient::setup(Config {
            root_directory: format!("test-drt-readiness-{suffix}"),
            ..test_fdb_config()
        })
        .await
        .unwrap();
        let db = Arc::new(client);
        let persister = Persister::new(db.clone());
        let batch = process_block(&bitcoin_client, &mut registry, &table, covenant, &event)
            .await
            .unwrap();
        persister
            .persist_batches(batch.tracker, &registry)
            .await
            .unwrap();
        let duties = batch.duties;
        assert_eq!(duties.len(), 2);
        assert_eq!(registry.num_deposits(), 2);
        assert_eq!(
            registry
                .get_deposit(&0)
                .unwrap()
                .context()
                .deposit_request_outpoint(),
            skipped_outpoint
        );
        assert_eq!(
            registry
                .get_deposit(&1)
                .unwrap()
                .context()
                .deposit_request_outpoint(),
            admitted_outpoint
        );

        let mut restored = persister
            .recover_registry(registry.cfg().clone())
            .await
            .unwrap();
        assert_eq!(
            restored.earliest_processed_block_height(),
            Some(INITIAL_BLOCK_HEIGHT + 1)
        );
        assert_eq!(restored.num_deposits(), 2);
        assert_eq!(restored.get_deposit(&0), registry.get_deposit(&0));
        assert!(restored.active_operator_snapshot(covenant, &table).is_ok());
        let original = restored.get_deposit(&0).unwrap().clone();
        let batch = process_block(&bitcoin_client, &mut restored, &table, covenant, &event)
            .await
            .unwrap();
        persister
            .persist_batches(batch.tracker, &restored)
            .await
            .unwrap();
        let duties = batch.duties;
        assert!(duties.is_empty());
        assert_eq!(restored.num_deposits(), 2);
        assert_eq!(restored.get_deposit(&0), Some(&original));
        let mut recovered = persister
            .recover_registry(registry.cfg().clone())
            .await
            .unwrap();
        let ids = recovered.get_all_ids();
        let before = recovered.clone();
        let batch = process_block(&bitcoin_client, &mut recovered, &table, covenant, &event)
            .await
            .unwrap();
        persister
            .persist_batches(batch.tracker, &recovered)
            .await
            .unwrap();
        let duties = batch.duties;
        assert!(duties.is_empty());
        for id in before.get_deposit_ids() {
            assert_eq!(recovered.get_deposit(&id), before.get_deposit(&id));
        }
        for id in before.get_graph_ids() {
            assert_eq!(recovered.get_graph(&id), before.get_graph(&id));
        }
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

        let mut applicator = Applicator::new(&mut registry, None);
        let duties = try_register_deposit(
            &cfg,
            &block_covenant_for(&operator_table),
            TEST_POV_IDX,
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

    /// Returns the covenants finalized before and after `exited` leaves [`test_membership`].
    fn covenants_around_exit(exited: OperatorIdx) -> (BlockCovenant, BlockCovenant) {
        let mut membership = test_membership();
        let exit_height = INITIAL_BLOCK_HEIGHT + 1;
        membership
            .apply_block(
                exit_height,
                &[ConfirmedExit {
                    operator_idx: exited,
                    txid: generate_txid(),
                    tx_index: 1,
                    kind: ExitKind::Slash,
                }],
            )
            .unwrap();
        (
            membership.covenant_at(INITIAL_BLOCK_HEIGHT).unwrap(),
            membership.covenant_at(exit_height).unwrap(),
        )
    }

    fn register(
        registry: &mut SMRegistry,
        covenant: &BlockCovenant,
        tx: &Transaction,
    ) -> Vec<UnifiedDuty> {
        let cfg = registry.cfg().deposit.clone();
        let mut applicator = Applicator::new(registry, None);
        let duties = try_register_deposit(
            &cfg,
            covenant,
            TEST_POV_IDX,
            &mut applicator,
            tx,
            TEST_HEIGHT,
        )
        .unwrap();
        applicator.finish();
        duties
    }

    #[test]
    fn registration_validates_requests_against_the_block_final_covenant() {
        let exited = N_TEST_OPERATORS as OperatorIdx - 1;
        let (initial, successor) = covenants_around_exit(exited);
        let successor_table = successor
            .operator_table
            .clone()
            .with_pov(TEST_POV_IDX)
            .unwrap();
        let mut registry = test_empty_registry();
        confirm_all_stakes(&mut registry, &successor_table);
        let cfg = registry.cfg().deposit.clone();
        let stale = DrtBuilder::aligned(
            &initial
                .operator_table
                .clone()
                .with_pov(TEST_POV_IDX)
                .unwrap(),
            &cfg,
        )
        .build();
        let current = DrtBuilder::aligned(&successor_table, &cfg).build();

        register(&mut registry, &successor, &stale);
        assert_eq!(
            registry.num_deposits(),
            0,
            "A request for the pre-exit covenant must not be registered after the exit"
        );

        register(&mut registry, &successor, &current);
        let deposit = registry
            .get_deposit(&0)
            .expect("a request for the block-final covenant must be registered");
        assert_eq!(
            deposit.context().deposit_request_outpoint(),
            OutPoint::new(current.compute_txid(), DRT_OUTPUT_INDEX as u32),
            "The block-final request must receive the first index"
        );
        assert!(
            deposit
                .context()
                .operator_table()
                .has_same_membership(&successor.operator_table),
            "The deposit must retain the block-final covenant's membership"
        );
    }

    #[test]
    fn registration_skips_covenants_without_the_local_operator() {
        let offset = 1200;
        let (initial, foreign) = covenants_around_exit(TEST_POV_IDX);
        let initial_table = initial
            .operator_table
            .clone()
            .with_pov(TEST_POV_IDX)
            .unwrap();
        let mut registry = SMRegistry::new(SMConfig {
            deposit_index_offset: offset,
            ..test_sm_config()
        });
        confirm_all_stakes(&mut registry, &initial_table);
        let cfg = registry.cfg().deposit.clone();
        let other_member = *foreign.operator_table.operator_idxs().first().unwrap();
        let foreign_request = DrtBuilder::aligned(
            &foreign
                .operator_table
                .clone()
                .with_pov(other_member)
                .unwrap(),
            &cfg,
        )
        .build();

        register(&mut registry, &foreign, &foreign_request);
        assert_eq!(
            registry.num_deposits(),
            0,
            "A request for a covenant without the local operator must not consume the offset"
        );

        let request = DrtBuilder::aligned(&initial_table, &cfg).build();
        register(&mut registry, &initial, &request);
        assert_eq!(
            registry.get_deposit_ids(),
            vec![offset],
            "The first request the local operator can process must receive the offset"
        );
    }

    #[test]
    fn registration_requires_membership_to_resolve_the_block_covenant() {
        let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let covenant = CovenantId::from_operator_table(&table, INITIAL_BLOCK_HEIGHT).unwrap();
        let mut registry = test_empty_registry();
        confirm_all_stakes(&mut registry, &table);
        let mut block = generate_block_with_height(INITIAL_BLOCK_HEIGHT + 1);
        block
            .txdata
            .push(DrtBuilder::aligned(&table, &registry.cfg().deposit).build());
        let event = BlockEvent {
            block,
            status: BlockStatus::Buried,
        };

        let mut applicator = Applicator::new(&mut registry, None);
        process_deposit_graph_pass(&mut applicator, &table, covenant, true, &event).unwrap();
        applicator.finish();
        assert_eq!(
            registry.num_deposits(),
            0,
            "Without membership the block's covenant is unknown, so no request may be registered"
        );
    }

    /// Builds a covenant member that registers deposits from `offset` when it has none.
    fn seeded_member(
        local_operator: OperatorIdx,
        offset: DepositIdx,
    ) -> (SMRegistry, OperatorTable) {
        let table = test_membership()
            .current_operator_table()
            .unwrap()
            .with_pov(local_operator)
            .unwrap();
        let mut registry = SMRegistry::new(SMConfig {
            deposit_index_offset: offset,
            ..test_sm_config()
        });
        insert_test_membership(&mut registry, INITIAL_BLOCK_HEIGHT);
        confirm_all_stakes(&mut registry, &table);
        (registry, table)
    }

    /// Returns each registered request outpoint with its index and covenant membership.
    fn registered_mapping(
        registry: &SMRegistry,
    ) -> Vec<(OutPoint, DepositIdx, PublicOperatorTable)> {
        registry
            .deposits()
            .map(|(&idx, sm)| {
                (
                    sm.context().deposit_request_outpoint(),
                    idx,
                    sm.context().operator_table().clone().into_public(),
                )
            })
            .collect()
    }

    #[tokio::test]
    async fn seeded_joiner_and_participant_assign_identical_indices() {
        let bitcoin_client = unavailable_bitcoin_client();
        let history = 3;
        let joiner_operator = N_TEST_OPERATORS as OperatorIdx - 1;
        let (mut participant, participant_table) = seeded_member(TEST_POV_IDX, 0);
        for idx in 0..history {
            insert_deposit_with_graphs(&mut participant, idx);
        }
        let (mut joiner, joiner_table) = seeded_member(joiner_operator, history);
        let covenant = test_membership().current_covenant();

        let mut block = generate_block_with_height(INITIAL_BLOCK_HEIGHT + 1);
        for _ in 0..2 {
            block
                .txdata
                .push(DrtBuilder::aligned(&participant_table, &participant.cfg().deposit).build());
        }
        let event = BlockEvent {
            block,
            status: BlockStatus::Buried,
        };

        process_block(
            &bitcoin_client,
            &mut participant,
            &participant_table,
            covenant,
            &event,
        )
        .await
        .unwrap();
        process_block(
            &bitcoin_client,
            &mut joiner,
            &joiner_table,
            covenant,
            &event,
        )
        .await
        .unwrap();
        let shared: Vec<_> = registered_mapping(&participant)
            .into_iter()
            .filter(|(_, idx, _)| *idx >= history)
            .collect();
        assert_eq!(
            shared.iter().map(|(_, idx, _)| *idx).collect::<Vec<_>>(),
            vec![history, history + 1],
            "Both requests in the block must receive consecutive indices after the participant's history"
        );
        assert_eq!(
            registered_mapping(&joiner),
            shared,
            "A correctly seeded joiner must assign the participant's outpoint, index, and covenant"
        );

        process_block(
            &bitcoin_client,
            &mut joiner,
            &joiner_table,
            covenant,
            &event,
        )
        .await
        .unwrap();
        assert_eq!(
            registered_mapping(&joiner),
            shared,
            "Replaying the block must not register the requests again or renumber them"
        );
    }

    #[tokio::test]
    async fn wrong_offset_makes_a_joiner_disagree_with_peers() {
        let bitcoin_client = unavailable_bitcoin_client();
        let history = 3;
        let joiner_operator = N_TEST_OPERATORS as OperatorIdx - 1;
        let (mut participant, participant_table) = seeded_member(TEST_POV_IDX, 0);
        for idx in 0..history {
            insert_deposit_with_graphs(&mut participant, idx);
        }
        let (mut joiner, joiner_table) = seeded_member(joiner_operator, history + 1);
        let covenant = test_membership().current_covenant();

        let mut block = generate_block_with_height(INITIAL_BLOCK_HEIGHT + 1);
        block
            .txdata
            .push(DrtBuilder::aligned(&participant_table, &participant.cfg().deposit).build());
        let event = BlockEvent {
            block,
            status: BlockStatus::Buried,
        };

        process_block(
            &bitcoin_client,
            &mut participant,
            &participant_table,
            covenant,
            &event,
        )
        .await
        .unwrap();
        process_block(
            &bitcoin_client,
            &mut joiner,
            &joiner_table,
            covenant,
            &event,
        )
        .await
        .unwrap();
        assert_eq!(
            participant.get_deposit_ids().last(),
            Some(&history),
            "The participant must index the request after its history"
        );
        assert_eq!(
            joiner.get_deposit_ids(),
            vec![history + 1],
            "A joiner seeded with the wrong offset must keep that index rather than correct it"
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
        let events = classify_stake_tx(&cfg.stake, &registry, &tx, 201);
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
        assert!(classify_stake_tx(&cfg.stake, &registry, &tx, 201).is_empty());
    }
}
