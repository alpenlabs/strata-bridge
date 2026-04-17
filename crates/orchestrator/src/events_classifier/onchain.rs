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

use bitcoin::{Transaction, hex::DisplayHex, secp256k1::XOnlyPublicKey};
use btc_tracker::event::BlockEvent;
use strata_asm_txs_bridge_v1::deposit_request::parse_drt;
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
use tracing::{Level, error, info, warn};

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
        // If this tx is a DRT, register new DepositSM + per-operator GraphSMs using the currently
        // active operator snapshot. Because stake SM state transitions settle between transaction
        // batches via the Applicator, a stake transition that removes an operator from the active
        // set in an earlier transaction will be reflected here for a DRT appearing later in the
        // same block.
        let initial_duties = try_register_deposit(
            &deposit_cfg,
            initial_operator_table,
            applicator.registry_mut(),
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
/// Returns `Ok(Vec::new())` if the transaction is not a DRT or if the registry is not yet ready
/// to accept deposits (either because not all operators have staked, or because this node's own
/// operator is not active).
fn try_register_deposit(
    deposit_cfg: &Arc<DepositSMCfg>,
    full_operator_table: &OperatorTable,
    registry: &mut SMRegistry,
    tx: &Transaction,
    height: BitcoinBlockHeight,
) -> Result<Vec<UnifiedDuty>, ProcessError> {
    let Ok(drt_info) = parse_drt(tx) else {
        return Ok(Vec::new());
    };

    let drt_txid = tx.compute_txid();

    let span = tracing::span!(Level::INFO, "registering new deposit", drt_txid=%drt_txid);
    let _entered = span.entered();

    // Activation rule: before any DSM / GSM may become active, one stake state machine must exist
    // for every configured operator and all of them must have reached `Confirmed` or higher.
    if !registry.all_operators_have_staked() {
        warn!(
            %drt_txid,
            "skipping DRT: not all operators have completed staking"
        );
        return Ok(Vec::new());
    }

    let snapshot = match registry.active_operator_snapshot(full_operator_table) {
        Ok(snap) => snap,
        Err(err) => {
            warn!(%drt_txid, %err, "skipping DRT: could not derive active operator snapshot");
            return Ok(Vec::new());
        }
    };

    let depositor_pubkey = drt_info.header_aux().recovery_pk();
    let Ok(depositor_pubkey) = XOnlyPublicKey::from_slice(depositor_pubkey) else {
        error!(pk=%depositor_pubkey.to_lower_hex_string(), "invalid depositor pubkey in DRT, ignoring");
        return Ok(Vec::new());
    };

    let magic_bytes = deposit_cfg.magic_bytes;

    let deposit_idx_offset = registry.next_deposit_idx()?;

    // Always second output for now: output 0 is SPS-50 OP_RETURN and output 1 is DRT spend UTXO.
    let Some(deposit_request_output) = tx.output.get(1) else {
        error!(
            %drt_txid,
            "invalid DRT: expected spendable output at index 1, ignoring"
        );
        return Ok(Vec::new());
    };
    let deposit_request_outpoint = bitcoin::OutPoint::new(drt_txid, 1);
    let deposit_data = DepositData {
        deposit_idx: deposit_idx_offset,
        deposit_request_outpoint,
        magic_bytes,
    };

    let ActiveOperatorSnapshot {
        operator_table: active_operator_table,
        stake_inputs,
        unstaking_images,
    } = snapshot;

    let dsm = DepositSM::new(
        deposit_cfg.clone(),
        active_operator_table.clone(),
        deposit_data,
        depositor_pubkey,
        deposit_request_output.value,
        height,
    );

    let deposit_outpoint = dsm.context().deposit_outpoint();
    info!(%deposit_outpoint, deposit_idx=deposit_idx_offset, "registering new DepositSM for detected DRT");
    registry.insert_deposit(deposit_idx_offset, dsm)?;

    // Register one GraphSM per active operator, collecting initial duties.
    let mut duties = Vec::new();
    for &op_idx in active_operator_table.operator_idxs().iter() {
        let graph_idx = GraphIdx {
            deposit: deposit_idx_offset,
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
        registry.insert_graph(gsm.context().graph_idx(), gsm)?;
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
                .map(|ev| (deposit_idx.into(), ev.into()))
        })
        .chain(registry.graphs().filter_map(|(&graph_idx, sm)| {
            sm.classify_tx(graph_cfg, tx, height)
                .map(|ev| (graph_idx.into(), ev.into()))
        }))
        .chain(registry.stakes().filter_map(|(&operator_idx, sm)| {
            sm.classify_tx(stake_cfg, tx, height)
                .map(|ev| (operator_idx.into(), ev.into()))
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
        .map(|&idx| (idx.into(), deposit_event.clone().into()))
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
            &mut registry,
            &random_tx,
            100,
        )
        .expect("non-DRT path should not fail");

        assert!(duties.is_empty());
        assert_eq!(registry.num_deposits(), 0);
    }
}
