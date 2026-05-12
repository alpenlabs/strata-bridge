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

use bitcoin::{Amount, Transaction, hex::DisplayHex, secp256k1::XOnlyPublicKey};
use btc_tracker::event::BlockEvent;
use strata_asm_proto_bridge_v1_txs::{
    BRIDGE_V1_SUBPROTOCOL_ID,
    constants::BridgeTxType,
    deposit_request::{create_deposit_request_locking_script, parse_drt},
    errors::TxStructureError,
};
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
use strata_bridge_tx_graph::transactions::{deposit::DepositTx, prelude::DepositData};
use strata_l1_txfmt::extract_tx_magic_and_tag;
use thiserror::Error;
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

/// Successfully validated DRT data needed to construct a [`DepositSM`].
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "wired into try_register_deposit in the next commit"
    )
)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidDrt {
    /// Depositor's x-only recovery pubkey parsed from the SPS-50 aux data.
    depositor_pubkey: XOnlyPublicKey,
    /// Amount on the deposit-request output (output index 1).
    drt_output_amount: Amount,
}

/// Reason [`validate_drt`] rejected a transaction.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "wired into try_register_deposit in the next commit"
    )
)]
#[derive(Debug, Error)]
enum DrtValidationError {
    /// Transaction is not addressed to this bridge: missing SPS-50 OP_RETURN, or the magic /
    /// subprotocol id / tx type do not identify it as a Bridge-v1 DRT for `cfg.magic_bytes`.
    /// Expected for the vast majority of block transactions and not worth surfacing as an
    /// error to the operator.
    #[error("transaction is not a DRT for this bridge")]
    NotOurEnvelope,
    /// SPS-50 envelope identified the tx as our DRT, but the structural parse failed.
    #[error("DRT is structurally invalid: {0}")]
    Structure(#[source] TxStructureError),
    /// The 32-byte recovery pubkey in the SPS-50 aux data is not a valid x-only point.
    #[error("DRT aux carries invalid recovery pubkey: {0}")]
    InvalidRecoveryPubkey(String),
    /// Output-1 carries less than `deposit_amount + deposit-tx fee` and so cannot fund a
    /// relayable deposit transaction.
    #[error("DRT output value {actual} is below required {required}")]
    OutputValueBelowRequired { actual: Amount, required: Amount },
    /// Output-1's P2TR script does not match the script reconstructed from the depositor's
    /// recovery pubkey, the active N-of-N aggregated key, and the bridge's recovery delay.
    /// The DRT is therefore not cooperatively spendable by the bridge.
    #[error("DRT output script does not match expected P2TR locking script")]
    LockingScriptMismatch,
}

/// Validates that `tx` is a well-formed DRT for the bridge with the given `cfg` and the given
/// active operator set, and returns the parts a [`DepositSM`] needs.
///
/// Pure: no registry or applicator access. The caller is responsible for ensuring stake
/// readiness and deriving `active_operator_table` from the active-operator snapshot before
/// calling.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "wired into try_register_deposit in the next commit"
    )
)]
fn validate_drt(
    tx: &Transaction,
    cfg: &DepositSMCfg,
    active_operator_table: &OperatorTable,
) -> Result<ValidDrt, DrtValidationError> {
    let Ok((magic, tag)) = extract_tx_magic_and_tag(tx) else {
        return Err(DrtValidationError::NotOurEnvelope);
    };
    if magic != cfg.magic_bytes
        || tag.subproto_id() != BRIDGE_V1_SUBPROTOCOL_ID
        || tag.tx_type() != BridgeTxType::DepositRequest as u8
    {
        return Err(DrtValidationError::NotOurEnvelope);
    }

    let drt_info = parse_drt(tx).map_err(DrtValidationError::Structure)?;

    let recovery_pk_bytes = drt_info.header_aux().recovery_pk();
    let depositor_pubkey = XOnlyPublicKey::from_slice(recovery_pk_bytes).map_err(|_| {
        DrtValidationError::InvalidRecoveryPubkey(recovery_pk_bytes.to_lower_hex_string())
    })?;

    // `parse_drt` already ensures output at index 1 exists.
    let drt_output = tx
        .output
        .get(1)
        .expect("parse_drt guarantees output index 1 exists");

    let required = DepositTx::drt_required(cfg.deposit_amount);
    if drt_output.value < required {
        return Err(DrtValidationError::OutputValueBelowRequired {
            actual: drt_output.value,
            required,
        });
    }

    let n_of_n = active_operator_table
        .aggregated_btc_key()
        .x_only_public_key()
        .0;
    let expected_script =
        create_deposit_request_locking_script(recovery_pk_bytes, n_of_n, cfg.recovery_delay);
    if drt_output.script_pubkey != expected_script {
        return Err(DrtValidationError::LockingScriptMismatch);
    }

    Ok(ValidDrt {
        depositor_pubkey,
        drt_output_amount: drt_output.value,
    })
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
    applicator: &mut Applicator<'_>,
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
    if !applicator
        .registry()
        .all_operators_have_staked(full_operator_table)
    {
        warn!("skipping DRT: not all operators have completed staking");
        return Ok(Vec::new());
    }

    let snapshot = match applicator
        .registry()
        .active_operator_snapshot(full_operator_table)
    {
        Ok(snap) => snap,
        Err(err) => {
            warn!(%err, "skipping DRT: could not derive active operator snapshot");
            return Ok(Vec::new());
        }
    };
    info!(
        active_operator_count = snapshot.operator_table.operator_idxs().len(),
        "passed stake-readiness gate; registering DSM / GSMs from active operator snapshot"
    );

    let depositor_pubkey = drt_info.header_aux().recovery_pk();
    let Ok(depositor_pubkey) = XOnlyPublicKey::from_slice(depositor_pubkey) else {
        error!(pk=%depositor_pubkey.to_lower_hex_string(), "invalid depositor pubkey in DRT, ignoring");
        return Ok(Vec::new());
    };

    let magic_bytes = deposit_cfg.magic_bytes;

    let deposit_idx_offset = applicator.registry().next_deposit_idx()?;

    // Always second output for now: output 0 is SPS-50 OP_RETURN and output 1 is DRT spend UTXO.
    let Some(deposit_request_output) = tx.output.get(1) else {
        error!("invalid DRT: expected spendable output at index 1, ignoring");
        return Ok(Vec::new());
    };

    // The deposit-request UTXO must include the deposit amount plus the bridge's hardcoded
    // deposit-tx fee — without that surplus the deposit transaction would have insufficient
    // fee to relay.
    let drt_required = DepositTx::drt_required(deposit_cfg.deposit_amount);
    if deposit_request_output.value < drt_required {
        error!(
            drt_value = %deposit_request_output.value,
            %drt_required,
            "invalid DRT: spendable output value is less than deposit_amount + deposit_fee, ignoring"
        );
        return Ok(Vec::new());
    }

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
    applicator.insert_deposit(deposit_idx_offset, dsm)?;

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
    use bitcoin::{Amount, Network, ScriptBuf, TxIn, TxOut, absolute, transaction};
    use strata_bridge_test_utils::{
        bitcoin::generate_xonly_pubkey,
        bridge_fixtures::{TEST_MAGIC_BYTES, TEST_RECOVERY_DELAY},
    };
    use strata_l1_txfmt::{MagicBytes, ParseConfig, TagData};

    use super::*;
    use crate::testing::{
        N_TEST_OPERATORS, TEST_POV_IDX, test_deposit_sm_cfg, test_operator_table,
        test_populated_registry,
    };

    const TEST_HEIGHT: BitcoinBlockHeight = 200;

    // ===== Test fixture builders =====

    /// Configurable builder for synthetic DRTs. Defaults produce a structurally valid DRT for
    /// the bridge whose `operator_table` and `cfg` are passed to [`Self::aligned`]; individual
    /// fields can then be overridden to drive each gate in [`validate_drt`].
    struct DrtBuilder {
        magic: MagicBytes,
        subproto_id: u8,
        tx_type: u8,
        /// Recovery pubkey bytes placed in the SPS-50 aux data.
        recovery_pk_in_aux: [u8; 32],
        /// N-of-N internal key used when building the output-1 P2TR script.
        n_of_n_in_script: XOnlyPublicKey,
        /// Recovery pubkey bytes used inside the output-1 takeback tapscript.
        recovery_pk_in_script: [u8; 32],
        /// CSV delay encoded inside the output-1 takeback tapscript.
        recovery_delay_in_script: u16,
        /// Amount placed on output 1.
        output_value: Amount,
        /// Optional destination bytes appended after the 32-byte recovery_pk in aux.
        destination: Vec<u8>,
    }

    impl DrtBuilder {
        /// Returns a builder whose every field is aligned with a valid DRT for the given
        /// operator table and configuration.
        fn aligned(operator_table: &OperatorTable, cfg: &DepositSMCfg) -> Self {
            let recovery_pk = generate_xonly_pubkey().serialize();
            let n_of_n = operator_table.aggregated_btc_key().x_only_public_key().0;
            Self {
                magic: cfg.magic_bytes,
                subproto_id: BRIDGE_V1_SUBPROTOCOL_ID,
                tx_type: BridgeTxType::DepositRequest as u8,
                recovery_pk_in_aux: recovery_pk,
                n_of_n_in_script: n_of_n,
                recovery_pk_in_script: recovery_pk,
                recovery_delay_in_script: cfg.recovery_delay,
                output_value: DepositTx::drt_required(cfg.deposit_amount),
                destination: Vec::new(),
            }
        }

        /// Build the synthetic transaction.
        fn build(&self) -> Transaction {
            let mut aux = Vec::with_capacity(32 + self.destination.len());
            aux.extend_from_slice(&self.recovery_pk_in_aux);
            aux.extend_from_slice(&self.destination);

            let tag = TagData::new(self.subproto_id, self.tx_type, aux)
                .expect("aux must fit SPS-50 size limits");
            let op_return = ParseConfig::new(self.magic)
                .encode_script_buf(&tag.as_ref())
                .expect("SPS-50 tag must encode");

            let lock = create_deposit_request_locking_script(
                &self.recovery_pk_in_script,
                self.n_of_n_in_script,
                self.recovery_delay_in_script,
            );

            Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![TxIn::default()],
                output: vec![
                    TxOut {
                        value: Amount::ZERO,
                        script_pubkey: op_return,
                    },
                    TxOut {
                        value: self.output_value,
                        script_pubkey: lock,
                    },
                ],
            }
        }
    }

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

        let mut applicator = Applicator::new(&mut registry);
        let duties = try_register_deposit(
            &deposit_cfg,
            &operator_table,
            &mut applicator,
            &random_tx,
            100,
        )
        .expect("non-DRT path should not fail");
        let (_, tracker) = applicator.finish();

        assert!(duties.is_empty());
        assert_eq!(registry.num_deposits(), 0);
        assert!(
            tracker.into_batches().is_empty(),
            "non-DRT path must not record any SMs in the persistence tracker"
        );
    }

    // ===== validate_drt tests =====

    #[test]
    fn validate_drt_accepts_aligned_drt() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let builder = DrtBuilder::aligned(&operator_table, &cfg);
        let expected_pk = XOnlyPublicKey::from_slice(&builder.recovery_pk_in_aux).unwrap();
        let expected_value = builder.output_value;

        let valid = validate_drt(&builder.build(), &cfg, &operator_table)
            .expect("aligned DRT must validate");

        assert_eq!(valid.depositor_pubkey, expected_pk);
        assert_eq!(valid.drt_output_amount, expected_value);
    }

    #[test]
    fn validate_drt_rejects_tx_without_sps50_envelope() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();

        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        assert!(matches!(
            validate_drt(&tx, &cfg, &operator_table),
            Err(DrtValidationError::NotOurEnvelope)
        ));
    }

    #[test]
    fn validate_drt_rejects_non_op_return_first_output() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new_p2tr(
                    bitcoin::secp256k1::SECP256K1,
                    generate_xonly_pubkey(),
                    None,
                ),
            }],
        };

        assert!(matches!(
            validate_drt(&tx, &cfg, &operator_table),
            Err(DrtValidationError::NotOurEnvelope)
        ));
    }

    #[test]
    fn validate_drt_rejects_wrong_magic() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();

        let mut builder = DrtBuilder::aligned(&operator_table, &cfg);
        builder.magic = MagicBytes::new(*b"XXXX");

        assert!(matches!(
            validate_drt(&builder.build(), &cfg, &operator_table),
            Err(DrtValidationError::NotOurEnvelope)
        ));
    }

    #[test]
    fn validate_drt_rejects_wrong_subproto() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();

        let mut builder = DrtBuilder::aligned(&operator_table, &cfg);
        builder.subproto_id = BRIDGE_V1_SUBPROTOCOL_ID.wrapping_add(1);

        assert!(matches!(
            validate_drt(&builder.build(), &cfg, &operator_table),
            Err(DrtValidationError::NotOurEnvelope)
        ));
    }

    #[test]
    fn validate_drt_rejects_wrong_tx_type() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();

        let mut builder = DrtBuilder::aligned(&operator_table, &cfg);
        builder.tx_type = BridgeTxType::Deposit as u8;

        assert!(matches!(
            validate_drt(&builder.build(), &cfg, &operator_table),
            Err(DrtValidationError::NotOurEnvelope)
        ));
    }

    #[test]
    fn validate_drt_rejects_malformed_aux() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();

        // Aux below 32 bytes makes `parse_drt` fail with InvalidAuxiliaryData; envelope is
        // otherwise aligned for our bridge.
        let tag = TagData::new(
            BRIDGE_V1_SUBPROTOCOL_ID,
            BridgeTxType::DepositRequest as u8,
            vec![0u8; 31],
        )
        .expect("aux must fit SPS-50 size limits");
        let op_return = ParseConfig::new(cfg.magic_bytes)
            .encode_script_buf(&tag.as_ref())
            .expect("SPS-50 tag must encode");
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: op_return,
            }],
        };

        assert!(matches!(
            validate_drt(&tx, &cfg, &operator_table),
            Err(DrtValidationError::Structure(_))
        ));
    }

    #[test]
    fn validate_drt_rejects_invalid_recovery_pubkey() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();

        let mut builder = DrtBuilder::aligned(&operator_table, &cfg);
        // 32 zero bytes are not a valid x-only point.
        builder.recovery_pk_in_aux = [0u8; 32];
        builder.recovery_pk_in_script = [0u8; 32];

        assert!(matches!(
            validate_drt(&builder.build(), &cfg, &operator_table),
            Err(DrtValidationError::InvalidRecoveryPubkey(_))
        ));
    }

    #[test]
    fn validate_drt_rejects_output_value_below_required() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();

        let required = DepositTx::drt_required(cfg.deposit_amount);
        let actual = required - Amount::from_sat(1);
        let mut builder = DrtBuilder::aligned(&operator_table, &cfg);
        builder.output_value = actual;

        let err = validate_drt(&builder.build(), &cfg, &operator_table).unwrap_err();
        match err {
            DrtValidationError::OutputValueBelowRequired {
                actual: got_actual,
                required: got_required,
            } => {
                assert_eq!(got_actual, actual);
                assert_eq!(got_required, required);
            }
            other => panic!("expected OutputValueBelowRequired, got {other:?}"),
        }
    }

    #[test]
    fn validate_drt_rejects_mismatched_recovery_pk_in_script() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();

        let mut builder = DrtBuilder::aligned(&operator_table, &cfg);
        // Aux carries one recovery pk, but the takeback tapscript commits to a different one.
        builder.recovery_pk_in_script = generate_xonly_pubkey().serialize();
        assert_ne!(builder.recovery_pk_in_aux, builder.recovery_pk_in_script);

        assert!(matches!(
            validate_drt(&builder.build(), &cfg, &operator_table),
            Err(DrtValidationError::LockingScriptMismatch)
        ));
    }

    #[test]
    fn validate_drt_rejects_mismatched_internal_key() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();

        let mut builder = DrtBuilder::aligned(&operator_table, &cfg);
        // Pin the output to a P2TR with a non-bridge internal key.
        builder.n_of_n_in_script = generate_xonly_pubkey();

        assert!(matches!(
            validate_drt(&builder.build(), &cfg, &operator_table),
            Err(DrtValidationError::LockingScriptMismatch)
        ));
    }

    #[test]
    fn validate_drt_rejects_mismatched_recovery_delay() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();

        let mut builder = DrtBuilder::aligned(&operator_table, &cfg);
        builder.recovery_delay_in_script = cfg.recovery_delay.wrapping_add(1);

        assert!(matches!(
            validate_drt(&builder.build(), &cfg, &operator_table),
            Err(DrtValidationError::LockingScriptMismatch)
        ));
    }
}
