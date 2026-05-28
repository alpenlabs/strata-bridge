//! Shared test helpers for the orchestrator crate.
//!
//! Crate-agnostic fixtures (operator tables, descriptors, shared constants) are imported from
//! [`strata_bridge_test_utils::bridge_fixtures`]. This module adds orchestrator-specific SM config
//! construction and registry helpers on top.

use std::{num::NonZero, sync::Arc};

use bitcoin::{
    Amount, Network, OutPoint, Transaction, TxIn, TxOut, Txid, absolute,
    hashes::{Hash, sha256},
    relative,
    secp256k1::XOnlyPublicKey,
    transaction,
};
use strata_asm_proto_bridge_v1_txs::{
    BRIDGE_V1_SUBPROTOCOL_ID, constants::BridgeTxType,
    deposit_request::create_deposit_request_locking_script,
};
use strata_bridge_primitives::{
    operator_table::OperatorTable,
    types::{DepositIdx, GraphIdx, OperatorIdx},
};
use strata_bridge_sm::{
    deposit::{config::DepositSMCfg, machine::DepositSM},
    graph::{config::GraphSMCfg, context::GraphSMCtx, machine::GraphSM},
    stake::{
        config::StakeSMCfg,
        context::{MinimumStakeData, StakeSMCtx},
        machine::StakeSM,
        state::StakeState,
    },
};
// Re-export shared bridge fixtures so other test modules in this crate can use them.
pub(crate) use strata_bridge_test_utils::bridge_fixtures::{
    TEST_DEPOSIT_AMOUNT, TEST_MAGIC_BYTES, TEST_OPERATOR_FEE, TEST_POV_IDX, random_p2tr_desc,
    test_operator_table,
};
use strata_bridge_test_utils::{
    bitcoin::generate_xonly_pubkey, bridge_fixtures::TEST_RECOVERY_DELAY, prelude::generate_txid,
};
use strata_bridge_tx_graph::{
    game_graph::ProtocolParams as GameProtocolParams,
    stake_graph::{ProtocolParams as StakeProtocolParams, StakeGraphSummary},
    transactions::{deposit::DepositTx, prelude::DepositData},
};
use strata_l1_txfmt::{MagicBytes, ParseConfig, TagData};
use strata_predicate::PredicateKey;

use crate::sm_registry::{SMConfig, SMRegistry};

/// Number of operators used in orchestrator test fixtures.
pub(crate) const N_TEST_OPERATORS: usize = 3;

/// Operator index of a non-POV operator used in orchestrator test fixtures.
pub(crate) const TEST_NONPOV: OperatorIdx = 1;

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
    let payout_descs = (0..N_TEST_OPERATORS).map(|_| random_p2tr_desc()).collect();

    Arc::new(GraphSMCfg {
        game_graph_params: GameProtocolParams {
            network: Network::Regtest,
            magic_bytes: TEST_MAGIC_BYTES.into(),
            contest_timelock: relative::Height::from_height(10),
            proof_timelock: relative::Height::from_height(5),
            ack_timelock: relative::Height::from_height(10),
            nack_timelock: relative::Height::from_height(5),
            contested_payout_timelock: relative::Height::from_height(15),
            counterproof_n_data: NonZero::new(128).unwrap(),
            deposit_amount: TEST_DEPOSIT_AMOUNT,
            stake_amount: Amount::from_sat(100_000_000),
        },
        admin_pubkey: generate_xonly_pubkey(),
        operator_fee: TEST_OPERATOR_FEE,
        payout_descs,
        bridge_proof_predicate: PredicateKey::always_accept(),
        counterproof_predicate: PredicateKey::always_accept(),
    })
}

/// Creates a test `StakeSMCfg`, mirroring `bridge-sm/stake/tests::TEST_CFG`.
pub(crate) fn test_stake_sm_cfg() -> Arc<StakeSMCfg> {
    Arc::new(StakeSMCfg {
        protocol_params: StakeProtocolParams {
            network: Network::Regtest,
            magic_bytes: TEST_MAGIC_BYTES.into(),
            unstaking_timelock: relative::Height::from_height(144),
            stake_amount: Amount::from_sat(100_000_000),
        },
    })
}

/// Creates a combined `SMConfig` from the test deposit, graph, and stake configs.
pub(crate) fn test_sm_config() -> SMConfig {
    SMConfig {
        deposit: test_deposit_sm_cfg(),
        graph: test_graph_sm_cfg(),
        stake: test_stake_sm_cfg(),
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
    let deposit_request_amount = cfg.deposit_amount() + Amount::from_sat(10_000); // ensure drt output amount is greater than deposit amount
    let dsm = DepositSM::new(
        cfg,
        operator_table.clone(),
        data,
        depositor_pubkey,
        deposit_request_amount,
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

/// Inserts a [`StakeSM`] in the initial [`StakeState::Created`] state for the given operator into
/// the registry.
pub(crate) fn insert_created_stake(
    registry: &mut SMRegistry,
    operator_idx: OperatorIdx,
    operator_table: OperatorTable,
) {
    let ctx = StakeSMCtx::new(operator_idx, operator_table);
    let (ssm, _duty) = StakeSM::new(ctx, INITIAL_BLOCK_HEIGHT);
    registry
        .insert_stake(operator_idx, ssm)
        .expect("test helper must not insert duplicate stake state machine");
}

/// Inserts one [`StakeSM`] per operator in the test operator table, each in the initial
/// [`StakeState::Created`] state.
pub(crate) fn insert_stakes_for_all_operators(
    registry: &mut SMRegistry,
    operator_table: &OperatorTable,
) {
    for op_idx in operator_table.operator_idxs() {
        insert_created_stake(registry, op_idx, operator_table.clone());
    }
}

/// Builds a [`StakeSM`] in [`StakeState::Confirmed`] for the given operator, with deterministic
/// dummy values for stake-graph fields that are not relevant to the test being written.
pub(crate) fn make_confirmed_stake_sm(
    operator_idx: OperatorIdx,
    operator_table: OperatorTable,
    stake_txid: Txid,
) -> StakeSM {
    let stake_data = MinimumStakeData {
        stake_funds: OutPoint::default(),
        unstaking_image: sha256::Hash::all_zeros(),
        unstaking_operator_desc: random_p2tr_desc(),
    };
    let summary = StakeGraphSummary {
        stake: stake_txid,
        unstaking_intent: generate_txid(),
        unstaking: generate_txid(),
    };
    StakeSM {
        context: StakeSMCtx::new(operator_idx, operator_table),
        state: StakeState::Confirmed {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            stake_data,
            summary,
            signatures: Box::new(None),
        },
    }
}

/// Inserts a [`StakeSM`] in [`StakeState::Confirmed`] for `operator_idx` into the registry. The
/// registry must not already contain a stake state machine for that operator — tests building
/// scenarios with confirmed stakes should start from a registry without pre-bootstrapped stakes.
pub(crate) fn insert_confirmed_stake(
    registry: &mut SMRegistry,
    operator_idx: OperatorIdx,
    operator_table: OperatorTable,
    stake_txid: Txid,
) {
    let sm = make_confirmed_stake_sm(operator_idx, operator_table, stake_txid);
    registry
        .insert_stake(operator_idx, sm)
        .expect("test helper must not insert duplicate confirmed stake state machine");
}

/// Creates a pre-populated registry with `n_deposits` deposits, each with `N_TEST_OPERATORS` graph
/// SMs. Stake state machines are intentionally **not** included — tests that exercise stake-gated
/// logic should compose them via [`insert_stakes_for_all_operators`] or
/// [`insert_confirmed_stake`].
pub(crate) fn test_populated_registry(n_deposits: usize) -> SMRegistry {
    let mut registry = test_empty_registry();
    for i in 0..n_deposits {
        insert_deposit_with_graphs(&mut registry, i as DepositIdx);
    }
    registry
}

// ===== DRT fixture =====

/// Configurable builder for synthetic deposit request transactions. Defaults from
/// [`Self::aligned`] produce a structurally valid DRT for the given bridge config and operator
/// set; tests override individual fields to drive each gate in the validator.
pub(crate) struct DrtBuilder {
    pub(crate) magic: MagicBytes,
    pub(crate) subproto_id: u8,
    pub(crate) tx_type: u8,
    /// Recovery pubkey bytes placed in the SPS-50 aux data.
    pub(crate) recovery_pk_in_aux: [u8; 32],
    /// N-of-N internal key used when building the output-1 P2TR script.
    pub(crate) n_of_n_in_script: XOnlyPublicKey,
    /// Recovery pubkey bytes used inside the output-1 takeback tapscript.
    pub(crate) recovery_pk_in_script: [u8; 32],
    /// CSV delay encoded inside the output-1 takeback tapscript.
    pub(crate) recovery_delay_in_script: u16,
    /// Amount placed on output 1.
    pub(crate) output_value: Amount,
    /// Optional destination bytes appended after the 32-byte recovery_pk in aux.
    pub(crate) destination: Vec<u8>,
}

impl DrtBuilder {
    /// Returns a builder whose fields are aligned with a valid DRT for the given operator
    /// table and configuration.
    pub(crate) fn aligned(operator_table: &OperatorTable, cfg: &DepositSMCfg) -> Self {
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
    pub(crate) fn build(&self) -> Transaction {
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
