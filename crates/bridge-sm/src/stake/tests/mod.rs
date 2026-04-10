//! Unit tests for the Stake State Machine.

mod nag_tick;
mod new_block;
mod preimage_revealed;
mod retry_tick;
mod stake_confirmed;
mod stake_data_received;
mod tx_classifier;
mod unstaking_confirmed;
mod unstaking_nonces_received;
mod unstaking_partials_received;

use std::{
    array,
    collections::BTreeMap,
    sync::{Arc, LazyLock},
};

use bitcoin::{
    Amount, Network, OutPoint,
    hashes::{Hash, sha256},
    relative,
};
use bitcoin_bosd::Descriptor;
use musig2::{AggNonce, KeyAggContext, PartialSignature, PubNonce, aggregate_partial_signatures};
use secp256k1::{Keypair, schnorr::Signature};
use strata_bridge_connectors::SigningInfo;
use strata_bridge_primitives::{
    key_agg::create_agg_ctx, operator_table::OperatorTable, types::P2POperatorPubKey,
};
use strata_bridge_test_utils::{
    bridge_fixtures::{TEST_MAGIC_BYTES, TEST_POV_IDX, random_p2tr_desc},
    prelude::generate_keypair,
};
use strata_bridge_tx_graph::{
    musig_functor::StakeFunctor,
    stake_graph::{ProtocolParams, SetupParams, StakeData, StakeGraph, StakeGraphSummary},
};

use crate::{
    signals::Signal,
    stake::{
        config::StakeSMCfg, context::StakeSMCtx, duties::StakeDuty, errors::SSMError,
        events::StakeEvent, machine::StakeSM, state::StakeState,
    },
    testing::{
        signer::TestMusigSigner,
        transition::{InvalidTransition, Transition, test_invalid_transition, test_transition},
    },
};

// ┌───────────────────────────────────────────────────────────────────┐
// │                       Helper Functions                            │
// └───────────────────────────────────────────────────────────────────┘

/// Creates a [`StakeSM`] in the given state.
fn create_state_machine(state: StakeState) -> StakeSM {
    StakeSM {
        context: TEST_CTX.clone(),
        state,
    }
}

/// Creates a non-POV [`StakeSM`] in the given state.
fn create_nonpov_state_machine(state: StakeState) -> StakeSM {
    StakeSM {
        context: TEST_NONPOV_CTX.clone(),
        state,
    }
}

/// Gets the state from a [`StakeSM`].
const fn get_state(sm: &StakeSM) -> &StakeState {
    sm.state()
}

/// Type alias for [`StakeSM`] transitions.
type StakeTransition = Transition<StakeState, StakeEvent, StakeDuty, Signal>;

/// Type alias for invalid [`StakeSM`] transitions.
type StakeInvalidTransition = InvalidTransition<StakeState, StakeEvent, SSMError>;

/// Test a valid [`StakeSM`] transition with pre-configured test helpers.
fn test_stake_transition(transition: StakeTransition) {
    test_transition::<StakeSM, _, _, _, _, _, _, _>(
        create_state_machine,
        get_state,
        TEST_CFG.clone(),
        transition,
    );
}

/// Test an invalid [`StakeSM`] transition with pre-configured test helpers.
fn test_stake_invalid_transition(invalid: StakeInvalidTransition) {
    test_invalid_transition::<StakeSM, _, _, _, _, _, _>(
        create_state_machine,
        TEST_CFG.clone(),
        invalid,
    );
}

/// Test a valid non-POV [`StakeSM`] transition with pre-configured test helpers.
fn test_nonpov_stake_transition(transition: StakeTransition) {
    test_transition::<StakeSM, _, _, _, _, _, _, _>(
        create_nonpov_state_machine,
        get_state,
        TEST_CFG.clone(),
        transition,
    );
}

// ┌───────────────────────────────────────────────────────────────────┐
// │                            Operators                              │
// └───────────────────────────────────────────────────────────────────┘

/// Number of operators.
const TEST_N_OPERATORS: usize = 3;
/// Operator index representing a non-POV operator in tests.
const TEST_NONPOV_IDX: u32 = 1;
// Compile-time assertion: TEST_NONPOV_IDX must differ from TEST_POV_IDX.
const _: () = assert!(TEST_NONPOV_IDX != TEST_POV_IDX);
/// Operator keypairs.
static TEST_KEYPAIRS: LazyLock<[Keypair; TEST_N_OPERATORS]> =
    LazyLock::new(|| array::from_fn(|_| generate_keypair()));
/// Operator table.
static TEST_OPERATOR_TABLE: LazyLock<OperatorTable> = LazyLock::new(|| {
    let operators = TEST_KEYPAIRS
        .iter()
        .enumerate()
        .map(|(idx, keypair)| {
            let public_key = keypair.public_key();
            let p2p_key = P2POperatorPubKey::from(public_key.serialize().to_vec());

            (idx as u32, p2p_key, public_key)
        })
        .collect();

    OperatorTable::new(operators, |entry| entry.0 == TEST_POV_IDX).expect("operator table is valid")
});
/// Operator table as seen by a non-POV operator tracking the POV operator's stake.
static TEST_NONPOV_OPERATOR_TABLE: LazyLock<OperatorTable> = LazyLock::new(|| {
    let operators = TEST_KEYPAIRS
        .iter()
        .enumerate()
        .map(|(idx, keypair)| {
            let public_key = keypair.public_key();
            let p2p_key = P2POperatorPubKey::from(public_key.serialize().to_vec());

            (idx as u32, p2p_key, public_key)
        })
        .collect();

    OperatorTable::new(operators, |entry| entry.0 == TEST_NONPOV_IDX)
        .expect("operator table is valid")
});
const TEST_NETWORK: Network = Network::Regtest;

/// Stake state machine configuration.
static TEST_CFG: LazyLock<Arc<StakeSMCfg>> = LazyLock::new(|| {
    Arc::new(StakeSMCfg {
        protocol_params: ProtocolParams {
            network: TEST_NETWORK,
            magic_bytes: TEST_MAGIC_BYTES.into(),
            game_timelock: relative::Height::from_height(TEST_UNSTAKING_TIMELOCK as u16), /* cast safety: TEST_UNSTAKING_TIMELOCK <= u16::MAX */
            stake_amount: Amount::from_int_btc(TEST_STAKE_BTC_AMOUNT),
        },
    })
});
/// Stake state machine context.
static TEST_CTX: LazyLock<StakeSMCtx> =
    LazyLock::new(|| StakeSMCtx::new(TEST_POV_IDX, TEST_OPERATOR_TABLE.clone()));
/// Stake state machine context for a non-POV operator tracking the POV operator's stake.
static TEST_NONPOV_CTX: LazyLock<StakeSMCtx> =
    LazyLock::new(|| StakeSMCtx::new(TEST_POV_IDX, TEST_NONPOV_OPERATOR_TABLE.clone()));

// ┌───────────────────────────────────────────────────────────────────┐
// │                          Stake Graph                              │
// └───────────────────────────────────────────────────────────────────┘

/// Relative timelock for the unstaking transaction.
const TEST_UNSTAKING_TIMELOCK: u64 = 100;
/// Stake amount in BTC.
const TEST_STAKE_BTC_AMOUNT: u64 = 1;
/// Preimage for the unstaking intent transaction.
const TEST_UNSTAKING_PREIMAGE: [u8; 32] = [0; 32];
/// Operator payout descriptor.
static TEST_UNSTAKING_OPERATOR_DESCRIPTOR: LazyLock<Descriptor> = LazyLock::new(random_p2tr_desc);
/// UTXO that funds the stake transaction.
static TEST_STAKE_FUNDS: LazyLock<OutPoint> = LazyLock::new(OutPoint::null);
/// Data for the stake transaction graph.
static TEST_STAKE_DATA: LazyLock<StakeData> = LazyLock::new(|| StakeData {
    protocol: TEST_CFG.protocol_params,
    setup: SetupParams {
        operator_index: TEST_POV_IDX,
        n_of_n_pubkey: TEST_CTX
            .operator_table()
            .aggregated_btc_key()
            .x_only_public_key()
            .0,
        unstaking_image: sha256::Hash::hash(&TEST_UNSTAKING_PREIMAGE),
        unstaking_operator_descriptor: TEST_UNSTAKING_OPERATOR_DESCRIPTOR.clone(),
        stake_funds: *TEST_STAKE_FUNDS,
    },
});
/// Stake transaction graph.
static TEST_GRAPH: LazyLock<StakeGraph> =
    LazyLock::new(|| StakeGraph::new(TEST_STAKE_DATA.clone()));
/// Stake transaction graph summary.
static TEST_GRAPH_SUMMARY: LazyLock<StakeGraphSummary> = LazyLock::new(|| TEST_GRAPH.summarize());
/// Block height of the stake transaction.
const STAKE_HEIGHT: u64 = 100;
/// Block height of the unstaking intent transaction.
const UNSTAKING_INTENT_HEIGHT: u64 = 200;

// ┌───────────────────────────────────────────────────────────────────┐
// │                             Musig2                                │
// └───────────────────────────────────────────────────────────────────┘

/// 1 Musig signer for each operator.
static TEST_MUSIG_SIGNERS: LazyLock<[TestMusigSigner; TEST_N_OPERATORS]> = LazyLock::new(|| {
    array::from_fn(|operator_idx| {
        TestMusigSigner::new(
            operator_idx as u32,
            TEST_KEYPAIRS[operator_idx].secret_key(),
        )
    })
});
/// 1 signing info for each Musig transaction input in the stake graph.
static TEST_SIGNING_INFOS: LazyLock<StakeFunctor<SigningInfo>> =
    LazyLock::new(|| TEST_GRAPH.musig_signing_info());
/// 1 key aggregation context for each Musig transaction input in the stake graph.
static TEST_KEY_AGG_CTXS: LazyLock<StakeFunctor<KeyAggContext>> = LazyLock::new(|| {
    TEST_SIGNING_INFOS.map(|info| {
        create_agg_ctx(TEST_CTX.operator_table().btc_keys(), &info.tweak)
            .expect("must be able to build key aggregation contexts for tests")
    })
});
/// Maps each operator to their public nonces.
/// There is 1 public nonce for each Musig transaction input in the stake graph.
static TEST_PUB_NONCES_MAP: LazyLock<BTreeMap<u32, StakeFunctor<PubNonce>>> = LazyLock::new(|| {
    TEST_MUSIG_SIGNERS
        .iter()
        .map(|signer| {
            let nonces = TEST_KEY_AGG_CTXS
                .clone()
                .enumerate()
                .map(|(txin_idx, ctx)| signer.pubnonce(ctx.aggregated_pubkey(), txin_idx as u64));
            (signer.operator_idx(), nonces)
        })
        .collect()
});
/// 1 aggregated nonce for each Musig transaction input in the stake graph.
static TEST_AGG_NONCES: LazyLock<StakeFunctor<AggNonce>> = LazyLock::new(|| {
    StakeFunctor::sequence_functor(TEST_PUB_NONCES_MAP.values().map(StakeFunctor::as_ref))
        .map(AggNonce::sum)
});
/// Maps each operator to their partial signatures.
/// There is 1 partial signature for each Musig transaction input in the stake graph.
static TEST_PARTIAL_SIGS_MAP: LazyLock<BTreeMap<u32, StakeFunctor<PartialSignature>>> =
    LazyLock::new(|| {
        TEST_MUSIG_SIGNERS
            .iter()
            .map(|signer| {
                let partials = StakeFunctor::zip3(
                    TEST_KEY_AGG_CTXS.as_ref(),
                    TEST_AGG_NONCES.as_ref(),
                    TEST_SIGNING_INFOS.as_ref(),
                )
                .enumerate()
                .map(|(txin_idx, (ctx, agg_nonce, info))| {
                    signer.sign(ctx, txin_idx as u64, agg_nonce, info.sighash)
                });
                (signer.operator_idx(), partials)
            })
            .collect()
    });
/// 1 final signature for each Musig transaction input in the stake graph.
static TEST_FINAL_SIGS: LazyLock<StakeFunctor<Signature>> = LazyLock::new(|| {
    let partials = StakeFunctor::sequence_functor(TEST_PARTIAL_SIGS_MAP.values().cloned());
    StakeFunctor::zip_with_4(
        |ctx, agg_nonce, partials, info| {
            aggregate_partial_signatures(ctx, agg_nonce, partials, info.sighash.as_ref())
                .expect("test partial signatures must aggregate")
        },
        TEST_KEY_AGG_CTXS.as_ref(),
        TEST_AGG_NONCES.as_ref(),
        partials,
        TEST_SIGNING_INFOS.as_ref(),
    )
});
