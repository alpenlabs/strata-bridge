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
    num::NonZero,
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
use strata_bridge_tx_graph::stake_graph::{
    ProtocolParams, SetupParams, StakeData, StakeGraph, StakeGraphSummary,
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

// ┌───────────────────────────────────────────────────────────────────┐
// │                            Operators                              │
// └───────────────────────────────────────────────────────────────────┘

/// Number of operators.
const TEST_N_OPERATORS: usize = 3;
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
/// Stake state machine configuration.
static TEST_CFG: LazyLock<Arc<StakeSMCfg>> = LazyLock::new(|| {
    Arc::new(StakeSMCfg {
        unstaking_timelock: relative::Height::from_height(TEST_UNSTAKING_TIMELOCK as u16), /* cast safety: TEST_GAME_TIMELOCK <= u16::MAX */
    })
});
/// Stake state machine context.
static TEST_CTX: LazyLock<StakeSMCtx> =
    LazyLock::new(|| StakeSMCtx::new(TEST_POV_IDX, TEST_OPERATOR_TABLE.clone()));

// ┌───────────────────────────────────────────────────────────────────┐
// │                          Stake Graph                              │
// └───────────────────────────────────────────────────────────────────┘

/// Relative timelock for the unstaking transaction.
const TEST_UNSTAKING_TIMELOCK: u64 = 100;
/// Stake amount in BTC.
const TEST_STAKE_BTC_AMOUNT: u64 = 1;
/// Game index.
const TEST_GAME_INDEX: NonZero<u32> = NonZero::new(1).expect("1 is not zero");
/// Preimage for the unstaking intent transaction.
const TEST_UNSTAKING_PREIMAGE: [u8; 32] = [0; 32];
/// Operator payout descriptor.
static TEST_UNSTAKING_OPERATOR_DESCRIPTOR: LazyLock<Descriptor> = LazyLock::new(random_p2tr_desc);
/// UTXO that funds the stake transaction.
static TEST_STAKE_FUNDS: LazyLock<OutPoint> = LazyLock::new(OutPoint::null);
/// Data for the stake transaction graph.
static TEST_STAKE_DATA: LazyLock<StakeData> = LazyLock::new(|| {
    StakeData {
        protocol: ProtocolParams {
            game_timelock: relative::Height::from_height(TEST_UNSTAKING_TIMELOCK as u16), /* cast safety: TEST_GAME_TIMELOCK <= u16::MAX */
            stake_amount: Amount::from_int_btc(TEST_STAKE_BTC_AMOUNT),
        },
        setup: SetupParams {
            network: Network::Regtest,
            magic_bytes: TEST_MAGIC_BYTES.into(),
            game_index: TEST_GAME_INDEX,
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
    }
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
static TEST_SIGNING_INFOS: LazyLock<[SigningInfo; StakeGraph::N_MUSIG_INPUTS]> =
    LazyLock::new(|| {
        TEST_GRAPH
            .musig_signing_info()
            .pack()
            .try_into()
            .expect("correct number of transaction inputs")
    });
/// 1 key aggregation context for each Musig transaction input in the stake graph.
static TEST_KEY_AGG_CTXS: LazyLock<[KeyAggContext; StakeGraph::N_MUSIG_INPUTS]> =
    LazyLock::new(|| {
        array::from_fn(|txin_idx| {
            create_agg_ctx(
                TEST_CTX.operator_table().btc_keys(),
                &TEST_SIGNING_INFOS[txin_idx].tweak,
            )
            .expect("must be able to build key aggregation contexts for tests")
        })
    });
/// Maps each operator to their public nonces.
/// There is 1 public nonce for each Musig transaction input in the stake graph.
static TEST_PUB_NONCES_MAP: LazyLock<BTreeMap<u32, [PubNonce; StakeGraph::N_MUSIG_INPUTS]>> =
    LazyLock::new(|| {
        TEST_MUSIG_SIGNERS
            .iter()
            .map(|signer| {
                let nonces = array::from_fn(|txin_idx| {
                    signer.pubnonce(
                        TEST_KEY_AGG_CTXS[txin_idx].aggregated_pubkey(),
                        txin_idx as u64,
                    )
                });
                (signer.operator_idx(), nonces)
            })
            .collect()
    });
/// 1 aggregated nonce for each Musig transaction input in the stake graph.
static TEST_AGG_NONCES: LazyLock<Box<[AggNonce; StakeGraph::N_MUSIG_INPUTS]>> =
    LazyLock::new(|| {
        Box::new(array::from_fn(|txin_idx| {
            AggNonce::sum(
                TEST_PUB_NONCES_MAP
                    .values()
                    .map(|nonces| nonces[txin_idx].clone()),
            )
        }))
    });
/// Maps each operator to their partial signatures.
/// There is 1 partial signature for each Musig transaction input in the stake graph.
static TEST_PARTIAL_SIGS_MAP: LazyLock<
    BTreeMap<u32, [PartialSignature; StakeGraph::N_MUSIG_INPUTS]>,
> = LazyLock::new(|| {
    TEST_MUSIG_SIGNERS
        .iter()
        .map(|signer| {
            let partials = array::from_fn(|txin_idx| {
                signer.sign(
                    &TEST_KEY_AGG_CTXS[txin_idx],
                    txin_idx as u64,
                    &TEST_AGG_NONCES[txin_idx],
                    TEST_SIGNING_INFOS[txin_idx].sighash,
                )
            });
            (signer.operator_idx(), partials)
        })
        .collect()
});
/// 1 final signature for each Musig transaction input in the stake graph.
static TEST_FINAL_SIGS: LazyLock<Box<[Signature; StakeGraph::N_MUSIG_INPUTS]>> =
    LazyLock::new(|| {
        Box::new(array::from_fn(|txin_idx| {
            aggregate_partial_signatures(
                &TEST_KEY_AGG_CTXS[txin_idx],
                &TEST_AGG_NONCES[txin_idx],
                TEST_PARTIAL_SIGS_MAP
                    .values()
                    .map(|operator_partial_sigs| operator_partial_sigs[txin_idx]),
                TEST_SIGNING_INFOS[txin_idx].sighash.as_ref(),
            )
            .expect("test partial signatures must aggregate")
        }))
    });
