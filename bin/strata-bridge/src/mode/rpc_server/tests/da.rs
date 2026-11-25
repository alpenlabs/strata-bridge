use std::collections::BTreeMap;

use bitcoin::{
    Amount, Network, OutPoint,
    hashes::{Hash, sha256},
    relative,
    secp256k1::schnorr,
};
use strata_bridge_primitives::types::OperatorIdx;
use strata_bridge_sm::stake::{
    config::StakeSMCfg,
    context::{MinimumStakeData, StakeSMCtx},
    state::StakeState,
};
use strata_bridge_test_utils::{
    bridge_fixtures::{TEST_MAGIC_BYTES, TEST_POV_IDX, random_p2tr_desc, test_operator_table},
    musig2::generate_agg_nonce,
    prelude::generate_txid,
};
use strata_bridge_tx_graph::{
    musig_functor::StakeFunctor,
    stake_graph::{ProtocolParams, StakeGraphSummary},
};

use crate::mode::rpc_server::da::{stake_aggregate_signatures_response, stake_data_response};

const OPERATOR_IDX: OperatorIdx = 1;

fn test_stake_ctx() -> StakeSMCtx {
    StakeSMCtx::new(OPERATOR_IDX, test_operator_table(3, TEST_POV_IDX))
}

fn test_stake_cfg() -> StakeSMCfg {
    StakeSMCfg {
        protocol_params: ProtocolParams {
            network: Network::Regtest,
            magic_bytes: TEST_MAGIC_BYTES.into(),
            unstaking_timelock: relative::Height::from_height(10),
            stake_amount: Amount::from_sat(20_000),
        },
    }
}

fn test_minimum_stake_data() -> MinimumStakeData {
    MinimumStakeData {
        stake_funds: OutPoint::new(generate_txid(), 0),
        unstaking_image: sha256::Hash::hash(b"test-unstaking-preimage"),
        unstaking_operator_desc: random_p2tr_desc(),
    }
}

fn test_stake_summary() -> StakeGraphSummary {
    StakeGraphSummary {
        stake: generate_txid(),
        unstaking_intent: generate_txid(),
        unstaking: generate_txid(),
    }
}

fn test_stake_signatures() -> StakeFunctor<schnorr::Signature> {
    StakeFunctor {
        unstaking_intent: [schnorr::Signature::from_slice(&[0x0a; 64]).expect("valid signature")],
        unstaking: [
            schnorr::Signature::from_slice(&[0x0b; 64]).expect("valid signature"),
            schnorr::Signature::from_slice(&[0x0c; 64]).expect("valid signature"),
        ],
    }
}

#[test]
fn stake_data_response_returns_stake_data_after_generation() {
    let stake_ctx = test_stake_ctx();
    let stake_cfg = test_stake_cfg();
    let stake_data = test_minimum_stake_data();
    let expected_setup = stake_data.expand(stake_cfg, &stake_ctx).setup;
    let state = StakeState::StakeGraphGenerated {
        last_block_height: 100,
        stake_data,
        summary: test_stake_summary(),
        pub_nonces: BTreeMap::new(),
    };

    let response =
        stake_data_response(&stake_ctx, &state, &stake_cfg).expect("stake data should be returned");

    assert_eq!(response.context, stake_ctx);
    assert_eq!(response.protocol, stake_cfg.protocol_params);
    assert_eq!(response.setup, expected_setup);
}

#[test]
fn stake_data_response_returns_none_before_stake_data_arrives() {
    let state = StakeState::Created {
        last_block_height: 100,
    };

    let response = stake_data_response(&test_stake_ctx(), &state, &test_stake_cfg());

    assert!(response.is_none());
}

#[test]
fn stake_aggregate_signatures_response_returns_packed_signatures() {
    let signatures = test_stake_signatures();
    let expected_signatures = signatures.pack().to_vec();
    let agg_nonces = StakeFunctor {
        unstaking_intent: [generate_agg_nonce()],
        unstaking: [generate_agg_nonce(), generate_agg_nonce()],
    };
    let state = StakeState::UnstakingSigned {
        last_block_height: 100,
        stake_data: test_minimum_stake_data(),
        summary: test_stake_summary(),
        agg_nonces: agg_nonces.boxed(),
        signatures: Box::new(signatures),
    };

    let response = stake_aggregate_signatures_response(OPERATOR_IDX, &state)
        .expect("stake signatures should be returned");

    assert_eq!(response.operator_idx, OPERATOR_IDX);
    assert_eq!(response.signatures, expected_signatures);
}

#[test]
fn stake_aggregate_signatures_response_returns_none_before_signing() {
    let state = StakeState::StakeGraphGenerated {
        last_block_height: 100,
        stake_data: test_minimum_stake_data(),
        summary: test_stake_summary(),
        pub_nonces: BTreeMap::new(),
    };

    let response = stake_aggregate_signatures_response(OPERATOR_IDX, &state);

    assert!(response.is_none());
}
