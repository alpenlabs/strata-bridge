//! Shared MuSig2 test utilities for building nonces, key aggregation contexts, and partial
//! signatures.

use std::collections::BTreeMap;

use musig2::{AggNonce, KeyAggContext, PartialSignature, PubNonce};
use strata_bridge_connectors2::SigningInfo;
use strata_bridge_primitives::{key_agg::create_agg_ctx, types::OperatorIdx};

use super::{test_graph_sm_ctx, test_operator_signers};
use crate::testing::signer::TestMusigSigner;

/// Holds the crypto artifacts needed for partial signature tests.
pub(super) struct NonceContext {
    pub signing_infos: Vec<SigningInfo>,
    pub signers: Vec<TestMusigSigner>,
    pub key_agg_ctxs: Vec<KeyAggContext>,
    pub pubnonces: BTreeMap<OperatorIdx, Vec<PubNonce>>,
    pub agg_nonces: Vec<AggNonce>,
}

/// Builds a [`NonceContext`] from signing infos, deriving all crypto artifacts.
pub(super) fn build_nonce_context(signing_infos: Vec<SigningInfo>) -> NonceContext {
    let signers = test_operator_signers(test_graph_sm_ctx().operator_table().cardinality());
    let key_agg_ctxs = build_key_agg_ctxs(&signing_infos);
    let pubnonces = build_pubnonces(&signers, &key_agg_ctxs);
    let agg_nonces = build_agg_nonces(&pubnonces, signing_infos.len());

    NonceContext {
        signing_infos,
        signers,
        key_agg_ctxs,
        pubnonces,
        agg_nonces,
    }
}

/// Builds key aggregation contexts from signing infos using the test operator table.
pub(super) fn build_key_agg_ctxs(signing_infos: &[SigningInfo]) -> Vec<KeyAggContext> {
    let btc_keys: Vec<_> = test_graph_sm_ctx()
        .operator_table()
        .btc_keys()
        .into_iter()
        .collect();
    signing_infos
        .iter()
        .map(|info| {
            create_agg_ctx(btc_keys.iter().copied(), &info.tweak)
                .expect("must be able to create key aggregation context")
        })
        .collect()
}

/// Builds per-operator public nonces from signers and key aggregation contexts.
pub(super) fn build_pubnonces(
    signers: &[TestMusigSigner],
    key_agg_ctxs: &[KeyAggContext],
) -> BTreeMap<OperatorIdx, Vec<PubNonce>> {
    let agg_pubkeys: Vec<_> = key_agg_ctxs
        .iter()
        .map(|ctx| ctx.aggregated_pubkey())
        .collect();

    signers
        .iter()
        .map(|signer| {
            let nonces = agg_pubkeys
                .iter()
                .enumerate()
                .map(|(idx, agg_pubkey)| signer.pubnonce(*agg_pubkey, idx as u64))
                .collect();
            (signer.operator_idx(), nonces)
        })
        .collect()
}

/// Aggregates public nonces into a single `AggNonce` per signing session.
pub(super) fn build_agg_nonces(
    pubnonces: &BTreeMap<OperatorIdx, Vec<PubNonce>>,
    nonce_count: usize,
) -> Vec<AggNonce> {
    (0..nonce_count)
        .map(|nonce_idx| AggNonce::sum(pubnonces.values().map(|nonces| nonces[nonce_idx].clone())))
        .collect()
}

/// Builds per-operator partial signatures using the provided crypto context.
pub(super) fn build_partial_signatures(
    signers: &[TestMusigSigner],
    key_agg_ctxs: &[KeyAggContext],
    agg_nonces: &[AggNonce],
    signing_infos: &[SigningInfo],
    nonce_offset: u64,
) -> BTreeMap<OperatorIdx, Vec<PartialSignature>> {
    signers
        .iter()
        .map(|signer| {
            let sigs = signing_infos
                .iter()
                .enumerate()
                .map(|(idx, info)| {
                    let nonce_counter = idx as u64 + nonce_offset;
                    signer.sign(
                        &key_agg_ctxs[idx],
                        nonce_counter,
                        &agg_nonces[idx],
                        info.sighash,
                    )
                })
                .collect();
            (signer.operator_idx(), sigs)
        })
        .collect()
}
