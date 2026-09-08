//! Per-UTXO denomination for the claim-funding pool, computed on demand from the current
//! protocol state instead of being snapshotted onto [`ExecutionConfig`] at startup.
//!
//! Each claim transaction consumes one UTXO of this size from the reserved wallet, so the value
//! is derived from the connectors the claim tx must pay for — which depend on the watchtower
//! set size. That set will change at runtime once operator entry/exit lands, and a value frozen
//! at startup would then go stale: refills after the change would deposit UTXOs of the wrong
//! size and silently fail to fund a claim later.
//!
//! To be precise about what this buys *today*: [`ExecutionConfig::watchtower_musig2_keys`] is
//! itself still a startup snapshot, so per-duty recomputation currently always yields the same
//! value. The point is structural — when entry/exit lands, only that one field needs to swap to
//! a live handle and every duty picks up the current denomination with no further plumbing.
//!
//! The wallet API (`reserve_utxo_with_value` / `reserved_utxos_with_value` /
//! `create_reserved_utxos`) is denomination-agnostic — it takes the value as a parameter — so
//! the plumbing change is entirely on this side.

use bitcoin::{Amount, XOnlyPublicKey, hashes::Hash, secp256k1::hashes::sha256};
use strata_bridge_connectors::prelude::{ClaimContestConnector, ClaimPayoutConnector};
use strata_bridge_tx_graph::{fee, transactions::prelude::ClaimTx};

use crate::config::ExecutionConfig;

/// Computes the per-UTXO denomination for the claim-funding pool from the live inputs on `cfg`.
///
/// Reads the current watchtower set from [`ExecutionConfig::watchtower_musig2_keys`] (which
/// the orchestrator populates from `params.keys.covenant`, excluding the operator's own key),
/// the protocol-static inputs from `cfg.graph_sm_cfg.game_graph_params`, and the admin
/// multisig from `cfg.graph_sm_cfg.admin`. The `n_of_n_key` and `unstaking_image` plumbed into
/// the connectors here are dummies: they affect
/// the connectors' consensus validity, not the amount [`ClaimTx::claim_funds_required`]
/// reports, so wiring up the real values would be churn for no value.
pub fn utxo_value(cfg: &ExecutionConfig) -> Amount {
    let game_params = &cfg.graph_sm_cfg.game_graph_params;

    let n_of_n_key = XOnlyPublicKey::from_slice(&[1u8; 32]).expect("must be a valid x-only pubkey");
    let unstaking_image =
        sha256::Hash::from_slice(&[0u8; 32]).expect("must be a valid sha256 hash");

    let watchtower_keys: Vec<XOnlyPublicKey> = cfg.watchtower_musig2_keys.as_ref().clone();
    // cast safety: watchtower set is bounded by the operator count, which is way under u32::MAX.
    let n_watchtowers = watchtower_keys.len() as u32;

    let claim_contest_connector = ClaimContestConnector::new(
        game_params.network,
        n_of_n_key,
        watchtower_keys,
        game_params.contest_timelock,
        fee::claim_contest_surcharge(n_watchtowers, game_params.counterproof_n_data),
    );

    let claim_payout_connector = ClaimPayoutConnector::new(
        game_params.network,
        n_of_n_key,
        cfg.graph_sm_cfg.admin.pubkeys.clone(),
        cfg.graph_sm_cfg.admin.threshold,
        unstaking_image,
    );

    ClaimTx::claim_funds_required(&claim_contest_connector, &claim_payout_connector)
}
