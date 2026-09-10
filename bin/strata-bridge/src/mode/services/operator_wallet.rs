//! Provides operator wallet initialization.

use std::{num::NonZero, sync::Arc, time::Instant};

use anyhow::{Context, anyhow, ensure};
use bdk_bitcoind_rpc::bitcoincore_rpc;
use bitcoin::{
    Amount, BlockHash, XOnlyPublicKey,
    hashes::{Hash, sha256},
    relative,
};
use bitcoind_async_client::{Client as BitcoinClient, traits::Reader};
use operator_wallet::{
    BlockId, DEFAULT_PERSIST_EVERY_BLOCKS, NativeGeneralWallet, OperatorWallet,
    OperatorWalletConfig, SqliteStore, WalletKind, sync::Backend,
};
use secret_service_client::SecretServiceClient;
use secret_service_proto::v2::traits::{SchnorrSigner, SecretService};
use strata_bridge_common::params::Params;
use strata_bridge_connectors::prelude::{ClaimContestConnector, ClaimPayoutConnector};
use strata_bridge_db::{fdb::client::FdbClient, traits::BridgeDb};
use strata_bridge_exec::output_handles::NativeWallet;
use strata_bridge_primitives::constants::SEGWIT_MIN_AMOUNT;
use strata_bridge_tx_graph::{fee, transactions::prelude::ClaimTx};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::config::Config;

/// Result of [`init_operator_wallet`] — the constructed wallet plus the per-UTXO
/// denomination of the claim-funding pool. The latter is no longer stored on
/// `OperatorWalletConfig` (the composer is now agnostic of caller denominations); the
/// orchestrator forwards it into `strata_bridge_exec::config::ExecutionConfig` so duty
/// executors can reference the pool by value.
pub(in crate::mode) struct InitializedOperatorWallet {
    /// The composed operator wallet, ready to lease + sign against.
    pub wallet: NativeWallet,
    /// Per-UTXO denomination of the claim-funding pool. The composer is denomination-
    /// agnostic; this value is propagated into `strata_bridge_exec::config::ExecutionConfig`
    /// so duty executors can reference the pool by value.
    pub claim_funding_utxo_value: Amount,
}

pub(in crate::mode) async fn init_operator_wallet(
    config: &Config,
    params: &Params,
    s2_client: &SecretServiceClient,
    db_client: &FdbClient,
    btc_rpc_client: &BitcoinClient,
) -> anyhow::Result<InitializedOperatorWallet> {
    info!("fetching leased utxos from database");
    let leased_outpoints = db_client
        .get_all_funds()
        .await
        .map_err(|e| anyhow!("error while fetching leased outpoints from FDB: {e:?}"))?
        .iter()
        .copied()
        .collect();

    let auth = bitcoincore_rpc::Auth::UserPass(
        config.btc_client.user.to_string(),
        config.btc_client.pass.to_string(),
    );
    let bitcoin_rpc_client = Arc::new(
        bitcoincore_rpc::Client::new(config.btc_client.url.as_str(), auth)
            .expect("should be able to create bitcoin client"),
    );
    debug!(?bitcoin_rpc_client, "bitcoin rpc client");

    let general_key = s2_client.general_wallet_signer().pubkey().await?;
    info!(%general_key, "operator wallet general key");
    let reserved_key = s2_client.reserved_wallet_signer().pubkey().await?;
    info!(%reserved_key, "operator wallet reserved key");
    let own_musig2_key = s2_client.musig2_signer().pubkey().await?;
    let claim_funding_utxo_value = compute_claim_funding_utxo_value(params, own_musig2_key);
    let persist_every_blocks = config
        .operator_wallet
        .persist_every_blocks
        .unwrap_or(DEFAULT_PERSIST_EVERY_BLOCKS);
    let operator_wallet_config = OperatorWalletConfig::new(SEGWIT_MIN_AMOUNT, params.network)
        .with_persist_every_blocks(persist_every_blocks);
    debug!(?operator_wallet_config, %claim_funding_utxo_value, "operator wallet config");

    let general_sync_backend = Backend::BitcoinCore(bitcoin_rpc_client.clone());
    let reserved_sync_backend = Backend::BitcoinCore(bitcoin_rpc_client.clone());
    debug!(?general_sync_backend, "operator wallet sync backend");

    let data_dir = &config.operator_wallet.data_dir;
    info!(data_dir = %data_dir.display(), "opening operator wallet stores");
    let open_store = |kind| {
        SqliteStore::open_in_dir(data_dir, kind)
            .with_context(|| format!("opening {kind} wallet store"))
    };
    let general_store = open_store(WalletKind::General)?;
    let reserved_store = open_store(WalletKind::Reserved)?;

    let bootstrap_checkpoint = resolve_bootstrap_checkpoint(btc_rpc_client, config, params).await?;
    let general_wallet = NativeGeneralWallet::load_or_create(
        general_key,
        &operator_wallet_config,
        general_sync_backend,
        general_store,
        bootstrap_checkpoint,
    )
    .await
    .context("loading general wallet")?;
    let wallet = OperatorWallet::load_or_create(
        general_wallet,
        reserved_key,
        operator_wallet_config,
        reserved_sync_backend,
        reserved_store,
        bootstrap_checkpoint,
        leased_outpoints,
    )
    .await
    .context("loading reserved wallet")?;
    debug!("operator wallet initialized");

    Ok(InitializedOperatorWallet {
        wallet,
        claim_funding_utxo_value,
    })
}

/// What the `operator_wallet.bootstrap_*` settings ask of a store created on this start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BootstrapSetting {
    /// No checkpoint: scan from the network's genesis block.
    Genesis,
    /// Start at this height, trusting whichever block the node has there.
    UnverifiedHeight(u32),
    /// Start at this block, and refuse to start unless the node agrees it is the one.
    Checkpoint(BlockId),
}

/// Reads the pair of `operator_wallet.bootstrap_*` settings.
///
/// A height of `0`, like an unset height, means genesis. A hash without a height, or with height
/// `0`, is a contradiction rather than a default, so it is rejected instead of ignored.
fn bootstrap_setting(
    height: Option<u64>,
    block_hash: Option<BlockHash>,
) -> anyhow::Result<BootstrapSetting> {
    let height = match height {
        None | Some(0) => {
            ensure!(
                block_hash.is_none(),
                "operator_wallet.bootstrap_block_hash is set without a bootstrap_height above zero"
            );
            return Ok(BootstrapSetting::Genesis);
        }
        Some(height) => u32::try_from(height).map_err(|_| {
            anyhow!("operator_wallet.bootstrap_height {height} is not a block height")
        })?,
    };
    Ok(match block_hash {
        Some(hash) => BootstrapSetting::Checkpoint(BlockId { height, hash }),
        None => BootstrapSetting::UnverifiedHeight(height),
    })
}

/// Resolves the bootstrap settings into the checkpoint that stores created on this start begin
/// scanning from.
///
/// A configured hash is checked against the connected node, so a node following another chain
/// aborts startup instead of seeding wallets from the wrong history. Without a hash the node's
/// own block is taken on trust. Either way a height the node has no block for aborts startup:
/// falling back to genesis would silently cost a full rescan. Existing stores resume from their
/// own tip and never consult this.
async fn resolve_bootstrap_checkpoint(
    client: &BitcoinClient,
    config: &Config,
    params: &Params,
) -> anyhow::Result<Option<BlockId>> {
    let wallet = &config.operator_wallet;
    let setting = bootstrap_setting(wallet.bootstrap_height, wallet.bootstrap_block_hash)?;
    let height = match setting {
        BootstrapSetting::Genesis => {
            info!("wallet stores created on this start will scan from bitcoin genesis");
            return Ok(None);
        }
        BootstrapSetting::UnverifiedHeight(height)
        | BootstrapSetting::Checkpoint(BlockId { height, .. }) => height,
    };
    if u64::from(height) > params.genesis_height {
        warn!(
            height,
            genesis_height = params.genesis_height,
            "operator_wallet.bootstrap_height is above bridge genesis; wallet funds received \
             below it stay invisible"
        );
    }

    let reported = client
        .get_block_hash(u64::from(height))
        .await
        .map_err(|e| {
            anyhow!("could not fetch the block at operator_wallet.bootstrap_height {height}: {e:?}")
        })?;
    match setting {
        BootstrapSetting::Checkpoint(checkpoint) => {
            ensure!(
                reported == checkpoint.hash,
                "operator_wallet.bootstrap_block_hash {} is not the block at height {height}: \
                 the connected node reports {reported}. Check the pair against an independent \
                 source; the node may be following another chain.",
                checkpoint.hash
            );
            info!(height, hash = %reported, "verified bootstrap checkpoint against the connected node");
            Ok(Some(checkpoint))
        }
        _ => {
            warn!(
                height,
                hash = %reported,
                "operator_wallet.bootstrap_height has no bootstrap_block_hash, so this block is \
                 taken from the connected node on trust"
            );
            Ok(Some(BlockId {
                height,
                hash: reported,
            }))
        }
    }
}

/// Performs a one-shot sync of the operator wallet against its backend.
///
/// Intended to run as a background task at startup so the wallet has a head start before its
/// first on-demand use. A sync failure is logged and swallowed: callers must still sync the wallet
/// before use, so a failed initial sync must not crash the node.
pub(in crate::mode) async fn spawn_initial_operator_wallet_sync(wallet: Arc<RwLock<NativeWallet>>) {
    info!("starting initial operator wallet sync");
    let start = Instant::now();
    match wallet.write().await.sync().await {
        Ok(()) => info!(time_spent=?start.elapsed(), "initial operator wallet sync complete"),
        Err(e) => {
            warn!(?e, time_spent=?start.elapsed(), "initial operator wallet sync failed, first use might be slow")
        }
    }
}

/// Computes the per-UTXO denomination for the claim-funding pool. Each claim transaction
/// consumes one UTXO of this size from the reserved wallet, so the value is derived from
/// the connectors that the claim tx must pay for (which depend on the watchtower set size).
///
/// Not a constant since it depends on the number of watchtowers allowed to contest a claim.
fn compute_claim_funding_utxo_value(params: &Params, own_musig2_key: XOnlyPublicKey) -> Amount {
    // Must match the value used in `orchestrator.rs::COUNTERPROOF_N_DATA`. Hardcoded here too
    // because `Params` does not currently expose it.
    const COUNTERPROOF_N_DATA: NonZero<usize> =
        NonZero::new(128 + 4).expect("counterproof_n_data must be non-zero");

    let network = params.network;

    // The consensus-validity of the following two values do not affect the calculation of the
    // funding amount and so have been set to dummy values instead of hooking this up with other
    // more complicated services to obtain proper values.
    let n_of_n_key = XOnlyPublicKey::from_slice(&[1u8; 32]).expect("must be a valid x-only pubkey");
    let unstaking_image =
        sha256::Hash::from_slice(&[0u8; 32]).expect("must be a valid sha256 hash");

    // NOTE: (@Rajil1213)  musig2 keys are the watchtower keys for the time being until we separate
    // the sets. Exclude the owner — graph construction in `bridge-sm` excludes the owner from
    // watchtowers (see `GraphContext::watchtower_pubkeys`), so the funding amount must too.
    let watchtower_keys: Vec<_> = params
        .keys
        .covenant
        .iter()
        .map(|c| c.musig2)
        .filter(|k| *k != own_musig2_key)
        .collect();
    // cast safety: covenant.len() is bounded by the number of operators, much smaller than u32::MAX
    let n_watchtowers = watchtower_keys.len() as u32;
    let contest_timelock = relative::Height::from_height(params.protocol.contest_timelock);

    let claim_contest_connector = ClaimContestConnector::new(
        network,
        n_of_n_key,
        watchtower_keys,
        contest_timelock,
        fee::claim_contest_surcharge(n_watchtowers, COUNTERPROOF_N_DATA),
    );

    let claim_payout_connector = ClaimPayoutConnector::new(
        network,
        n_of_n_key,
        params.keys.admin.pubkeys.clone(),
        params.keys.admin.threshold,
        unstaking_image,
    );

    ClaimTx::claim_funds_required(&claim_contest_connector, &claim_payout_connector)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> BlockHash {
        BlockHash::from_byte_array([byte; 32])
    }

    #[test]
    fn no_height_and_no_hash_mean_genesis() {
        assert_eq!(
            bootstrap_setting(None, None).expect("unset is valid"),
            BootstrapSetting::Genesis
        );
        assert_eq!(
            bootstrap_setting(Some(0), None).expect("zero is valid"),
            BootstrapSetting::Genesis
        );
    }

    #[test]
    fn a_height_without_a_hash_is_taken_on_trust() {
        assert_eq!(
            bootstrap_setting(Some(101), None).expect("valid height"),
            BootstrapSetting::UnverifiedHeight(101)
        );
    }

    #[test]
    fn a_height_and_a_hash_make_a_checkpoint() {
        assert_eq!(
            bootstrap_setting(Some(101), Some(hash(7))).expect("valid pair"),
            BootstrapSetting::Checkpoint(BlockId {
                height: 101,
                hash: hash(7)
            })
        );
    }

    #[test]
    fn a_hash_without_a_height_is_rejected() {
        for height in [None, Some(0)] {
            let err = bootstrap_setting(height, Some(hash(7))).expect_err("hash needs a height");
            assert!(
                err.to_string().contains("without a bootstrap_height"),
                "{err}"
            );
        }
    }

    #[test]
    fn a_height_past_the_block_height_range_is_rejected() {
        let too_big = u64::from(u32::MAX) + 1;
        let err = bootstrap_setting(Some(too_big), None).expect_err("not a block height");
        assert!(err.to_string().contains(&too_big.to_string()), "{err}");
    }
}
