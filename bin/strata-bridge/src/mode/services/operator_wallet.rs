//! Provides operator wallet initialization.

use std::{future::Future, sync::Arc, time::Instant};

use anyhow::{Context, anyhow, ensure};
use bdk_bitcoind_rpc::bitcoincore_rpc;
use bitcoin::BlockHash;
use bitcoind_async_client::{Client as BitcoinClient, traits::Reader};
use btc_tracker::event::{BlockEvent, BlockStatus};
use futures::{FutureExt, Stream, StreamExt, future::ready};
use operator_wallet::{
    BlockId, DEFAULT_PERSIST_EVERY_BLOCKS, GeneralCustody, OperatorWallet, OperatorWalletConfig,
    SqliteStore, WalletKind,
    general::fireblocks::{CheckedVault, FireblocksConfig, FireblocksSigner},
    sync::Backend,
};
use secret_service_client::SecretServiceClient;
use secret_service_proto::v2::traits::{SchnorrSigner, SecretService};
use strata_bridge_common::params::Params;
use strata_bridge_db::{fdb::client::FdbClient, traits::BridgeDb};
use strata_bridge_primitives::subscription::Subscription;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::config::Config;

pub(in crate::mode) async fn init_operator_wallet(
    config: &Config,
    params: &Params,
    s2_client: &SecretServiceClient,
    db_client: &FdbClient,
    btc_rpc_client: &BitcoinClient,
) -> anyhow::Result<OperatorWallet<SqliteStore>> {
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

    let reserved_key = s2_client.reserved_wallet_signer().pubkey().await?;
    info!(%reserved_key, "operator wallet reserved key");
    let persist_every_blocks = config
        .operator_wallet
        .persist_every_blocks
        .unwrap_or(DEFAULT_PERSIST_EVERY_BLOCKS);
    let bury_depth = u32::try_from(params.protocol.bury_depth).expect("bury depth fits in u32");
    let operator_wallet_config = OperatorWalletConfig::new(bury_depth, params.network)
        .with_persist_every_blocks(persist_every_blocks);
    debug!(?operator_wallet_config, "operator wallet config");

    // Resolved before the stores are opened: opening creates the files, and a rejected checkpoint
    // must leave none behind.
    let bootstrap_checkpoint = resolve_bootstrap_checkpoint(btc_rpc_client, config, params).await?;

    let data_dir = &config.operator_wallet.data_dir;
    info!(data_dir = %data_dir.display(), "opening operator wallet stores");
    let open_store = |kind| {
        SqliteStore::open_in_dir(data_dir, kind)
            .with_context(|| format!("opening {kind} wallet store"))
    };
    let reserved_store = open_store(WalletKind::Reserved)?;

    let custody = match &config.operator_wallet.fireblocks {
        None => {
            let general_key = s2_client.general_wallet_signer().pubkey().await?;
            info!(%general_key, "operator wallet general key (secret-service custody)");
            GeneralCustody::SecretService {
                general_key,
                store: open_store(WalletKind::General)?,
            }
        }
        Some(fb) => {
            info!(
                vault = %fb.vault_account_id,
                asset = %fb.asset_id,
                "operator wallet general custody: fireblocks"
            );
            let api_secret = std::fs::read(&fb.api_secret_path).map_err(|e| {
                anyhow!(
                    "failed to read Fireblocks API secret at {:?}: {e}",
                    fb.api_secret_path
                )
            })?;
            let fb_config = FireblocksConfig {
                base_url: fb.base_url.clone(),
                api_key: fb.api_key.clone(),
                vault_account_id: fb.vault_account_id.clone(),
                asset_id: fb.asset_id.clone(),
                vault_pubkey: fb.vault_pubkey,
            };
            let signer = FireblocksSigner::new(fb_config, &api_secret)
                .map_err(|e| anyhow!("failed to initialize Fireblocks signer: {e}"))?;
            let vault = CheckedVault::check(signer, open_store(WalletKind::Vault)?)
                .await
                .map_err(|e| anyhow!("Fireblocks startup check failed: {e}"))?;
            GeneralCustody::Fireblocks(vault)
        }
    };

    let wallet = OperatorWallet::load_or_create(
        custody,
        reserved_key,
        operator_wallet_config,
        Backend::BitcoinCore(bitcoin_rpc_client),
        reserved_store,
        bootstrap_checkpoint,
        leased_outpoints,
    )
    .await
    .context("loading operator wallet")?;
    debug!("operator wallet initialized");

    Ok(wallet)
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

/// The block a fresh store is seeded with so that its first sync begins at `first_scanned`.
///
/// A sync only fetches blocks above the seed, so the seed is the parent. The parent of height 1
/// is genesis, which every fresh store already holds.
fn seed_below(first_scanned: u32, parent: BlockHash) -> Option<BlockId> {
    let height = first_scanned.checked_sub(1)?;
    (height > 0).then_some(BlockId {
        height,
        hash: parent,
    })
}

/// Resolves the bootstrap settings into the block that stores created on this start are seeded
/// with: the parent of the configured block, so the configured block is the first one scanned.
///
/// A configured hash is checked against the connected node, so a node following another chain
/// aborts startup instead of seeding wallets from the wrong history. Without a hash the node's
/// own block is taken on trust. Either way a height the node has no block for aborts startup:
/// falling back to genesis would silently cost a full rescan. The settings are checked on every
/// start, but existing stores resume from their own tip and are never reseeded.
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
        }
        _ => {
            warn!(
                height,
                hash = %reported,
                "operator_wallet.bootstrap_height has no bootstrap_block_hash, so this block is \
                 taken from the connected node on trust"
            );
        }
    }

    // The verified block's own header names its parent, so the seed needs no trust of its own.
    let parent = client
        .get_block_header(&reported)
        .await
        .map_err(|e| anyhow!("could not fetch the header of bootstrap block {reported}: {e:?}"))?
        .prev_blockhash;
    Ok(seed_below(height, parent))
}

/// Performs a one-shot sync of the operator wallet against the node.
///
/// Intended to run as a background task at startup so the wallet has a head start before its
/// first on-demand use. A sync failure is logged and swallowed: callers must still sync the wallet
/// before use, so a failed initial sync must not crash the node.
pub(in crate::mode) async fn spawn_initial_operator_wallet_sync(
    wallet: Arc<RwLock<OperatorWallet<SqliteStore>>>,
) {
    info!("starting initial operator wallet sync");
    let start = Instant::now();
    // Bind the result so the write guard (a temporary in this expression) drops here.
    let result = wallet.write().await.sync().await;
    match result {
        Ok(()) => info!(time_spent=?start.elapsed(), "initial operator wallet sync complete"),
        Err(e) => {
            warn!(?e, time_spent=?start.elapsed(), "initial operator wallet sync failed, first use might be slow");
        }
    }
}

/// Syncs the operator wallet once for each new block, for as long as `blocks` yields.
///
/// Selection reads the view of the last sync, so this bounds the age of that view to one block on
/// an active chain. The task takes the exclusive guard for each sync, as any duty does, and it
/// is the only sync that a node with no running duty sees. A failed sync waits for the next block.
pub(in crate::mode) async fn sync_wallet_on_new_blocks(
    wallet: Arc<RwLock<OperatorWallet<SqliteStore>>>,
    blocks: Subscription<BlockEvent>,
) {
    let mined = blocks.filter(|event| ready(event.status == BlockStatus::Mined));
    run_for_each_batch(Box::pin(mined), || async {
        // Bind the result so the write guard (a temporary in this expression) drops here.
        let result = wallet.write().await.sync().await;
        if let Err(e) = result {
            warn!(
                ?e,
                "wallet sync on a new block failed; the next block retries"
            );
        }
    })
    .await;
}

/// Calls `action` once for each batch of items that `items` has ready. A sync reads the whole
/// chain tip, so the replay at startup and a burst of blocks cost one call each.
async fn run_for_each_batch<T, F, Fut>(mut items: impl Stream<Item = T> + Unpin, action: F)
where
    F: Fn() -> Fut,
    Fut: Future<Output = ()>,
{
    while items.next().await.is_some() {
        while let Some(Some(_)) = items.next().now_or_never() {}
        action().await;
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use bitcoin::hashes::Hash;
    use futures::channel::mpsc;

    use super::*;

    /// Items that arrive while an earlier batch runs form one later batch.
    #[tokio::test]
    async fn ready_items_form_one_batch_each() {
        let (sender, receiver) = mpsc::unbounded();
        for item in 0..3 {
            sender.unbounded_send(item).expect("open channel");
        }
        let calls = Cell::new(0);
        run_for_each_batch(receiver, || async {
            calls.set(calls.get() + 1);
            if calls.get() == 1 {
                sender.unbounded_send(3).expect("open channel");
                sender.unbounded_send(4).expect("open channel");
            } else {
                sender.close_channel();
            }
        })
        .await;
        assert_eq!(
            calls.get(),
            2,
            "the three queued items form one batch and the two sent during it form another"
        );
    }

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
    fn the_seed_is_the_parent_of_the_first_scanned_block() {
        assert_eq!(
            seed_below(101, hash(7)),
            Some(BlockId {
                height: 100,
                hash: hash(7)
            })
        );
    }

    #[test]
    fn a_first_scanned_block_right_above_genesis_needs_no_seed() {
        assert_eq!(seed_below(1, hash(7)), None);
    }

    #[test]
    fn a_height_past_the_block_height_range_is_rejected() {
        let too_big = u64::from(u32::MAX) + 1;
        let err = bootstrap_setting(Some(too_big), None).expect_err("not a block height");
        assert!(err.to_string().contains(&too_big.to_string()), "{err}");
    }
}
