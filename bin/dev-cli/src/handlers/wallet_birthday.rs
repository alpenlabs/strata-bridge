//! Computes the operator wallet bootstrap checkpoint from the node's UTXO set.
//!
//! A wallet store created on a node start scans from `operator_wallet.bootstrap_height`, so that
//! height must be at or below the block holding the oldest output either wallet still has unspent:
//! the general wallet and the reserved (claim-funding) wallet. The node only ever reads unspent
//! outputs, so the UTXO set is the complete answer and one `scantxoutset` over both addresses
//! finds it.
//!
//! The reserved wallet matters as much as the general one: a checkpoint above its outputs makes
//! the node treat the claim-funding pool as spent and fund it again from the general wallet.

use std::time::Duration;

use anyhow::{anyhow, ensure, Context};
use bitcoin::{Amount, BlockHash, Script};
use bitcoincore_rpc::{
    json::{ScanTxOutRequest, Utxo},
    RpcApi,
};
use tracing::{info, warn};

use crate::{cli::WalletBirthdayArgs, handlers::rpc};

const EXPLORER_TIMEOUT: Duration = Duration::from_secs(30);

/// Prints the `[operator_wallet]` checkpoint for the two wallet addresses, or checks a configured
/// one.
pub(crate) async fn handle_wallet_birthday(args: WalletBirthdayArgs) -> anyhow::Result<()> {
    // A full UTXO-set scan runs for minutes on mainnet, longer than the transport's 15 s default.
    let btc_client = rpc::get_btc_client_with_timeout(
        &args.btc_args.url,
        args.btc_args.user,
        args.btc_args.pass,
        Duration::from_secs(args.rpc_timeout),
    )?;

    let info = btc_client.get_blockchain_info().map_err(|e| {
        anyhow!(
            "unable to reach bitcoin node at {}: {}",
            args.btc_args.url,
            e
        )
    })?;
    ensure!(
        !info.initial_block_download,
        "the node is in initial block download ({:.2}% verified), so its UTXO set is incomplete \
         and the birthday would come out too high; let it finish syncing first (on an idle \
         regtest, mine a block)",
        info.verification_progress * 100.0
    );

    let general = args
        .general_address
        .require_network(info.chain)
        .with_context(|| format!("--general-address is not a {} address", info.chain))?;
    let reserved = args
        .reserved_address
        .require_network(info.chain)
        .with_context(|| format!("--reserved-address is not a {} address", info.chain))?;
    ensure!(
        general != reserved,
        "--general-address and --reserved-address are the same address"
    );

    info!(
        chain = %info.chain,
        tip = info.blocks,
        %general,
        %reserved,
        rpc_timeout_secs = args.rpc_timeout,
        "scanning the UTXO set for both wallet addresses; this takes minutes on mainnet"
    );
    let scan = btc_client
        .scan_tx_out_set_blocking(&[
            ScanTxOutRequest::Single(format!("addr({general})")),
            ScanTxOutRequest::Single(format!("addr({reserved})")),
        ])
        .map_err(|e| {
            anyhow!(
                "scantxoutset failed: {e}. If the node reports a scan already in progress, run \
                 `bitcoin-cli scantxoutset abort` and retry"
            )
        })?;
    ensure!(
        scan.success.unwrap_or(false),
        "scantxoutset did not complete; it may have been aborted"
    );
    let tip = scan
        .height
        .context("scantxoutset returned no UTXO-set height")?;

    for (wallet, address) in [("general", &general), ("reserved", &reserved)] {
        let summary = summarize(&scan.unspents, &address.script_pubkey());
        info!(
            wallet,
            %address,
            utxos = summary.count,
            oldest_height = ?summary.oldest,
            total = %summary.total,
            "scan result"
        );
    }

    // One scan covers both addresses, so the birthday is the minimum over the whole result.
    let birthday = match scan.unspents.iter().map(|u| u.height).min() {
        Some(height) => height,
        None => {
            warn!(
                tip,
                "neither address has unspent outputs; using the UTXO-set tip as the birthday"
            );
            tip
        }
    };
    ensure!(
        birthday > 0,
        "the birthday is the genesis block; leave operator_wallet.bootstrap_height and \
         bootstrap_block_hash unset"
    );

    let checked_height = args.expect_height.unwrap_or(birthday);
    ensure_blocks_retained(info.prune_height, checked_height)?;
    let node_hash = btc_client
        .get_block_hash(checked_height)
        .with_context(|| format!("the node has no block at height {checked_height}"))?;
    // The scan is a snapshot and the lookup above is live, so a reorganization in between would
    // pair a birthday from one chain with a hash from another.
    let scanned_tip = scan
        .best_block_hash
        .context("scantxoutset returned no bestblock")?;
    let current_tip = btc_client
        .get_block_hash(tip)
        .with_context(|| format!("the node has no block at height {tip}"))?;
    ensure!(
        current_tip == scanned_tip,
        "the chain reorganized during the scan: block {tip} was {scanned_tip} and is now \
         {current_tip}; rerun"
    );

    if let Some(base) = args.explorer_url.as_deref() {
        let explorer_hash = explorer_block_hash(base, checked_height).await?;
        ensure!(
            explorer_hash == node_hash,
            "block {checked_height}: the node reports {node_hash} but {base} reports \
             {explorer_hash}; the node may be following another chain"
        );
        info!(height = checked_height, hash = %node_hash, "explorer agrees with the node");
    }

    if let Some(expect_height) = args.expect_height {
        check_expectation(expect_height, args.expect_block_hash, birthday, node_hash)?;
        println!(
            "ok: bootstrap_height {expect_height} is at or below the wallet birthday {birthday}; \
             the block at {expect_height} is {node_hash}"
        );
        return Ok(());
    }

    println!("{}", render_config(birthday, &node_hash));
    Ok(())
}

/// What the scan found for one address.
#[derive(Debug)]
struct AddressSummary {
    count: usize,
    oldest: Option<u64>,
    total: Amount,
}

/// The unspent outputs in `unspents` paying `script_pubkey`. The script is what tells the two
/// addresses' shares of one scan apart; the `desc` field would too, but carries a checksum suffix.
fn summarize(unspents: &[Utxo], script_pubkey: &Script) -> AddressSummary {
    let mine = unspents
        .iter()
        .filter(|u| u.script_pub_key.as_script() == script_pubkey);
    AddressSummary {
        count: mine.clone().count(),
        oldest: mine.clone().map(|u| u.height).min(),
        total: mine.map(|u| u.amount).sum(),
    }
}

/// Verify mode: a configured pair passes when it skips no unspent output and, if it names a hash,
/// names `node_hash`, the node's block at `expect_height`.
fn check_expectation(
    expect_height: u64,
    expect_hash: Option<BlockHash>,
    birthday: u64,
    node_hash: BlockHash,
) -> anyhow::Result<()> {
    // The node reads height 0 as "unset" and rejects a hash beside it instead of checking it.
    ensure!(
        expect_height > 0 || expect_hash.is_none(),
        "bootstrap_height 0 means genesis and the node rejects a bootstrap_block_hash beside it; \
         leave both unset"
    );
    ensure!(
        expect_height <= birthday,
        "bootstrap_height {expect_height} is above the wallet birthday {birthday}; outputs below \
         it would be invisible to the wallet"
    );
    if let Some(expected) = expect_hash {
        ensure!(
            expected == node_hash,
            "bootstrap_block_hash {expected} is not the block at height {expect_height}; the node \
             reports {node_hash}"
        );
    }
    Ok(())
}

/// The UTXO set survives pruning, so the scan still finds outputs whose blocks a pruned node has
/// deleted; the bridge would then fail to fetch them. `prune_height` is the lowest complete block
/// the node stores, so scanning from it is fine.
fn ensure_blocks_retained(prune_height: Option<u64>, height: u64) -> anyhow::Result<()> {
    if let Some(prune_height) = prune_height {
        ensure!(
            height >= prune_height,
            "the node is pruned below block {prune_height}, so the bridge could not scan from block \
             {height}; run this against an archival node"
        );
    }
    Ok(())
}

/// The `[operator_wallet]` lines to paste into the node config.
fn render_config(height: u64, hash: &BlockHash) -> String {
    format!("[operator_wallet]\nbootstrap_height = {height}\nbootstrap_block_hash = \"{hash}\"")
}

/// Hash of the block at `height` according to a mempool/esplora API rooted at `base`, which
/// answers `block-height/<height>` with the hash as plain text.
async fn explorer_block_hash(base: &str, height: u64) -> anyhow::Result<BlockHash> {
    let url = format!("{}/block-height/{height}", base.trim_end_matches('/'));
    let body = reqwest::Client::builder()
        .timeout(EXPLORER_TIMEOUT)
        .build()
        .context("building the explorer HTTP client")?
        .get(&url)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .with_context(|| format!("fetching {url}"))?
        .text()
        .await
        .with_context(|| format!("reading the reply from {url}"))?;
    body.trim()
        .parse()
        .with_context(|| format!("{url} did not answer with a block hash: {body:?}"))
}

#[cfg(test)]
mod tests {
    use bitcoin::{hashes::Hash, ScriptBuf, Txid};

    use super::*;

    fn utxo(script_pub_key: &ScriptBuf, height: u64) -> Utxo {
        Utxo {
            txid: Txid::all_zeros(),
            vout: 0,
            script_pub_key: script_pub_key.clone(),
            descriptor: String::new(),
            amount: Amount::ONE_BTC,
            height,
        }
    }

    /// A share is filtered by script, so the other address's outputs never leak into it.
    #[test]
    fn summary_is_one_address_share_of_the_scan() {
        let general = ScriptBuf::from_bytes(vec![0x51]);
        let reserved = ScriptBuf::from_bytes(vec![0x52]);
        let unspents = [
            utxo(&general, 105),
            utxo(&general, 110),
            utxo(&reserved, 100),
        ];

        let share = summarize(&unspents, &reserved);
        assert_eq!(
            (share.count, share.oldest, share.total),
            (1, Some(100), Amount::ONE_BTC)
        );
    }

    /// A configured pair passes only when it skips no unspent output and names the node's block;
    /// height 0 is genesis and takes no hash.
    #[test]
    fn expectation_holds_only_at_or_below_the_birthday_with_the_nodes_hash() {
        let node_hash = BlockHash::all_zeros();
        let other = BlockHash::from_byte_array([1; 32]);

        assert!(check_expectation(100, Some(node_hash), 100, node_hash).is_ok());
        assert!(check_expectation(99, None, 100, node_hash).is_ok());
        assert!(check_expectation(0, None, 100, node_hash).is_ok());
        assert!(check_expectation(101, None, 100, node_hash).is_err());
        assert!(check_expectation(100, Some(other), 100, node_hash).is_err());
        assert!(check_expectation(0, Some(node_hash), 100, node_hash).is_err());
    }

    /// An unpruned node retains everything; a pruned one serves its prune height and above.
    #[test]
    fn checkpoint_must_be_within_a_pruned_nodes_retained_blocks() {
        assert!(ensure_blocks_retained(None, 1).is_ok());
        assert!(ensure_blocks_retained(Some(100), 100).is_ok());
        assert!(ensure_blocks_retained(Some(100), 99).is_err());
    }

    /// The printed block is pasted into the node config verbatim.
    #[test]
    fn rendered_config_is_the_operator_wallet_table() {
        let zeros = "0".repeat(64);
        assert_eq!(
            render_config(800_000, &BlockHash::all_zeros()),
            format!(
                "[operator_wallet]\nbootstrap_height = 800000\nbootstrap_block_hash = \"{zeros}\""
            )
        );
    }
}
