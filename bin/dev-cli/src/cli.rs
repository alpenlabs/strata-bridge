use std::path::PathBuf;

use bitcoin::{address::NetworkUnchecked, Address, BlockHash, Network};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "dev-cli",
    about = "Strata Bridge-in/Bridge-out CLI for dev environment",
    version
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum Commands {
    BridgeIn(BridgeInArgs),

    DeriveKeys(DeriveKeysArgs),

    /// Create and publish a mock checkpoint.
    CreateAndPublishMockCheckpoint(CreateAndPublishMockCheckpointArgs),

    /// Publish a Defcon1 admin transaction activating the ASM safe harbour.
    Defcon1(Defcon1Args),

    /// Contest a claim transaction.
    Contest(ContestArgs),

    /// Post a claim transaction.
    Claim(ClaimArgs),

    /// Post an empty bridge proof receipt transaction.
    BridgeProof(BridgeProofArgs),

    /// Post an unstaking intent transaction.
    UnstakingIntent(UnstakingIntentArgs),

    /// Compute or verify the operator wallet bootstrap checkpoint from the node's UTXO set.
    WalletBirthday(WalletBirthdayArgs),
}

#[derive(Parser, Debug, Clone)]
#[command(
    about = "Derive operator keys and addresses from a master xpriv seed",
    version
)]
pub(crate) struct DeriveKeysArgs {
    #[arg(help = "32-byte hex-encoded seed (64 hex characters)")]
    pub(crate) seed: String,

    #[arg(
        help = "network to derive addresses for",
        default_value_t = Network::Regtest
    )]
    pub(crate) network: Network,
}

#[derive(Parser, Debug, Clone)]
#[command(about = "Send the deposit request on bitcoin", version)]
pub(crate) struct BridgeInArgs {
    #[arg(long, help = "execution environment address to mint funds to")]
    pub(crate) ee_address: String,

    #[arg(long, help = "the path to the params file")]
    pub(crate) params: PathBuf,

    #[clap(flatten)]
    pub(crate) btc_args: BtcArgs,
}

#[derive(Parser, Debug, Clone)]
#[command(about = "Create and publish a mock checkpoint", version)]
pub(crate) struct CreateAndPublishMockCheckpointArgs {
    #[arg(
        long,
        default_value = "1",
        help = "number of withdrawal logs to include"
    )]
    pub(crate) num_withdrawals: usize,

    #[arg(long, default_value = "1", help = "checkpoint epoch")]
    pub(crate) epoch: u32,

    #[arg(
        long,
        help = "genesis L1 height (defaults to `genesis_height` from the params file)"
    )]
    pub(crate) genesis_l1_height: Option<u32>,

    #[arg(long, help = "start OL block slot for the L2 range")]
    pub(crate) ol_start_slot: u64,

    #[arg(long, help = "end OL block slot for the L2 range")]
    pub(crate) ol_end_slot: u64,

    #[arg(
        long,
        default_value = "0",
        help = "operator node index to assign withdrawals to"
    )]
    pub(crate) assignee_node_idx: u32,

    #[arg(long, help = "the path to the params file")]
    pub(crate) params: PathBuf,

    #[clap(flatten)]
    pub(crate) btc_args: BtcArgs,
}

#[derive(Parser, Debug, Clone)]
#[command(
    about = "Publish a Defcon1 admin tx activating the ASM safe harbour",
    version
)]
pub(crate) struct Defcon1Args {
    #[arg(
        long,
        help = "hex-encoded seed of the council signer (operator 0 in test setups)"
    )]
    pub(crate) seed: String,

    #[arg(
        long,
        default_value = "1",
        help = "admin action sequence number (must exceed the council's last seqno)"
    )]
    pub(crate) seqno: u64,

    #[arg(long, default_value_t = Network::Regtest, help = "bitcoin network")]
    pub(crate) network: Network,

    #[clap(flatten)]
    pub(crate) btc_args: BtcArgs,
}

#[derive(Parser, Debug, Clone)]
#[command(about = "Contest a claim transaction", version)]
pub(crate) struct ContestArgs {
    #[arg(long, help = "deposit index of the graph")]
    pub(crate) deposit_idx: u32,

    #[arg(long, help = "operator index of the graph")]
    pub(crate) operator_idx: u32,

    #[arg(long, help = "url of the bridge node RPC")]
    pub(crate) bridge_node_url: String,

    #[arg(long, help = "index of the operator node contesting the claim")]
    pub(crate) contester_node_idx: u32,

    #[arg(long, help = "hex-encoded seed of the contesting operator")]
    pub(crate) seed: String,

    #[arg(long, help = "the path to the params file")]
    pub(crate) params: PathBuf,

    #[clap(flatten)]
    pub(crate) btc_args: BtcArgs,
}

#[derive(Parser, Debug, Clone)]
#[command(about = "Post a claim transaction", version)]
pub(crate) struct ClaimArgs {
    #[arg(long, help = "deposit index of the graph")]
    pub(crate) deposit_idx: u32,

    #[arg(long, help = "operator index of the graph")]
    pub(crate) operator_idx: u32,

    #[arg(long, help = "url of the bridge node RPC")]
    pub(crate) bridge_node_url: String,

    #[arg(long, help = "hex-encoded seed of the claiming operator")]
    pub(crate) seed: String,

    #[arg(long, help = "the path to the params file")]
    pub(crate) params: PathBuf,

    #[clap(flatten)]
    pub(crate) btc_args: BtcArgs,
}

#[derive(Parser, Debug, Clone)]
#[command(about = "Post an empty bridge proof receipt transaction", version)]
pub(crate) struct BridgeProofArgs {
    #[arg(long, help = "deposit index of the graph")]
    pub(crate) deposit_idx: u32,

    #[arg(long, help = "operator index of the graph")]
    pub(crate) operator_idx: u32,

    #[arg(long, help = "url of the bridge node RPC")]
    pub(crate) bridge_node_url: String,

    #[arg(long, help = "hex-encoded seed of the graph-owning operator")]
    pub(crate) seed: String,

    #[arg(long, help = "the path to the params file")]
    pub(crate) params: PathBuf,

    #[clap(flatten)]
    pub(crate) btc_args: BtcArgs,
}

#[derive(Parser, Debug, Clone)]
#[command(about = "Post an unstaking intent transaction", version)]
pub(crate) struct UnstakingIntentArgs {
    #[arg(long, help = "operator index of the stake graph")]
    pub(crate) operator_idx: u32,

    #[arg(long, help = "url of the bridge node RPC")]
    pub(crate) bridge_node_url: String,

    #[arg(long, help = "hex-encoded seed of the unstaking operator")]
    pub(crate) seed: String,

    #[arg(long, help = "the path to the params file")]
    pub(crate) params: PathBuf,

    #[clap(flatten)]
    pub(crate) btc_args: BtcArgs,
}

#[derive(Parser, Debug, Clone)]
#[command(
    about = "Compute or verify the operator_wallet bootstrap checkpoint from the node's UTXO set",
    version
)]
pub(crate) struct WalletBirthdayArgs {
    #[arg(
        long,
        help = "general wallet address (`general_wallet_address` from derive-keys)"
    )]
    pub(crate) general_address: Address<NetworkUnchecked>,

    #[arg(
        long,
        help = "reserved wallet address (`reserved_wallet_address` from derive-keys)"
    )]
    pub(crate) reserved_address: Address<NetworkUnchecked>,

    #[arg(
        long,
        help = "base URL of a mempool/esplora API whose block hash must match the node's, e.g. https://mempool.space/api"
    )]
    pub(crate) explorer_url: Option<String>,

    #[arg(
        long,
        help = "verify mode: the configured bootstrap_height, which must be at or below the birthday"
    )]
    pub(crate) expect_height: Option<u64>,

    #[arg(
        long,
        requires = "expect_height",
        help = "verify mode: the configured bootstrap_block_hash, which must be the node's block at --expect-height"
    )]
    pub(crate) expect_block_hash: Option<BlockHash>,

    #[arg(
        long,
        default_value_t = 3600,
        value_parser = clap::value_parser!(u64).range(1..),
        help = "seconds to wait for each node RPC; a mainnet scantxoutset runs for minutes"
    )]
    pub(crate) rpc_timeout: u64,

    #[clap(flatten)]
    pub(crate) btc_args: BtcArgs,
}

#[derive(Parser, Debug, Clone)]
pub(crate) struct BtcArgs {
    #[arg(
        long = "btc-url",
        help = "url of the bitcoind node",
        env = "BTC_URL",
        default_value = "http://localhost:18443/wallet/default"
    )]
    pub(crate) url: String,

    #[arg(
        long = "btc-user",
        help = "user for the bitcoind node",
        env = "BTC_USER",
        default_value = "rpcuser"
    )]
    pub(crate) user: String,

    #[arg(
        long = "btc-pass",
        help = "password for the bitcoind node",
        env = "BTC_PASS",
        default_value = "rpcpassword"
    )]
    pub(crate) pass: String,
}
