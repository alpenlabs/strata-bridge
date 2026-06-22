use std::path::PathBuf;

use bitcoin::Network;
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

    /// Contest a claim transaction.
    Contest(ContestArgs),

    /// Post a claim transaction.
    Claim(ClaimArgs),

    /// Post an empty bridge proof receipt transaction.
    BridgeProof(BridgeProofArgs),

    /// DEMO ONLY: forge + post a REAL bridge proof for an arbitrary claim
    /// (unanchored-genesis attack). Requires the `sp1` build feature.
    ForgeBridgeProof(ForgeBridgeProofArgs),

    /// Post an unstaking intent transaction.
    UnstakingIntent(UnstakingIntentArgs),
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

    #[arg(long, default_value = "101", help = "genesis L1 height")]
    pub(crate) genesis_l1_height: u32,

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

/// DEMO ONLY: args for the unanchored-genesis attack harness.
#[derive(Parser, Debug, Clone)]
#[command(about = "Forge and post a real bridge proof for an arbitrary claim", version)]
pub(crate) struct ForgeBridgeProofArgs {
    #[arg(long, help = "deposit index to forge a claim for")]
    pub(crate) deposit_idx: u32,

    #[arg(long, help = "operator index claiming it (the attacker)")]
    pub(crate) operator_idx: u32,

    #[arg(long, help = "url of the bridge node RPC")]
    pub(crate) bridge_node_url: String,

    #[arg(long, help = "hex-encoded seed of the graph-owning operator")]
    pub(crate) seed: String,

    #[arg(long, help = "the path to the params file")]
    pub(crate) params: PathBuf,

    #[arg(long, help = "url of the strata-asm-runner RPC")]
    pub(crate) asm_rpc_url: String,

    #[arg(long, help = "path to the honest bridge-proof guest ELF")]
    pub(crate) elf_path: PathBuf,

    #[arg(long, help = "L1 height to anchor the proof at (asm must have proven Moho for it)")]
    pub(crate) last_block_height: u64,

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
