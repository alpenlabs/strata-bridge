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

    BridgeOut(BridgeOutArgs),

    DeriveKeys(DeriveKeysArgs),

    /// Create and publish a mock checkpoint.
    CreateAndPublishMockCheckpoint(CreateAndPublishMockCheckpointArgs),
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
#[command(about = "Send withdrawal request on strata", version)]
pub(crate) struct BridgeOutArgs {
    #[arg(long, help = "the pubkey to send funds to on bitcoin")]
    pub(crate) destination_address_pubkey: String,

    #[arg(long, help = "the url of the execution environment aka the reth node")]
    pub(crate) ee_url: String,

    #[arg(long, help = "the path to the params file")]
    pub(crate) params: PathBuf,

    #[arg(long, help = "the private key for an address in strata")]
    pub(crate) private_key: String,
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

    #[arg(long, default_value_t = Network::Regtest, help = "bitcoin network")]
    pub(crate) network: Network,

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
