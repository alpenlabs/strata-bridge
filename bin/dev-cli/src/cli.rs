use std::path::PathBuf;

use bitcoin::Txid;
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

    Challenge(ChallengeArgs),

    Disprove(DisproveArgs),
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
#[command(about = "Send challenge transaction", version)]
pub(crate) struct ChallengeArgs {
    #[arg(
        long,
        env = "CLAIM_TXID",
        value_parser = clap::value_parser!(Txid),
        help = "the txid of the claim being challenged"
    )]
    pub(crate) claim_txid: Txid,

    #[clap(flatten)]
    pub(crate) btc_args: BtcArgs,

    #[arg(long, help = "the path to the params file")]
    pub(crate) params: PathBuf,

    #[arg(
        long,
        env = "BRIDGE_NODE_URL",
        help = "the url of the bridge node to query for challenge signature"
    )]
    pub(crate) bridge_node_url: String,
}

#[derive(Parser, Debug, Clone)]
#[command(about = "Send challenge transaction", version)]
pub(crate) struct DisproveArgs {
    #[arg(
        long,
        env = "POST_ASSERT_TXID",
        value_parser = clap::value_parser!(Txid),
        help = "the txid of the claim being challenged"
    )]
    pub(crate) post_assert_txid: Txid,

    #[clap(flatten)]
    pub(crate) btc_args: BtcArgs,

    #[arg(
        long,
        env = "BRIDGE_NODE_URL",
        help = "the url of the bridge node to query for challenge signature"
    )]
    pub(crate) bridge_node_url: String,

    #[arg(long, help = "the strata bridge params file")]
    pub(crate) params: PathBuf,
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
