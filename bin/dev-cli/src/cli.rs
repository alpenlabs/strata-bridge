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
}

#[derive(Parser, Debug, Clone)]
#[command(about = "Send the deposit request on bitcoin", version)]
pub(crate) struct BridgeInArgs {
    #[arg(long, help = "strata address to mint funds to")]
    pub(crate) strata_address: String,

    #[arg(
        long,
        help = "url of the bitcoind node",
        env = "BTC_URL",
        default_value = "http://localhost:18443/wallet/default"
    )]
    pub(crate) btc_url: String,

    #[arg(
        long,
        help = "user for the bitcoind node",
        env = "BTC_USER",
        default_value = "rpcuser"
    )]
    pub(crate) btc_user: String,

    #[arg(
        long,
        help = "password for the bitcoind node",
        env = "BTC_PASS",
        default_value = "rpcpassword"
    )]
    pub(crate) btc_pass: String,

    #[arg(long, help = "if not provided, will use the default address")]
    pub(crate) recovery_address: Option<String>,
}

#[derive(Parser, Debug, Clone)]
#[command(about = "Send withdrawal request on strata", version)]
pub(crate) struct BridgeOutArgs {
    #[arg(long, help = "the pubkey to send funds to on bitcoin")]
    pub(crate) destination_address_pubkey: String,

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

    #[arg(
        long,
        help = "url of the bitcoind node",
        env = "BTC_URL",
        default_value = "http://localhost:18443/wallet/default"
    )]
    pub(crate) btc_url: String,

    #[arg(
        long,
        help = "user for the bitcoind node",
        env = "BTC_USER",
        default_value = "rpcuser"
    )]
    pub(crate) btc_user: String,

    #[arg(
        long,
        help = "password for the bitcoind node",
        env = "BTC_PASS",
        default_value = "rpcpassword"
    )]
    pub(crate) btc_pass: String,

    #[arg(
        long,
        env = "BRIDGE_NODE_URL",
        help = "the url of the bridge node to query for challenge signature"
    )]
    pub(crate) bridge_node_url: String,
}
