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

    /// Generate a Bitcoin private key and write it as WIF.
    #[command(
        name = "keygen",
        alias = "generate-private-key",
        alias = "generate_a_private_key"
    )]
    GeneratePrivateKey(GeneratePrivateKeyArgs),

    /// Generate the P2TR funding address for a private key.
    #[command(
        name = "addr",
        alias = "generate-address",
        alias = "generate_an_address"
    )]
    GenerateAddress(GenerateAddressArgs),

    /// Send bitcoin from a WIF-backed address.
    Send(SendArgs),

    DeriveKeys(DeriveKeysArgs),

    /// Create and publish a mock checkpoint.
    CreateAndPublishMockCheckpoint(CreateAndPublishMockCheckpointArgs),

    /// Contest a claim transaction.
    Contest(ContestArgs),

    /// Post a claim transaction.
    Claim(ClaimArgs),
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

    #[arg(
        long = "key-file",
        alias = "private-key-file",
        help = "path to a WIF private key; when set, bridge-in signs locally, uses this key for DRT recovery, and uses mempool/Esplora REST instead of bitcoind"
    )]
    pub(crate) private_key_file: Option<PathBuf>,

    #[arg(
        long = "api-url",
        alias = "esplora-url",
        help = "mempool/Esplora API base URL; defaults to the selected network"
    )]
    pub(crate) esplora_url: Option<String>,

    #[arg(
        long = "fee-rate",
        alias = "fee-rate-sats-per-vbyte",
        default_value_t = 2,
        help = "fee rate in sat/vB for the private-key bridge-in path"
    )]
    pub(crate) fee_rate_sats_per_vbyte: u64,

    #[arg(
        long = "change",
        alias = "change-address",
        help = "optional change address for the private-key bridge-in path; defaults to the funding address"
    )]
    pub(crate) change_address: Option<String>,

    #[arg(
        long,
        help = "construct and sign the private-key bridge-in transaction without broadcasting"
    )]
    pub(crate) dry_run: bool,

    #[clap(flatten)]
    pub(crate) btc_args: BtcArgs,
}

#[derive(Parser, Debug, Clone)]
#[command(about = "Generate a Bitcoin private key", version)]
pub(crate) struct GeneratePrivateKeyArgs {
    #[arg(long, short, help = "path to write the WIF private key")]
    pub(crate) output: PathBuf,

    #[arg(long, default_value_t = Network::Signet, help = "bitcoin network")]
    pub(crate) network: Network,

    #[arg(long, help = "overwrite the output file if it already exists")]
    pub(crate) force: bool,
}

#[derive(Parser, Debug, Clone)]
#[command(about = "Generate a Bitcoin address from a private key file", version)]
pub(crate) struct GenerateAddressArgs {
    #[arg(
        long = "key-file",
        alias = "private-key-file",
        help = "path to a WIF private key"
    )]
    pub(crate) private_key_file: PathBuf,

    #[arg(long, default_value_t = Network::Signet, help = "bitcoin network")]
    pub(crate) network: Network,
}

#[derive(Parser, Debug, Clone)]
#[command(about = "Send bitcoin from a WIF private key", version)]
pub(crate) struct SendArgs {
    #[arg(
        long = "key-file",
        alias = "private-key-file",
        help = "path to a WIF private key"
    )]
    pub(crate) private_key_file: PathBuf,

    #[arg(long, default_value_t = Network::Signet, help = "bitcoin network")]
    pub(crate) network: Network,

    #[arg(long, help = "recipient bitcoin address")]
    pub(crate) to: String,

    #[arg(
        long = "amount-sats",
        alias = "sats",
        help = "amount to send in satoshis"
    )]
    pub(crate) amount_sats: u64,

    #[arg(
        long = "fee-rate",
        alias = "fee-rate-sats-per-vbyte",
        default_value_t = 2,
        help = "fee rate in sat/vB"
    )]
    pub(crate) fee_rate_sats_per_vbyte: u64,

    #[arg(
        long = "api-url",
        alias = "esplora-url",
        help = "mempool/Esplora API base URL; defaults to the selected network"
    )]
    pub(crate) esplora_url: Option<String>,

    #[arg(
        long = "change",
        alias = "change-address",
        help = "optional change address; defaults to the funding address"
    )]
    pub(crate) change_address: Option<String>,

    #[arg(long, help = "construct and sign the transaction without broadcasting")]
    pub(crate) dry_run: bool,
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
