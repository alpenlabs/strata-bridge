use std::path::PathBuf;

use bitcoin::{address::NetworkUnchecked, Address, Network, Txid};
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

    /// Publish an admin transaction rotating the ASM safe harbour address.
    SafeHarbourAddressUpdate(SafeHarbourAddressUpdateArgs),

    /// Reclaim a deposit request output through the depositor's takeback path.
    DrtTakeback(DrtTakebackArgs),

    /// Contest a claim transaction.
    Contest(ContestArgs),

    /// Post a claim transaction.
    Claim(ClaimArgs),

    /// Post an empty bridge proof receipt transaction.
    BridgeProof(BridgeProofArgs),

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

    #[arg(long, help = "also print the musig2 secret key")]
    pub(crate) with_secrets: bool,
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
    #[clap(flatten)]
    pub(crate) admin: AdminTxArgs,

    #[arg(long, default_value_t = Network::Regtest, help = "bitcoin network")]
    pub(crate) network: Network,

    #[clap(flatten)]
    pub(crate) btc_args: BtcArgs,
}

#[derive(Parser, Debug, Clone)]
#[command(
    about = "Publish an admin tx rotating the ASM safe harbour address (enacted after the configured confirmation depth; rejected once Defcon1 is active)",
    version
)]
pub(crate) struct SafeHarbourAddressUpdateArgs {
    #[arg(long, help = "new safe harbour address (must be P2TR / bech32m)")]
    pub(crate) address: Address<NetworkUnchecked>,

    #[clap(flatten)]
    pub(crate) admin: AdminTxArgs,

    #[arg(long, default_value_t = Network::Regtest, help = "bitcoin network")]
    pub(crate) network: Network,

    #[clap(flatten)]
    pub(crate) btc_args: BtcArgs,
}

#[derive(Parser, Debug, Clone)]
#[command(
    about = "Reclaim a DRT output via the depositor's takeback tapscript once the recovery delay has passed",
    version
)]
pub(crate) struct DrtTakebackArgs {
    #[arg(long, help = "txid of the deposit request transaction")]
    pub(crate) drt_txid: Txid,

    #[arg(
        long,
        help = "hex-encoded recovery secret key that bridge-in generated for this DRT"
    )]
    pub(crate) recovery_secret: String,

    #[arg(
        long,
        help = "destination address (defaults to a fresh bech32m address from the bitcoind wallet)"
    )]
    pub(crate) destination: Option<Address<NetworkUnchecked>>,

    #[arg(long, default_value = "10", help = "fee rate in sat/vB")]
    pub(crate) fee_rate: u64,

    #[arg(long, help = "the path to the params file")]
    pub(crate) params: PathBuf,

    #[clap(flatten)]
    pub(crate) btc_args: BtcArgs,
}

/// Signer set and sequencing shared by every multisig admin tx.
#[derive(Parser, Debug, Clone)]
pub(crate) struct AdminTxArgs {
    #[arg(
        long,
        required = true,
        help = "hex-encoded seed of a multisig signer; repeat once per signer (operator seeds in test setups)"
    )]
    pub(crate) seed: Vec<String>,

    #[arg(
        long,
        help = "multisig key index of each --seed, in the same order (defaults to 0, 1, ...)"
    )]
    pub(crate) signer_idx: Vec<u8>,

    #[arg(
        long,
        default_value = "1",
        help = "admin action sequence number (must exceed the signing role's last seqno)"
    )]
    pub(crate) seqno: u64,
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
