//! Parses command-line arguments for the p2p-client CLI.

use std::{net::Ipv4Addr, time::Duration};

use bitcoin::{key::Parity, secp256k1::SecretKey, XOnlyPublicKey};
use clap::{crate_version, Parser};
use libp2p::{Multiaddr, PeerId};
// Oh my this is annoying...
use libp2p_identity::{
    secp256k1::{
        Keypair as Libp2pSecpKeypair, PublicKey as Libp2pSecpPublicKey,
        SecretKey as Libp2pSecpSecretKey,
    },
    PublicKey as Libp2pPublicKey,
};
use strata_p2p::swarm::P2PConfig;
use strata_p2p_types::OperatorPubKey;
use tracing::{info, trace};

use crate::constants::{
    DEFAULT_IDLE_CONNECTION_TIMEOUT, DEFAULT_NUM_THREADS, DEFAULT_RPC_HOST, DEFAULT_RPC_PORT,
    DEFAULT_STACK_SIZE_MB,
};

/// CLI arguments for the p2p-client.
#[derive(Debug, Clone, Parser, Default)]
#[clap(
    name = "strata-bridge",
    about = "The bridge node for Strata",
    version = crate_version!()
)]
pub(crate) struct Cli {
    /// Server host for the P2P node.
    #[clap(long, help = "Server host for the P2P node", default_value_t = DEFAULT_RPC_HOST.to_string())]
    pub host: String,

    /// Server port for the P2P node.
    #[clap(long, help = "Server port for the P2P node", default_value_t = DEFAULT_RPC_PORT)]
    pub port: u32,

    /// The number of tokio threads to use.
    #[clap(long, help = "The number of tokio threads to use", default_value_t = DEFAULT_NUM_THREADS)]
    pub num_threads: usize,

    /// The stack size per thread (in MB).
    #[clap(long, help = "The stack size per thread (in MB)", default_value_t = DEFAULT_STACK_SIZE_MB)]
    pub stack_size: usize,

    /// Idle connection timeout in seconds.
    #[clap(
        long,
        help = "Idle connection timeout in seconds",
        default_value_t = DEFAULT_IDLE_CONNECTION_TIMEOUT
    )]
    pub idle_connection_timeout: u16,

    /// [`SecretKey`] for the P2P node.
    #[clap(long, help = "Secret key for the P2P node")]
    pub secret_key: String,

    /// Allowlist of peers to connect to as hex-encoded _even_ X-only public keys.
    #[clap(
        long,
        help = "Allowlist of peers to connect to as hex-encoded even X-only public keys"
    )]
    pub allowlist: Vec<String>,

    /// Connect to the given IPv4 addresses.
    #[clap(long, help = "Connect to the given IPv4 addresses")]
    pub connect_to: Vec<String>,
}

impl Cli {
    /// Parses the command-line arguments to a [`P2PConfig`].
    pub(crate) fn extract_config(&self) -> anyhow::Result<P2PConfig> {
        let cli = Self::parse();

        info!("Parsing command-line arguments");

        let secret_key = cli.secret_key.parse::<SecretKey>()?;
        trace!(?secret_key, "parsed secret key");

        let secret_key = Libp2pSecpSecretKey::try_from_bytes(secret_key.secret_bytes())?;
        trace!(?secret_key, "parsed secret key into libp2p's secret key");

        let keypair: Libp2pSecpKeypair = secret_key.into();
        trace!(?keypair, "parsed libp2p's keypair");

        let idle_connection_timeout = Duration::from_secs(cli.idle_connection_timeout as u64);

        let listening_addr: Multiaddr = cli.host.parse::<Ipv4Addr>()?.into();
        trace!(%listening_addr, "parsed libp2p's listening address");

        let allowlist: Vec<PeerId> = cli
            .allowlist
            .iter()
            .map(|s| {
                let x_only_pk = s
                    .parse::<XOnlyPublicKey>()
                    .expect("Failed to parse X-only public key");
                let bytes = &x_only_pk.public_key(Parity::Even).serialize();
                let public_key = Libp2pSecpPublicKey::try_from_bytes(bytes)
                    .expect("Must read the 33-byte public key");
                let public_key: Libp2pPublicKey = public_key.into();
                let peer_id: PeerId = public_key.into();
                peer_id
            })
            .collect();
        trace!(?allowlist, "parsed allowlist");

        let connect_to: Vec<Ipv4Addr> = cli
            .connect_to
            .iter()
            .map(|s| s.parse::<Ipv4Addr>().expect("Failed to parse IPv4 address"))
            .collect();
        let connect_to: Vec<Multiaddr> = connect_to.into_iter().map(Into::into).collect();
        trace!(?connect_to, "parsed connect_to");

        let signers_allowlist: Vec<OperatorPubKey> = cli
            .allowlist
            .iter()
            .map(|s| {
                let x_only_pk = s
                    .parse::<XOnlyPublicKey>()
                    .expect("Failed to parse X-only public key");
                let bytes = &x_only_pk.public_key(Parity::Even).serialize();
                let public_key = Libp2pSecpPublicKey::try_from_bytes(bytes)
                    .expect("Must read the 33-byte public key");
                let operator_pk: OperatorPubKey = public_key.into();
                operator_pk
            })
            .collect();
        trace!(?signers_allowlist, "parsed signers_allowlist");

        Ok(P2PConfig {
            keypair,
            idle_connection_timeout,
            listening_addr,
            allowlist,
            connect_to,
            signers_allowlist,
        })
    }
}
