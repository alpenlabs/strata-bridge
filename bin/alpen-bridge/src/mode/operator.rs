//! Defines the main loop for the bridge-client in operator mode.
use bitcoin::secp256k1::SecretKey;
use libp2p::{
    identity::{secp256k1::PublicKey as LibP2pSecpPublicKey, PublicKey as LibP2pPublicKey},
    PeerId,
};
use secp256k1::SECP256K1;
use secret_service_client::SecretServiceClient;
use strata_bridge_db::persistent::sqlite::SqliteDb;
use strata_bridge_p2p_service::{
    bootstrap as p2p_bootstrap, Configuration as P2PConfiguration, MessageHandler,
};
use strata_p2p_types::P2POperatorPubKey;
use tokio::task::JoinHandle;
use tracing::info;

use crate::{
    config::{Config, P2PConfig},
    params::Params,
};

/// Bootstraps the bridge client in Operator mode by hooking up all the required auxiliary services
/// including database, rpc server, etc.pub(crate) async fn bootstrap() -> anyhow::Result<()> {
pub(crate) async fn bootstrap(params: Params, config: Config) -> anyhow::Result<()> {
    info!("bootstrapping operator node");

    let s2_client = init_secret_service_client(&config);

    // TODO(@Zk2u!): give the `init_p2p_message_handler` the P2P secret key `sk`.
    let sk = get_p2p_key(&s2_client).await?;
    let message_handler = init_p2p_msg_handler(&config, &params, sk).await?;

    let db = init_database_handle(&config);

    init_duty_tracker(&params, &config, s2_client, message_handler, db);

    let rpc_task = start_rpc_server().await;

    // Wait for all tasks to run
    // They are supposed to run indefinitely in most cases
    // TODO: add duty tracker task
    tokio::try_join!(rpc_task)?;

    Ok(())
}

fn init_secret_service_client(_config: &Config) -> SecretServiceClient {
    unimplemented!("@Zk2u!");
}

async fn get_p2p_key(_secret_service: &SecretServiceClient) -> anyhow::Result<SecretKey> {
    unimplemented!("@Zk2u!");
}

/// Initialize the P2P message handler.
///
/// Needs a secret key and configuration.
async fn init_p2p_msg_handler(
    config: &Config,
    params: &Params,
    sk: SecretKey,
) -> anyhow::Result<MessageHandler> {
    let my_key = LibP2pSecpPublicKey::try_from_bytes(&sk.public_key(SECP256K1).serialize())
        .expect("infallible");
    let other_operators: Vec<LibP2pSecpPublicKey> = params
        .keys
        .p2p
        .clone()
        .into_iter()
        .filter(|pk| pk != &my_key)
        .collect();
    let allowlist: Vec<PeerId> = other_operators
        .clone()
        .into_iter()
        .map(|pk| {
            let pk: LibP2pPublicKey = pk.into();
            PeerId::from(pk)
        })
        .collect();
    let signers_allowlist: Vec<P2POperatorPubKey> =
        other_operators.into_iter().map(Into::into).collect();

    let P2PConfig {
        idle_connection_timeout,
        listening_addr,
        connect_to,
        num_threads,
    } = config.p2p.clone();

    let config = P2PConfiguration::new_with_secret_key(
        sk,
        idle_connection_timeout,
        listening_addr,
        allowlist,
        connect_to,
        signers_allowlist,
        num_threads,
    );
    let (p2p_handle, _cancel) = p2p_bootstrap(&config).await?;
    Ok(MessageHandler::new(p2p_handle))
}

fn init_database_handle(_config: &Config) -> SqliteDb {
    unimplemented!("@Rajil1213");
}

fn init_duty_tracker(
    _params: &Params,
    _config: &Config,
    _s2_client: SecretServiceClient,
    _message_handler: MessageHandler,
    _db: SqliteDb,
) {
    unimplemented!("@ProofOfKeags");
}

async fn start_rpc_server() -> JoinHandle<()> {
    unimplemented!("@storopoli");
}
