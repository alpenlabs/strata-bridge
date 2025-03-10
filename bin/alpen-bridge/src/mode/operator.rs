//! Defines the main loop for the bridge-client in operator mode.
use secret_service_client::SecretServiceClient;
use strata_bridge_db::persistent::sqlite::SqliteDb;
use strata_bridge_p2p_service::MessageHandler;
use strata_bridge_rpc;
use tokio::task::{JoinHandle, JoinSet};
use tracing::info;

use crate::{config::Config, params::Params};

/// Bootstraps the bridge client in Operator mode by hooking up all the required auxiliary services
/// including database, rpc server, etc.pub(crate) async fn bootstrap() -> anyhow::Result<()> {
pub(crate) async fn bootstrap(params: Params, config: Config) -> anyhow::Result<()> {
    info!("bootstrapping operator node");

    let s2_client = init_secret_service_client(&config);

    let message_handler = init_p2p_msg_handler(&config);

    let db = init_database_handle(&config);

    init_duty_tracker(&params, &config, s2_client, message_handler, db);

    let rpc_task = start_rpc_server().await;

    // Wait for all tasks to run
    // They are supposed to run indefinitely in most cases
    // TODO: add duty tracker task
    tokio::try_join!(rpc_task)?;

    Ok(())
}

fn init_secret_service_client(config: &Config) -> SecretServiceClient {
    unimplemented!("@Zk2u!");
}

fn init_p2p_msg_handler(config: &Config) -> MessageHandler {
    unimplemented!("@storopoli");
}

fn init_database_handle(config: &Config) -> SqliteDb {
    unimplemented!("@Rajil1213");
}

fn init_duty_tracker(
    params: &Params,
    config: &Config,
    s2_client: SecretServiceClient,
    message_handler: MessageHandler,
    db: SqliteDb,
) {
    unimplemented!("@ProofOfKeags");
}

async fn start_rpc_server() -> JoinHandle<()> {
    unimplemented!("@storopoli");
}
