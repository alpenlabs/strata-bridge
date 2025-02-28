//! Module to bootstrap the p2p node by hooking up all the required services.

use std::sync::Arc;

use strata_p2p::swarm::{self, handle::P2PHandle, P2PConfig, P2P};
use strata_p2p_db::sled::AsyncDB;
use threadpool::ThreadPool;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{config::Configuration, constants::DEFAULT_NUM_THREADS};

/// Bootstrap the p2p node by hooking up all the required services.
pub async fn bootstrap(config: &Configuration) -> anyhow::Result<(P2PHandle, CancellationToken)> {
    let p2p_config = P2PConfig {
        keypair: config.keypair.clone(),
        idle_connection_timeout: config.idle_connection_timeout,
        listening_addr: config.listening_addr.clone(),
        allowlist: config.allowlist.clone(),
        connect_to: config.connect_to.clone(),
        signers_allowlist: config.signers_allowlist.clone(),
    };
    let cancel = CancellationToken::new();

    info!("creating an in-memory sled database");
    let db = sled::Config::new().temporary(true).open()?;
    let db = AsyncDB::new(
        ThreadPool::new(config.num_threads.unwrap_or(DEFAULT_NUM_THREADS)),
        Arc::new(db),
    );

    info!("creating a swarm");
    let swarm = swarm::with_inmemory_transport(&p2p_config)?;

    info!("creating a p2p node");
    let (mut p2p, handle) = P2P::from_config(p2p_config, cancel.clone(), db, swarm, None)?;

    info!("establishing connections");
    let _ = p2p.establish_connections().await;

    info!("listening for network events and commands from handles");
    let _ = p2p.listen().await;

    Ok((handle, cancel))
}
