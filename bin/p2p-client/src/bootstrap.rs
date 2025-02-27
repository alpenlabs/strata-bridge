//! Module to bootstrap the p2p node by hooking up all the required services.

use std::sync::Arc;

use strata_p2p::swarm::{self, handle::P2PHandle, P2P};
use strata_p2p_db::sled::AsyncDB;
use threadpool::ThreadPool;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::cli::Cli;

/// Bootstrap the p2p node by hooking up all the required services.
pub(crate) async fn bootstrap(args: Cli) -> anyhow::Result<(P2PHandle, CancellationToken)> {
    let config = args.extract_config()?;
    let cancel = CancellationToken::new();

    info!("creating an in-memory sled database");
    let db = sled::Config::new().temporary(true).open()?;
    let db = AsyncDB::new(ThreadPool::new(1), Arc::new(db));

    info!("creating a swarm");
    let swarm = swarm::with_inmemory_transport(&config)?;

    info!("creating a p2p node");
    let (mut p2p, handle) = P2P::from_config(config, cancel.clone(), db, swarm, None)?;

    info!("establishing connections");
    let _ = p2p.establish_connections().await;

    info!("listening for network events and commands from handles");
    let _ = p2p.listen().await;

    // TODO(@storopoli): Implement RPC logic.
    tokio::spawn(async move {
        // Implement RPC logic here.
        // Probably a function in a new module.
        // Should take a handle and then call send_command on it
        // whenever the RPC receives a request.
    });

    Ok((handle, cancel))
}
