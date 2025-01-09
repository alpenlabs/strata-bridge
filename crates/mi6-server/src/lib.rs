use std::{future::Future, io, net::SocketAddr, pin::Pin, sync::Arc};

use mi6_proto::traits::MI6Factory;
use quinn::{
    crypto::rustls::{NoInitialCipherSuite, QuicServerConfig},
    rustls, Endpoint, ServerConfig,
};
use terrors::OneOf;
use tokio::task::{JoinError, JoinHandle};

pub struct Config {
    addr: SocketAddr,
    connection_limit: Option<usize>,
    tls_config: rustls::ServerConfig,
}

pub struct ServerHandle {
    main: JoinHandle<()>,
}

impl Future for ServerHandle {
    type Output = Result<(), JoinError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        Pin::new(&mut self.get_mut().main).poll(cx)
    }
}

pub fn run_server<Factory: MI6Factory>(
    c: Config,
    factory: Factory,
) -> Result<ServerHandle, OneOf<(NoInitialCipherSuite, io::Error)>> {
    let quic_server_config = ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(c.tls_config).map_err(OneOf::new)?,
    ));
    let endpoint = Endpoint::server(quic_server_config, c.addr).map_err(OneOf::new)?;
    let handle = tokio::spawn(async move {
        while let Some(conn) = endpoint.accept().await {
            if c.connection_limit
                .is_some_and(|n| endpoint.open_connections() >= n)
            {
                conn.refuse();
            } else {
                // handle_conn(conn, factory).await;
            }
        }
    });
    Ok(ServerHandle { main: handle })
}
