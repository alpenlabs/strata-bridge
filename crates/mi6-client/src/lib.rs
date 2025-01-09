use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use quinn::{
    crypto::rustls::{NoInitialCipherSuite, QuicClientConfig},
    rustls, ClientConfig, ConnectError, Connection, ConnectionError, Endpoint,
};
use terrors::OneOf;

#[derive(Clone)]
pub struct Config {
    server_addr: SocketAddr,
    server_hostname: String,
    local_addr: Option<SocketAddr>,
    connection_limit: Option<usize>,
    tls_config: rustls::ClientConfig,
}

#[derive(Clone)]
pub struct Client {
    endpoint: Endpoint,
    config: Config,
    conn: Option<Connection>,
}

impl Client {
    pub fn new(config: Config) -> Result<Self, io::Error> {
        let endpoint = Endpoint::client(
            config
                .local_addr
                .unwrap_or((Ipv4Addr::UNSPECIFIED, 0).into()),
        )?;
        Ok(Client {
            endpoint,
            config,
            conn: None,
        })
    }

    pub async fn connect(
        &mut self,
    ) -> Result<(), OneOf<(NoInitialCipherSuite, ConnectError, ConnectionError)>> {
        if self.conn.is_some() {
            return Ok(());
        }

        let connecting = self
            .endpoint
            .connect_with(
                ClientConfig::new(Arc::new(
                    QuicClientConfig::try_from(self.config.tls_config.clone())
                        .map_err(OneOf::new)?,
                )),
                self.config.server_addr,
                &self.config.server_hostname,
            )
            .map_err(OneOf::new)?;
        let conn = connecting.await.map_err(OneOf::new)?;
        self.conn = Some(conn);
        Ok(())
    }
}
