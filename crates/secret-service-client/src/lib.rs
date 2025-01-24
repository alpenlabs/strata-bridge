use std::{
    future::Future,
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use musig2::{
    errors::{RoundContributionError, RoundFinalizeError},
    secp256k1::PublicKey,
    PubNonce,
};
use quinn::{
    crypto::rustls::{NoInitialCipherSuite, QuicClientConfig},
    rustls, ClientConfig, ConnectError, Connection, ConnectionError, Endpoint,
};
use secret_service_proto::v1::traits::{
    self, Client, Musig2SessionId, Musig2SignerFirstRound, Musig2SignerSecondRound, Origin,
    SecretService,
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
pub struct SecretServiceClient {
    endpoint: Endpoint,
    config: Config,
    conn: Option<Connection>,
}

impl SecretServiceClient {
    pub fn new(config: Config) -> Result<Self, io::Error> {
        let endpoint = Endpoint::client(
            config
                .local_addr
                .unwrap_or((Ipv4Addr::UNSPECIFIED, 0).into()),
        )?;
        Ok(SecretServiceClient {
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

struct Musig2FirstRound {
    session_id: Musig2SessionId,
}

impl Musig2SignerFirstRound<Client, Musig2SecondRound> for Musig2FirstRound {
    fn our_nonce(&self) -> impl Future<Output = <Client as Origin>::Container<PubNonce>> + Send {
        async move { todo!() }
    }

    fn holdouts(
        &self,
    ) -> impl Future<Output = <Client as Origin>::Container<Vec<PublicKey>>> + Send {
        async move { todo!() }
    }

    fn is_complete(&self) -> impl Future<Output = <Client as Origin>::Container<bool>> + Send {
        async move { todo!() }
    }

    fn receive_pub_nonce(
        &self,
        pubkey: PublicKey,
        pubnonce: PubNonce,
    ) -> impl Future<Output = <Client as Origin>::Container<Result<(), RoundContributionError>>> + Send
    {
        async move { todo!() }
    }

    fn finalize(
        self,
        hash: [u8; 32],
    ) -> impl Future<
        Output = <Client as Origin>::Container<Result<Musig2SecondRound, RoundFinalizeError>>,
    > + Send {
        async move { todo!() }
    }
}

struct Musig2SecondRound {
    session_id: Musig2SessionId,
}

impl Musig2SignerSecondRound<Client> for Musig2SecondRound {
    fn agg_nonce(
        &self,
    ) -> impl Future<Output = <Client as Origin>::Container<musig2::AggNonce>> + Send {
        async move { todo!() }
    }

    fn holdouts(
        &self,
    ) -> impl Future<Output = <Client as Origin>::Container<Vec<PublicKey>>> + Send {
        async move { todo!() }
    }

    fn our_signature(
        &self,
    ) -> impl Future<Output = <Client as Origin>::Container<musig2::PartialSignature>> + Send {
        async move { todo!() }
    }

    fn is_complete(&self) -> impl Future<Output = <Client as Origin>::Container<bool>> + Send {
        async move { todo!() }
    }

    fn receive_signature(
        &self,
        pubkey: PublicKey,
        signature: musig2::PartialSignature,
    ) -> impl Future<Output = <Client as Origin>::Container<Result<(), RoundContributionError>>> + Send
    {
        async move { todo!() }
    }

    fn finalize(
        self,
    ) -> impl Future<
        Output = <Client as Origin>::Container<Result<musig2::LiftedSignature, RoundFinalizeError>>,
    > + Send {
        async move { todo!() }
    }
}

// impl SecretService<Client, Musig2SecondRound, Musig2FirstRound> for SecretServiceClient {
//     type OperatorSigner;

//     type P2PSigner;

//     type Musig2Signer;

//     type WotsSigner;

//     fn operator_signer(&self) -> &Self::OperatorSigner {
//         todo!()
//     }

//     fn p2p_signer(&self) -> &Self::P2PSigner {
//         todo!()
//     }

//     fn musig2_signer(&self) -> &Self::Musig2Signer {
//         todo!()
//     }

//     fn wots_signer(&self) -> &Self::WotsSigner {
//         todo!()
//     }
// }
