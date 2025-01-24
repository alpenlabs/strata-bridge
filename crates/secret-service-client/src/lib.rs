use std::{
    future::Future,
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use bitcoin::Psbt;
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
    Client, Musig2SessionId, Musig2Signer, Musig2SignerFirstRound, Musig2SignerSecondRound,
    OperatorSigner, Origin, P2PSigner, SecretService, WotsSigner,
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
    connection: Connection,
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
    connection: Connection,
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

impl SecretService<Client, Musig2FirstRound, Musig2SecondRound> for SecretServiceClient {
    type OperatorSigner = OperatorClient;

    type P2PSigner = P2PClient;

    type Musig2Signer = Musig2Client;

    type WotsSigner = WotsClient;

    fn operator_signer(&self) -> Self::OperatorSigner {
        OperatorClient(self.conn.as_ref().unwrap().clone())
    }

    fn p2p_signer(&self) -> Self::P2PSigner {
        todo!()
    }

    fn musig2_signer(&self) -> Self::Musig2Signer {
        todo!()
    }

    fn wots_signer(&self) -> Self::WotsSigner {
        todo!()
    }
}

struct OperatorClient(Connection);

impl OperatorSigner<Client> for OperatorClient {
    type OperatorSigningError = ();

    fn sign_psbt(
        &self,
        psbt: Psbt,
    ) -> impl Future<Output = <Client as Origin>::Container<Result<Psbt, Self::OperatorSigningError>>>
           + Send {
        async move { todo!() }
    }
}

struct P2PClient(Connection);

impl P2PSigner<Client> for P2PClient {
    type P2PSigningError = ();

    fn sign_p2p(
        &self,
        hash: [u8; 32],
    ) -> impl Future<Output = <Client as Origin>::Container<Result<[u8; 64], Self::P2PSigningError>>>
           + Send {
        async move { todo!() }
    }

    fn p2p_pubkey(&self) -> impl Future<Output = [u8; 32]> + Send {
        async move { todo!() }
    }
}

struct Musig2Client(Connection);

impl Musig2Signer<Client, Musig2FirstRound> for Musig2Client {
    fn new_session(
        &self,
    ) -> impl Future<Output = <Client as Origin>::Container<Musig2FirstRound>> + Send {
        async move {
            // self.0.open_bi();
            todo!()
        }
    }
}

struct WotsClient(Connection);

impl WotsSigner<Client> for WotsClient {
    fn get_key(
        &self,
        index: u64,
    ) -> impl Future<Output = <Client as Origin>::Container<[u8; 64]>> + Send {
        async move { todo!() }
    }
}
