// use secret_service_server::rustls::ServerConfig;

pub mod disk;

use std::{
    cell::RefCell,
    env::args,
    future::Future,
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
};

use musig2::{
    errors::{RoundContributionError, RoundFinalizeError},
    secp256k1::PublicKey,
    FirstRound, KeyAggContext, LiftedSignature, SecondRound,
};
use parking_lot::Mutex;
use rand::{thread_rng, Rng};
use rkyv::rancor;
use secret_service_proto::v1::traits::{
    Musig2SessionId, Musig2Signer, Musig2SignerFirstRound, Musig2SignerSecondRound, OperatorSigner,
    Origin, SecretService, Server,
};
use secret_service_server::{
    run_server,
    rustls::{
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        ServerConfig,
    },
    Config, RoundPersister,
};
use sled::{Db, Tree};
use terrors::OneOf;
use tokio::{fs, task::spawn_blocking};
use tracing::info;

#[tokio::main]
async fn main() {
    let config_path =
        PathBuf::from_str(&args().nth(1).unwrap_or_else(|| "config.toml".to_string()))
            .expect("valid config path");

    let text = std::fs::read_to_string(&config_path).expect("read config file");
    let conf: TomlConfig = toml::from_str(&text).expect("valid toml");

    let (certs, key) = if let Some(TlsConfig {
        cert: Some(ref crt_path),
        key: Some(ref key_path),
    }) = conf.tls
    {
        let key = fs::read(key_path).await.expect("readable key");
        let key = if key_path.extension().is_some_and(|x| x == "der") {
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key))
        } else {
            rustls_pemfile::private_key(&mut &*key)
                .expect("valid PEM-encoded private key")
                .expect("non-empty private key")
        };
        let cert_chain = fs::read(crt_path).await.expect("readable certificate");
        let cert_chain = if crt_path.extension().is_some_and(|x| x == "der") {
            vec![CertificateDer::from(cert_chain)]
        } else {
            rustls_pemfile::certs(&mut &*cert_chain)
                .collect::<Result<_, _>>()
                .expect("valid PEM-encoded certificate")
        };

        (cert_chain, key)
    } else {
        info!("using self-signed certificate");
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let cert = cert.cert.into();
        (vec![cert], key.into())
    };

    let tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("valid rustls config");

    let config = Config {
        addr: conf.transport.addr,
        tls_config: tls,
        connection_limit: conf.transport.conn_limit,
    };

    let service = Service::load_from_seed_and_db(
        &conf
            .seed
            .unwrap_or(PathBuf::from_str("seed").expect("valid path")),
        conf.db
            .unwrap_or(PathBuf::from_str("db").expect("valid path")),
    )
    .await
    .expect("good service");

    run_server(config, service.into()).unwrap().await;
}

#[derive(serde::Deserialize)]
struct TomlConfig {
    tls: Option<TlsConfig>,
    transport: TransportConfig,
    seed: Option<PathBuf>,
    db: Option<PathBuf>,
}

#[derive(serde::Deserialize)]
struct TransportConfig {
    addr: SocketAddr,
    conn_limit: Option<usize>,
}

#[derive(serde::Deserialize)]
struct TlsConfig {
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
}

struct Service {
    seed: [u8; 32],
    db: Db,
}

impl Service {
    async fn load_from_seed_and_db(seed_path: &Path, db_path: PathBuf) -> io::Result<Self> {
        let mut seed = [0; 32];

        if let Some(parent) = seed_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        match fs::read(seed_path).await {
            Ok(vec) => seed.copy_from_slice(&vec),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut rng = rand::thread_rng();
                rng.fill(&mut seed);
                fs::write(seed_path, &seed).await?;
            }
            Err(e) => return Err(e),
        };

        let db = spawn_blocking(move || sled::open(db_path))
            .await
            .expect("thread ok")?;
        Ok(Self { seed, db })
    }
}

struct ServerFirstRound {
    session_id: Musig2SessionId,
    tree: Tree,
    first_round: FirstRound,
    ordered_public_keys: Vec<PublicKey>,
}

impl RoundPersister for ServerFirstRound {
    type Error = OneOf<(rancor::Error, sled::Error)>;

    fn persist(
        &self,
        session_id: Musig2SessionId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async move {
            let bytes = rkyv::to_bytes::<rancor::Error>(&self.first_round).map_err(OneOf::new)?;
            self.tree
                .insert(&session_id.to_be_bytes(), bytes.as_ref())
                .map_err(OneOf::new)?;
            self.tree.flush_async().await.map_err(OneOf::new)?;
            Ok(())
        }
    }
}

impl Musig2SignerFirstRound<Server, ServerSecondRound> for ServerFirstRound {
    fn our_nonce(
        &self,
    ) -> impl Future<Output = <Server as Origin>::Container<musig2::PubNonce>> + Send {
        async move { todo!() }
    }

    fn holdouts(
        &self,
    ) -> impl Future<Output = <Server as Origin>::Container<Vec<PublicKey>>> + Send {
        async move { todo!() }
    }

    fn is_complete(&self) -> impl Future<Output = <Server as Origin>::Container<bool>> + Send {
        async move { todo!() }
    }

    fn receive_pub_nonce(
        &self,
        pubkey: PublicKey,
        pubnonce: musig2::PubNonce,
    ) -> impl Future<Output = <Server as Origin>::Container<Result<(), RoundContributionError>>> + Send
    {
        async move { todo!() }
    }

    fn finalize(
        self,
        hash: [u8; 32],
    ) -> impl Future<
        Output = <Server as Origin>::Container<Result<ServerSecondRound, RoundFinalizeError>>,
    > + Send {
        async move { todo!() }
    }
}

struct ServerSecondRound {
    session_id: Musig2SessionId,
    tree: Tree,
    second_round: Mutex<SecondRound<[u8; 32]>>,
    ordered_public_keys: Mutex<Vec<PublicKey>>,
}

impl RoundPersister for ServerSecondRound {
    type Error = OneOf<(rancor::Error, sled::Error)>;

    fn persist(
        &self,
        session_id: Musig2SessionId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async move {
            let bytes =
                rkyv::to_bytes::<rancor::Error>(&*self.second_round.lock()).map_err(OneOf::new)?;
            self.tree
                .insert(&session_id.to_be_bytes(), bytes.as_ref())
                .map_err(OneOf::new)?;
            self.tree.flush_async().await.map_err(OneOf::new)?;
            Ok(())
        }
    }
}

impl Musig2SignerSecondRound<Server> for ServerSecondRound {
    fn agg_nonce(
        &self,
    ) -> impl Future<Output = <Server as Origin>::Container<musig2::AggNonce>> + Send {
        async move { self.second_round.lock().aggregated_nonce().clone() }
    }

    fn holdouts(
        &self,
    ) -> impl Future<Output = <Server as Origin>::Container<Vec<PublicKey>>> + Send {
        async move {
            let ordered_public_keys = self.ordered_public_keys.lock();
            self.second_round
                .lock()
                .holdouts()
                .into_iter()
                .map(|idx| ordered_public_keys[*idx])
                .collect()
        }
    }

    fn our_signature(
        &self,
    ) -> impl Future<Output = <Server as Origin>::Container<musig2::PartialSignature>> + Send {
        async move { self.second_round.lock().our_signature() }
    }

    fn is_complete(&self) -> impl Future<Output = <Server as Origin>::Container<bool>> + Send {
        async move { self.second_round.lock().is_complete() }
    }

    fn receive_signature(
        &self,
        pubkey: PublicKey,
        signature: musig2::PartialSignature,
    ) -> impl Future<Output = <Server as Origin>::Container<Result<(), RoundContributionError>>> + Send
    {
        async move {
            let signer_idx = self
                .ordered_public_keys
                .lock()
                .iter()
                .position(|x| x == &pubkey)
                .ok_or(RoundContributionError::out_of_range(0, 0))?;
            self.second_round
                .lock()
                .receive_signature(signer_idx, signature)
        }
    }

    fn finalize(
        self,
    ) -> impl Future<
        Output = <Server as Origin>::Container<Result<LiftedSignature, RoundFinalizeError>>,
    > + Send {
        async move { self.second_round.into_inner().finalize() }
    }
}

struct Operator;

impl OperatorSigner<Server> for Operator {
    fn sign_psbt(&self, psbt: bitcoin::Psbt) -> impl Future<Output = bitcoin::Psbt> + Send {
        async move { todo!() }
    }
}

struct P2PSigner;

impl SecretService<Server, ServerFirstRound, ServerSecondRound> for Service {
    type OperatorSigner = Operator;

    type P2PSigner;

    type Musig2Signer;

    type WotsSigner;

    fn operator_signer(&self) -> Self::OperatorSigner {
        todo!()
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

struct Ms2Signer {
    tree: Tree,
}

impl Musig2Signer<Server, ServerFirstRound> for Ms2Signer {
    fn new_session(
        &self,
        public_keys: Vec<PublicKey>,
    ) -> impl Future<Output = ServerFirstRound> + Send {
        async move {
            let nonce_seed = thread_rng().gen::<[u8; 32]>();
            let first_round = FirstRound::new(
                KeyAggContext::new(public_keys),
                nonce_seed,
                signer_index,
                spices,
            );
            ServerFirstRound {
                session_id,
                tree: self.tree.clone(),
                first_round,
                ordered_public_keys: public_keys,
            }
        }
    }
}
