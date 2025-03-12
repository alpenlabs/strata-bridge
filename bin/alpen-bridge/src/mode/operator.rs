//! Defines the main loop for the bridge-client in operator mode.
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::anyhow;
use bitcoin::secp256k1::SecretKey;
use libp2p::{
    identity::{secp256k1::PublicKey as LibP2pSecpPublicKey, PublicKey as LibP2pPublicKey},
    PeerId,
};
use secp256k1::SECP256K1;
use secret_service_client::{
    rustls::{
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        ClientConfig, RootCertStore,
    },
    SecretServiceClient,
};
use secret_service_proto::v1::traits::{P2PSigner, SecretService};
use sqlx::{
    migrate::Migrator,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use strata_bridge_db::persistent::sqlite::SqliteDb;
use strata_bridge_p2p_service::{
    bootstrap as p2p_bootstrap, Configuration as P2PConfiguration, MessageHandler,
};
use strata_p2p_types::P2POperatorPubKey;
use tokio::{spawn, task::JoinHandle, try_join};
use tracing::info;

use crate::{
    config::{Config, P2PConfig, SecretServiceConfig},
    params::Params,
    rpc_server::{start_rpc, BridgeRpc},
};

/// Bootstraps the bridge client in Operator mode by hooking up all the required auxiliary services
/// including database, rpc server, etc.
pub(crate) async fn bootstrap(params: Params, config: Config) -> anyhow::Result<()> {
    info!("bootstrapping operator node");

    let s2_client = init_secret_service_client(&config.secret_service_client).await;

    let sk = s2_client
        .p2p_signer()
        .secret_key()
        .await
        .map_err(|e| anyhow!("error while asking for p2p key: {e:?}"))?;

    info!(
        "Retrieved P2P secret key from S2: {sk_fingerprint:?}",
        sk_fingerprint = sk
    );

    let message_handler = init_p2p_msg_handler(&config, &params, sk).await?;

    let db = init_database_handle(&config).await;
    let db_rpc = db.clone();

    init_duty_tracker(&params, &config, s2_client, message_handler, db);

    let rpc_address = config.rpc_addr.clone();
    let rpc_task = start_rpc_server(rpc_address, db_rpc, params.clone()).await?;

    // Wait for all tasks to run
    // They are supposed to run indefinitely in most cases
    // TODO: add duty tracker task
    try_join!(rpc_task)?;

    Ok(())
}

async fn init_secret_service_client(config: &SecretServiceConfig) -> SecretServiceClient {
    let key = fs::read(&config.key).expect("readable key");
    let key = if config.key.extension().is_some_and(|x| x == "der") {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key))
    } else {
        rustls_pemfile::private_key(&mut &*key)
            .expect("valid PEM-encoded private key")
            .expect("non-empty private key")
    };
    let certs = read_cert(&config.cert).expect("valid cert");

    let ca_certs = read_cert(&config.service_ca).expect("valid CA cert");
    let mut root_store = RootCertStore::empty();
    let (added, ignored) = root_store.add_parsable_certificates(ca_certs);
    debug!("loaded {added} certs for the secret service CA, ignored {ignored}");

    let tls_client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)
        .expect("good client config");

    let s2_config = secret_service_client::Config {
        // fixme: use dns lookup
        server_addr: config.server_addr.parse().expect("invalid server address"),
        server_hostname: config.server_hostname.clone(),
        local_addr: None,
        tls_config: tls_client_config,
        timeout: Duration::from_secs(config.timeout),
    };
    SecretServiceClient::new(s2_config)
        .await
        .expect("good client")
}

/// Reads a certificate from a file.
fn read_cert(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let cert_chain = fs::read(path)?;
    if path.extension().is_some_and(|x| x == "der") {
        Ok(vec![CertificateDer::from(cert_chain)])
    } else {
        rustls_pemfile::certs(&mut &*cert_chain).collect()
    }
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

async fn init_database_handle(config: &Config) -> SqliteDb {
    const DB_NAME: &str = "bridge.db";

    let datadir = &config.datadir;
    let db_path = create_db_file(datadir, DB_NAME);

    let connect_options = SqliteConnectOptions::new()
        .filename(db_path)
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal);

    let pool_options = SqlitePoolOptions::new();

    let pool = pool_options
        .connect_with(connect_options)
        .await
        .expect("should be able to connect to db");

    let current_dir = env::current_dir().expect("should be able to get current working directory");
    let migrations_path = current_dir.join("migrations");

    let migrator = Migrator::new(migrations_path)
        .await
        .expect("should be able to initialize migrator");

    info!(action = "running migrations", %DB_NAME);
    migrator
        .run(&pool)
        .await
        .expect("should be able to run migrations");

    SqliteDb::new(pool)
}

fn create_db_file(datadir: impl AsRef<Path>, db_name: &str) -> PathBuf {
    if !datadir.as_ref().exists() {
        fs::create_dir_all(datadir.as_ref())
            .map_err(|e| {
                panic!(
                    "could not create datadir at {:?} due to {}",
                    datadir.as_ref().canonicalize(),
                    e
                );
            })
            .unwrap();
    }

    let db_path = datadir.as_ref().join(db_name);

    if !db_path.exists() {
        fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false) // don't overwrite the file
            .open(db_path.as_path())
            .map_err(|e| {
                panic!(
                    "could not create db at {:?} due to {}",
                    db_path.to_string_lossy(),
                    e
                );
            })
            .unwrap();
    }

    db_path
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

async fn start_rpc_server(
    rpc_address: String,
    db: SqliteDb,
    params: Params,
) -> anyhow::Result<JoinHandle<()>> {
    let rpc_client = BridgeRpc::new(db, params);
    let handle = spawn(async move {
        start_rpc(&rpc_client, rpc_address.as_str())
            .await
            .expect("failed to start RPC server");
    });
    Ok(handle)
}
