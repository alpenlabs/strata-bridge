//! Defines the main loop for the bridge-client in operator mode.
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::anyhow;
use bdk_bitcoind_rpc::bitcoincore_rpc::{self, RpcApi};
use bitcoin::{
    consensus,
    hashes::Hash,
    secp256k1::SecretKey,
    sighash::{Prevouts, SighashCache, TapSighashType},
    FeeRate, OutPoint, TxOut,
};
use libp2p::{
    identity::{secp256k1::PublicKey as LibP2pSecpPublicKey, PublicKey as LibP2pPublicKey},
    PeerId,
};
use operator_wallet::{sync::Backend, OperatorWallet, OperatorWalletConfig};
use secp256k1::SECP256K1;
use secret_service_client::{
    rustls::{
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        ClientConfig, RootCertStore,
    },
    SecretServiceClient,
};
use secret_service_proto::v1::traits::{Musig2Signer, P2PSigner, SecretService, WalletSigner};
use sqlx::{
    migrate::Migrator,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use strata_bridge_db::{persistent::sqlite::SqliteDb, public::PublicDb};
use strata_bridge_p2p_service::{
    bootstrap as p2p_bootstrap, Configuration as P2PConfiguration, MessageHandler,
};
use strata_bridge_primitives::constants::SEGWIT_MIN_AMOUNT;
use strata_bridge_stake_chain::prelude::OPERATOR_FUNDS;
use strata_p2p::swarm::handle::P2PHandle;
use strata_p2p_types::P2POperatorPubKey;
use tokio::{spawn, task::JoinHandle, try_join};
use tracing::{debug, info};

use crate::{
    config::{Config, P2PConfig, SecretServiceConfig},
    params::Params,
    rpc_server::{start_rpc, BridgeRpc},
};

/// Bootstraps the bridge client in Operator mode by hooking up all the required auxiliary services
/// including database, rpc server, etc.
pub(crate) async fn bootstrap(params: Params, config: Config) -> anyhow::Result<()> {
    info!("bootstrapping operator node");

    // Secret Service stuff.
    info!("initializing the secret service client");
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

    // Database instances.
    let db = init_database_handle(&config).await;
    let db_rpc = db.clone();

    // BitcoinD RPC client for the Operator Wallet.
    let auth = bitcoincore_rpc::Auth::UserPass(
        config.btc_client.user.to_string(),
        config.btc_client.pass.to_string(),
    );
    let bitcoin_rpc_client = Arc::new(
        bitcoincore_rpc::Client::new(config.btc_client.url.as_str(), auth)
            .expect("should be able to create bitcoin client"),
    );
    info!(?bitcoin_rpc_client, "bitcoin rpc client");

    // Operator wallet stuff.
    let general_key = s2_client.general_wallet_signer().pubkey().await?;
    info!(%general_key, "operator wallet general key");
    let stakechain_key = s2_client.stakechain_wallet_signer().pubkey().await?;
    info!(%stakechain_key, "operator wallet stakechain key");
    let my_key = s2_client.musig2_signer().pubkey().await?;
    info!(%my_key, "MuSig2 operator key");
    let my_index = params
        .keys
        .musig2
        .iter()
        .position(|k| k == &my_key)
        .expect("should be able to find my index");
    info!(%my_index, "my index");
    let operator_wallet_config = OperatorWalletConfig::new(
        OPERATOR_FUNDS,
        // NOTE: 32 seems an OK-ish pool size for the operator wallet.
        //       These will be refilled that's why its a 'pool'.
        32,
        SEGWIT_MIN_AMOUNT,
        params.stake_chain.stake_amount,
        params.network,
    );

    let sync_backend = Backend::BitcoinCore(bitcoin_rpc_client.clone());
    info!(?sync_backend, "operator wallet sync backend");
    let mut operator_wallet = OperatorWallet::new(
        general_key,
        stakechain_key,
        operator_wallet_config,
        sync_backend,
    );
    info!(?operator_wallet, "created operator wallet");

    // Handle the pre-stake tx.
    if db
        .get_pre_stake(my_index as u32)
        .await
        .expect("should be able to consult the database")
        .is_none()
    {
        // This means that we don't have a pre-stake tx in the database.
        // We need to create a pre-stake tx, sign it, broadcast it and save it to the database.
        info!("no pre-stake tx in the database, creating one");
        // BitcoinD is ancient technology, so we need to convert the fee rate estimate to a proper
        // FeeRate.
        let fee_rate = bitcoin_rpc_client
            .estimate_smart_fee(1, None)
            .expect("should be able to get the fee rate estimate")
            .fee_rate
            .and_then(|per_kw| per_kw.checked_div(1_000))
            .and_then(|per_vb| FeeRate::from_sat_per_vb(per_vb.to_sat()))
            .unwrap_or(FeeRate::from_sat_per_vb_unchecked(3));

        info!(?fee_rate, "fee rate");

        // We need to sync the wallet.
        info!("syncing the operator wallet");
        operator_wallet
            .sync()
            .await
            .expect("should be able to sync the wallet");
        info!("synced the operator wallet");

        // Create the PreStake tx.
        let pre_stake_psbt = operator_wallet
            .create_prestake_tx(fee_rate)
            .expect("should be able to create the pre-stake tx");
        // Get the unsigned pre-stake tx.
        let pre_stake_tx = pre_stake_psbt.unsigned_tx;
        let pre_stake_txid = pre_stake_tx.compute_txid();
        info!(%pre_stake_txid, "created the pre-stake tx");

        // Collect all the UTXOs in the stakechain wallet that match the pre-stake tx inputs.
        const VOUT: u32 = 0;
        let general_wallet = operator_wallet.general_wallet();
        let prevouts = pre_stake_tx
            .input
            .iter()
            .map(|i| {
                let outpoint = i.previous_output;
                info!(?outpoint, "outpoint");
                general_wallet
                    .get_utxo(outpoint)
                    .expect("should be able to get the outpoint")
                    .txout
            })
            .collect::<Vec<TxOut>>();
        info!(?prevouts, "prevouts");
        let prevouts = Prevouts::All(&prevouts);
        let mut sighasher = SighashCache::new(pre_stake_tx);
        let sighash = sighasher
            .taproot_key_spend_signature_hash(VOUT as usize, &prevouts, TapSighashType::Default)
            .expect("must be able to compute the sighash");

        // Sign the pre-stake tx.
        let signature = s2_client
            .general_wallet_signer()
            .sign(&sighash.to_byte_array(), None)
            .await?;

        // let signature = taproot::Signature {
        //     signature,
        //     sighash_type: TapSighashType::Default,
        // };
        sighasher
            .witness_mut(0)
            .expect("must be able to get the witness")
            .push(signature.serialize());
        let signed_pre_stake_tx = sighasher.into_transaction();
        info!(%pre_stake_txid, "signed the pre-stake tx");
        info!(signed_pre_stake_tx = %consensus::encode::serialize_hex(&signed_pre_stake_tx), "signed pre-stake tx");
        dbg!(&signed_pre_stake_tx);

        // Broadcast the pre-stake tx.
        bitcoin_rpc_client
            .send_raw_transaction(&signed_pre_stake_tx)
            .expect("should be able to broadcast the pre-stake tx");
        info!(%pre_stake_txid, "broadcasted the pre-stake tx");

        // Save the pre-stake tx to the database.
        let pre_stake_outpoint = OutPoint {
            txid: pre_stake_txid,
            vout: VOUT,
        };
        db.set_pre_stake(my_index as u32, pre_stake_outpoint)
            .await
            .expect("should be able to save the pre-stake tx to the database");
        info!(%pre_stake_txid, "saved the pre-stake tx to the database");
    }

    // P2P message handler.
    let (message_handler, p2p_task) = init_p2p_msg_handler(&config, &params, sk).await?;
    info!(?message_handler, "initialized the P2P message handler");
    let p2p_handle_rpc = message_handler.handle.clone();

    // Initialize the duty tracker.
    info!("initializing the duty tracker");
    init_duty_tracker(
        &params,
        &config,
        s2_client,
        message_handler,
        operator_wallet,
        db,
    );
    info!("initialized the duty tracker");

    info!("starting the RPC server");
    let rpc_address = config.rpc_addr.clone();
    let rpc_task = start_rpc_server(rpc_address, db_rpc, p2p_handle_rpc, params.clone()).await?;
    info!("started the RPC server");

    // Wait for all tasks to run
    // They are supposed to run indefinitely in most cases
    try_join!(rpc_task, p2p_task)?;

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
) -> anyhow::Result<(MessageHandler, JoinHandle<()>)> {
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
    let (p2p_handle, _cancel, listen_task) = p2p_bootstrap(&config).await?;
    Ok((MessageHandler::new(p2p_handle), listen_task))
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
    info!(?migrations_path, "migrations path");
    info!(exists = %migrations_path.exists(), "migrations path exists");

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
    _operator_wallet: OperatorWallet,
    _db: SqliteDb,
) {
    unimplemented!("@ProofOfKeags");
}

async fn start_rpc_server(
    rpc_address: String,
    db: SqliteDb,
    p2p_handle: P2PHandle,
    params: Params,
) -> anyhow::Result<JoinHandle<()>> {
    let rpc_client = BridgeRpc::new(db, p2p_handle, params);
    let handle = spawn(async move {
        start_rpc(&rpc_client, rpc_address.as_str())
            .await
            .expect("failed to start RPC server");
    });
    Ok(handle)
}
