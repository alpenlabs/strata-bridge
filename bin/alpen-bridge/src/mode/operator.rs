//! Defines the main loop for the bridge-client in operator mode.
use std::{
    collections::VecDeque,
    env, fs, io,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::anyhow;
use bdk_bitcoind_rpc::bitcoincore_rpc;
use bitcoin::{
    hashes::Hash,
    secp256k1::SecretKey,
    sighash::{Prevouts, SighashCache, TapSighashType},
    FeeRate, OutPoint, ScriptBuf, TxOut, XOnlyPublicKey,
};
use bitcoind_async_client::{
    traits::{Broadcaster, Reader},
    Client as BitcoinClient,
};
use btc_notify::client::BtcZmqClient;
use duty_tracker::{
    contract_manager::ContractManager, contract_persister::ContractPersister,
    stake_chain_persister::StakeChainPersister, tx_driver::TxDriver,
};
use libp2p::{
    identity::{secp256k1::PublicKey as LibP2pSecpPublicKey, PublicKey as LibP2pPublicKey},
    multiaddr::Protocol,
    PeerId,
};
use musig2::KeyAggContext;
use operator_wallet::{sync::Backend, OperatorWallet, OperatorWalletConfig};
use secp256k1::{Parity, SECP256K1};
use secret_service_client::{
    rustls::{
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        ClientConfig, RootCertStore,
    },
    SecretServiceClient,
};
use secret_service_proto::v1::traits::{P2PSigner, SchnorrSigner, SecretService};
use sqlx::{
    migrate::Migrator,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use strata_bridge_db::{persistent::sqlite::SqliteDb, public::PublicDb};
use strata_bridge_p2p_service::{
    bootstrap as p2p_bootstrap, Configuration as P2PConfiguration, MessageHandler,
};
use strata_bridge_primitives::{
    constants::SEGWIT_MIN_AMOUNT, operator_table::OperatorTable, types::OperatorIdx,
};
use strata_bridge_stake_chain::prelude::OPERATOR_FUNDS;
use strata_p2p::swarm::handle::P2PHandle;
use strata_p2p_types::{P2POperatorPubKey, StakeChainId};
use tokio::{
    net::{lookup_host, TcpListener},
    spawn,
    sync::broadcast,
    task::JoinHandle,
    try_join,
};
use tracing::{debug, error, info};

use crate::{
    config::{Config, P2PConfig, RpcConfig, SecretServiceConfig},
    params::Params,
    rpc_server::{start_rpc, BridgeRpc},
};

/// Bootstraps the bridge client in Operator mode by hooking up all the required auxiliary services
/// including database, rpc server, etc.
pub(crate) async fn bootstrap(params: Params, config: Config) -> anyhow::Result<()> {
    info!("bootstrapping operator node");

    // Validate network configuration before starting services
    validate_network_config(&config).await?;

    // Secret Service stuff.
    info!("initializing the secret service client");
    let s2_client = init_secret_service_client(&config.secret_service_client).await;
    let p2p_sk = s2_client
        .p2p_signer()
        .secret_key()
        .await
        .map_err(|e| anyhow!("error while asking for p2p key: {e:?}"))?;
    info!(
        "Retrieved P2P secret key from S2: {sk_fingerprint:?}",
        sk_fingerprint = p2p_sk
    );
    let p2p_pk = p2p_sk.public_key(SECP256K1);
    info!(%p2p_pk, "Retrieved P2P public key from S2");

    let my_btc_pk = s2_client.musig2_signer().pubkey().await?;
    info!(%my_btc_pk, "Retrieved MuSig2 operator key from S2");

    let pks = params
        .keys
        .musig2
        .iter()
        .map(|k| k.public_key(Parity::Even))
        .collect::<Vec<_>>();
    let aggregated_xonly_pubkey: XOnlyPublicKey =
        KeyAggContext::new(pks).unwrap().aggregated_pubkey();
    info!(%aggregated_xonly_pubkey, "Aggregated MuSig2 bridge key");

    // Database instances.
    let db = init_database_handle(&config).await;
    let db_rpc = db.clone();
    let db_stakechain = db.clone();

    // Create the async BitcoinD RPC client.
    let bitcoin_rpc_client = BitcoinClient::new(
        config.btc_client.url.to_string(),
        config.btc_client.user.to_string(),
        config.btc_client.pass.to_string(),
        config.btc_client.retry_count,
        config.btc_client.retry_interval,
    )?;

    // Initialize the operator wallet.
    let mut operator_wallet = init_operator_wallet(&config, &params, s2_client.clone()).await?;

    // Get the operator's key index.
    let my_index = params
        .keys
        .musig2
        .iter()
        .position(|k| k == &my_btc_pk)
        .expect("should be able to find my index") as u32;

    // Initialize the P2P handle.
    let (p2p_handle, p2p_task) = init_p2p_handle(&config, &params, p2p_sk).await?;
    info!(?p2p_handle, "initialized the P2P handle");
    let p2p_handle_rpc = p2p_handle.clone();

    // Handle the stakechain genesis.
    handle_stakechain_genesis(
        db_stakechain,
        s2_client.clone(),
        p2p_handle.clone(),
        &mut operator_wallet,
        my_index,
        Arc::new(bitcoin_rpc_client.clone()),
    )
    .await;

    let current = bitcoin_rpc_client.get_block_count().await?;
    let bury_height = current.saturating_sub(config.btc_zmq.bury_depth() as u64);

    // we grab every block starting with the block after the bury_height all the way up to the
    // current height and place it in the unburied blocks queue.
    let mut unburied_blocks = VecDeque::new();
    for height in bury_height + 1..=current {
        unburied_blocks.push_front(bitcoin_rpc_client.get_block_at(height).await?);
    }
    // Initialize the duty tracker.
    info!("initializing the duty tracker with the contract manager");
    let zmq_client = BtcZmqClient::connect(&config.btc_zmq, unburied_blocks)
        .await
        .expect("should be able to connect to zmq");

    let pre_stake_pubkey = operator_wallet.stakechain_script_buf();
    let contract_manager_task = init_duty_tracker(
        &params,
        &config,
        pre_stake_pubkey.clone(),
        bitcoin_rpc_client.clone(),
        zmq_client,
        s2_client,
        p2p_handle,
        operator_wallet,
        db,
    )
    .await?;
    info!("initialized the contract manager");

    info!("starting the RPC server");
    let rpc_config = config.rpc.clone();
    let rpc_params = params.clone();
    let rpc_task = start_rpc_server(db_rpc, p2p_handle_rpc, rpc_params, rpc_config).await?;
    info!("started the RPC server");

    // Wait for all tasks to run
    // They are supposed to run indefinitely in most cases
    try_join!(rpc_task, p2p_task, contract_manager_task)?;

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

    let mut addrs = lookup_host(&config.server_addr)
        .await
        .expect("DNS resolution failed");

    let server_addr = addrs.next().expect("DNS resolved, but no addresses");

    let s2_config = secret_service_client::Config {
        server_addr,
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

/// Initialize the P2P handle.
///
/// Needs a secret key and configuration.
async fn init_p2p_handle(
    config: &Config,
    params: &Params,
    sk: SecretKey,
) -> anyhow::Result<(P2PHandle, JoinHandle<()>)> {
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
        dial_timeout,
        general_timeout,
        connection_check_interval,
    } = config.p2p.clone();

    let config = P2PConfiguration::new_with_secret_key(
        sk,
        idle_connection_timeout,
        listening_addr,
        allowlist,
        connect_to,
        signers_allowlist,
        num_threads,
        dial_timeout,
        general_timeout,
        connection_check_interval,
    );
    let (p2p_handle, _cancel, listen_task) = p2p_bootstrap(&config).await?;
    Ok((p2p_handle, listen_task))
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

/// Initializes the duty tracker by creating a new [`ContractManager`] task.
#[expect(clippy::too_many_arguments)]
async fn init_duty_tracker(
    params: &Params,
    config: &Config,
    pre_stake_pubkey: ScriptBuf,
    rpc_client: BitcoinClient,
    zmq_client: BtcZmqClient,
    s2_client: SecretServiceClient,
    p2p_handle: P2PHandle,
    operator_wallet: OperatorWallet,
    db: SqliteDb,
) -> anyhow::Result<JoinHandle<()>> {
    let network = params.network;
    let nag_interval = config.nag_interval;
    let connector_params = params.connectors;
    let pegout_graph_params = params.tx_graph;
    let stake_chain_params = params.stake_chain;
    let sidesystem_params = params.sidesystem.clone();
    let operator_table_entries: Vec<(u32, P2POperatorPubKey, secp256k1::PublicKey)> = params
        .keys
        .p2p
        .iter()
        .zip(params.keys.musig2.iter())
        .map(|(p2p_key, musig2_x_only_key)| {
            let p2p_key = P2POperatorPubKey::from(p2p_key.clone());
            let musig2_key = musig2_x_only_key.public_key(Parity::Even);
            (p2p_key, musig2_key)
        })
        .enumerate()
        .map(|(idx, (p2p, musig2))| (idx as u32, p2p, musig2))
        .collect();
    let my_btc_key = s2_client.musig2_signer().pubkey().await?;
    let my_idx = operator_table_entries
        .iter()
        .position(|(_, _, key)| key.x_only_public_key().0 == my_btc_key)
        .expect("should be able to find my index");
    let operator_table =
        OperatorTable::new(operator_table_entries, my_idx as u32).expect("my index exists");
    let tx_driver = TxDriver::new(zmq_client.clone(), rpc_client.clone()).await;

    info!("initializing the contract persister");
    let db_pool = db.pool().clone();
    let contract_persister = ContractPersister::new(db_pool, config.db).await?;

    info!("initializing the stake chain persister");
    let stake_chain_persister = StakeChainPersister::new(db.clone()).await?;

    Ok(ContractManager::new(
        network,
        nag_interval,
        connector_params,
        pegout_graph_params,
        stake_chain_params,
        sidesystem_params,
        operator_table,
        pre_stake_pubkey,
        zmq_client,
        rpc_client,
        tx_driver,
        p2p_handle,
        contract_persister,
        stake_chain_persister,
        s2_client,
        operator_wallet,
        db,
    ))
}

async fn start_rpc_server(
    db: SqliteDb,
    p2p_handle: P2PHandle,
    params: Params,
    config: RpcConfig,
) -> anyhow::Result<JoinHandle<()>> {
    let rpc_addr = config.rpc_addr.clone();
    let rpc_client = BridgeRpc::new(db, p2p_handle, params, config);
    let handle = spawn(async move {
        if let Err(e) = start_rpc(&rpc_client, rpc_addr.as_str()).await {
            error!(?e, "RPC server failed");
        }
    });
    Ok(handle)
}

/// Validates network configuration by checking port availability.
async fn validate_network_config(config: &Config) -> anyhow::Result<()> {
    info!("validating network configuration");

    // Check RPC server port availability
    let rpc_addr = &config.rpc.rpc_addr;
    match TcpListener::bind(rpc_addr).await {
        Ok(_) => {
            info!("RPC server port {} is available", rpc_addr);
            info!(%rpc_addr, "RPC server is available");
        }
        Err(e) => {
            return Err(anyhow!(
                "RPC server at {rpc_addr} is not available: {e}. \
                 This may indicate another bridge instance is running or a previous instance didn't shut down cleanly. \
                 Please check for conflicting processes on this port.",
            ));
        }
    }

    // Check P2P port availability (extract port from Multiaddr)
    let p2p_addr = &config.p2p.listening_addr;
    if let Some(tcp_component) = p2p_addr.iter().find_map(|component| {
        if let Protocol::Tcp(port) = component {
            Some(port)
        } else {
            None
        }
    }) {
        // Try to bind to the P2P port to check availability
        let p2p_bind_addr = format!("127.0.0.1:{tcp_component}");
        match TcpListener::bind(&p2p_bind_addr).await {
            Ok(_) => {
                info!(%tcp_component, "P2P server is available");
            }
            Err(e) => {
                return Err(anyhow!(
                    "P2P server port {tcp_component} is not available: {e}. \
                     This may indicate another bridge instance is running or a previous instance didn't shut down cleanly. \
                     Please check for conflicting processes on this port.",
                ));
            }
        }
    } else {
        info!("P2P listening address doesn't contain TCP port, skipping port validation");
    }

    info!("network configuration validation completed successfully");
    Ok(())
}

/// Initializes the operator wallet
async fn init_operator_wallet(
    config: &Config,
    params: &Params,
    s2_client: SecretServiceClient,
) -> anyhow::Result<OperatorWallet> {
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
    let operator_wallet_config = OperatorWalletConfig::new(
        OPERATOR_FUNDS,
        config.operator_wallet.stake_funding_pool_size,
        SEGWIT_MIN_AMOUNT,
        params.stake_chain.stake_amount,
        params.network,
    );

    let sync_backend = Backend::BitcoinCore(bitcoin_rpc_client.clone());
    info!(?sync_backend, "operator wallet sync backend");
    let operator_wallet = OperatorWallet::new(
        general_key,
        stakechain_key,
        operator_wallet_config,
        sync_backend,
    );
    info!(?operator_wallet, "created operator wallet");

    Ok(operator_wallet)
}

/// Handles the stakechain genesis.
///
/// If the pre-stake tx is not in the database, this function will create a pre-stake tx, sign it,
/// broadcast it and save it to the database.
async fn handle_stakechain_genesis(
    db: SqliteDb,
    s2_client: SecretServiceClient,
    p2p_handle: P2PHandle,
    operator_wallet: &mut OperatorWallet,
    my_index: OperatorIdx,
    bitcoin_rpc_client: Arc<BitcoinClient>,
) {
    // the ouroboros sender is part of the message handler interface but is unused when sending
    // stakechain genesis information.
    let (ouroboros_sender, _ouroboros_receiver) = broadcast::channel(1);
    let message_handler = MessageHandler::new(p2p_handle, ouroboros_sender);

    let general_key = s2_client
        .general_wallet_signer()
        .pubkey()
        .await
        .expect("must be able to get the pubkey from general wallet");

    if let Some(pre_stake) = db
        .get_pre_stake(my_index)
        .await
        .expect("should be able to consult the database")
    {
        let stake_chain_id = StakeChainId::from_bytes([0u8; 32]);
        info!(%stake_chain_id, "broadcasting pre-stake information");

        message_handler
            .send_stake_chain_exchange(stake_chain_id, general_key, pre_stake.txid, pre_stake.vout)
            .await;
    } else {
        // This means that we don't have a pre-stake tx in the database.
        // We need to create a pre-stake tx, sign it, broadcast it and save it to the database.
        info!("no pre-stake tx in the database, creating one");
        let fee_rate = bitcoin_rpc_client
            .estimate_smart_fee(1)
            .await
            .expect("should be able to get the fee rate estimate");

        let fee_rate =
            FeeRate::from_sat_per_vb(fee_rate).expect("should be able to create a fee rate");

        info!(%fee_rate, "fetched fee rate from bitcoin client");

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
        let general_wallet = operator_wallet.general_wallet();
        let txins_as_outs = pre_stake_tx
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
        let prevouts = Prevouts::All(&txins_as_outs);
        let mut sighasher = SighashCache::new(pre_stake_tx);
        // Sign all the inputs.
        for input in 0..txins_as_outs.len() {
            let sighash = sighasher
                .taproot_key_spend_signature_hash(input, &prevouts, TapSighashType::Default)
                .expect("must be able to compute the sighash");

            // Sign the pre-stake tx.
            let signature = s2_client
                .general_wallet_signer()
                .sign(&sighash.to_byte_array(), None)
                .await
                .expect("should be able to sign the pre-stake tx");

            sighasher
                .witness_mut(input)
                .expect("must be able to get the witness")
                .push(signature.serialize());
        }
        let signed_pre_stake_tx = sighasher.into_transaction();
        info!(%pre_stake_txid, "signed the pre-stake tx");

        // Broadcast the pre-stake tx.
        bitcoin_rpc_client
            .send_raw_transaction(&signed_pre_stake_tx)
            .await
            .expect("should be able to broadcast the pre-stake tx");
        info!(%pre_stake_txid, "broadcasted the pre-stake tx");

        // Save the pre-stake tx to the database.
        let pre_stake_outpoint = OutPoint {
            txid: pre_stake_txid,
            vout: 0, // NOTE: the protocol specifies that the s_connector vout is 0
        };
        db.set_pre_stake(my_index, pre_stake_outpoint)
            .await
            .expect("should be able to save the pre-stake tx to the database");
        info!(%pre_stake_txid, "saved the pre-stake tx to the database");

        let stake_chain_id = StakeChainId::from_bytes([0u8; 32]);
        info!(%stake_chain_id, "broadcasting pre-stake information");
        message_handler
            .send_stake_chain_exchange(stake_chain_id, general_key, pre_stake_txid, 0)
            .await;
    }
}
