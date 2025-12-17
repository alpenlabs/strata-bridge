//! Defines the main loop for the bridge-client in operator mode.
use std::{
    collections::{BTreeSet, VecDeque},
    env, fs, io,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, Context};
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
use btc_tracker::client::BtcNotifyClient;
use duty_tracker::{
    contract_manager::ContractManager, contract_persister::ContractPersister,
    shutdown::ShutdownHandler, stake_chain_persister::StakeChainPersister,
};
use libp2p::{
    identity::{secp256k1::PublicKey as LibP2pSecpPublicKey, PublicKey as LibP2pPublicKey},
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
use secret_service_proto::v2::traits::{P2PSigner, SchnorrSigner, SecretService};
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
use strata_tasks::TaskExecutor;
use tokio::{net::lookup_host, select, sync::mpsc, task::JoinHandle};
use tracing::{debug, error, info};

use crate::{
    config::{Config, P2PConfig, SecretServiceConfig},
    params::Params,
    rpc_server::{start_rpc, BridgeRpc},
};

/// Bootstraps the bridge client in Operator mode by hooking up all the required auxiliary services
/// including database, rpc server, graceful shutdown handler, etc.
pub(crate) async fn bootstrap(
    params: Params,
    config: Config,
    executor: TaskExecutor,
) -> anyhow::Result<()> {
    debug!("bootstrapping operator node");

    // Secret Service stuff.
    debug!("initializing secret service client (s2)");
    let s2_client = init_secret_service_client(&config.secret_service_client).await;
    let p2p_sk = s2_client
        .p2p_signer()
        .secret_key()
        .await
        .map_err(|e| anyhow!("error while requesting p2p key: {e:?}"))?;
    debug!(key = ?p2p_sk, "p2p secret key");
    let p2p_pk = p2p_sk.public_key(SECP256K1);
    info!(key=%p2p_pk, "p2p public key");

    let my_btc_pk = s2_client.musig2_signer().pubkey().await?;
    info!(key=%my_btc_pk, "musig2 public key");

    let pks = params
        .keys
        .musig2
        .iter()
        .map(|k| k.public_key(Parity::Even))
        .collect::<Vec<_>>();
    let aggregated_xonly_pubkey: XOnlyPublicKey =
        KeyAggContext::new(pks).unwrap().aggregated_pubkey();
    info!(key=%aggregated_xonly_pubkey, "aggregated musig2 bridge key");

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
    let p2p_keys = params.keys.p2p.iter().cloned().map(P2POperatorPubKey::from);
    let musig_keys = params
        .keys
        .musig2
        .iter()
        .cloned()
        .map(|x| x.public_key(Parity::Even));
    let zipped = p2p_keys.zip(musig_keys);
    let indexed = zipped.enumerate().map(|(i, (op, btc))| (i as u32, op, btc));
    let operator_table = OperatorTable::new(
        indexed.collect(),
        OperatorTable::select_btc_x_only(my_btc_pk),
    )
    .context("could not build OperatorTable")?;

    let leased = StakeChainPersister::new(db.clone())
        .await?
        .load(&operator_table)
        .await?
        .get(operator_table.pov_p2p_key())
        .map_or(BTreeSet::new(), |inputs| {
            inputs
                .stake_inputs
                .values()
                .map(|x| x.operator_funds)
                .collect()
        });
    let mut operator_wallet =
        init_operator_wallet(&config, &params, s2_client.clone(), leased).await?;

    // Get the operator's key index.
    let my_index = params
        .keys
        .musig2
        .iter()
        .position(|k| k == &my_btc_pk)
        .expect("should be able to find my index") as u32;

    // Initialize the P2P handle.
    info!("initializing p2p handle");
    let (p2p_handle, p2p_task) = init_p2p_handle(&config, &params, p2p_sk).await?;
    debug!("p2p handle initialized");
    let p2p_handle_rpc = p2p_handle.clone();

    // Handle the stakechain genesis.
    handle_stakechain_genesis(
        db_stakechain,
        s2_client.clone(),
        &mut operator_wallet,
        my_index,
        Arc::new(bitcoin_rpc_client.clone()),
    )
    .await;

    // We have no awareness of what blocks are unburied at startup, so we start with an empty list.
    let unburied_blocks = VecDeque::new();
    // Initialize the duty tracker.
    info!("initializing contract manager");
    let zmq_client = BtcNotifyClient::new(&config.btc_zmq, unburied_blocks);

    let pre_stake_pubkey = operator_wallet.stakechain_script_buf();
    let (contract_manager, contract_persister, stake_chain_persister) = init_duty_tracker(
        &params,
        &config,
        operator_table,
        pre_stake_pubkey.clone(),
        bitcoin_rpc_client.clone(),
        zmq_client,
        s2_client,
        p2p_handle,
        operator_wallet,
        db,
    )
    .await?;
    debug!("contract manager initialized");

    // Create shutdown handler for graceful shutdown.
    let shutdown_handler = ShutdownHandler::new(contract_persister, stake_chain_persister);

    info!("starting rpc server");
    let rpc_config = config.rpc.clone();
    let rpc_params = params.clone();
    let rpc_addr = rpc_config.rpc_addr.clone();
    executor.spawn_critical_async_with_shutdown("rpc_server", |_| async move {
        let rpc_client = BridgeRpc::new(db_rpc, p2p_handle_rpc, rpc_params, rpc_config);
        start_rpc(&rpc_client, rpc_addr.as_str()).await
    });
    debug!("rpc server started");

    info!("starting p2p service");
    executor.spawn_critical_async_with_shutdown("p2p_service", |_| async move {
        p2p_task.await.map_err(anyhow::Error::from)
    });
    debug!("p2p service started");

    info!("starting contract manager");
    let shutdown_timeout = config.shutdown_timeout;
    executor.spawn_critical_async_with_shutdown("contract_manager", |shutdown_guard| async move {
        let mut contract_manager = contract_manager;

        // Race between shutdown signal and contract manager completion
        select! {
            // Handle shutdown signal.
            _ = shutdown_guard.wait_for_shutdown() => {
                info!("shutdown signal received, initiating graceful shutdown");

                // Extract execution state and persist before shutdown.
                match contract_manager.shutdown_and_extract_state().await {
                    Ok(execution_state) => {
                        info!("extracted execution state, persisting before shutdown");
                        match shutdown_handler
                            .persist_state_before_shutdown(
                                &execution_state,
                                &shutdown_guard,
                                shutdown_timeout,
                            )
                            .await
                        {
                            Ok(()) => info!("successfully persisted state before shutdown"),
                            Err(e) => error!("failed to persist state before shutdown: {e:?}"),
                        }
                    }
                    Err(e) => error!("failed to extract execution state: {e:?}"),
                }
                Ok(())
            }

            // Handle contract manager completion (this should indicate an error)
            result = &mut contract_manager.thread_handle => {
                match result {
                    Ok(e) => {
                        error!("contract manager failed: {e:?}");
                        Err(anyhow::Error::from(e))
                    }
                    Err(e) => {
                        error!("contract manager panicked: {e:?}");
                        Err(anyhow::Error::from(e))
                    }
                }
            }
        }
    });
    debug!("contract manager started");

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
    debug!(?migrations_path, "migrations path");
    debug!(exists = %migrations_path.exists(), "migrations path exists");

    let migrator = Migrator::new(migrations_path)
        .await
        .expect("should be able to initialize migrator");

    info!(%DB_NAME, "running migrations");
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
    operator_table: OperatorTable,
    pre_stake_pubkey: ScriptBuf,
    rpc_client: BitcoinClient,
    zmq_client: BtcNotifyClient,
    s2_client: SecretServiceClient,
    p2p_handle: P2PHandle,
    operator_wallet: OperatorWallet,
    db: SqliteDb,
) -> anyhow::Result<(ContractManager, ContractPersister, StakeChainPersister)> {
    let network = params.network;
    let nag_interval = config.nag_interval;
    let connector_params = params.connectors;
    let pegout_graph_params = params.tx_graph;
    let stake_chain_params = params.stake_chain;
    let sidesystem_params = params.sidesystem.clone();

    let db_pool = db.pool().clone();
    info!("initializing contract persister");
    let contract_persister = ContractPersister::new(db_pool.clone(), config.db).await?;
    debug!("contract persister initialized");

    info!("initializing stake chain persister");
    let stake_chain_persister = StakeChainPersister::new(db.clone()).await?;
    debug!("stake chain persister initialized");

    // Create separate persisters for shutdown handler since they don't implement Clone
    info!("initializing shutdown persisters");
    let shutdown_contract_persister = ContractPersister::new(db_pool.clone(), config.db).await?;
    let shutdown_stake_chain_persister = StakeChainPersister::new(db.clone()).await?;
    debug!("shutdown persisters initialized");

    let contract_manager = ContractManager::new(
        network,
        nag_interval,
        connector_params,
        pegout_graph_params,
        stake_chain_params,
        sidesystem_params,
        operator_table,
        config.is_faulty,
        config.min_withdrawal_fulfillment_window,
        config.stake_funding_pool_size,
        config.stake_tx,
        pre_stake_pubkey,
        zmq_client,
        rpc_client,
        p2p_handle,
        contract_persister,
        stake_chain_persister,
        s2_client,
        operator_wallet,
        db,
    );

    Ok((
        contract_manager,
        shutdown_contract_persister,
        shutdown_stake_chain_persister,
    ))
}

/// Initializes the operator wallet
async fn init_operator_wallet(
    config: &Config,
    params: &Params,
    s2_client: SecretServiceClient,
    leased_outpoints: BTreeSet<OutPoint>,
) -> anyhow::Result<OperatorWallet> {
    info!("initializing operator wallet");

    // BitcoinD RPC client for the Operator Wallet.
    let auth = bitcoincore_rpc::Auth::UserPass(
        config.btc_client.user.to_string(),
        config.btc_client.pass.to_string(),
    );
    let bitcoin_rpc_client = Arc::new(
        bitcoincore_rpc::Client::new(config.btc_client.url.as_str(), auth)
            .expect("should be able to create bitcoin client"),
    );
    debug!(?bitcoin_rpc_client, "bitcoin rpc client");

    // Operator wallet stuff.
    let general_key = s2_client.general_wallet_signer().pubkey().await?;
    info!(%general_key, "operator wallet general key");
    let stakechain_key = s2_client.stakechain_wallet_signer().pubkey().await?;
    info!(%stakechain_key, "operator wallet stakechain key");
    let operator_wallet_config = OperatorWalletConfig::new(
        OPERATOR_FUNDS,
        SEGWIT_MIN_AMOUNT,
        params.stake_chain.stake_amount,
        params.network,
    );
    debug!(?operator_wallet_config, "operator wallet config");

    let sync_backend = Backend::BitcoinCore(bitcoin_rpc_client.clone());
    debug!(?sync_backend, "operator wallet sync backend");
    let operator_wallet = OperatorWallet::new(
        general_key,
        stakechain_key,
        operator_wallet_config,
        sync_backend,
        leased_outpoints,
    );
    debug!("operator wallet initialized");

    Ok(operator_wallet)
}

/// Handles the stakechain genesis.
///
/// If the pre-stake tx is not in the database, this function will create a pre-stake tx, sign it,
/// broadcast it and save it to the database.
async fn handle_stakechain_genesis(
    db: SqliteDb,
    s2_client: SecretServiceClient,
    operator_wallet: &mut OperatorWallet,
    my_index: OperatorIdx,
    bitcoin_rpc_client: Arc<BitcoinClient>,
) {
    // the ouroboros sender is part of the message handler interface but is unused when sending
    // stakechain genesis information.
    let (ouroboros_msg_sender, _ouroboros_msg_receiver) = mpsc::unbounded_channel();
    let (ouroboros_req_sender, _ouroboros_req_receiver) = mpsc::unbounded_channel();
    let message_handler = MessageHandler::new(ouroboros_msg_sender, ouroboros_req_sender);
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
        info!("pre-stake tx not found, creating...");

        let fee_rate = bitcoin_rpc_client
            .estimate_smart_fee(1)
            .await
            .expect("should be able to get the fee rate estimate");

        let fee_rate =
            FeeRate::from_sat_per_vb(fee_rate).expect("should be able to create a fee rate");

        debug!(%fee_rate, "fetched fee rate from bitcoin client");

        // We need to sync the wallet.
        info!("syncing operator wallet");
        operator_wallet
            .sync()
            .await
            .expect("should be able to sync the wallet");
        debug!("operator wallet synced");

        // Create the PreStake tx.
        let pre_stake_psbt = operator_wallet
            .create_prestake_tx(fee_rate)
            .expect("should be able to create the pre-stake tx");
        // Get the unsigned pre-stake tx.
        let pre_stake_tx = pre_stake_psbt.unsigned_tx;
        let pre_stake_txid = pre_stake_tx.compute_txid();
        debug!(%pre_stake_txid, "pre-stake tx created");

        // Collect all the UTXOs in the stakechain wallet that match the pre-stake tx inputs.
        let general_wallet = operator_wallet.general_wallet();
        let txins_as_outs = pre_stake_tx
            .input
            .iter()
            .map(|i| {
                let outpoint = i.previous_output;
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
        debug!(%pre_stake_txid, "pre-stake tx signed");

        // Broadcast the pre-stake tx.
        info!(%pre_stake_txid, "broadcasting pre-stake tx");
        bitcoin_rpc_client
            .send_raw_transaction(&signed_pre_stake_tx)
            .await
            .expect("should be able to broadcast the pre-stake tx");
        debug!(%pre_stake_txid, "pre-stake tx broadcasted");

        // Save the pre-stake tx to the database.
        info!(%pre_stake_txid, "committing pre-stake tx");
        let pre_stake_outpoint = OutPoint {
            txid: pre_stake_txid,
            vout: 0, // NOTE: the protocol specifies that the s_connector vout is 0
        };
        db.set_pre_stake(my_index, pre_stake_outpoint)
            .await
            .expect("should be able to save the pre-stake tx to the database");
        debug!(%pre_stake_txid, "pre-stake tx committed");

        let stake_chain_id = StakeChainId::from_bytes([0u8; 32]);
        info!(%stake_chain_id, "broadcasting pre-stake information");
        message_handler
            .send_stake_chain_exchange(stake_chain_id, general_key, pre_stake_txid, 0)
            .await;
        debug!(%stake_chain_id, "pre-stake information broadcasted");
    }
}
