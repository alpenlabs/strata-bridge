//! Module to bootstrap the operator node by hooking up all the required services.

use std::{fs, sync::Arc};

use bitcoin::{Address, Network, Txid};
use jsonrpsee::ws_client::WsClientBuilder;
use rand::{rngs::OsRng, Rng};
use secp256k1::{Keypair, SECP256K1};
use strata_bridge_agent::{
    base::Agent,
    bitcoin_watcher::BitcoinWatcher,
    duty_watcher::{DutyWatcher, DutyWatcherConfig},
    operator::Operator,
    signal::{CovenantNonceSignal, CovenantSignatureSignal, DepositSignal},
    verifier::{Verifier, VerifierDuty},
};
use strata_bridge_btcio::{traits::Reader, BitcoinClient};
use strata_bridge_db::persistent::sqlite::SqliteDb;
use strata_bridge_primitives::{
    build_context::{BuildContext, TxBuildContext},
    duties::{BridgeDuty, BridgeDutyStatus},
    types::PublickeyTable,
};
use strata_rpc::StrataApiClient;
use tokio::{
    sync::{broadcast, mpsc},
    task::JoinSet,
};
use tracing::{debug, error, info};

use crate::{
    cli::Cli,
    constants::{
        BITCOIN_BLOCK_TRACKER_DB_NAME, COVENANT_QUEUE_MULTIPLIER, DEPOSIT_QUEUE_MULTIPLIER,
        DUTY_QUEUE_SIZE, DUTY_TRACKER_DB_NAME, OPERATOR_DB_PREFIX, PUBLIC_DB_NAME,
        VERIFIER_DUTY_QUEUE_SIZE,
    },
    db::create_db,
    rpc_server::{self, BridgeRpc},
    xpriv::get_keypairs_and_load_xpriv,
};

pub(crate) async fn bootstrap(args: Cli) {
    // instantiate RPC client for Strata and Bitcoin
    let strata_rpc_client = WsClientBuilder::default()
        .request_timeout(args.strata_ws_timeout)
        .build(args.strata_url.as_str())
        .await
        .expect("failed to connect to the strata RPC server");

    let bitcoin_rpc_client = Arc::new(
        BitcoinClient::new(&args.btc_url, &args.btc_user, &args.btc_pass)
            .expect("should be able to create bitcoin client"),
    );

    // create dbs
    let duty_tracker_db = Arc::new(create_db(args.data_dir.as_path(), DUTY_TRACKER_DB_NAME).await);
    let btc_block_tracker_db =
        create_db(args.data_dir.as_path(), BITCOIN_BLOCK_TRACKER_DB_NAME).await;
    let public_db = create_db(args.data_dir.as_path(), PUBLIC_DB_NAME).await;

    let network = bitcoin_rpc_client
        .network()
        .await
        .expect("should be able to get network information");

    debug!(action = "querying for operator pubkey set");
    let pubkey_table = strata_rpc_client
        .get_active_operator_chain_pubkey_set()
        .await
        .expect("should be able to fetch pubkey table");

    let duty_watcher_config = DutyWatcherConfig {
        poll_interval: args.duty_interval,
    };

    let mut duty_watcher = DutyWatcher::new(
        duty_watcher_config,
        Arc::new(strata_rpc_client),
        duty_tracker_db.clone(),
    );

    let (duty_sender, _duty_receiver) = broadcast::channel::<BridgeDuty>(DUTY_QUEUE_SIZE);
    let (duty_status_sender, duty_status_receiver) =
        mpsc::channel::<(Txid, BridgeDutyStatus)>(DUTY_QUEUE_SIZE);

    // initialize public database
    let public_db = Arc::new(public_db);
    debug!(event = "initialized public db");

    let operators: Vec<Operator<SqliteDb, SqliteDb, SqliteDb>> = generate_operator_set(
        &args,
        pubkey_table.clone(),
        public_db.clone(),
        duty_tracker_db.clone(),
        duty_status_sender,
        network,
    )
    .await;

    let mut tasks = JoinSet::new();

    let duty_sender_copy = duty_sender.clone();
    info!(action = "starting duty watcher", poll_interval=?args.duty_interval);
    tasks.spawn(async move {
        duty_watcher
            .start(duty_sender_copy.clone(), duty_status_receiver)
            .await;
    });

    info!(action = "starting operators");
    for operator in operators {
        let mut duty_receiver = duty_sender.subscribe();

        tasks.spawn(async move {
            let mut operator = operator;
            operator.start(&mut duty_receiver).await;
        });
    }

    // spawn verifier and bitcoin watcher
    let (notification_sender, mut notification_receiver) =
        broadcast::channel::<VerifierDuty>(VERIFIER_DUTY_QUEUE_SIZE);

    let bitcoin_tracker_db = Arc::new(btc_block_tracker_db);

    let bitcoin_watcher = BitcoinWatcher::new(
        bitcoin_tracker_db,
        public_db.clone(),
        bitcoin_rpc_client.clone(),
        args.btc_scan_interval,
        args.btc_genesis_height,
    );

    let keypair = Keypair::new(SECP256K1, &mut rand::thread_rng());
    let agent = Agent::new(
        keypair,
        &args.btc_url,
        &args.btc_user,
        &args.btc_pass,
        &args.strata_url,
        args.strata_ws_timeout,
    )
    .await;

    let verifier_build_context = TxBuildContext::new(network, pubkey_table, u32::MAX); // operator_id
                                                                                       // does not matter for verifier
    let mut verifier = Verifier::new(public_db.clone(), verifier_build_context, agent);

    tasks.spawn(async move {
        verifier.start(&mut notification_receiver).await;
    });

    tasks.spawn(async move { bitcoin_watcher.start(notification_sender).await });

    // spawn rpc server
    let bridge_rpc = BridgeRpc::new();

    let rpc_host = args.rpc_host.clone();
    let rpc_port = args.rpc_port;
    let rpc_addr = format!("{rpc_host}:{rpc_port}");

    info!(action = "starting rpc server");
    tasks.spawn(async move {
        if let Err(e) = rpc_server::start(&bridge_rpc, rpc_addr.as_str()).await {
            error!(error = %e, "could not start RPC server");
        }
    });

    tasks.join_all().await;
}

pub(crate) async fn generate_operator_set(
    args: &Cli,
    pubkey_table: PublickeyTable,
    public_db: Arc<SqliteDb>,
    duty_db: Arc<SqliteDb>,
    duty_status_sender: mpsc::Sender<(Txid, BridgeDutyStatus)>,
    network: Network,
) -> Vec<Operator<SqliteDb, SqliteDb, SqliteDb>> {
    let operator_indexes_and_keypairs =
        get_keypairs_and_load_xpriv(&args.xpriv_file, &pubkey_table);

    let msks = fs::read_to_string(&args.msks_file)
        .expect("must be able to read msks file")
        .lines()
        .map(|msk| msk.to_string())
        .collect::<Vec<_>>();

    let num_operators = pubkey_table.0.len();

    assert!(
        operator_indexes_and_keypairs.len() == num_operators,
        "operator count in strata and number of xprivs do not match"
    );

    assert!(
        msks.len() == num_operators,
        "operator count in strata and number of msks not match"
    );

    let deposit_queue_size = num_operators * DEPOSIT_QUEUE_MULTIPLIER; // buffer for nonces and signatures (overkill)
    let (deposit_signal_sender, _deposit_signal_receiver) =
        broadcast::channel::<DepositSignal>(deposit_queue_size);

    let covenant_queue_size = num_operators * COVENANT_QUEUE_MULTIPLIER; // higher 'cause nonces and signatures are sent in bulk
    let (covenant_nonce_signal_sender, _covenant_nonce_signal_receiver) =
        broadcast::channel::<CovenantNonceSignal>(covenant_queue_size);

    let (covenant_sig_signal_sender, _covenant_sig_signal_receiver) =
        broadcast::channel::<CovenantSignatureSignal>(covenant_queue_size);

    let mut faulty_idxs = Vec::new();
    let mut operator_set: Vec<Operator<SqliteDb, SqliteDb, SqliteDb>> =
        Vec::with_capacity(num_operators);

    for ((operator_idx, keypair), msk) in operator_indexes_and_keypairs.into_iter().zip(msks) {
        let agent = Agent::new(
            keypair,
            format!(
                "{}/wallet/{}_{}",
                &args.btc_url, &args.wallet_prefix, operator_idx,
            )
            .as_str(),
            &args.btc_user,
            &args.btc_pass,
            &args.strata_url,
            args.strata_ws_timeout,
        )
        .await;

        let build_context = TxBuildContext::new(network, pubkey_table.clone(), operator_idx);

        let aggregated_pubkey = build_context.aggregated_pubkey();
        let bridge_address = Address::p2tr(SECP256K1, aggregated_pubkey, None, network);
        info!(event = "build context initialized", %bridge_address, %network, %aggregated_pubkey);

        let is_faulty = OsRng.gen_ratio(args.fault_tolerance as u32, 100);

        if is_faulty {
            faulty_idxs.push(operator_idx);
        }

        let operator_db = create_db(
            args.data_dir.as_path(),
            format!("{}{}.db", OPERATOR_DB_PREFIX, build_context.own_index()).as_str(),
        )
        .await;
        let operator_db = Arc::new(operator_db);

        let operator = Operator {
            agent,
            build_context,
            is_faulty,
            msk,
            db: operator_db,
            public_db: public_db.clone(),
            duty_db: duty_db.clone(),
            btc_poll_interval: args.btc_scan_interval,

            duty_status_sender: duty_status_sender.clone(),
            deposit_signal_sender: deposit_signal_sender.clone(),
            deposit_signal_receiver: deposit_signal_sender.subscribe(),
            covenant_nonce_sender: covenant_nonce_signal_sender.clone(),
            covenant_nonce_receiver: covenant_nonce_signal_sender.subscribe(),
            covenant_sig_sender: covenant_sig_signal_sender.clone(),
            covenant_sig_receiver: covenant_sig_signal_sender.subscribe(),
        };

        operator_set.push(operator);
    }

    info!(event = "operator set initialization complete", %num_operators, num_faulty_operators=%faulty_idxs.len(), ?faulty_idxs);

    operator_set
}
