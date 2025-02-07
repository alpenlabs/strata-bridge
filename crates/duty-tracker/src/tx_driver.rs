use std::sync::Arc;

use bitcoin::{Block, Transaction, Txid};
use btc_notify::client::BtcZmqClient;
use futures::channel::oneshot;
use strata_btcio::rpc::{traits::BroadcasterRpc, BitcoinClient};
use tokio::{sync::Mutex, task::JoinHandle};

type DriveErr = Box<dyn std::error::Error>;

pub struct TxDriver {
    zmq_client: BtcZmqClient,
    rpc_client: BitcoinClient,
    jobs: Arc<Mutex<Vec<(Txid, usize, oneshot::Sender<Result<(), DriveErr>>)>>>,
    driver: JoinHandle<()>,
}

impl TxDriver {
    fn new(block_sub: btc_notify::Subscription<Block>, rpc_client: BitcoinClient) -> Self {
        tokio::task::spawn(async move {
            loop {
                select! {

                }
            }
        })
        TxDriver {
            zmq_client,
            rpc_client,
            jobs: Vec::new(),
        }
    }

    async fn drive(&self, tx: &Transaction, deadline: usize) -> Result<(), DriveErr> {
        let mut block_sub = self.zmq_client.subscribe_blocks().await;
        let mut tx_sub = self.zmq_client.subscribe_transactions(|a| a == tx).await;
        tokio::task::spawn(async move {
            loop {
                select! {}
            }
            let res = self.rpc_client.send_raw_transaction(tx).await?;
            Ok(())
        })
    }
}
