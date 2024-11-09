use std::{sync::Arc, time::Duration};

use bitcoin::{Transaction, Txid};
use strata_bridge_btcio::{traits::Reader, BitcoinClient};
use strata_bridge_db::{connector_db::ConnectorDb, public::PublicDb};
use strata_bridge_tx_graph::transactions::constants::NUM_ASSERT_DATA_TX;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use crate::{operator::OperatorIdx, verifier::VerifierDuty};

#[derive(Debug, Clone)]
pub struct BitcoinWatcher {
    db: PublicDb,

    poll_interval: Duration,

    client: Arc<BitcoinClient>,

    genesis_height: u32,
}

impl BitcoinWatcher {
    pub fn new(
        db: PublicDb,
        client: Arc<BitcoinClient>,
        poll_interval: Duration,
        genesis_height: u32,
    ) -> Self {
        Self {
            db,
            client,
            poll_interval,
            genesis_height,
        }
    }

    pub async fn start(&self, notifier: broadcast::Sender<VerifierDuty>) {
        info!(action = "starting bitcoin watcher", %self.genesis_height);

        let mut height = self.genesis_height;
        loop {
            let block = self.client.get_block_at(height).await;

            if let Err(e) = block {
                if height % 1000 == 0 {
                    warn!(%e, %height, msg = "could not get block");
                }
                continue;
            }

            let block = block.unwrap();

            for tx in block.txdata {
                let txid = tx.compute_txid();

                if let Some((operator_idx, deposit_txid)) =
                    self.db.get_operator_and_deposit_for_claim(&txid).await
                {
                    info!(event = "noticed claim transaction", by_operator=%operator_idx, for_deposit_txid=%deposit_txid);

                    warn!(action = "not dispatching challenge duty for now as it is unimplemented");

                    // FIXME: uncomment when `handle_claim()` is updated
                    // let duty = self.handle_claim().await;
                    // debug!(action = "dispatching challenge duty for verifier", claim_txid=%txid);
                    // notifier
                    //     .send(duty)
                    //     .expect("should be able to send challenge duty to the verifier");
                } else if let Some((operator_idx, deposit_txid)) = self
                    .db
                    .get_operator_and_deposit_for_post_assert(&txid)
                    .await
                {
                    info!(event = "noticed post-assert transaction", by_operator=%operator_idx, for_deposit_txid=%deposit_txid);
                    let duty = self.handle_assertion(tx, operator_idx, deposit_txid).await;

                    debug!(action = "dispatching disprove duty for verifier", post_assert_txid=%txid);
                    notifier
                        .send(duty)
                        .expect("should be able to send disprove duty to the verifier");
                }
            }

            tokio::time::sleep(self.poll_interval).await;
            height += 1;

            if height % 10 == 0 {
                info!(event = "block scanned", cur_height=%height);
            }
        }
    }

    pub async fn handle_claim(&self) -> VerifierDuty {
        unimplemented!("challenge not supported yet");
    }

    pub async fn handle_assertion(
        &self,
        post_assert_tx: Transaction,
        operator_id: OperatorIdx,
        deposit_txid: Txid,
    ) -> VerifierDuty {
        let mut assert_data_txs = Vec::new();
        // skip the first input i.e., the stake
        for txin in post_assert_tx.input.iter().skip(1) {
            let txid = &txin.previous_output.txid;

            let tx = self
                .client
                .get_raw_transaction(txid, None)
                .await
                .expect("should be able to fetch post_assert tx");

            assert_data_txs.push(tx);
        }

        assert_eq!(
            assert_data_txs.len(),
            NUM_ASSERT_DATA_TX,
            "number of assert data txs must be as expected"
        );

        let assert_data_txs: [Transaction; NUM_ASSERT_DATA_TX] = assert_data_txs
            .try_into()
            .expect("the number of assert-data txs must match");

        let pre_assert_tx = self
            .client
            .get_raw_transaction(&assert_data_txs[0].input[0].previous_output.txid, None)
            .await
            .expect("should be able to get pre-assert tx");

        let claim_tx = self
            .client
            .get_raw_transaction(&pre_assert_tx.input[0].previous_output.txid, None)
            .await
            .expect("should be able to get claim tx");

        VerifierDuty::VerifyAssertions {
            operator_id,
            deposit_txid,

            post_assert_tx,
            claim_tx,
            assert_data_txs,
        }
    }
}