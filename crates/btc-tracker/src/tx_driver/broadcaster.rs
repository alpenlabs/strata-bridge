//! Bare sends of parents.

use std::{collections::HashMap, sync::Arc};

use bitcoin::Transaction;
use bitcoind_async_client::error::ClientError;
use tokio::task::{Id, JoinSet};
use tracing::{debug, error, info, warn};

use super::{
    node::ChainAccess,
    package::{BroadcastResult, PackageId},
};
use crate::event::TxStatus;

/// Sends parents bare, each in its own task, and reports each result once.
pub(super) struct Broadcaster {
    chain: Arc<dyn ChainAccess>,
    tasks: JoinSet<(PackageId, BroadcastResult)>,
    packages: HashMap<Id, PackageId>,
}

impl Broadcaster {
    pub(super) fn new(chain: Arc<dyn ChainAccess>) -> Self {
        Self {
            chain,
            tasks: JoinSet::new(),
            packages: HashMap::new(),
        }
    }

    /// Sends `tx` for package `id`.
    pub(super) fn request(&mut self, id: PackageId, tx: Transaction) {
        let chain = self.chain.clone();
        let task = self
            .tasks
            .spawn(async move { (id, send(chain.as_ref(), &tx).await) });
        self.packages.insert(task.id(), id);
    }

    /// The result of the next send to finish. `None` while no send runs. A send whose task
    /// panicked reports a rejection, so that its package does not wait on it forever.
    pub(super) async fn next_result(&mut self) -> Option<(PackageId, BroadcastResult)> {
        loop {
            match self.tasks.join_next_with_id().await? {
                Ok((task, result)) => {
                    self.packages.remove(&task);
                    return Some(result);
                }
                Err(err) => {
                    let Some(id) = self.packages.remove(&err.id()) else {
                        continue;
                    };
                    error!(%err, "a send task failed");
                    let error = ClientError::Other(format!("the send task failed: {err}"));
                    return Some((id, BroadcastResult::Rejected(error)));
                }
            }
        }
    }
}

/// Sends `tx` bare and reads the node when it refuses.
///
/// bitcoind reports a confirmed transaction as already known only while one of its outputs is
/// unspent, and a variant with another witness can hold the txid in the mempool. A refusal of a
/// transaction that the node holds therefore reports where the node holds it.
async fn send(chain: &dyn ChainAccess, tx: &Transaction) -> BroadcastResult {
    let txid = tx.compute_txid();
    let Err(error) = chain.broadcast(tx).await else {
        info!(%txid, "sent the transaction");
        return BroadcastResult::Accepted;
    };
    match chain.fetch_status(txid).await {
        Ok(TxStatus::Mempool) => BroadcastResult::Accepted,
        Ok(status @ (TxStatus::Mined { .. } | TxStatus::Buried { .. })) => {
            debug!(%txid, %error, "the transaction is already in a block");
            BroadcastResult::Known(status)
        }
        Ok(TxStatus::Unknown) | Err(_) => {
            warn!(%txid, %error, "the node refused the transaction");
            BroadcastResult::Rejected(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::{
        event::TxStatus,
        tx_driver::test_utils::{input_of, mined, parent, FakeChain},
    };

    async fn send(chain: Arc<FakeChain>) -> BroadcastResult {
        let mut broadcaster = Broadcaster::new(chain);
        broadcaster.request(PackageId(7), parent(1));
        let (id, result) = broadcaster
            .next_result()
            .await
            .expect("the send reports a result");
        assert_eq!(id, PackageId(7), "the result names its package");
        assert!(
            broadcaster.next_result().await.is_none(),
            "one send reports once"
        );
        result
    }

    #[tokio::test]
    async fn an_accepted_send_reports_acceptance() {
        let chain = Arc::new(FakeChain::default());

        let result = send(chain.clone()).await;

        assert_eq!(
            result,
            BroadcastResult::Accepted,
            "the node took the parent"
        );
        assert_eq!(chain.broadcasts(), 1, "one send went out");
    }

    #[tokio::test]
    async fn a_rejected_send_reports_the_error() {
        let chain = Arc::new(FakeChain::default());
        chain.reject_broadcast.store(true, Ordering::SeqCst);

        let result = send(chain).await;

        assert!(
            matches!(result, BroadcastResult::Rejected(_)),
            "the node refused the parent, got {result:?}"
        );
    }

    #[tokio::test]
    async fn a_rejected_send_of_a_parent_in_a_block_reports_its_status() {
        let chain = Arc::new(FakeChain::default());
        chain.spend(input_of(1));
        chain.set_status(parent(1).compute_txid(), mined());

        let result = send(chain).await;

        assert_eq!(
            result,
            BroadcastResult::Known(mined()),
            "the node rejects a parent whose outputs are all spent, but it is in a block"
        );
    }

    #[tokio::test]
    async fn a_rejected_send_of_a_parent_in_the_mempool_reports_acceptance() {
        let chain = Arc::new(FakeChain::default());
        chain.reject_broadcast.store(true, Ordering::SeqCst);
        chain.set_status(parent(1).compute_txid(), TxStatus::Mempool);

        let result = send(chain).await;

        assert_eq!(
            result,
            BroadcastResult::Accepted,
            "a variant with another witness holds the txid in the mempool"
        );
    }
}
