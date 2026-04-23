use mosaic_rpc_api::MosaicRpcClient;
use mosaic_rpc_types::{DepositStatus, RpcTablesetId};
use strata_bridge_primitives::types::{GraphIdx, OperatorIdx};
use strata_mosaic_client_api::{MosaicEvent, types::*};
use tracing::{debug, error, info, warn};

use crate::{MosaicClient, MosaicIdResolver};

impl<R: MosaicRpcClient + Send + Sync + 'static, P: MosaicIdResolver> MosaicClient<R, P> {
    /// Emits `AdaptorsVerified` and removes any watch-list entry for the deposit first.
    // This helper is shared by both completion paths:
    // - the synchronous "init observed `Ready` immediately" path, and
    // - the asynchronous poller path for deposits that were previously `Incomplete`.
    //
    // Keeping the two paths on the same helper prevents them from drifting and re-introducing
    // duplicate-event bugs where one path emits without clearing the watch entry.
    pub(crate) async fn emit_adaptors_verified(
        &self,
        tableset_id: RpcTablesetId,
        operator_idx: OperatorIdx,
        deposit_idx: DepositIdx,
    ) {
        let key = (tableset_id, operator_idx, deposit_idx);
        info!(%operator_idx, %deposit_idx, "deposit adaptors verified");
        self.watched_deposits.lock().await.remove(&key);
        self.emit(MosaicEvent::AdaptorsVerified(GraphIdx {
            operator: operator_idx,
            deposit: deposit_idx,
        }))
        .await;
    }

    /// Polls watched deposits periodically and emits events when their status changes.
    ///
    /// - `Ready` → emits [`MosaicEvent::AdaptorsVerified`] and removes the deposit.
    /// - `Aborted` / `UncontestedWithdrawal` / `Consumed` → logs an error and removes the deposit.
    /// - `Incomplete` → keeps watching (resets the RPC failure counter).
    /// - RPC error → increments the failure counter; removes the deposit after `max_retries`
    ///   consecutive failures (this may indicate the deposit was never initialized).
    ///
    /// This method runs forever. To stop it, race it against a shutdown signal
    /// externally (e.g., via `tokio::select!`).
    pub async fn poll_watched_deposits(&self) {
        // Only deposits that were previously observed as `Incomplete` should be present in
        // `watched_deposits`. Deposits that are already `Ready` at init time are completed
        // immediately by `init_garbler_deposit` and never need to wait for this loop.
        loop {
            tokio::time::sleep(self.poll_interval).await;

            // Snapshot keys to avoid holding the lock during RPC calls.
            let snapshot: Vec<(RpcTablesetId, OperatorIdx, DepositIdx)> =
                { self.watched_deposits.lock().await.keys().cloned().collect() };

            if snapshot.is_empty() {
                continue;
            }

            debug!(count = snapshot.len(), "polling watched deposits");

            for (tableset_id, operator_idx, deposit_idx) in snapshot {
                let deposit_id = self.provider.resolve_deposit_id(deposit_idx);
                let rpc_deposit_id = deposit_id.into();
                match self
                    .rpc
                    .get_deposit_status(tableset_id, rpc_deposit_id)
                    .await
                {
                    Ok(Some(status)) => {
                        self.handle_watched_deposit_status(
                            tableset_id,
                            operator_idx,
                            deposit_idx,
                            status,
                        )
                        .await;
                    }
                    Ok(None) => {
                        self.handle_watched_deposit_not_found(
                            tableset_id,
                            operator_idx,
                            deposit_idx,
                        )
                        .await;
                    }
                    Err(rpc_err) => {
                        self.handle_watched_deposit_rpc_error(
                            tableset_id,
                            operator_idx,
                            deposit_idx,
                            rpc_err,
                        )
                        .await;
                    }
                }
            }
        }
    }

    async fn handle_watched_deposit_status(
        &self,
        tableset_id: RpcTablesetId,
        operator_idx: OperatorIdx,
        deposit_idx: DepositIdx,
        status: DepositStatus,
    ) {
        let key = (tableset_id, operator_idx, deposit_idx);
        match status {
            DepositStatus::Ready => {
                self.emit_adaptors_verified(tableset_id, operator_idx, deposit_idx)
                    .await;
            }
            DepositStatus::Aborted { reason } => {
                error!(%operator_idx, %deposit_idx, %reason, "watched deposit aborted");
                self.watched_deposits.lock().await.remove(&key);
            }
            DepositStatus::UncontestedWithdrawal => {
                error!(%operator_idx, %deposit_idx, "watched deposit withdrawn");
                self.watched_deposits.lock().await.remove(&key);
            }
            DepositStatus::Consumed { .. } => {
                error!(%operator_idx, %deposit_idx, "watched deposit consumed");
                self.watched_deposits.lock().await.remove(&key);
            }
            DepositStatus::Incomplete { details } => {
                // Deposit exists but isn't ready yet — reset failure counter, keep watching.
                debug!(%operator_idx, %deposit_idx, %details, "watched deposit still incomplete");
                if let Some(counter) = self.watched_deposits.lock().await.get_mut(&key) {
                    *counter = 0;
                }
            }
        }
    }

    async fn handle_watched_deposit_not_found(
        &self,
        tableset_id: RpcTablesetId,
        operator_idx: OperatorIdx,
        deposit_idx: DepositIdx,
    ) {
        let key = (tableset_id, operator_idx, deposit_idx);
        let mut watched = self.watched_deposits.lock().await;
        if let Some(failure_count) = watched.get_mut(&key) {
            *failure_count += 1;
            if *failure_count >= self.max_retries {
                warn!(
                    %operator_idx,
                    %deposit_idx,
                    attempts = *failure_count,
                    "watched deposit not found after max retries, removing"
                );
                watched.remove(&key);
            } else {
                debug!(
                    %operator_idx,
                    %deposit_idx,
                    attempt = *failure_count,
                    max = self.max_retries,
                    "watched deposit not found, will retry"
                );
            }
        }
    }

    async fn handle_watched_deposit_rpc_error(
        &self,
        tableset_id: RpcTablesetId,
        operator_idx: OperatorIdx,
        deposit_idx: DepositIdx,
        rpc_err: impl std::error::Error,
    ) {
        let key = (tableset_id, operator_idx, deposit_idx);
        let mut watched = self.watched_deposits.lock().await;
        if let Some(failure_count) = watched.get_mut(&key) {
            *failure_count += 1;
            if *failure_count >= self.max_retries {
                warn!(
                    %operator_idx,
                    %deposit_idx,
                    attempts = *failure_count,
                    %rpc_err,
                    "watched deposit RPC failed after max retries, removing"
                );
                watched.remove(&key);
            } else {
                debug!(
                    %operator_idx,
                    %deposit_idx,
                    attempt = *failure_count,
                    max = self.max_retries,
                    %rpc_err,
                    "watched deposit RPC failed, will retry"
                );
            }
        }
    }
}
