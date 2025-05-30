//! Duty watcher for the agent.

use std::{sync::Arc, time::Duration};

use bitcoin::Txid;
use strata_bridge_db::tracker::DutyTrackerDb;
use strata_bridge_primitives::duties::{BridgeDuty, BridgeDutyStatus};
use strata_rpc_api::StrataApiClient;
use tokio::{
    sync::{broadcast, mpsc},
    task::JoinSet,
};
use tracing::{debug, error, info};

use crate::strata_rpc::{BridgeDutyInterop, BridgeDutyInteropTraitClient, RpcBridgeDutiesInterop};

/// The configuration for the duty watcher.
#[derive(Debug, Clone)]
pub struct DutyWatcherConfig {
    /// The interval at which to poll the blockchain.
    pub poll_interval: Duration,
}

/// The duty watcher is responsible for watching the blockchain and dispatching duties to the
/// verifier.
#[derive(Debug, Clone)]
pub struct DutyWatcher<
    StrataClient: StrataApiClient + BridgeDutyInteropTraitClient,
    Db: DutyTrackerDb,
> {
    config: DutyWatcherConfig,

    strata_rpc_client: Arc<StrataClient>,

    db: Arc<Db>,
}

impl<StrataClient, Db> DutyWatcher<StrataClient, Db>
where
    StrataClient: StrataApiClient + BridgeDutyInteropTraitClient + Send + Sync + 'static,
    Db: DutyTrackerDb + Send + Sync + 'static,
{
    /// Creates a new duty watcher.
    pub const fn new(
        config: DutyWatcherConfig,
        strata_rpc_client: Arc<StrataClient>,
        db: Arc<Db>,
    ) -> Self {
        Self {
            config,
            strata_rpc_client,
            db,
        }
    }

    /// Starts the duty watcher.
    pub async fn start(
        &mut self,
        duty_sender: broadcast::Sender<BridgeDuty>,
        status_receiver: mpsc::Receiver<(Txid, BridgeDutyStatus)>,
    ) {
        let mut handles = JoinSet::new();

        let mut status_receiver = status_receiver;
        let db = self.db.clone();

        handles.spawn(async move {
            while let Some((duty_id, status)) = status_receiver.recv().await {
                info!(event = "received duty report", %duty_id, ?status);
                db.update_duty_status(duty_id, status.clone())
                    .await
                    .unwrap(); // FIXME: Handle me
                info!(event = "updated duty status in db", %duty_id, ?status);
            }
        });

        let db = self.db.clone();
        let strata_rpc_client = self.strata_rpc_client.clone();
        let poll_interval = self.config.poll_interval;

        handles.spawn(async move {
            let mut stake_index = 0;
            loop {
                let operator_idx = u32::MAX; // doesn't really matter in the current impl
                let last_fetched_duty_index = db.get_last_fetched_duty_index().await.unwrap(); // FIXME:
                                                                                               // Handle me

                match strata_rpc_client
                    .get_bridge_duties(operator_idx, last_fetched_duty_index)
                    .await
                {
                    Ok(RpcBridgeDutiesInterop {
                        duties,
                        start_index,
                        stop_index,
                    }) => {
                        let num_duties = duties.len();
                        info!(event = "fetched duties", %start_index, %stop_index, %num_duties);

                        for duty in duties {
                            debug!(action = "dispatching duty", ?duty);

                            let duty = if let BridgeDutyInterop::SignDeposit(deposit_duty) = duty {
                                let mut updated_deposit_duty = deposit_duty.clone();
                                updated_deposit_duty.stake_index = stake_index;
                                stake_index += 1;

                                BridgeDutyInterop::SignDeposit(updated_deposit_duty)
                            } else {
                                duty
                            };

                            let duty_interop: BridgeDuty =
                                serde_json::from_str(&serde_json::to_string(&duty).unwrap())
                                    .unwrap();

                            duty_sender
                                .send(duty_interop)
                                .expect("should be able to send duty");
                        }

                        db.set_last_fetched_duty_index(stop_index).await.unwrap(); // FIXME: Handle
                                                                                   // me
                    }
                    Err(e) => {
                        error!(?e, "could not get duties from strata");
                    }
                }

                tokio::time::sleep(poll_interval).await;
            }
        });

        handles.join_all().await;
    }
}
