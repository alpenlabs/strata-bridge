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

use crate::strata_rpc::{BridgeDutyInteropTraitClient, RpcBridgeDutiesInterop};

#[derive(Debug, Clone)]
pub struct DutyWatcherConfig {
    pub poll_interval: Duration,
}

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
    pub fn new(
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
