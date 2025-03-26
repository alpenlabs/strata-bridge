use std::{sync::Arc, time::Duration};

use bitcoin::{Amount, OutPoint, TapNodeHash, Txid};
use bitcoin_bosd::Descriptor;
use serde::{Deserialize, Serialize};
use strata_bridge_db::tracker::DutyTrackerDb;
use strata_bridge_primitives::{
    bitcoin::BitcoinAddress,
    deposit::DepositInfo,
    duties::{BridgeDuty, BridgeDutyStatus},
    types::{BitcoinBlockHeight, OperatorIdx},
    withdrawal::WithdrawalInfo,
};
use strata_rpc_api::StrataApiClient;
use strata_rpc_types::RpcBridgeDuties;
use tokio::{
    sync::{broadcast, mpsc},
    task::JoinSet,
};
use tracing::{debug, error, info};

#[derive(Debug, Clone)]
pub struct DutyWatcherConfig {
    pub poll_interval: Duration,
}

#[derive(Debug, Clone)]
pub struct DutyWatcher<StrataClient: StrataApiClient, Db: DutyTrackerDb> {
    config: DutyWatcherConfig,

    strata_rpc_client: Arc<StrataClient>,

    db: Arc<Db>,
}

impl<StrataClient, Db> DutyWatcher<StrataClient, Db>
where
    StrataClient: StrataApiClient + Send + Sync + 'static,
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

                let mut stake_index = 0;
                match strata_rpc_client
                    .get_bridge_duties(operator_idx, last_fetched_duty_index)
                    .await
                {
                    Ok(RpcBridgeDuties {
                        duties,
                        start_index,
                        stop_index,
                    }) => {
                        let num_duties = duties.len();
                        info!(event = "fetched duties", %start_index, %stop_index, %num_duties);

                        for duty in duties {
                            debug!(action = "dispatching duty", ?duty);
                            // HACK: convert from `strata` type to `strata-bridge` type
                            // to avoid having to use all the deposit/withdrawal types from
                            // `strata`. This is fine for now since these duties will be generated
                            // by `strata-bridge` directly in the immediate future.
                            #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
                            struct DepositInfoInterop {
                                /// The deposit request transaction outpoints from the users.
                                pub deposit_request_outpoint: OutPoint,

                                /// The execution layer address to mint the equivalent tokens to.
                                /// As of now, this is just the 20-byte EVM address.
                                pub el_address: Vec<u8>,

                                /// The amount in bitcoins that the user is sending.
                                ///
                                /// This amount should be greater than the [`BRIDGE_DENOMINATION`]
                                /// for the deposit to be confirmed
                                /// on bitcoin. The excess amount is used as miner fees for the
                                /// Deposit Transaction.
                                pub total_amount: Amount,

                                /// The hash of the take back leaf in the Deposit Request
                                /// Transaction (DRT) as provided by the
                                /// user in their `OP_RETURN` output.
                                pub take_back_leaf_hash: TapNodeHash,

                                /// The original taproot address in the Deposit Request Transaction
                                /// (DRT) output used to
                                /// sanity check computation internally i.e., whether the known
                                /// information (n/n script spend
                                /// path, [`static@UNSPENDABLE_INTERNAL_KEY`]) + the
                                /// [`Self::take_back_leaf_hash`] yields the
                                /// same P2TR address.
                                pub original_taproot_addr: BitcoinAddress,
                            }

                            #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
                            struct CooperativeWithdrawalInfoInterop {
                                /// The [`OutPoint`] of the UTXO in the Bridge Address that is to
                                /// be used to service the
                                /// withdrawal request.
                                pub deposit_outpoint: OutPoint,

                                /// The BOSD [`Descriptor`] supplied by the user.
                                pub user_destination: Descriptor,

                                /// The index of the operator that is assigned the withdrawal.
                                pub assigned_operator_idx: OperatorIdx,

                                /// The bitcoin block height before which the withdrawal has to be
                                /// processed.
                                ///
                                /// Any withdrawal request whose `exec_deadline` is before the
                                /// current bitcoin block height is
                                /// considered stale and must be ignored.
                                pub exec_deadline: BitcoinBlockHeight,
                            }

                            #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
                            #[serde(tag = "type", content = "payload")]
                            enum BridgeDutyInterop {
                                SignDeposit(DepositInfoInterop),
                                FulfillWithdrawal(CooperativeWithdrawalInfoInterop),
                            }

                            let duty_interop: BridgeDutyInterop =
                                serde_json::from_str(&serde_json::to_string(&duty).unwrap())
                                    .unwrap();

                            let duty = match duty_interop {
                                BridgeDutyInterop::SignDeposit(deposit_info) => {
                                    let deposit_info = DepositInfo::new(
                                        deposit_info.deposit_request_outpoint,
                                        stake_index, // FIXME: UPDATE THIS FOR NEW STAKE
                                        deposit_info.el_address,
                                        deposit_info.total_amount,
                                        deposit_info.take_back_leaf_hash,
                                        deposit_info
                                            .original_taproot_addr
                                            .address()
                                            .script_pubkey(),
                                    );
                                    stake_index += 1;
                                    BridgeDuty::SignDeposit(deposit_info)
                                }
                                BridgeDutyInterop::FulfillWithdrawal(
                                    cooperative_withdrawal_info,
                                ) => {
                                    let withdrawal_info = WithdrawalInfo::new(
                                        cooperative_withdrawal_info.deposit_outpoint,
                                        cooperative_withdrawal_info.user_destination,
                                        cooperative_withdrawal_info.assigned_operator_idx,
                                        cooperative_withdrawal_info.exec_deadline,
                                    );
                                    BridgeDuty::FulfillWithdrawal(withdrawal_info)
                                }
                            };

                            duty_sender.send(duty).expect("should be able to send duty");
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
