use std::collections::BTreeMap;

use bitcoin::{Transaction, Txid};
use btc_notify::{client::BtcZmqClient, subscription::Subscription};
use futures::StreamExt;
use sqlx::{Pool, Sqlite};
use strata_p2p::{self, swarm::handle::P2PHandle};
use tokio::task::JoinHandle;

use crate::{
    contract_persister::{self, ContractPersister},
    contract_state_machine::ContractSM,
};

pub struct ContractManager {
    thread_handle: JoinHandle<()>,
}
impl ContractManager {
    fn new<Msg: prost::Message + Clone + 'static>(
        zmq_client: BtcZmqClient,
        mut p2p_handle: P2PHandle<Msg>,
        contract_persister: ContractPersister,
    ) -> Self {
        let thread_handle = tokio::task::spawn(async move {
            let mut active_contracts = match contract_persister.load_all().await {
                Ok(contract_data) => contract_data
                    .into_iter()
                    .map(|(cfg, state)| (cfg.deposit_idx, ContractSM::restore(cfg, state)))
                    .collect::<BTreeMap<u32, ContractSM>>(),
                Err(_) => {
                    debug_assert!(false, "Failed to load contracts");
                    BTreeMap::new()
                }
            };

            let mut block_sub = zmq_client.subscribe_blocks().await;
            tokio::select! {
                Some(block) = block_sub.next() => {
                    for tx in block.txdata {
                        for contract in active_contracts.iter() {
                            if contract.transaction_filter()(&tx) {
                                todo!()
                                // contract.process_peg_out_graph_tx_confirmation()
                            }
                        }
                    }
                }
                msg = p2p_handle.next() => {}
            }
        });
        ContractManager { thread_handle }
    }
}
