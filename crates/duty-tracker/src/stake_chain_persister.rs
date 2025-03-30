//! This module is responsible for persisting the state of the stake chain to a database and
//! retrieving it when needed.
// FIXME: remove these once this impl is complete
#![expect(missing_docs)]
#![expect(unused)]
use std::{collections::BTreeMap, fmt::Display};

use alpen_bridge_params::prelude::StakeChainParams;
use bitcoin::OutPoint;
use indexmap::IndexSet;
use sqlx::{Pool, Sqlite};
use strata_bridge_db::{errors::DbError, persistent::sqlite::SqliteDb, public::PublicDb};
use strata_bridge_primitives::operator_table::OperatorTable;
use strata_bridge_stake_chain::{stake_chain::StakeChainInputs, transactions::stake::StakeTxData};
use strata_p2p_types::P2POperatorPubKey;
use thiserror::Error;
use tracing::warn;

use crate::errors::StakeChainErr;

#[derive(Debug)]
pub struct StakeChainPersister {
    db: SqliteDb,
}

impl StakeChainPersister {
    pub async fn new(db: SqliteDb) -> Result<Self, DbError> {
        Ok(StakeChainPersister { db })
    }

    pub async fn commit_prestake(
        &self,
        operator_id: u32,
        prestake: OutPoint,
    ) -> Result<(), DbError> {
        self.db.set_pre_stake(operator_id, prestake).await
    }

    pub async fn commit_stake_data(
        &self,
        cfg: &OperatorTable,
        state: BTreeMap<P2POperatorPubKey, StakeChainInputs>,
    ) -> Result<(), DbError> {
        let op_id_and_chain_inputs = state.iter().filter_map(|(p2p_key, chain_inputs)| {
            // extract only those with valid operator ids
            cfg.op_key_to_idx(p2p_key)
                .map(|op_id| (op_id, chain_inputs))
        });

        for (operator_id, chain_inputs) in op_id_and_chain_inputs {
            for (stake_index, stake_input) in chain_inputs.stake_inputs.iter().enumerate() {
                self.db
                    .add_stake_data(operator_id, stake_index as u32, stake_input.to_owned())
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn load(
        &self,
        cfg: &OperatorTable,
        params: &StakeChainParams,
    ) -> Result<(BTreeMap<P2POperatorPubKey, StakeChainInputs>), DbError> {
        let mut stake_chain_inputs = BTreeMap::new();
        let operator_ids = cfg.operator_idxs();

        for operator_id in operator_ids {
            let stake_data = self.db.get_stake_data(operator_id, 0).await?;
            let pre_stake_outpoint = self.db.get_pre_stake(operator_id).await?;
            let p2p_key = cfg.idx_to_op_key(&operator_id);
            let btc_key = cfg.idx_to_btc_key(&operator_id);

            match (stake_data, pre_stake_outpoint, p2p_key, btc_key) {
                (Some(stake_data), Some(pre_stake_outpoint), Some(p2p_key), Some(btc_key)) => {
                    stake_chain_inputs.insert(
                        p2p_key.clone(),
                        StakeChainInputs {
                            operator_pubkey: btc_key.x_only_public_key().0,
                            pre_stake_outpoint,
                            stake_inputs: IndexSet::from([stake_data]),
                        },
                    );
                }
                _ => {
                    warn!(
                        ?stake_data,
                        ?pre_stake_outpoint,
                        ?p2p_key,
                        ?btc_key,
                        "ignoring incomplete data"
                    );
                    continue;
                }
            }
        }

        Ok(stake_chain_inputs)
    }
}
