//! This module is responsible for persisting the state of the stake chain to a database and
//! retrieving it when needed.
use std::collections::BTreeMap;

use bitcoin::OutPoint;
use strata_bridge_db::{errors::DbError, persistent::sqlite::SqliteDb, public::PublicDb};
use strata_bridge_primitives::operator_table::OperatorTable;
use strata_bridge_stake_chain::stake_chain::StakeChainInputs;
use strata_p2p_types::P2POperatorPubKey;
use tracing::warn;

/// A database wrapper for dumping ad retrieving stake chain data.
#[derive(Debug)]
pub struct StakeChainPersister {
    db: SqliteDb,
}

impl StakeChainPersister {
    /// Creates a new instance of [`StakeChainPersister`].
    pub async fn new(db: SqliteDb) -> Result<Self, DbError> {
        Ok(StakeChainPersister { db })
    }

    /// Commits the pre stake outpoint to disk.
    pub async fn commit_prestake(
        &self,
        operator_id: u32,
        prestake: OutPoint,
    ) -> Result<(), DbError> {
        self.db.set_pre_stake(operator_id, prestake).await
    }

    /// Commits the stake chain inputs to the database.
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

    /// Loads the stake chain inputs from disk in order to build the stake chain.
    pub async fn load(
        &self,
        cfg: &OperatorTable,
    ) -> Result<BTreeMap<P2POperatorPubKey, StakeChainInputs>, DbError> {
        let mut stake_chain_inputs = BTreeMap::new();
        let operator_ids = cfg.operator_idxs();

        for operator_id in operator_ids {
            let stake_data = self.db.get_all_stake_data(operator_id).await?;
            let pre_stake_outpoint = self.db.get_pre_stake(operator_id).await?;
            let p2p_key = cfg.idx_to_op_key(&operator_id);
            let btc_key = cfg.idx_to_btc_key(&operator_id);

            match (pre_stake_outpoint, p2p_key, btc_key) {
                (Some(pre_stake_outpoint), Some(p2p_key), Some(btc_key)) => {
                    stake_chain_inputs.insert(
                        p2p_key.clone(),
                        StakeChainInputs {
                            operator_pubkey: btc_key.x_only_public_key().0,
                            pre_stake_outpoint,
                            // NOTE: (@Rajil1213) convert stake data to an IndexedSet to avoid this
                            // conversion alternatively, this is okay
                            // since the loading of the stake data only
                            // happens once.
                            stake_inputs: stake_data.into_iter().collect(),
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
