//! This module is responsible for persisting the state of the stake chain to a database and
//! retrieving it when needed.
// FIXME: remove these once this impl is complete
#![expect(missing_docs)]
#![expect(unused)]
use std::{collections::BTreeMap, fmt::Display};

use sqlx::{Pool, Sqlite};
use strata_bridge_primitives::operator_table::OperatorTable;
use strata_bridge_stake_chain::stake_chain::StakeChainInputs;
use strata_p2p_types::P2POperatorPubKey;
use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub struct StakePersistErr;
impl Display for StakePersistErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StakePersistErr")
    }
}

#[derive(Debug)]
pub struct StakeChainPersister {
    pool: Pool<Sqlite>,
}
impl StakeChainPersister {
    pub async fn new(pool: Pool<Sqlite>) -> Result<Self, StakePersistErr> {
        Ok(StakeChainPersister { pool })
    }
    pub async fn init(
        &self,
        cfg: &OperatorTable,
        state: &BTreeMap<P2POperatorPubKey, StakeChainInputs>,
    ) -> Result<(), StakePersistErr> {
        todo!()
    }
    pub async fn commit(
        &self,
        state: &BTreeMap<P2POperatorPubKey, StakeChainInputs>,
    ) -> Result<(), StakePersistErr> {
        todo!()
    }
    pub async fn load(
        &self,
    ) -> Result<(OperatorTable, BTreeMap<P2POperatorPubKey, StakeChainInputs>), StakePersistErr>
    {
        todo!()
    }
}
