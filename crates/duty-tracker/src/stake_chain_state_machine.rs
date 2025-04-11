//! State machine for managing the current state of all the operators' stake chains.
use std::collections::BTreeMap;

use alpen_bridge_params::prelude::StakeChainParams;
use bitcoin::{Network, OutPoint, Txid};
use indexmap::IndexSet;
use strata_bridge_connectors::prelude::ConnectorCpfp;
use strata_bridge_primitives::operator_table::OperatorTable;
use strata_bridge_stake_chain::{
    prelude::{StakeTx, STAKE_VOUT},
    stake_chain::StakeChainInputs,
    StakeChain,
};
use strata_p2p_types::{P2POperatorPubKey, StakeChainId};
use tracing::{info, warn};

use crate::{contract_state_machine::DepositSetup, errors::StakeChainErr};

/// State machine for managing the current state of all the operators' stake chains.
#[derive(Debug, Clone)]
pub struct StakeChainSM {
    network: Network,
    params: StakeChainParams,
    operator_table: OperatorTable,
    stake_chains: BTreeMap<P2POperatorPubKey, StakeChainInputs>,
    stake_txids: BTreeMap<P2POperatorPubKey, Vec<Txid>>,
}

impl StakeChainSM {
    /// Constructor for a brand new StakeChainSM.
    pub fn new(network: Network, operator_table: OperatorTable, params: StakeChainParams) -> Self {
        StakeChainSM {
            network,
            params,
            operator_table,
            stake_chains: BTreeMap::new(),
            stake_txids: BTreeMap::new(),
        }
    }

    /// Constructor for restoring the state of the StakeChainSM on startup.
    pub fn restore(
        network: Network,
        operator_table: OperatorTable,
        params: StakeChainParams,
        stake_chains: BTreeMap<P2POperatorPubKey, StakeChainInputs>,
    ) -> Result<Self, StakeChainErr> {
        let p2p_keys = operator_table.p2p_keys();

        info!("reconstructing stake txids");
        let stake_txids = p2p_keys
            .iter()
            .filter_map(|p2p_key| stake_chains.get(p2p_key))
            .map(|inputs| {
                StakeChain::new(
                    &operator_table.tx_build_context(network),
                    inputs,
                    &params,
                    ConnectorCpfp::new(inputs.operator_pubkey, network),
                )
            })
            .map(|chain| {
                chain
                    .iter()
                    .map(|stake_tx| stake_tx.compute_txid())
                    .collect::<Vec<_>>()
            })
            .zip(p2p_keys.iter())
            .map(|(stake_txids, p2p_key)| (p2p_key.clone(), stake_txids))
            .collect();

        Ok(StakeChainSM {
            network,
            params,
            operator_table,
            stake_chains,
            stake_txids,
        })
    }

    /// State transition function for processing the StakeChainExchange P2P message.
    ///
    /// # Caution
    ///
    /// This resets the in-memory state of the stake chain for the operator if it already has data.
    pub fn process_exchange(
        &mut self,
        operator: P2POperatorPubKey,
        _id: StakeChainId,
        pre_stake_outpoint: OutPoint,
    ) -> Result<(), StakeChainErr> {
        let operator_pubkey = match self.operator_table.op_key_to_btc_key(&operator) {
            Some(operator_pk) => operator_pk.x_only_public_key().0,
            None => {
                return Err(StakeChainErr::OperatorP2PKeyNotFound(operator.clone()));
            }
        };

        let inputs = StakeChainInputs {
            operator_pubkey,
            stake_inputs: IndexSet::new(),
            pre_stake_outpoint,
        };

        if let Some(a) = self.stake_chains.insert(operator.clone(), inputs) {
            warn!(%operator, "tried to re-insert stake chain input that already exists");
            self.stake_chains.insert(operator, a);
        }

        Ok(())
    }

    /// State transition function for processing the DepositSetup P2P message.
    ///
    /// This involves updating the in-memory cache to hold the new stake chain inputs and creating a
    /// new stake transaction corresponding to that input and adding its txid to the stake txid
    /// cache. It returns the txid of the stake transaction if it was created and added to the cache
    /// successfully.
    pub fn process_setup(
        &mut self,
        operator: P2POperatorPubKey,
        setup: &DepositSetup,
    ) -> Result<Option<Txid>, StakeChainErr> {
        info!(%operator, "processing deposit setup");
        if let Some(chain_input) = self.stake_chains.get_mut(&operator) {
            let new_entry = chain_input.stake_inputs.insert(setup.stake_tx_data());
            if !new_entry {
                warn!(%operator, "stake input already exists for this operator");
            }

            // also try to create a new stake tx and update the txid table
            if let Some(stake_tx) = self.stake_tx(&operator, setup.index as usize)? {
                let stake_txid = stake_tx.compute_txid();

                self.stake_txids
                    .entry(operator.clone())
                    .or_default()
                    .push(stake_txid);

                Ok(Some(stake_txid))
            } else {
                // if unable to create the stake tx, we ignore it but inform the caller.
                // this can happen if the deposit setup msg is received out of order.
                Ok(None)
            }
        } else {
            warn!(%operator, "tried to process deposit setup for non-existent stake chain");
            Err(StakeChainErr::StakeSetupDataNotFound(operator.clone()))
        }
    }

    /// Returns the state that can be used to restore the StakeChainSM.
    pub fn state(&self) -> &BTreeMap<P2POperatorPubKey, StakeChainInputs> {
        &self.stake_chains
    }

    /// Gets the stake transaction for the operator at the stake index of the argument.
    pub fn stake_tx(
        &self,
        op: &P2POperatorPubKey,
        nth: usize,
    ) -> Result<Option<StakeTx>, StakeChainErr> {
        match self.stake_chains.get(op) {
            Some(stake_chain_inputs) => {
                let pre_stake = stake_chain_inputs.pre_stake_outpoint;

                let context = self.operator_table.tx_build_context(self.network);
                let operator_pubkey = stake_chain_inputs.operator_pubkey;
                let connector_cpfp = ConnectorCpfp::new(operator_pubkey, self.network);

                // handle the first stake tx differently as it spends a pre-stake and not the stake
                // tx.
                if nth == 0 {
                    let first_input = stake_chain_inputs
                        .stake_inputs
                        .first()
                        .ok_or(StakeChainErr::StakeTxNotFound(op.clone(), nth as u32))?;
                    let stake_hash = first_input.hash;
                    let withdrawal_fulfillment_pk = first_input.withdrawal_fulfillment_pk;
                    let operator_funds = first_input.operator_funds;

                    let first_stake = StakeTx::create_initial(
                        &context,
                        &self.params,
                        stake_hash,
                        withdrawal_fulfillment_pk,
                        pre_stake,
                        operator_funds,
                        operator_pubkey,
                        connector_cpfp,
                    );

                    return Ok(Some(first_stake));
                }

                let stake_txids = self
                    .stake_txids
                    .get(op)
                    .ok_or(StakeChainErr::StakeTxNotFound(op.clone(), nth as u32))?;

                let prev_stake_txid =
                    stake_txids
                        .get(nth - 1)
                        .ok_or(StakeChainErr::IncompleteStakeChainInput(
                            op.clone(),
                            nth - 1,
                        ))?;
                let prev_input = stake_chain_inputs.stake_inputs.iter().nth(nth - 1).ok_or(
                    StakeChainErr::IncompleteStakeChainInput(op.clone(), nth - 1),
                )?;
                let prev_stake = OutPoint::new(*prev_stake_txid, STAKE_VOUT);

                let input = stake_chain_inputs
                    .stake_inputs
                    .iter()
                    .nth(nth)
                    .ok_or(StakeChainErr::IncompleteStakeChainInput(op.clone(), nth))?;

                let stake_tx = StakeTx::advance(
                    &context,
                    &self.params,
                    *input,
                    prev_input.hash,
                    prev_stake,
                    operator_pubkey,
                    connector_cpfp,
                );

                Ok(Some(stake_tx))
            }
            _ => Ok(None),
        }
    }
}
