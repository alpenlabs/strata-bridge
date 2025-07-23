//! State machine for managing the current state of all the operators' stake chains.
use std::collections::BTreeMap;

use alpen_bridge_params::prelude::StakeChainParams;
use bitcoin::{Network, OutPoint, Txid};
use strata_bridge_primitives::operator_table::OperatorTable;
use strata_bridge_stake_chain::{
    prelude::{StakeTx, STAKE_VOUT},
    stake_chain::StakeChainInputs,
    transactions::stake::{Head, StakeTxKind, Tail},
    StakeChain,
};
use strata_p2p_types::P2POperatorPubKey;
use tracing::{debug, info, warn};

use crate::{contract_state_machine::DepositSetup, errors::StakeChainErr};

/// State machine for managing the current state of all the operators' stake chains.
#[derive(Debug, Clone)]
pub struct StakeChainSM {
    network: Network,
    params: StakeChainParams,
    operator_table: OperatorTable,
    stake_chains: BTreeMap<P2POperatorPubKey, StakeChainInputs>,
    stake_txids: BTreeMap<P2POperatorPubKey, BTreeMap<u32, Txid>>,
}

impl StakeChainSM {
    /// Constructor for a brand new StakeChainSM.
    pub const fn new(
        network: Network,
        operator_table: OperatorTable,
        params: StakeChainParams,
    ) -> Self {
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

        debug!("reconstructing stake txids");
        let stake_txids = p2p_keys
            .iter()
            .filter_map(|p2p_key| stake_chains.get(p2p_key))
            .map(|inputs| {
                StakeChain::new(&operator_table.tx_build_context(network), inputs, &params)
            })
            .map(|chain| {
                let mut txids = BTreeMap::new();

                let Some(first_stake_txid) = chain.head().map(|stake_tx| stake_tx.compute_txid())
                else {
                    return txids;
                };

                txids.insert(0, first_stake_txid);
                txids.extend(
                    chain
                        .tail()
                        .iter()
                        .enumerate()
                        .map(|(index, stake_tx)| (index as u32 + 1, stake_tx.compute_txid())),
                );

                txids
            })
            .zip(p2p_keys.iter())
            .map(|(stake_txids, p2p_key)| (p2p_key.clone(), stake_txids))
            .collect();
        info!("stake txids reconstructed");

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
        pre_stake_outpoint: OutPoint,
    ) -> Result<(), StakeChainErr> {
        let inputs = StakeChainInputs {
            stake_inputs: BTreeMap::new(),
            pre_stake_outpoint,
        };

        if let Some(old_prestake_outpoint) = self.stake_chains.insert(operator.clone(), inputs) {
            warn!(%operator, "ignoring redundant stake chain exchange");
            self.stake_chains.insert(operator, old_prestake_outpoint);
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
        let deposit_index = setup.index;
        info!(%operator, %deposit_index, "processing deposit setup");

        if let Some(stake_txid) = self
            .stake_txids
            .get(&operator)
            .and_then(|txids| txids.get(&deposit_index))
        {
            warn!(%operator, %deposit_index, "stake txid already exists for this index");

            return Ok(Some(*stake_txid));
        }

        let Some(chain_input) = self.stake_chains.get_mut(&operator) else {
            warn!(%operator, "received deposit setup for unknown operator");

            return Err(StakeChainErr::StakeSetupDataNotFound(operator.clone()));
        };

        chain_input
            .stake_inputs
            .insert(deposit_index, setup.stake_tx_data());

        // now try to create the stake transaction at the index
        let Some(stake_tx) = self.stake_tx(&operator, deposit_index)? else {
            warn!(%operator, "stake tx not found for this operator");

            // if unable to create the stake tx, we ignore it but inform the caller.
            // this can happen if the deposit setup msg is received out of order.
            return Ok(None);
        };

        // add the new stake txid to the state
        let stake_txid = stake_tx.compute_txid();
        self.stake_txids
            .entry(operator.clone())
            .or_default()
            .insert(deposit_index, stake_txid);

        Ok(Some(stake_txid))
    }

    /// Returns the state that can be used to restore the StakeChainSM.
    pub const fn state(&self) -> &BTreeMap<P2POperatorPubKey, StakeChainInputs> {
        &self.stake_chains
    }

    /// Returns the height of the current stake chain.
    ///
    /// This corresponds to the number of contracts in the
    /// [`crate::contract_state_machine::ContractSM`] that have been processed since genesis.
    pub fn height(&self) -> u32 {
        let my_key = self.operator_table.pov_p2p_key();

        self.stake_chains
            .get(my_key)
            .map(|inputs| inputs.stake_inputs.len() as u32)
            .unwrap_or(0)
    }

    /// Gets the stake transaction for the operator at the stake index of the argument.
    pub fn stake_tx(
        &self,
        op: &P2POperatorPubKey,
        nth: u32,
    ) -> Result<Option<StakeTxKind>, StakeChainErr> {
        match self.stake_chains.get(op) {
            Some(stake_chain_inputs) => {
                let context = self.operator_table.tx_build_context(self.network);

                // handle the first stake tx differently as it spends a pre-stake and not the stake
                // tx.
                if nth == 0 {
                    let pre_stake = stake_chain_inputs.pre_stake_outpoint;
                    let first_input = stake_chain_inputs
                        .stake_inputs
                        .values()
                        .nth(0)
                        .ok_or(StakeChainErr::StakeTxNotFound(op.clone(), 0))?;
                    let stake_hash = first_input.hash;
                    let withdrawal_fulfillment_pk = first_input.withdrawal_fulfillment_pk.clone();
                    let operator_funds = first_input.operator_funds;
                    let operator_pubkey = first_input.operator_pubkey;

                    let first_stake = StakeTx::<Head>::new(
                        &context,
                        &self.params,
                        stake_hash,
                        withdrawal_fulfillment_pk,
                        pre_stake,
                        operator_funds,
                        operator_pubkey,
                    );

                    return Ok(Some(StakeTxKind::Head(first_stake)));
                }

                let stake_txids = self
                    .stake_txids
                    .get(op)
                    .ok_or(StakeChainErr::StakeTxNotFound(op.clone(), nth))?;

                let prev_stake_txid =
                    stake_txids
                        .get(&(nth - 1))
                        .ok_or(StakeChainErr::IncompleteStakeChainInput(
                            op.clone(),
                            nth - 1,
                        ))?;
                let prev_input = stake_chain_inputs.stake_inputs.get(&(nth - 1)).ok_or(
                    StakeChainErr::IncompleteStakeChainInput(op.clone(), nth - 1),
                )?;
                let prev_stake = OutPoint::new(*prev_stake_txid, STAKE_VOUT);

                let input = stake_chain_inputs
                    .stake_inputs
                    .get(&nth)
                    .ok_or(StakeChainErr::IncompleteStakeChainInput(op.clone(), nth))?;

                let stake_tx = StakeTx::<Tail>::new(
                    &context,
                    &self.params,
                    input.clone(),
                    prev_input.hash,
                    prev_stake,
                );

                Ok(Some(StakeTxKind::Tail(stake_tx)))
            }
            _ => Ok(None),
        }
    }
}
