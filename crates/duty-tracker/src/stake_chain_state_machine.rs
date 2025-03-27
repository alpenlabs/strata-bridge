//! State machine for managing the current state of all the operators' stake chains.
use std::{collections::BTreeMap, fmt::Display};

use alpen_bridge_params::prelude::StakeChainParams;
use bitcoin::{Network, OutPoint};
use strata_bridge_connectors::prelude::ConnectorCpfp;
use strata_bridge_primitives::operator_table::OperatorTable;
use strata_bridge_stake_chain::{prelude::StakeTx, stake_chain::StakeChainInputs, StakeChain};
use strata_p2p_types::{P2POperatorPubKey, StakeChainId};
use thiserror::Error;

use crate::contract_state_machine::DepositSetup;

/// Error type for problems arising in maintaining or querying stake chain data.
#[derive(Debug, Clone, Error)]
pub struct StakeChainErr;
impl Display for StakeChainErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StakeChainErr")
    }
}

/// State machine for managing the current state of all the operators' stake chains.
#[derive(Debug, Clone)]
pub struct StakeChainSM {
    network: Network,
    operator_table: OperatorTable,
    stake_chains: BTreeMap<P2POperatorPubKey, StakeChainInputs>,
}
impl StakeChainSM {
    /// Constructor for a brand new StakeChainSM.
    pub fn new(network: Network, operator_table: OperatorTable) -> Self {
        StakeChainSM {
            network,
            operator_table,
            stake_chains: BTreeMap::new(),
        }
    }

    /// Constructor for restoring the state of the StakeChainSM on startup.
    pub fn restore(
        network: Network,
        operator_table: OperatorTable,
        stake_chains: BTreeMap<P2POperatorPubKey, StakeChainInputs>,
    ) -> Self {
        StakeChainSM {
            network,
            operator_table,
            stake_chains,
        }
    }

    /// State transition function for processing the StakeChainExchange P2P message.
    pub fn process_exchange(
        &mut self,
        operator: P2POperatorPubKey,
        _id: StakeChainId,
        pre_stake_outpoint: OutPoint,
    ) -> Result<(), StakeChainErr> {
        let operator_pubkey = match self.operator_table.op_key_to_btc_key(&operator) {
            Some(operator_pk) => operator_pk.x_only_public_key().0,
            None => {
                return Err(StakeChainErr);
            }
        };
        let inputs = StakeChainInputs {
            operator_pubkey,
            stake_inputs: Vec::new(),
            pre_stake_outpoint,
            params: StakeChainParams::default(),
        };

        if let Some(a) = self.stake_chains.insert(operator.clone(), inputs) {
            self.stake_chains.insert(operator, a);
            return Err(StakeChainErr);
        }

        Ok(())
    }

    /// State transition function for processing the DepositSetup P2P message.
    pub fn process_setup(
        &mut self,
        operator: P2POperatorPubKey,
        setup: &DepositSetup,
    ) -> Result<(), StakeChainErr> {
        if let Some(chain) = self.stake_chains.get_mut(&operator) {
            chain.stake_inputs.push(setup.stake_tx_data());
            Ok(())
        } else {
            Err(StakeChainErr)
        }
    }

    /// Returns the state that can be used to restore the StakeChainSM.
    pub fn state(&self) -> &BTreeMap<P2POperatorPubKey, StakeChainInputs> {
        &self.stake_chains
    }

    /// Gets the stake transaction for the operator at the stake index of the argument.
    pub fn stake_tx(&self, op: &P2POperatorPubKey, nth: usize) -> Option<StakeTx> {
        let inputs = self.stake_chains.get(op)?;
        let stake_chain = StakeChain::new(
            &self.operator_table.tx_build_context(self.network),
            inputs,
            // TODO(proofofkeags): is this the right key?
            ConnectorCpfp::new(inputs.operator_pubkey, self.network),
        );
        stake_chain.get(nth).cloned()
    }
}
