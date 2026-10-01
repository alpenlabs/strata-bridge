//! Validation of transaction-driven operator exits.

use bitcoin::{OutPoint, ScriptBuf, Txid, secp256k1::SECP256K1};
use strata_asm_proto_bridge_txs::{
    slash::SlashInfo,
    unstake::{UnstakeInfo, expected_stake_connector_script_pubkey},
};
use strata_bridge_primitives::{
    operator_table::PublicOperatorTable,
    types::{BitcoinBlockHeight, OperatorIdx},
};

use super::{ConfirmedExit, ExitKind, OperatorSetError, OperatorSetSM};

/// An operator exit extracted from a Bitcoin transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedExit {
    /// A slash transaction.
    Slash(SlashInfo),
    /// An unstaking intent.
    Unstake(UnstakeInfo),
}

impl ParsedExit {
    /// The permanent operator index declared by the transaction.
    pub fn operator(&self) -> OperatorIdx {
        match self {
            Self::Slash(info) => info.header_aux().operator_idx(),
            Self::Unstake(info) => info.header_aux().operator_idx(),
        }
    }

    /// The outpoint referenced by the transaction's stake connector input.
    pub fn source(&self) -> OutPoint {
        match self {
            Self::Slash(info) => *info.stake_inpoint().outpoint(),
            Self::Unstake(info) => *info.stake_inpoint().outpoint(),
        }
    }

    /// The reason for the operator's exit.
    pub const fn kind(&self) -> ExitKind {
        match self {
            Self::Slash(_) => ExitKind::Slash,
            Self::Unstake(_) => ExitKind::UnstakingIntent,
        }
    }
}

/// An exit observation with its spent-output script and Bitcoin transaction position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitObservation {
    /// The parsed transaction data.
    pub parsed: ParsedExit,
    /// The transaction declaring the exit.
    pub txid: Txid,
    /// Its zero-based position within the block.
    pub tx_index: u32,
    /// Script of the output referenced by the parsed stake connector input.
    pub spent_output_script: ScriptBuf,
}

impl OperatorSetSM {
    /// Validates ordered exits against historical signing configurations.
    ///
    /// Invalid observations are ignored. Earlier valid exits establish configurations available
    /// to later transactions in the same block. Validation leaves membership unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error for unordered observations, unavailable history, or an exit sequence
    /// that would leave no members.
    pub fn validate_exits(
        &self,
        height: BitcoinBlockHeight,
        observations: &[ExitObservation],
    ) -> Result<Vec<ConfirmedExit>, OperatorSetError> {
        if observations.is_empty() {
            return Ok(vec![]);
        }

        if observations
            .windows(2)
            .any(|pair| pair[0].tx_index >= pair[1].tx_index)
        {
            return Err(OperatorSetError::UnorderedExits);
        }

        // Replayed blocks must not authorize an exit using a later signing configuration.
        let snapshots: Vec<_> = self
            .membership_history
            .iter()
            .filter(|snapshot| snapshot.block_height < height)
            .collect();

        let mut members = snapshots
            .last()
            .ok_or(OperatorSetError::HistoryUnavailable(height))?
            .members
            .clone();

        let mut configurations = snapshots
            .into_iter()
            .map(|snapshot| {
                let table = self.historical_operator_table(snapshot)?;
                Ok((nn_script(&table), table))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut exits = Vec::new();
        for observation in observations {
            let operator = observation.parsed.operator();
            let signing_script = match &observation.parsed {
                ParsedExit::Slash(_) => observation.spent_output_script.clone(),
                ParsedExit::Unstake(info) => {
                    let expected = expected_stake_connector_script_pubkey(
                        *info.stake_hash(),
                        *info.witness_pushed_pubkey(),
                    );
                    if observation.spent_output_script != expected {
                        continue;
                    }
                    ScriptBuf::new_p2tr(SECP256K1, *info.witness_pushed_pubkey(), None)
                }
            };

            let configuration = configurations
                .iter()
                .find(|(script, _)| script == &signing_script);
            if configuration.is_none_or(|(_, table)| table.idx_to_btc_key(&operator).is_none()) {
                continue;
            }

            exits.push(ConfirmedExit {
                operator_idx: operator,
                txid: observation.txid,
                tx_index: observation.tx_index,
                kind: observation.parsed.kind(),
            });

            if members.remove(&operator) {
                let table = Self::table_for(&self.registrations, &members)?;
                configurations.push((nn_script(&table), table));
            }
        }

        Ok(exits)
    }
}

fn nn_script(table: &PublicOperatorTable) -> ScriptBuf {
    ScriptBuf::new_p2tr(
        SECP256K1,
        table.aggregated_btc_key().x_only_public_key().0,
        None,
    )
}
