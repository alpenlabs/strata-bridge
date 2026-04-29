//! Context for the Stake State Machine.

use bitcoin::{OutPoint, hashes::sha256};
use bitcoin_bosd::Descriptor;
use serde::{Deserialize, Serialize};
use strata_bridge_primitives::{operator_table::OperatorTable, types::OperatorIdx};
use strata_bridge_tx_graph::stake_graph::{SetupParams, StakeData};

use crate::stake::config::StakeSMCfg;

/// Execution context for a single instance of a Stake State Machine.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StakeSMCtx {
    // Invariant: `operator_idx` is included in `operator_table`.
    /// The index of the operator whose stake is tracked by this state machine.
    operator_idx: OperatorIdx,

    /// The operator table for this state machine instance.
    operator_table: OperatorTable,
}

impl StakeSMCtx {
    /// Creates a new Stake State Machine context.
    ///
    /// # Panics
    ///
    /// This method panics if the operator index is not included in the operator table.
    pub fn new(operator_idx: OperatorIdx, operator_table: OperatorTable) -> Self {
        assert!(
            operator_table.contains_idx(&operator_idx),
            "The operator index must be included in the operator table"
        );

        Self {
            operator_idx,
            operator_table,
        }
    }

    /// Returns the index of the operator whose stake is tracked.
    pub const fn operator_idx(&self) -> OperatorIdx {
        self.operator_idx
    }

    /// Returns the operator table.
    pub const fn operator_table(&self) -> &OperatorTable {
        &self.operator_table
    }

    /// Constructs the complete set of information required to construct the unstaking graph.
    ///
    /// # Parameters
    ///
    /// - `stake_funds`: The funding input for the stake transaction.
    /// - `unstaking_image`: The unstaking hash image whose preimage is revealed in the `Unstaking
    /// Intent` transaction
    /// - `unstaking_output_desc`: The descriptor where the operator wants to receive the staked
    ///   funds after unstaking.
    pub fn generate_setup_params(
        &self,
        stake_funds: OutPoint,
        unstaking_image: sha256::Hash,
        unstaking_output_desc: Descriptor,
    ) -> SetupParams {
        SetupParams {
            operator_index: self.operator_idx(),
            operator_pubkey: self
                .operator_table()
                .idx_to_btc_key(&self.operator_idx())
                .expect("operator index must be valid")
                .x_only_public_key()
                .0,
            n_of_n_pubkey: self
                .operator_table()
                .aggregated_btc_key()
                .x_only_public_key()
                .0,
            unstaking_image,
            unstaking_operator_descriptor: unstaking_output_desc,
            stake_funds,
        }
    }
}

/// Smaller version of [`StakeData`].
///
/// The original [`StakeData`] is obtained by adding  [`StakeSMCfg`] and [`StakeSMCtx`].
// NOTE: (@uncomputable) This struct is almost identical to `UnstakingInput`,
// but here the unstaking operator descriptor is of type `Descriptor`, which is validated.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MinimumStakeData {
    /// The UTXO that funds the stake transaction.
    pub stake_funds: OutPoint,
    /// The unstaking hash image.
    pub unstaking_image: sha256::Hash,
    /// The descriptor where the operator wants to receive the unstaked funds.
    pub unstaking_operator_desc: Descriptor,
}

impl MinimumStakeData {
    /// Combines the [`MinimumStakeData`] with [`StakeSMCfg`] and [`StakeSMCtx`]
    /// to obtain the original [`StakeData`].
    pub fn expand(&self, cfg: StakeSMCfg, ctx: &StakeSMCtx) -> StakeData {
        StakeData {
            protocol: cfg.protocol_params,
            setup: SetupParams {
                operator_index: ctx.operator_idx(),
                operator_pubkey: ctx
                    .operator_table()
                    .idx_to_btc_key(&ctx.operator_idx())
                    .expect("operator index must be valid")
                    .x_only_public_key()
                    .0,
                n_of_n_pubkey: ctx
                    .operator_table()
                    .aggregated_btc_key()
                    .x_only_public_key()
                    .0,
                unstaking_image: self.unstaking_image,
                unstaking_operator_descriptor: self.unstaking_operator_desc.clone(),
                stake_funds: self.stake_funds,
            },
        }
    }
}
