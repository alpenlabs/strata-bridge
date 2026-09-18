//! Context for the Stake State Machine.

use bitcoin::{OutPoint, hashes::sha256};
use bitcoin_bosd::Descriptor;
use serde::{Deserialize, Serialize};
use strata_bridge_primitives::{
    covenant::{CovenantId, StakeKey},
    operator_table::{OperatorTable, PublicOperatorTable},
    types::OperatorIdx,
};
use strata_bridge_tx_graph::stake_graph::{SetupParams, StakeData};
use thiserror::Error;

use crate::stake::config::StakeSMCfg;

/// Invalid immutable stake context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum StakeContextError {
    /// The owner is absent from the covenant.
    #[error("stake owner is not a covenant member")]
    OwnerAbsent,
    /// The local signer is absent from the covenant.
    #[error("local signer is not a covenant member")]
    SignerAbsent,
    /// The identity does not match the supplied signing keys.
    #[error("covenant identity does not match the operator table")]
    CovenantMismatch,
}

/// Immutable execution context for one operator's stake in one covenant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StakeSMCtx {
    stake_key: StakeKey,
    operator_table: PublicOperatorTable,
    local_operator: Option<OperatorIdx>,
}

impl StakeSMCtx {
    /// Creates a participant context with an explicit admin activation boundary.
    ///
    /// # Panics
    /// Panics if the owner is absent or the keys cannot be aggregated.
    pub fn new(
        operator_idx: OperatorIdx,
        operator_table: OperatorTable,
        activation_height: u64,
    ) -> Self {
        let covenant = CovenantId::from_operator_table(&operator_table, activation_height)
            .expect("valid covenant signing keys");
        let pov = operator_table.pov_idx();
        Self::from_public(
            StakeKey {
                covenant,
                operator: operator_idx,
            },
            operator_table.into_public(),
            Some(pov),
        )
        .expect("valid stake context")
    }

    /// Creates a public or participant context, validating owner, local membership, and identity.
    /// The caller must separately validate the full membership and protocol configuration.
    pub fn from_public(
        stake_key: StakeKey,
        operator_table: PublicOperatorTable,
        local_operator: Option<OperatorIdx>,
    ) -> Result<Self, StakeContextError> {
        if !operator_table.contains_idx(&stake_key.operator) {
            return Err(StakeContextError::OwnerAbsent);
        }
        if local_operator.is_some_and(|idx| !operator_table.contains_idx(&idx)) {
            return Err(StakeContextError::SignerAbsent);
        }
        if CovenantId::from_operator_table(&operator_table, stake_key.covenant.activation_height)
            .ok()
            != Some(stake_key.covenant)
        {
            return Err(StakeContextError::CovenantMismatch);
        }
        Ok(Self {
            stake_key,
            operator_table,
            local_operator,
        })
    }

    /// Returns the exact covenant-qualified stake identity.
    pub const fn stake_key(&self) -> StakeKey {
        self.stake_key
    }

    /// Returns the stake owner.
    pub const fn operator_idx(&self) -> OperatorIdx {
        self.stake_key.operator
    }

    /// Returns the exact public covenant membership.
    pub const fn operator_table(&self) -> &PublicOperatorTable {
        &self.operator_table
    }

    /// Returns the local signing member, or none for observers.
    pub const fn pov_idx(&self) -> Option<OperatorIdx> {
        self.local_operator
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
