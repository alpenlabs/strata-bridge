//! Just import this if you want a no-brainer `use` statement to get the most of the `stake-chain`
//! crate.

pub use crate::{
    errors::StakeChainError,
    stake_chain::StakeChain,
    transactions::{constants::*, pre_stake::PreStakeTx, stake::StakeTx},
};
