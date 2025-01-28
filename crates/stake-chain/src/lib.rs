//! # Strata Bridge Stake Chain
//!
//! In a BitVM-based brideg, each transaction graph requires a stake that gets burnt/slashed/spent
//! in the corresponding BitVM game.
//!
//! Additionally, the staked amount must be greater than the amount paid to the operator in the
//! `Challenge` transaction i.e., the amount required to post the `Assert` transactions on chain.
//! This means that the amount of stake that an operator must lock in this setup scales linearly
//! with the number of deposits and that leads to a very high capital requirement for an operator.
//! In practice, operating the bridge may become too costly an endeavor (for example, if the rate of
//! withdrawals is too low).
//!
//! Ideally, we would like a single stake to be reused for each deposit. If any operator makes a
//! faulty claim, this stake is spent by a disprover and renders any future reimbursement payouts
//! impossible. The purpose of a stake chain is to enable this by creating a series of transactions
//! that “move” the stake. The tradeoff is that each operator can service any one withdrawal request
//! per stake chain at any given time i.e., if two withdrawal requests are assigned to the same
//! operator with one stake chain, they cannot process both those requests concurrently. However, in
//! the same scenario, if each operator had two stake chains, they could, in fact, process two
//! separate withdrawal requests concurrently.

#![feature(duration_constructors)] // for constructing `Duration::from_days`

pub mod errors;
pub mod stake_chain;
pub mod transactions;

pub use errors::StakeChainError;
pub use stake_chain::StakeChain;
