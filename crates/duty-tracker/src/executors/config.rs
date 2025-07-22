//! This mdoule contains the configuration for the duty executors.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// The configuration for retrying the publishing of stake chain transactions.
///
/// As there may be a non-zero timelock between consecutive transactions in the stake chain, it is
/// not possible to execute withdrawal duties in parallel. This configuration tells the executor how
/// soon to retry publishing a stake chain transaction in case of failure and how many times to do
/// it.
// NOTE: (@Rajil1213) this is a temporary solution to handle parallel execution of withdrawal
// fulfillment until we fundamentally reshape the current model of the contract manager as it
// pertains to the stake chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StakeTxRetryConfig {
    /// The maximum number of retries for a stake transaction.
    pub max_retries: u32,

    /// The delay between retries.
    pub retry_delay: Duration,
}
