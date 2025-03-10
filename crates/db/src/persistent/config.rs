//! This module contains all the configuration types used in the persistence layer.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::constants::{DEFAULT_BACKOFF_PERIOD, DEFAULT_MAX_RETRY_COUNT};

/// The configuration for the SQLite database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbConfig {
    max_retry_count: usize,
    backoff_period: Duration,
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            max_retry_count: DEFAULT_MAX_RETRY_COUNT,
            backoff_period: DEFAULT_BACKOFF_PERIOD,
        }
    }
}

impl DbConfig {
    /// Sets the max retry count for the database.
    pub fn with_max_retry_count(self, count: usize) -> Self {
        Self {
            max_retry_count: count,
            ..self
        }
    }

    /// Sets the backoff period for the database.
    pub fn with_backoff_period(self, period: Duration) -> Self {
        Self {
            backoff_period: period,
            ..self
        }
    }

    /// Returns the max retry count for the database.
    pub fn max_retry_count(&self) -> usize {
        self.max_retry_count
    }

    /// Returns the backoff period for the database.
    pub fn backoff_period(&self) -> Duration {
        self.backoff_period
    }
}
