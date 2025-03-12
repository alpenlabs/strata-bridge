//! This module contains all the constants used in the persistence layer.

use std::time::Duration;

/// The number of times to retry a database operation before erroring out.
pub const DEFAULT_MAX_RETRY_COUNT: usize = 5;

/// The period of time to wait before retrying a database operation.
pub const DEFAULT_BACKOFF_PERIOD: Duration = Duration::from_secs(1);
