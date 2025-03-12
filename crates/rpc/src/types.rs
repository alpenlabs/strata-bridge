//! Types for the RPC server.

use serde::{Deserialize, Serialize};

/// Enum representing the status of a bridge operator
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcOperatorStatus {
    /// Operator is online and ready to process transactions.
    Online,

    /// Operator is offline and not processing transactions.
    Offline,
}
