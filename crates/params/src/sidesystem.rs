//! Params related to the side system.

use serde::{Deserialize, Serialize};

/// The parameters related to the side system where the funds are bridge-in/minted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SideSystemParams {
    /// The size of the address in the sidesystem's execution environment where the funds are
    /// minted.
    pub ee_addr_size: usize,
}
