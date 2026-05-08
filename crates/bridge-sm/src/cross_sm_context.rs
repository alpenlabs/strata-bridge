//! Auxiliary context resolved from sibling state machines.
//!
//! This data is destination-scoped: it is not a signal that should causally
//! persist another state machine, but context that the receiving state machine
//! may use while processing its own event.

use serde::{Deserialize, Serialize};

/// Cross-state-machine context available to a state transition.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossSmContext {
    /// Revealed unstaking preimage for the graph owner, if known.
    unstaking_preimage: Option<[u8; 32]>,
}

impl CrossSmContext {
    /// Constructs a context with a revealed unstaking preimage.
    pub const fn with_unstaking_preimage(unstaking_preimage: [u8; 32]) -> Self {
        Self {
            unstaking_preimage: Some(unstaking_preimage),
        }
    }

    /// Returns the revealed unstaking preimage, if known.
    pub const fn unstaking_preimage(&self) -> Option<[u8; 32]> {
        self.unstaking_preimage
    }
}
