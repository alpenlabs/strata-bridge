//! This module provides the constant values used throughout the crate.

/// Default depth at which a block is considered "buried".
///
/// This can be overridden everywhere it is used.
// TODO: <https://atlassian.alpenlabs.net/browse/STR-2682>
// Use different default finality depths depending on the active network.
pub(crate) const DEFAULT_BURY_DEPTH: usize = 6;
