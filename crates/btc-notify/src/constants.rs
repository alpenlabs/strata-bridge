//! This module provides the constant values used throughout the crate.

/// Default depth at which a block is considered "buried".
///
/// This can be overridden everywhere it is used.
// TODO(proofofkeags), TODO(Rajil1213): Use different default finality depths depending on the
// network we are on?
pub(crate) const DEFAULT_BURY_DEPTH: usize = 6;
