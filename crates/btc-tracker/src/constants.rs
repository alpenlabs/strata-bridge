//! This module provides the constant values used throughout the crate.

/// Default depth at which a block is considered "buried".
///
/// This can be overridden everywhere it is used.
// TODO: <https://alpenlabs.atlassian.net/browse/STR-2682>
// Use different default finality depths depending on the active network.
pub(crate) const DEFAULT_BURY_DEPTH: usize = 6;

/// Default number of blocks backfilled, fetched and processed at once after a gap in the block
/// stream. Roughly one day's worth of blocks at Bitcoin's ten minute block time.
///
/// This can be overridden everywhere it is used.
pub(crate) const DEFAULT_BACKFILL_BATCH_SIZE: usize = 144;
