//! This module provides the constant values used throughout the crate.

/// Default depth at which a block is considered "buried".
///
/// This can be overridden everywhere it is used.
// TODO: <https://alpenlabs.atlassian.net/browse/STR-2682>
// Use different default finality depths depending on the active network.
pub(crate) const DEFAULT_BURY_DEPTH: usize = 6;

/// Default number of block fetches that run ahead of the block being processed while backfilling
/// a gap in the block stream. Block subscribers apply blocks far slower than bitcoind serves them,
/// so a few fetches in flight are enough to keep them busy.
///
/// This can be overridden everywhere it is used.
pub(crate) const DEFAULT_BACKFILL_FETCH_CONCURRENCY: usize = 8;

/// Default number of block events each block subscription queues before the client waits for the
/// subscriber to catch up. Subscribers handle block events one at a time, so this only needs to
/// absorb short bursts.
///
/// This can be overridden everywhere it is used.
pub(crate) const DEFAULT_BLOCK_SUBSCRIPTION_CAPACITY: usize = 16;
