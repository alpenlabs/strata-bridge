//! Classification of on-chain events (buried blocks) into state-machine-specific events.
//!
//! This module handles:
//! - Phase 1: Detecting new deposit requests and spawning SMs (TODO)
//! - Phase 2: Running `TxClassifier::classify_tx()` per SM per transaction (TODO)
//! - Phase 3: Appending `NewBlock` cursor events for all active SMs (TODO)

use btc_tracker::event::BlockEvent;

use crate::{sm_registry::SMRegistry, sm_types::{SMEvent, SMId}};

/// Classifies a buried block into a list of (SMId, SMEvent) targets.
///
/// Currently a stub — all three phases are TODO pending TxClassifier implementation.
pub(crate) const fn classify_block(
    _block_event: &BlockEvent,
    _registry: &SMRegistry,
) -> Vec<(SMId, SMEvent)> {
    // TODO: Phase 1 — detect new deposit requests, spawn new SMs into the registry
    // TODO: Phase 2 — classify transactions against all active SMs via TxClassifier
    // TODO: Phase 3 — append NewBlock cursor events for all active SMs

    Vec::new()
}
