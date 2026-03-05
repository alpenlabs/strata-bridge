//! Shared state machine utility helpers.

use std::fmt::{Debug, Display};

use crate::errors::BridgeSMError;

/// Downgrades peer-driven invalid-event failures into rejections.
///
/// Peer messages can legitimately arrive late, out of order, or after the local
/// state machine has already advanced past the relevant state. Treating those
/// cases as `InvalidEvent` would crash the node even though the correct behavior
/// is to ignore the stale message and continue. This is also a DoS boundary:
/// `InvalidEvent` is treated as fatal by the orchestrator pipeline, so a peer
/// that can trigger it with otherwise well-formed but stale traffic can crash
/// other nodes unless we downgrade those cases here.
pub(crate) fn soften_peer_event_error<S, E>(
    event: E,
    err: BridgeSMError<S, E>,
) -> BridgeSMError<S, E>
where
    S: Display + Debug,
    E: Display + Debug,
{
    // NOTE: (@Rajil1213) This is a scoped safety fix chosen to avoid a broader
    // STF refactor. We could model stale peer traffic directly in the STF by
    // returning `Rejected` from each peer-facing transition handler, but that
    // would widen the change across many handlers and duplicate the same
    // downgrade logic. Centralizing it here keeps the fix narrow.
    match err {
        BridgeSMError::InvalidEvent { state, reason, .. } => BridgeSMError::Rejected {
            state,
            event: Box::new(event),
            reason: reason.unwrap_or_else(|| {
                "Peer message is not applicable in the current state".to_string()
            }),
        },
        _ => err,
    }
}
