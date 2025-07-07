//! Crate includes reusable utils for services that handle common behavior.
//! Such as initializing the tracing framework and whatever else.

pub mod logging;

// Re-export tracing crate for convenience.
pub use tracing;
