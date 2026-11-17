//! The bridge node's client for its sidecar.
//!
//! [`SidecarClient`] is the orchestrator's `SidecarHook` backed by a sidecar service: it asks the
//! service over JSON-RPC, using the contract in [`strata_bridge_sidecar_api`].
//!
//! The pipeline asks the hook after every committed batch, so the client answers from memory and
//! never blocks. The first ask for a request starts a call in the background and returns no
//! decision. When the call finishes, the client wakes the pipeline, which asks again and gets the
//! answer. A failed call, or a `Defer`, is retried a few seconds later.
//!
//! # Layout
//!
//! - `config`: the node's `[sidecar]` section and the client's fixed limits.
//! - `client`: [`SidecarClient`]: building it, the answers it holds, and `poll`.
//! - `worker`: the one background task that runs the calls.

mod client;
mod config;
mod worker;

pub use client::SidecarClient;
pub use config::SidecarConfig;
