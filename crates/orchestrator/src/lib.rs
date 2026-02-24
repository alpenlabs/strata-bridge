// needed because of `wots` in `p2p-types`
// TODO: (@Rajil1213) remove these when `wots` is removed.
#![expect(incomplete_features)]
#![feature(generic_const_exprs)]
//! The shallowest layer of abstraction in the `strata-bridge` that is responsible for:
//!
//! - Dispatching duty executors that implement the actual duties of the bridge (e.g. relaying
//!   messages, signing, etc.).
//! - Providing a high-level API for the `strata-bridge` to interact with the underlying layers of
//!   abstraction.
//! - Subscribing to various event streams, filtering and routing them to the appropriate state
//!   machines.
//! - Driving state machines that implement the core business-logic of the bridge.
//! - Providing a channel of communication between the various state machines in the bridge.

pub mod duty_dispatcher;
pub mod errors;
pub mod events_classifier;
pub mod events_mux;
pub mod events_router;
pub mod persister;
pub mod pipeline;
pub mod signals_router;
pub mod sm_registry;
pub mod sm_types;

#[cfg(test)]
mod testing;
