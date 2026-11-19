//! The contract between a bridge node and its sidecar.
//!
//! A bridge operator can attach a sidecar: a separate service that decides whether this node may
//! take two of its own actions. The bridge asks; the sidecar answers. This crate holds the only
//! types both sides share, so either side can be built and reviewed without the other.
//!
//! # One exchange
//!
//! ```text
//! bridge                                          sidecar
//!   │  sidecar_assess(AssessmentRequest)             │
//!   │ ─────────────────────────────────────────────► │
//!   │                                   Assessment   │
//!   │ ◄───────────────────────────────────────────── │
//! ```
//!
//! - [`AssessmentRequest`] carries one [`Action`]: a deposit request this node may take part in, or
//!   a withdrawal request assigned to this node to pay. Its [`id`](AssessmentRequest::id) is a hash
//!   of its content, so the same question always has the same ID and any changed field is a new
//!   question.
//! - [`Assessment`] answers with a [`Decision`] (`Proceed`, `Decline` or `Defer`), bound to that
//!   request ID, and valid only for a bounded time.
//!
//! # Rules both sides rely on
//!
//! - **Silence is never a decision.** The bridge acts only on a `Proceed` or `Decline` that passes
//!   [`Assessment::valid_for`]. No answer, a transport error, a malformed, stale or mismatched
//!   answer, and `Defer` all leave the action waiting, and the bridge asks again later.
//! - **`Defer` is not an error.** A healthy sidecar that cannot decide yet (a lookup is slow, data
//!   has not arrived, a manual review is queued) answers `Defer`.
//! - **The wire is strict.** The request and answer objects reject unknown fields, so adding or
//!   renaming a field is a protocol change: bump [`PROTOCOL_VERSION`] and upgrade both sides
//!   together. The contract is the JSON object form pinned in this crate's tests; other encodings
//!   serde happens to accept (a struct as an array, an enum as a map) are not part of it. The
//!   JSON-RPC envelope around them is jsonrpsee's.
//! - **Deployment settings stay in configuration.** Which network each side runs on, which policy
//!   the sidecar applies, and how the two are paired are set and checked at deployment, not carried
//!   on the wire. The only compatibility field is [`PROTOCOL_VERSION`].
//! - **Both sides compute request IDs with this crate.** The ID hashes this crate's exact JSON
//!   encoding; an implementation in another language must reproduce it byte for byte.
//!
//! # Layout
//!
//! - `request`: the question ([`Action`], [`AssessmentRequest`]).
//! - `assessment`: the answer ([`Decision`], [`Assessment`]).
//! - `rpc`: the JSON-RPC method; the client side is behind the `client` feature.

mod assessment;
mod request;

pub mod rpc;

pub use assessment::{Assessment, Decision, unix_ms};
pub use request::{Action, AssessmentRequest, PROTOCOL_VERSION};
