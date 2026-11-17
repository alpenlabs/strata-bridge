//! The JSON-RPC method: `bridgeSidecar_assess`.
//!
//! The `client` feature generates `SidecarRpcClient` for the bridge; the `server` feature
//! generates `SidecarRpcServer` for a sidecar. jsonrpsee's `rpc` macro needs the matching
//! jsonrpsee features for each side, hence one attribute per feature combination.

use jsonrpsee::proc_macros::rpc;

use crate::{Assessment, AssessmentRequest};

/// The sidecar's RPC interface. A transport error never lets the bridge act.
#[cfg_attr(
    all(feature = "client", feature = "server"),
    rpc(client, server, namespace = "bridgeSidecar")
)]
#[cfg_attr(
    all(feature = "client", not(feature = "server")),
    rpc(client, namespace = "bridgeSidecar")
)]
#[cfg_attr(
    all(feature = "server", not(feature = "client")),
    rpc(server, namespace = "bridgeSidecar")
)]
pub trait SidecarRpc {
    /// Answers one request.
    #[method(name = "assess")]
    async fn assess(&self, request: AssessmentRequest) -> jsonrpsee::core::RpcResult<Assessment>;
}
