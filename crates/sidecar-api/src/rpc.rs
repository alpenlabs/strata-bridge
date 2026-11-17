//! The JSON-RPC method `sidecar_assess`.
//!
//! The server side (`SidecarRpcServer`, implemented by a sidecar) is always generated; the
//! `client` feature adds `SidecarRpcClient` for the bridge, as in the bridge's own RPC crate.

use jsonrpsee::{core::RpcResult, proc_macros::rpc};

use crate::{Assessment, AssessmentRequest};

/// `sidecar_assess`: the bridge sends one request, the sidecar returns its assessment.
#[cfg_attr(not(feature = "client"), rpc(server, namespace = "sidecar"))]
#[cfg_attr(feature = "client", rpc(server, client, namespace = "sidecar"))]
pub trait SidecarRpc {
    /// Answers one request.
    #[method(name = "assess")]
    async fn assess(&self, request: AssessmentRequest) -> RpcResult<Assessment>;
}

#[cfg(test)]
mod tests {
    use jsonrpsee::core::async_trait;

    use super::*;

    struct Unreachable;

    #[async_trait]
    impl SidecarRpcServer for Unreachable {
        async fn assess(&self, _request: AssessmentRequest) -> RpcResult<Assessment> {
            unreachable!("only the method name is checked")
        }
    }

    /// Deployed bridges and sidecars call this exact name. A change here is a protocol change.
    #[test]
    fn the_method_is_sidecar_assess() {
        let module = Unreachable.into_rpc();
        assert_eq!(
            module.method_names().collect::<Vec<_>>(),
            ["sidecar_assess"]
        );
    }
}
