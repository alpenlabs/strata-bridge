import flexitest

from rpc.client import JsonrpcClient
from utils.utils import wait_until


def inject_service_create_rpc(svc: flexitest.service.ProcService, rpc_url: str, name: str):
    """
    Injects a `create_rpc` method using JSON-RPC onto a `ProcService`, checking
    its status before each call.
    """

    def _status_ck(method: str):
        """
        Hook to check that the process is still running before every call.
        """
        # TODO: (@Rajil1213) make `timeout` and `step` configurable
        wait_until(svc.check_status, timeout=30, step=1, error_msg=f"service '{name}' has stopped")

    def _create_rpc() -> JsonrpcClient:
        vrpc = JsonrpcClient(rpc_url)
        vrpc._pre_call_hook = _status_ck
        return vrpc

    svc.create_rpc = _create_rpc
