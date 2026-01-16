import logging

from rpc.types import RpcDepositInfo, RpcDepositStatus
from utils.utils import wait_until


def wait_until_drt_recognized(bridge_rpc, drt_txid: str, timeout=300) -> str | None:
    """Wait until the deposit request with the specified txid is recognized."""
    result: dict[str, str | None] = {"deposit_id": None}

    def check_drt_recognized():
        deposit_requests: list[str] = bridge_rpc.stratabridge_depositRequests()
        logging.info(f"Current deposit requests: {deposit_requests}")

        for txid in deposit_requests:
            if txid == drt_txid:
                result["deposit_id"] = txid
                return True
        return False

    wait_until(
        check_drt_recognized,
        timeout=timeout,
        step=10,
        error_msg=f"Timeout after {timeout} seconds waiting for DRT {drt_txid} to be recognized",
    )
    return result["deposit_id"]


def wait_until_deposit_status(
    bridge_rpc, deposit_id, target_status: type[RpcDepositStatus], timeout=300
) -> RpcDepositInfo | None:
    """Wait until deposit reaches the target status.

    Args:
        bridge_rpc: RPC client for the bridge
        deposit_id: The deposit request txid
        target_status: Status to wait for
        timeout: Maximum wait time in seconds
    """
    result = {"deposit_info": None}

    def check_deposit_status():
        result["deposit_info"] = bridge_rpc.stratabridge_depositInfo(deposit_id)
        logging.info(f"Deposit info for {deposit_id}: {result['deposit_info']}")
        status: str = result["deposit_info"].get("status", {}).get("status")
        return status == target_status.status

    wait_until(
        check_deposit_status,
        timeout=timeout,
        step=10,
        error_msg=f"Timeout after {timeout} seconds waiting for deposit status '{target_status}'",
    )
    return result["deposit_info"]
