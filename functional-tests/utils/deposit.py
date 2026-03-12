import logging

from bitcoinlib.services.bitcoind import BitcoindClient

from constants import DT_DEPOSIT_VOUT
from rpc.types import RpcDepositInfo, RpcDepositStatus
from utils.utils import wait_until


def wait_until_deposit_utxo_spent(bitcoin_rpc: BitcoindClient, deposit_txid: str, timeout=300):
    """Wait until the deposit UTXO is spent."""

    def check():
        return bitcoin_rpc.proxy.gettxout(deposit_txid, DT_DEPOSIT_VOUT) is None

    wait_until(
        check,
        timeout=timeout,
        step=1,
        error_msg=(
            f"Deposit UTXO (txid={deposit_txid}, vout={DT_DEPOSIT_VOUT}) "
            f"was not spent within {timeout}s"
        ),
    )


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
        step=1,
        error_msg=f"Timeout after {timeout} seconds waiting for DRT {drt_txid} to be recognized",
    )
    return result["deposit_id"]


def wait_until_deposit_status(
    bridge_rpc,
    deposit_id,
    target_status: type[RpcDepositStatus],
    timeout=300,
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


def wait_until_drts_recognized(
    bridge_rpc,
    drt_txids: list[str],
    timeout=300,
) -> list[str]:
    """Wait until all DRTs in the batch are recognized."""
    result: dict[str, list[str] | None] = {"deposit_ids": None}

    def check_deposit_batch():
        deposit_requests: list[str] = bridge_rpc.stratabridge_depositRequests()
        logging.info(f"Current deposit requests: {deposit_requests}")

        missing_txids = [drt_txid for drt_txid in drt_txids if drt_txid not in deposit_requests]
        if missing_txids:
            return False

        result["deposit_ids"] = drt_txids
        return True

    wait_until(
        check_deposit_batch,
        timeout=timeout,
        step=1,
        error_msg=f"Timeout after {timeout} seconds waiting for DRT batch recognition",
    )
    assert result["deposit_ids"] is not None
    return result["deposit_ids"]


def wait_until_drts_reach_status_threshold(
    bridge_rpc,
    drt_txids: list[str],
    expected_status: type[RpcDepositStatus],
    threshold: int,
    timeout=300,
) -> list[str]:
    """Wait until all DRTs are recognized and at least `threshold` reach `expected_status`.

    The threshold is evaluated only after every DRT in `drt_txids` appears in the
    bridge RPC's deposit request list. This keeps the helper's semantics stable for
    restart tests where recognition and progress are checked as separate milestones.
    """
    result: dict[str, list[str] | None] = {"deposit_ids": None}

    def check_deposit_batch():
        deposit_requests: list[str] = bridge_rpc.stratabridge_depositRequests()
        logging.info(f"Current deposit requests: {deposit_requests}")

        missing_txids = [drt_txid for drt_txid in drt_txids if drt_txid not in deposit_requests]
        if missing_txids:
            return False

        matching_status_count = 0
        for drt_txid in drt_txids:
            deposit_info = bridge_rpc.stratabridge_depositInfo(drt_txid)
            logging.info(f"Deposit info for {drt_txid}: {deposit_info}")
            status: str = deposit_info.get("status", {}).get("status")
            if status == expected_status.status:
                matching_status_count += 1

        logging.info(
            "Post-restart DRT status summary: %s=%s/%s, threshold=%s",
            expected_status.status,
            matching_status_count,
            len(drt_txids),
            threshold,
        )

        if matching_status_count >= threshold:
            result["deposit_ids"] = drt_txids
            return True

        return False

    wait_until(
        check_deposit_batch,
        timeout=timeout,
        step=1,
        error_msg=(
            "Timeout after "
            f"{timeout} seconds waiting for all DRTs to be recognized and at least "
            f"{threshold} deposits to remain in status '{expected_status.status}'"
        ),
    )
    assert result["deposit_ids"] is not None
    return result["deposit_ids"]
