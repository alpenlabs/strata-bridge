import logging

from bitcoinlib.services.bitcoind import BitcoindClient

from constants import DT_DEPOSIT_VOUT
from rpc.types import RpcDepositInfo, RpcDepositStatus
from utils.utils import wait_until


def wait_until_utxo_spent(bitcoin_rpc: BitcoindClient, txid: str, vout: int, timeout=300):
    """Wait until the specified UTXO is spent."""

    def check():
        return bitcoin_rpc.proxy.gettxout(txid, vout) is None

    wait_until(
        check,
        timeout=timeout,
        step=1,
        error_msg=f"UTXO (txid={txid}, vout={vout}) was not spent within {timeout}s",
    )


def wait_until_deposit_utxo_spent(bitcoin_rpc: BitcoindClient, deposit_txid: str, timeout=300):
    """Wait until the deposit UTXO is spent."""
    wait_until_utxo_spent(bitcoin_rpc, deposit_txid, DT_DEPOSIT_VOUT, timeout)


def _deposit_infos(bridge_rpc) -> list[dict]:
    deposit_indices: list[int] = bridge_rpc.stratabridge_depositIndices()
    logging.info(f"Current deposit indices: {deposit_indices}")

    return [bridge_rpc.stratabridge_depositInfo(deposit_idx) for deposit_idx in deposit_indices]


def wait_until_drt_recognized(bridge_rpc, drt_txid: str, timeout=300) -> int:
    """Wait until the deposit request with the specified txid is recognized."""
    result: dict[str, int | None] = {"deposit_id": None}

    def check_drt_recognized():
        for deposit_info in _deposit_infos(bridge_rpc):
            if deposit_info.get("deposit_request_txid") == drt_txid:
                result["deposit_id"] = int(deposit_info["deposit_idx"])
                return True
        return False

    wait_until(
        check_drt_recognized,
        timeout=timeout,
        step=1,
        error_msg=f"Timeout after {timeout} seconds waiting for DRT {drt_txid} to be recognized",
    )
    assert result["deposit_id"] is not None
    return result["deposit_id"]


def wait_until_deposit_status(
    bridge_rpc,
    deposit_id: int,
    target_status: type[RpcDepositStatus],
    timeout=300,
) -> RpcDepositInfo | None:
    """Wait until deposit reaches the target status.

    Args:
        bridge_rpc: RPC client for the bridge
        deposit_id: The deposit index
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
) -> list[int]:
    """Wait until all DRTs in the batch are recognized."""
    result: dict[str, list[int] | None] = {"deposit_ids": None}

    def check_deposit_batch():
        deposits_by_drt = {
            deposit_info.get("deposit_request_txid"): int(deposit_info["deposit_idx"])
            for deposit_info in _deposit_infos(bridge_rpc)
        }

        missing_txids = [drt_txid for drt_txid in drt_txids if drt_txid not in deposits_by_drt]
        if missing_txids:
            return False

        result["deposit_ids"] = [deposits_by_drt[drt_txid] for drt_txid in drt_txids]
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
) -> list[int]:
    """Wait until all DRTs are recognized and at least `threshold` reach `expected_status`.

    The threshold is evaluated only after every DRT in `drt_txids` appears in the
    bridge RPC's deposit index list. This keeps the helper's semantics stable for
    restart tests where recognition and progress are checked as separate milestones.
    """
    result: dict[str, list[int] | None] = {"deposit_ids": None}

    def check_deposit_batch():
        deposits_by_drt = {
            deposit_info.get("deposit_request_txid"): int(deposit_info["deposit_idx"])
            for deposit_info in _deposit_infos(bridge_rpc)
        }

        missing_txids = [drt_txid for drt_txid in drt_txids if drt_txid not in deposits_by_drt]
        if missing_txids:
            return False

        matching_status_count = 0
        for drt_txid in drt_txids:
            deposit_idx = deposits_by_drt[drt_txid]
            deposit_info = bridge_rpc.stratabridge_depositInfo(deposit_idx)
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
            result["deposit_ids"] = [deposits_by_drt[drt_txid] for drt_txid in drt_txids]
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
