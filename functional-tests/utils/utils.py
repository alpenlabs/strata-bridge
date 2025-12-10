import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Thread

from bitcoinlib.services.bitcoind import BitcoindClient

from utils.constants import *


@dataclass
class OperatorKeyInfo:
    """Type definition for operator keys."""

    SEED: str
    GENERAL_WALLET: str
    STAKE_CHAIN_WALLET: str
    MUSIG2_KEY: str
    P2P_KEY: str


def read_operator_key(operator_idx: int) -> OperatorKeyInfo:
    """
    Get operator keys from artifacts/keys.json

    Args:
        operator_idx: Index of the operator (0-based)

    Returns:
        OperatorKeyInfo containing all operator key data
    """
    keys_path = Path(__file__).parent.parent / "artifacts" / "keys.json"
    with open(keys_path) as f:
        keys_data = json.load(f)

    raw_keys = keys_data[operator_idx]
    return OperatorKeyInfo(**raw_keys)


def generate_blocks(
    bitcoin_rpc: BitcoindClient,
    wait_dur,
    addr: str,
) -> Thread:
    thr = Thread(
        target=generate_task,
        args=(
            bitcoin_rpc,
            wait_dur,
            addr,
        ),
    )
    thr.start()
    return thr


def generate_task(rpc: BitcoindClient, wait_dur, addr):
    while True:
        time.sleep(wait_dur)
        try:
            rpc.proxy.generatetoaddress(1, addr)
        except Exception as ex:
            logging.warning(f"{ex} while generating to address {addr}")
            return


def wait_until(
    condition,
    timeout: int = 120,
    step: int = 1,
    error_msg: str = "Condition not met within timeout",
):
    """
    Generic wait function that polls a condition until it's met or timeout occurs.

    Args:
        condition: A callable that returns True when the condition is met.
        timeout: Timeout in seconds (default: 120).
        step: Poll interval in seconds (default: 1).
        error_msg: Custom error message for timeout.
    """
    end_time = time.time() + timeout

    while time.time() < end_time:
        time.sleep(step)  # sleep first

        try:
            if condition():
                return
        except Exception:
            pass

    raise TimeoutError(f"{error_msg} (timeout: {timeout}s)")


def wait_until_bridge_ready(rpc_client, timeout: int = 120, step: int = 1):
    """
    Waits until the bridge client reports readiness.

    Args:
        rpc_client: The RPC client to check for readiness
        timeout: Timeout in seconds (default 120 seconds)
        step: Poll interval in seconds (default 1 second)
    """
    wait_until(
        lambda: rpc_client.stratabridge_uptime() is not None,
        timeout=timeout,
        step=step,
        error_msg="Bridge did not start within timeout",
    )


def wait_until_bitcoind_ready(rpc_client, timeout: int = 120, step: int = 1):
    """
    Waits until the bitcoin client reports readiness.

    Args:
        rpc_client: The RPC client to check for readiness
        timeout: Timeout in seconds (default 120 seconds)
        step: Poll interval in seconds (default 1 second)
    """
    wait_until(
        lambda: rpc_client.proxy.getblockcount() is not None,
        timeout=timeout,
        step=step,
        error_msg="Bitcoind did not start within timeout",
    )
