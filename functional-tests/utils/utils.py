import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from threading import Thread

from bitcoinlib.services.bitcoind import BitcoindClient

from constants import *


@dataclass
class OperatorKeyInfo:
    """Type definition for operator keys."""

    SEED: str
    GENERAL_WALLET: str
    GENERAL_WALLET_DESCRIPTOR: str
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


def generate_task(
    rpc: BitcoindClient,
    wait_dur,
    addr,
    max_retries_per_tick: int = 3,
    max_consecutive_failed_ticks: int = 5,
    max_retry_delay: int = 3,
):
    consecutive_failed_ticks = 0

    while True:
        time.sleep(wait_dur)
        logging.debug(f"Generating block to address {addr}")
        retry_delay = 1
        tick_succeeded = False

        for attempt in range(1, max_retries_per_tick + 1):
            try:
                rpc.proxy.generatetoaddress(1, addr)
                tick_succeeded = True
                break
            except Exception as ex:
                if attempt == max_retries_per_tick:
                    logging.warning(
                        f"{ex} while generating to address {addr} "
                        f"(attempt {attempt}/{max_retries_per_tick})"
                    )
                    break

                logging.warning(
                    f"{ex} while generating to address {addr} "
                    f"(attempt {attempt}/{max_retries_per_tick}); retrying in {retry_delay}s"
                )
                time.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, max_retry_delay)

        if tick_succeeded:
            consecutive_failed_ticks = 0
            continue

        consecutive_failed_ticks += 1
        if consecutive_failed_ticks >= max_consecutive_failed_ticks:
            logging.error(
                "Stopping miner thread after %s consecutive failed ticks while generating to %s",
                consecutive_failed_ticks,
                addr,
            )
            return


def wait_until(
    condition: Callable[[], bool],
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
        except Exception as e:
            ety = type(e)
            logging.debug(f"caught exception {ety}, will still wait for timeout: {e}")
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


def generate_p2p_ports(start_port=12800):
    """P2P port generator to avoid port conflicts."""
    port = start_port
    while True:
        yield f"/ip4/127.0.0.1/tcp/{port}"
        port += 1
