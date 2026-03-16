import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from threading import Event, Thread

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


class MinerThread:
    """Wraps the block-generation thread with a stop signal."""

    def __init__(self, thread: Thread, stop_event: Event):
        self._thread = thread
        self._stop_event = stop_event

    def stop(self, timeout: float = 5):
        self._stop_event.set()
        self._thread.join(timeout=timeout)


def generate_blocks(
    bitcoin_rpc: BitcoindClient,
    wait_dur,
    addr: str,
) -> MinerThread:
    stop_event = Event()
    thr = Thread(
        target=generate_task,
        args=(
            bitcoin_rpc,
            wait_dur,
            addr,
            stop_event,
        ),
    )
    thr.start()
    return MinerThread(thr, stop_event)


def generate_task(
    rpc: BitcoindClient,
    wait_dur,
    addr,
    stop_event: Event,
    max_retries_per_tick: int = 3,
    max_consecutive_failed_ticks: int = 5,
    max_retry_delay: int = 3,
):
    consecutive_failed_ticks = 0

    while not stop_event.is_set():
        if stop_event.wait(timeout=wait_dur):
            break
        logging.debug(f"Generating block to address {addr}")
        retry_delay = 1
        tick_succeeded = False

        for attempt in range(1, max_retries_per_tick + 1):
            if stop_event.is_set():
                return
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
                if stop_event.wait(timeout=retry_delay):
                    return
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


def snapshot_log_offsets(log_paths: list[str]) -> dict[str, int]:
    """
    Capture the current read offset for each log file path.

    Args:
        log_paths: Log files to snapshot.

    Returns:
        Mapping from log path to the current file size.
    """
    return {
        log_path: Path(log_path).stat().st_size if Path(log_path).exists() else 0
        for log_path in log_paths
    }


def wait_until_logs_match(
    log_offsets: dict[str, int],
    matcher: Callable[[str], bool],
    timeout: int = 120,
    step: int = 1,
    error_msg: str = "Condition not met within timeout",
):
    """
    Wait until any newly appended log line matches the provided predicate.

    Args:
        log_offsets: Starting offsets keyed by log path.
        matcher: Predicate applied to each newly appended line.
        timeout: Timeout in seconds (default: 120).
        step: Poll interval in seconds (default: 1).
        error_msg: Custom error message for timeout.

    The offsets are intentional. Tests that inspect whole log files can match stale
    lines emitted before the action under test. By reading only from a captured
    offset onward, this helper preserves "did this happen after X?" semantics.
    """

    def has_matching_line():
        for log_path, start_offset in log_offsets.items():
            path = Path(log_path)
            if not path.exists():
                continue

            with path.open(encoding="utf-8", errors="ignore") as f:
                f.seek(start_offset)
                for line in f:
                    if matcher(line):
                        return True

        return False

    wait_until(
        has_matching_line,
        timeout=timeout,
        step=step,
        error_msg=error_msg,
    )


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


def wait_for_tx_confirmation(bitcoin_rpc, txid: str, timeout: int = 60) -> str:
    """
    Waits until a transaction is confirmed and returns the block hash it was included in.

    Args:
        bitcoin_rpc: Bitcoin RPC client.
        txid: Transaction ID to wait for.
        timeout: Timeout in seconds (default: 60).

    Returns:
        The block hash containing the transaction.
    """
    block_hash = None

    def check():
        nonlocal block_hash
        tx_info = bitcoin_rpc.proxy.getrawtransaction(txid, True)
        if "blockhash" in tx_info:
            block_hash = tx_info["blockhash"]
            return True
        return False

    wait_until(check, timeout=timeout, error_msg=f"Tx {txid} not confirmed")
    assert block_hash is not None
    return block_hash


def generate_p2p_ports(start_port=12800):
    """P2P port generator to avoid port conflicts."""
    port = start_port
    while True:
        yield f"/ip4/127.0.0.1/tcp/{port}"
        port += 1
