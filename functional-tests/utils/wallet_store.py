"""Helpers for the persisted operator-wallet stores under a bridge node's wallet data dir.

The bridge node keeps one SQLite file per wallet (general, reserved) under
`operator_wallet.data_dir`. The operator factory places that directory at
`<service dir>/wallet` and exposes it as `props["wallet_data_dir"]`. Tests read the files
directly with `sqlite3`; BDK's schema is stable (`bdk_blocks`, `bdk_wallet`) and SQLite's WAL
mode allows a concurrent reader while the node runs.
"""

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from utils.utils import wait_until

GENERAL_STORE = "general-wallet.sqlite"
RESERVED_STORE = "reserved-wallet.sqlite"


@dataclass(frozen=True)
class StoreState:
    """What a wallet store says about itself, read straight from the file."""

    tip_height: int
    network: str
    descriptor: str


def wallet_data_dir(node) -> Path:
    return Path(node.props["wallet_data_dir"])


def store_path(node, store_file: str) -> Path:
    return wallet_data_dir(node) / store_file


def read_store(path: Path) -> StoreState:
    """Read the persisted tip, network, and descriptor from a BDK SQLite store.

    Raises if the file is missing rather than letting sqlite3 create an empty one.
    """
    if not path.exists():
        raise FileNotFoundError(path)
    con = sqlite3.connect(str(path), timeout=5)
    try:
        (tip,) = con.execute("SELECT MAX(block_height) FROM bdk_blocks").fetchone()
        network, descriptor = con.execute("SELECT network, descriptor FROM bdk_wallet").fetchone()
    finally:
        con.close()
    return StoreState(tip_height=tip, network=network, descriptor=descriptor)


def wait_until_store_synced(path: Path, height: int, timeout: int = 180):
    """Wait until the store on disk has committed a tip at or above `height`."""
    wait_until(
        lambda: read_store(path).tip_height >= height,
        timeout=timeout,
        error_msg=f"{path.name} did not reach height {height}",
    )


def wait_until_exited(node, timeout: int = 120) -> int:
    """Wait for a started service process to exit on its own and return its exit code.

    Call `node.stop()` afterwards so flexitest records the exit and clears the process handle.
    """
    proc = node.proc
    assert proc is not None, "service has no process handle; was it started?"
    wait_until(
        lambda: proc.poll() is not None,
        timeout=timeout,
        error_msg="bridge node did not exit",
    )
    return proc.returncode
