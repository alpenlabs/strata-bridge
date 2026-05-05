"""Standalone builder for the committed bitcoin snapshot fixture.

Run via ``./build-bitcoin-snapshot.sh``. Mines ``initial_blocks`` regtest
blocks to a fresh ``testwallet`` address, then writes the resulting datadir
to ``functional-tests/.bitcoin-snapshot/`` so subsequent test runs can skip
the mine.
"""

from __future__ import annotations

import argparse
import logging
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import closing
from pathlib import Path

from bitcoinlib.services.bitcoind import BitcoindClient

from envs.btc_config import BitcoinEnvConfig
from factory.bitcoin import (
    BD_PASSWORD,
    BD_USERNAME,
    BD_WALLETNAME,
    PORT_KEYS,
    build_bitcoind_args,
)
from utils.bitcoin_snapshot import snapshot_path, write_snapshot
from utils.utils import wait_until_bitcoind_ready

log = logging.getLogger(__name__)


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _allocate_ports() -> dict[str, int]:
    return {k: _free_port() for k in PORT_KEYS}


def _make_rpc(rpc_port: int) -> BitcoindClient:
    url = f"http://{BD_USERNAME}:{BD_PASSWORD}@127.0.0.1:{rpc_port}"
    return BitcoindClient(base_url=url, network="regtest")


def _stop_bitcoind(proc: subprocess.Popen, rpc: BitcoindClient, timeout: float = 30):
    """Ask bitcoind to stop via RPC, then wait for the process to exit."""
    try:
        rpc.proxy.stop()
    except Exception as ex:
        log.warning("rpc stop failed (%s); falling back to terminate()", ex)
        proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        log.warning("bitcoind did not exit within %ss; killing", timeout)
        proc.kill()
        proc.wait(timeout=10)


def build_snapshot(initial_blocks: int) -> None:
    """Mine ``initial_blocks`` regtest blocks in a temp datadir, then copy the
    resulting state into ``.bitcoin-snapshot/`` with a metadata sidecar."""
    started = time.monotonic()

    target = snapshot_path()
    if target.exists():
        log.info("removing existing snapshot at %s", target)
        shutil.rmtree(target)

    tmpdir = Path(tempfile.mkdtemp(prefix="btc-snapshot-build-"))
    log.info("staging datadir at %s", tmpdir)

    ports = _allocate_ports()
    cmd = build_bitcoind_args(datadir=str(tmpdir), **ports)
    logfile_path = tmpdir / "bitcoind.log"
    log.info("starting bitcoind (rpc=%s)", ports["rpc_port"])
    with logfile_path.open("w") as logfile:
        proc: subprocess.Popen | None = subprocess.Popen(
            cmd, stdout=logfile, stderr=subprocess.STDOUT
        )

    try:
        rpc = _make_rpc(ports["rpc_port"])
        wait_until_bitcoind_ready(rpc, timeout=30)

        log.info("creating wallet %s", BD_WALLETNAME)
        rpc.proxy.createwallet(BD_WALLETNAME)
        miner_address = rpc.proxy.getnewaddress()

        log.info("mining %s blocks to %s", initial_blocks, miner_address)
        rpc.proxy.generatetoaddress(initial_blocks, miner_address)

        block_count = rpc.proxy.getblockcount()
        if block_count != initial_blocks:
            raise RuntimeError(
                f"unexpected block count after mining: got {block_count}, expected {initial_blocks}"
            )
        tip_block_hash = rpc.proxy.getblockhash(block_count)

        log.info("stopping bitcoind so chainstate locks release")
        _stop_bitcoind(proc, rpc)
        proc = None  # cleanly stopped; no further cleanup needed
    finally:
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)

    log.info("writing snapshot to %s", target)
    snapshot_root = write_snapshot(
        source_datadir=tmpdir,
        miner_address=miner_address,
        tip_height=block_count,
        tip_block_hash=tip_block_hash,
    )

    shutil.rmtree(tmpdir, ignore_errors=True)

    elapsed = time.monotonic() - started
    size = sum(p.stat().st_size for p in snapshot_root.rglob("*") if p.is_file())
    log.info(
        "done in %.1fs; snapshot size %.1f MiB at %s",
        elapsed,
        size / (1024 * 1024),
        snapshot_root,
    )


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.INFO,
    )
    parser = argparse.ArgumentParser(description="build the bitcoin regtest snapshot fixture")
    parser.add_argument(
        "--initial-blocks",
        type=int,
        default=BitcoinEnvConfig().initial_blocks,
        help="number of regtest blocks to pre-mine (default: BitcoinEnvConfig.initial_blocks)",
    )
    args = parser.parse_args(argv)
    build_snapshot(args.initial_blocks)
    return 0


if __name__ == "__main__":
    sys.exit(main())
