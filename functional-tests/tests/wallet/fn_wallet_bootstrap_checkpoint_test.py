"""
Wallet Persistence: Bootstrap Checkpoint Test

Verifies the `operator_wallet.bootstrap_*` settings: stores created on a start begin scanning at
the configured block, and a hash the connected node disagrees with stops the node before any
wallet history can be skipped. Evidence is read from the SQLite store files themselves.

Each phase moves operator-0's stores aside first, so the node takes the create path and actually
consults the checkpoint. The env mines 101 blocks before creating any operator and funds the
wallets after, so height 101 is at or below every funding height.

Test flow:
1. Configure height 101 with a hash the node does not have there. The node must exit non-zero
   and create no stores.
2. Configure height 101 with the hash the node reports. The node must start and both fresh
   stores must hold that block as their lowest above genesis.
3. Configure the height alone. The node resolves the hash itself and starts the same way.
"""

import shutil
import time
from pathlib import Path

import flexitest
import toml

from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from utils.utils import wait_until_bridge_ready
from utils.wallet_store import (
    GENERAL_STORE,
    RESERVED_STORE,
    first_synced_height,
    read_store,
    store_path,
    wait_until_exited,
)

CHECKPOINT_HEIGHT = 101
WRONG_HASH = "00000000000000000000000000000000000000000000000000000000deadbeef"


@flexitest.register
class WalletBootstrapCheckpointTest(StrataTestBase):
    """A verified checkpoint seeds fresh stores; a mismatched one stops the node."""

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(BridgeNetworkEnv())

    def main(self, ctx: flexitest.RunContext):
        node = ctx.get_service("bridge_node_0")
        rpc = node.create_rpc()
        bitcoin_rpc = ctx.get_service("bitcoin").create_rpc()
        real_hash = bitcoin_rpc.proxy.getblockhash(CHECKPOINT_HEIGHT)
        self.logger.info(f"block {CHECKPOINT_HEIGHT} is {real_hash}")

        node_dir = Path(node.props["logfile"]).parent
        # Kept as raw text so the restore is byte-identical, not a toml round-trip.
        original_config = (node_dir / "config.toml").read_text()
        stores = [store_path(node, name) for name in (GENERAL_STORE, RESERVED_STORE)]

        # --- 1. A hash the node disagrees with must stop the node ---
        node.stop()
        self._clear_stores(stores)
        self._write_config(node_dir, original_config, CHECKPOINT_HEIGHT, WRONG_HASH)
        node.start()
        rc = wait_until_exited(node)
        node.stop()
        assert rc != 0, f"node started on a mismatched checkpoint (exit code {rc})"
        for path in stores:
            assert not path.exists(), f"{path.name} was created despite the mismatch"
        self.logger.info("mismatched checkpoint rejected before any store was created")

        # --- 2. The hash the node reports must be accepted and used ---
        self._write_config(node_dir, original_config, CHECKPOINT_HEIGHT, real_hash)
        self._start_and_check_stores(node, rpc, stores, "verified checkpoint")

        # --- 3. A height on its own resolves to the same block ---
        node.stop()
        self._clear_stores(stores)
        self._write_config(node_dir, original_config, CHECKPOINT_HEIGHT, None)
        self._start_and_check_stores(node, rpc, stores, "height alone")

        # Leave the node on its original config for the rest of the env's life.
        node.stop()
        self._clear_stores(stores)
        (node_dir / "config.toml").write_text(original_config)
        node.start()
        wait_until_bridge_ready(rpc)

        self.logger.info(
            "BOOTSTRAP CHECKPOINT VERIFIED: a mismatched hash stops the node, and a verified "
            f"pair or a bare height seeds both stores at block {CHECKPOINT_HEIGHT}"
        )
        return True

    def _clear_stores(self, stores: list[Path]):
        """Move any existing stores aside so the next start takes the create path."""
        for path in stores:
            retired = path.parent / "retired"
            retired.mkdir(exist_ok=True)
            for leftover in path.parent.glob(f"{path.name}*"):
                shutil.move(leftover, retired / f"{leftover.name}.{time.time_ns()}")

    def _write_config(self, node_dir: Path, original: str, height: int, block_hash: str | None):
        config = toml.loads(original)
        config["operator_wallet"]["bootstrap_height"] = height
        if block_hash is None:
            config["operator_wallet"].pop("bootstrap_block_hash", None)
        else:
            config["operator_wallet"]["bootstrap_block_hash"] = block_hash
        (node_dir / "config.toml").write_text(toml.dumps(config))
        time.sleep(5)  # ports need to be released before restarting

    def _start_and_check_stores(self, node, rpc, stores: list[Path], label: str):
        node.start()
        wait_until_bridge_ready(rpc)
        for path in stores:
            first = first_synced_height(path)
            assert first == CHECKPOINT_HEIGHT, (
                f"{path.name} starts at block {first}, expected {CHECKPOINT_HEIGHT} ({label})"
            )
            assert read_store(path).tip_height >= CHECKPOINT_HEIGHT
            self.logger.info(f"{label}: {path.name} starts at {first}")
