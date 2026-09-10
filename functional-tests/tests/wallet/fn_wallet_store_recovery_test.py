"""
Wallet Persistence: Store Recovery Test

Verifies the failure and rebuild paths of the persisted wallet stores. Evidence is read from
the SQLite store files themselves, not from the node's logs.

Test flow:
1. Bring up the network and wait for staking, so every operator has populated stores.
2. Stop operator-0 and overwrite its reserved store with garbage. Start it: the node must exit
   non-zero and the file must be left byte-for-byte intact.
3. Move both store files aside, as the documented rebuild procedure says. Start the node: fresh
   stores for the same descriptors must appear and sync to the chain.
4. Replace operator-0's reserved store with operator-1's, a store for the same network but
   another key. Start operator-0: it must exit non-zero and leave the file untouched. Restore
   operator-0's own file and confirm the node runs on it again.
"""

import shutil

import flexitest

from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from utils.bridge import get_bridge_nodes_and_rpcs
from utils.utils import wait_until_bridge_ready
from utils.wallet_store import (
    GENERAL_STORE,
    RESERVED_STORE,
    read_store,
    store_path,
    wait_until_exited,
    wait_until_store_synced,
)

GARBAGE = b"this is not a sqlite database; padded well past the header\n" * 64


@flexitest.register
class WalletStoreRecoveryTest(StrataTestBase):
    """Damaged or foreign wallet stores fail closed; moving them aside rebuilds."""

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(BridgeNetworkEnv())

    def main(self, ctx: flexitest.RunContext):
        bridge_nodes, bridge_rpcs = get_bridge_nodes_and_rpcs(ctx)
        node0, rpc0 = bridge_nodes[0], bridge_rpcs[0]
        node1, rpc1 = bridge_nodes[1], bridge_rpcs[1]
        bitcoin_rpc = ctx.get_service("bitcoin").create_rpc()
        general0 = store_path(node0, GENERAL_STORE)
        reserved0 = store_path(node0, RESERVED_STORE)
        own_general = read_store(general0)
        own_reserved = read_store(reserved0)

        # --- 1. Damaged reserved store: refused, file untouched ---
        self.logger.info("stopping operator-0 and corrupting its reserved wallet store")
        node0.stop()
        reserved0.write_bytes(GARBAGE)
        self._start_and_expect_crash(node0)
        assert reserved0.read_bytes() == GARBAGE, "a failed start must not modify the store"
        assert read_store(general0) == own_general, "the general store must be left as it was"
        self.logger.info("corrupt store rejected; file left intact")

        # --- 2. Operator moves both stores aside; next start rebuilds both wallets ---
        retired_dir = reserved0.parent / "retired"
        retired_dir.mkdir()
        for store in (general0, reserved0):
            shutil.move(store, retired_dir / store.name)
        assert (retired_dir / RESERVED_STORE).read_bytes() == GARBAGE, (
            "moving the store aside must keep the damaged bytes for diagnosis"
        )

        self._start_and_expect_synced(node0, rpc0, bitcoin_rpc, [general0, reserved0])
        for path, own in ((general0, own_general), (reserved0, own_reserved)):
            fresh = read_store(path)
            assert fresh.descriptor == own.descriptor and fresh.network == own.network, (
                f"{path.name} was rebuilt for a different wallet: {fresh}"
            )
        self.logger.info("stores moved aside; node rebuilt both wallets on fresh files")

        # --- 3. Another operator's store is rejected ---
        self.logger.info("swapping operator-1's reserved store into operator-0")
        node0.stop()
        node1.stop()  # clean close checkpoints the WAL so the main file is self-contained
        own_backup = reserved0.with_name(RESERVED_STORE + ".own")
        shutil.move(reserved0, own_backup)
        shutil.copyfile(store_path(node1, RESERVED_STORE), reserved0)
        foreign = read_store(reserved0)
        assert foreign.network == own_reserved.network, "same network, so only the key differs"
        assert foreign.descriptor != own_reserved.descriptor, "operator-1's store must differ"
        node1.start()
        wait_until_bridge_ready(rpc1)

        self._start_and_expect_crash(node0)
        assert read_store(reserved0) == foreign, "a refused foreign store must be left untouched"
        self.logger.info("foreign reserved store rejected")

        # Restore the operator's own file: the node runs on it again.
        shutil.move(own_backup, reserved0)
        self._start_and_expect_synced(node0, rpc0, bitcoin_rpc, [general0, reserved0])
        assert read_store(reserved0).descriptor == own_reserved.descriptor

        self.logger.info(
            "STORE RECOVERY VERIFIED: damaged and foreign stores fail closed with the file "
            "preserved, and moving the stores aside rebuilds both wallets"
        )
        return True

    def _start_and_expect_crash(self, node):
        """Start `node` and wait for it to exit on its own with a non-zero code."""
        node.start()
        rc = wait_until_exited(node)
        node.stop()  # record the exit and clear the handle so the node can be started again
        assert rc != 0, f"node should have refused to start (exit code {rc})"

    def _start_and_expect_synced(self, node, rpc, bitcoin_rpc, stores):
        """Start `node`, wait for readiness, and for every store to catch up to the chain."""
        target = bitcoin_rpc.proxy.getblockcount()
        node.start()
        wait_until_bridge_ready(rpc)
        for path in stores:
            wait_until_store_synced(path, target)
