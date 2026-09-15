"""
Wallet Persistence: Warm Restart Test

Verifies that a bridge node's two BDK wallets (general and reserved) persist their chain state
and resume from it across restarts. Evidence is read from the SQLite store files themselves,
not from the node's logs.

Test flow:
1. Bring up the network and wait for staking, which syncs and funds both wallets. Both store
   files must hold a regtest wallet with a tip above genesis.
2. Restart operator-0 gracefully (SIGTERM). The committed tip must survive the stop, the node
   must come back on the same files, and both stores must catch up to the chain.
3. Repeat with a forced termination (SIGKILL), which exercises SQLite WAL recovery.

A populated store can only be loaded: BDK refuses to create a wallet over existing data. So a
node that reaches ready on the same files, with the tip never regressing, resumed from them.
"""

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
    wait_until_store_synced,
)


@flexitest.register
class WalletWarmRestartTest(StrataTestBase):
    """Both wallets resume from their persisted tip after graceful and forced restarts."""

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(BridgeNetworkEnv())

    def main(self, ctx: flexitest.RunContext):
        bridge_nodes, bridge_rpcs = get_bridge_nodes_and_rpcs(ctx)
        node, rpc = bridge_nodes[0], bridge_rpcs[0]
        bitcoin_rpc = ctx.get_service("bitcoin").create_rpc()
        stores = [store_path(node, GENERAL_STORE), store_path(node, RESERVED_STORE)]

        # --- First start populated both stores for this network ---
        initial = [read_store(path) for path in stores]
        for path, state in zip(stores, initial, strict=True):
            assert state.network == "regtest", f"{path.name} is for {state.network}"
            assert state.tip_height > 0, f"{path.name} never synced past genesis"
        inodes = [path.stat().st_ino for path in stores]
        self.logger.info(f"stores populated; tips {[s.tip_height for s in initial]}")

        self._restart_and_verify(node, rpc, bitcoin_rpc, stores, inodes, initial, forced=False)
        self._restart_and_verify(node, rpc, bitcoin_rpc, stores, inodes, initial, forced=True)

        self.logger.info(
            "WARM RESTART VERIFIED: both wallets kept their committed state across a graceful "
            "and a forced restart and resumed on the same store files"
        )
        return True

    def _restart_and_verify(self, node, rpc, bitcoin_rpc, stores, inodes, initial, forced: bool):
        how = "SIGKILL" if forced else "SIGTERM"
        committed = [read_store(path).tip_height for path in stores]
        self.logger.info(f"restarting operator-0 via {how}; committed tips {committed}")

        if forced:
            node.proc.kill()
            node.proc.wait(timeout=30)
        node.stop()

        # Nothing committed is lost at shutdown, graceful or not. SQLite recovers any WAL frames
        # a killed process left behind when the file is next opened.
        after_stop = [read_store(path).tip_height for path in stores]
        for path, before, after in zip(stores, committed, after_stop, strict=True):
            assert after >= before, f"{path.name} lost commits on {how}: {before} -> {after}"

        target = bitcoin_rpc.proxy.getblockcount()
        node.start()
        wait_until_bridge_ready(rpc)
        for path in stores:
            wait_until_store_synced(path, target)

        # Same files, same wallets, tip monotonic: the node resumed from the persisted state.
        assert [path.stat().st_ino for path in stores] == inodes, "store files were replaced"
        for path, state, before in zip(stores, initial, after_stop, strict=True):
            now = read_store(path)
            assert now.descriptor == state.descriptor, f"{path.name} descriptor changed"
            assert now.tip_height >= before, f"{path.name} regressed below {before}"
        self.logger.info(
            f"{how} restart: stores intact and synced to at least {target}; "
            f"tips {[read_store(p).tip_height for p in stores]}"
        )
