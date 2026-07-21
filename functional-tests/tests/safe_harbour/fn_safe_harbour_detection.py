"""
Safe-Harbour Detection Test (hard bridge upgrade, T1)

Verifies the bridge's safe-harbour *detection* contract, independent of any
sweep behaviour:

1. Before activation, no operator reports a latched safe-harbour address.
2. A Security-Council Defcon1 admin tx activates the safe harbour in the ASM;
   every operator must latch the frozen address within a couple of blocks —
   the tip-read latency bound (a buried-height read would take ~bury_depth
   blocks and fail this test).
3. The latch is persisted: an operator restarted *while the ASM is stopped*
   must come back latched, proving recovery from the DB rather than
   re-observation of the ASM tip.

Detection must not change any other behaviour yet (halting/sweeping lands
with safe-harbour mode); the test finishes with the ASM restored so the
environment shuts down cleanly.
"""

import flexitest

from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from factory.common.asm_params import DEFAULT_SAFE_HARBOUR_ADDRESS
from utils.bridge import get_bridge_nodes_and_rpcs
from utils.dev_cli import DevCli
from utils.utils import read_operator_key, wait_until


@flexitest.register
class SafeHarbourDetectionTest(StrataTestBase):
    """Every operator must latch a safe-harbour activation and recover it across restarts."""

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(BridgeNetworkEnv())

    def main(self, ctx: flexitest.RunContext):
        bridge_nodes, bridge_rpcs = get_bridge_nodes_and_rpcs(ctx)
        num_operators = len(bridge_nodes)

        # --- Before activation: nothing is latched ---
        for idx, rpc in enumerate(bridge_rpcs):
            address = rpc.stratabridge_safeHarbourAddress()
            assert address is None, f"operator {idx} latched {address} before activation"

        # --- Activate: council (operator 0's key, threshold 1) publishes Defcon1 ---
        bitcoind_props = ctx.get_service("bitcoin").props
        operator_key_infos = [read_operator_key(i) for i in range(num_operators)]
        dev_cli = DevCli(bitcoind_props, operator_key_infos)

        txid = dev_cli.send_defcon1()
        self.logger.info(f"Broadcasted Defcon1 admin tx: {txid}")

        # --- Detection: every operator latches the frozen address ---
        # The flag is read at the ASM tip, so the latch must appear within a couple of
        # blocks of the Defcon1 tx confirming — not after bury_depth blocks.
        def all_latched():
            addresses = [rpc.stratabridge_safeHarbourAddress() for rpc in bridge_rpcs]
            self.logger.info(f"Safe-harbour addresses: {addresses}")
            return all(address == DEFAULT_SAFE_HARBOUR_ADDRESS for address in addresses)

        wait_until(
            all_latched,
            timeout=180,
            step=2,
            error_msg="operators did not latch the safe-harbour activation",
        )

        # --- Persistence: restart an operator with the ASM stopped ---
        # With the ASM down the restarted node cannot re-observe the flag from the tip;
        # reporting the address again proves the latch was recovered from the database.
        asm_service = ctx.get_service("asm_rpc")
        self.logger.info("Stopping the ASM and restarting operator 0")
        asm_service.stop()
        bridge_nodes[0].stop()
        bridge_nodes[0].start()
        restarted_rpc = bridge_nodes[0].create_rpc()

        def latched_after_restart():
            try:
                address = restarted_rpc.stratabridge_safeHarbourAddress()
            except Exception as exc:
                self.logger.info(f"operator 0 RPC not up yet: {exc}")
                return False
            self.logger.info(f"operator 0 safe-harbour address after restart: {address}")
            return address == DEFAULT_SAFE_HARBOUR_ADDRESS

        wait_until(
            latched_after_restart,
            timeout=120,
            step=2,
            error_msg="operator 0 did not recover the safe-harbour latch from persistence",
        )

        # Restore the ASM so the environment tears down cleanly.
        asm_service.start()

        return True
