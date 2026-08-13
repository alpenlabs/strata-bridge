"""
Safe-Harbour Abort Test: safe-window deposits (hard bridge upgrade)

A deposit still in the safe abort window (no partial signature gossiped yet)
must be aborted when the safe harbour activates, not completed.

Pacing: pausing block production cannot hold a deposit in the window, because
graph generation and MuSig2 signing progress off-chain. Instead one operator
is held down, which deterministically pins the deposit in Created (the graph
set never completes without it). The live operators must then abort the
deposit on activation; the deposit must never complete.

The held-down operator is restarted at the end and must converge: it either
never admits the buried DRT (its latch beats the block replay) or admits and
aborts it (the best-effort halt gate lost the race; the abort catches it).
"""

import flexitest

from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.config_cfg import BridgeConfigParams
from rpc.types import RpcDepositStatusFailed
from utils.bridge import get_bridge_nodes_and_rpcs
from utils.deposit import wait_until_deposit_status, wait_until_drt_recognized
from utils.dev_cli import DevCli
from utils.safe_harbour import activate_safe_harbour
from utils.utils import read_operator_key, wait_until


@flexitest.register
class SafeHarbourAbortsSafeWindowTest(StrataTestBase):
    """Activation mid-Created must abort the deposit on every operator."""

    def __init__(self, ctx: flexitest.InitContext):
        # Dev mode keeps the held-down operator's restart independent of ASM-fetching
        # startup checks, mirroring the detection test's restart phase.
        ctx.set_env(BridgeNetworkEnv(bridge_config_params=BridgeConfigParams(dev=True)))

    def main(self, ctx: flexitest.RunContext):
        bridge_nodes, bridge_rpcs = get_bridge_nodes_and_rpcs(ctx)
        num_operators = len(bridge_nodes)

        operator_key_infos = [read_operator_key(i) for i in range(num_operators)]
        dev_cli = DevCli(ctx.get_service("bitcoin").props, operator_key_infos)

        # --- Pin the deposit in the safe window: hold the last operator down ---
        held_down = num_operators - 1
        self.logger.info(f"Stopping operator {held_down} to pin the deposit in Created")
        bridge_nodes[held_down].stop()
        live_rpcs = bridge_rpcs[:held_down]

        drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted DRT: {drt_txid}")
        deposit_id = wait_until_drt_recognized(live_rpcs[0], drt_txid)

        # --- Activate the safe harbour on the live operators ---
        activate_safe_harbour(ctx, live_rpcs)

        # --- The live operators abort the deposit; it never completes ---
        for idx, rpc in enumerate(live_rpcs):
            deposit_info = wait_until_deposit_status(rpc, deposit_id, RpcDepositStatusFailed)
            self.logger.info(f"Operator {idx} aborted the deposit: {deposit_info}")

        # --- The held-down operator converges after restart ---
        bridge_nodes[held_down].start()
        restarted_rpc = bridge_nodes[held_down].create_rpc()

        def restarted_converged():
            try:
                deposit_indices = restarted_rpc.stratabridge_depositIndices()
            except Exception as exc:
                self.logger.info(f"operator {held_down} RPC not up yet: {exc}")
                return False

            if deposit_id not in deposit_indices:
                # The latch beat the DRT block replay, so the halt gate refused it.
                return True

            deposit_info = restarted_rpc.stratabridge_depositInfo(deposit_id)
            self.logger.info(f"operator {held_down} deposit info: {deposit_info}")
            status = deposit_info.get("status", {}).get("status")
            assert status != "complete", (
                f"operator {held_down} completed a deposit the others aborted"
            )
            return status == RpcDepositStatusFailed.status

        wait_until(
            restarted_converged,
            timeout=180,
            step=2,
            error_msg=f"operator {held_down} did not refuse or abort the deposit after restart",
        )

        return True
