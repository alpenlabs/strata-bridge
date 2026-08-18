"""
Safe-Harbour Sweep Test: assigned deposits (hard bridge upgrade)

A deposit with a withdrawal assignment (but no fulfillment yet) must be swept
on activation, and the assignee must never front the user:

1. The assignee is held down when the assignment lands, so the deposit
   deterministically sits in Assigned with no fulfillment broadcast.
2. Activation sweeps the deposit out of Assigned on the live operators; the
   sweep is an N-of-N round, so the deposit UTXO must stay unspent while the
   assignee is down.
3. The restarted assignee latches before the replayed assignment reaches its
   deposit SM (the mux orders safe-harbour state first), so its fulfillment
   duty is suppressed at dispatch: it joins the stalled round via nagging,
   the sweep must confirm, and the assignee's log must show no fulfillment
   submission at all.
"""

import re
import time

import flexitest

from constants import DT_DEPOSIT_VOUT
from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.params_cfg import BridgeProtocolParams
from rpc.types import RpcDepositStatusComplete
from utils.bridge import get_bridge_nodes_and_rpcs
from utils.deposit import wait_until_deposit_status, wait_until_drt_recognized
from utils.dev_cli import DevCli
from utils.safe_harbour import (
    activate_safe_harbour,
    assert_sweep_tx,
    wait_until_deposit_swept,
)
from utils.utils import read_operator_key, wait_for_tx_confirmation, wait_until

# The assignee's fulfillment submission log line (the same signal the fulfillment tests use).
FULFILLMENT_SUBMIT_RE = re.compile(
    r"submitting withdrawal fulfillment transaction.*txid=([0-9a-f]{64})"
)

# How long the deposit UTXO must stay unspent while the assignee is down. Spans many buried
# blocks (2s block interval), i.e. many scan replays and nag ticks.
STALL_OBSERVATION_SECS = 30


@flexitest.register
class SafeHarbourSweepAssignedTest(StrataTestBase):
    """Activation before fulfillment sweeps the deposit and suppresses the fulfillment."""

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(BridgeNetworkEnv())

    def main(self, ctx: flexitest.RunContext):
        protocol_params = BridgeProtocolParams()
        bridge_nodes, bridge_rpcs = get_bridge_nodes_and_rpcs(ctx)
        bridge_rpc = bridge_rpcs[0]

        bitcoind_service = ctx.get_service("bitcoin")
        bitcoin_rpc = bitcoind_service.create_rpc()
        asm_rpc = ctx.get_service("asm_rpc").create_rpc()

        num_operators = len(bridge_nodes)
        operator_key_infos = [read_operator_key(i) for i in range(num_operators)]
        dev_cli = DevCli(bitcoind_service.props, operator_key_infos)

        # --- One completed deposit ---
        drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted DRT: {drt_txid}")
        deposit_id = wait_until_drt_recognized(bridge_rpc, drt_txid)
        deposit_info = wait_until_deposit_status(bridge_rpc, deposit_id, RpcDepositStatusComplete)
        assert deposit_info is not None, "Deposit did not complete"
        deposit_txid = deposit_info.get("status").get("deposit_txid")

        # --- Assign the withdrawal to a held-down operator so nothing can be fulfilled ---
        assignee = num_operators - 1
        self.logger.info(f"Stopping operator {assignee} before it is assigned")
        bridge_nodes[assignee].stop()
        live_rpcs = bridge_rpcs[:assignee]

        recent_block_hash = bitcoin_rpc.proxy.getblockhash(bitcoin_rpc.proxy.getblockcount())
        ckp_l1_txn = dev_cli.send_mock_checkpoint_from_tip(
            asm_rpc,
            recent_block_hash,
            num_ol_slots=1,
            assignee_node_idx=assignee,
        )
        wait_for_tx_confirmation(bitcoin_rpc, ckp_l1_txn)

        def live_operators_assigned():
            return all(deposit_id in rpc.stratabridge_pendingWithdrawals() for rpc in live_rpcs)

        wait_until(
            live_operators_assigned,
            timeout=300,
            step=2,
            error_msg="live operators did not observe the withdrawal assignment",
        )

        # --- Activate: the deposit is swept out of Assigned, never fulfilled ---
        activate_safe_harbour(ctx, live_rpcs)

        # --- The sweep must stall: N-of-N cannot aggregate without the assignee ---
        deadline = time.time() + STALL_OBSERVATION_SECS
        while time.time() < deadline:
            utxo = bitcoin_rpc.proxy.gettxout(deposit_txid, DT_DEPOSIT_VOUT)
            assert utxo is not None, (
                f"deposit {deposit_txid} was swept while operator {assignee} was down; "
                "an N-of-N round must not complete without every operator"
            )
            time.sleep(2)

        # --- Restart: latch recovery + nagging must complete the sweep ---
        self.logger.info(f"Restarting operator {assignee}")
        bridge_nodes[assignee].start()

        sweep_tx = wait_until_deposit_swept(bitcoin_rpc, deposit_txid, timeout=600)
        self.logger.info(f"Assigned deposit {deposit_txid} swept by {sweep_tx['txid']}")
        assert_sweep_tx(
            sweep_tx,
            deposit_txid,
            protocol_params.deposit_amount,
            protocol_params.sweep_fee_rate,
        )

        # --- The assignee must never have submitted a fulfillment ---
        with open(bridge_nodes[assignee].props["logfile"]) as logfile:
            fulfillments = FULFILLMENT_SUBMIT_RE.findall(logfile.read())
        assert not fulfillments, (
            f"operator {assignee} submitted a fulfillment under safe harbour: {fulfillments}"
        )

        return True
