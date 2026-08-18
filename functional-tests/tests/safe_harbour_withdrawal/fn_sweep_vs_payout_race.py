"""
Safe-Harbour Race Test: sweep vs cooperative payout (hard bridge upgrade)

Activation lands mid-withdrawal, after the fulfillment confirms and while the
cooperative payout signing round is (or may be) in flight. Which transaction
wins is intentionally unspecified — the deposit outpoint is a fixed N-of-N
output and whichever spend confirms first is the outcome:

1. The deposit outpoint must be spent by exactly one transaction, which is
   either the sweep (paying the frozen safe-harbour address) or the
   cooperative payout.
2. Every operator must converge: no pending withdrawal remains and every
   node keeps serving RPC.
"""

import re

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
    safe_harbour_script_hex,
    wait_until_deposit_swept,
)
from utils.utils import (
    read_operator_key,
    wait_for_log_capture,
    wait_for_tx_confirmation,
    wait_until,
)

# The assignee's fulfillment submission log line (the same signal the fulfillment tests use).
FULFILLMENT_SUBMIT_RE = re.compile(
    r"submitting withdrawal fulfillment transaction.*txid=([0-9a-f]{64})"
)

ASSIGNEE = 0


@flexitest.register
class SafeHarbourSweepVsPayoutRaceTest(StrataTestBase):
    """The deposit outpoint is spent exactly once, by the sweep or the payout."""

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

        # --- One completed deposit, assigned and fulfilled ---
        drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted DRT: {drt_txid}")
        deposit_id = wait_until_drt_recognized(bridge_rpc, drt_txid)
        deposit_info = wait_until_deposit_status(bridge_rpc, deposit_id, RpcDepositStatusComplete)
        assert deposit_info is not None, "Deposit did not complete"
        deposit_txid = deposit_info.get("status").get("deposit_txid")

        recent_block_hash = bitcoin_rpc.proxy.getblockhash(bitcoin_rpc.proxy.getblockcount())
        ckp_l1_txn = dev_cli.send_mock_checkpoint_from_tip(
            asm_rpc,
            recent_block_hash,
            num_ol_slots=1,
            assignee_node_idx=ASSIGNEE,
        )
        wait_for_tx_confirmation(bitcoin_rpc, ckp_l1_txn)

        fulfillment_txid = wait_for_log_capture(
            bridge_nodes[ASSIGNEE].props["logfile"],
            FULFILLMENT_SUBMIT_RE,
            error_msg="assignee did not submit a fulfillment",
        ).group(1)
        wait_for_tx_confirmation(bitcoin_rpc, fulfillment_txid, timeout=300)
        self.logger.info(f"Fulfillment {fulfillment_txid} confirmed; racing the payout now")

        # --- Activate mid-payout: sweep and cooperative payout now race ---
        activate_safe_harbour(ctx, bridge_rpcs)

        # --- Exactly one spend of the deposit outpoint, by either transaction ---
        spender_tx = wait_until_deposit_swept(bitcoin_rpc, deposit_txid, timeout=600)
        spender_txid = spender_tx["txid"]

        inputs = [(vin["txid"], vin["vout"]) for vin in spender_tx.get("vin", [])]
        assert (deposit_txid, DT_DEPOSIT_VOUT) in inputs, (
            f"spender {spender_txid} does not spend the deposit outpoint; inputs: {inputs}"
        )

        payout_script = spender_tx["vout"][0]["scriptPubKey"]["hex"]
        if payout_script == safe_harbour_script_hex():
            self.logger.info(f"Sweep won the race: {spender_txid}")
            assert_sweep_tx(
                spender_tx,
                deposit_txid,
                protocol_params.deposit_amount,
                protocol_params.sweep_fee_rate,
            )
        else:
            self.logger.info(f"Cooperative payout won the race: {spender_txid}")

        # --- Every operator converges and stays up ---
        def all_operators_converged():
            pending = [rpc.stratabridge_pendingWithdrawals() for rpc in bridge_rpcs]
            self.logger.info(f"Pending withdrawals per operator: {pending}")
            return all(deposit_id not in operator_pending for operator_pending in pending)

        wait_until(
            all_operators_converged,
            timeout=300,
            step=2,
            error_msg="operators did not converge after the deposit outpoint was spent",
        )

        return True
