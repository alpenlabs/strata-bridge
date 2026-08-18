"""
Safe-Harbour Sweep Liveness Test: operator restart (hard bridge upgrade)

The sweep is an N-of-N signing round, so a single offline operator stalls it.
This test proves the stall and the recovery:

1. With one operator down at activation, the deposit UTXO must stay unspent
   (no sweep can aggregate without the missing nonce and partial).
2. After the operator restarts, it must latch the activation from the ASM tip
   and join the round via nagging, and the sweep must confirm.
"""

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
from utils.utils import read_operator_key

# How long the deposit UTXO must stay unspent while one operator is down. Spans many
# buried blocks (2s block interval), i.e. many scan replays and nag ticks.
STALL_OBSERVATION_SECS = 30


@flexitest.register
class SafeHarbourSweepLivenessTest(StrataTestBase):
    """A sweep stalled by an offline operator must complete once it restarts."""

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(BridgeNetworkEnv())

    def main(self, ctx: flexitest.RunContext):
        protocol_params = BridgeProtocolParams()
        bridge_nodes, bridge_rpcs = get_bridge_nodes_and_rpcs(ctx)
        bridge_rpc = bridge_rpcs[0]

        bitcoind_service = ctx.get_service("bitcoin")
        bitcoin_rpc = bitcoind_service.create_rpc()

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

        # --- Take one operator down, then activate ---
        offline = num_operators - 1
        self.logger.info(f"Stopping operator {offline} before activation")
        bridge_nodes[offline].stop()

        activate_safe_harbour(ctx, bridge_rpcs[:offline])

        # --- The sweep must stall: N-of-N cannot aggregate without the offline operator ---
        deadline = time.time() + STALL_OBSERVATION_SECS
        while time.time() < deadline:
            utxo = bitcoin_rpc.proxy.gettxout(deposit_txid, DT_DEPOSIT_VOUT)
            assert utxo is not None, (
                f"deposit {deposit_txid} was swept while operator {offline} was down; "
                "an N-of-N round must not complete without every operator"
            )
            time.sleep(2)

        # --- Restart: latch recovery + nagging must complete the sweep ---
        self.logger.info(f"Restarting operator {offline}")
        bridge_nodes[offline].start()

        sweep_tx = wait_until_deposit_swept(bitcoin_rpc, deposit_txid, timeout=600)
        self.logger.info(f"Deposit {deposit_txid} swept by {sweep_tx['txid']} after restart")
        assert_sweep_tx(
            sweep_tx,
            deposit_txid,
            protocol_params.deposit_amount,
            protocol_params.sweep_fee_rate,
        )

        return True
