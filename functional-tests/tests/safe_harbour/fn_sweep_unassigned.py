"""
Safe-Harbour Sweep Test: unassigned deposits (hard bridge upgrade)

The flagship sweep behaviour: with N completed (unassigned) deposits, a
Security-Council Defcon1 activation must cause every deposit UTXO to be swept
by its own transaction into the frozen safe-harbour address:

1. Each sweep is a single-input spend of exactly one deposit outpoint, so the
   deposits produce one sweep tx each (never batched).
2. Output 0 pays the frozen safe-harbour address exactly
   ``deposit_amount - sweep_fee_rate * sweep_vsize - anchor_value``.
3. Output 1 is the operator-keyed CPFP anchor at dust value.
"""

import flexitest

from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.params_cfg import BridgeProtocolParams
from rpc.types import RpcDepositStatusComplete
from utils.bridge import get_bridge_nodes_and_rpcs
from utils.deposit import wait_until_deposit_status, wait_until_drts_recognized
from utils.dev_cli import DevCli
from utils.safe_harbour import (
    activate_safe_harbour,
    assert_sweep_tx,
    wait_until_deposit_swept,
)
from utils.utils import read_operator_key

DEPOSIT_COUNT = 2


@flexitest.register
class SafeHarbourSweepUnassignedTest(StrataTestBase):
    """Every Deposited UTXO must be swept to the frozen safe-harbour address on activation."""

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

        # --- N unassigned deposits ---
        drt_txids = [dev_cli.send_deposit_request() for _ in range(DEPOSIT_COUNT)]
        for drt_txid in drt_txids:
            self.logger.info(f"Broadcasted DRT: {drt_txid}")

        deposit_ids = wait_until_drts_recognized(bridge_rpc, drt_txids)
        deposit_txids = []
        for deposit_id in deposit_ids:
            deposit_info = wait_until_deposit_status(
                bridge_rpc, deposit_id, RpcDepositStatusComplete
            )
            assert deposit_info is not None, "Deposit did not complete"
            deposit_txids.append(deposit_info.get("status").get("deposit_txid"))
        self.logger.info(f"Completed deposits: {deposit_txids}")

        # --- Activate the safe harbour ---
        activate_safe_harbour(ctx, bridge_rpcs)

        # --- One sweep tx per deposit, paying the frozen address ---
        for deposit_txid in deposit_txids:
            sweep_tx = wait_until_deposit_swept(bitcoin_rpc, deposit_txid)
            self.logger.info(f"Deposit {deposit_txid} swept by {sweep_tx['txid']}")
            assert_sweep_tx(
                sweep_tx,
                deposit_txid,
                protocol_params.deposit_amount,
                protocol_params.sweep_fee_rate,
            )

        return True
