"""
Safe-Harbour Halt Test: new deposits refused (hard bridge upgrade)

After activation the bridge must stop taking on new deposits: a deposit
request confirmed after every operator has latched must never be admitted as
a deposit, on any operator. A pre-activation deposit proves the deposit
pipeline itself works, so the post-activation silence is the halt gate and
not a broken environment.
"""

import time

import flexitest

from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.params_cfg import BridgeProtocolParams
from rpc.types import RpcDepositStatusComplete
from utils.bridge import get_bridge_nodes_and_rpcs
from utils.deposit import wait_until_deposit_status, wait_until_drt_recognized
from utils.dev_cli import DevCli
from utils.safe_harbour import activate_safe_harbour
from utils.utils import read_operator_key, wait_for_tx_confirmation, wait_until

# How long to watch for the (forbidden) admission after the DRT is buried. Blocks are mined
# every ~2s and bury_depth is small, so this spans many buried blocks.
OBSERVATION_SECS = 30


@flexitest.register
class SafeHarbourHaltsNewDepositsTest(StrataTestBase):
    """A DRT confirmed after safe-harbour activation must never become a deposit."""

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

        # --- Sanity: the deposit pipeline works before activation ---
        pre_drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted pre-activation DRT: {pre_drt_txid}")
        deposit_id = wait_until_drt_recognized(bridge_rpc, pre_drt_txid)
        wait_until_deposit_status(bridge_rpc, deposit_id, RpcDepositStatusComplete)

        # --- Activate the safe harbour ---
        activate_safe_harbour(ctx, bridge_rpcs)

        # --- A post-activation DRT must never become a deposit ---
        post_drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted post-activation DRT: {post_drt_txid}")

        block_hash = wait_for_tx_confirmation(bitcoin_rpc, post_drt_txid)
        confirmation_height = bitcoin_rpc.proxy.getblock(block_hash)["height"]

        # The bridge only acts on buried blocks; wait until the DRT's block is comfortably
        # buried before starting the observation window.
        buried_height = confirmation_height + protocol_params.bury_depth + 2
        wait_until(
            lambda: bitcoin_rpc.proxy.getblockcount() >= buried_height,
            timeout=120,
            step=2,
            error_msg="chain did not advance past the DRT's burial height",
        )

        deadline = time.time() + OBSERVATION_SECS
        while time.time() < deadline:
            for idx, rpc in enumerate(bridge_rpcs):
                admitted = [
                    deposit_idx
                    for deposit_idx in rpc.stratabridge_depositIndices()
                    if rpc.stratabridge_depositInfo(deposit_idx).get("deposit_request_txid")
                    == post_drt_txid
                ]
                assert not admitted, (
                    f"operator {idx} admitted post-activation DRT {post_drt_txid} "
                    f"as deposit {admitted}"
                )
            time.sleep(2)

        return True
