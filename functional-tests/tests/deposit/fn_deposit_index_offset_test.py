import time

import flexitest

from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.params_cfg import BridgeProtocolParams
from rpc.types import RpcDepositStatusComplete
from utils.bridge import bridge_rpc_url, get_bridge_nodes_and_rpcs
from utils.deposit import wait_until_deposit_status, wait_until_drt_recognized
from utils.dev_cli import DevCli
from utils.network import wait_until_p2p_connected
from utils.utils import read_operator_key, wait_until_bridge_ready

DEPOSIT_INDEX_OFFSET = 1200


@flexitest.register
class DepositIndexOffsetTest(StrataTestBase):
    """
    Test that the protocol's deposit index offset starts the covenant's deposit sequence
    at that index, and that a restart preserves the sequence.

    Verifies that:
    - every node assigns the offset to the covenant's first deposit,
    - the deposit completes with that index,
    - a restarted node keeps its persisted index, and
    - every node continues the sequence with the next index for the following deposit.
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(
            BridgeNetworkEnv(
                bridge_protocol_params=BridgeProtocolParams(
                    deposit_index_offset=DEPOSIT_INDEX_OFFSET
                ),
            )
        )

    def main(self, ctx: flexitest.RunContext):
        bridge_nodes, bridge_rpcs = get_bridge_nodes_and_rpcs(ctx)
        bitcoind_props = ctx.get_service("bitcoin").props
        operator_key_infos = [read_operator_key(i) for i in range(len(bridge_nodes))]
        dev_cli = DevCli(bitcoind_props, operator_key_infos)

        first_drt = dev_cli.send_deposit_request(bridge_rpc_url(bridge_nodes[0]))
        self._assert_all_nodes_index(bridge_rpcs, first_drt, DEPOSIT_INDEX_OFFSET)
        for bridge_rpc in bridge_rpcs:
            wait_until_deposit_status(bridge_rpc, DEPOSIT_INDEX_OFFSET, RpcDepositStatusComplete)
        self.logger.info(f"first deposit completed at index {DEPOSIT_INDEX_OFFSET}")

        restarted_node, restarted_rpc = bridge_nodes[0], bridge_rpcs[0]
        restarted_node.stop()
        time.sleep(5)  # ports need to be released before restarting
        restarted_node.start()
        wait_until_bridge_ready(restarted_rpc)
        wait_until_p2p_connected(bridge_rpcs)

        assert wait_until_drt_recognized(restarted_rpc, first_drt) == DEPOSIT_INDEX_OFFSET, (
            "a restart must preserve the persisted deposit index"
        )

        second_drt = dev_cli.send_deposit_request(bridge_rpc_url(bridge_nodes[0]))
        self._assert_all_nodes_index(bridge_rpcs, second_drt, DEPOSIT_INDEX_OFFSET + 1)
        for bridge_rpc in bridge_rpcs:
            wait_until_deposit_status(
                bridge_rpc, DEPOSIT_INDEX_OFFSET + 1, RpcDepositStatusComplete
            )

        self.logger.info(
            "DEPOSIT INDEX OFFSET VERIFIED: the deposit sequence started at the protocol offset "
            "and continued after restart"
        )
        return True

    def _assert_all_nodes_index(self, bridge_rpcs, drt_txid: str, expected: int):
        for node_idx, bridge_rpc in enumerate(bridge_rpcs):
            deposit_idx = wait_until_drt_recognized(bridge_rpc, drt_txid)
            assert deposit_idx == expected, (
                f"node {node_idx} assigned index {deposit_idx} to {drt_txid}, expected {expected}"
            )
