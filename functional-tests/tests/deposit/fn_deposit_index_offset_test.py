import time
from pathlib import Path

import flexitest
import toml

from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.config_cfg import BridgeConfigParams
from rpc.types import RpcDepositStatusComplete
from utils.bridge import get_bridge_nodes_and_rpcs
from utils.deposit import wait_until_deposit_status, wait_until_drt_recognized
from utils.dev_cli import DevCli
from utils.network import wait_until_p2p_connected
from utils.utils import read_operator_key, wait_until_bridge_ready

DEPOSIT_INDEX_OFFSET = 1200
EDITED_DEPOSIT_INDEX_OFFSET = 5000


@flexitest.register
class DepositIndexOffsetTest(StrataTestBase):
    """
    Test that nodes configured with a deposit index offset start the covenant's deposit sequence
    at that index, and that a later offset change does not restart the sequence.

    Verifies that:
    - every node assigns the offset to the covenant's first deposit,
    - the deposit completes with that index,
    - a node restarted with a different offset keeps its persisted index, and
    - every node continues the sequence with the next index for the following deposit.
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(
            BridgeNetworkEnv(
                bridge_config_params=BridgeConfigParams(deposit_index_offset=DEPOSIT_INDEX_OFFSET),
            )
        )

    def main(self, ctx: flexitest.RunContext):
        bridge_nodes, bridge_rpcs = get_bridge_nodes_and_rpcs(ctx)
        bitcoind_props = ctx.get_service("bitcoin").props
        operator_key_infos = [read_operator_key(i) for i in range(len(bridge_nodes))]
        dev_cli = DevCli(bitcoind_props, operator_key_infos)

        first_drt = dev_cli.send_deposit_request()
        self._assert_all_nodes_index(bridge_rpcs, first_drt, DEPOSIT_INDEX_OFFSET)
        for bridge_rpc in bridge_rpcs:
            wait_until_deposit_status(bridge_rpc, DEPOSIT_INDEX_OFFSET, RpcDepositStatusComplete)
        self.logger.info(f"first deposit completed at index {DEPOSIT_INDEX_OFFSET}")

        edited_node, edited_rpc = bridge_nodes[0], bridge_rpcs[0]
        config_path = Path(edited_node.props["logfile"]).parent / "config.toml"
        # Kept as raw text so the restore is byte-identical, not a toml round-trip.
        original_config = config_path.read_text()
        edited_node.stop()
        config = toml.loads(original_config)
        config["deposit_index_offset"] = EDITED_DEPOSIT_INDEX_OFFSET
        config_path.write_text(toml.dumps(config))
        time.sleep(5)  # ports need to be released before restarting
        edited_node.start()
        wait_until_bridge_ready(edited_rpc)
        wait_until_p2p_connected(bridge_rpcs)

        assert wait_until_drt_recognized(edited_rpc, first_drt) == DEPOSIT_INDEX_OFFSET, (
            "a changed offset must not renumber a persisted deposit"
        )

        second_drt = dev_cli.send_deposit_request()
        self._assert_all_nodes_index(bridge_rpcs, second_drt, DEPOSIT_INDEX_OFFSET + 1)
        for bridge_rpc in bridge_rpcs:
            wait_until_deposit_status(
                bridge_rpc, DEPOSIT_INDEX_OFFSET + 1, RpcDepositStatusComplete
            )

        # Leave the node on its original config for the rest of the env's life.
        edited_node.stop()
        config_path.write_text(original_config)
        time.sleep(5)  # ports need to be released before restarting
        edited_node.start()
        wait_until_bridge_ready(edited_rpc)

        self.logger.info(
            "DEPOSIT INDEX OFFSET VERIFIED: the deposit sequence started at the configured offset "
            "and a changed offset did not restart it"
        )
        return True

    def _assert_all_nodes_index(self, bridge_rpcs, drt_txid: str, expected: int):
        for node_idx, bridge_rpc in enumerate(bridge_rpcs):
            deposit_idx = wait_until_drt_recognized(bridge_rpc, drt_txid)
            assert deposit_idx == expected, (
                f"node {node_idx} assigned index {deposit_idx} to {drt_txid}, expected {expected}"
            )
