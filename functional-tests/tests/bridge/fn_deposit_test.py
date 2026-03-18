import flexitest

from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from rpc.types import RpcDepositStatusComplete, RpcDepositStatusInProgress
from utils.bridge import get_bridge_nodes_and_rpcs
from utils.deposit import (
    wait_until_deposit_status,
    wait_until_drt_recognized,
    wait_until_drts_reach_status_threshold,
    wait_until_drts_recognized,
)
from utils.dev_cli import DevCli
from utils.network import wait_until_p2p_connected
from utils.utils import (
    read_operator_key,
    snapshot_log_offsets,
    wait_until_bridge_ready,
    wait_until_logs_match,
)


@flexitest.register
class BridgeDepositTest(StrataTestBase):
    """
    Test that a deposit can be made and completed successfully in a bridge network environment.

    Then broadcast multiple DRTs before restarting all operator nodes,
    and verify that:
    - the restarted nodes recognize the DRTs,
    - emit nags if necessary, and
    - complete the deposits while maintaining P2P connectivity.
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(BridgeNetworkEnv())

    def main(self, ctx: flexitest.RunContext):
        CONCURRENT_DRT_COUNT = 5
        bridge_nodes, bridge_rpcs = get_bridge_nodes_and_rpcs(ctx)

        # Test deposit
        bitcoind_service = ctx.get_service("bitcoin")
        bitcoind_props = bitcoind_service.props

        num_operators = len(bridge_nodes)
        musig2_keys = [read_operator_key(i).MUSIG2_KEY for i in range(num_operators)]

        dev_cli = DevCli(bitcoind_props, musig2_keys)
        drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted DRT: {drt_txid}")

        bridge_rpc = bridge_rpcs[0]
        deposit_id = wait_until_drt_recognized(bridge_rpc, drt_txid)

        wait_until_deposit_status(bridge_rpc, deposit_id, RpcDepositStatusComplete)

        self.logger.info(f"Broadcasting {CONCURRENT_DRT_COUNT} DRTs before restarting all nodes")
        drt_txids = [dev_cli.send_deposit_request() for _ in range(CONCURRENT_DRT_COUNT)]

        for drt_txid in drt_txids:
            self.logger.info(f"Broadcasted DRT: {drt_txid}")

        operator_log_offsets = snapshot_log_offsets(
            [bridge_node.props["logfile"] for bridge_node in bridge_nodes]
        )

        self.logger.info("Waiting for all DRTs to be recognized before stopping nodes")
        wait_until_drts_recognized(
            bridge_rpc,
            drt_txids,
            timeout=180,
        )

        self.logger.info("Stopping all operator nodes")
        for i in range(num_operators):
            self.logger.info(f"Stopping operator node {i}")
            bridge_nodes[i].stop()

        self.logger.info("Restarting all operator nodes")
        for i in range(num_operators):
            self.logger.info(f"Restarting operator node {i}")
            bridge_nodes[i].start()
            wait_until_bridge_ready(bridge_rpcs[i])

        self.logger.info(
            "Waiting for restarted nodes to recognize all DRTs with enough deposits in progress"
        )

        deposit_ids = wait_until_drts_reach_status_threshold(
            bridge_rpc,
            drt_txids,
            expected_status=RpcDepositStatusInProgress,
            threshold=1,
            timeout=180,
        )

        self.logger.info("Waiting for a post-restart nag emission in operator logs")
        try:
            wait_until_logs_match(
                operator_log_offsets,
                lambda line: "executing nag duty to request missing peer data" in line,
                timeout=60,
                error_msg="Timed out waiting for post-restart nag emission",
            )
            self.logger.info("Observed post-restart nag emission in operator logs")
        except TimeoutError:
            self.logger.info("No post-restart nag emission observed within timeout")

        self.logger.info("Verifying P2P connectivity among bridge nodes before deposit")
        wait_until_p2p_connected(bridge_rpcs)

        self.logger.info("Waiting for all restarted deposits to complete")
        for deposit_id in deposit_ids:
            wait_until_deposit_status(
                bridge_rpc,
                deposit_id,
                RpcDepositStatusComplete,
                timeout=300,
            )

        self.logger.info("Verifying P2P connectivity among bridge nodes after deposits")
        wait_until_p2p_connected(bridge_rpcs)

        return True
