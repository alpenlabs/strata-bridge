import flexitest
import time


from constants import BRIDGE_NETWORK_SIZE
from envs.base_test import StrataTestBase
from utils.network import wait_until_p2p_connected
from utils.utils import wait_until_bridge_ready


@flexitest.register
class BridgeNetworkTest(StrataTestBase):
    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env("network")

    def main(self, ctx: flexitest.RunContext):
        num_operators = BRIDGE_NETWORK_SIZE
        bridge_nodes = [ctx.get_service(f"bridge_node_{idx}") for idx in range(num_operators)]
        bridge_rpcs = [bridge_node.create_rpc() for bridge_node in bridge_nodes]

        # Verify operator connectivity
        self.logger.info("Verifying P2P connectivity among bridge nodes")
        wait_until_p2p_connected(bridge_rpcs)
        self.logger.info("All bridge nodes are connected via P2P")

        # Stop all bridge nodes
        for idx, bridge_node in enumerate(bridge_nodes):
            self.logger.info(f"Stopping bridge node {idx}")
            bridge_node.stop()

        # Start all bridge nodes again
        for i, (node, rpc) in enumerate(zip(bridge_nodes, bridge_rpcs, strict=True)):
            self.logger.info(f"Starting bridge node {i}")
            node.start()
            wait_until_bridge_ready(rpc)

        # Verify operator connectivity again
        self.logger.info("Verifying P2P connectivity among bridge nodes")
        wait_until_p2p_connected(bridge_rpcs)
        self.logger.info("All bridge nodes are connected via P2P")

        return True
