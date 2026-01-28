import flexitest

from constants import BRIDGE_NETWORK_SIZE
from utils.utils import wait_until_bridge_ready

from .base_env import BaseEnv


class BridgeNetworkEnv(BaseEnv):
    """Env running configurable bridge operators connected to S2 instances and a Bitcoin node."""

    def __init__(
        self,
        funding_amount=5.01,
        initial_blocks=101,
        finalization_blocks=10,
    ):
        super().__init__(
            BRIDGE_NETWORK_SIZE,
            funding_amount,
            initial_blocks,
            finalization_blocks,
        )

    def init(self, ectx: flexitest.EnvContext) -> flexitest.LiveEnv:
        svcs = {}

        # Setup Bitcoin node
        bitcoind, brpc, wallet_addr = self.setup_bitcoin(ectx)
        svcs["bitcoin"] = bitcoind

        # Setup FoundationDB
        fdb = self.setup_fdb(ectx)
        svcs["fdb"] = fdb

        # Create operators dynamically based on configuration
        for i in range(self.num_operators):
            s2_service, bridge_node, asm_service = self.create_operator(
                ectx, i, bitcoind.props, brpc, fdb.props
            )

            # Fund operator
            self.fund_operator(brpc, bridge_node.props, wallet_addr)

            # wait bridge node to be ready
            bridge_rpc = bridge_node.create_rpc()
            wait_until_bridge_ready(bridge_rpc)

            # register services
            svcs[f"s2_{i}"] = s2_service
            svcs[f"bridge_node_{i}"] = bridge_node
            svcs["asm_rpc"] = asm_service

        return flexitest.LiveEnv(svcs)
