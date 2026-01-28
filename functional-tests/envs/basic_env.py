import flexitest

from utils.service_names import get_operator_dir_name
from utils.utils import wait_until_bridge_ready

from .base_env import BaseEnv


class BasicEnv(BaseEnv):
    """Environment running a single bridge operator connected to S2 instance and a Bitcoin node."""

    def __init__(self):
        super().__init__(num_operators=1)

    def init(self, ectx: flexitest.EnvContext) -> flexitest.LiveEnv:
        svcs = {}

        # Setup Bitcoin node
        bitcoind, brpc, wallet_addr = self.setup_bitcoin(ectx)
        svcs["bitcoin"] = bitcoind

        # Setup FoundationDB
        fdb = self.setup_fdb(ectx)
        svcs["fdb"] = fdb

        # Create operator directory
        operator_idx = 0
        bridge_operator_name = get_operator_dir_name(operator_idx)
        ectx.make_service_dir(bridge_operator_name)

        # Create single operator
        s2_service, bridge_node, asm_service = self.create_operator(
            ectx, operator_idx, bitcoind.props, brpc, fdb.props
        )

        # Fund operator
        self.fund_operator(brpc, bridge_node.props, wallet_addr)

        # wait bridge node to be ready
        bridge_rpc = bridge_node.create_rpc()
        wait_until_bridge_ready(bridge_rpc)

        # register services
        svcs["bridge_node"] = bridge_node
        svcs["s2"] = s2_service
        svcs["asm_rpc"] = asm_service

        return flexitest.LiveEnv(svcs)
