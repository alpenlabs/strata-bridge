import flexitest

from utils.service_names import get_operator_dir_name

from .base_env import BaseEnv


class BasicEnv(BaseEnv):
    """Environment running a single bridge operator connected to S2 instance and a Bitcoin node."""

    def __init__(self, p2p_port_generator):
        super().__init__(num_operators=1, p2p_port_generator=p2p_port_generator)

    def init(self, ectx: flexitest.EnvContext) -> flexitest.LiveEnv:
        svcs = {}

        # Setup Bitcoin node
        bitcoind, brpc, wallet_addr = self.setup_bitcoin(ectx)
        svcs["bitcoin"] = bitcoind

        # Create operator directory
        operator_idx = 0
        bridge_operator_name = get_operator_dir_name(operator_idx)
        ectx.make_service_dir(bridge_operator_name)

        # Create single operator
        s2_service, bridge_operator = self.create_operator(ectx, operator_idx, bitcoind.props)
        svcs["s2"] = s2_service
        svcs["bo"] = bridge_operator

        # Fund operator
        self.fund_operator(brpc, bridge_operator.props, wallet_addr)

        return flexitest.LiveEnv(svcs)
