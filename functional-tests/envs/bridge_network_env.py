import flexitest

from .base_env import BaseEnv


class BridgeNetworkEnv(BaseEnv):
    """Env running configurable bridge operators connected to S2 instances and a Bitcoin node."""

    def __init__(
        self,
        num_operators,
        p2p_port_generator,
        funding_amount=5.01,
        initial_blocks=101,
        finalization_blocks=10,
    ):
        super().__init__(
            num_operators, p2p_port_generator, funding_amount, initial_blocks, finalization_blocks
        )

    def init(self, ectx: flexitest.EnvContext) -> flexitest.LiveEnv:
        svcs = {}

        # Setup Bitcoin node
        bitcoind, brpc, wallet_addr = self.setup_bitcoin(ectx)
        svcs["bitcoin"] = bitcoind

        # Create operators dynamically based on configuration
        for i in range(self.num_operators):
            s2_service, bridge_operator = self.create_operator(ectx, i, bitcoind.props)
            svcs[f"s2_{i}"] = s2_service
            svcs[f"bo_{i}"] = bridge_operator

            # Fund operator
            self.fund_operator(brpc, bridge_operator.props, wallet_addr)

            # HACK: Find this fix
            # import time
            # time.sleep(1)

        return flexitest.LiveEnv(svcs)
