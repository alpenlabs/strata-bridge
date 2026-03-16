import flexitest

from constants import BRIDGE_NETWORK_SIZE
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import BridgeProtocolParams
from utils.utils import wait_until_bridge_ready

from .asm_config import AsmEnvConfig
from .base_env import BaseEnv
from .basic_env import StrataLiveEnv
from .btc_config import BitcoinEnvConfig


class BridgeNetworkEnv(BaseEnv):
    """Env running configurable bridge operators connected to S2 instances and a Bitcoin node."""

    def __init__(
        self,
        bridge_protocol_params=BridgeProtocolParams(),  # noqa: B008
        bridge_config_params=BridgeConfigParams(),  # noqa: B008
        btc_config: BitcoinEnvConfig | None = None,
        asm_config: AsmEnvConfig | None = None,
    ):
        super().__init__(
            BRIDGE_NETWORK_SIZE,
            bridge_protocol_params,
            bridge_config_params,
            btc_config,
            asm_config,
        )

    def init(self, ectx: flexitest.EnvContext) -> flexitest.LiveEnv:
        svcs = {}

        # Setup Bitcoin node
        bitcoind, brpc, wallet_addr, miner = self.setup_bitcoin(ectx)
        svcs["bitcoin"] = bitcoind

        # Setup FoundationDB with unique root directory for this environment
        fdb = self.setup_fdb(ectx, "network")
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

        return StrataLiveEnv(svcs, miner)
