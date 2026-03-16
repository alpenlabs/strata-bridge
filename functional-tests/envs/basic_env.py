import flexitest

from utils import generate_blocks
from utils.service_names import get_operator_dir_name
from utils.utils import MinerThread, wait_until_bridge_ready

from .base_env import BaseEnv


class StrataLiveEnv(flexitest.LiveEnv):
    """LiveEnv with miner control exposed to tests via ctx.env."""

    def __init__(self, svcs, miner: MinerThread | None = None):
        super().__init__(svcs)
        self._miner = miner

    def stop_miner(self):
        if self._miner is not None:
            self._miner.stop()
            self._miner = None

    def start_miner(self, bitcoin_rpc, block_interval, addr):
        self.stop_miner()
        self._miner = generate_blocks(bitcoin_rpc, block_interval, addr)

    def shutdown(self):
        self.stop_miner()
        super().shutdown()


class BasicEnv(BaseEnv):
    """Environment running a single bridge operator connected to S2 instance and a Bitcoin node."""

    def __init__(self):
        super().__init__(num_operators=1)

    def init(self, ectx: flexitest.EnvContext) -> flexitest.LiveEnv:
        svcs = {}

        # Setup Bitcoin node
        bitcoind, brpc, wallet_addr, miner = self.setup_bitcoin(ectx)
        svcs["bitcoin"] = bitcoind

        # Setup FoundationDB with unique root directory for this environment
        fdb = self.setup_fdb(ectx, "basic")
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

        return StrataLiveEnv(svcs, miner)
