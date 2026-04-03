import flexitest

from utils.service_names import get_operator_dir_name

from .base_env import BaseEnv
from .basic_env import StrataLiveEnv


class AsmEnv(BaseEnv):
    """Environment running a Bitcoin node and ASM."""

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

        # Create asm
        self._ensure_rollup_params(ectx, brpc)
        asm_fac = ectx.get_factory("asm_rpc")
        params_file_path = self._rollup_params_path
        asm_service = asm_fac.create_asm_rpc_service(bitcoind.props, params_file_path)

        # register services
        svcs["asm_rpc"] = asm_service

        return StrataLiveEnv(svcs, miner)
