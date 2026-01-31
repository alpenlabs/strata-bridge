from pathlib import Path

import flexitest

from factory.bridge_operator.sidesystem_cfg import build_sidesystem, write_rollup_params_json
from factory.fdb import generate_fdb_root_directory
from utils import (
    BLOCK_GENERATION_INTERVAL_SECS,
    generate_blocks,
    wait_until_bitcoind_ready,
)
from utils.utils import generate_p2p_ports, read_operator_key


class BaseEnv(flexitest.EnvConfig):
    """Base environment class with shared Bitcoin and operator setup logic."""

    def __init__(
        self,
        num_operators,
        funding_amount=5.01,
        initial_blocks=101,
        finalization_blocks=10,
    ):
        super().__init__()
        self.num_operators = num_operators
        self.funding_amount = funding_amount
        self.initial_blocks = initial_blocks
        self.finalization_blocks = finalization_blocks
        self._asm_rpc_service = None
        self._sidesystem = None
        self._rollup_params_path = None

        # Generate P2P ports for this environment
        p2p_port_gen = generate_p2p_ports()
        self.p2p_ports = [next(p2p_port_gen) for _ in range(num_operators)]

        # Load all operator keys
        self.operator_key_infos = [read_operator_key(i) for i in range(num_operators)]

        # Generate unique root directory for this environment's FDB data
        # This allows multiple test environments to share a single FDB instance
        self.fdb_root_directory: str | None = None

    def setup_bitcoin(self, ectx: flexitest.EnvContext):
        """Setup Bitcoin node with wallet and initial funding."""
        btc_fac = ectx.get_factory("bitcoin")
        bitcoind = btc_fac.create_regtest_bitcoin()
        brpc = bitcoind.create_rpc()
        wait_until_bitcoind_ready(brpc, timeout=10)

        # Create new wallet
        brpc.proxy.createwallet(bitcoind.get_prop("walletname"))
        wallet_addr = brpc.proxy.getnewaddress()

        # Mine initial blocks to have usable funds
        brpc.proxy.generatetoaddress(self.initial_blocks, wallet_addr)

        # Start automatic block generation
        generate_blocks(brpc, BLOCK_GENERATION_INTERVAL_SECS, wallet_addr)

        return bitcoind, brpc, wallet_addr

    def setup_fdb(self, ectx: flexitest.EnvContext, env_name: str):
        """Setup FoundationDB instance with a unique root directory for this environment.

        Args:
            ectx: Environment context
            env_name: Name of this environment (used to generate unique root directory)

        Returns:
            FDB service instance
        """
        fdb_fac = ectx.get_factory("fdb")
        fdb = fdb_fac.create_fdb()

        # Generate unique root directory for this environment
        self.fdb_root_directory = generate_fdb_root_directory(env_name)

        return fdb

    def _ensure_rollup_params(self, ectx: flexitest.EnvContext, bitcoind_rpc) -> None:
        """Build sidesystem params and rollup_params.json once per environment."""
        if self._sidesystem is not None and self._rollup_params_path is not None:
            return

        genesis_height = int(self.initial_blocks)
        sidesystem = build_sidesystem(bitcoind_rpc, self.operator_key_infos, genesis_height)

        envdd_path = Path(ectx.envdd_path)
        rollup_params_path = envdd_path / "generated" / "rollup_params.json"
        self._rollup_params_path = write_rollup_params_json(rollup_params_path, sidesystem)
        self._sidesystem = sidesystem

    def create_operator(
        self,
        ectx: flexitest.EnvContext,
        operator_idx,
        bitcoind_props,
        bitcoind_rpc,
        fdb_props,
    ):
        """Create a single bridge operator (S2 service + Bridge node + ASM RPC)."""
        s2_fac = ectx.get_factory("s2")
        bo_fac = ectx.get_factory("bofac")

        # Use pre-loaded operator key
        operator_key = self.operator_key_infos[operator_idx]

        # Build sidesystem + rollup params once using live bitcoind data.
        self._ensure_rollup_params(ectx, bitcoind_rpc)

        # Augment fdb_props with root_directory for this environment
        fdb_props_with_root = {
            **fdb_props,
            "root_directory": self.fdb_root_directory,
        }

        s2_service = s2_fac.create_s2_service(operator_idx, operator_key)
        bridge_operator = bo_fac.create_server(
            operator_idx,
            bitcoind_props,
            s2_service.props,
            fdb_props_with_root,
            self.operator_key_infos,
            self.p2p_ports,
            sidesystem=self._sidesystem,
        )

        if self._asm_rpc_service is None:
            asm_fac = ectx.get_factory("asm_rpc")
            params_file_path = self._rollup_params_path
            self._asm_rpc_service = asm_fac.create_asm_rpc_service(bitcoind_props, params_file_path)

        return s2_service, bridge_operator, self._asm_rpc_service

    def fund_operator(self, brpc, bridge_operator_props, wallet_addr):
        """Fund an operator's wallets."""
        sc_wallet_address = bridge_operator_props["sc_wallet_address"]
        general_wallet_address = bridge_operator_props["general_wallet_address"]
        brpc.proxy.sendtoaddress(sc_wallet_address, self.funding_amount)
        brpc.proxy.sendtoaddress(general_wallet_address, self.funding_amount)

        # Generate blocks for finalization
        brpc.proxy.generatetoaddress(self.finalization_blocks, wallet_addr)
