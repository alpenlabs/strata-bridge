import os
from pathlib import Path

import flexitest

from constants import (
    GENERATED_DIR,
    NATIVE_TEST_ASM_SIGNING_KEY,
    NATIVE_TEST_MOHO_SIGNING_KEY,
)
from factory.asm_rpc.config_cfg import (
    Duration,
    NativeBackend,
    OrchestratorConfig,
    Sp1Backend,
)
from factory.bridge_operator.asm_cfg import copy_rollup_params, write_rollup_params
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import BridgeProtocolParams
from factory.fdb import generate_fdb_root_directory
from utils.bitcoin import generate_blocks
from utils.mosaic import get_peer_ids
from utils.utils import (
    generate_p2p_ports,
    read_operator_key,
    wait_until_bitcoind_ready,
)

from .asm_config import AsmEnvConfig
from .btc_config import BitcoinEnvConfig


class BaseEnv(flexitest.EnvConfig):
    """Base environment class with shared Bitcoin and operator setup logic."""

    def __init__(
        self,
        num_operators,
        bridge_protocol_params=BridgeProtocolParams(),  # noqa: B008
        bridge_config_params=BridgeConfigParams(),  # noqa: B008
        btc_config: BitcoinEnvConfig | None = None,
        asm_config: AsmEnvConfig | None = None,
        enable_asm_proof: bool = True,
    ):
        super().__init__()
        self.num_operators = num_operators
        self.btc_config = btc_config or BitcoinEnvConfig()
        self.funding_amount = self.btc_config.funding_amount
        self.initial_blocks = self.btc_config.initial_blocks
        self.finalization_blocks = self.btc_config.finalization_blocks
        self._asm_config = asm_config
        self._asm_rpc_service = None
        self._bridge_genesis_height = None
        self._rollup_params_path = None
        self._asm_vk_path = None
        self._moho_vk_path = None
        self._bridge_protocol_params = bridge_protocol_params
        self._bridge_config_params = bridge_config_params
        self._enable_asm_proof = enable_asm_proof

        # Generate P2P ports for this environment
        p2p_port_gen = generate_p2p_ports()
        self.p2p_ports = [next(p2p_port_gen) for _ in range(num_operators)]

        # Load all operator keys
        self.operator_key_infos = [read_operator_key(i) for i in range(num_operators)]

        # Generate unique root directory prefix for this environment's FDB data.
        # Each operator derives its own namespace from this prefix.
        self.fdb_root_directory_prefix: str | None = None

        self.mosaic_peer_ids = get_peer_ids(num_operators)

    def setup_bitcoin(self, ectx: flexitest.EnvContext):
        """Setup Bitcoin node with wallet and initial funding."""
        btc_fac = ectx.get_factory("bitcoin")
        if self.btc_config.external:
            bitcoind = btc_fac.connect_external_bitcoin()
        else:
            bitcoind = btc_fac.create_regtest_bitcoin()
        brpc = bitcoind.create_rpc()
        wait_until_bitcoind_ready(brpc, timeout=10)

        walletname = bitcoind.get_prop("walletname")
        if self.btc_config.external:
            # run_test.sh (SP1 mode) may have already created the wallet and mined to the
            # genesis height on this externally-managed node. Load it instead of creating,
            # and only mine the shortfall.
            if walletname not in brpc.proxy.listwallets():
                try:
                    brpc.proxy.loadwallet(walletname)
                except Exception:
                    brpc.proxy.createwallet(walletname)
            wallet_addr = brpc.proxy.getnewaddress()
            shortfall = self.initial_blocks - brpc.proxy.getblockcount()
            if shortfall > 0:
                brpc.proxy.generatetoaddress(shortfall, wallet_addr)
        else:
            # Create new wallet
            brpc.proxy.createwallet(walletname)
            wallet_addr = brpc.proxy.getnewaddress()

            # Mine initial blocks to have usable funds
            brpc.proxy.generatetoaddress(self.initial_blocks, wallet_addr)

        # Start automatic block generation
        miner = None
        if self.btc_config.auto_mine:
            miner = generate_blocks(
                brpc,
                self.btc_config.block_generation_interval_secs,
                wallet_addr,
                mine_on_demand=self.btc_config.mine_on_demand,
                trailing_blocks=self.btc_config.mine_on_demand_trailing_blocks,
            )

        return bitcoind, brpc, wallet_addr, miner

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
        self.fdb_root_directory_prefix = generate_fdb_root_directory(env_name)

        return fdb

    def _build_orchestrator_config(self, ectx: flexitest.EnvContext) -> OrchestratorConfig | None:
        """Return the proof-orchestrator config when enabled, else None.

        Enabling the orchestrator is the gate that makes the asm-runner open its
        `MohoStateDb` / `ExportEntriesDb`, which back `strata_asm_getExportEntryMMRProof`.
        """
        if not self._enable_asm_proof:
            return None

        envdd_path = Path(ectx.envdd_path)
        proof_db_path = str((envdd_path / "asm_rpc" / "proof_db").resolve())

        # When run_test.sh built the ASM/Moho SP1 ELFs (BRIDGE_PROOF_SP1_ASM=1) it exports
        # their paths; use the SP1 backend so the asm-runner emits real Groth16 proofs.
        # Otherwise sign native Schnorr attestations.
        asm_elf = os.environ.get("BRIDGE_PROOF_ASM_ELF_PATH")
        moho_elf = os.environ.get("BRIDGE_PROOF_MOHO_ELF_PATH")
        if asm_elf and moho_elf:
            backend = Sp1Backend(asm_elf_path=asm_elf, moho_elf_path=moho_elf)
        else:
            backend = NativeBackend(
                asm_schnorr_signing_key=NATIVE_TEST_ASM_SIGNING_KEY,
                moho_schnorr_signing_key=NATIVE_TEST_MOHO_SIGNING_KEY,
            )

        return OrchestratorConfig(
            tick_interval=Duration(secs=1, nanos=0),
            max_concurrent_proofs=4,
            proof_db_path=proof_db_path,
            backend=backend,
        )

    def _ensure_rollup_params(self, ectx: flexitest.EnvContext, bitcoind_rpc) -> None:
        """Build bridge/ASM params once per environment."""
        # All attrs are written together below; one sentinel is enough.
        if self._rollup_params_path is not None:
            return

        genesis_height = int(self.initial_blocks)
        self._bridge_genesis_height = genesis_height

        generated_dir = Path(ectx.envdd_path) / GENERATED_DIR

        # In SP1 proving mode run_test.sh pre-generates these params from the external L1
        # and bakes them into the guest ELF. Reuse the exact files so the runtime
        # asm-runner anchors to the same genesis the ELF was built against.
        prebuilt_dir = os.environ.get("BRIDGE_PROOF_SP1_PARAMS_DIR")
        if prebuilt_dir:
            params = copy_rollup_params(prebuilt_dir, generated_dir)
        else:
            params = write_rollup_params(
                bitcoind_rpc,
                self.operator_key_infos,
                genesis_height,
                self._asm_config,
                generated_dir,
            )
        self._rollup_params_path, self._asm_vk_path, self._moho_vk_path = params

    def create_operator(
        self,
        ectx: flexitest.EnvContext,
        operator_idx,
        bitcoind_props,
        bitcoind_rpc,
        fdb_props,
        mosaic_rpc: str,
    ):
        """Create a single bridge operator (S2 service + Bridge node + ASM RPC)."""
        s2_fac = ectx.get_factory("s2")
        bo_fac = ectx.get_factory("bofac")

        # Use pre-loaded operator key
        operator_key = self.operator_key_infos[operator_idx]

        # Build bridge/ASM params once using live bitcoind data.
        self._ensure_rollup_params(ectx, bitcoind_rpc)

        if self._bridge_genesis_height is None:
            raise RuntimeError("Bridge genesis height must be initialized before operators")

        if self.fdb_root_directory_prefix is None:
            raise RuntimeError("FDB root directory prefix must be initialized before operators")

        operator_root_directory = f"{self.fdb_root_directory_prefix}-operator-{operator_idx}"

        # Augment fdb_props with an operator-specific root_directory
        fdb_props_with_root = {
            **fdb_props,
            "root_directory": operator_root_directory,
        }

        if self._asm_rpc_service is None:
            asm_fac = ectx.get_factory("asm_rpc")
            params_file_path = self._rollup_params_path
            orchestrator_config = self._build_orchestrator_config(ectx)
            self._asm_rpc_service = asm_fac.create_asm_rpc_service(
                bitcoind_props,
                params_file_path,
                orchestrator_config=orchestrator_config,
            )
        asm_props = self._asm_rpc_service.props

        s2_service = s2_fac.create_s2_service(operator_idx, operator_key)

        bridge_operator = bo_fac.create_server(
            operator_idx,
            bitcoind_props,
            s2_service.props,
            fdb_props_with_root,
            asm_props,
            self.operator_key_infos,
            self.p2p_ports,
            genesis_height=self._bridge_genesis_height,
            bridge_protocol_params=self._bridge_protocol_params,
            bridge_config_params=self._bridge_config_params,
            mosaic_rpc=mosaic_rpc,
            mosaic_peers=self.mosaic_peer_ids,
        )

        return s2_service, bridge_operator, self._asm_rpc_service

    def fund_operator(self, brpc, bridge_operator_props, wallet_addr):
        """Fund an operator's wallet.
        Only the general wallet needs to be funded.
        The node will take care of funding the reserved wallet from the general wallet.
        """
        general_wallet_address = bridge_operator_props["general_wallet_address"]
        brpc.proxy.sendtoaddress(general_wallet_address, self.funding_amount)

        # Generate blocks for finalization
        brpc.proxy.generatetoaddress(self.finalization_blocks, wallet_addr)
