import logging
from pathlib import Path

import flexitest

from factory.asm_rpc.config_cfg import Duration, OrchestratorConfig
from factory.bridge_operator.asm_cfg import build_asm_params
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import BridgeProtocolParams
from factory.common.asm_params import write_asm_params_json
from factory.fdb import generate_fdb_root_directory
from utils import (
    bitcoin_snapshot,
    generate_blocks,
    wait_until_bitcoind_ready,
)
from utils.mosaic import get_peer_ids
from utils.utils import generate_p2p_ports, read_operator_key

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
        enable_asm_proof: bool = False,
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
        """Setup Bitcoin node by restoring the committed regtest snapshot."""
        meta = bitcoin_snapshot.validate(self.initial_blocks)
        expected_tip = meta["chain_tip"]

        btc_fac = ectx.get_factory("bitcoin")
        bitcoind = btc_fac.create_regtest_bitcoin()
        brpc = bitcoind.create_rpc()
        wait_until_bitcoind_ready(brpc, timeout=30)

        # Verify the running chain matches the snapshot's recorded tip
        actual_height = brpc.proxy.getblockcount()
        actual_hash = brpc.proxy.getbestblockhash()
        if actual_height != expected_tip["height"] or actual_hash != expected_tip["block_hash"]:
            raise RuntimeError(
                "bitcoin snapshot tip mismatch after restore: "
                f"rpc=(height={actual_height}, hash={actual_hash}), "
                f"metadata=(height={expected_tip['height']}, "
                f"hash={expected_tip['block_hash']}); "
                f"{bitcoin_snapshot.REBUILD_HINT}"
            )
        logging.info(
            "resuming L1 chain from snapshot: tip height=%s block_hash=%s (verified via RPC)",
            actual_height,
            actual_hash,
        )

        # Snapshot ships the wallet but bitcoind doesn't auto-load it on startup.
        brpc.proxy.loadwallet(bitcoind.get_prop("walletname"))
        wallet_addr = meta["miner_address"]

        # Start automatic block generation
        miner = None
        if self.btc_config.auto_mine:
            miner = generate_blocks(
                brpc, self.btc_config.block_generation_interval_secs, wallet_addr
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
        return OrchestratorConfig(
            tick_interval=Duration(secs=1, nanos=0),
            max_concurrent_proofs=4,
            proof_db_path=proof_db_path,
        )

    def _ensure_rollup_params(self, ectx: flexitest.EnvContext, bitcoind_rpc) -> None:
        """Build bridge/ASM params and write asm-params.json once per environment."""
        if self._bridge_genesis_height is not None and self._rollup_params_path is not None:
            return

        genesis_height = int(self.initial_blocks)
        self._bridge_genesis_height = genesis_height

        asm_params = build_asm_params(
            bitcoind_rpc, self.operator_key_infos, genesis_height, self._asm_config
        )
        envdd_path = Path(ectx.envdd_path)
        asm_params_path = envdd_path / "generated" / "asm-params.json"
        self._rollup_params_path = write_asm_params_json(asm_params_path, asm_params)

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
        The node will take care of funding the stakechain wallet from the general wallet.
        """
        general_wallet_address = bridge_operator_props["general_wallet_address"]
        brpc.proxy.sendtoaddress(general_wallet_address, self.funding_amount)

        # Generate blocks for finalization
        brpc.proxy.generatetoaddress(self.finalization_blocks, wallet_addr)
