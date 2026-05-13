import flexitest

from constants import BRIDGE_NETWORK_SIZE
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import BridgeProtocolParams
from factory.mosaic import MosaicFactoryConfig
from utils.mosaic import get_circuit_path, get_peer_configs
from utils.utils import wait_until_bridge_ready

from .asm_config import AsmEnvConfig
from .base_env import BaseEnv
from .btc_config import BitcoinEnvConfig
from .live_env import StrataLiveEnv


class DeferredStartBridgeNetworkEnv(BaseEnv):
    """Bridge network env for tests that need to observe the bridges' first
    protocol broadcasts in the post-setup mempool.

    Setup order is:
      1. Create each operator and immediately stop its bridge node.
      2. Send `funding_amount` BTC to every operator's general wallet.
      3. Mine `finalization_blocks` once to confirm every funding send.
      4. Start each bridge node back up and wait for it to be ready.

    Bridges are stopped throughout steps 1–3, so they cannot emit any protocol
    broadcasts during env setup. After step 4 they run their normal startup
    flow — publishing stake funding transactions, stake transactions, and any
    other first-time protocol txs — and the resulting broadcasts land in the
    post-setup mempool where the test body can snapshot them deterministically.

    Auto-mining is intentionally disabled and not exposed as a constructor
    argument: a background miner would confirm those mempool transactions
    before the test body could observe them. Tests that need background mining
    should use `BridgeNetworkEnv` instead.
    """

    def __init__(
        self,
        bridge_protocol_params=BridgeProtocolParams(),  # noqa: B008
        bridge_config_params=BridgeConfigParams(),  # noqa: B008
        asm_config: AsmEnvConfig | None = None,
        enable_asm_proof: bool = True,
    ):
        super().__init__(
            BRIDGE_NETWORK_SIZE,
            bridge_protocol_params,
            bridge_config_params,
            BitcoinEnvConfig(auto_mine=False),
            asm_config,
            enable_asm_proof=enable_asm_proof,
        )

    def init(self, ectx: flexitest.EnvContext) -> flexitest.LiveEnv:
        svcs = {}

        bitcoind, brpc, wallet_addr, miner = self.setup_bitcoin(ectx)
        svcs["bitcoin"] = bitcoind

        # `setup_bitcoin` matures only `initial_blocks - 100` coinbases. With
        # finalization mining batched after every operator is funded, the wallet
        # must hold one mature coinbase per operator up front; top up if needed.
        coinbase_shortfall = max(0, 100 + self.num_operators - self.initial_blocks)
        if coinbase_shortfall > 0:
            brpc.proxy.generatetoaddress(coinbase_shortfall, wallet_addr)

        fdb = self.setup_fdb(ectx, "deferred-start-network")
        svcs["fdb"] = fdb

        mosaic_fac = ectx.get_factory("mosaic")
        mosaic_factory_config = MosaicFactoryConfig(
            circuit_path=get_circuit_path(),
            storage_cluster_file=fdb.props["cluster_file"],
            fdb_prefix=self.fdb_root_directory_prefix,
            all_peers=get_peer_configs(self.num_operators),
        )

        created = []
        for i in range(self.num_operators):
            mosaic_service = mosaic_fac.create_mosaic_service(i, mosaic_factory_config)
            s2_service, bridge_node, asm_service = self.create_operator(
                ectx, i, bitcoind.props, brpc, fdb.props, mosaic_service.props["rpc_url"]
            )
            bridge_node.stop()

            brpc.proxy.sendtoaddress(
                bridge_node.props["general_wallet_address"], self.funding_amount
            )
            created.append((i, s2_service, bridge_node, asm_service, mosaic_service))

        brpc.proxy.generatetoaddress(self.finalization_blocks, wallet_addr)

        for i, s2_service, bridge_node, asm_service, mosaic_service in created:
            bridge_node.start()
            bridge_rpc = bridge_node.create_rpc()
            wait_until_bridge_ready(bridge_rpc)

            svcs[f"s2_{i}"] = s2_service
            svcs[f"bridge_node_{i}"] = bridge_node
            svcs["asm_rpc"] = asm_service
            svcs[f"mosaic_{i}"] = mosaic_service

        return StrataLiveEnv(svcs, miner)
