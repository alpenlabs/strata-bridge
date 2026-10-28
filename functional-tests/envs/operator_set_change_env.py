import flexitest

from constants import BRIDGE_NETWORK_SIZE
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import BridgeProtocolParams
from factory.mosaic import MosaicFactoryConfig
from utils.mosaic import get_circuit_path, get_peer_configs
from utils.operator_set import scheduled_operator, write_operator_schedule
from utils.utils import OperatorKeyInfo, read_all_operator_keys, wait_until_bridge_ready

from .asm_config import AsmEnvConfig
from .base_env import BaseEnv
from .btc_config import BitcoinEnvConfig
from .live_env import StrataLiveEnv


class OperatorSetChangeEnv(BaseEnv):
    """Env provisioning every fixture operator, of which only the genesis operators run.

    The first `num_genesis_operators` operators form ASM's genesis operator set and start on a
    genesis schedule. Every other operator's services are created and funded, but its bridge
    node stays stopped until a test registers it in an edited operator schedule.
    """

    def __init__(
        self,
        num_genesis_operators: int = BRIDGE_NETWORK_SIZE,
        bridge_protocol_params=BridgeProtocolParams(),  # noqa: B008
        bridge_config_params=BridgeConfigParams(),  # noqa: B008
        btc_config: BitcoinEnvConfig | None = None,
        asm_config: AsmEnvConfig | None = None,
    ):
        super().__init__(
            len(read_all_operator_keys()),
            bridge_protocol_params,
            bridge_config_params,
            btc_config,
            asm_config,
        )
        self.num_genesis_operators = num_genesis_operators

    @property
    def genesis_operator_key_infos(self) -> list[OperatorKeyInfo]:
        return self.operator_key_infos[: self.num_genesis_operators]

    def init(self, ectx: flexitest.EnvContext) -> flexitest.LiveEnv:
        svcs = {}

        bitcoind, brpc, wallet_addr, miner = self.setup_bitcoin(ectx)
        svcs["bitcoin"] = bitcoind

        fdb = self.setup_fdb(ectx, "operator-set-change")
        svcs["fdb"] = fdb

        mosaic_fac = ectx.get_factory("mosaic")
        mosaic_factory_config = MosaicFactoryConfig(
            circuit_path=get_circuit_path(),
            storage_cluster_file=fdb.props["cluster_file"],
            fdb_prefix=self.fdb_root_directory_prefix,
            all_peers=get_peer_configs(self.num_operators),
        )

        nodes = {}
        for i in range(self.num_operators):
            mosaic_service = mosaic_fac.create_mosaic_service(i, mosaic_factory_config)
            s2_service, bridge_node, asm_service = self.create_operator(
                ectx,
                i,
                bitcoind.props,
                brpc,
                fdb.props,
                mosaic_service.props["rpc_url"],
                start=False,
            )
            self.fund_operator(brpc, bridge_node.props, wallet_addr)

            nodes[i] = bridge_node
            svcs[f"s2_{i}"] = s2_service
            svcs[f"bridge_node_{i}"] = bridge_node
            svcs["asm_rpc"] = asm_service
            svcs[f"mosaic_{i}"] = mosaic_service

        genesis_height = self.asm_params.anchor.block.height
        genesis_schedule = [
            scheduled_operator(i, genesis_height) for i in range(self.num_genesis_operators)
        ]
        for registration in genesis_schedule:
            write_operator_schedule(nodes[registration.index], nodes, genesis_schedule)
        for registration in genesis_schedule:
            node = nodes[registration.index]
            node.start()
            wait_until_bridge_ready(node.create_rpc())

        return StrataLiveEnv(svcs, miner)
