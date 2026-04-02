import flexitest

from constants import BRIDGE_NETWORK_SIZE
from factory.mosaic import MosaicFactoryConfig
from utils.mosaic import get_circuit_path, get_peer_configs

from .base_env import BaseEnv


class MosaicEnv(BaseEnv):
    """Env running mosaic nodes only."""

    def __init__(self):
        super().__init__(BRIDGE_NETWORK_SIZE)

    def init(self, ectx: flexitest.EnvContext) -> flexitest.LiveEnv:
        svcs = {}

        # Setup FoundationDB with unique root directory for this environment
        fdb = self.setup_fdb(ectx, "mosaic")
        svcs["fdb"] = fdb

        # Create mosaic peer config
        peers = get_peer_configs(self.num_operators)

        mosaic_factory_config = MosaicFactoryConfig(
            circuit_path=get_circuit_path(),
            storage_cluster_file=fdb.props["cluster_file"],
            all_peers=peers,
        )

        # Create mosaic instances based on configuration
        for i in range(self.num_operators):
            factory = ectx.get_factory("mosaic")
            mosaic_service = factory.create_mosaic_service(i, mosaic_factory_config)

            # register services
            svcs[f"mosaic_{i}"] = mosaic_service

        return flexitest.LiveEnv(svcs)
