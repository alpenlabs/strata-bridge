import os
from dataclasses import asdict, dataclass
from pathlib import Path

import flexitest
import toml

from constants import MOSAIC_DIR
from rpc import inject_service_create_rpc
from utils.mosaic import PeerConfig
from utils.service_names import get_operator_service_name

from ..bridge_operator import ProcServiceWithEnv, _get_fdb_env
from .mosaic_config import *


@dataclass
class MosaicFactoryConfig:
    circuit_path: str
    storage_cluster_file: str
    all_peers: dict[int, PeerConfig]


class MosaicFactory(flexitest.Factory):
    def __init__(self, port_range: list[int]):
        super().__init__(port_range)

    @flexitest.with_ectx("ctx")
    def create_mosaic_service(
        self, operator_idx: int, config: MosaicFactoryConfig, ctx: flexitest.EnvContext
    ) -> flexitest.Service:
        service_name = get_operator_service_name(operator_idx, MOSAIC_DIR)
        datadir = ctx.make_service_dir(service_name)

        rpc_port = self.next_port()
        rpc_url = f"http://127.0.0.1:{rpc_port}"

        # write config
        config_toml = str((Path(datadir) / "config.toml").resolve())
        generate_config(
            config_toml,
            operator_idx=operator_idx,
            config=config,
            rpc_port=rpc_port,
            fs_storage_root=datadir,
        )

        logfile = os.path.join(datadir, "service.log")

        cmd = [
            "mosaic",
            config_toml,
        ]

        props = {
            "rpc_port": rpc_port,
            "rpc_url": rpc_url,
        }

        svc = ProcServiceWithEnv(
            props,
            cmd,
            stdout=logfile,
            env=_get_fdb_env(),
        )

        svc.start()
        inject_service_create_rpc(svc, rpc_url, service_name)

        return svc


def generate_config(
    output_path: str, operator_idx: int, config: MosaicFactoryConfig, rpc_port: int, fs_storage_root
):
    own_peer = config.all_peers[operator_idx]
    other_peers = [config.all_peers[idx] for idx in config.all_peers if idx != operator_idx]
    mosaic_config = MosaicConfig(
        circuit=CircuitConfig(path=config.circuit_path),
        network=NetworkConfig(
            signing_key_hex=own_peer.signing_key,
            bind_addr=f"127.0.0.1:{own_peer.port}",
            peers=[
                PeerEntry(peer_id_hex=peer.peer_id, addr=f"127.0.0.1:{peer.port}")
                for peer in other_peers
            ],
        ),
        storage=StorageConfig(
            cluster_file=config.storage_cluster_file,
            global_path=[f"mosaic-{operator_idx}"],
        ),
        table_store=LocalFilesystemBackend(root=fs_storage_root),
        rpc=RpcConfig(bind_addr=f"127.0.0.1:{rpc_port}"),
    )

    with open(output_path, "w") as f:
        toml.dump(asdict(mosaic_config), f)
