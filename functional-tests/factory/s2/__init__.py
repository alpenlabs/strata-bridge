import os
from dataclasses import asdict
from pathlib import Path

import flexitest
import toml

from utils.service_names import SECRET_SERVICE_DIR, get_mtls_cred_path, get_operator_service_name
from utils.utils import OperatorKeyInfo

from .config_cfg import S2Config, TlsConfig, TransportConfig


class S2Factory(flexitest.Factory):
    def __init__(self, port_range: list[int]):
        super().__init__(port_range)

    @flexitest.with_ectx("ctx")
    def create_s2_service(
        self, operator_idx: int, operator_key: OperatorKeyInfo, ctx: flexitest.EnvContext
    ) -> flexitest.Service:
        bridge_operator_name = get_operator_service_name(operator_idx, SECRET_SERVICE_DIR)
        datadir = ctx.make_service_dir(bridge_operator_name)

        envdd_path = Path(ctx.envdd_path)
        mtls_cred_path = str(
            (envdd_path / get_mtls_cred_path(operator_idx, SECRET_SERVICE_DIR)).resolve()
        )

        # Dynamic ports
        s2_port = self.next_port()

        # write seed file
        seed_file = str((envdd_path / bridge_operator_name / "seed").resolve())
        write_s2_seed(seed_file, operator_key)

        # write s2 config
        config_toml = str((envdd_path / bridge_operator_name / "config.toml").resolve())
        generate_s2_config(config_toml, mtls_cred_path, seed_file, s2_port)

        logfile = os.path.join(datadir, "service.log")

        cmd = [
            "secret-service",
            config_toml,
        ]

        props = {
            "s2_port": s2_port,
        }

        svc = flexitest.service.ProcService(props, cmd, stdout=logfile)
        svc.start()
        return svc


def generate_s2_config(output_path: str, mtls_cred: str, seed_file: str, s2_port: int):
    """
    Generate S2 service TOML config file using dataclass configuration.

    Args:
        output_path (str): Path to write the TOML file to.
        mtls_cred (str): Directory containing TLS credentials.
                         Expected files: key.pem, cert.pem, bridge.ca.pem
        seed_file (str): Path to the seed file.
    """
    mtls_dir = Path(mtls_cred)

    s2_config = S2Config(
        seed=seed_file,
        tls=TlsConfig(
            key=str(mtls_dir / "key.pem"),
            cert=str(mtls_dir / "cert.pem"),
            ca=str(mtls_dir / "bridge.ca.pem"),
        ),
        transport=TransportConfig(addr=f"127.0.0.1:{s2_port}"),
    )

    with open(output_path, "w") as f:
        toml.dump(asdict(s2_config), f)


def write_s2_seed(output_path: str, operator_key: OperatorKeyInfo):
    """
    Write S2 seed file using operator keys.

    Args:
        output_path: Path to write the seed file
        operator_key: OperatorKeyInfo containing the SEED hex string
    """
    hex_seed = operator_key.SEED
    data = bytes.fromhex(hex_seed)

    with open(output_path, "wb") as f:
        f.write(data)
