import os
import flexitest
import toml
from pathlib import Path


class S2Factory(flexitest.Factory):
    def __init__(self, port_range: list[int]):
        super().__init__(port_range)

    @flexitest.with_ectx("ctx")
    def create_s2_service(self, ctx: flexitest.EnvContext) -> flexitest.Service:
        datadir = ctx.make_service_dir("s2")

        base = Path(ctx.envdd_path)
        mtls_cred = str((base / "../s2_cred/tls").resolve())
        config_toml = str((base / "s2" / "config.toml").resolve())
        seed_file = str((base / "s2" / "seed").resolve())
        write_s2_seed(seed_file)
        write_config_toml(config_toml, mtls_cred, seed_file)

        # Dynamic ports
        p2p_port = self.next_port()
        rpc_port = self.next_port()
        logfile = os.path.join(datadir, "service.log")

        cmd = [
            "secret-service",
            config_toml,
        ]

        props = {
            "p2p_port": p2p_port,
            "rpc_port": rpc_port,
        }

        svc = flexitest.service.ProcService(props, cmd, stdout=logfile)
        svc.start()
        return svc


def write_config_toml(output_path: str, mtls_cred: str, seed_file: str):
    """
    Generate a TOML config file with hardcoded values except for TLS paths.

    Args:
        output_path (str): Path to write the TOML file to.
        mtls_cred (str): Directory containing TLS credentials.
                         Expected files: key.pem, cert.pem, bridge.ca.pem
    """
    mtls_dir = Path(mtls_cred)

    config = {
        "seed": seed_file,
        "network": "regtest",
        "tls": {
            "key": str(mtls_dir / "key.pem"),
            "cert": str(mtls_dir / "cert.pem"),
            "ca": str(mtls_dir / "bridge.ca.pem"),
        },
        "transport": {"addr": "0.0.0.0:69"},
    }

    with open(output_path, "w") as f:
        toml.dump(config, f)


def write_s2_seed(output_path: str):
    hex_seed = "195a61de8fdac38f9c97e493c03718c98a3c85a977b49192ceac32e429f6c409"

    data = bytes.fromhex(hex_seed)

    with open(output_path, "wb") as f:
        f.write(data)
