"""ASM RPC factory for functional testing.

This factory creates and manages ASM RPC service instances for testing.
"""

import os
import shutil
from dataclasses import asdict
from pathlib import Path

import flexitest
import toml

from rpc import inject_service_create_rpc

from .config_cfg import (
    AsmRpcConfig,
    BitcoinConfig,
    BtcNotifyConfig,
    DatabaseConfig,
    Duration,
    RpcConfig,
)


class AsmRpcFactory(flexitest.Factory):
    """Factory for creating ASM RPC service instances."""

    def __init__(self, port_range: list[int]):
        super().__init__(port_range)

    @flexitest.with_ectx("ctx")
    def create_asm_rpc_service(
        self,
        bitcoind_props: dict,
        params_file_path: str,
        ctx: flexitest.EnvContext,
    ) -> flexitest.Service:
        """Create an ASM RPC service instance.

        Args:
            bitcoind_props: Properties from the Bitcoin service (includes zmq ports, rpc details)
            params_file_path: Path to the params.json file for rollup parameters
            ctx: Environment context from flexitest

        Returns:
            A running ASM RPC service
        """
        service_name = "asm_rpc"
        datadir = ctx.make_service_dir(service_name)

        envdd_path = Path(ctx.envdd_path)

        # Allocate a port for the RPC server
        rpc_port = self.next_port()

        # Database path
        db_path = str((envdd_path / service_name / "db").resolve())

        # Generate config file
        config_toml_path = str((envdd_path / service_name / "config.toml").resolve())
        generate_asm_rpc_config(
            bitcoind_props=bitcoind_props,
            rpc_port=rpc_port,
            db_path=db_path,
            output_path=config_toml_path,
        )

        # Log file
        logfile = os.path.join(datadir, "service.log")

        # Command to start ASM RPC
        cmd = [
            resolve_asm_runner_bin(),
            "--config",
            config_toml_path,
            "--params",
            params_file_path,
        ]

        props = {
            "rpc_port": rpc_port,
            "rpc_url": f"http://127.0.0.1:{rpc_port}",
            "db_path": db_path,
        }

        rpc_url = f"http://127.0.0.1:{rpc_port}"
        svc = flexitest.service.ProcService(props, cmd, stdout=logfile)
        svc.start()
        inject_service_create_rpc(svc, rpc_url, service_name)
        return svc


def resolve_asm_runner_bin() -> str:
    """Resolve the strata-asm-runner binary path."""
    env_override = os.environ.get("STRATA_ASM_RUNNER_BIN")
    if env_override:
        return env_override

    path = shutil.which("strata-asm-runner")
    if path:
        return path

    repo_root = Path(__file__).resolve().parents[2]
    for rel in ("target/debug/strata-asm-runner", "target/release/strata-asm-runner"):
        candidate = (repo_root / rel).as_posix()
        if os.path.exists(candidate):
            return candidate

    return "strata-asm-runner"


def zmq_connection_string(port: int) -> str:
    """Generate ZMQ connection string for a given port."""
    return f"tcp://127.0.0.1:{port}"


def generate_asm_rpc_config(
    bitcoind_props: dict,
    rpc_port: int,
    db_path: str,
    output_path: str,
):
    """Generate ASM RPC configuration TOML file.

    Args:
        bitcoind_props: Bitcoin service properties (rpc_port, zmq ports, etc.)
        rpc_port: Port for ASM RPC server to listen on
        db_path: Path to the database directory
        output_path: Path to write the config.toml file
    """
    config = AsmRpcConfig(
        rpc=RpcConfig(
            host="127.0.0.1",
            port=rpc_port,
        ),
        database=DatabaseConfig(
            path=db_path,
            num_threads=4,
            retry_count=4,
            delay=Duration(secs=0, nanos=150_000_000),
        ),
        bitcoin=BitcoinConfig(
            rpc_url=f"http://127.0.0.1:{bitcoind_props['rpc_port']}",
            rpc_user="user",
            rpc_password="password",
            retry_count=3,
            retry_interval=Duration(secs=1, nanos=0),
        ),
        btc_tracker=BtcNotifyConfig(
            bury_depth=2,
            hashblock_connection_string=zmq_connection_string(bitcoind_props["zmq_hashblock"]),
            hashtx_connection_string=zmq_connection_string(bitcoind_props["zmq_hashtx"]),
            rawblock_connection_string=zmq_connection_string(bitcoind_props["zmq_rawblock"]),
            rawtx_connection_string=zmq_connection_string(bitcoind_props["zmq_rawtx"]),
            sequence_connection_string=zmq_connection_string(bitcoind_props["zmq_sequence"]),
        ),
    )

    with open(output_path, "w") as f:
        toml.dump(asdict(config), f)
