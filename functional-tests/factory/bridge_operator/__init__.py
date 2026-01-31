import os
import subprocess
import sys
from pathlib import Path

import flexitest

from constants import BRIDGE_NODE_DIR
from rpc import inject_service_create_rpc
from utils.service_names import get_mtls_cred_path, get_operator_service_name
from utils.utils import OperatorKeyInfo

from .sidesystem_cfg import Sidesystem
from .utils import generate_config_toml, generate_params_toml


class ProcServiceWithEnv(flexitest.service.ProcService):
    """ProcService subclass that supports passing environment variables."""

    def __init__(self, props: dict, cmd: list[str], stdout=None, env=None):
        super().__init__(props, cmd, stdout)
        self.env = env

    def start(self):
        if self.is_started():
            raise RuntimeError("already running")

        self._reset_state()

        kwargs = {}
        if self.env is not None:
            kwargs["env"] = self.env

        if self.stdout is not None:
            if type(self.stdout) is str:
                # file handle must stay open for subprocess lifetime (no context manager)
                f = open(self.stdout, "a")  # noqa: SIM115
                f.write(f"(process started as: {self.cmd})\n")
                kwargs["stdout"] = f
                kwargs["stderr"] = f
            else:
                kwargs["stdout"] = self.stdout

        p = subprocess.Popen(self.cmd, **kwargs)
        flexitest.service._register_kill(p)
        self.proc = p
        self._update_status_msg()


def _get_fdb_env():
    """Build environment dict with FDB library path for subprocesses."""
    env = os.environ.copy()
    fdb_lib_path = os.environ.get("FDB_LIBRARY_PATH", "/usr/local/lib")
    if sys.platform == "darwin":
        # macOS uses DYLD_LIBRARY_PATH
        existing = env.get("DYLD_LIBRARY_PATH", "")
        env["DYLD_LIBRARY_PATH"] = f"{fdb_lib_path}:{existing}" if existing else fdb_lib_path
    else:
        # Linux uses LD_LIBRARY_PATH
        existing = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = f"{fdb_lib_path}:{existing}" if existing else fdb_lib_path
    return env


class BridgeOperatorFactory(flexitest.Factory):
    def __init__(self, port_range: list[int]):
        super().__init__(port_range)

    @flexitest.with_ectx("ectx")
    def create_server(
        self,
        operator_idx: int,
        bitcoind_props: dict,
        s2_props: dict,
        fdb_props: dict,
        operator_key_infos: list[OperatorKeyInfo],
        p2p_ports: list[str],
        ectx: flexitest.EnvContext,
        sidesystem: Sidesystem,
    ) -> flexitest.Service:
        bridge_operator_name = get_operator_service_name(operator_idx, BRIDGE_NODE_DIR)
        rpc_port = self.next_port()
        # Use provided P2P port for this operator
        my_p2p_addr = p2p_ports[operator_idx]
        # Connect to all other operators
        other_p2p_addrs = [addr for i, addr in enumerate(p2p_ports) if i != operator_idx]
        dd = ectx.make_service_dir(bridge_operator_name)

        envdd_path = Path(ectx.envdd_path)
        mtls_cred_path = str(
            (envdd_path / get_mtls_cred_path(operator_idx, BRIDGE_NODE_DIR)).resolve()
        )

        # write bridge operator config
        config_toml_path = str((envdd_path / bridge_operator_name / "config.toml").resolve())
        # heartbeat delay decreases with operator index
        # so that first node tries to establish connections the last_cred_path
        # NOTE: (@Rajil1213) This assumes that the nodes are started in the order of their indices
        heartbeat_delay_factor = len(operator_key_infos) - operator_idx
        generate_config_toml(
            bitcoind_props,
            s2_props,
            fdb_props,
            rpc_port,
            my_p2p_addr,
            other_p2p_addrs,
            config_toml_path,
            dd,
            mtls_cred_path,
            heartbeat_delay_factor,
        )

        # write bridge operator params
        params_toml_path = str((envdd_path / bridge_operator_name / "params.toml").resolve())
        generate_params_toml(
            params_toml_path,
            operator_key_infos,
            sidesystem=sidesystem,
        )

        logfile_path = os.path.join(dd, "service.log")
        cmd = [
            "alpen-bridge",
            "--params",
            params_toml_path,
            "--config",
            config_toml_path,
        ]

        rpc_url = f"http://0.0.0.0:{rpc_port}"
        # Use the current operator's wallet addresses
        current_operator_key = operator_key_infos[operator_idx]
        props = {
            "rpc_port": rpc_port,
            "logfile": logfile_path,
            "sc_wallet_address": current_operator_key.STAKE_CHAIN_WALLET,
            "general_wallet_address": current_operator_key.GENERAL_WALLET,
        }

        svc = ProcServiceWithEnv(
            props,
            cmd,
            stdout=logfile_path,
            env=_get_fdb_env(),
        )
        svc.stop_timeout = 300
        svc.start()
        inject_service_create_rpc(svc, rpc_url, bridge_operator_name)
        return svc
