import os
from pathlib import Path

import flexitest

from rpc import inject_service_create_rpc
from utils.utils import OperatorKeyInfo

from .utils import generate_config_toml, generate_params_toml


class BridgeOperatorFactory(flexitest.Factory):
    def __init__(self, port_range: list[int]):
        super().__init__(port_range)

    @flexitest.with_ectx("ectx")
    def create_server(
        self,
        name: str,
        bitcoind_props: dict,
        s2_props: dict,
        operator_key: OperatorKeyInfo,
        ectx: flexitest.EnvContext,
    ) -> flexitest.Service:
        print("Abishek running with ", bitcoind_props, s2_props)
        rpc_port = self.next_port()
        p2p_port = self.next_port()
        dd = ectx.make_service_dir(name)

        base = Path(ectx.envdd_path)
        mtls_cred = str((base / "../operator_cred/tls").resolve())

        # write bridge operator config
        config_toml_path = str((base / name / "config.toml").resolve())
        generate_config_toml(
            bitcoind_props, s2_props, rpc_port, p2p_port, config_toml_path, dd, mtls_cred
        )

        # write bridge operator params
        params_toml_path = str((base / name / "params.toml").resolve())
        generate_params_toml(params_toml_path, operator_key)

        logfile_path = os.path.join(dd, "service.log")
        cmd = [
            "alpen-bridge",
            "--params",
            params_toml_path,
            "--config",
            config_toml_path,
        ]

        rpc_url = f"http://0.0.0.0:{rpc_port}"
        props = {
            "rpc_port": rpc_port,
            "logfile": logfile_path,
            "sc_wallet_address": operator_key.STAKE_CHAIN_WALLET,
            "general_wallet_address": operator_key.GENERAL_WALLET,
        }

        svc = flexitest.service.ProcService(props, cmd, stdout=logfile_path)
        svc.start()
        inject_service_create_rpc(svc, rpc_url, name)
        return svc
