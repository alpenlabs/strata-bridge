import os
from pathlib import Path

import flexitest

from constants import BRIDGE_NODE_DIR
from rpc import inject_service_create_rpc
from utils.service_names import get_mtls_cred_path, get_operator_service_name
from utils.utils import OperatorKeyInfo

from .utils import generate_config_toml, generate_params_toml


class BridgeOperatorFactory(flexitest.Factory):
    def __init__(self, port_range: list[int]):
        super().__init__(port_range)

    @flexitest.with_ectx("ectx")
    def create_server(
        self,
        operator_idx: int,
        bitcoind_props: dict,
        s2_props: dict,
        operator_key_infos: list[OperatorKeyInfo],
        p2p_ports: list[str],
        ectx: flexitest.EnvContext,
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
        generate_config_toml(
            bitcoind_props,
            s2_props,
            rpc_port,
            my_p2p_addr,
            other_p2p_addrs,
            config_toml_path,
            dd,
            mtls_cred_path,
        )

        # write bridge operator params
        params_toml_path = str((envdd_path / bridge_operator_name / "params.toml").resolve())
        generate_params_toml(params_toml_path, operator_key_infos)

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

        svc = flexitest.service.ProcService(props, cmd, stdout=logfile_path)
        svc.stop_timeout = 300
        svc.start()
        inject_service_create_rpc(svc, rpc_url, bridge_operator_name)
        return svc
