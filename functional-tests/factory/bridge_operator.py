import os
import flexitest
from rpc import inject_service_create_rpc
from utils.constants import WALLETS


class BridgeOperatorFactory(flexitest.Factory):
    def __init__(self, port_range: list[int]):
        super().__init__(port_range)

    @flexitest.with_ectx("ectx")
    def create_server(self, name: str, ectx: flexitest.EnvContext) -> flexitest.Service:
        rpc_port = self.next_port()
        dd = ectx.make_service_dir(name)
        logfile_path = os.path.join(dd, "service.log")
        cmd = [
            "alpen-bridge",
            "--params",
            "/Users/abishekbashyal/Codes/strata-bridge/functional-tests/config/op1/params.toml"
            "",
            "--config",
            "/Users/abishekbashyal/Codes/strata-bridge/functional-tests/config/op1/config.toml"
        ]

        rpc_url = "http://0.0.0.0:5678"
        props = {
            "rpc_port": rpc_port,
            "logfile": logfile_path,
            "sc_wallet_address":WALLETS["OP1"]["STAKE_CHAIN_WALLET"],
        }

        svc = flexitest.service.ProcService(props, cmd, stdout=logfile_path)
        svc.start()
        inject_service_create_rpc(svc, rpc_url, name)
        return svc
