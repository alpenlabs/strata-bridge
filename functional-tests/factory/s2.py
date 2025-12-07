import os
import flexitest


class S2Factory(flexitest.Factory):
    def __init__(self, port_range: list[int]):
        super().__init__(port_range)

    @flexitest.with_ectx("ctx")
    def create_s2_service(self, ctx: flexitest.EnvContext) -> flexitest.Service:
        datadir = ctx.make_service_dir("s2")

        # Dynamic ports
        p2p_port = self.next_port()
        rpc_port = self.next_port()
        logfile = os.path.join(datadir, "service.log")

        cmd = [
            "secret-service",
            "/Users/abishekbashyal/Codes/strata-bridge/functional-tests/config/s2/config.toml",
        ]

        props = {
            "p2p_port": p2p_port,
            "rpc_port": rpc_port,
        }

        svc = flexitest.service.ProcService(props, cmd, stdout=logfile)
        svc.start()
        return svc
