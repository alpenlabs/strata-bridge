import os
import flexitest
from bitcoinlib.services.bitcoind import BitcoindClient

BD_USERNAME = "user"
BD_PASSWORD = "password"


class BitcoinFactory(flexitest.Factory):
    def __init__(self, port_range: list[int]):
        super().__init__(port_range)

    @flexitest.with_ectx("ctx")
    def create_regtest_bitcoin(self, ctx: flexitest.EnvContext) -> flexitest.Service:
        datadir = ctx.make_service_dir("bitcoin")

        logfile = os.path.join(datadir, "service.log")

        cmd = [
            "bitcoind",
            "-regtest",
            "-listen=0",
            "-port=18444",
            "-printtoconsole",
            "-server=1",
            "-txindex=1",
            "-acceptnonstdtxn=1",
            "-fallbackfee=0.00001",
            "-minrelaytxfee=0",
            "-blockmintxfee=0",
            "-dustrelayfee=0",
            f"-datadir={datadir}",
            "-rpcport=18443",
            "-rpcbind=0.0.0.0",
            "-rpcallowip=0.0.0.0/0",
            f"-rpcuser={BD_USERNAME}",
            f"-rpcpassword={BD_PASSWORD}",
            # --- Dynamic ZMQ ports ---
            "-zmqpubhashblock=tcp://0.0.0.0:28332",
            "-zmqpubhashtx=tcp://0.0.0.0:28333",
            "-zmqpubrawblock=tcp://0.0.0.0:28334",
            "-zmqpubrawtx=tcp://0.0.0.0:28335",
            "-zmqpubsequence=tcp://0.0.0.0:28336",
        ]

        props = {
            "rpc_user": BD_USERNAME,
            "rpc_password": BD_PASSWORD,
            "walletname": "testwallet",
        }

        svc = flexitest.service.ProcService(props, cmd, stdout=logfile)
        svc.start()

        def _create_rpc() -> BitcoindClient:
            st = svc.check_status()
            if not st:
                raise RuntimeError("service isn't active")
            url = f"http://{BD_USERNAME}:{BD_PASSWORD}@0.0.0.0:18443"
            return BitcoindClient(base_url=url, network="regtest")

        svc.create_rpc = _create_rpc

        return svc
