import shutil
from pathlib import Path

import flexitest
from bitcoinlib.services.bitcoind import BitcoindClient

BD_USERNAME = "user"
BD_PASSWORD = "password"
BD_WALLETNAME = "testwallet"

PORT_KEYS = (
    "p2p_port",
    "rpc_port",
    "zmq_hashblock",
    "zmq_hashtx",
    "zmq_rawblock",
    "zmq_rawtx",
    "zmq_sequence",
)


class BitcoinFactory(flexitest.Factory):
    @flexitest.with_ectx("ctx")
    def create_regtest_bitcoin(
        self,
        ctx: flexitest.EnvContext,
        prepopulated_datadir: Path | None = None,
    ) -> flexitest.Service:
        datadir = Path(ctx.make_service_dir("bitcoin"))

        if prepopulated_datadir is not None:
            src_regtest = Path(prepopulated_datadir) / "regtest"
            if not src_regtest.is_dir():
                raise FileNotFoundError(
                    f"prepopulated bitcoin datadir missing regtest/ at {src_regtest}"
                )
            shutil.copytree(src_regtest, datadir / "regtest")

        logfile = str(datadir / "service.log")

        ports = {key: self.next_port() for key in PORT_KEYS}
        cmd = build_bitcoind_args(datadir=str(datadir), **ports)

        props = {
            "rpc_user": BD_USERNAME,
            "rpc_password": BD_PASSWORD,
            "walletname": BD_WALLETNAME,
            **ports,
        }

        svc = flexitest.service.ProcService(props, cmd, stdout=logfile)
        svc.start()

        rpc_port = ports["rpc_port"]

        def _create_rpc() -> BitcoindClient:
            st = svc.check_status()
            if not st:
                raise RuntimeError("service isn't active")
            url = f"http://{BD_USERNAME}:{BD_PASSWORD}@0.0.0.0:{rpc_port}"
            return BitcoindClient(base_url=url, network="regtest")

        svc.create_rpc = _create_rpc

        return svc


def build_bitcoind_args(
    *,
    datadir: str,
    p2p_port: int,
    rpc_port: int,
    zmq_hashblock: int,
    zmq_hashtx: int,
    zmq_rawblock: int,
    zmq_rawtx: int,
    zmq_sequence: int,
) -> list[str]:
    """Argv for `bitcoind -regtest`. Shared between the flexitest factory and
    the offline snapshot builder so the two can never drift."""
    return [
        "bitcoind",
        "-regtest",
        "-listen=0",
        f"-port={p2p_port}",
        "-printtoconsole",
        "-server=1",
        "-txindex=1",
        "-acceptnonstdtxn=1",
        "-fallbackfee=0.00001",
        "-minrelaytxfee=0",
        "-blockmintxfee=0",
        "-dustrelayfee=0",
        f"-datadir={datadir}",
        f"-rpcport={rpc_port}",
        "-rpcbind=0.0.0.0",
        "-rpcallowip=0.0.0.0/0",
        f"-rpcuser={BD_USERNAME}",
        f"-rpcpassword={BD_PASSWORD}",
        f"-zmqpubhashblock=tcp://0.0.0.0:{zmq_hashblock}",
        f"-zmqpubhashtx=tcp://0.0.0.0:{zmq_hashtx}",
        f"-zmqpubrawblock=tcp://0.0.0.0:{zmq_rawblock}",
        f"-zmqpubrawtx=tcp://0.0.0.0:{zmq_rawtx}",
        f"-zmqpubsequence=tcp://0.0.0.0:{zmq_sequence}",
    ]
