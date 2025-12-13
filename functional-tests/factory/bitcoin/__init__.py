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

        p2p_port = self.next_port()
        rpc_port = self.next_port()
        zmq_hashblock = self.next_port()
        zmq_hashtx = self.next_port()
        zmq_rawblock = self.next_port()
        zmq_rawtx = self.next_port()
        zmq_sequence = self.next_port()

        cmd = [
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

        props = {
            "rpc_user": BD_USERNAME,
            "rpc_password": BD_PASSWORD,
            "walletname": "testwallet",
            "p2p_port": p2p_port,
            "rpc_port": rpc_port,
            "zmq_hashblock": zmq_hashblock,
            "zmq_hashtx": zmq_hashtx,
            "zmq_rawblock": zmq_rawblock,
            "zmq_rawtx": zmq_rawtx,
            "zmq_sequence": zmq_sequence,
        }

        svc = flexitest.service.ProcService(props, cmd, stdout=logfile)
        svc.start()

        def _create_rpc() -> BitcoindClient:
            st = svc.check_status()
            if not st:
                raise RuntimeError("service isn't active")
            url = f"http://{BD_USERNAME}:{BD_PASSWORD}@0.0.0.0:{rpc_port}"
            return BitcoindClient(base_url=url, network="regtest")

        svc.create_rpc = _create_rpc

        return svc
