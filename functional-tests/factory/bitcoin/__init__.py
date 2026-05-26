import os
from urllib.parse import urlparse

import flexitest
from bitcoinlib.services.bitcoind import BitcoindClient

BD_USERNAME = "user"
BD_PASSWORD = "password"

# Env vars that describe an already-running regtest bitcoind for the
# `network-extbtc` environment. See `connect_external_bitcoin`.
EXTERNAL_ZMQ_PORT_ENVS = {
    "zmq_hashblock": "BITCOIN_ZMQ_HASHBLOCK_PORT",
    "zmq_hashtx": "BITCOIN_ZMQ_HASHTX_PORT",
    "zmq_rawblock": "BITCOIN_ZMQ_RAWBLOCK_PORT",
    "zmq_rawtx": "BITCOIN_ZMQ_RAWTX_PORT",
    "zmq_sequence": "BITCOIN_ZMQ_SEQUENCE_PORT",
}


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"network-extbtc selected but {name} is unset; "
            "export the external bitcoin env vars (see run_test.sh)"
        )
    return value


def _read_external_btc_env() -> tuple[dict, str]:
    """Read external regtest bitcoind connection details from the environment.

    Returns the bitcoind `props` dict (same shape as the spawn path) plus the
    RPC url (with embedded credentials) used to build a `BitcoindClient`.
    """
    rpc_url = _require_env("BITCOIN_RPC_URL")
    parsed = urlparse(rpc_url)
    if parsed.hostname is None or parsed.port is None:
        raise RuntimeError(f"BITCOIN_RPC_URL must be http://host:port, got: {rpc_url!r}")

    rpc_user = _require_env("BITCOIN_RPC_USER")
    rpc_password = _require_env("BITCOIN_RPC_PASSWORD")
    zmq_host = _require_env("BITCOIN_ZMQ_HOST")

    props = {
        "rpc_user": rpc_user,
        "rpc_password": rpc_password,
        "walletname": "testwallet",
        "rpc_host": parsed.hostname,
        "rpc_port": parsed.port,
        "zmq_host": zmq_host,
        "p2p_port": 0,  # unused downstream for an external node
    }
    for prop_key, env_name in EXTERNAL_ZMQ_PORT_ENVS.items():
        props[prop_key] = int(_require_env(env_name))

    # Build the credentialed url the bitcoinlib client expects.
    client_url = f"http://{rpc_user}:{rpc_password}@{parsed.hostname}:{parsed.port}"
    return props, client_url


class ExternalBitcoinService(flexitest.service.Service):
    """Handle for an externally-managed regtest bitcoind.

    The test never starts or stops this node, so `is_started()` returns False;
    `LiveEnv.shutdown()` only calls `stop()` on started services, leaving the
    external node running.
    """

    def __init__(self, props: dict, client_url: str):
        super().__init__(props)
        self._client_url = client_url

        def _create_rpc() -> BitcoindClient:
            return BitcoindClient(base_url=client_url, network="regtest")

        self.create_rpc = _create_rpc

    def is_started(self) -> bool:
        return False

    def check_status(self) -> bool:
        return True


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

        # Run bitcoind with mainnet-like fee and dust policies so the bridge node's
        # transactions must pay at least the minimum relay fee (1 sat/vB) and respect the
        # dust threshold. This catches regressions where any tx-graph transaction is
        # broadcast with zero fee or with a dust output.
        cmd = [
            "bitcoind",
            "-regtest",
            "-listen=0",
            f"-port={p2p_port}",
            "-printtoconsole",
            "-server=1",
            "-txindex=1",
            "-acceptnonstdtxn=0",
            "-fallbackfee=0.00001",
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
            "rpc_host": "127.0.0.1",
            "zmq_host": "127.0.0.1",
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

    def connect_external_bitcoin(self) -> flexitest.Service:
        """Attach to an already-running regtest bitcoind described by env vars.

        Unlike `create_regtest_bitcoin`, this spawns no process and allocates no
        ports; the external node owns those. The returned service exposes the same
        `props` and `create_rpc` interface so all downstream config generation and
        block/wallet driving works unchanged.
        """
        props, client_url = _read_external_btc_env()
        return ExternalBitcoinService(props, client_url)
