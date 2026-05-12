import os
from urllib.parse import urlparse

import flexitest
from bitcoinlib.services.bitcoind import BitcoindClient

BD_USERNAME = "user"
BD_PASSWORD = "password"

# Default ZMQ ports the remote env expects bitcoind to publish on.
# The user must start bitcoind with `-zmqpub{hashblock,hashtx,rawblock,rawtx,sequence}=tcp://0.0.0.0:<port>`
# matching these values. Host is hardcoded to 127.0.0.1 elsewhere in the harness
# (factory/bridge_operator/utils.py:29), so the remote bitcoind must be reachable
# at localhost.
REMOTE_BTC_ZMQ_HASHBLOCK = 28332
REMOTE_BTC_ZMQ_HASHTX = 28333
REMOTE_BTC_ZMQ_RAWBLOCK = 28334
REMOTE_BTC_ZMQ_RAWTX = 28335
REMOTE_BTC_ZMQ_SEQUENCE = 28336


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

    @flexitest.with_ectx("ctx")
    def create_remote_bitcoin(
        self,
        ctx: flexitest.EnvContext,
        url: str,
        user: str,
        password: str,
    ) -> flexitest.Service:
        """Connect to a user-managed bitcoind instead of spawning one.

        The returned Service has no-op start/stop but exposes the same props
        and `create_rpc()` surface as `create_regtest_bitcoin`, so all
        downstream wallet/mining/funding logic works unchanged. ZMQ ports
        default to the REMOTE_BTC_ZMQ_* constants — the user must start
        bitcoind with matching `-zmqpub*` flags.
        """
        parsed = urlparse(url)
        host = parsed.hostname or "127.0.0.1"
        if host not in ("127.0.0.1", "localhost"):
            # Bridge / asm-runner configs hardcode 127.0.0.1 (see
            # factory/bridge_operator/utils.py:29 and factory/asm_rpc/__init__.py:157),
            # so the remote bitcoind must be reachable at localhost.
            raise ValueError(
                f"BRIDGE_REMOTE_BTC_URL must resolve to 127.0.0.1; got host={host!r}"
            )
        rpc_port = parsed.port
        if rpc_port is None:
            raise ValueError(f"BRIDGE_REMOTE_BTC_URL must include a port; got {url!r}")

        props = {
            "rpc_user": user,
            "rpc_password": password,
            "walletname": "testwallet",
            "p2p_port": 0,  # unused by remote consumers
            "rpc_port": rpc_port,
            "zmq_hashblock": REMOTE_BTC_ZMQ_HASHBLOCK,
            "zmq_hashtx": REMOTE_BTC_ZMQ_HASHTX,
            "zmq_rawblock": REMOTE_BTC_ZMQ_RAWBLOCK,
            "zmq_rawtx": REMOTE_BTC_ZMQ_RAWTX,
            "zmq_sequence": REMOTE_BTC_ZMQ_SEQUENCE,
        }

        svc = _RemoteBitcoindService(props, user=user, password=password, rpc_port=rpc_port)
        svc.start()  # sanity-pings the URL; raises on bad creds.
        return svc


class _RemoteBitcoindService(flexitest.service.Service):
    """Flexitest Service that wraps a user-managed bitcoind RPC.

    start/stop are no-ops; create_rpc returns a BitcoindClient pointing at
    the supplied URL; check_status pings the node once to verify reachability.
    """

    def __init__(self, props: dict, user: str, password: str, rpc_port: int):
        super().__init__(props)
        self._user = user
        self._password = password
        self._rpc_port = rpc_port
        self._started = False

    def start(self) -> None:
        # One-shot reachability check so we fail fast if the URL/creds are bad.
        rpc = self.create_rpc()
        rpc.proxy.getblockchaininfo()
        self._started = True

    def stop(self) -> None:
        # User owns the bitcoind lifecycle.
        self._started = False

    def is_started(self) -> bool:
        return self._started

    def check_status(self) -> bool:
        return self._started

    def create_rpc(self) -> BitcoindClient:
        url = f"http://{self._user}:{self._password}@127.0.0.1:{self._rpc_port}"
        return BitcoindClient(base_url=url, network="regtest")
