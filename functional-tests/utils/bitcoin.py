import logging
from threading import Event, Thread

from bitcoinlib.services.bitcoind import BitcoindClient

from constants import MEMPOOL_POLL_INTERVAL_SECS


def prepare_wallet_and_chain(rpc: BitcoindClient, walletname: str, min_height: int) -> str:
    """Load-or-create `walletname`, mine up to `min_height`, and return a wallet address."""
    if walletname not in rpc.proxy.listwallets():
        try:
            rpc.proxy.loadwallet(walletname)
        except Exception:
            rpc.proxy.createwallet(walletname)
    addr = rpc.proxy.getnewaddress()
    shortfall = min_height - rpc.proxy.getblockcount()
    if shortfall > 0:
        rpc.proxy.generatetoaddress(shortfall, addr)
    return addr


class MinerThread:
    """Wraps the block-generation thread with a stop signal."""

    def __init__(self, thread: Thread, stop_event: Event):
        self._thread = thread
        self._stop_event = stop_event

    def stop(self, timeout: float = 5):
        self._stop_event.set()
        self._thread.join(timeout=timeout)


def generate_blocks(
    bitcoin_rpc: BitcoindClient,
    interval_secs,
    addr: str,
    mine_on_demand: bool = False,
    trailing_blocks: int = 0,
) -> MinerThread:
    stop_event = Event()
    if mine_on_demand:
        thr = Thread(
            target=on_demand_mining_loop,
            args=(bitcoin_rpc, addr, stop_event, trailing_blocks),
        )
    else:
        thr = Thread(
            target=interval_mining_loop,
            args=(bitcoin_rpc, interval_secs, addr, stop_event),
        )
    thr.start()
    return MinerThread(thr, stop_event)


def interval_mining_loop(rpc: BitcoindClient, interval_secs, addr, stop_event: Event):
    """Mine one block every `interval_secs`"""
    while not stop_event.is_set():
        if stop_event.wait(timeout=interval_secs):
            break
        try:
            rpc.proxy.generatetoaddress(1, addr)
        except Exception as ex:
            logging.warning(f"{ex} while mining to {addr}; retrying next tick")


def on_demand_mining_loop(rpc: BitcoindClient, addr, stop_event: Event, trailing_blocks: int = 0):
    """Poll the mempool; when a tx is pending, mine one block plus `trailing_blocks`
    empty blocks to bury it. Mines nothing while the mempool is empty."""
    while not stop_event.is_set():
        if stop_event.wait(timeout=MEMPOOL_POLL_INTERVAL_SECS):
            break
        try:
            if not rpc.proxy.getrawmempool():
                continue  # nothing pending
            rpc.proxy.generatetoaddress(1 + trailing_blocks, addr)
        except Exception as ex:
            logging.warning(f"{ex} while mining to {addr}; retrying next tick")
