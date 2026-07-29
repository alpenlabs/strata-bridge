import logging
import time
from dataclasses import dataclass
from threading import Event, Thread

from bitcoinlib.services.bitcoind import BitcoindClient

from constants import MEMPOOL_POLL_INTERVAL_SECS

# Pause after each block generated during a reorg so ZMQ subscribers process the
# disconnect/connect events in order.
ZMQ_SETTLE_SECS = 0.25


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


def interval_mining_loop(rpc: BitcoindClient, interval_secs, addr, stop_event: Event, mine=None):
    """Every `interval_secs`, call `mine` (default: mine one block to `addr`)."""
    mine = mine or (lambda: rpc.proxy.generatetoaddress(1, addr))
    while not stop_event.is_set():
        if stop_event.wait(timeout=interval_secs):
            break
        try:
            mine()
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


def mine_block_excluding(rpc: BitcoindClient, addr: str, exclude_txids: set[str]) -> str:
    """Mine one block containing every mempool tx except `exclude_txids` and their
    in-mempool descendants, and return its hash.

    Uses `generateblock` with an explicit tx list; never `generatetoaddress`, which would
    blindly confirm the excluded txs.
    """
    mempool = rpc.proxy.getrawmempool(True)

    excluded = set(exclude_txids)
    frontier = [txid for txid in excluded if txid in mempool]
    while frontier:
        for child in mempool[frontier.pop()].get("spentby", []):
            if child not in excluded:
                excluded.add(child)
                frontier.append(child)

    # Ancestors must precede descendants within the block.
    included = sorted(
        (txid for txid in mempool if txid not in excluded),
        key=lambda txid: mempool[txid]["ancestorcount"],
    )
    return rpc.proxy.generateblock(addr, included)["hash"]


def generate_blocks_excluding(
    bitcoin_rpc: BitcoindClient,
    interval_secs,
    addr: str,
    exclude_txids: set[str],
) -> MinerThread:
    """Interval miner that keeps `exclude_txids` (and their descendants) out of every block."""
    excluded = set(exclude_txids)  # snapshot so caller-side mutation can't race the miner thread
    stop_event = Event()
    thr = Thread(
        target=interval_mining_loop,
        args=(bitcoin_rpc, interval_secs, addr, stop_event),
        kwargs={"mine": lambda: mine_block_excluding(bitcoin_rpc, addr, excluded)},
    )
    thr.start()
    return MinerThread(thr, stop_event)


@dataclass(frozen=True)
class ReorgResult:
    fork_height: int
    old_tip_height: int
    new_tip_hash: str
    excluded: set[str]  # full exclusion closure: the seed txids + everything spending them


def reorg_excluding(
    rpc: BitcoindClient,
    addr: str,
    invalidate_hash: str,
    exclude_txids: set[str],
    extra_blocks: int,
) -> ReorgResult:
    """Replace the chain from `invalidate_hash` (inclusive) to the tip with a strictly
    longer fork that replays the same transactions minus `exclude_txids` and everything
    that (transitively) spends them.

    Each original block's surviving txs are replayed at their original height so relative
    timelocks (BIP68/CSV) between them keep the exact spacing they confirmed with. Raw tx
    hexes are passed to `generateblock` directly, so the rebuild does not depend on the
    mempool re-accepting the disconnected txs.
    """
    fork_height = rpc.proxy.getblock(invalidate_hash)["height"]
    old_tip_height = rpc.proxy.getblockcount()

    # Snapshot the doomed blocks: per height, each non-coinbase tx with its input txids.
    per_height = []
    for height in range(fork_height, old_tip_height + 1):
        block = rpc.proxy.getblock(rpc.proxy.getblockhash(height), 2)
        txs = [
            (tx["txid"], tx["hex"], {vin.get("txid") for vin in tx.get("vin", [])})
            for tx in block["tx"][1:]
        ]
        per_height.append((height, txs))

    # Exclusion closure: the seed txids plus, in chain order, every tx spending the closure.
    excluded = set(exclude_txids)
    for _, txs in per_height:
        for txid, _, input_txids in txs:
            if txid not in excluded and input_txids & excluded:
                excluded.add(txid)

    rpc.proxy.invalidateblock(invalidate_hash)

    for height, txs in per_height:
        kept = [raw for txid, raw, _ in txs if txid not in excluded]
        rpc.proxy.generateblock(addr, kept)
        logging.info(f"replayed height {height} with {len(kept)}/{len(txs)} txs")
        time.sleep(ZMQ_SETTLE_SECS)

    for _ in range(extra_blocks):
        mine_block_excluding(rpc, addr, excluded)
        time.sleep(ZMQ_SETTLE_SECS)

    return ReorgResult(fork_height, old_tip_height, rpc.proxy.getbestblockhash(), excluded)
