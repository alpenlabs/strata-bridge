from collections.abc import Iterator
from contextlib import contextmanager

import flexitest

from constants import BLOCK_GENERATION_INTERVAL_SECS
from utils.bitcoin import MinerThread, generate_blocks


class StrataLiveEnv(flexitest.LiveEnv):
    """LiveEnv with miner control exposed to tests via ctx.env."""

    def __init__(self, svcs, miner: MinerThread | None = None):
        super().__init__(svcs)
        self._miner = miner

    def stop_miner(self):
        if self._miner is not None:
            self._miner.stop()
            self._miner = None

    def start_miner(
        self,
        bitcoin_rpc,
        block_interval,
        addr,
        mine_on_demand: bool = False,
        trailing_blocks: int = 0,
    ):
        self.stop_miner()
        self._miner = generate_blocks(
            bitcoin_rpc,
            block_interval,
            addr,
            mine_on_demand=mine_on_demand,
            trailing_blocks=trailing_blocks,
        )

    @contextmanager
    def mining_paused(self, bitcoin_rpc, addr) -> Iterator[None]:
        """Pause block production for the duration of the block, resuming it afterwards."""
        self.stop_miner()
        yield
        self.start_miner(bitcoin_rpc, BLOCK_GENERATION_INTERVAL_SECS, addr)

    def shutdown(self):
        self.stop_miner()
        super().shutdown()
