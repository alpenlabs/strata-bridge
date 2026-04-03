import flexitest

from utils import generate_blocks
from utils.utils import MinerThread


class StrataLiveEnv(flexitest.LiveEnv):
    """LiveEnv with miner control exposed to tests via ctx.env."""

    def __init__(self, svcs, miner: MinerThread | None = None):
        super().__init__(svcs)
        self._miner = miner

    def stop_miner(self):
        if self._miner is not None:
            self._miner.stop()
            self._miner = None

    def start_miner(self, bitcoin_rpc, block_interval, addr):
        self.stop_miner()
        self._miner = generate_blocks(bitcoin_rpc, block_interval, addr)

    def shutdown(self):
        self.stop_miner()
        super().shutdown()
