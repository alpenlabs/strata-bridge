import flexitest

from utils import (
    BLOCK_GENERATION_INTERVAL_SECS,
    generate_blocks,
    wait_until_bitcoind_ready,
)
from utils.utils import read_operator_key


class BridgeNetworkEnv(flexitest.EnvConfig):
    """Environment running a single bridge operator connected to S2 instance and a Bitcoin node."""

    def __init__(self):
        super().__init__()

    def init(self, ectx: flexitest.EnvContext) -> flexitest.LiveEnv:
        op1 = read_operator_key(0)
        op2 = read_operator_key(0)
        op3 = read_operator_key(0)
