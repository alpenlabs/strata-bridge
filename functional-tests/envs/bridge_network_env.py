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
        svcs = {}

        btc_fac = ectx.get_factory("bitcoin")
        s2_fac = ectx.get_factory("s2")
        bo_fac = ectx.get_factory("bofac")

        # TODO: @MdTeach make random seed for each operator and derive relevant keys
        op1 = read_operator_key(0)
        op2 = read_operator_key(1)
        op3 = read_operator_key(2)


        s2_1 = s2_fac.create_s2_service("s2_op1", op1)
        s2_2 = s2_fac.create_s2_service("s2_op2", op2)
        s2_3 = s2_fac.create_s2_service("s2_op3", op3)
        svcs["s2_1"] = s2_1
        svcs["s2_2"] = s2_2
        svcs["s2_3"] = s2_3


