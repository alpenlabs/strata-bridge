import flexitest
from utils import (
    generate_blocks,
    BLOCK_GENERATION_INTERVAL_SECS,
    wait_until_bitcoind_ready,
)


class BasicEnv(flexitest.EnvConfig):
    """Environment that just inits some number of clients and servers."""

    def __init__(self):
        super().__init__()

    def init(self, ectx: flexitest.EnvContext) -> flexitest.LiveEnv:
        svcs = {}

        btc_fac = ectx.get_factory("bitcoin")
        s2_fac = ectx.get_factory("s2")
        bo_fac = ectx.get_factory("bofac")

        s2 = s2_fac.create_s2_service()
        svcs["s2"] = s2

        bitcoind = btc_fac.create_regtest_bitcoin()
        brpc = bitcoind.create_rpc()
        wait_until_bitcoind_ready(brpc, timeout=10)

        # mine 101 blocks to have some usable funds
        brpc.proxy.generatetoaddress(
            101, "bcrt1pz3lhscydysketvdtdw57320wqeflea8avz3vwxvhlg64cse558lqkyycgz"
        )

        # automie blocks
        generate_blocks(
            brpc,
            BLOCK_GENERATION_INTERVAL_SECS,
            "bcrt1pz3lhscydysketvdtdw57320wqeflea8avz3vwxvhlg64cse558lqkyycgz",
        )
        svcs["bitcoin"] = bitcoind

        # run the bridge
        bo = bo_fac.create_server("bridge")
        svcs["bo"] = bo
        return flexitest.LiveEnv(svcs)
