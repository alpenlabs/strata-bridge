import flexitest

from utils import (
    BLOCK_GENERATION_INTERVAL_SECS,
    generate_blocks,
    wait_until_bitcoind_ready,
)
from utils.utils import read_operator_key


class BasicEnv(flexitest.EnvConfig):
    """Environment running a single bridge operator connected to S2 instance and a Bitcoin node."""

    def __init__(self):
        super().__init__()

    def init(self, ectx: flexitest.EnvContext) -> flexitest.LiveEnv:
        svcs = {}

        btc_fac = ectx.get_factory("bitcoin")
        s2_fac = ectx.get_factory("s2")
        bo_fac = ectx.get_factory("bofac")

        # TODO: @MdTeach make random seed for each operator and derive relevant keys
        # Get operator key for first operator (OP1)
        operator_key = read_operator_key(0)

        s2 = s2_fac.create_s2_service("s2_op1", operator_key)
        svcs["s2"] = s2

        bitcoind = btc_fac.create_regtest_bitcoin()
        brpc = bitcoind.create_rpc()
        wait_until_bitcoind_ready(brpc, timeout=10)

        # create new wallet
        brpc.proxy.createwallet(bitcoind.get_prop("walletname"))
        wallet_addr = brpc.proxy.getnewaddress()

        # mine 101 blocks to have some usable funds
        brpc.proxy.generatetoaddress(101, wallet_addr)

        # automie blocks
        generate_blocks(
            brpc,
            BLOCK_GENERATION_INTERVAL_SECS,
            wallet_addr,
        )
        svcs["bitcoin"] = bitcoind

        # run the bridge
        bo = bo_fac.create_server("bridge_1", bitcoind.props, s2.props, operator_key)
        svcs["bo"] = bo

        # fund operator wallet
        sc_wallet_address = bo.get_prop("sc_wallet_address")
        general_wallet_address = bo.get_prop("general_wallet_address")
        brpc.proxy.sendtoaddress(sc_wallet_address, 5.01)
        brpc.proxy.sendtoaddress(general_wallet_address, 5.01)

        # wait few blocks for finalization
        brpc.proxy.generatetoaddress(10, wallet_addr)

        return flexitest.LiveEnv(svcs)
