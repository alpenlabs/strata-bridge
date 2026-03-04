import flexitest

from envs.base_test import StrataTestBase
from utils.deposit import wait_until_drt_recognized
from utils.dev_cli import DevCli
from utils.utils import read_operator_key


@flexitest.register
class DevCliDRTTest(StrataTestBase):
    """
    Test that a DRT from dev-cli is recognized by the bridge node
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env("basic")

    def main(self, ctx: flexitest.RunContext):
        bridge_node = ctx.get_service("bridge_node")
        bridge_rpc = bridge_node.create_rpc()

        bitcoind_service = ctx.get_service("bitcoin")
        bitcoind_props = bitcoind_service.props

        operators = bridge_rpc.stratabridge_bridgeOperators()
        musig2_keys = [read_operator_key(i).MUSIG2_KEY for i in range(len(operators))]

        dev_cli = DevCli(bitcoind_props, musig2_keys)
        drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted DRT: {drt_txid}")

        wait_until_drt_recognized(bridge_rpc, drt_txid)
