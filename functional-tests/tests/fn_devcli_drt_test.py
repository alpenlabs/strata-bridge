import flexitest

from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from utils.deposit import wait_until_drt_recognized
from utils.dev_cli import DevCli
from utils.utils import read_operator_key
from utils.bridge import get_bridge_nodes_and_rpcs


@flexitest.register
class DevCliDRTTest(StrataTestBase):
    """
    Test that a DRT from dev-cli is recognized by the bridge node
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(BridgeNetworkEnv())

    def main(self, ctx: flexitest.RunContext):
        bridge_nodes, bridge_rpcs = get_bridge_nodes_and_rpcs(ctx)

        # Test deposit
        bitcoind_service = ctx.get_service("bitcoin")
        bitcoind_props = bitcoind_service.props

        num_operators = len(bridge_nodes)
        musig2_keys = [read_operator_key(i).MUSIG2_KEY for i in range(num_operators)]

        dev_cli = DevCli(bitcoind_props, musig2_keys)
        drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted DRT: {drt_txid}")

        bridge_rpc = bridge_rpcs[0]
        deposit_id = wait_until_drt_recognized(bridge_rpc, drt_txid)
        print("deposit is recognized...", deposit_id)
