import flexitest

from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from rpc.types import RpcDepositStatusComplete, RpcDepositStatusInProgress
from utils.bridge import get_bridge_nodes_and_rpcs
from utils.deposit import wait_until_deposit_status, wait_until_drt_recognized
from utils.dev_cli import DevCli
from utils.network import wait_until_p2p_connected
from utils.utils import read_operator_key, wait_until_bridge_ready


# NOTE: (@Rajil1213) `flexitest` only recognizes modules that end with `Test`. The `-Disabled`
# suffix has been used to disable this test until `dev-cli` is updated to use the new
# DRT format recognized by ASM. See: https://github.com/alpenlabs/strata-bridge/pull/375.
@flexitest.register
class BridgeDepositTestDisabled(StrataTestBase):
    """
    Test that a deposit can be made and completed successfully in a bridge network environment.
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

        wait_until_deposit_status(bridge_rpc, deposit_id, RpcDepositStatusComplete)

        # Reuse environment to check if deposit goes through even if the operator nodes crash midway
        self.logger.info("Sending another DRT to test resilience against operator crashes")
        drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted DRT: {drt_txid}")

        new_deposit_id = wait_until_drt_recognized(bridge_rpc, drt_txid)

        self.logger.info("Crashing all operator nodes")
        for i in range(num_operators):
            self.logger.info(f"Stopping operator node {i}")
            bridge_nodes[i].stop()

        self.logger.info("Restarting nodes")
        for i in range(num_operators):
            self.logger.info(f"Restarting operator node {i}")
            bridge_nodes[i].start()
            wait_until_bridge_ready(bridge_rpcs[i])

        self.logger.info("Making sure deposit is still in progress after restarting nodes")
        wait_until_deposit_status(bridge_rpc, new_deposit_id, RpcDepositStatusInProgress)

        self.logger.info("Verifying P2P connectivity among bridge nodes before deposit")
        wait_until_p2p_connected(bridge_rpcs)

        self.logger.info("Waiting for deposit to complete after operator nodes restart")
        wait_until_deposit_status(bridge_rpc, new_deposit_id, RpcDepositStatusComplete)

        # Verify operator connectivity again
        # TODO: @MdTeach investigate why this fails in CI but passes locally
        self.logger.info("Verifying P2P connectivity among bridge nodes after deposit")
        wait_until_p2p_connected(bridge_rpcs)

        return True
