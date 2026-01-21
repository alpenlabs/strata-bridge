import flexitest

from constants import BRIDGE_NETWORK_SIZE
from envs.base_test import StrataTestBase
from utils.dev_cli import DevCli
from utils.network import wait_until_p2p_connected
from utils.utils import read_operator_key, wait_until, wait_until_bridge_ready


@flexitest.register
class BridgeDepositTest(StrataTestBase):
    """
    Test that a deposit can be made and completed successfully in a bridge network environment.
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env("network")

    def main(self, ctx: flexitest.RunContext):
        num_operators = BRIDGE_NETWORK_SIZE
        bridge_nodes = [ctx.get_service(f"bridge_node_{idx}") for idx in range(num_operators)]
        bridge_rpcs = [bridge_node.create_rpc() for bridge_node in bridge_nodes]

        # Verify operator connectivity
        wait_until_p2p_connected(bridge_rpcs)

        # Test deposit
        bitcoind_service = ctx.get_service("bitcoin")
        bitcoind_props = bitcoind_service.props

        musig2_keys = [read_operator_key(i).MUSIG2_KEY for i in range(num_operators)]

        dev_cli = DevCli(bitcoind_props, musig2_keys)
        result = dev_cli.send_deposit_request()
        self.logger.debug(f"Deposit request result: {result}")

        bridge_rpc = bridge_rpcs[0]
        id = self.wait_until_first_drt_recognized(bridge_rpc)

        self.wait_until_deposit_complete(bridge_rpc, id)

        # again
        print("doing 2nd depsit")
        result = dev_cli.send_deposit_request()
        self.logger.debug(f"Deposit request result: {result}")

        bridge_rpc = bridge_rpcs[0]
        id = self.wait_until_first_drt_recognized_2(bridge_rpc)

        self.logger.info("Crashing all operator nodes")
        for i in range(num_operators):
            self.logger.info(f"Stopping operator node {i}")
            bridge_nodes[i].stop()

        self.logger.info("Restarting nodes")
        for i in range(num_operators):
            self.logger.info(f"Restarting operator node {i}")
            bridge_nodes[i].start()
            wait_until_bridge_ready(bridge_rpcs[i])

        self.wait_until_deposit_complete(bridge_rpc, id)

        # Verify operator connectivity
        print("p2p restart")
        wait_until_p2p_connected(bridge_rpcs)
        self.logger.info("Connected with all peers")
        print("Connected with all peers")

        return True

    def wait_until_first_drt_recognized(self, bridge_rpc, timeout=300):
        result = {"deposit_id": None}

        def check_drt_recognized():
            depositRequests = bridge_rpc.stratabridge_depositRequests()
            self.logger.info(f"Current deposit requests: {depositRequests}")
            if len(depositRequests) >= 1:
                result["deposit_id"] = depositRequests[0]
                return True
            return False

        wait_until(
            check_drt_recognized,
            timeout=timeout,
            step=10,
            error_msg=f"Timeout after {timeout} seconds waiting for DRT to be recognized",
        )

        return result["deposit_id"]

    def wait_until_first_drt_recognized_2(self, bridge_rpc, timeout=300):
        result = {"deposit_id": None}

        def check_drt_recognized():
            depositRequests = bridge_rpc.stratabridge_depositRequests()
            self.logger.info(f"Current deposit requests: {depositRequests}")
            if len(depositRequests) >= 2:
                result["deposit_id"] = depositRequests[1]
                return True
            return False

        wait_until(
            check_drt_recognized,
            timeout=timeout,
            step=10,
            error_msg=f"Timeout after {timeout} seconds waiting for DRT to be recognized",
        )

        return result["deposit_id"]

    def wait_until_deposit_complete(self, bridge_rpc, deposit_id, timeout=300):
        result = {"deposit_info": None}

        def check_deposit_complete():
            result["deposit_info"] = bridge_rpc.stratabridge_depositInfo(deposit_id)
            self.logger.info(f"Deposit info for {deposit_id}: {result['deposit_info']}")
            return result["deposit_info"].get("status", {}).get("status") == "complete"

        wait_until(
            check_deposit_complete,
            timeout=timeout,
            step=10,
            error_msg=f"Timeout after {timeout} seconds waiting for deposit to complete",
        )

        return result["deposit_info"]
