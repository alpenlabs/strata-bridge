import flexitest

from constants import BRIDGE_NETWORK_SIZE
from utils.dev_cli import DevCli
from utils.network import wait_until_p2p_connected
from utils.utils import read_operator_key, wait_until


@flexitest.register
class BridgeNetworkTest(flexitest.Test):
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
        print(f"Deposit request result: {result}")

        bridge_rpc = bridge_rpcs[0]
        wait_until_first_drt_recognized(bridge_rpc)

        import time

        time.sleep(2)

        return True


def wait_until_first_drt_recognized(bridge_rpc, timeout=300):
    result = {"deposit_id": None}

    def check_drt_recognized():
        depositRequests = bridge_rpc.stratabridge_depositRequests()
        if len(depositRequests) >= 1:
            result["deposit_id"] = depositRequests[0]
            return True
        return False

    wait_until(
        check_drt_recognized,
        timeout=timeout,
        step=10,
        error_msg=f"Timeout after {timeout} seconds waiting for deposit request to be recognized",
    )

    return result["deposit_id"]


def wait_until_deposit_complete(bridge_rpc, deposit_id, timeout=300):
    result = {"deposit_info": None}

    def check_deposit_complete():
        result["deposit_info"] = bridge_rpc.stratabridge_depositInfo(deposit_id)
        print("current duties ", result["deposit_info"])
        return result["deposit_info"].get("status", {}).get("status") == "complete"

    wait_until(
        check_deposit_complete,
        timeout=timeout,
        step=10,
        error_msg=f"Timeout after {timeout} seconds waiting for deposit to complete",
    )

    return result["deposit_info"]
