import time

import flexitest

from utils.dev_cli import DevCli
from utils.utils import read_operator_key


@flexitest.register
class BridgeNetworkTest(flexitest.Test):
    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env("network")

    def main(self, ctx: flexitest.RunContext):
        num_operators = 3
        bridge_nodes = [ctx.get_service(f"bridge_node_{idx}") for idx in range(num_operators)]
        bridge_rpcs = [bridge_node.create_rpc() for bridge_node in bridge_nodes]

        # Verify operator connectivity
        wait_until_p2p_connected(bridge_rpcs, num_operators)

        # Test deposit
        bitcoind_service = ctx.get_service("bitcoin")
        bitcoind_props = bitcoind_service.props

        musig2_keys = [read_operator_key(i).MUSIG2_KEY for i in range(num_operators)]

        dev_cli = DevCli(bitcoind_props, musig2_keys)
        result = dev_cli.send_deposit_request()
        print(f"Deposit request result: {result}")

        bridge_rpc = bridge_rpcs[0]
        id = wait_until_first_deposit(bridge_rpc)

        wait_until_deposit_complete(bridge_rpc, id)

        return True


def wait_until_first_deposit(bridge_rpc, timeout=300):
    elapsed = 0
    while elapsed < timeout:
        time.sleep(10)
        elapsed += 10
        depositRequests = bridge_rpc.stratabridge_depositRequests()
        if len(depositRequests) >= 1:
            id = depositRequests[0]
            return id
    raise TimeoutError(f"Timeout after {timeout} seconds waiting for more than one deposit request")


def wait_until_deposit_complete(bridge_rpc, deposit_id, timeout=150):
    elapsed = 0
    while elapsed < timeout:
        deposit_info = bridge_rpc.stratabridge_depositInfo(deposit_id)
        print("current duties ", deposit_info)
        if deposit_info.get("status", {}).get("status") == "complete":
            return deposit_info
        time.sleep(10)
        elapsed += 10
    raise TimeoutError(f"Timeout after {timeout} seconds waiting for deposit to complete")


def wait_until_p2p_connected(bridge_rpcs, num_operators, timeout=300):
    elapsed = 0
    while elapsed < timeout:
        all_connected = True
        for bridge_index, rpc in enumerate(bridge_rpcs):
            operators = rpc.stratabridge_bridgeOperators()
            other_operators = [op for idx, op in enumerate(operators) if idx != bridge_index]
            for operator in other_operators:
                status = rpc.stratabridge_operatorStatus(operator)
                if status != "online":
                    print(f"Bridge {bridge_index}: Operator {operator} is {status}, waiting...")
                    all_connected = False
                    break

            if not all_connected:
                break

        if all_connected:
            print("All operators are connected and online")
            return

        time.sleep(10)
        elapsed += 10

    raise TimeoutError(f"Timeout after {timeout} seconds waiting for all operators to be online")
