import time

import flexitest

from utils.dev_cli import DevCli


@flexitest.register
class BridgeNetworkTest(flexitest.Test):
    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env("network")

    def main(self, ctx: flexitest.RunContext):
        num_operators = 3
        bridge_rpcs = initialize_bridge_rpcs(ctx, num_operators)

        # Verify operator connectivity
        wait_until_p2p_connected(bridge_rpcs, num_operators)

        # Test deposit
        bitcoind_service = ctx.get_service("bitcoin")
        bitcoind_props = bitcoind_service.props

        musig2_keys = [
            "ac407ba319846e25d69c1c0cb2a845ab75ef93ad2e9e846cdc5cf6da766e00b2",
            "c8200b381f7dd57f4c474d2bea56747fdfba32f2d20463f4269a1cf06a1acd77",
            "ae12cceeee9d4888766b1abb0531f8c66c0629bfc4fabe97e3c0d5d9b4dd3fd7",
        ]

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
            print("Abishek got id ", id)
            return id
    raise TimeoutError(f"Timeout after {timeout} seconds waiting for more than one deposit request")


def wait_until_deposit_complete(bridge_rpc, deposit_id, timeout=150):
    elapsed = 0
    while elapsed < timeout:
        deposit_info = bridge_rpc.stratabridge_depositInfo(deposit_id)
        print("now duties ", deposit_info)
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


def initialize_bridge_rpcs(ctx, num_operators):
    bridge_rpcs = []
    for i in range(num_operators):
        bridge_operator = ctx.get_service(f"bo_{i}")
        rpc = bridge_operator.create_rpc()
        bridge_rpcs.append(rpc)
    return bridge_rpcs
