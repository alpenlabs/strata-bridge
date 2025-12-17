import flexitest

from utils.utils import wait_until_bridge_ready


@flexitest.register
class BridgeNetworkTest(flexitest.Test):
    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env("network")

    def main(self, ctx: flexitest.RunContext):
        num_operators = 3
        bridge_rpcs = []
        
        # Initialize bridge RPC connections
        for i in range(num_operators):
            bridge_operator = ctx.get_service(f"bo_{i}")
            rpc = bridge_operator.create_rpc()
            wait_until_bridge_ready(rpc)
            bridge_rpcs.append(rpc)

        # Verify operator connectivity
        for bridge_index, rpc in enumerate(bridge_rpcs):
            operators = rpc.stratabridge_bridgeOperators()
            assert len(operators) == num_operators, (
                f"Expected {num_operators} operators, got {len(operators)}"
            )
            
            other_operators = [op for idx, op in enumerate(operators) if idx != bridge_index]
            for operator in other_operators:
                status = rpc.stratabridge_operatorStatus(operator)
                assert status == "online", (
                    f"Bridge {bridge_index}: Operator {operator} should be online but is {status}"
                )
        
        return True
