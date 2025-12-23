# Tests server can start correctly

import flexitest
from envs.base_test import StrataTestBase



@flexitest.register
class BridgeRpcTest(StrataTestBase):
    def __init__(self, ctx: flexitest.InitContext):
        print("Abishek: Setting up BridgeRpcTest ", ctx, dir(ctx))
        ctx.set_env("basic")

    def main(self, ctx: flexitest.RunContext):
        bridge_node = ctx.get_service("bridge_node")
        bridge_rpc = bridge_node.create_rpc()

        operators = bridge_rpc.stratabridge_bridgeOperators()
        assert len(operators) == 1

        return True
