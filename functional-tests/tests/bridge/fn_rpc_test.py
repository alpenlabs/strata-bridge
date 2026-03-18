# Tests server can start correctly

import flexitest

from envs.base_test import StrataTestBase


@flexitest.register
class BridgeRpcTest(StrataTestBase):
    """
    Test that bridge RPC can retrieve bridge operators correctly.
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env("basic")

    def main(self, ctx: flexitest.RunContext):
        bridge_node = ctx.get_service("bridge_node")
        bridge_rpc = bridge_node.create_rpc()

        operators = bridge_rpc.stratabridge_bridgeOperators()
        self.logger.info(f"Bridge Operators: {operators}")
        assert len(operators) == 1

        return True
