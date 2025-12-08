# Tests server can start correctly

import flexitest
from utils.utils import wait_until_bridge_ready


@flexitest.register
class BridgeRpcTest(flexitest.Test):
    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env("basic")

    def main(self, ctx: flexitest.RunContext):
        bo = ctx.get_service("bo")
        borpc = bo.create_rpc()
        wait_until_bridge_ready(borpc)

        operators = borpc.stratabridge_bridgeOperators()
        assert len(operators) == 1

        return True
