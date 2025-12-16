import flexitest

from utils.utils import wait_until_bridge_ready


@flexitest.register
class BridgeRpcTest(flexitest.Test):
    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env("network")

    def main(self, ctx: flexitest.RunContext):
        for i in range(3):
            bo = ctx.get_service(f"bo_{i}")
            borpc = bo.create_rpc()
            wait_until_bridge_ready(borpc)
            operators = borpc.stratabridge_bridgeOperators()
            assert len(operators) == 3

        return True
