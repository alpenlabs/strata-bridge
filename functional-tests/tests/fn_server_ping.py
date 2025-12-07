# Tests server can start correctly

import flexitest
import time


@flexitest.register
class Test(flexitest.Test):
    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env("basic")

    def main(self, ctx: flexitest.RunContext):
        bo = ctx.get_service("bo")
        time.sleep(6)
        borpc = bo.create_rpc()

        operators = borpc.stratabridge_bridgeOperators()
        operator = operators[0]

        op_info = borpc.stratabridge_operatorStatus(operator)
        print("op info: ", op_info)

        return True
