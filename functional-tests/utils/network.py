import logging

from utils.utils import wait_until


def wait_until_p2p_connected(bridge_rpcs, timeout=300):
    """Wait until all bridge operators are connected in p2p network"""

    def check_all_connected():
        for bridge_index, rpc in enumerate(bridge_rpcs):
            operators = rpc.stratabridge_bridgeOperators()
            other_operators = [op for idx, op in enumerate(operators) if idx != bridge_index]
            for operator in other_operators:
                status = rpc.stratabridge_operatorStatus(operator)
                if status != "online":
                    logging.debug(
                        f"Bridge {bridge_index}: Operator {operator} is {status} waiting..."
                    )
                    return False
        logging.info("All operators are connected and online")
        return True

    wait_until(
        check_all_connected,
        timeout=timeout,
        step=10,
        error_msg=f"Timeout after {timeout} seconds waiting for all operators to be online",
    )
