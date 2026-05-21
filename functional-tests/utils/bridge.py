import logging

from constants import BRIDGE_NETWORK_SIZE
from utils.network import wait_until_p2p_connected
from utils.stake import wait_until_all_operators_staked


def get_bridge_nodes_and_rpcs(ctx, num_operators=BRIDGE_NETWORK_SIZE, stake_timeout=600):
    """Get bridge nodes and their RPC clients for the network.

    `stake_timeout` bounds the wait for every operator's stake to confirm on-chain;
    raise it for slow-cadence runs (e.g. SP1 proving mode mines on a 3-minute block
    interval, so stake confirmation takes far longer than the default 600s).
    """
    bridge_nodes = [ctx.get_service(f"bridge_node_{idx}") for idx in range(num_operators)]
    bridge_rpcs = [bridge_node.create_rpc() for bridge_node in bridge_nodes]

    # Verify operator connectivity
    wait_until_p2p_connected(bridge_rpcs)

    bitcoind_service = ctx.get_service("bitcoin")
    bitcoin_rpc = bitcoind_service.create_rpc()

    logging.info("Waiting for all operators to complete staking")
    wait_until_all_operators_staked(
        bridge_rpcs[0], bitcoin_rpc, expected_operator_count=num_operators, timeout=stake_timeout
    )

    return bridge_nodes, bridge_rpcs
