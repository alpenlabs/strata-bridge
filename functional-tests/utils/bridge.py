from constants import BRIDGE_NETWORK_SIZE
from utils.network import wait_until_p2p_connected


def get_bridge_nodes_and_rpcs(ctx, num_operators=BRIDGE_NETWORK_SIZE):
    """Get bridge nodes and their RPC clients for the network."""
    bridge_nodes = [ctx.get_service(f"bridge_node_{idx}") for idx in range(num_operators)]
    bridge_rpcs = [bridge_node.create_rpc() for bridge_node in bridge_nodes]

    # Verify operator connectivity
    wait_until_p2p_connected(bridge_rpcs)

    return bridge_nodes, bridge_rpcs
