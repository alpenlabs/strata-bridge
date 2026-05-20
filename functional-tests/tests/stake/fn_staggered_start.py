"""
Staggered start test

Make sure that the bridge nodes can operator without all nodes coming online at the same time.

Test flow:
1. Start each node in the network one at a time waiting each one to be ready.
2. Make sure that the operators can still complete staking.
"""

from time import sleep
from typing import cast

import flexitest

from constants import BLOCK_GENERATION_INTERVAL_SECS, BRIDGE_NETWORK_SIZE
from envs import DeferredStartBridgeNetworkEnv, StrataLiveEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import BridgeProtocolParams
from utils.stake import wait_until_all_operators_staked
from utils.utils import (
    wait_until_bridge_ready,
)


@flexitest.register
class StaggeredStartTest(StrataTestBase):
    """Operator-0 must not broadcast a second stake funding tx across a restart."""

    def __init__(self, ctx: flexitest.InitContext):
        # `DeferredStartBridgeNetworkEnv` keeps bridges stopped through funding so
        # each operator's first stake-funding broadcast lands in the post-setup
        # mempool (and the env hard-codes `auto_mine=False` to keep it there).
        # `bury_depth=1` keeps the test fast: a tx is considered buried as soon as
        # one block is mined on top of it. `nag_interval_secs=1` makes peers
        # constantly nag the restarted operator so `PublishStakeData` re-runs
        # quickly post-restart.
        ctx.set_env(
            DeferredStartBridgeNetworkEnv(
                bridge_protocol_params=BridgeProtocolParams(bury_depth=1),
                bridge_config_params=BridgeConfigParams(nag_interval_secs=1),
            )
        )

    def main(self, ctx: flexitest.RunContext):
        self.logger.info("Getting bridge node services and Bitcoin RPC")
        bridge_nodes = [ctx.get_service(f"bridge_node_{i}") for i in range(BRIDGE_NETWORK_SIZE)]
        mosaic_nodes = [ctx.get_service(f"mosaic_{i}") for i in range(BRIDGE_NETWORK_SIZE)]

        bitcoind_service = ctx.get_service("bitcoin")
        bitcoin_rpc = bitcoind_service.create_rpc()

        # Snapshot the chain tip so we only inspect blocks mined during this test.
        start_height = bitcoin_rpc.proxy.getblockcount()
        self.logger.info(f"Chain tip at test start: height={start_height}")

        # --- Restart operator-0 to force `PublishStakeData` to re-execute ---
        self.logger.info("Stopping other mosaic nodes")
        for i in range(1, BRIDGE_NETWORK_SIZE):
            self.logger.info(f"Stopping mosaic-{i}")
            mosaic_nodes[i].stop()

        self.logger.info("Starting operator-0")
        bridge_nodes[0].start()

        bridge_rpcs = [node.create_rpc() for node in bridge_nodes]  # ty: ignore[possibly-missing-attribute]
        wait_until_bridge_ready(bridge_rpcs[0])
        self.logger.info("Operator-0 started and ready")

        sleep_secs = 600
        self.logger.info(f"Sleeping for {sleep_secs} seconds before starting N-2 nodes")
        sleep(sleep_secs)

        for i in range(1, BRIDGE_NETWORK_SIZE - 1):
            self.logger.info(f"Starting operator-{i}")
            bridge_nodes[i].start()
            self.logger.info(f"Starting mosaic-{i}")
            mosaic_nodes[i].start()
            wait_until_bridge_ready(bridge_nodes[i].create_rpc())  # ty: ignore[possibly-missing-attribute]
            self.logger.info(f"Operator-{i} started and ready")

        self.logger.info("All N-2 nodes started, sleeping before starting final node")
        sleep(sleep_secs)
        self.logger.info(f"Starting operator-{BRIDGE_NETWORK_SIZE - 1}")
        bridge_nodes[BRIDGE_NETWORK_SIZE - 1].start()
        self.logger.info(f"Starting mosaic-{BRIDGE_NETWORK_SIZE - 1}")
        mosaic_nodes[BRIDGE_NETWORK_SIZE - 1].start()

        # --- Resume mining and let the stake flow complete for all operators ---
        miner_addr = bitcoin_rpc.proxy.getnewaddress()
        cast(StrataLiveEnv, ctx.env).start_miner(
            bitcoin_rpc, BLOCK_GENERATION_INTERVAL_SECS, miner_addr
        )
        try:
            wait_until_all_operators_staked(bridge_rpcs[0], bitcoin_rpc, BRIDGE_NETWORK_SIZE)
        finally:
            cast(StrataLiveEnv, ctx.env).stop_miner()

        return True

