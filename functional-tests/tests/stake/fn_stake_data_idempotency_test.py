"""
Stake Data Idempotency Test

Verifies that operator-0 does not build a second stake funding transaction after
a crash + restart. The assertion is on-chain: every operator's reserved-wallet address
must receive exactly one funding tx, and operator-0's must match the txid first
seen in the mempool.

Test flow:
1. Bring up the bridge network with auto-mining disabled and a short bury depth.
   `nag_interval_secs=1` keeps peers constantly nagging the restarted operator so
   `PublishStakeData` re-runs quickly after restart.
2. Wait for each operator's funding tx to land in the mempool, identifying it by
   its output paying into the operator's reserved-wallet address.
3. Restart operator-0 to force `PublishStakeData` to re-execute.
4. Resume mining and wait for every operator's stake to reach `confirmed`.
5. Walk every block mined during the test and count funding-tx outputs paying
   into each operator's reserved-wallet address. Assert exactly one per operator and
   that operator-0's funding txid is unchanged.
"""

from typing import cast

import flexitest

from constants import BLOCK_GENERATION_INTERVAL_SECS, BRIDGE_NETWORK_SIZE
from envs import DeferredStartBridgeNetworkEnv, StrataLiveEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import BridgeProtocolParams
from utils.stake import wait_until_all_operators_staked
from utils.utils import (
    find_block_txs_paying_to_address,
    find_mempool_txs_paying_to_address,
    wait_until,
    wait_until_bridge_ready,
)


@flexitest.register
class StakeDataIdempotencyTest(StrataTestBase):
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
        bridge_nodes = [ctx.get_service(f"bridge_node_{i}") for i in range(BRIDGE_NETWORK_SIZE)]
        # `Service` is the static type; concrete bridge-node services attach `create_rpc`.
        bridge_rpcs = [node.create_rpc() for node in bridge_nodes]  # ty: ignore[possibly-missing-attribute]
        reserved_addresses = [node.props["reserved_wallet_address"] for node in bridge_nodes]

        bitcoind_service = ctx.get_service("bitcoin")
        bitcoin_rpc = bitcoind_service.create_rpc()

        # Snapshot the chain tip so we only inspect blocks mined during this test.
        start_height = bitcoin_rpc.proxy.getblockcount()

        # --- Wait for every operator to broadcast its stake funding tx ---
        initial_funding_txids = self._wait_for_funding_txids(bitcoin_rpc, reserved_addresses)
        self.logger.info(
            f"Initial funding txids by reserved-wallet address: {initial_funding_txids}"
        )

        # --- Restart operator-0 to force `PublishStakeData` to re-execute ---
        self.logger.info("Restarting operator-0")
        bridge_nodes[0].stop()
        bridge_nodes[0].start()
        wait_until_bridge_ready(bridge_rpcs[0])
        self.logger.info("Operator-0 restarted and ready")

        # --- Resume mining and let the stake flow complete for all operators ---
        miner_addr = bitcoin_rpc.proxy.getnewaddress()
        cast(StrataLiveEnv, ctx.env).start_miner(
            bitcoin_rpc, BLOCK_GENERATION_INTERVAL_SECS, miner_addr
        )
        try:
            wait_until_all_operators_staked(bridge_rpcs[0], bitcoin_rpc, BRIDGE_NETWORK_SIZE)
        finally:
            cast(StrataLiveEnv, ctx.env).stop_miner()

        # --- Verify on-chain: exactly one funding tx per operator reserved-wallet address ---
        for idx, addr in enumerate(reserved_addresses):
            mined = find_block_txs_paying_to_address(bitcoin_rpc, addr, start_height + 1)
            assert len(mined) == 1, (
                f"operator-{idx} reserved-wallet address {addr} received "
                f"{len(mined)} funding txs (expected 1): {mined}"
            )
            assert mined[0] == initial_funding_txids[addr], (
                f"operator-{idx} funding txid changed across the restart: "
                f"originally seen in mempool as {initial_funding_txids[addr]}, "
                f"confirmed on-chain as {mined[0]}"
            )

        self.logger.info(
            "IDEMPOTENCY VERIFIED: each operator's reserved-wallet address received exactly "
            "one funding tx, and operator-0's matches the pre-restart mempool entry"
        )
        return True

    def _wait_for_funding_txids(self, bitcoin_rpc, reserved_addresses: list[str]) -> dict[str, str]:
        """Wait for the mempool to contain a funding tx for each reserved-wallet address and return
        a mapping from address to the txid that pays into it."""
        per_addr: dict[str, str] = {}

        def check():
            for addr in reserved_addresses:
                if addr in per_addr:
                    continue
                matches = find_mempool_txs_paying_to_address(bitcoin_rpc, addr)
                if matches:
                    per_addr[addr] = matches[0]
            return len(per_addr) == len(reserved_addresses)

        wait_until(
            check,
            timeout=180,
            error_msg="Not all operators broadcast their initial stake funding tx",
        )
        return per_addr
