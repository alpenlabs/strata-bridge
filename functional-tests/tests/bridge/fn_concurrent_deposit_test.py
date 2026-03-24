import flexitest

from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.config_cfg import BridgeConfigParams
from rpc.types import RpcDepositStatusComplete
from utils.bridge import get_bridge_nodes_and_rpcs
from utils.deposit import wait_until_deposit_status, wait_until_drts_recognized
from utils.dev_cli import DevCli
from utils.utils import read_operator_key

# Higher burial depth makes sequential processing more apparent
TEST_BURY_DEPTH = 20

# If sequential: each new publish starts only after previous tx is buried,
# so consecutive mined-height gaps should be >= bury_depth.
# If concurrent: at least one pair should have mined-height gap < bury_depth.
BURIAL_GAP_BLOCKS = TEST_BURY_DEPTH


def get_tx_block_height(bitcoin_rpc, txid: str) -> int | None:
    """Get the block height where a transaction was mined, or None if unconfirmed."""
    try:
        tx_info = bitcoin_rpc.proxy.getrawtransaction(txid, True)
        if "blockhash" in tx_info:
            block_info = bitcoin_rpc.proxy.getblock(tx_info["blockhash"])
            return block_info["height"]
    except Exception:
        pass
    return None


def compute_consecutive_height_gaps(heights: list[int]) -> list[int]:
    """
    Compute gaps in blocks between consecutive heights (in DRT submission order).

    Returns a list of gaps in block heights.
    """
    if len(heights) < 2:
        return []
    return [heights[i + 1] - heights[i] for i in range(len(heights) - 1)]


@flexitest.register
class ConcurrentDepositTest(StrataTestBase):
    """
    Test that multiple DRTs are processed concurrently rather than burial-gated sequentially.

    Validation metric: mined block-height gaps among deposit txs.
    - If sequential: every consecutive height gap is >= bury_depth.
    - If concurrent: at least one consecutive height gap is < bury_depth.
    """

    def __init__(self, ctx: flexitest.InitContext):
        # Use higher burial depth to make sequential processing more apparent
        bridge_config = BridgeConfigParams(bury_depth=TEST_BURY_DEPTH)
        ctx.set_env(BridgeNetworkEnv(bridge_config_params=bridge_config))

    def main(self, ctx: flexitest.RunContext):
        CONCURRENT_DRT_COUNT = 3

        bridge_nodes, bridge_rpcs = get_bridge_nodes_and_rpcs(ctx)

        bitcoind_service = ctx.get_service("bitcoin")
        bitcoind_props = bitcoind_service.props
        bitcoin_rpc = bitcoind_service.create_rpc()

        num_operators = len(bridge_nodes)
        musig2_keys = [read_operator_key(i).MUSIG2_KEY for i in range(num_operators)]

        dev_cli = DevCli(bitcoind_props, musig2_keys)
        bridge_rpc = bridge_rpcs[0]

        # Send multiple DRTs simultaneously
        self.logger.info(f"Broadcasting {CONCURRENT_DRT_COUNT} DRTs")
        drt_txids = [dev_cli.send_deposit_request() for _ in range(CONCURRENT_DRT_COUNT)]

        for i, drt_txid in enumerate(drt_txids):
            self.logger.info(f"Broadcasted DRT {i + 1}: {drt_txid}")

        # Wait for all DRTs to be recognized
        self.logger.info("Waiting for all DRTs to be recognized")
        wait_until_drts_recognized(bridge_rpc, drt_txids, timeout=180)

        # Wait for deposits to complete and collect deposit txids
        self.logger.info("Waiting for all deposits to complete")
        deposit_txids = []
        for drt_txid in drt_txids:
            deposit_info = wait_until_deposit_status(
                bridge_rpc,
                drt_txid,
                RpcDepositStatusComplete,
                timeout=600,
            )
            deposit_txid = deposit_info.get("status").get("deposit_txid")
            if deposit_txid:
                deposit_txids.append(deposit_txid)
                self.logger.info(f"Deposit completed: DRT {drt_txid} -> DT {deposit_txid}")

        assert len(deposit_txids) == CONCURRENT_DRT_COUNT, (
            f"Expected {CONCURRENT_DRT_COUNT} deposit txids, got {len(deposit_txids)}"
        )

        # Primary validation: block-height gaps
        self.logger.info("Validating mined block-height gaps for deposit transactions")
        block_heights = []
        for deposit_txid in deposit_txids:
            height = get_tx_block_height(bitcoin_rpc, deposit_txid)
            assert height is not None, (
                f"Deposit TX {deposit_txid} is not mined or block height unavailable"
            )
            block_heights.append(height)
            self.logger.info(f"Deposit TX {deposit_txid} mined at block {height}")

        gaps = compute_consecutive_height_gaps(block_heights)
        assert len(gaps) == CONCURRENT_DRT_COUNT - 1, (
            f"Expected {CONCURRENT_DRT_COUNT - 1} consecutive height gaps, got {len(gaps)}"
        )

        min_height = min(block_heights)
        max_height = max(block_heights)
        height_spread = max_height - min_height
        min_gap = min(gaps)

        self.logger.info(
            f"Block height spread: {height_spread} blocks "
            f"(min={min_height}, max={max_height}), consecutive gaps={gaps}, min_gap={min_gap}"
        )

        assert min_gap < BURIAL_GAP_BLOCKS, (
            f"Minimum consecutive deposit height gap ({min_gap} blocks) >= burial gap "
            f"({BURIAL_GAP_BLOCKS} blocks). This indicates burial-gated sequential behavior: "
            f"no deposit was mined before the previous one had enough confirmations "
            f"to be treated as buried."
        )

        self.logger.info("Concurrent deposit validation passed!")
        return True
