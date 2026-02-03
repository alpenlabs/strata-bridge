import flexitest

from envs.base_test import StrataTestBase
from rpc.asm_types import AsmWorkerStatus, AssignmentEntry
from utils.utils import wait_until, wait_until_bitcoind_ready


@flexitest.register
class AsmBlockProcessingTest(StrataTestBase):
    """
    Test that the ASM binary is working properly by verifying:
    1. ASM service starts and is responsive
    2. ASM processes Bitcoin blocks
    3. ASM progresses with new L1 blocks via getStatus
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env("basic")

    def main(self, ctx: flexitest.RunContext):
        # Get services
        bitcoind_service = ctx.get_service("bitcoin")
        asm_service = ctx.get_service("asm_rpc")

        bitcoin_rpc = bitcoind_service.create_rpc()
        asm_rpc = asm_service.create_rpc()

        # Wait for Bitcoin to be ready
        wait_until_bitcoind_ready(bitcoin_rpc, timeout=30)
        self.logger.info("Bitcoin node is ready")

        # Wait for ASM to be responsive
        self.wait_until_asm_ready(asm_rpc)
        self.logger.info("ASM RPC service is ready")

        # Get initial status
        initial_status = AsmWorkerStatus.from_dict(asm_rpc.strata_asm_getStatus())
        self.logger.info(f"ASM status: {initial_status.cur_block}")

        # Get initial block count from Bitcoin
        initial_btc_height = bitcoin_rpc.proxy.getblockcount()
        self.logger.info(f"Initial Bitcoin block height: {initial_btc_height}")

        # Generate blocks to ensure ASM has something to process
        wallet_addr = bitcoin_rpc.proxy.getnewaddress()
        NUM_BLOCKS_TO_GENERATE = 10
        self.logger.info(f"Generating {NUM_BLOCKS_TO_GENERATE} blocks")
        bitcoin_rpc.proxy.generatetoaddress(NUM_BLOCKS_TO_GENERATE, wallet_addr)

        new_btc_height = bitcoin_rpc.proxy.getblockcount()
        self.logger.info(f"New Bitcoin block height: {new_btc_height}")

        # Wait for ASM to progress past its initial height
        latest_asm_height = self.wait_until_asm_progresses(
            asm_rpc,
            initial_height=initial_status.cur_block.height,
        )
        self.logger.info(f"ASM has progressed to height {latest_asm_height}")

        # Verify the assignments RPC works at the latest ASM block (may be empty).
        # IMPORTANT: the blkid in getStatus is in internal byte order, while the
        # RPC expects Bitcoin display byte order. Use bitcoind's blockhash here.
        latest_btc_block_hash = bitcoin_rpc.proxy.getblockhash(latest_asm_height)
        self.logger.info(
            f"Bitcoin block hash at ASM height {latest_asm_height}: {latest_btc_block_hash}"
        )
        assignments: list[AssignmentEntry] = asm_rpc.strata_asm_getAssignments(
            latest_btc_block_hash
        )
        if assignments is None:
            raise AssertionError("ASM getAssignments should return a list (possibly empty)")
        self.logger.info(f"Assignments at latest ASM block: {len(assignments)} entries")

        return True

    def wait_until_asm_ready(self, asm_rpc, timeout=60):
        """Wait until ASM RPC service responds."""

        def check_asm_ready():
            try:
                status = asm_rpc.strata_asm_getStatus()
                self.logger.debug(f"ASM status: {status}")
                return True
            except Exception as e:
                self.logger.debug(f"ASM not ready yet: {e}")
                return False

        wait_until(
            check_asm_ready,
            timeout=timeout,
            step=2,
            error_msg=f"ASM RPC did not become ready within {timeout} seconds",
        )

    def wait_until_asm_progresses(
        self,
        asm_rpc,
        initial_height: int,
        timeout=180,
    ) -> int:
        """Wait until ASM processes a new block beyond the initial height.

        Returns the new height.
        """

        height_holder: dict = {}

        def check_asm_progressed():
            try:
                status = AsmWorkerStatus.from_dict(asm_rpc.strata_asm_getStatus())
                if status.cur_block is None:
                    self.logger.debug("ASM has no current block yet")
                    return False

                cur_height = status.cur_block.height

                self.logger.debug(
                    f"ASM height check: current={cur_height}, initial={initial_height}"
                )

                if cur_height > initial_height:
                    height_holder["height"] = cur_height
                    return True
                return False
            except Exception as e:
                self.logger.debug(f"Error checking ASM progression: {e}")
                return False

        wait_until(
            check_asm_progressed,
            timeout=timeout,
            step=5,
            error_msg=f"ASM did not progress within {timeout} seconds",
        )
        return height_holder["height"]
