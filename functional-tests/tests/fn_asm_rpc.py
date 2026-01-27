import flexitest

from envs.base_test import StrataTestBase
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

        # Ensure ASM has a current block commitment
        initial_status = self.wait_until_asm_has_block(asm_rpc)
        initial_cur_block = initial_status["cur_block"]
        initial_asm_height = int(initial_cur_block["height"])
        initial_asm_blkid = initial_cur_block["blkid"]
        self.logger.info(f"Initial ASM block: {initial_asm_blkid} at height {initial_asm_height}")

        # Get initial block count from Bitcoin
        initial_btc_height = bitcoin_rpc.proxy.getblockcount()
        self.logger.info(f"Initial Bitcoin block height: {initial_btc_height}")

        # Generate blocks to ensure ASM has something to process
        wallet_addr = bitcoin_rpc.proxy.getnewaddress()
        num_blocks_to_generate = 10
        self.logger.info(f"Generating {num_blocks_to_generate} blocks")
        bitcoin_rpc.proxy.generatetoaddress(num_blocks_to_generate, wallet_addr)

        new_btc_height = bitcoin_rpc.proxy.getblockcount()
        self.logger.info(f"New Bitcoin block height: {new_btc_height}")

        # Wait for ASM to progress past its initial height
        self.wait_until_asm_progresses(
            asm_rpc,
            initial_height=initial_asm_height,
        )
        self.logger.info("ASM has progressed to a new block")

        # Get the processed state from status
        latest_status = asm_rpc.strata_asm_getStatus()
        if not latest_status.get("is_initialized", False):
            raise AssertionError("ASM should report is_initialized=True")

        latest_cur_block = latest_status["cur_block"]
        if latest_cur_block is None:
            raise AssertionError("ASM should have a current block commitment")

        latest_asm_height = int(latest_cur_block["height"])
        latest_asm_blkid = latest_cur_block["blkid"]
        self.logger.info(
            f"ASM latest processed block: {latest_asm_blkid} at height {latest_asm_height}"
        )

        if latest_asm_height <= initial_asm_height:
            raise AssertionError(
                f"ASM did not progress: {latest_asm_height} <= {initial_asm_height}"
            )

        # Verify the assignments RPC works at the latest ASM block (may be empty).
        # IMPORTANT: the blkid in getStatus is in internal byte order, while the
        # RPC expects Bitcoin display byte order. Use bitcoind's blockhash here.
        latest_btc_block_hash = bitcoin_rpc.proxy.getblockhash(latest_asm_height)
        self.logger.info(
            f"Bitcoin block hash at ASM height {latest_asm_height}: {latest_btc_block_hash}"
        )
        assignments = asm_rpc.strata_asm_getAssignments(latest_btc_block_hash)
        if assignments is None:
            raise AssertionError("ASM getAssignments should return a list (possibly empty)")
        self.logger.info(f"Assignments at latest ASM block: {len(assignments)} entries")

        return True

    def wait_until_asm_ready(self, asm_rpc, timeout=60):
        """Wait until ASM RPC service responds."""

        def check_asm_ready():
            try:
                # Try to get status - even if it returns None, it means RPC is responsive
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

    def wait_until_asm_has_block(self, asm_rpc, timeout=120):
        """Wait until ASM reports a current block commitment."""

        status_holder: dict = {}

        def check_asm_has_block():
            try:
                status = asm_rpc.strata_asm_getStatus()
                cur_block = status.get("cur_block")
                if cur_block is None:
                    self.logger.debug("ASM has no current block yet")
                    return False
                status_holder["status"] = status
                self.logger.debug(f"ASM current block: {cur_block}")
                return True
            except Exception as e:
                self.logger.debug(f"ASM not ready yet: {e}")
                return False

        wait_until(
            check_asm_has_block,
            timeout=timeout,
            step=3,
            error_msg=f"ASM did not report a current block within {timeout} seconds",
        )
        return status_holder["status"]

    def wait_until_asm_progresses(
        self,
        asm_rpc,
        initial_height: int,
        timeout=180,
    ):
        """Wait until ASM processes a new block beyond the initial height."""

        def check_asm_progressed():
            try:
                status = asm_rpc.strata_asm_getStatus()
                cur_block = status.get("cur_block")
                if cur_block is None:
                    self.logger.debug("ASM has no current block yet")
                    return False

                cur_height = int(cur_block["height"])

                self.logger.debug(
                    f"ASM height check: current={cur_height}, initial={initial_height}"
                )

                return cur_height > initial_height
            except Exception as e:
                self.logger.debug(f"Error checking ASM progression: {e}")
                return False

        wait_until(
            check_asm_progressed,
            timeout=timeout,
            step=5,
            error_msg=f"ASM did not progress within {timeout} seconds",
        )
