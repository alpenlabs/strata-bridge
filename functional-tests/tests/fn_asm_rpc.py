import flexitest

from envs.base_test import StrataTestBase
from utils.utils import wait_until, wait_until_bitcoind_ready


@flexitest.register
class AsmBlockProcessingTest(StrataTestBase):
    """
    Test that the ASM binary is working properly by verifying:
    1. ASM service starts and is responsive
    2. TODO: (@prajwolrg) ASM processes Bitcoin blocks
    3. TODO: (@prajwolrg) progresses with new L1 blocks via getStatus
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
