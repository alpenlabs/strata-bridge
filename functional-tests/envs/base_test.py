from utils.logging import setup_test_logger
import flexitest

class StrataTestBase(flexitest.Test):
    """
    Class to be used instead of flexitest.Test for accessing logger
    """

    def __init__(self, ctx: flexitest.RunContext):
        logger = setup_test_logger(ctx.datadir_root, ctx.name)
        self.logger = logger
        self.debug = logger.debug
        self.info = logger.info
        self.warning = logger.warning
        self.error = logger.error
        self.critical = logger.critical
