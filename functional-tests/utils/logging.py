import logging
import os

def setup_root_logger():
    """
    reads `LOG_LEVEL` from the environment. Defaults to `WARNING` if not provided.
    """
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, log_level, logging.NOTSET)
    # Configure the root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
