import logging
import os
import sys

from constants import DEFAULT_LOG_LEVEL

# Common formatter
FORMATTER = logging.Formatter("%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s")
TEST_FILE_HANDLER_ATTR = "_strata_test_file_handler"


def setup_root_logger():
    """
    reads `LOG_LEVEL` from the environment. Defaults to `DEFAULT_LOG_LEVEL` if not provided.
    """
    log_level = os.getenv("LOG_LEVEL", DEFAULT_LOG_LEVEL).upper()
    log_level = getattr(logging, log_level, logging.NOTSET)

    # Configure the root logger with a single stream handler.
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(FORMATTER)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.handlers.clear()
    root_logger.addHandler(stream_handler)


def setup_test_logger(datadir_root: str, test_name: str) -> logging.Logger:
    """
    Set up logger for a given test, with corresponding log file in a logs directory.
    - Configures the root logger with a per-test file handler.
    - Returns a test logger that propagates to root.
    - Logs are stored in `<datadir_root>/logs/<test_name>.log`.

    Parameters:
        datadir_root (str): Root directory for logs.
        test_name (str): A test names to create loggers for.

    Returns:
        logging.Logger
    """
    # Create the logs directory
    log_dir = os.path.join(datadir_root, "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, f"{test_name}.log")

    root_logger = logging.getLogger()
    for handler in list(root_logger.handlers):
        if getattr(handler, TEST_FILE_HANDLER_ATTR, False):
            root_logger.removeHandler(handler)
            handler.close()

    # File handler for the current test. Attach it to the root logger so helper
    # modules that log via logging.info(...) are captured in the per-test log.
    file_handler = logging.FileHandler(log_path)
    file_handler.setFormatter(FORMATTER)
    setattr(file_handler, TEST_FILE_HANDLER_ATTR, True)
    root_logger.addHandler(file_handler)

    # Set up an individual logger for the test that propagates to root.
    logger = logging.getLogger(f"root.{test_name}")
    logger.handlers.clear()
    logger.propagate = True

    # Set level to something sensible.
    log_level = os.getenv("LOG_LEVEL", DEFAULT_LOG_LEVEL).upper()
    logger.setLevel(getattr(logging, log_level, logging.NOTSET))

    return logger
