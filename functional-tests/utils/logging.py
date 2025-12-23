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


def setup_test_logger(datadir_root: str, test_name: str) -> logging.Logger:
    """
    Set up logger for a given test, with corresponding log file in a logs directory.
    - Configures both file and stream handlers for the test logger.
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

    # Common formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s"
    )

    # Set up individual loggers for each test
    logger = logging.getLogger(f"root.{test_name}")

    # File handler
    log_path = os.path.join(log_dir, f"{test_name}.log")
    file_handler = logging.FileHandler(log_path)
    file_handler.setFormatter(formatter)

    # Stream handler
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    # Add handlers to the logger
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

    # Set level to something sensible.
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    logger.setLevel(log_level)

    return logger
