import logging
import socket

import flexitest

logger = logging.getLogger(__name__)


def is_port_free(port: int, host: str = "0.0.0.0") -> bool:
    """Returns True if `host:port` can be bound right now.

    No SO_REUSEADDR, so a port in TIME_WAIT reads as busy; that only wastes one port from
    the range and never hands out one that is taken.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


class PortProbingFactory(flexitest.Factory):
    """`flexitest.Factory` whose `next_port` skips ports something else already holds."""

    def next_port(self) -> int:
        while True:
            port = super().next_port()  # raises "asked for too many ports" when exhausted
            if is_port_free(port):
                return port
            logger.warning(f"port {port} is already in use, skipping")
