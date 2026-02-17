"""FoundationDB factory for functional testing.

This factory creates a single shared FoundationDB server instance for all tests.
Each test environment can use different root directories within the shared FDB
instance for isolation.
"""

import atexit
import logging
import os
import random
import string
import subprocess
import threading

import flexitest

from utils.utils import wait_until

logger = logging.getLogger(__name__)

# Environment variable to override fdbserver binary path
# Useful when fdbserver is not on PATH (e.g., /usr/local/libexec/fdbserver on macOS)
FDBSERVER_PATH = os.environ.get("FDBSERVER_PATH", "fdbserver")
FDBCLI_PATH = os.environ.get("FDBCLI_PATH", "fdbcli")

# Module-level singleton for the shared FDB instance
_fdb_instance: "PersistentFdbService | None" = None
_fdb_lock = threading.Lock()


class PersistentFdbService(flexitest.service.ProcService):
    """A ProcService that ignores stop() calls from flexitest environment teardown.

    This allows the FDB instance to persist across multiple test environments.
    The service is only stopped when force_stop() is called (typically at process exit).
    """

    def __init__(self, props: dict, cmd: list[str], stdout=None):
        super().__init__(props, cmd, stdout)
        self._force_stopped = False

    def stop(self):
        """Ignore stop calls from flexitest - we want to persist across environments."""
        logger.debug("Ignoring stop() call for persistent FDB instance")
        # Don't actually stop - just return

    def force_stop(self):
        """Actually stop the FDB server (called at process exit)."""
        if self._force_stopped:
            return
        self._force_stopped = True
        logger.info("Force stopping FDB server")
        super().stop()


def _cleanup_fdb():
    """Cleanup function called at process exit."""
    global _fdb_instance
    if _fdb_instance is not None:
        _fdb_instance.force_stop()
        _fdb_instance = None


# Register cleanup at process exit
atexit.register(_cleanup_fdb)


class FdbFactory(flexitest.Factory):
    """Factory for creating a shared FoundationDB server instance for testing.

    This factory implements a singleton pattern - only one FDB server is created
    and shared across all test environments. Each environment should use a unique
    `root_directory` in its FDB config for isolation.
    """

    def __init__(self, port_range: list[int]):
        super().__init__(port_range)
        self._datadir_root: str | None = None

    @flexitest.with_ectx("ctx")
    def create_fdb(self, ctx: flexitest.EnvContext) -> flexitest.Service:
        """
        Get or create the shared FoundationDB server instance.

        On first call, spawns an fdbserver process. Subsequent calls return
        the existing instance.

        Returns a service with the following properties:
        - port: The port the server is listening on
        - cluster_file: Path to the cluster file for client connections
        """
        global _fdb_instance

        with _fdb_lock:
            if _fdb_instance is not None and _fdb_instance.check_status():
                logger.info(
                    "Reusing existing FDB instance on port %d", _fdb_instance.get_prop("port")
                )
                return _fdb_instance

            # Store datadir root from first context we see
            if self._datadir_root is None:
                # Go up one level from environment dir to get the test run root
                self._datadir_root = os.path.dirname(ctx.envdd_path)

            _fdb_instance = self._create_fdb_instance()
            return _fdb_instance

    def _create_fdb_instance(self) -> PersistentFdbService:
        """Create a new FDB server instance at the test run root level."""
        # Create FDB directory at test run root (shared across all environments)
        assert self._datadir_root is not None, "datadir_root must be set before creating FDB"
        datadir = os.path.join(self._datadir_root, "_shared_fdb")
        os.makedirs(datadir, exist_ok=True)

        logfile = os.path.join(datadir, "service.log")

        port = self.next_port()
        cluster_file = os.path.join(datadir, "fdb.cluster")
        data_dir = os.path.join(datadir, "data")
        log_dir = os.path.join(datadir, "logs")

        # Create required directories
        os.makedirs(data_dir, exist_ok=True)
        os.makedirs(log_dir, exist_ok=True)

        # Generate cluster file with random ID to avoid conflicts
        cluster_id = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        cluster_content = f"test:{cluster_id}@127.0.0.1:{port}"
        with open(cluster_file, "w") as f:
            f.write(f"{cluster_content}\n")

        logger.info("Starting FDB server on port %d with cluster file: %s", port, cluster_file)

        cmd = [
            FDBSERVER_PATH,
            "-p",
            f"127.0.0.1:{port}",
            "-C",
            cluster_file,
            "-d",
            data_dir,
            "-L",
            log_dir,
            "--listen-address",
            "public",
            # Set an explicit machine ID so fdbserver does not try to open
            # POSIX shared memory.  macOS Tahoe 26+ restricts shm_open for
            # non-launchd processes, causing "Could not open shared memory -
            # Operation not permitted".
            "-i",
            f"fdb-test-{cluster_id}",
        ]

        props = {
            "port": port,
            "cluster_file": cluster_file,
        }

        svc = PersistentFdbService(props, cmd, stdout=logfile)
        svc.start()

        # Check if process is still running
        if not svc.check_status():
            error_details = ""
            if os.path.exists(logfile):
                with open(logfile) as f:
                    error_details = f.read()
            raise RuntimeError(
                f"FDB server process died immediately after start. Log contents:\n{error_details}"
            )

        # Initialize database after startup
        _wait_and_init_fdb(cluster_file, log_dir)

        logger.info("FDB server started successfully on port %d", port)

        return svc


def _wait_and_init_fdb(cluster_file: str, log_dir: str, timeout: int = 60):
    """
    Wait for FDB to start and initialize the database.

    Uses 'single ssd' configuration which is appropriate for tests:
    - single replica (no redundancy needed for tests)
    - on-disk storage engine (avoids memory exhaustion with many operators)

    IMPORTANT: We must configure the database FIRST before checking status.
    On an unconfigured database, 'status minimal' will hang indefinitely,
    but 'configure new single ssd' will work immediately.
    """
    logger.info("Waiting for FDB to become ready (timeout: %ds)...", timeout)

    # State to track configuration success and errors for diagnostics
    config_state = {"configured": False}

    def try_configure_database() -> bool:
        """Attempt to configure the database as 'new single ssd'."""
        if config_state["configured"]:
            return True

        try:
            logger.info("Configuring database as 'new single ssd'...")
            configure_result = subprocess.run(
                [
                    FDBCLI_PATH,
                    "-C",
                    cluster_file,
                    "--exec",
                    "configure new single ssd",
                    "--timeout",
                    "10",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )

            logger.debug(
                "Configure result: returncode=%d, stdout='%s', stderr='%s'",
                configure_result.returncode,
                configure_result.stdout.strip(),
                configure_result.stderr.strip(),
            )

            if configure_result.returncode == 0:
                logger.info("Database configuration successful")
                config_state["configured"] = True
                return True

            return False

        except subprocess.TimeoutExpired:
            logger.debug("Configure attempt timed out")
            return False
        except Exception as e:
            logger.debug("Configure attempt error: %s", e)
            return False

    # First, configure the database (this works even when status would hang)
    wait_until(
        try_configure_database,
        timeout=timeout,
        step=2,
        error_msg=f"Failed to configure FDB database. Check logs in {log_dir}",
    )

    def check_database_available() -> bool:
        """Check if the database is available."""
        try:
            result = subprocess.run(
                [FDBCLI_PATH, "-C", cluster_file, "--exec", "status minimal", "--timeout", "5"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if "The database is available" in result.stdout:
                logger.info("FDB database is available and ready")
                return True

            logger.debug("Database not yet available: %s", result.stdout.strip())
            return False

        except subprocess.TimeoutExpired:
            logger.debug("Status check timed out")
            return False
        except Exception as e:
            logger.debug("Status check error: %s", e)
            return False

    # Now wait for the database to become available
    wait_until(
        check_database_available,
        timeout=timeout,
        step=1,
        error_msg=f"FDB database did not become available. Check logs in {log_dir}",
    )


def generate_fdb_root_directory(env_name: str) -> str:
    """Generate a unique root directory name for an environment.

    Args:
        env_name: Name of the test environment (e.g., "basic", "network")

    Returns:
        A unique root directory name like "test-basic-a1b2c3d4"
    """
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"test-{env_name}-{suffix}"
