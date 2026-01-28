import logging
import os
import random
import string
import subprocess
import time

import flexitest

logger = logging.getLogger(__name__)

# Environment variable to override fdbserver binary path
# Useful when fdbserver is not on PATH (e.g., /usr/local/libexec/fdbserver on macOS)
FDBSERVER_PATH = os.environ.get("FDBSERVER_PATH", "fdbserver")
FDBCLI_PATH = os.environ.get("FDBCLI_PATH", "fdbcli")


class FdbFactory(flexitest.Factory):
    """Factory for creating FoundationDB server instances for testing."""

    def __init__(self, port_range: list[int]):
        super().__init__(port_range)

    @flexitest.with_ectx("ctx")
    def create_fdb(self, ctx: flexitest.EnvContext) -> flexitest.Service:
        """
        Create and start a FoundationDB server instance.

        Spawns an isolated fdbserver process for testing.

        Returns a service with the following properties:
        - port: The port the server is listening on
        - cluster_file: Path to the cluster file for client connections
        """
        datadir = ctx.make_service_dir("fdb")
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
        ]

        props = {
            "port": port,
            "cluster_file": cluster_file,
        }

        svc = flexitest.service.ProcService(props, cmd, stdout=logfile)
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
    start = time.time()
    last_error = None
    last_stdout = ""
    last_stderr = ""

    logger.info("Waiting for FDB to become ready (timeout: %ds)...", timeout)

    # First, configure the database (this works even when status would hang)
    for attempt in range(1, 6):  # Try up to 5 times
        if time.time() - start > timeout:
            break

        try:
            logger.info("Attempt %d: Configuring database as 'new single ssd'...", attempt)
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

            # "Database created" means success
            if configure_result.returncode == 0:
                logger.info("Database configuration successful")
                break

            last_error = (
                f"Configure attempt {attempt}: {configure_result.stderr or configure_result.stdout}"
            )

        except subprocess.TimeoutExpired:
            last_error = f"Configure attempt {attempt}: timed out"
            logger.debug("Configure attempt %d timed out", attempt)
        except Exception as e:
            last_error = f"Configure attempt {attempt}: {e}"
            logger.debug("Configure attempt %d error: %s", attempt, e)

        time.sleep(2)
    else:
        # All attempts failed
        _raise_fdb_error(cluster_file, log_dir, timeout, last_error, last_stdout, last_stderr)

    # Now wait for the database to become available
    while time.time() - start < timeout:
        try:
            result = subprocess.run(
                [FDBCLI_PATH, "-C", cluster_file, "--exec", "status minimal", "--timeout", "5"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            last_stdout = result.stdout
            last_stderr = result.stderr

            if "The database is available" in result.stdout:
                logger.info("FDB database is available and ready")
                return

            last_error = f"Database not yet available: {result.stdout.strip()}"

        except subprocess.TimeoutExpired:
            last_error = "Status check timed out"
        except Exception as e:
            last_error = f"Status check error: {e}"

        time.sleep(1)

    # Timeout reached
    _raise_fdb_error(cluster_file, log_dir, timeout, last_error, last_stdout, last_stderr)


def _raise_fdb_error(
    cluster_file: str,
    log_dir: str,
    timeout: int,
    last_error: str | None,
    last_stdout: str,
    last_stderr: str,
):
    """Gather diagnostic information and raise an error."""
    diagnostics = [
        f"FDB failed to start within {timeout} seconds",
        f"Last error: {last_error}",
        f"Last stdout: {last_stdout}",
        f"Last stderr: {last_stderr}",
        f"Cluster file: {cluster_file}",
    ]

    # Try to read cluster file
    try:
        with open(cluster_file) as f:
            diagnostics.append(f"Cluster file contents: {f.read().strip()}")
    except Exception as e:
        diagnostics.append(f"Could not read cluster file: {e}")

    # Check for FDB log files
    try:
        if os.path.isdir(log_dir):
            log_files = os.listdir(log_dir)
            diagnostics.append(f"FDB log files in {log_dir}: {log_files}")
            for log_file in sorted(log_files, reverse=True)[:1]:
                log_path = os.path.join(log_dir, log_file)
                with open(log_path) as f:
                    lines = f.readlines()[-50:]
                    diagnostics.append(f"Last 50 lines of {log_file}:\n{''.join(lines)}")
    except Exception as e:
        diagnostics.append(f"Could not read FDB logs: {e}")

    error_message = "\n".join(diagnostics)
    logger.error(error_message)
    raise RuntimeError(error_message)
