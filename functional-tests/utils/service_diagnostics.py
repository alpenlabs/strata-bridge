"""Logs how each flexitest service process exited.

flexitest discards a service's exit status at teardown, so a process that died
mid-test (and which signal took it) leaves no trace in the test output.
"""

import logging
import os
import signal
import subprocess

import flexitest

logger = logging.getLogger(__name__)


def _describe_rc(rc: int) -> str:
    if rc < 0:
        try:
            name = signal.Signals(-rc).name
        except ValueError:
            name = f"signal {-rc}"
        return f"killed by {name} ({rc})"
    return f"exited with code {rc}"


def _svc_label(svc) -> str:
    """Identify a service by its command; arg paths keep their last 3 components."""

    def shorten(arg: str) -> str:
        parts = str(arg).split(os.sep)
        return os.sep.join(parts[-3:]) if len(parts) > 3 else str(arg)

    cmd = getattr(svc, "cmd", None) or ["?"]
    return " ".join([os.path.basename(str(cmd[0])), *(shorten(a) for a in cmd[1:])])


def install_service_exit_logging() -> None:
    """Replace ProcService.stop() with a version that logs pid and exit status."""

    def stop(self):
        if not self.is_started():
            raise RuntimeError("not running")

        p = self.proc
        self.proc = None

        rc = p.poll()
        if rc is not None:
            logger.warning(
                "pid=%d died before teardown: %s: %s", p.pid, _describe_rc(rc), _svc_label(self)
            )
            self._rc = rc
            self._update_status_msg()
            return

        p.terminate()
        try:
            self._rc = p.wait(timeout=self.stop_timeout)
        except subprocess.TimeoutExpired:
            # flexitest catches TimeoutError here, which Popen.wait never raises.
            p.kill()
            try:
                self._rc = p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._rc = -9
        finally:
            self._update_status_msg()
        logger.info("pid=%d stopped: %s: %s", p.pid, _describe_rc(self._rc), _svc_label(self))

    # setattr: plain assignment trips ty's invalid-assignment on the method slot
    setattr(flexitest.service.ProcService, "stop", stop)  # noqa: B010
