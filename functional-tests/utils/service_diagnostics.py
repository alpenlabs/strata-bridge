"""Flake-triage diagnostics: service exit-code logging and RSS sampling.

Context: fn tests flake with one mosaic process dying silently during the
garbling burst (see scripts/scan_fntest_flakes.py). The exit signal is the
one bit that discriminates the hypotheses (SIGSEGV/SIGABRT/SIGKILL), but
flexitest never logs it - and its stop() catches TimeoutError where
Popen.wait raises TimeoutExpired, so the SIGKILL escalation is dead code.
"""

import os
import signal
import subprocess
import threading
import time

import flexitest

# Binaries tracked by the RSS sampler (ps `comm` truncates to 15 chars).
_TRACKED_COMMS = (
    "mosaic",
    "strata-bridge",
    "secret-service",
    "bitcoind",
    "fdbserver",
    "strata-asm-runn",
)


def _describe_rc(rc: int | None) -> str:
    if rc is None:
        return "still running"
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


def install_service_diagnostics() -> None:
    """Patch ProcService to log start pids and exit statuses at teardown."""
    proc_service = flexitest.service.ProcService
    if getattr(proc_service, "_diag_installed", False):
        return
    proc_service._diag_installed = True

    orig_start = proc_service.start

    def start(self):
        orig_start(self)
        if self.proc is not None:
            print(f"=== diag: started pid={self.proc.pid}: {_svc_label(self)}")

    def stop(self):
        if not self.is_started():
            raise RuntimeError("not running")

        p = self.proc
        self.proc = None

        rc = p.poll()
        if rc is not None:
            # Died on its own before teardown - the interesting case for flake triage.
            print(
                f"=== diag: pid={p.pid} DIED BEFORE TEARDOWN: "
                f"{_describe_rc(rc)}: {_svc_label(self)}"
            )
            self._rc = rc
            self._update_status_msg()
            return

        p.terminate()
        try:
            self._rc = p.wait(timeout=self.stop_timeout)
        except subprocess.TimeoutExpired:
            # Upstream catches TimeoutError, which Popen.wait never raises.
            p.kill()
            try:
                self._rc = p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._rc = -9  # dummy code matching upstream's convention
        finally:
            self._update_status_msg()
        print(
            f"=== diag: pid={p.pid} stopped at teardown: "
            f"{_describe_rc(self._rc)}: {_svc_label(self)}"
        )

    # setattr: deliberate monkeypatch (plain assignment trips ty's invalid-assignment)
    setattr(proc_service, "start", start)  # noqa: B010
    setattr(proc_service, "stop", stop)  # noqa: B010

    # ProcServiceWithEnv overrides start() wholesale; wrap it too (stop is inherited).
    try:
        from factory.bridge_operator import ProcServiceWithEnv

        if "start" in ProcServiceWithEnv.__dict__:
            orig_env_start = ProcServiceWithEnv.start

            def env_start(self):
                orig_env_start(self)
                if self.proc is not None:
                    print(f"=== diag: started pid={self.proc.pid}: {_svc_label(self)}")

            setattr(ProcServiceWithEnv, "start", env_start)  # noqa: B010
    except ImportError:
        pass


def start_rss_sampler(out_path: str, interval: float = 2.0) -> None:
    """Append RSS of tracked service processes to `out_path` every `interval` seconds."""
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    def run():
        with open(out_path, "a", buffering=1) as f:
            f.write("# ts pid rss_kb comm\n")
            while True:
                try:
                    out = subprocess.run(
                        ["ps", "-eo", "pid=,rss=,comm="],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    ).stdout
                    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    for line in out.splitlines():
                        parts = line.split(None, 2)
                        if len(parts) == 3 and parts[2].startswith(_TRACKED_COMMS):
                            f.write(f"{ts} {parts[0]} {parts[1]} {parts[2]}\n")
                except Exception:  # noqa: BLE001 - the sampler must never kill the run
                    pass
                time.sleep(interval)

    threading.Thread(target=run, daemon=True, name="rss-sampler").start()
