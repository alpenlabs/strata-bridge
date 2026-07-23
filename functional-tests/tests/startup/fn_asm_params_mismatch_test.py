import time
from pathlib import Path

import flexitest
import toml

from envs.base_test import StrataTestBase
from envs.bridge_network_env import BridgeNetworkEnv
from utils.utils import (
    snapshot_log_offsets,
    wait_until,
    wait_until_bridge_ready,
    wait_until_logs_match,
)

MISMATCH_MSG = "does not match peer value"
DEV_SKIP_MSG = "dev mode: skipping bridge startup consistency checks"


@flexitest.register
class AsmParamsMismatchTest(StrataTestBase):
    """
    A bridge node whose params disagree with the ASM's must abort startup,
    unless `dev = true` skips the consistency checks.

    The env starts healthy; the test then restarts one node with a mutated
    params.toml so a mismatch can never fail env setup itself. The dev phase
    reuses the same mismatch, proving the skip on the exact config that just
    aborted.
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(BridgeNetworkEnv())

    def main(self, ctx: flexitest.RunContext):
        node = ctx.get_service("bridge_node_0")
        node_dir = Path(node.props["logfile"]).parent

        # Originals stay raw text so the restore is byte-identical, not a toml round-trip.
        original_params = (node_dir / "params.toml").read_text()
        original_config = (node_dir / "config.toml").read_text()
        mutated = toml.loads(original_params)
        mutated["protocol"]["deposit_amount"] += 1
        mismatched_params = toml.dumps(mutated)
        dev_config = toml.dumps({**toml.loads(original_config), "dev": True})

        self.logger.info("Restarting bridge node 0 with mismatched deposit_amount")
        offsets = self._restart_with(node, mismatched_params, original_config)
        wait_until_logs_match(
            offsets,
            lambda line: "deposit_amount" in line and MISMATCH_MSG in line,
            timeout=240,
            error_msg="node did not log the ASM params mismatch",
        )
        wait_until(
            lambda: not node.check_status(),
            error_msg="node kept running despite the params mismatch",
        )
        self.logger.info("Node aborted startup on the params mismatch as expected")

        self.logger.info("Restarting bridge node 0 with dev = true and the same mismatch")
        offsets = self._restart_with(node, mismatched_params, dev_config)

        wait_until_bridge_ready(node.create_rpc(), timeout=240)
        wait_until_logs_match(
            offsets,
            lambda line: DEV_SKIP_MSG in line,
            timeout=240,
            error_msg="node did not log the dev-mode skip",
        )
        self.logger.info("Dev mode skipped the check despite the mismatch")

        # Restore so env teardown sees a healthy service.
        self._restart_with(node, original_params, original_config)
        wait_until_bridge_ready(node.create_rpc(), timeout=240)
        self.logger.info("Node restarted cleanly with the original params")

        return True

    def _restart_with(self, node, params: str, config: str) -> dict:
        """Returned offsets are snapshotted just before the start, for wait_until_logs_match."""
        node.stop()
        time.sleep(5)  # ports need to be released before restarting
        logfile = node.props["logfile"]
        node_dir = Path(logfile).parent
        (node_dir / "params.toml").write_text(params)
        (node_dir / "config.toml").write_text(config)
        offsets = snapshot_log_offsets([logfile])
        node.start()
        return offsets
