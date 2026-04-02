import secrets

import flexitest

from envs.base_test import StrataTestBase
from envs.mosaic_env import MosaicEnv
from utils.utils import wait_until


@flexitest.register
class MosaicSetupTest(StrataTestBase):
    """
    Tests mosaic setup across 3 nodes:
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(MosaicEnv())

    def main(self, ctx: flexitest.RunContext):
        num_nodes = 3
        instance_id = "0" * 64

        # Get services and RPCs for all nodes (0-indexed)
        rpcs = {}
        for i in range(num_nodes):
            svc = ctx.get_service(f"mosaic_{i}")
            rpc = svc.create_rpc()
            self.wait_unit_mosaic_ready(rpc)
            rpcs[i] = rpc

        # Get peer IDs
        peer_ids = {i: rpcs[i].mosaic_getRpcPeerId() for i in range(num_nodes)}

        # Setup garbler + evaluator for every unordered pair.
        # Garbler and evaluator share the same random setup_inputs.
        setups = []
        for garbler in range(num_nodes):
            for evaluator in range(garbler + 1, num_nodes):
                setup_inputs = secrets.token_hex(32)

                tsid_g = rpcs[garbler].mosaic_setupTableset(
                    {
                        "role": "garbler",
                        "peer_info": {"peer_id": peer_ids[evaluator]},
                        "setup_inputs": setup_inputs,
                        "instance_id": instance_id,
                    }
                )
                name_g = f"node{garbler}_garbler_to_node{evaluator}"
                self.logger.info(f"{name_g}: {tsid_g}")
                setups.append((name_g, rpcs[garbler], tsid_g))

                tsid_e = rpcs[evaluator].mosaic_setupTableset(
                    {
                        "role": "evaluator",
                        "peer_info": {"peer_id": peer_ids[garbler]},
                        "setup_inputs": setup_inputs,
                        "instance_id": instance_id,
                    }
                )
                name_e = f"node{evaluator}_evaluator_to_node{garbler}"
                self.logger.info(f"{name_e}: {tsid_e}")
                setups.append((name_e, rpcs[evaluator], tsid_e))

        # Poll all setups until SetupComplete
        self.wait_all_setup_complete(setups)

        return True

    def wait_unit_mosaic_ready(self, mosaic_rpc, timeout=60):
        """Wait until MOSAIC RPC service responds."""

        def check_ready():
            try:
                peer_id = mosaic_rpc.mosaic_getRpcPeerId()
                self.logger.debug(f"Peer ID: {peer_id}")
                return True
            except Exception as e:
                self.logger.debug(f"Mosaic not ready yet: {e}")
                return False

        wait_until(
            check_ready,
            timeout=timeout,
            step=2,
            error_msg=f"Mosaic RPC did not become ready within {timeout} seconds",
        )

    def wait_all_setup_complete(self, setups, timeout=120, step=2):
        """Poll all tableset setups until every one reaches SetupComplete.
        Raises immediately if any setup returns Aborted."""
        pending = {name for name, _, _ in setups}

        def check_all_complete():
            for name, rpc, tsid in setups:
                if name not in pending:
                    continue
                status = rpc.mosaic_getTablesetStatus(tsid)
                self.logger.info(f"{name} status: {status}")

                if isinstance(status, dict) and "Aborted" in status:
                    reason = status["Aborted"].get("reason", "unknown")
                    raise RuntimeError(f"{name} setup aborted: {reason}")

                if status == "SetupComplete":
                    self.logger.info(f"{name} reached SetupComplete")
                    pending.discard(name)

            return len(pending) == 0

        wait_until(
            check_all_complete,
            timeout=timeout,
            step=step,
            error_msg=(
                f"Not all setups reached SetupComplete within {timeout}s."
                f" Still pending: {pending}"
            ),
        )
