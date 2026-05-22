"""
Secret-Service Restart Resilience Test

Verifies that a bridge node tolerates its secret-service (s2) process being
stopped and restarted mid-deposit. The bridge node's `secret-service-client`
holds a long-lived QUIC connection to the per-operator s2 server. Before
STR-3305, dropping that connection (e.g. s2 process restart) caused every
subsequent signing request to fail until the bridge node itself was
restarted. STR-3305 adds lazy on-failure reconnect; this test exercises
that path end-to-end.

Test flow:
1. Submit a DRT and wait until the deposit SM reaches `InProgress` (signing
   requests are flowing through s2).
2. Stop every s2 process. The bridge nodes' existing QUIC connections become
   stale.
3. Restart every s2 process on the same port (their on-disk config is
   unchanged).
4. The deposit must complete — proving the bridge nodes' `make_v2_req`
   reconnect path successfully re-established each connection without
   requiring a bridge-node restart.
"""

import flexitest

from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from rpc.types import RpcDepositStatusComplete, RpcDepositStatusInProgress
from utils.bridge import get_bridge_nodes_and_rpcs
from utils.deposit import wait_until_deposit_status, wait_until_drt_recognized
from utils.dev_cli import DevCli
from utils.utils import read_operator_key


@flexitest.register
class DepositTolerantOfS2RestartTest(StrataTestBase):
    """The bridge must complete a deposit across an s2 restart without a bridge-node restart."""

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(BridgeNetworkEnv())

    def main(self, ctx: flexitest.RunContext):
        bridge_nodes, bridge_rpcs = get_bridge_nodes_and_rpcs(ctx)
        bridge_rpc = bridge_rpcs[0]
        num_operators = len(bridge_nodes)

        # `get_service` is typed as the base `Service`; the s2 services are concretely
        # `ProcService`s with `.start()`/`.stop()`.
        s2_services = [ctx.get_service(f"s2_{i}") for i in range(num_operators)]

        bitcoind_service = ctx.get_service("bitcoin")
        bitcoind_props = bitcoind_service.props
        operator_key_infos = [read_operator_key(i) for i in range(num_operators)]
        dev_cli = DevCli(bitcoind_props, operator_key_infos)

        # --- Submit DRT and wait for the signing phase to begin ---
        drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted DRT: {drt_txid}")
        deposit_id = wait_until_drt_recognized(bridge_rpc, drt_txid)
        wait_until_deposit_status(
            bridge_rpc,
            deposit_id,
            RpcDepositStatusInProgress,
            timeout=180,
        )

        # --- Stop every s2: the bridge nodes' QUIC connections are now stale ---
        self.logger.info("Stopping all secret-service nodes mid-deposit")
        for i, s2 in enumerate(s2_services):
            self.logger.info(f"Stopping s2 node {i}")
            s2.stop()

        # --- Restart on the same port; the bridge clients must reconnect on demand ---
        self.logger.info("Restarting all secret-service nodes")
        for i, s2 in enumerate(s2_services):
            self.logger.info(f"Starting s2 node {i}")
            s2.start()

        # --- The deposit must complete: any signing call on a stale connection should
        #     trigger reconnect in `make_v2_req`, succeed on the second attempt against the
        #     fresh s2, and the deposit drives to completion as normal ---
        self.logger.info("Waiting for deposit to complete post-s2-restart")
        wait_until_deposit_status(
            bridge_rpc,
            deposit_id,
            RpcDepositStatusComplete,
            timeout=300,
        )

        return True
