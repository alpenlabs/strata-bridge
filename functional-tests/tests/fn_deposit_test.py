import flexitest

from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from rpc.types import RpcDepositStatusComplete, RpcDepositStatusInProgress
from utils.bridge import get_bridge_nodes_and_rpcs
from utils.deposit import wait_until_deposit_status, wait_until_drt_recognized
from utils.dev_cli import DevCli
from utils.network import wait_until_p2p_connected
from utils.utils import (
    read_operator_key,
    snapshot_log_offsets,
    wait_until_bridge_ready,
    wait_until_logs_match,
)


@flexitest.register
class BridgeDepositTest(StrataTestBase):
    """
    Test that a deposit can be made and completed successfully in a bridge network environment.
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(BridgeNetworkEnv())

    def main(self, ctx: flexitest.RunContext):
        bridge_nodes, bridge_rpcs = get_bridge_nodes_and_rpcs(ctx)

        # Test deposit
        bitcoind_service = ctx.get_service("bitcoin")
        bitcoind_props = bitcoind_service.props

        num_operators = len(bridge_nodes)
        musig2_keys = [read_operator_key(i).MUSIG2_KEY for i in range(num_operators)]

        dev_cli = DevCli(bitcoind_props, musig2_keys)
        drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted DRT: {drt_txid}")

        bridge_rpc = bridge_rpcs[0]
        deposit_id = wait_until_drt_recognized(bridge_rpc, drt_txid)

        wait_until_deposit_status(bridge_rpc, deposit_id, RpcDepositStatusComplete)

        # Reuse environment to check recovery/nag behavior when one operator is down.
        # Shutting down all operators except one to force nagging behavior in the active nodes,
        # then restarting the stopped node to verify it can rejoin and process the deposit.
        # Shutting down all nodes will prevent us from checking whether a DRT gets recognized.
        # Shutting down all nodes after DRT recognition is too slow,
        # and causes the deposit to go through before restart.
        CRASHED_OPERATOR_IDX = 2
        active_operator_indices = [
            idx for idx in range(num_operators) if idx != CRASHED_OPERATOR_IDX
        ]

        self.logger.info(
            f"Stopping operator node {CRASHED_OPERATOR_IDX} before next DRT to force nagging"
        )
        bridge_nodes[CRASHED_OPERATOR_IDX].stop()

        nag_log_offsets = snapshot_log_offsets(
            [bridge_nodes[idx].props["logfile"] for idx in active_operator_indices]
        )

        self.logger.info("Sending another DRT to test resilience with one operator offline")
        drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted DRT: {drt_txid}")

        new_deposit_id = wait_until_drt_recognized(bridge_rpc, drt_txid)

        self.logger.info("Ensuring deposit is in progress while one operator is offline")
        wait_until_deposit_status(
            bridge_rpc,
            new_deposit_id,
            RpcDepositStatusInProgress,
            timeout=180,
        )

        self.logger.info(
            f"Waiting for active operators to nag missing operator {CRASHED_OPERATOR_IDX}"
        )
        wait_until_logs_match(
            nag_log_offsets,
            lambda line: (
                "executing nag duty to request missing graph peer data" in line
                and f"operator_idx={CRASHED_OPERATOR_IDX}" in line
            ),
            timeout=180,
            error_msg=(
                f"Timeout after 180 seconds waiting for nag duty targeting "
                f"operator {CRASHED_OPERATOR_IDX}"
            ),
        )

        self.logger.info(f"Restarting operator node {CRASHED_OPERATOR_IDX}")
        bridge_nodes[CRASHED_OPERATOR_IDX].start()
        wait_until_bridge_ready(bridge_rpcs[CRASHED_OPERATOR_IDX])

        self.logger.info("Verifying P2P connectivity among bridge nodes before deposit")
        wait_until_p2p_connected(bridge_rpcs)

        self.logger.info("Waiting for deposit to complete after operator nodes restart")
        wait_until_deposit_status(
            bridge_rpc,
            new_deposit_id,
            RpcDepositStatusComplete,
            timeout=300,
        )

        # Verify operator connectivity again
        # TODO: @MdTeach investigate why this fails in CI but passes locally
        self.logger.info("Verifying P2P connectivity among bridge nodes after deposit")
        wait_until_p2p_connected(bridge_rpcs)

        return True
