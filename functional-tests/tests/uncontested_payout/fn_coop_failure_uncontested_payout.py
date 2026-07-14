import flexitest

from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import BridgeProtocolParams
from rpc.asm_types import AssignmentEntry
from rpc.types import RpcDepositStatusComplete
from utils.bridge import get_bridge_nodes_and_rpcs
from utils.deposit import (
    wait_until_deposit_status,
    wait_until_deposit_utxo_spent,
    wait_until_drt_recognized,
)
from utils.dev_cli import DevCli
from utils.utils import (
    read_operator_key,
    wait_for_tx_confirmation,
    wait_until,
)
from utils.withdrawal import wait_until_active_valid_claim

# Non-zero, unlike fn_uncontested_payout: the assignee must genuinely attempt the
# cooperative payout and only fall back once this many blocks pass after fulfillment.
COOPERATIVE_PAYOUT_TIMEOUT = 10


@flexitest.register
class CoopFailureUncontestedPayoutTest(StrataTestBase):
    """
    Test that the uncontested payout path works after the cooperative payout path fails.
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(
            BridgeNetworkEnv(
                bridge_protocol_params=BridgeProtocolParams(contest_timelock=5),
                bridge_config_params=BridgeConfigParams(
                    cooperative_payout_timeout=COOPERATIVE_PAYOUT_TIMEOUT,
                ),
            )
        )

    def main(self, ctx: flexitest.RunContext):
        bridge_nodes, bridge_rpcs = get_bridge_nodes_and_rpcs(ctx)
        bridge_rpc = bridge_rpcs[0]

        bitcoind_service = ctx.get_service("bitcoin")
        bitcoin_rpc = bitcoind_service.create_rpc()
        asm_rpc = ctx.get_service("asm_rpc").create_rpc()

        operator_key_infos = [read_operator_key(i) for i in range(len(bridge_nodes))]
        dev_cli = DevCli(bitcoind_service.props, operator_key_infos)

        drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted DRT: {drt_txid}")
        deposit_id = wait_until_drt_recognized(bridge_rpc, drt_txid)
        self.logger.info(f"DRT recognized, deposit_id: {deposit_id}")

        deposit_info = wait_until_deposit_status(bridge_rpc, deposit_id, RpcDepositStatusComplete)
        assert deposit_info is not None, "Deposit did not complete"
        deposit_txid = deposit_info.get("status").get("deposit_txid")
        self.logger.info(f"Deposit completed, txid: {deposit_txid}")

        # The deposit (graph pre-signing) needs every operator, so peers can only go
        # down now. Without them nonce collection stalls and the cooperative payout
        # is forced to time out.
        self.logger.info("Stopping operator-1 and operator-2")
        bridge_nodes[1].stop()
        bridge_nodes[2].stop()

        recent_block_hash = bitcoin_rpc.proxy.getblockhash(bitcoin_rpc.proxy.getblockcount())
        ckp_l1_txn = dev_cli.send_mock_checkpoint_from_tip(
            asm_rpc,
            recent_block_hash,
            num_ol_slots=1,
            num_withdrawals=1,
            assignee_node_idx=0,
        )
        ckp_block_hash = wait_for_tx_confirmation(bitcoin_rpc, ckp_l1_txn)
        self.logger.info(f"Checkpoint tx {ckp_l1_txn} included in block {ckp_block_hash}")

        wait_until(
            lambda: len(asm_rpc.strata_asm_getAssignments(ckp_block_hash)) > 0,
            timeout=300,
            error_msg="ASM did not produce assignment",
        )
        assignments = asm_rpc.strata_asm_getAssignments(ckp_block_hash)
        assignment = AssignmentEntry.from_dict(assignments[0])
        assert assignment.current_assignee == 0, (
            f"Expected assignee to be operator-0, got operator-{assignment.current_assignee}"
        )

        # The cooperative path never publishes a claim, so a claim appearing proves
        # operator-0 gave up on the cooperative payout and fell back to the claim path.
        active_claim = wait_until_active_valid_claim(bridge_rpc)
        self.logger.info(
            "Retrieved active claim %s for withdrawal of deposit %s assigned to operator %s",
            active_claim.claim_txid,
            active_claim.deposit_idx,
            active_claim.assigned_operator,
        )

        claim_block_hash = wait_for_tx_confirmation(
            bitcoin_rpc,
            active_claim.claim_txid,
            timeout=300,
        )
        self.logger.info(
            f"Active claim tx {active_claim.claim_txid} included in block {claim_block_hash}"
        )

        assert assignment.current_assignee == active_claim.assigned_operator, (
            "Active claim operator does not match ASM assignment"
        )
        assert assignment.deposit_entry.deposit_idx == active_claim.deposit_idx, (
            "Active claim deposit ID does not match ASM assignment"
        )

        # Deposit UTXO spent while operators 1 and 2 are still down: the uncontested
        # payout needed no cooperation.
        wait_until_deposit_utxo_spent(bitcoin_rpc, deposit_txid, timeout=450)
        self.logger.info("Deposit UTXO confirmed spent after uncontested payout")

        return True
