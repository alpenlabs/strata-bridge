import flexitest

from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from rpc.asm_types import AssignmentEntry, DepositEntry
from rpc.types import RpcDepositStatusComplete
from utils.bridge import get_bridge_nodes_and_rpcs
from utils.deposit import (
    wait_until_deposit_status,
    wait_until_drt_recognized,
)
from utils.dev_cli import DevCli
from utils.utils import (
    read_operator_key,
    wait_for_tx_confirmation,
    wait_until,
)


@flexitest.register
class AsmBinaryTest(StrataTestBase):
    """
    Test that ASM can serve the Deposits and Assignments
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(BridgeNetworkEnv())

    def main(self, ctx: flexitest.RunContext):
        bridge_nodes, bridge_rpcs = get_bridge_nodes_and_rpcs(ctx)
        bitcoind_service = ctx.get_service("bitcoin")
        bitcoin_rpc = bitcoind_service.create_rpc()

        num_operators = len(bridge_nodes)
        musig2_keys = [read_operator_key(i).MUSIG2_KEY for i in range(num_operators)]

        # Send a deposit request and wait for completion
        bitcoind_props = bitcoind_service.props
        dev_cli = DevCli(bitcoind_props, musig2_keys)
        drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted DRT: {drt_txid}")

        bridge_rpc = bridge_rpcs[0]
        deposit_id = wait_until_drt_recognized(bridge_rpc, drt_txid)
        self.logger.info(f"DRT recognized, deposit_id: {deposit_id}")

        wait_until_deposit_status(bridge_rpc, deposit_id, RpcDepositStatusComplete)
        self.logger.info("Deposit completed")

        # Stop bridge nodes to prevent the payouts
        self.logger.info("Stopping all operator nodes")
        for i in range(num_operators):
            self.logger.info(f"Stopping operator node {i}")
            bridge_nodes[i].stop()

        # Set up ASM RPC client and fetch the latest block hash
        asm_service = ctx.get_service("asm_rpc")
        asm_rpc = asm_service.create_rpc()
        recent_block_num = bitcoin_rpc.proxy.getblockcount()
        recent_block_hash = bitcoin_rpc.proxy.getblockhash(recent_block_num)

        # Assert ASM has the deposit entry
        deposit_entries: list[DepositEntry] = asm_rpc.strata_asm_getDeposits(recent_block_hash)
        self.logger.info(f"ASM deposits at block {recent_block_num}: {deposit_entries}")
        assert len(deposit_entries) == 1
        deposit_entry = DepositEntry.from_dict(deposit_entries[0])
        assert deposit_entry.deposit_idx == 0

        # Post mock checkpoint using the current tip to derive the OL range
        ckp_l1_txn = dev_cli.send_mock_checkpoint_from_tip(
            asm_rpc, recent_block_hash, num_ol_slots=1, num_withdrawals=1
        )
        ckp_block_hash = wait_for_tx_confirmation(bitcoin_rpc, ckp_l1_txn)
        self.logger.info(f"Checkpoint tx {ckp_l1_txn} included in block {ckp_block_hash}")

        # Wait for ASM to process the checkpoint block, then assert assignment
        wait_until(
            lambda: len(asm_rpc.strata_asm_getAssignments(ckp_block_hash)) == 1,
            timeout=100,
            error_msg="ASM did not produce assignment",
        )

        assignments: list[AssignmentEntry] = asm_rpc.strata_asm_getAssignments(ckp_block_hash)
        self.logger.info(f"ASM assignments at block {ckp_block_hash}: {len(assignments)}")
        assignment = AssignmentEntry.from_dict(assignments[0])
        assert assignment.deposit_entry == deposit_entry

        return True
