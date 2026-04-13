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
    wait_until_drt_recognized,
    wait_until_utxo_spent,
)
from utils.dev_cli import DevCli
from utils.utils import (
    read_operator_key,
    wait_for_tx_confirmation,
    wait_until,
)


@flexitest.register
class FaultyClaimContestedTest(StrataTestBase):
    """
    Test that a watchtower automatically contests a faulty claim.

    A faulty claim is one posted without a prior fulfillment transaction.

    Steps:
    1. Complete a deposit
    2. Post a faulty claim via dev-cli from operator-0 (no assignment)
    3. Wait for a watchtower to contest by confirming the claim tx's
       contest connector (vout 0) is spent on bitcoin
    4. Post a mock checkpoint explicitly assigning the withdrawal to
       operator-1, then shut operator-1 down so it cannot perform its
       fulfillment
    5. Verify operator-1 is the ASM assignee
    6. Post a second faulty claim via dev-cli from operator-1's POV (no fulfillment)
    7. Wait for a watchtower to contest the second claim
    """

    def __init__(self, ctx: flexitest.InitContext):
        self.bridge_protocol_params = BridgeProtocolParams(
            contest_timelock=5,
        )
        ctx.set_env(
            BridgeNetworkEnv(
                bridge_protocol_params=self.bridge_protocol_params,
                bridge_config_params=BridgeConfigParams(
                    cooperative_payout_timeout=0,
                ),
            )
        )

    def main(self, ctx: flexitest.RunContext):
        bridge_nodes, bridge_rpcs = get_bridge_nodes_and_rpcs(ctx)
        bitcoind_service = ctx.get_service("bitcoin")
        bitcoin_rpc = bitcoind_service.create_rpc()
        asm_rpc = ctx.get_service("asm_rpc").create_rpc()

        num_operators = len(bridge_nodes)
        operator_key_infos = [read_operator_key(i) for i in range(num_operators)]

        bitcoind_props = bitcoind_service.props
        dev_cli = DevCli(
            bitcoind_props,
            operator_key_infos,
            bridge_protocol_params=self.bridge_protocol_params,
        )

        # 1. Send deposit request and wait for completion
        drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted DRT: {drt_txid}")

        bridge_rpc = bridge_rpcs[0]
        deposit_id = wait_until_drt_recognized(bridge_rpc, drt_txid)
        self.logger.info(f"DRT recognized, deposit_id: {deposit_id}")

        deposit_info = wait_until_deposit_status(bridge_rpc, deposit_id, RpcDepositStatusComplete)
        assert deposit_info is not None, "Deposit did not complete"
        self.logger.info("Deposit completed")

        # 2. Post a faulty claim via dev-cli (no assignment) from operator-0
        op0_idx = 0
        op0_node = bridge_nodes[op0_idx]
        op0_rpc_url = f"http://127.0.0.1:{op0_node.props['rpc_port']}"
        op0_seed = read_operator_key(op0_idx).SEED

        claim_txid = dev_cli.send_claim(
            deposit_idx=0,
            operator_idx=op0_idx,
            bridge_node_url=op0_rpc_url,
            seed=op0_seed,
        )
        self.logger.info(f"Broadcasted faulty claim tx from op-0: {claim_txid}")

        claim_block_hash = wait_for_tx_confirmation(
            bitcoin_rpc,
            claim_txid,
            timeout=300,
        )
        self.logger.info(f"Faulty claim tx {claim_txid} confirmed in block {claim_block_hash}")

        # 3. Wait for a watchtower to contest by spending the claim's contest connector (vout 0)
        wait_until_utxo_spent(bitcoin_rpc, claim_txid, vout=0, timeout=300)
        self.logger.info("Claim contest connector (vout 0) spent — watchtower contested op-0 claim")

        # 4. Post a mock checkpoint explicitly assigning the withdrawal to
        #    operator-1, then shut operator-1 down so it cannot fulfill
        #    the assignment.
        target_idx = 1
        recent_block_hash = bitcoin_rpc.proxy.getblockhash(bitcoin_rpc.proxy.getblockcount())
        ckp_l1_txn = dev_cli.send_mock_checkpoint_from_tip(
            asm_rpc,
            recent_block_hash,
            num_ol_slots=1,
            assignee_node_idx=target_idx,
        )
        ckp_block_hash = wait_for_tx_confirmation(bitcoin_rpc, ckp_l1_txn)
        self.logger.info(f"Checkpoint tx {ckp_l1_txn} confirmed in block {ckp_block_hash}")

        self.logger.info(f"Stopping operator-{target_idx} to prevent fulfillment")
        bridge_nodes[target_idx].stop()

        # 5. Verify ASM assignee == operator-1
        wait_until(
            lambda: len(asm_rpc.strata_asm_getAssignments(ckp_block_hash)) > 0,
            timeout=300,
            error_msg="ASM did not produce assignment",
        )
        assignments = asm_rpc.strata_asm_getAssignments(ckp_block_hash)
        assignment = AssignmentEntry.from_dict(assignments[0])
        self.logger.info(
            f"ASM assignment: deposit_idx={assignment.deposit_entry.deposit_idx}, "
            f"assignee={assignment.current_assignee}"
        )
        assert assignment.current_assignee == target_idx, (
            f"expected operator-{target_idx} to be assigned, "
            f"got operator-{assignment.current_assignee}"
        )

        # 6. Post a faulty claim via dev-cli from operator-1's POV.
        #    operator-1 is stopped, so fetch graph data from another
        #    operator's bridge node RPC but sign with operator-1's seed.
        proxy_idx = (target_idx + 1) % num_operators
        proxy_rpc_url = f"http://127.0.0.1:{bridge_nodes[proxy_idx].props['rpc_port']}"
        op1_seed = read_operator_key(target_idx).SEED

        claim_txid_2 = dev_cli.send_claim(
            deposit_idx=0,
            operator_idx=target_idx,
            bridge_node_url=proxy_rpc_url,
            seed=op1_seed,
        )
        self.logger.info(f"Broadcasted faulty claim tx from op-{target_idx}: {claim_txid_2}")

        claim_block_hash_2 = wait_for_tx_confirmation(
            bitcoin_rpc,
            claim_txid_2,
            timeout=300,
        )
        self.logger.info(f"Faulty claim tx {claim_txid_2} confirmed in block {claim_block_hash_2}")

        # 7. Wait for a watchtower to contest the second claim
        wait_until_utxo_spent(bitcoin_rpc, claim_txid_2, vout=0, timeout=300)
        self.logger.info(
            f"Second claim contest connector (vout 0) spent "
            f"— watchtower contested op-{target_idx} claim"
        )

        return True
