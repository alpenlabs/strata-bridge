import flexitest

from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import BridgeProtocolParams
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
from utils.withdrawal import wait_until_active_valid_claim


@flexitest.register
class BridgeProofTimeoutTest(StrataTestBase):
    """
    Test that the bridge proof timeout path completes when no bridge proof is submitted.

    Steps:
    1. Complete a deposit
    2. Wait for an active claim
    3. Shut down the assigned operator's bridge node so it can't post the bridge proof
    4. Publish a contest against the claim
    5. Wait for the claim phase to transition to bridge_proof_timedout
    """

    def __init__(self, ctx: flexitest.InitContext):
        self.bridge_protocol_params = BridgeProtocolParams(
            contest_timelock=5,
            proof_timelock=5,
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

        num_operators = len(bridge_nodes)
        operator_key_infos = [read_operator_key(i) for i in range(num_operators)]

        # Init ASM rpc
        asm_service = ctx.get_service("asm_rpc")
        asm_rpc = asm_service.create_rpc()

        # Send DRT and wait for deposit
        bitcoind_props = bitcoind_service.props
        dev_cli = DevCli(
            bitcoind_props,
            operator_key_infos,
            bridge_protocol_params=self.bridge_protocol_params,
        )
        drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted DRT: {drt_txid}")

        bridge_rpc = bridge_rpcs[0]
        deposit_id = wait_until_drt_recognized(bridge_rpc, drt_txid)
        self.logger.info(f"DRT recognized, deposit_id: {deposit_id}")

        deposit_info = wait_until_deposit_status(bridge_rpc, deposit_id, RpcDepositStatusComplete)
        assert deposit_info is not None, "Deposit did not complete"
        self.logger.info("Deposit completed")
        deposit_txid = deposit_info.get("status").get("deposit_txid")
        self.logger.info(f"Deposit txid: {deposit_txid}")

        # Post mock checkpoint so that a withdrawal is assigned
        recent_block_hash = bitcoin_rpc.proxy.getblockhash(bitcoin_rpc.proxy.getblockcount())
        ckp_l1_txn = dev_cli.send_mock_checkpoint_from_tip(
            asm_rpc,
            recent_block_hash,
            num_ol_slots=1,
        )
        ckp_block_hash = wait_for_tx_confirmation(bitcoin_rpc, ckp_l1_txn)
        self.logger.info(f"Checkpoint tx {ckp_l1_txn} included in block {ckp_block_hash}")

        # Wait for ASM to process the checkpoint, then wait for an active claim
        wait_until(
            lambda: len(asm_rpc.strata_asm_getAssignments(ckp_block_hash)) > 0,
            timeout=300,
            error_msg="ASM did not produce assignment",
        )

        active_claim = wait_until_active_valid_claim(bridge_rpc)
        self.logger.info(
            "Active claim %s for deposit %s assigned to operator %s",
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
            f"Claim tx {active_claim.claim_txid} confirmed in block {claim_block_hash}"
        )

        # Shut down the assigned operator's node so it can't publish the bridge proof
        assigned_idx = active_claim.assigned_operator
        self.logger.info(
            f"Stopping assigned operator {assigned_idx} to prevent bridge proof submission"
        )
        bridge_nodes[assigned_idx].stop()

        # Use a different operator's node to publish a contest
        contester_idx = (active_claim.assigned_operator + 1) % num_operators
        contester_node = bridge_nodes[contester_idx]
        contester_rpc_url = f"http://127.0.0.1:{contester_node.props['rpc_port']}"

        self.logger.info(f"Contesting with operator {contester_idx} via {contester_rpc_url}")
        contester_seed = read_operator_key(contester_idx).SEED

        contest_txid = dev_cli.send_contest(
            deposit_idx=active_claim.deposit_idx,
            operator_idx=active_claim.assigned_operator,
            bridge_node_url=contester_rpc_url,
            contester_node_idx=contester_idx,
            seed=contester_seed,
        )
        self.logger.info(f"Broadcasted contest_txid: {contest_txid}")
        contest_block_hash = wait_for_tx_confirmation(
            bitcoin_rpc,
            contest_txid,
            timeout=300,
        )
        self.logger.info(f"Contest tx {contest_txid} confirmed in block {contest_block_hash}")

        # Wait for the contest-proof connector (vout 0) to be spent.
        # The assigned operator is shut down, so only the proof-timeout tx can spend it.
        wait_until_utxo_spent(bitcoin_rpc, contest_txid, vout=0, timeout=600)
        self.logger.info("Contest-proof connector spent (bridge proof timed out)")

        return True
