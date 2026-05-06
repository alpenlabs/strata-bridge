import flexitest

from constants import CONTEST_WATCHTOWER_0_VOUT
from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import BridgeProtocolParams, ProofPredicate
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
from utils.withdrawal import wait_until_active_valid_claim, wait_until_bridge_proof_posted


@flexitest.register
class CounterproofPublishedOnBridgeProofVerificationFailureTest(StrataTestBase):
    """
    Test that every watchtower publishes a counterproof when the bridge proof is invalid.

    NEVER_ACCEPT forces every watchtower to reject the bridge proof regardless of its
    content, so the counterproof step is what's under test.

    1. Complete a deposit.
    2. Post a mock checkpoint so ASM produces an assignment; the assigned operator
       fulfills and posts a real claim.
    3. A different operator dev-cli-contests the claim.
    4. Assigned operator generates a bridge proof.
    5. Every watchtower auto-publishes a counterproof because the predicate is
       NEVER_ACCEPT. Verified by asserting every watchtower's counterproof output
       on the contest tx is spent.
    """

    def __init__(self, ctx: flexitest.InitContext):
        self.bridge_protocol_params = BridgeProtocolParams(
            contest_timelock=5,
            proof_timelock=100,
            bridge_proof_predicate=ProofPredicate.NEVER_ACCEPT,
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
        bridge_rpc = bridge_rpcs[0]

        bitcoind_service = ctx.get_service("bitcoin")
        bitcoin_rpc = bitcoind_service.create_rpc()

        asm_service = ctx.get_service("asm_rpc")
        asm_rpc = asm_service.create_rpc()

        num_operators = len(bridge_nodes)
        operator_key_infos = [read_operator_key(i) for i in range(num_operators)]

        bitcoind_props = bitcoind_service.props
        dev_cli = DevCli(
            bitcoind_props,
            operator_key_infos,
            bridge_protocol_params=self.bridge_protocol_params,
        )

        # 1. Complete a deposit.
        drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted DRT: {drt_txid}")
        deposit_id = wait_until_drt_recognized(bridge_rpc, drt_txid)
        self.logger.info(f"DRT recognized, deposit_id: {deposit_id}")

        deposit_info = wait_until_deposit_status(bridge_rpc, deposit_id, RpcDepositStatusComplete)
        assert deposit_info is not None, "Deposit did not complete"
        self.logger.info("Deposit completed")

        # 2. Trigger assignment via mock checkpoint; orchestrator fulfills + claims.
        recent_block_hash = bitcoin_rpc.proxy.getblockhash(bitcoin_rpc.proxy.getblockcount())
        ckp_l1_txn = dev_cli.send_mock_checkpoint_from_tip(
            asm_rpc,
            recent_block_hash,
            num_ol_slots=1,
        )
        ckp_block_hash = wait_for_tx_confirmation(bitcoin_rpc, ckp_l1_txn)
        self.logger.info(f"Checkpoint tx {ckp_l1_txn} included in block {ckp_block_hash}")

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

        # 3. Contest from a different operator (a watchtower).
        contester_idx = (active_claim.assigned_operator + 1) % num_operators
        contester_node = bridge_nodes[contester_idx]
        contester_rpc_url = f"http://127.0.0.1:{contester_node.props['rpc_port']}"
        contester_seed = read_operator_key(contester_idx).SEED

        self.logger.info(f"Contesting with operator {contester_idx} via {contester_rpc_url}")
        contest_txid = dev_cli.send_contest(
            deposit_idx=active_claim.deposit_idx,
            operator_idx=active_claim.assigned_operator,
            bridge_node_url=contester_rpc_url,
            contester_node_idx=contester_idx,
            seed=contester_seed,
        )
        contest_block_hash = wait_for_tx_confirmation(bitcoin_rpc, contest_txid, timeout=300)
        self.logger.info(f"Contest tx {contest_txid} confirmed in block {contest_block_hash}")

        # 4. Assigned operator posts a real bridge proof defending the contest.
        wait_until_bridge_proof_posted(bridge_rpc, active_claim.deposit_idx)
        self.logger.info("Bridge proof posted")

        # 5. Every watchtower must publish its counterproof. The contest tx has one
        # counterproof output per watchtower starting at WATCHTOWER_0_VOUT.
        num_watchtowers = num_operators - 1
        for slot in range(num_watchtowers):
            watchtower_vout = CONTEST_WATCHTOWER_0_VOUT + slot
            wait_until_utxo_spent(bitcoin_rpc, contest_txid, watchtower_vout, timeout=300)
            self.logger.info(
                f"Counterproof posted by watchtower slot {slot} (contest:{watchtower_vout} spent)"
            )

        return True
