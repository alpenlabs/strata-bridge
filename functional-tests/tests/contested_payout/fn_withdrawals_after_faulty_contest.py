from typing import Any, cast

import flexitest

from constants import CONTEST_WATCHTOWER_0_VOUT, COUNTERPROOF_ACK_NACK_VOUT
from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import BridgeProtocolParams
from rpc.types import RpcDepositStatusComplete
from utils.bridge import bridge_rpc_url, get_bridge_nodes_and_rpcs
from utils.covenant import get_current_covenant
from utils.deposit import (
    wait_until_deposit_status,
    wait_until_deposit_utxo_spent,
    wait_until_drts_recognized,
    wait_until_utxo_spent,
)
from utils.dev_cli import DevCli
from utils.utils import (
    find_utxo_spender_txid,
    read_all_operator_keys,
    wait_for_tx_confirmation,
)
from utils.withdrawal import (
    fulfill_withdrawal,
    tx_inputs,
    wait_until_bridge_proof_posted,
    wait_until_claim_posted,
    wait_until_counter_proof_posted,
    wait_until_paid_out,
)

CLAIMANT = 0
CONTESTER = 1

# Game index `deposit_idx + 1` must be even for the native-mode garbled circuit to let the
# claimant extract the fault secret and NACK, so the contested deposit has an odd index.
CONTESTED_DEPOSIT_IDX = 1
CLAIMANT_DEPOSIT_IDX = 2
CONTESTER_DEPOSIT_IDX = 3
NUM_DEPOSITS = 4


@flexitest.register
class WithdrawalsAfterFaultyContestTest(StrataTestBase):
    """
    Test that both sides of a faulty contest keep withdrawing through claims afterwards.

    The bridge proof predicate is `NeverAccept`, so every watchtower counterproofs the contested
    claim's bridge proof and the claimant NACKs each counterproof. That consumes the claimant's
    evaluator setup with every watchtower, and the contester's garbler setup with the claimant.

    Steps:
    1. Complete four deposits. Every deposit's graphs exist before the contest, since a consumed
       setup cannot serve new deposits.
    2. Withdraw deposits 0 and 1 through the claimant, and contest its honest claim on deposit 1
       from the contester.
    3. Wait for every counterproof to be NACKed and the contested payout to sweep deposit 1.
    4. Withdraw deposit 2 through the claimant and deposit 3 through the contester; each
       assignee's own claim must pay it out.
    """

    def __init__(self, ctx: flexitest.InitContext):
        self.bridge_protocol_params = BridgeProtocolParams(
            contest_timelock=5,
            bridge_proof_predicate="NeverAccept",
        )
        ctx.set_env(
            BridgeNetworkEnv(
                bridge_protocol_params=self.bridge_protocol_params,
                bridge_config_params=BridgeConfigParams(cooperative_payout_timeout=0),
            )
        )

    def main(self, ctx: flexitest.RunContext):
        bridge_nodes, bridge_rpcs = get_bridge_nodes_and_rpcs(ctx)
        bridge_rpc = bridge_rpcs[CLAIMANT]

        bitcoind_service = ctx.get_service("bitcoin")
        bitcoin_rpc = bitcoind_service.create_rpc()
        asm_rpc = ctx.get_service("asm_rpc").create_rpc()

        num_operators = len(bridge_nodes)
        operator_keys = read_all_operator_keys()[:num_operators]
        dev_cli = DevCli(
            bitcoind_service.props,
            operator_keys,
            bridge_protocol_params=self.bridge_protocol_params,
        )

        drt_txids = [
            dev_cli.send_deposit_request(bridge_rpc_url(bridge_nodes[CLAIMANT]))
            for _ in range(NUM_DEPOSITS)
        ]
        deposit_ids = wait_until_drts_recognized(bridge_rpc, drt_txids)
        assert sorted(deposit_ids) == list(range(NUM_DEPOSITS)), (
            f"expected deposits 0 to {NUM_DEPOSITS - 1}, got {deposit_ids}"
        )
        deposit_txids = {
            deposit_idx: str(
                cast(
                    "dict[str, Any]",
                    wait_until_deposit_status(bridge_rpc, deposit_idx, RpcDepositStatusComplete),
                )["status"]["deposit_txid"]
            )
            for deposit_idx in range(NUM_DEPOSITS)
        }
        self.logger.info(f"Deposits completed: {deposit_txids}")

        genesis_height = get_current_covenant(bridge_rpc).covenant.activation_height

        self.logger.info(
            f"Faulty contest: operator {CONTESTER} contests operator {CLAIMANT}'s honest claim "
            f"on deposit {CONTESTED_DEPOSIT_IDX}"
        )
        tip_hash = bitcoin_rpc.proxy.getblockhash(bitcoin_rpc.proxy.getblockcount())
        # The ASM assigns the oldest unassigned deposits first: deposits 0 and 1.
        checkpoint_txid = dev_cli.send_mock_checkpoint_from_tip(
            asm_rpc,
            tip_hash,
            num_ol_slots=1,
            num_withdrawals=2,
            assignee_node_idx=CLAIMANT,
            genesis_l1_height=genesis_height,
        )
        wait_for_tx_confirmation(bitcoin_rpc, checkpoint_txid)

        claim = wait_until_claim_posted(bridge_rpc, CONTESTED_DEPOSIT_IDX)
        assert claim.assigned_operator == CLAIMANT, (
            f"operator {CLAIMANT} must claim deposit {CONTESTED_DEPOSIT_IDX}, got {claim}"
        )
        wait_for_tx_confirmation(bitcoin_rpc, claim.claim_txid, timeout=300)

        contester_node = bridge_nodes[CONTESTER]
        contest_txid = dev_cli.send_contest(
            deposit_idx=CONTESTED_DEPOSIT_IDX,
            operator_idx=CLAIMANT,
            bridge_node_url=f"http://127.0.0.1:{contester_node.props['rpc_port']}",
            contester_node_idx=CONTESTER,
            seed=operator_keys[CONTESTER].SEED,
        )
        wait_for_tx_confirmation(bitcoin_rpc, contest_txid, timeout=300)
        self.logger.info(f"Contest {contest_txid} confirmed")

        wait_until_bridge_proof_posted(bridge_rpc, CONTESTED_DEPOSIT_IDX)
        wait_until_counter_proof_posted(bridge_rpc, CONTESTED_DEPOSIT_IDX)
        for slot in range(num_operators - 1):
            watchtower_vout = CONTEST_WATCHTOWER_0_VOUT + slot
            wait_until_utxo_spent(bitcoin_rpc, contest_txid, watchtower_vout, timeout=300)
            counterproof_txid = find_utxo_spender_txid(bitcoin_rpc, contest_txid, watchtower_vout)
            wait_until_utxo_spent(
                bitcoin_rpc, counterproof_txid, COUNTERPROOF_ACK_NACK_VOUT, timeout=300
            )
            self.logger.info(f"Counterproof {counterproof_txid} answered")
        # Only the contested payout after a NACK sweeps the deposit; an ACK would slash instead.
        wait_until_deposit_utxo_spent(
            bitcoin_rpc, deposit_txids[CONTESTED_DEPOSIT_IDX], timeout=450
        )
        self.logger.info(f"Contested payout swept deposit {CONTESTED_DEPOSIT_IDX}")

        def withdraw_through_claim(deposit_idx: int, assignee: int):
            self.logger.info(f"Withdrawing deposit {deposit_idx} through operator {assignee}")
            fulfill_withdrawal(
                dev_cli,
                asm_rpc,
                bitcoin_rpc,
                bridge_rpcs[assignee],
                deposit_idx,
                assignee,
                genesis_height,
            )
            claim = wait_until_claim_posted(bridge_rpcs[assignee], deposit_idx)
            assert claim.assigned_operator == assignee, (
                f"operator {assignee} must claim deposit {deposit_idx}, got {claim}"
            )
            payout_txid = wait_until_paid_out(
                bitcoin_rpc,
                deposit_txids[deposit_idx],
                deposit_idx,
                assignee,
                operator_keys[assignee].GENERAL_WALLET,
            )
            payout_inputs = tx_inputs(bitcoin_rpc, payout_txid)
            assert any(txid == claim.claim_txid for txid, _ in payout_inputs), (
                f"payout {payout_txid} must spend claim {claim.claim_txid}, spent {payout_inputs}"
            )

        withdraw_through_claim(CLAIMANT_DEPOSIT_IDX, CLAIMANT)
        withdraw_through_claim(CONTESTER_DEPOSIT_IDX, CONTESTER)

        # Deposit 0's withdrawal was assigned with deposit 1's; its claim pays out uncontested.
        wait_until_deposit_utxo_spent(bitcoin_rpc, deposit_txids[0], timeout=300)

        return True
