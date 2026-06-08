import flexitest

from constants import (
    CONTEST_WATCHTOWER_0_VOUT,
    COUNTERPROOF_ACK_NACK_VOUT,
)
from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import BridgeProtocolParams
from rpc.types import RpcDepositStatusComplete
from utils.bridge import get_bridge_nodes_and_rpcs
from utils.deposit import (
    wait_until_deposit_status,
    wait_until_deposit_utxo_spent,
    wait_until_drts_recognized,
    wait_until_utxo_spent,
)
from utils.dev_cli import DevCli
from utils.utils import (
    find_utxo_spender_txid,
    read_operator_key,
    wait_for_tx_confirmation,
    wait_until,
)
from utils.withdrawal import (
    wait_until_bridge_proof_posted,
    wait_until_claim_posted,
    wait_until_counter_proof_posted,
)


@flexitest.register
class CounterproofNackPublishedOnInvalidCounterproofTest(StrataTestBase):
    """
    Test that the POV operator publishes a counterproof NACK after watchtowers post a
    counterproof, and the contested payout path completes end-to-end.

    The bridge proof predicate is set to `NeverAccept` so every bridge proof fails
    verification and watchtowers respond with a counterproof. The POV operator then
    runs the mosaic-backed `evaluate_and_sign` flow and publishes a counterproof NACK
    transaction. Once the NACKs and contested payout confirm, the deposit UTXO is spent.

    Two deposits are created and the *second* one (deposit index 1) is contested. In
    native proving mode the mosaic node runs the bundled "simple" garbled circuit whose
    output is just the LSB of the deposit-input wire, and the bridge sets that wire to the
    game index (`deposit_idx + 1`). The POV operator can only extract the fault secret
    (and therefore sign the NACK) when that LSB is 0 — i.e. when the game index is even.
    Deposit index 1 → game index 2 (even) satisfies this; deposit index 0 → game index 1
    (odd) never would.

    Steps:
    1. Complete two deposits
    2. Assign a withdrawal to each, then contest the active claim on deposit index 1
    3. Wait for the bridge proof to be posted
    4. Wait for the counterproof to be posted by watchtowers
    5. Verify the deposit UTXO is spent after the NACK + contested-payout path completes
    """

    def __init__(self, ctx: flexitest.InitContext):
        self.bridge_protocol_params = BridgeProtocolParams(
            contest_timelock=5,
            bridge_proof_predicate="NeverAccept",
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

        num_operators = len(bridge_nodes)
        operator_key_infos = [read_operator_key(i) for i in range(num_operators)]

        # Init ASM rpc
        asm_service = ctx.get_service("asm_rpc")
        asm_rpc = asm_service.create_rpc()

        # Wait for DT and DRT
        bitcoind_props = bitcoind_service.props
        dev_cli = DevCli(
            bitcoind_props,
            operator_key_infos,
            bridge_protocol_params=self.bridge_protocol_params,
        )

        # Contest the second deposit (index 1 → game index 2, even) so the POV operator's
        # native-mode mosaic evaluation can extract the fault secret and sign the NACK.
        contested_deposit_idx = 1

        drt_txids = [dev_cli.send_deposit_request() for _ in range(2)]
        for i, drt_txid in enumerate(drt_txids):
            self.logger.info(f"Broadcasted DRT[{i}]: {drt_txid}")

        deposit_ids = wait_until_drts_recognized(bridge_rpc, drt_txids)
        self.logger.info(f"DRTs recognized, deposit_ids: {deposit_ids}")

        # Complete both deposits so the ASM can assign a withdrawal to each. Capture the
        # contested deposit's txid — that is the UTXO we expect to be swept at the end.
        contested_deposit_txid = None
        for deposit_id in sorted(deposit_ids):
            deposit_info = wait_until_deposit_status(
                bridge_rpc, deposit_id, RpcDepositStatusComplete
            )
            assert deposit_info is not None, f"Deposit {deposit_id} did not complete"
            if deposit_id == contested_deposit_idx:
                contested_deposit_txid = deposit_info.get("status").get("deposit_txid")
        assert contested_deposit_txid is not None, (
            f"contested deposit {contested_deposit_idx} did not complete"
        )
        self.logger.info("Both deposits completed")
        self.logger.info(
            f"Contesting deposit {contested_deposit_idx}, txid: {contested_deposit_txid}"
        )

        # Now post mock checkpoint so that a withdrawal is assigned
        recent_block_hash = bitcoin_rpc.proxy.getblockhash(bitcoin_rpc.proxy.getblockcount())
        # One checkpoint creating two withdrawal commands. The ASM assigns the oldest
        # unassigned deposit first, so this yields one assignment per deposit (indices 0
        # and 1).
        ckp_l1_txn = dev_cli.send_mock_checkpoint_from_tip(
            asm_rpc,
            recent_block_hash,
            num_ol_slots=1,
            num_withdrawals=2,
        )
        ckp_block_hash = wait_for_tx_confirmation(bitcoin_rpc, ckp_l1_txn)
        self.logger.info(f"Checkpoint tx {ckp_l1_txn} included in block {ckp_block_hash}")

        # Wait for ASM to process the checkpoint, then wait for the contested deposit's claim
        wait_until(
            lambda: len(asm_rpc.strata_asm_getAssignments(ckp_block_hash)) >= 2,
            timeout=300,
            error_msg="ASM did not produce assignments",
        )

        # Two withdrawals are in flight, so target the contested deposit directly (rather than
        # assuming a single pending withdrawal).
        active_claim = wait_until_claim_posted(bridge_rpc, contested_deposit_idx)
        assigned_operator = active_claim.assigned_operator
        claim_txid = active_claim.claim_txid
        self.logger.info(
            "Active claim %s for deposit %s assigned to operator %s",
            claim_txid,
            contested_deposit_idx,
            assigned_operator,
        )

        claim_block_hash = wait_for_tx_confirmation(
            bitcoin_rpc,
            claim_txid,
            timeout=300,
        )
        self.logger.info(f"Claim tx {claim_txid} confirmed in block {claim_block_hash}")

        # Use a different operator's node to contest
        contester_idx = (assigned_operator + 1) % num_operators
        contester_node = bridge_nodes[contester_idx]
        contester_rpc_url = f"http://127.0.0.1:{contester_node.props['rpc_port']}"

        self.logger.info(f"Contesting with operator {contester_idx} via {contester_rpc_url}")
        contester_seed = read_operator_key(contester_idx).SEED

        contest_txid = dev_cli.send_contest(
            deposit_idx=contested_deposit_idx,
            operator_idx=assigned_operator,
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

        # The POV (assigned) operator's RPC observes the full game and emits the NACK duty.
        pov_rpc = bridge_rpcs[assigned_operator]

        # Wait for bridge proof to be posted by the assigned operator
        wait_until_bridge_proof_posted(pov_rpc, contested_deposit_idx)
        self.logger.info("Bridge proof posted")

        # With NeverAccept predicate, watchtowers reject the proof and publish counterproofs.
        wait_until_counter_proof_posted(pov_rpc, contested_deposit_idx)
        self.logger.info("Counterproof posted — watchtowers rejected the invalid bridge proof")

        # Each watchtower spends one of contest's watchtower outputs with its counterproof.
        # The POV operator then publishes a NACK that spends each counterproof's ack/nack output.
        # Verify every watchtower's counterproof had its ack/nack output spent before asserting
        # the deposit was swept.
        num_watchtowers = num_operators - 1
        for slot in range(num_watchtowers):
            watchtower_vout = CONTEST_WATCHTOWER_0_VOUT + slot
            wait_until_utxo_spent(bitcoin_rpc, contest_txid, watchtower_vout, timeout=300)
            counterproof_txid = find_utxo_spender_txid(bitcoin_rpc, contest_txid, watchtower_vout)
            self.logger.info(f"Watchtower slot {slot} counterproof tx: {counterproof_txid}")
            wait_until_utxo_spent(
                bitcoin_rpc,
                counterproof_txid,
                COUNTERPROOF_ACK_NACK_VOUT,
                timeout=300,
            )
            self.logger.info(
                f"Counterproof {counterproof_txid} ack/nack output spent (NACK published)"
            )

        # The ack/nack vout we checked above could've been spent by either an ACK or a NACK,
        # so seeing it spent isn't enough on its own. Waiting for the deposit to get swept is
        # what tells us the NACK actually fired — only the contested-payout path gets there.
        wait_until_deposit_utxo_spent(bitcoin_rpc, contested_deposit_txid, timeout=450)
        self.logger.info("Deposit UTXO confirmed spent after counterproof NACK + contested payout")

        return True
