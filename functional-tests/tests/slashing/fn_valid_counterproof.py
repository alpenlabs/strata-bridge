import re

import flexitest

from constants import (
    CONTEST_PAYOUT_VOUT,
    CONTEST_WATCHTOWER_0_VOUT,
    COUNTERPROOF_ACK_NACK_VOUT,
    COUNTERPROOF_N_DATA,
    COUNTERPROOF_WITNESS_LEN,
    SCHNORR_SIG_LEN,
)
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
    find_utxo_spender_txid,
    read_operator_key,
    snapshot_log_offsets,
    wait_for_log_capture,
    wait_for_tx_confirmation,
    wait_until,
)
from utils.withdrawal import wait_until_active_valid_claim, wait_until_bridge_proof_posted

# Emitted by the POV operator's NACK executor right before mosaic recovers the
# counterproof from the on-chain adaptor signatures and evaluates it.
EVALUATE_AND_SIGN_RE = re.compile(r"calling mosaic evaluate_and_sign")

# Emitted when mosaic successfully recovered the counterproof bytes from the
# on-chain signatures, evaluated the verifier circuit, and found the proof
# VALID — so no fault secret exists and the NACK cannot be signed.
FAULT_SECRET_UNEXTRACTABLE_RE = re.compile(
    r"evaluator failed to extract fault secret from counterproof"
)


@flexitest.register
class ValidCounterproofExtractionTest(StrataTestBase):
    """
    Test that a *valid* counterproof, recovered from its on-chain adaptor
    signatures, survives the POV operator's NACK attempt — with the operator
    fully alive.

    This is the cryptographic complement of `fn_publish_counterproof_nack.py`
    (invalid counterproof → fault secret extracted → NACK) and the live-operator
    complement of `fn_counterproof_ack.py` (which stops the operator so the NACK
    never even gets attempted). Here the NACK *is* attempted and fails only
    because the recovered proof verifies.

    The counterproof carries no proof bytes directly: each byte is encoded as a
    completed adaptor signature in the counterproof tx witness. The POV operator's
    GSM strips those signatures from the confirmed tx (`decode_completed_sigs`)
    and hands them to mosaic's `evaluate_and_sign`, which extracts the per-wire
    adaptor secrets, reconstructs the proof input wires, and evaluates the
    verifier circuit. Only an INVALID proof yields the `wt_fault` secret that
    signs the NACK.

    In native mode mosaic runs the reduced "simple" circuit: its output is the
    LSB of the deposit-input wire, which the bridge sets to the game index
    (`deposit_idx + 1`). The fault secret is extractable only when that LSB is 0
    (even game index). A single deposit (index 0 → game index 1, odd) therefore
    models a counterproof that VERIFIES — the recovery succeeds but no fault
    secret comes out. Under the SP1 env the same flow carries a real Groth16
    counterproof through the identical decode-and-judge path.

    Steps:
    1. Complete one deposit (game index 1 → "valid counterproof" in native mode).
    2. Trigger assignment; the assigned operator fulfills and posts a real claim.
    3. A different operator contests the claim.
    4. The assigned operator auto-posts its bridge proof; with NEVER_ACCEPT every
       watchtower rejects it and posts a counterproof.
    5. Assert each on-chain counterproof witness has the adaptor-signature shape
       the GSM decodes: 135 elements, the first 133 being 64-byte schnorr sigs
       (132 per-byte operator sigs + 1 N-of-N sig), then leaf script + control
       block.
    6. Assert from the live POV operator's logs that the NACK was attempted
       (`evaluate_and_sign`) and failed precisely because no fault secret was
       extractable — i.e. the recovered proof is valid.
    7. Assert the counterproof wins on-chain: after the NACK timelock a
       counterprover's ACK (not a NACK) spends the counterproof's ack/nack
       output together with the contest payout output.
    """

    def __init__(self, ctx: flexitest.InitContext):
        self.bridge_protocol_params = BridgeProtocolParams(
            contest_timelock=5,
            proof_timelock=100,  # ensure no proof timeout fires
            nack_timelock=5,
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

        # 1. Complete a single deposit: deposit index 0 → game index 1 (odd), the
        # native-mode encoding of a counterproof that verifies.
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

        # 4. Assigned operator posts a real bridge proof defending the contest;
        # NEVER_ACCEPT makes every watchtower reject it and counterproof.
        wait_until_bridge_proof_posted(bridge_rpc, active_claim.deposit_idx)
        self.logger.info("Bridge proof posted")

        # Snapshot the live POV operator's log now: every NACK attempt happens
        # after this point, once counterproofs start confirming.
        pov_idx = active_claim.assigned_operator
        pov_logfile = bridge_nodes[pov_idx].props["logfile"]
        pov_log_offsets = snapshot_log_offsets([pov_logfile])

        # 5. Each watchtower spends its contest output with a counterproof. Verify
        # the on-chain witness has exactly the adaptor-signature layout that the
        # POV's GSM decodes the proof from.
        num_watchtowers = num_operators - 1
        counterproof_txids = []
        for slot in range(num_watchtowers):
            watchtower_vout = CONTEST_WATCHTOWER_0_VOUT + slot
            wait_until_utxo_spent(bitcoin_rpc, contest_txid, watchtower_vout, timeout=300)
            counterproof_txid = find_utxo_spender_txid(bitcoin_rpc, contest_txid, watchtower_vout)
            counterproof_txids.append(counterproof_txid)
            self.assert_counterproof_witness_shape(bitcoin_rpc, counterproof_txid)
            self.logger.info(
                f"Watchtower slot {slot} counterproof {counterproof_txid} carries "
                f"{COUNTERPROOF_N_DATA} per-byte adaptor signatures on-chain"
            )

        # 6. The live POV operator attempts the NACK: mosaic recovers the proof
        # from the on-chain signatures and evaluates it...
        wait_for_log_capture(
            pov_logfile,
            EVALUATE_AND_SIGN_RE,
            log_offsets=pov_log_offsets,
            timeout=300,
            error_msg="POV operator never called mosaic evaluate_and_sign",
        )
        self.logger.info("POV operator started mosaic evaluate_and_sign (proof recovery)")

        # ...and the verdict is VALID: recovery succeeded but no fault secret
        # exists, so the NACK cannot be signed. A recovery failure would surface
        # as a different mosaic error, not this message.
        wait_for_log_capture(
            pov_logfile,
            FAULT_SECRET_UNEXTRACTABLE_RE,
            log_offsets=pov_log_offsets,
            timeout=300,
            error_msg="POV operator never reported the fault secret as unextractable",
        )
        self.logger.info(
            "POV operator recovered the counterproof from adaptors and could not refute it "
            "(no fault secret) — the proof is valid"
        )

        # 7. With no NACK possible, a counterprover's ACK wins after the NACK
        # timelock: it spends the contest payout output together with one
        # counterproof's ack/nack output. (A NACK would be a 1-input spend of
        # the ack/nack output alone; the 2-input shape proves an ACK.)
        wait_until_utxo_spent(bitcoin_rpc, contest_txid, CONTEST_PAYOUT_VOUT, timeout=600)
        ack_txid = find_utxo_spender_txid(bitcoin_rpc, contest_txid, CONTEST_PAYOUT_VOUT)

        ack_tx = bitcoin_rpc.proxy.getrawtransaction(ack_txid, True)
        ack_inputs = [(vin["txid"], vin["vout"]) for vin in ack_tx.get("vin", [])]
        assert len(ack_inputs) == 2, (
            f"ACK candidate {ack_txid} must have 2 inputs, got {len(ack_inputs)}: {ack_inputs}"
        )
        contest_input = (contest_txid, CONTEST_PAYOUT_VOUT)
        assert contest_input in ack_inputs, (
            f"ACK candidate {ack_txid} does not spend contest payout {contest_input}"
        )
        ((cp_txid, cp_vout),) = [inp for inp in ack_inputs if inp != contest_input]
        assert cp_vout == COUNTERPROOF_ACK_NACK_VOUT, (
            f"ACK candidate's other input is {cp_txid}:{cp_vout}, "
            f"expected vout {COUNTERPROOF_ACK_NACK_VOUT}"
        )
        assert cp_txid in counterproof_txids, (
            f"ACK candidate's other input {cp_txid} is not one of the observed "
            f"counterproofs {counterproof_txids}"
        )

        self.logger.info(
            f"Counterproof ACK {ack_txid} confirmed with the POV operator alive — "
            f"the valid counterproof survived the NACK attempt"
        )

        return True

    def assert_counterproof_witness_shape(self, bitcoin_rpc, counterproof_txid: str):
        """Asserts the counterproof witness is exactly the adaptor-signature encoding.

        Layout (witness order): 132 per-byte operator signatures, the N-of-N
        signature, the leaf script, and the control block. The first 133 elements
        must each be a 64-byte schnorr signature (default sighash, no flag byte).
        """
        tx = bitcoin_rpc.proxy.getrawtransaction(counterproof_txid, True)
        vin = tx.get("vin", [])
        assert len(vin) == 1, f"counterproof {counterproof_txid} must have 1 input, got {len(vin)}"

        witness = vin[0].get("txinwitness", [])
        assert len(witness) == COUNTERPROOF_WITNESS_LEN, (
            f"counterproof {counterproof_txid} witness has {len(witness)} elements, "
            f"expected {COUNTERPROOF_WITNESS_LEN}"
        )

        # 132 per-byte operator signatures + 1 N-of-N signature.
        for i, element in enumerate(witness[: COUNTERPROOF_N_DATA + 1]):
            assert len(element) == 2 * SCHNORR_SIG_LEN, (
                f"counterproof {counterproof_txid} witness[{i}] is {len(element) // 2} bytes, "
                f"expected a {SCHNORR_SIG_LEN}-byte schnorr signature"
            )
