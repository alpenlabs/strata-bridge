import logging
from dataclasses import dataclass

from constants import (
    CLAIM_CONTEST_VOUT,
    CLAIM_PAYOUT_VOUT,
    CONTEST_PAYOUT_VOUT,
    CONTEST_SLASH_VOUT,
    CONTEST_WATCHTOWER_0_VOUT,
    COUNTERPROOF_ACK_NACK_VOUT,
    DT_DEPOSIT_VOUT,
)
from rpc.asm_types import AssignmentEntry
from rpc.types import RpcClaimPhase, RpcPendingWithdrawalInfo
from utils.deposit import wait_until_utxo_spent
from utils.utils import find_utxo_spender_txid, wait_for_tx_confirmation, wait_until


def tx_inputs(bitcoin_rpc, txid: str) -> list[tuple[str, int]]:
    """The (txid, vout) outpoints a confirmed or mempool tx spends."""
    tx = bitcoin_rpc.proxy.getrawtransaction(txid, True)
    return [(vin["txid"], vin["vout"]) for vin in tx.get("vin", [])]


def _spender_inputs(bitcoin_rpc, txid: str, vout: int) -> tuple[str, list[tuple[str, int]]]:
    """The tx spending `txid:vout`, and the outpoints it spends."""
    spender_txid = find_utxo_spender_txid(bitcoin_rpc, txid, vout)
    return spender_txid, tx_inputs(bitcoin_rpc, spender_txid)


@dataclass
class PendingWithdrawalClaim:
    """The active claim currently associated with the assigned operator."""

    deposit_idx: int
    assigned_operator: int
    claim_txid: str


def wait_until_active_valid_claim(
    bridge_rpc,
    timeout=300,
) -> PendingWithdrawalClaim:
    """Wait until the assigned operator for the only pending withdrawal has an active claim."""

    result: dict[str, PendingWithdrawalClaim | None] = {"active_claim": None}

    def check_pending_withdrawal():
        pending_withdrawals: list[int] = bridge_rpc.stratabridge_pendingWithdrawals()
        logging.info(f"Current pending withdrawals: {pending_withdrawals}")

        if len(pending_withdrawals) != 1:
            return False

        deposit_idx = pending_withdrawals[0]
        pending_withdrawal_data = bridge_rpc.stratabridge_pendingWithdrawalInfo(deposit_idx)
        logging.info(f"Pending withdrawal info for {deposit_idx}: {pending_withdrawal_data}")

        if pending_withdrawal_data is None:
            return False

        pending_withdrawal = RpcPendingWithdrawalInfo.from_json(pending_withdrawal_data)
        if pending_withdrawal.assigned_claim is None:
            return False

        result["active_claim"] = PendingWithdrawalClaim(
            deposit_idx=deposit_idx,
            assigned_operator=pending_withdrawal.assigned_operator,
            claim_txid=pending_withdrawal.assigned_claim.claim_txid,
        )
        return True

    wait_until(
        check_pending_withdrawal,
        timeout=timeout,
        step=1,
        error_msg=(
            f"Timeout after {timeout} seconds waiting for the assigned operator active claim"
        ),
    )

    assert result["active_claim"] is not None
    return result["active_claim"]


def wait_until_claim_posted(
    bridge_rpc,
    deposit_idx: int,
    timeout=300,
) -> PendingWithdrawalClaim:
    """Wait until the operator assigned to `deposit_idx` has posted an active claim.

    Targets a specific deposit, so unlike [`wait_until_active_valid_claim`] it works when
    several withdrawals are pending at once.
    """
    result: dict[str, PendingWithdrawalClaim | None] = {"active_claim": None}

    def check_claim_posted():
        data = bridge_rpc.stratabridge_pendingWithdrawalInfo(deposit_idx)
        logging.info(f"Pending withdrawal info for {deposit_idx}: {data}")

        if data is None:
            return False

        pending_withdrawal = RpcPendingWithdrawalInfo.from_json(data)
        if pending_withdrawal.assigned_claim is None:
            return False

        result["active_claim"] = PendingWithdrawalClaim(
            deposit_idx=deposit_idx,
            assigned_operator=pending_withdrawal.assigned_operator,
            claim_txid=pending_withdrawal.assigned_claim.claim_txid,
        )
        return True

    wait_until(
        check_claim_posted,
        timeout=timeout,
        step=1,
        error_msg=(
            f"Timeout after {timeout} seconds waiting for deposit {deposit_idx} active claim"
        ),
    )

    assert result["active_claim"] is not None
    return result["active_claim"]


def _wait_until_claim_phase(bridge_rpc, deposit_idx: int, phase: RpcClaimPhase, timeout) -> None:
    def check():
        info_data = bridge_rpc.stratabridge_pendingWithdrawalInfo(deposit_idx)
        if info_data is None:
            return False
        info = RpcPendingWithdrawalInfo.from_json(info_data)
        return info.assigned_claim is not None and info.assigned_claim.phase == phase

    wait_until(
        check,
        timeout=timeout,
        step=1,
        error_msg=f"Claim phase for deposit {deposit_idx} did not advance to {phase.value}",
    )


def wait_until_bridge_proof_posted(bridge_rpc, deposit_idx: int, timeout=450) -> None:
    _wait_until_claim_phase(bridge_rpc, deposit_idx, RpcClaimPhase.BRIDGE_PROOF_POSTED, timeout)


def wait_until_counter_proof_posted(bridge_rpc, deposit_idx: int, timeout=450) -> None:
    _wait_until_claim_phase(bridge_rpc, deposit_idx, RpcClaimPhase.COUNTER_PROOF_POSTED, timeout)


def wait_until_counterproof_ack(bitcoin_rpc, contest_txid: str, timeout=600) -> str:
    """Wait until the contest payout output is spent, verify the spender has the
    counterproof-ACK shape, and return its txid.

    An ACK has exactly two inputs: the contest payout output and a counterproof's
    ACK_NACK output, where the counterproof is itself a single-input tx spending one of
    the contest's per-watchtower outputs. Backtracking through the inputs rules out
    false positives where another tx (e.g. `contested_payout`) spends the contest
    payout output.
    """
    wait_until_utxo_spent(bitcoin_rpc, contest_txid, CONTEST_PAYOUT_VOUT, timeout=timeout)
    ack_txid, ack_inputs = _spender_inputs(bitcoin_rpc, contest_txid, CONTEST_PAYOUT_VOUT)
    assert len(ack_inputs) == 2, (
        f"ACK candidate {ack_txid} must have 2 inputs, got {len(ack_inputs)}: {ack_inputs}"
    )
    contest_input = (contest_txid, CONTEST_PAYOUT_VOUT)
    assert contest_input in ack_inputs, (
        f"ACK candidate {ack_txid} does not spend contest payout {contest_input}"
    )
    ((counterproof_txid, counterproof_vout),) = [inp for inp in ack_inputs if inp != contest_input]
    assert counterproof_vout == COUNTERPROOF_ACK_NACK_VOUT, (
        f"ACK candidate's other input is {counterproof_txid}:{counterproof_vout}, "
        f"expected vout {COUNTERPROOF_ACK_NACK_VOUT}"
    )

    cp_inputs = tx_inputs(bitcoin_rpc, counterproof_txid)
    assert len(cp_inputs) == 1, (
        f"counterproof candidate {counterproof_txid} must have 1 input, got {len(cp_inputs)}"
    )
    cp_in_txid, cp_in_vout = cp_inputs[0]
    assert cp_in_txid == contest_txid and cp_in_vout >= CONTEST_WATCHTOWER_0_VOUT, (
        f"counterproof candidate {counterproof_txid} spends {cp_in_txid}:{cp_in_vout}, "
        f"expected contest:{CONTEST_WATCHTOWER_0_VOUT}+"
    )

    logging.info(
        f"Counterproof ACK {ack_txid} spends counterproof:{COUNTERPROOF_ACK_NACK_VOUT}="
        f"{counterproof_txid}:{counterproof_vout} + contest:{CONTEST_PAYOUT_VOUT}; "
        f"counterproof spends contest:{cp_in_vout}"
    )
    return ack_txid


def wait_until_bridge_proof_timedout(bridge_rpc, deposit_idx: int, timeout=600) -> None:
    _wait_until_claim_phase(bridge_rpc, deposit_idx, RpcClaimPhase.BRIDGE_PROOF_TIMEDOUT, timeout)


def wait_until_counterproof_nack(bitcoin_rpc, counterproof_txid: str, timeout=600) -> str:
    """Wait until a counterproof's ACK/NACK output is spent, verify the spender has the
    NACK shape, and return its txid.

    NACK and ACK race for the same output, so shape is what tells them apart — never
    timing. A NACK is the graph owner's immediate key-path spend under `wt_i_fault` and
    has exactly ONE input, the counterproof's ACK/NACK output. An ACK is the
    counterprover's CSV `nack_timelock` script-path spend and has TWO, that same output
    plus the contest payout output.
    """
    wait_until_utxo_spent(
        bitcoin_rpc, counterproof_txid, COUNTERPROOF_ACK_NACK_VOUT, timeout=timeout
    )
    nack_txid, nack_inputs = _spender_inputs(
        bitcoin_rpc, counterproof_txid, COUNTERPROOF_ACK_NACK_VOUT
    )
    assert len(nack_inputs) == 1, (
        f"NACK candidate {nack_txid} must have exactly 1 input, got {len(nack_inputs)}: "
        f"{nack_inputs}. Two inputs means the counterproof was ACKed, not NACKed"
    )
    logging.info(
        f"Counterproof NACK {nack_txid} spends {counterproof_txid}:{COUNTERPROOF_ACK_NACK_VOUT}"
    )
    return nack_txid


def wait_until_all_nackd(bridge_rpc, deposit_idx: int, timeout=600) -> None:
    """The state machine only enters 'all_nackd' once *every* watchtower slot's counterproof
    has been NACKed, so this is the single check that no counterproof slipped through."""
    _wait_until_claim_phase(bridge_rpc, deposit_idx, RpcClaimPhase.ALL_NACKD, timeout)


def assert_contested_payout_shape(
    bitcoin_rpc,
    contested_payout_txid: str,
    *,
    deposit_txid: str,
    claim_txid: str,
    contest_txid: str,
) -> None:
    """Assert the tx is a `contested_payout`: exactly four inputs, being the deposit UTXO,
    the claim payout output, and the contest's payout and slash outputs.

    Checking all four rules out both alternatives that could otherwise spend the contest
    payout output: a `counterproof_ack` (2 inputs) and a `slash` (which would take the
    contest slash output instead).
    """
    inputs = tx_inputs(bitcoin_rpc, contested_payout_txid)
    expected = {
        (deposit_txid, DT_DEPOSIT_VOUT),
        (claim_txid, CLAIM_PAYOUT_VOUT),
        (contest_txid, CONTEST_PAYOUT_VOUT),
        (contest_txid, CONTEST_SLASH_VOUT),
    }
    assert len(inputs) == 4, (
        f"contested_payout candidate {contested_payout_txid} must have 4 inputs, "
        f"got {len(inputs)}: {inputs}"
    )
    assert set(inputs) == expected, (
        f"contested_payout candidate {contested_payout_txid} spends {sorted(inputs)}, "
        f"expected {sorted(expected)}"
    )

    logging.info(f"Contested payout {contested_payout_txid} has the expected 4-input shape")


def assert_contest_shape(bitcoin_rpc, claim_txid: str, num_watchtowers: int) -> str:
    """Assert the tx spending the claim contest output is a `contest` and return its txid.

    A `contest` spends only the claim contest output and carries the proof, payout and
    slash outputs, one counterproof output per watchtower, and the CPFP anchor. The other
    spender of that output, an `uncontested_payout`, takes the claim contest and payout
    outputs together and has a different output count.
    """
    contest_txid, inputs = _spender_inputs(bitcoin_rpc, claim_txid, CLAIM_CONTEST_VOUT)
    assert inputs == [(claim_txid, CLAIM_CONTEST_VOUT)], (
        f"contest candidate {contest_txid} must spend exactly {claim_txid}:{CLAIM_CONTEST_VOUT}, "
        f"got {inputs}"
    )
    n_out = len(bitcoin_rpc.proxy.getrawtransaction(contest_txid, True)["vout"])
    expected_out = CONTEST_WATCHTOWER_0_VOUT + num_watchtowers + 1
    assert n_out == expected_out, (
        f"contest candidate {contest_txid} must have {expected_out} outputs "
        f"for {num_watchtowers} watchtowers, got {n_out}"
    )

    logging.info(f"Contest {contest_txid} spends claim:{CLAIM_CONTEST_VOUT} with {n_out} outputs")
    return contest_txid


def fulfill_withdrawal(
    dev_cli,
    asm_rpc,
    bitcoin_rpc,
    assignee_rpc,
    deposit_idx: int,
    assignee: int,
    genesis_l1_height: int,
) -> None:
    """Withdraw `deposit_idx` through `assignee` and wait until it fulfills the withdrawal.

    ASM assigns the oldest unassigned deposit, preferring `assignee` among its eligible operators;
    fails unless that is `deposit_idx` assigned to `assignee`.
    """
    tip_hash = bitcoin_rpc.proxy.getblockhash(bitcoin_rpc.proxy.getblockcount())
    checkpoint_txid = dev_cli.send_mock_checkpoint_from_tip(
        asm_rpc,
        tip_hash,
        num_ol_slots=1,
        assignee_node_idx=assignee,
        genesis_l1_height=genesis_l1_height,
    )
    checkpoint_block_hash = wait_for_tx_confirmation(bitcoin_rpc, checkpoint_txid)

    result: dict[str, AssignmentEntry | None] = {"assignment": None}

    def assigned():
        assignments = [
            AssignmentEntry.from_dict(raw)
            for raw in asm_rpc.strata_asm_getAssignments(checkpoint_block_hash)
        ]
        result["assignment"] = next(
            (entry for entry in assignments if entry.deposit_entry.deposit_idx == deposit_idx),
            None,
        )
        return result["assignment"] is not None

    wait_until(
        assigned,
        timeout=300,
        error_msg=f"ASM did not assign the withdrawal of deposit {deposit_idx}",
    )
    assignment = result["assignment"]
    assert assignment is not None
    assert assignment.current_assignee == assignee, (
        f"ASM must assign deposit {deposit_idx} to operator {assignee}, assigned {assignment}"
    )

    wait_until(
        lambda: (
            (assignee_rpc.stratabridge_withdrawalStatus(deposit_idx) or {}).get("status")
            == "complete"
        ),
        timeout=600,
        error_msg=f"operator {assignee} did not fulfill the withdrawal of deposit {deposit_idx}",
    )


def wait_until_paid_out(
    bitcoin_rpc,
    deposit_txid: str,
    deposit_idx: int,
    assignee: int,
    assignee_payout_address: str,
    timeout=900,
) -> str:
    """Wait until deposit `deposit_idx` pays `assignee` out and return the payout's txid.

    Only the deposit's covenant can spend its output, so a cooperative payout shows every member
    of that covenant co-signed.
    """
    wait_until_utxo_spent(bitcoin_rpc, deposit_txid, DT_DEPOSIT_VOUT, timeout)
    payout_txid = find_utxo_spender_txid(bitcoin_rpc, deposit_txid, DT_DEPOSIT_VOUT)
    payout = bitcoin_rpc.proxy.getrawtransaction(payout_txid, True)
    paid_addresses = [output["scriptPubKey"].get("address") for output in payout["vout"]]
    assert assignee_payout_address in paid_addresses, (
        f"payout {payout_txid} of deposit {deposit_idx} must pay operator {assignee} at "
        f"{assignee_payout_address}, paid {paid_addresses}"
    )
    logging.info(f"Deposit {deposit_idx} paid out to operator {assignee} by {payout_txid}")
    return payout_txid
