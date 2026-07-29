import logging
from dataclasses import dataclass

from constants import (
    CONTEST_PAYOUT_VOUT,
    CONTEST_WATCHTOWER_0_VOUT,
    COUNTERPROOF_ACK_NACK_VOUT,
)
from rpc.types import RpcClaimPhase, RpcPendingWithdrawalInfo
from utils.deposit import wait_until_utxo_spent
from utils.utils import find_utxo_spender_txid, wait_until


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


def wait_until_bridge_proof_posted(
    bridge_rpc,
    deposit_idx: int,
    timeout=450,
) -> None:
    """Wait until the pending withdrawal's assigned claim phase is 'bridge_proof_posted'."""

    def check():
        info_data = bridge_rpc.stratabridge_pendingWithdrawalInfo(deposit_idx)
        if info_data is None:
            return False
        info = RpcPendingWithdrawalInfo.from_json(info_data)
        if info.assigned_claim is None:
            return False
        return info.assigned_claim.phase == RpcClaimPhase.BRIDGE_PROOF_POSTED

    wait_until(
        check,
        timeout=timeout,
        step=1,
        error_msg=f"Claim phase for deposit {deposit_idx} did not advance to bridge_proof_posted",
    )


def wait_until_counter_proof_posted(
    bridge_rpc,
    deposit_idx: int,
    timeout=450,
) -> None:
    """Wait until the pending withdrawal's assigned claim phase is 'counter_proof_posted'."""

    def check():
        info_data = bridge_rpc.stratabridge_pendingWithdrawalInfo(deposit_idx)
        if info_data is None:
            return False
        info = RpcPendingWithdrawalInfo.from_json(info_data)
        if info.assigned_claim is None:
            return False
        return info.assigned_claim.phase == RpcClaimPhase.COUNTER_PROOF_POSTED

    wait_until(
        check,
        timeout=timeout,
        step=1,
        error_msg=f"Claim phase for deposit {deposit_idx} did not advance to counter_proof_posted",
    )


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
    ((counterproof_txid, counterproof_vout),) = [inp for inp in ack_inputs if inp != contest_input]
    assert counterproof_vout == COUNTERPROOF_ACK_NACK_VOUT, (
        f"ACK candidate's other input is {counterproof_txid}:{counterproof_vout}, "
        f"expected vout {COUNTERPROOF_ACK_NACK_VOUT}"
    )

    counterproof_tx = bitcoin_rpc.proxy.getrawtransaction(counterproof_txid, True)
    cp_inputs = counterproof_tx.get("vin", [])
    assert len(cp_inputs) == 1, (
        f"counterproof candidate {counterproof_txid} must have 1 input, got {len(cp_inputs)}"
    )
    cp_in_txid = cp_inputs[0].get("txid")
    cp_in_vout = cp_inputs[0].get("vout")
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


def wait_until_bridge_proof_timedout(
    bridge_rpc,
    deposit_idx: int,
    timeout=600,
) -> None:
    """Wait until the pending withdrawal's assigned claim phase is 'bridge_proof_timedout'."""

    def check():
        info_data = bridge_rpc.stratabridge_pendingWithdrawalInfo(deposit_idx)
        if info_data is None:
            return False
        info = RpcPendingWithdrawalInfo.from_json(info_data)
        if info.assigned_claim is None:
            return False
        return info.assigned_claim.phase == RpcClaimPhase.BRIDGE_PROOF_TIMEDOUT

    wait_until(
        check,
        timeout=timeout,
        step=1,
        error_msg=(
            f"Claim phase for deposit {deposit_idx} did not advance to bridge_proof_timedout"
        ),
    )
