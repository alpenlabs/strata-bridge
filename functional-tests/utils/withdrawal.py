import logging
import os
from dataclasses import dataclass

from rpc.types import RpcClaimPhase, RpcPendingWithdrawalInfo
from utils.utils import wait_until

# Under BRIDGE_SP1=1 a real Groth16 proof takes 10–30 min; default mock-mode
# timeouts (minutes) would trip first. Bump the proof-phase waits to an hour
# so the test waits long enough without making mock-mode runs slower.
_SP1_PROOF_TIMEOUT_SECS = 3600


def _proof_phase_timeout(default_secs: int) -> int:
    if os.environ.get("BRIDGE_SP1") == "1":
        return max(default_secs, _SP1_PROOF_TIMEOUT_SECS)
    return default_secs


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


def wait_until_bridge_proof_posted(
    bridge_rpc,
    deposit_idx: int,
    timeout=450,
) -> None:
    """Wait until the pending withdrawal's assigned claim phase is 'bridge_proof_posted'."""
    timeout = _proof_phase_timeout(timeout)

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
    timeout = _proof_phase_timeout(timeout)

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
