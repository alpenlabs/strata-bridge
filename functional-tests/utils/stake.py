import logging

from rpc.types import RpcOperatorStakeInfo, RpcStakeStateLabel
from utils.utils import wait_for_tx_confirmation, wait_until


def get_stake_status(bridge_rpc) -> list[RpcOperatorStakeInfo]:
    """Return the bridge node's view of every operator's stake status."""
    return [
        RpcOperatorStakeInfo.from_json(entry) for entry in bridge_rpc.stratabridge_stakeStatus()
    ]


def wait_until_all_operators_staked(
    bridge_rpc,
    bitcoin_rpc,
    expected_operator_count: int,
    timeout: int = 300,
) -> list[RpcOperatorStakeInfo]:
    """Wait until the bridge node reports that every operator's stake is confirmed.

    A stake is considered confirmed once its state is `confirmed` or later
    (`preimage_revealed` / `unstaked`). This mirrors the orchestrator's
    `all_operators_have_staked()` gate that unblocks DRT processing. When the
    state is `confirmed` the returned `stake_txid` is additionally verified to
    be present and confirmed on-chain so the gate can't fire on stale /
    optimistic state.

    Args:
        bridge_rpc: RPC client for the bridge.
        bitcoin_rpc: Bitcoin RPC client used to look up stake txids on-chain.
        expected_operator_count: Number of operators that must appear in the
            stake-status response. The call blocks until the node is tracking
            this many stakes, protecting against premature ``True`` during
            startup before every SSM has been bootstrapped.
        timeout: Maximum wait time in seconds.
    """
    confirmed_states = {
        RpcStakeStateLabel.CONFIRMED,
        RpcStakeStateLabel.PREIMAGE_REVEALED,
        RpcStakeStateLabel.UNSTAKED,
    }
    result: dict[str, list[RpcOperatorStakeInfo] | None] = {"stakes": None}

    def check():
        stakes = get_stake_status(bridge_rpc)
        logging.info(f"Current stake status: {stakes}")
        if len(stakes) < expected_operator_count:
            return False
        if not all(s.state in confirmed_states for s in stakes):
            return False
        result["stakes"] = stakes
        return True

    wait_until(
        check,
        timeout=timeout,
        step=1,
        error_msg=(
            f"Timeout after {timeout}s waiting for all {expected_operator_count} "
            "operators' stakes to reach `confirmed`"
        ),
    )
    stakes = result["stakes"]
    assert stakes is not None

    for stake in stakes:
        if stake.state is RpcStakeStateLabel.CONFIRMED:
            assert stake.stake_txid is not None, (
                f"operator {stake.operator_idx} reported `confirmed` without a stake_txid"
            )
            wait_for_tx_confirmation(bitcoin_rpc, stake.stake_txid)
            logging.info(
                f"Verified stake tx {stake.stake_txid} on-chain for operator {stake.operator_idx}"
            )

    return stakes
