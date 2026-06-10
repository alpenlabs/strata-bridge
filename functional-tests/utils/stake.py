import logging

from constants import STAKE_VOUT
from rpc.types import RpcOperatorStakeInfo, RpcStakeStateLabel
from utils.utils import wait_for_tx_confirmation, wait_until


def get_stake_status(bridge_rpc) -> list[RpcOperatorStakeInfo]:
    """Return the bridge node's view of every operator's stake status."""
    return [
        RpcOperatorStakeInfo.from_json(entry) for entry in bridge_rpc.stratabridge_stakeStatus()
    ]


def get_operator_stake_status(bridge_rpc, operator_idx: int) -> RpcOperatorStakeInfo:
    """Return the given operator's current stake status from `stakeStatus`.

    Fails if the bridge node is not tracking the requested operator.
    """
    for stake in get_stake_status(bridge_rpc):
        if stake.operator_idx == operator_idx:
            return stake

    raise AssertionError(f"operator {operator_idx} is missing from stakeStatus")


def confirmed_stake_txid_for_operator(bridge_rpc, bitcoin_rpc, operator_idx: int) -> str:
    """Return the operator's confirmed stake txid while its stake output is still live on chain.

    The bridge RPC is used to query for the stake UTXO.
    """
    stake = get_operator_stake_status(bridge_rpc, operator_idx)
    assert stake.state is RpcStakeStateLabel.CONFIRMED, (
        f"operator {operator_idx} must be confirmed before slashing, got {stake.state}"
    )
    assert stake.stake_txid is not None, (
        f"operator {operator_idx} reported `confirmed` without a stake_txid"
    )

    wait_for_tx_confirmation(bitcoin_rpc, stake.stake_txid)
    stake_utxo = bitcoin_rpc.proxy.gettxout(stake.stake_txid, STAKE_VOUT)
    assert stake_utxo is not None, (
        f"operator {operator_idx} stake output {stake.stake_txid}:{STAKE_VOUT} is not unspent"
    )

    return stake.stake_txid


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


def wait_until_operator_slashed(
    bridge_rpc,
    operator_idx: int,
    timeout: int = 600,
) -> RpcOperatorStakeInfo:
    """Wait until the bridge node reports `slashed` and exposes the slash txid."""
    result: dict[str, RpcOperatorStakeInfo | None] = {"stake": None}

    def check():
        stake = get_operator_stake_status(bridge_rpc, operator_idx)
        logging.info(f"Current stake status for operator {operator_idx}: {stake}")
        if stake.state is not RpcStakeStateLabel.SLASHED:
            return False

        assert stake.slash_txid is not None, (
            f"operator {operator_idx} reported `slashed` without a slash_txid"
        )
        result["stake"] = stake
        return True

    wait_until(
        check,
        timeout=timeout,
        step=1,
        error_msg=(
            f"Timeout after {timeout}s waiting for operator {operator_idx} stake to reach `slashed`"
        ),
    )

    stake = result["stake"]
    assert stake is not None
    return stake


def assert_slash_spends_stake(bitcoin_rpc, stake_txid: str, slash_txid: str) -> None:
    """Verify the slash tx consumes the operator's stake outpoint on-chain."""
    wait_for_tx_confirmation(bitcoin_rpc, slash_txid, timeout=300)

    slash_tx = bitcoin_rpc.proxy.getrawtransaction(slash_txid, True)
    slash_inputs = [(vin["txid"], vin["vout"]) for vin in slash_tx.get("vin", [])]
    stake_outpoint = (stake_txid, STAKE_VOUT)

    assert stake_outpoint in slash_inputs, (
        f"slash tx {slash_txid} does not spend operator stake output {stake_outpoint}; "
        f"inputs: {slash_inputs}"
    )
    assert bitcoin_rpc.proxy.gettxout(stake_txid, STAKE_VOUT) is None, (
        f"operator stake output {stake_txid}:{STAKE_VOUT} is still unspent after slash {slash_txid}"
    )
