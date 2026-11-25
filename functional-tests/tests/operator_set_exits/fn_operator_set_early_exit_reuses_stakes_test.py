from typing import cast

import flexitest

from envs import AsmEnvConfig, OperatorSetChangeEnv, StrataLiveEnv
from envs.base_test import StrataTestBase
from rpc.types import RpcCovenantId, RpcStakeStateLabel
from utils.bridge import bridge_rpc_url
from utils.covenant import wait_until_current_covenant
from utils.deposit import make_deposit, wait_until_asm_deposit
from utils.dev_cli import DevCli
from utils.network import wait_until_p2p_connected
from utils.operator_set import (
    OperatorSetUpdate,
    include_operator_set_updates,
    restart_with_operator_schedule,
    scheduled_operator,
)
from utils.stake import get_stake_status, wait_until_all_operators_staked
from utils.utils import read_all_operator_keys, wait_for_tx_confirmation, wait_until

GENESIS_MEMBERS = [0, 1, 2]

# Added by an admin update and scheduled for removal by a later one, but exits before then.
TEMPORARY_OPERATOR = 3

# Blocks between an admin operator set update's inclusion and its activation, long enough for
# the temporary operator's unstaking intent to confirm before its scheduled removal.
OPERATOR_UPDATE_DEPTH = 30

# Successor covenants start their deposit sequences clear of every earlier covenant's indices.
ADDITION_DEPOSIT_INDEX_OFFSET = 100
REMOVAL_DEPOSIT_INDEX_OFFSET = 200


@flexitest.register
class OperatorSetEarlyExitReusesStakesTest(StrataTestBase):
    """
    Exercise an operator that is added, scheduled for removal, and exits before the removal
    activates, returning membership to the genesis signing set.

    Verifies that:
    - the covenant left by the exit keeps the addition's activation height,
    - every genesis member backs that covenant, and the one after the cancelled removal, with
      its genesis stake: no stake is added under any signing set after the exit, and
    - the returning signing set admits a deposit that ASM records.
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(
            OperatorSetChangeEnv(
                num_operators=len(GENESIS_MEMBERS) + 1,
                asm_config=AsmEnvConfig(operator_update_confirmation_depth=OPERATOR_UPDATE_DEPTH),
            )
        )

    def main(self, ctx: flexitest.RunContext):
        operator_keys = read_all_operator_keys()
        all_operators = GENESIS_MEMBERS + [TEMPORARY_OPERATOR]
        nodes = {idx: ctx.get_service(f"bridge_node_{idx}") for idx in all_operators}
        # `Service` is the static type; concrete bridge-node services attach `create_rpc`.
        rpcs = {idx: node.create_rpc() for idx, node in nodes.items()}  # ty: ignore[possibly-missing-attribute]
        live_env = cast(StrataLiveEnv, ctx.env)
        bitcoin = ctx.get_service("bitcoin")
        bitcoin_rpc = bitcoin.create_rpc()
        asm_rpc = ctx.get_service("asm_rpc").create_rpc()
        mining_address = bitcoin_rpc.proxy.getnewaddress()
        dev_cli = DevCli(bitcoin.props, operator_keys)

        def member_rpcs(members: list[int]) -> list:
            return [rpcs[idx] for idx in members]

        def include_update(update: OperatorSetUpdate) -> int:
            return include_operator_set_updates(
                dev_cli, bitcoin_rpc, mining_address, [update], OPERATOR_UPDATE_DEPTH
            )

        def genesis_stake_txids(covenant: RpcCovenantId) -> dict[int, dict[int, str | None]]:
            """Return, per genesis member's node, the confirmed stake txid of each operator
            backing `covenant`'s signing set."""
            return {
                idx: {
                    stake.operator_idx: stake.stake_txid
                    for stake in get_stake_status(rpcs[idx], covenant)
                }
                for idx in GENESIS_MEMBERS
            }

        def tracked_stakes() -> dict[int, set[tuple[str, int]]]:
            """Return, per genesis member's node, the signing set and operator of every stake it
            tracks."""
            return {
                idx: {
                    (stake.aggregate_pubkey, stake.operator_idx)
                    for stake in get_stake_status(rpcs[idx])
                }
                for idx in GENESIS_MEMBERS
            }

        self.logger.info("Genesis: every genesis member stakes once for the genesis signing set")
        wait_until_p2p_connected(member_rpcs(GENESIS_MEMBERS))
        genesis_covenant = wait_until_current_covenant(
            member_rpcs(GENESIS_MEMBERS), GENESIS_MEMBERS
        )
        genesis_height = genesis_covenant.activation_height
        for idx in GENESIS_MEMBERS:
            wait_until_all_operators_staked(
                rpcs[idx], bitcoin_rpc, len(GENESIS_MEMBERS), covenant=genesis_covenant
            )
        genesis_stakes = genesis_stake_txids(genesis_covenant)
        for idx, stakes in genesis_stakes.items():
            assert set(stakes) == set(GENESIS_MEMBERS), (
                f"operator {idx} must track exactly one stake per genesis member for the genesis "
                f"signing set, got {stakes}"
            )

        self.logger.info(f"Addition: operator {TEMPORARY_OPERATOR} joins")
        addition_members = all_operators
        # No node may process the activation block before it restarts on the edited schedule.
        with live_env.mining_paused(bitcoin_rpc, mining_address):
            addition_height = include_update(
                OperatorSetUpdate(seqno=1, add_keys=[operator_keys[TEMPORARY_OPERATOR].MUSIG2_KEY])
            )
            addition_schedule = [scheduled_operator(idx, genesis_height) for idx in GENESIS_MEMBERS]
            addition_schedule.append(scheduled_operator(TEMPORARY_OPERATOR, addition_height))
            restart_with_operator_schedule(
                nodes, addition_schedule, deposit_index_offset=ADDITION_DEPOSIT_INDEX_OFFSET
            )
        wait_until_p2p_connected(member_rpcs(addition_members))
        addition_covenant = wait_until_current_covenant(
            member_rpcs(addition_members), addition_members, activation_height=addition_height
        )
        for idx in addition_members:
            wait_until_all_operators_staked(
                rpcs[idx], bitcoin_rpc, len(addition_members), covenant=addition_covenant
            )
        stakes_before_exit = tracked_stakes()

        self.logger.info(
            f"Scheduled removal: operator {TEMPORARY_OPERATOR} is to leave, but exits first"
        )
        with live_env.mining_paused(bitcoin_rpc, mining_address):
            removal_height = include_update(
                OperatorSetUpdate(seqno=2, remove_indices=[TEMPORARY_OPERATOR])
            )
            removal_schedule = [
                scheduled_operator(
                    registration.index,
                    registration.activation_height,
                    removal_height if registration.index == TEMPORARY_OPERATOR else None,
                )
                for registration in addition_schedule
            ]
            restart_with_operator_schedule(
                nodes, removal_schedule, deposit_index_offset=REMOVAL_DEPOSIT_INDEX_OFFSET
            )
        wait_until_p2p_connected(member_rpcs(addition_members))
        intent_txid = dev_cli.send_unstaking_intent(
            TEMPORARY_OPERATOR,
            bridge_rpc_url(nodes[TEMPORARY_OPERATOR]),
            operator_keys[TEMPORARY_OPERATOR].SEED,
            covenant=addition_covenant,
        )
        intent_block_hash = wait_for_tx_confirmation(bitcoin_rpc, intent_txid)
        intent_height = bitcoin_rpc.proxy.getblockheader(intent_block_hash)["height"]
        assert intent_height < removal_height, (
            f"operator {TEMPORARY_OPERATOR}'s unstaking intent must confirm before its removal "
            f"activates at {removal_height}, confirmed at {intent_height}"
        )

        self.logger.info("Early exit: the genesis signing set returns with its genesis stakes")
        # An exit keeps the admin activation height of the covenant it leaves.
        exit_covenant = wait_until_current_covenant(
            member_rpcs(GENESIS_MEMBERS), GENESIS_MEMBERS, activation_height=addition_height
        )
        assert exit_covenant.aggregate_pubkey == genesis_covenant.aggregate_pubkey, (
            f"the exit must restore the genesis signing set: {exit_covenant} after "
            f"{genesis_covenant}"
        )
        assert genesis_stake_txids(exit_covenant) == genesis_stakes, (
            "the returning signing set must be backed by the genesis stakes alone"
        )
        assert tracked_stakes() == stakes_before_exit, (
            "the exit must not add stakes under any signing set"
        )

        self.logger.info("Cancelled removal: the scheduled removal changes nothing")
        wait_until(
            lambda: bitcoin_rpc.proxy.getblockcount() > removal_height,
            timeout=600,
            error_msg=f"the chain must pass the scheduled removal at {removal_height}",
        )
        after_removal = wait_until_current_covenant(
            member_rpcs(GENESIS_MEMBERS), GENESIS_MEMBERS, activation_height=addition_height
        )
        assert after_removal == exit_covenant, (
            f"the removal of an exited operator must not change the covenant: {after_removal} "
            f"after {exit_covenant}"
        )
        assert genesis_stake_txids(after_removal) == genesis_stakes, (
            "the removal of an exited operator must not change the genesis stakes"
        )
        assert tracked_stakes() == stakes_before_exit, (
            "the removal of an exited operator must not add stakes under any signing set"
        )
        for idx in GENESIS_MEMBERS:
            assert all(
                stake.state is RpcStakeStateLabel.CONFIRMED
                for stake in get_stake_status(rpcs[idx], after_removal)
            ), f"operator {idx} must still see every genesis stake confirmed"

        self.logger.info("Deposit: the returning signing set admits a deposit")
        deposit_idx = REMOVAL_DEPOSIT_INDEX_OFFSET
        make_deposit(dev_cli, bridge_rpc_url(nodes[0]), member_rpcs(GENESIS_MEMBERS), deposit_idx)
        wait_until_asm_deposit(asm_rpc, bitcoin_rpc, deposit_idx)
        assert deposit_idx not in rpcs[TEMPORARY_OPERATOR].stratabridge_depositIndices(), (
            f"operator {TEMPORARY_OPERATOR} must take no part in deposit {deposit_idx}, made "
            "after it exited"
        )

        return True
