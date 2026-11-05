from collections.abc import Callable
from typing import cast

import flexitest

from envs import AsmEnvConfig, OperatorSetChangeEnv, StrataLiveEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import ScheduledOperator
from utils.bitcoin import mine_block_including, mine_to_height
from utils.bridge import bridge_rpc_url
from utils.covenant import wait_until_current_covenant
from utils.deposit import make_deposit, wait_until_asm_deposit
from utils.dev_cli import DevCli
from utils.network import wait_until_p2p_connected
from utils.node_config import restart_bridge_node_with_overrides
from utils.operator_set import (
    OperatorSetUpdate,
    include_operator_set_updates,
    restart_with_operator_schedule,
    scheduled_operator,
)
from utils.utils import read_all_operator_keys, wait_until_bridge_ready
from utils.withdrawal import (
    assert_cooperative_payout,
    fulfill_withdrawal,
    tx_inputs,
    wait_until_active_valid_claim,
    wait_until_paid_out,
)

GENESIS_MEMBERS = [0, 1, 2]

# Removed by an admin update and by its own unstaking intent in the same block.
DOUBLY_REMOVED_OPERATOR = 1

# Added by an admin update while another operator's unstaking intent confirms in the same block.
JOINING_OPERATOR = 3
UNSTAKING_OPERATOR = 2

# Takes the claim (unilateral) path for its withdrawal instead of a cooperative payout.
CLAIMING_OPERATOR = 0

# Blocks between an admin operator set update's inclusion and its activation.
OPERATOR_UPDATE_DEPTH = 10

# Successor covenants start their deposit sequences clear of every earlier covenant's indices.
DOUBLE_REMOVAL_DEPOSIT_INDEX_OFFSET = 100
EXIT_AT_ADDITION_DEPOSIT_INDEX_OFFSET = 200


@flexitest.register
class OperatorSetExitAtAdminActivationTest(StrataTestBase):
    """
    Exercise unstaking exits that confirm in the block where an admin operator set update
    activates.

    Verifies that:
    - an operator removed both by an admin update and by its own unstaking intent in that
      update's activation block leaves once: the exit applies first, so the admin removal
      changes nothing and the successor covenant keeps its activation height,
    - an admin addition and another operator's unstaking exit in the same block both apply, and
      the successor covenant takes the admin update's activation height,
    - ASM records a deposit to each successor that the exited operators take no part in, and
    - every covenant's deposit pays out, cooperatively or, for an assignee that skips the
      cooperative payout, through its own claim.
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
        all_operators = GENESIS_MEMBERS + [JOINING_OPERATOR]
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

        def deposit(members: list[int], expected_idx: int) -> str:
            deposit_txid = make_deposit(
                dev_cli, bridge_rpc_url(nodes[0]), member_rpcs(members), expected_idx
            )
            wait_until_asm_deposit(asm_rpc, bitcoin_rpc, expected_idx)
            return deposit_txid

        def assert_absent(operator: int, deposit_idx: int):
            assert deposit_idx not in rpcs[operator].stratabridge_depositIndices(), (
                f"operator {operator} must take no part in deposit {deposit_idx}, made after it "
                "left"
            )

        def update_with_exit_at_activation(
            update: OperatorSetUpdate,
            unstaking_operator: int,
            schedule_at: Callable[[int], list[ScheduledOperator]],
            deposit_index_offset: int,
        ) -> tuple[int, list[ScheduledOperator]]:
            """Enact `update`, and confirm `unstaking_operator`'s unstaking intent in that
            update's activation block.

            `schedule_at` maps the activation height to the schedule the network restarts on.
            Returns the activation height and that schedule.
            """
            # No node may process the activation block before it restarts on the edited
            # schedule, and the intent must confirm in exactly that block.
            with live_env.mining_paused(bitcoin_rpc, mining_address):
                activation_height = include_operator_set_updates(
                    dev_cli, bitcoin_rpc, mining_address, [update], OPERATOR_UPDATE_DEPTH
                )
                mine_to_height(bitcoin_rpc, mining_address, activation_height - 1)
                schedule = schedule_at(activation_height)
                restart_with_operator_schedule(
                    nodes, schedule, deposit_index_offset=deposit_index_offset
                )
                intent_txid = dev_cli.send_unstaking_intent(
                    unstaking_operator,
                    bridge_rpc_url(nodes[unstaking_operator]),
                    operator_keys[unstaking_operator].SEED,
                )
                intent_height = mine_block_including(bitcoin_rpc, mining_address, [intent_txid])
                assert intent_height == activation_height, (
                    f"operator {unstaking_operator}'s unstaking intent {intent_txid} must confirm "
                    f"at the admin activation height {activation_height}, confirmed at "
                    f"{intent_height}"
                )
                self.logger.info(
                    f"Admin update {update.seqno} and operator {unstaking_operator}'s unstaking "
                    f"intent both take effect at {activation_height}"
                )
            wait_until_p2p_connected(member_rpcs([registration.index for registration in schedule]))
            return activation_height, schedule

        self.logger.info("Genesis: the genesis members admit a deposit")
        wait_until_p2p_connected(member_rpcs(GENESIS_MEMBERS))
        genesis_covenant = wait_until_current_covenant(
            member_rpcs(GENESIS_MEMBERS), GENESIS_MEMBERS
        )
        genesis_height = genesis_covenant.activation_height
        genesis_deposit_idx = 0
        genesis_deposit_txid = deposit(GENESIS_MEMBERS, genesis_deposit_idx)

        self.logger.info(
            f"Same operator, two sources: operator {DOUBLY_REMOVED_OPERATOR} is removed by an "
            "admin update and unstakes in its activation block"
        )
        double_removal_members = [idx for idx in GENESIS_MEMBERS if idx != DOUBLY_REMOVED_OPERATOR]

        def double_removal_schedule_at(activation_height: int) -> list[ScheduledOperator]:
            return [
                scheduled_operator(
                    idx,
                    genesis_height,
                    activation_height if idx == DOUBLY_REMOVED_OPERATOR else None,
                )
                for idx in GENESIS_MEMBERS
            ]

        _, double_removal_schedule = update_with_exit_at_activation(
            OperatorSetUpdate(seqno=1, remove_indices=[DOUBLY_REMOVED_OPERATOR]),
            unstaking_operator=DOUBLY_REMOVED_OPERATOR,
            schedule_at=double_removal_schedule_at,
            deposit_index_offset=DOUBLE_REMOVAL_DEPOSIT_INDEX_OFFSET,
        )
        # The exit applies before the admin update, which then removes no one, so the successor
        # keeps the activation height of the covenant it replaces.
        wait_until_current_covenant(
            member_rpcs(double_removal_members),
            double_removal_members,
            activation_height=genesis_height,
        )
        double_removal_deposit_idx = DOUBLE_REMOVAL_DEPOSIT_INDEX_OFFSET
        double_removal_deposit_txid = deposit(double_removal_members, double_removal_deposit_idx)
        assert_absent(DOUBLY_REMOVED_OPERATOR, double_removal_deposit_idx)

        self.logger.info(
            f"Different operators, two sources: operator {JOINING_OPERATOR} is added by an admin "
            f"update while operator {UNSTAKING_OPERATOR} unstakes in its activation block"
        )
        exit_at_addition_members = [
            idx for idx in double_removal_members if idx != UNSTAKING_OPERATOR
        ] + [JOINING_OPERATOR]
        exit_at_addition_height, _ = update_with_exit_at_activation(
            OperatorSetUpdate(seqno=2, add_keys=[operator_keys[JOINING_OPERATOR].MUSIG2_KEY]),
            unstaking_operator=UNSTAKING_OPERATOR,
            schedule_at=lambda activation_height: double_removal_schedule
            + [scheduled_operator(JOINING_OPERATOR, activation_height)],
            deposit_index_offset=EXIT_AT_ADDITION_DEPOSIT_INDEX_OFFSET,
        )
        wait_until_current_covenant(
            member_rpcs(exit_at_addition_members),
            exit_at_addition_members,
            activation_height=exit_at_addition_height,
        )
        exit_at_addition_deposit_idx = EXIT_AT_ADDITION_DEPOSIT_INDEX_OFFSET
        exit_at_addition_deposit_txid = deposit(
            exit_at_addition_members, exit_at_addition_deposit_idx
        )
        for operator in (DOUBLY_REMOVED_OPERATOR, UNSTAKING_OPERATOR):
            assert_absent(operator, exit_at_addition_deposit_idx)

        def withdraw(deposit_idx: int, assignee: int):
            self.logger.info(f"Withdrawing deposit {deposit_idx} through operator {assignee}")
            fulfill_withdrawal(
                dev_cli,
                asm_rpc,
                bitcoin_rpc,
                rpcs[assignee],
                deposit_idx,
                assignee,
                genesis_height,
            )

        def wait_until_deposit_paid_out(deposit_idx: int, deposit_txid: str, assignee: int) -> str:
            return wait_until_paid_out(
                bitcoin_rpc,
                deposit_txid,
                deposit_idx,
                assignee,
                operator_keys[assignee].GENERAL_WALLET,
            )

        def withdraw_cooperatively(deposit_idx: int, deposit_txid: str, assignee: int):
            withdraw(deposit_idx, assignee)
            payout_txid = wait_until_deposit_paid_out(deposit_idx, deposit_txid, assignee)
            assert_cooperative_payout(bitcoin_rpc, payout_txid, deposit_txid)

        # ASM assigns the oldest unassigned deposit first, so the deposits are withdrawn in the
        # order they were made. Each assignee is active and belongs to that deposit's covenant;
        # operator 0 is the only active member left of the covenants before the addition.
        self.logger.info("Withdrawals: every covenant's deposit pays out")
        withdraw_cooperatively(genesis_deposit_idx, genesis_deposit_txid, GENESIS_MEMBERS[0])

        def restart_with_cooperative_payout_timeout(operator: int, timeout: int):
            restart_bridge_node_with_overrides(
                nodes[operator],
                config_overrides={"cooperative_payout_timeout": timeout},
                params_overrides={},
            )
            wait_until_bridge_ready(rpcs[operator])
            wait_until_p2p_connected(member_rpcs(all_operators))

        self.logger.info(
            f"Unilateral reimbursement: operator {CLAIMING_OPERATOR} skips the cooperative payout"
        )
        restart_with_cooperative_payout_timeout(CLAIMING_OPERATOR, 0)
        withdraw(double_removal_deposit_idx, CLAIMING_OPERATOR)
        claim = wait_until_active_valid_claim(rpcs[CLAIMING_OPERATOR])
        assert (claim.deposit_idx, claim.assigned_operator) == (
            double_removal_deposit_idx,
            CLAIMING_OPERATOR,
        ), (
            f"operator {CLAIMING_OPERATOR} must claim deposit {double_removal_deposit_idx}, "
            f"got {claim}"
        )
        payout_txid = wait_until_deposit_paid_out(
            double_removal_deposit_idx, double_removal_deposit_txid, CLAIMING_OPERATOR
        )
        payout_inputs = tx_inputs(bitcoin_rpc, payout_txid)
        assert any(txid == claim.claim_txid for txid, _ in payout_inputs), (
            f"payout {payout_txid} must spend claim {claim.claim_txid}, spent {payout_inputs}"
        )

        # Every member checks a cooperative payout against its own timeout, so a member with a
        # zero timeout refuses to co-sign another assignee's cooperative payout too.
        restart_with_cooperative_payout_timeout(
            CLAIMING_OPERATOR, BridgeConfigParams().cooperative_payout_timeout
        )
        withdraw_cooperatively(
            exit_at_addition_deposit_idx, exit_at_addition_deposit_txid, JOINING_OPERATOR
        )

        return True
