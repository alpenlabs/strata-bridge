from typing import cast

import flexitest

from envs import AsmEnvConfig, OperatorSetChangeEnv, StrataLiveEnv
from envs.base_test import StrataTestBase
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
from utils.utils import read_all_operator_keys
from utils.withdrawal import assert_cooperative_payout, fulfill_withdrawal, wait_until_paid_out

GENESIS_MEMBERS = [0, 1, 2]
JOINING_OPERATORS = [3, 4]
LEAVING_OPERATORS = [1, 2]

# Blocks between an admin operator set update's inclusion and its activation.
OPERATOR_UPDATE_DEPTH = 10

# Successor covenants start their deposit sequences clear of every earlier covenant's indices.
ADDITION_DEPOSIT_INDEX_OFFSET = 100
REMOVAL_DEPOSIT_INDEX_OFFSET = 200


@flexitest.register
class OperatorSetBatchedChangesTest(StrataTestBase):
    """
    Exercise admin operator set updates that each add or remove several operators at once.

    Verifies that:
    - one update adding two operators activates a successor covenant with both of them, and ASM
      records a deposit to it,
    - one update removing two operators activates a successor covenant without either of them,
      and ASM records a deposit to it that neither takes part in,
    - deposits of the replaced covenants pay out cooperatively, the removed operators co-signing
      those of the covenants they belonged to, and
    - the final covenant pays out cooperatively with the removed operators shut down.
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(
            OperatorSetChangeEnv(
                num_operators=len(GENESIS_MEMBERS) + len(JOINING_OPERATORS),
                asm_config=AsmEnvConfig(operator_update_confirmation_depth=OPERATOR_UPDATE_DEPTH),
            )
        )

    def main(self, ctx: flexitest.RunContext):
        operator_keys = read_all_operator_keys()
        all_operators = GENESIS_MEMBERS + JOINING_OPERATORS
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

        def include_update(update: OperatorSetUpdate) -> int:
            return include_operator_set_updates(
                dev_cli, bitcoin_rpc, mining_address, [update], OPERATOR_UPDATE_DEPTH
            )

        self.logger.info("Genesis: the genesis members admit a deposit")
        wait_until_p2p_connected(member_rpcs(GENESIS_MEMBERS))
        genesis_covenant = wait_until_current_covenant(
            member_rpcs(GENESIS_MEMBERS), GENESIS_MEMBERS
        )
        genesis_height = genesis_covenant.activation_height
        genesis_deposit_idx = 0
        genesis_deposit_txid = deposit(GENESIS_MEMBERS, genesis_deposit_idx)

        self.logger.info(f"Batched addition: operators {JOINING_OPERATORS} join in one update")
        # No node may process the activation block before it restarts on the edited schedule.
        with live_env.mining_paused(bitcoin_rpc, mining_address):
            addition_height = include_update(
                OperatorSetUpdate(
                    seqno=1,
                    add_keys=[operator_keys[idx].MUSIG2_KEY for idx in JOINING_OPERATORS],
                )
            )
            addition_schedule = [scheduled_operator(idx, genesis_height) for idx in GENESIS_MEMBERS]
            addition_schedule += [
                scheduled_operator(idx, addition_height) for idx in JOINING_OPERATORS
            ]
            restart_with_operator_schedule(
                nodes, addition_schedule, deposit_index_offset=ADDITION_DEPOSIT_INDEX_OFFSET
            )
        wait_until_p2p_connected(member_rpcs(all_operators))
        wait_until_current_covenant(
            member_rpcs(all_operators), all_operators, activation_height=addition_height
        )
        addition_deposit_idx = ADDITION_DEPOSIT_INDEX_OFFSET
        addition_deposit_txid = deposit(all_operators, addition_deposit_idx)

        self.logger.info(f"Batched removal: operators {LEAVING_OPERATORS} leave in one update")
        removal_members = [idx for idx in all_operators if idx not in LEAVING_OPERATORS]
        # No node may process the activation block before it restarts on the edited schedule.
        with live_env.mining_paused(bitcoin_rpc, mining_address):
            removal_height = include_update(
                OperatorSetUpdate(seqno=2, remove_indices=LEAVING_OPERATORS)
            )
            removal_schedule = [
                scheduled_operator(
                    registration.index,
                    registration.activation_height,
                    removal_height if registration.index in LEAVING_OPERATORS else None,
                )
                for registration in addition_schedule
            ]
            restart_with_operator_schedule(
                nodes, removal_schedule, deposit_index_offset=REMOVAL_DEPOSIT_INDEX_OFFSET
            )
        wait_until_p2p_connected(member_rpcs(all_operators))
        wait_until_current_covenant(
            member_rpcs(removal_members), removal_members, activation_height=removal_height
        )
        removal_deposit_idx = REMOVAL_DEPOSIT_INDEX_OFFSET
        removal_deposit_txid = deposit(removal_members, removal_deposit_idx)
        for idx in LEAVING_OPERATORS:
            assert removal_deposit_idx not in rpcs[idx].stratabridge_depositIndices(), (
                f"operator {idx} must take no part in deposit {removal_deposit_idx}, made after "
                "it left"
            )

        def withdraw_cooperatively(deposit_idx: int, deposit_txid: str, assignee: int):
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
            payout_txid = wait_until_paid_out(
                bitcoin_rpc,
                deposit_txid,
                deposit_idx,
                assignee,
                operator_keys[assignee].GENERAL_WALLET,
            )
            assert_cooperative_payout(bitcoin_rpc, payout_txid, deposit_txid)

        # ASM assigns the oldest unassigned deposit first, so the deposits are withdrawn in the
        # order they were made. Each assignee is active and belongs to that deposit's covenant;
        # operator 0 is the only genesis member left.
        self.logger.info("Withdrawals: replaced covenants pay out with the removed operators")
        withdraw_cooperatively(genesis_deposit_idx, genesis_deposit_txid, GENESIS_MEMBERS[0])
        withdraw_cooperatively(addition_deposit_idx, addition_deposit_txid, JOINING_OPERATORS[0])

        self.logger.info(f"Decommission: operators {LEAVING_OPERATORS} shut down")
        for idx in LEAVING_OPERATORS:
            nodes[idx].stop()
        withdraw_cooperatively(removal_deposit_idx, removal_deposit_txid, JOINING_OPERATORS[1])

        return True
