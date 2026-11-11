from functools import partial
from typing import cast

import flexitest

from envs import AsmEnvConfig, OperatorSetChangeEnv, StrataLiveEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.params_cfg import BridgeProtocolParams
from utils.bitcoin import mine_to_height
from utils.bridge import bridge_rpc_url
from utils.covenant import get_current_covenant, wait_until_current_covenant
from utils.deposit import make_deposit, wait_until_asm_deposit
from utils.dev_cli import DevCli
from utils.network import wait_until_p2p_connected
from utils.operator_set import (
    OperatorSetUpdate,
    include_operator_set_updates,
    restart_with_operator_schedule,
    scheduled_operator,
)
from utils.utils import read_all_operator_keys, wait_until
from utils.withdrawal import assert_cooperative_payout, fulfill_withdrawal, wait_until_paid_out

GENESIS_MEMBERS = [0, 1, 2]

# Joins and leaves in one block, through separate updates.
SAME_BLOCK_JOINER = 3
SAME_BLOCK_LEAVER = 1

# Joins, then leaves before the join activates, through updates in different blocks.
OVERLAPPING_JOINER = 4
OVERLAPPING_LEAVER = 2

# Blocks between an admin operator set update's inclusion and its activation.
OPERATOR_UPDATE_DEPTH = 10

# Blocks between the overlapping updates' inclusions, so the second is queued before the first
# activates.
OVERLAP_GAP = 3

# Successor covenants start their deposit sequences clear of every earlier covenant's indices.
SAME_BLOCK_DEPOSIT_INDEX_OFFSET = 100
OVERLAPPING_DEPOSIT_INDEX_OFFSET = 200


@flexitest.register
class OperatorSetOverlappingChangesTest(StrataTestBase):
    """
    Exercise admin operator set updates that activate in the same block or overlap in flight.

    Verifies that:
    - an addition and a removal enacted in the same block, through separate updates, activate a
      single successor covenant with both applied, and ASM records a deposit to it that the
      removed operator takes no part in,
    - an addition and a removal queued in different blocks, the removal before the addition
      activates, activate one covenant after the other, and the later one admits a deposit
      that ASM records,
    - the final covenant survives a restart of every node on the final schedule, and
    - the deposits of every covenant pay out cooperatively.
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(
            OperatorSetChangeEnv(
                num_operators=len(GENESIS_MEMBERS) + 2,
                asm_config=AsmEnvConfig(operator_update_confirmation_depth=OPERATOR_UPDATE_DEPTH),
            )
        )

    def main(self, ctx: flexitest.RunContext):
        operator_keys = read_all_operator_keys()
        all_operators = GENESIS_MEMBERS + [SAME_BLOCK_JOINER, OVERLAPPING_JOINER]
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

        def include_updates(updates: list[OperatorSetUpdate]) -> int:
            return include_operator_set_updates(
                dev_cli, bitcoin_rpc, mining_address, updates, OPERATOR_UPDATE_DEPTH
            )

        bury_depth = BridgeProtocolParams().bury_depth

        def all_processed(height: int) -> bool:
            return all(
                get_current_covenant(rpc).processed_height >= height
                for rpc in member_rpcs(all_operators)
            )

        def mine_until_processed(height: int, unprocessed_height: int):
            """Mine single blocks until every node has processed `height` but not
            `unprocessed_height`.

            A restarted node reports no covenant until its orchestrator starts, and only then
            catches up, on the next block to arrive. Nodes process a block once `bury_depth` blocks
            cover it.
            """
            wait_until(
                lambda: all(
                    rpc.stratabridge_currentCovenant() is not None
                    for rpc in member_rpcs(all_operators)
                ),
                timeout=600,
                error_msg="every node must report a current covenant after restarting",
            )
            while True:
                tip = bitcoin_rpc.proxy.getblockcount()
                if tip - bury_depth >= height:
                    try:
                        wait_until(
                            partial(all_processed, height),
                            timeout=15,
                            error_msg=f"every node must process block {height}",
                        )
                        return
                    except TimeoutError:
                        pass
                assert tip + 1 - bury_depth < unprocessed_height, (
                    f"every node must process block {height} before it can process block "
                    f"{unprocessed_height}, tip is {tip}"
                )
                mine_to_height(bitcoin_rpc, mining_address, tip + 1)

        def assert_absent(operator: int, deposit_idx: int):
            assert deposit_idx not in rpcs[operator].stratabridge_depositIndices(), (
                f"operator {operator} must take no part in deposit {deposit_idx}, made after it "
                "left"
            )

        self.logger.info("Genesis: the genesis members admit a deposit")
        wait_until_p2p_connected(member_rpcs(GENESIS_MEMBERS))
        genesis_covenant = wait_until_current_covenant(
            member_rpcs(GENESIS_MEMBERS), GENESIS_MEMBERS
        )
        genesis_height = genesis_covenant.activation_height
        genesis_deposit_idx = 0
        genesis_deposit_txid = deposit(GENESIS_MEMBERS, genesis_deposit_idx)

        self.logger.info(
            f"Same block: operator {SAME_BLOCK_JOINER} joins and operator {SAME_BLOCK_LEAVER} "
            "leaves through separate updates"
        )
        same_block_members = [
            idx for idx in GENESIS_MEMBERS + [SAME_BLOCK_JOINER] if idx != SAME_BLOCK_LEAVER
        ]
        # No node may process the activation block before it restarts on the edited schedule.
        with live_env.mining_paused(bitcoin_rpc, mining_address):
            same_block_height = include_updates(
                [
                    OperatorSetUpdate(
                        seqno=1, add_keys=[operator_keys[SAME_BLOCK_JOINER].MUSIG2_KEY]
                    ),
                    OperatorSetUpdate(seqno=2, remove_indices=[SAME_BLOCK_LEAVER]),
                ]
            )
            same_block_schedule = [
                scheduled_operator(
                    idx,
                    genesis_height,
                    same_block_height if idx == SAME_BLOCK_LEAVER else None,
                )
                for idx in GENESIS_MEMBERS
            ]
            same_block_schedule.append(scheduled_operator(SAME_BLOCK_JOINER, same_block_height))
            restart_with_operator_schedule(
                nodes, same_block_schedule, deposit_index_offset=SAME_BLOCK_DEPOSIT_INDEX_OFFSET
            )
        same_block_operators = GENESIS_MEMBERS + [SAME_BLOCK_JOINER]
        wait_until_p2p_connected(member_rpcs(same_block_operators))
        wait_until_current_covenant(
            member_rpcs(same_block_members),
            same_block_members,
            activation_height=same_block_height,
        )
        same_block_deposit_idx = SAME_BLOCK_DEPOSIT_INDEX_OFFSET
        same_block_deposit_txid = deposit(same_block_members, same_block_deposit_idx)
        assert_absent(SAME_BLOCK_LEAVER, same_block_deposit_idx)

        self.logger.info(
            f"Overlapping: operator {OVERLAPPING_JOINER} joins, and operator "
            f"{OVERLAPPING_LEAVER} leaves before the join activates"
        )
        joined_members = same_block_members + [OVERLAPPING_JOINER]
        overlapping_members = [idx for idx in joined_members if idx != OVERLAPPING_LEAVER]
        # No node may process either activation block before it restarts on the edited schedule.
        with live_env.mining_paused(bitcoin_rpc, mining_address):
            join_height = include_updates(
                [
                    OperatorSetUpdate(
                        seqno=3, add_keys=[operator_keys[OVERLAPPING_JOINER].MUSIG2_KEY]
                    )
                ]
            )
            mine_to_height(
                bitcoin_rpc, mining_address, bitcoin_rpc.proxy.getblockcount() + OVERLAP_GAP - 1
            )
            leave_height = include_updates(
                [OperatorSetUpdate(seqno=4, remove_indices=[OVERLAPPING_LEAVER])]
            )
            assert bitcoin_rpc.proxy.getblockcount() < join_height < leave_height, (
                f"the removal, activating at {leave_height}, must be queued before the addition "
                f"activates at {join_height}"
            )
            overlapping_schedule = [
                scheduled_operator(
                    registration.index,
                    registration.activation_height,
                    leave_height
                    if registration.index == OVERLAPPING_LEAVER
                    else registration.deactivation_height,
                )
                for registration in same_block_schedule
            ]
            overlapping_schedule.append(scheduled_operator(OVERLAPPING_JOINER, join_height))
            restart_with_operator_schedule(
                nodes,
                overlapping_schedule,
                deposit_index_offset=OVERLAPPING_DEPOSIT_INDEX_OFFSET,
            )
            mine_until_processed(join_height, leave_height)
            # With mining paused, the joined covenant's stakes cannot confirm, so it does not admit
            # deposits yet.
            wait_until_current_covenant(
                member_rpcs(joined_members),
                joined_members,
                activation_height=join_height,
                admission_status=None,
            )
        wait_until_p2p_connected(member_rpcs(all_operators))
        overlapping_covenant = wait_until_current_covenant(
            member_rpcs(overlapping_members),
            overlapping_members,
            activation_height=leave_height,
        )

        self.logger.info("Restart: every node restarts on the final schedule")
        restart_with_operator_schedule(
            nodes,
            overlapping_schedule,
            deposit_index_offset=OVERLAPPING_DEPOSIT_INDEX_OFFSET,
        )
        wait_until_p2p_connected(member_rpcs(all_operators))
        restored = wait_until_current_covenant(
            member_rpcs(overlapping_members),
            overlapping_members,
            activation_height=leave_height,
        )
        assert restored == overlapping_covenant, (
            f"the covenant must survive a restart on an unchanged schedule: {restored} after "
            f"{overlapping_covenant}"
        )
        overlapping_deposit_idx = OVERLAPPING_DEPOSIT_INDEX_OFFSET
        overlapping_deposit_txid = deposit(overlapping_members, overlapping_deposit_idx)
        assert_absent(SAME_BLOCK_LEAVER, overlapping_deposit_idx)
        assert_absent(OVERLAPPING_LEAVER, overlapping_deposit_idx)

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
        self.logger.info("Withdrawals: every covenant's deposit pays out cooperatively")
        withdraw_cooperatively(genesis_deposit_idx, genesis_deposit_txid, GENESIS_MEMBERS[0])
        withdraw_cooperatively(same_block_deposit_idx, same_block_deposit_txid, SAME_BLOCK_JOINER)
        withdraw_cooperatively(
            overlapping_deposit_idx, overlapping_deposit_txid, OVERLAPPING_JOINER
        )

        return True
