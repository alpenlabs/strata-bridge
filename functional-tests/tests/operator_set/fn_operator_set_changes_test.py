import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import cast

import flexitest

from constants import BLOCK_GENERATION_INTERVAL_SECS
from envs import AsmEnvConfig, OperatorSetChangeEnv, StrataLiveEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.config_cfg import BridgeConfigParams
from utils.bridge import bridge_rpc_url
from utils.covenant import wait_until_current_covenant
from utils.deposit import make_deposit, wait_until_asm_deposit
from utils.dev_cli import DevCli
from utils.network import wait_until_p2p_connected
from utils.operator_set import (
    restart_with_operator_schedule,
    scheduled_operator,
    write_operator_schedule,
)
from utils.utils import (
    read_all_operator_keys,
    snapshot_log_offsets,
    wait_until_logs_match,
)
from utils.wallet_store import wait_until_exited
from utils.withdrawal import (
    fulfill_withdrawal,
    tx_inputs,
    wait_until_active_valid_claim,
    wait_until_paid_out,
)

GENESIS_MEMBERS = [0, 1, 2]
JOINING_OPERATOR = 3
LEAVING_OPERATOR = 1

# Blocks between an admin operator set update's inclusion and its activation.
OPERATOR_UPDATE_DEPTH = 10

# Successor covenants start their deposit sequences clear of every earlier covenant's indices.
ADDITION_DEPOSIT_INDEX_OFFSET = 100
REMOVAL_DEPOSIT_INDEX_OFFSET = 200


@flexitest.register
class OperatorSetChangesTest(StrataTestBase):
    """
    Exercise admin-enacted operator set changes end to end on one network.

    Verifies that:
    - the genesis covenant admits a deposit that ASM records,
    - a planned addition activates at the ASM-enacted height after a coordinated restart on
      edited params,
    - the joining operator takes no part in deposits made before it joined,
    - after the addition, ASM records a deposit from the successor's own offset, and the genesis
      deposit is withdrawn and paid out while the joined operator keeps running,
    - a node refuses to start on params that rewrite a historical registration,
    - a planned removal deactivates its registration at the ASM-enacted height, after which the
      leaving operator takes no part in new deposits, and
    - after the removal, ASM records a deposit from the successor's own offset, and the joined
      operator withdraws a deposit made after it joined and is reimbursed through its own claim.
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(
            OperatorSetChangeEnv(
                # Assignees claim right after fulfilling instead of first trying a cooperative
                # payout.
                bridge_config_params=BridgeConfigParams(cooperative_payout_timeout=0),
                asm_config=AsmEnvConfig(operator_update_confirmation_depth=OPERATOR_UPDATE_DEPTH),
            )
        )

    def main(self, ctx: flexitest.RunContext):
        operator_keys = read_all_operator_keys()
        nodes = {idx: ctx.get_service(f"bridge_node_{idx}") for idx in range(len(operator_keys))}
        # `Service` is the static type; concrete bridge-node services attach `create_rpc`.
        rpcs = {idx: node.create_rpc() for idx, node in nodes.items()}  # ty: ignore[possibly-missing-attribute]
        self.live_env = cast(StrataLiveEnv, ctx.env)
        bitcoin = ctx.get_service("bitcoin")
        self.bitcoin_rpc = bitcoin.create_rpc()
        self.asm_rpc = ctx.get_service("asm_rpc").create_rpc()
        self.mining_address = self.bitcoin_rpc.proxy.getnewaddress()
        dev_cli = DevCli(bitcoin.props, operator_keys)

        def member_rpcs(members: list[int]) -> list:
            return [rpcs[idx] for idx in members]

        self.logger.info("Genesis: the genesis members admit a deposit")
        wait_until_p2p_connected(member_rpcs(GENESIS_MEMBERS))
        genesis_covenant = wait_until_current_covenant(
            member_rpcs(GENESIS_MEMBERS), GENESIS_MEMBERS
        )
        genesis_height = genesis_covenant.activation_height
        genesis_deposit_idx = 0
        genesis_deposit_txid = self._deposit(
            dev_cli, nodes[0], member_rpcs(GENESIS_MEMBERS), genesis_deposit_idx
        )

        self.logger.info(f"Planned addition: operator {JOINING_OPERATOR} joins")
        addition_members = GENESIS_MEMBERS + [JOINING_OPERATOR]
        # No node may process the activation block before it restarts on the edited schedule.
        with self._mining_paused():
            addition_height = self._include_operator_set_update(
                dev_cli, seqno=1, add_keys=[operator_keys[JOINING_OPERATOR].MUSIG2_KEY]
            )
            addition_schedule = [scheduled_operator(idx, genesis_height) for idx in GENESIS_MEMBERS]
            addition_schedule.append(scheduled_operator(JOINING_OPERATOR, addition_height))
            restart_with_operator_schedule(
                nodes, addition_schedule, deposit_index_offset=ADDITION_DEPOSIT_INDEX_OFFSET
            )
        wait_until_p2p_connected(member_rpcs(addition_members))
        wait_until_current_covenant(
            member_rpcs(addition_members), addition_members, activation_height=addition_height
        )
        assert genesis_deposit_idx not in rpcs[JOINING_OPERATOR].stratabridge_depositIndices(), (
            f"operator {JOINING_OPERATOR} must take no part in deposit {genesis_deposit_idx}, "
            "made before it joined"
        )
        addition_deposit_idx = ADDITION_DEPOSIT_INDEX_OFFSET
        addition_deposit_txid = self._deposit(
            dev_cli, nodes[0], member_rpcs(addition_members), addition_deposit_idx
        )

        self.logger.info("Withdrawal after the addition: the genesis deposit pays out")
        # ASM assigns the oldest unassigned deposit, the genesis one; operator 0 is one of its
        # active members.
        genesis_assignee = GENESIS_MEMBERS[0]
        fulfill_withdrawal(
            dev_cli,
            self.asm_rpc,
            self.bitcoin_rpc,
            rpcs[genesis_assignee],
            genesis_deposit_idx,
            genesis_assignee,
            genesis_height,
        )
        wait_until_paid_out(
            self.bitcoin_rpc,
            genesis_deposit_txid,
            genesis_deposit_idx,
            genesis_assignee,
            operator_keys[genesis_assignee].GENERAL_WALLET,
        )
        assert nodes[JOINING_OPERATOR].check_status(), (
            f"operator {JOINING_OPERATOR} must keep running through the withdrawal of deposit "
            f"{genesis_deposit_idx}, which it never took part in"
        )

        self.logger.info("Restart rejection: a node refuses a rewritten historical registration")
        rewritten_schedule = addition_schedule[:-1] + [
            scheduled_operator(JOINING_OPERATOR, addition_height + 1)
        ]
        self._assert_restart_rejected(nodes, nodes[0], rewritten_schedule, JOINING_OPERATOR)

        self.logger.info(f"Planned removal: operator {LEAVING_OPERATOR} leaves")
        removal_members = [idx for idx in addition_members if idx != LEAVING_OPERATOR]
        # No node may process the activation block before it restarts on the edited schedule.
        with self._mining_paused():
            removal_height = self._include_operator_set_update(
                dev_cli, seqno=2, remove_indices=[LEAVING_OPERATOR]
            )
            removal_schedule = [
                scheduled_operator(
                    registration.index,
                    registration.activation_height,
                    removal_height if registration.index == LEAVING_OPERATOR else None,
                )
                for registration in addition_schedule
            ]
            restart_with_operator_schedule(
                nodes, removal_schedule, deposit_index_offset=REMOVAL_DEPOSIT_INDEX_OFFSET
            )
        wait_until_p2p_connected(member_rpcs(addition_members))
        wait_until_current_covenant(
            member_rpcs(removal_members), removal_members, activation_height=removal_height
        )
        removal_deposit_idx = REMOVAL_DEPOSIT_INDEX_OFFSET
        self._deposit(dev_cli, nodes[0], member_rpcs(removal_members), removal_deposit_idx)
        assert removal_deposit_idx not in rpcs[LEAVING_OPERATOR].stratabridge_depositIndices(), (
            f"operator {LEAVING_OPERATOR} must take no part in deposit {removal_deposit_idx}, "
            "made after it left"
        )

        self.logger.info(
            f"Withdrawal after the removal: operator {JOINING_OPERATOR} claims its deposit"
        )
        # ASM assigns the oldest unassigned deposit: the first one made after operator 3 joined.
        fulfill_withdrawal(
            dev_cli,
            self.asm_rpc,
            self.bitcoin_rpc,
            rpcs[JOINING_OPERATOR],
            addition_deposit_idx,
            JOINING_OPERATOR,
            genesis_height,
        )
        claim = wait_until_active_valid_claim(rpcs[JOINING_OPERATOR])
        assert (claim.deposit_idx, claim.assigned_operator) == (
            addition_deposit_idx,
            JOINING_OPERATOR,
        ), f"operator {JOINING_OPERATOR} must claim deposit {addition_deposit_idx}, got {claim}"
        payout_txid = wait_until_paid_out(
            self.bitcoin_rpc,
            addition_deposit_txid,
            addition_deposit_idx,
            JOINING_OPERATOR,
            operator_keys[JOINING_OPERATOR].GENERAL_WALLET,
        )
        payout_inputs = tx_inputs(self.bitcoin_rpc, payout_txid)
        assert any(txid == claim.claim_txid for txid, _ in payout_inputs), (
            f"payout {payout_txid} must spend claim {claim.claim_txid}, spent {payout_inputs}"
        )

        return True

    def _deposit(self, dev_cli: DevCli, node, member_rpcs: list, expected_idx: int) -> str:
        """Make a deposit at `expected_idx` that every member completes and ASM records.

        Returns the deposit txid.
        """
        deposit_txid = make_deposit(dev_cli, bridge_rpc_url(node), member_rpcs, expected_idx)
        wait_until_asm_deposit(self.asm_rpc, self.bitcoin_rpc, expected_idx)
        return deposit_txid

    def _assert_restart_rejected(self, nodes: dict, node, schedule: list, mismatched_idx: int):
        """Restart `node` alone on `schedule` and check it exits over `mismatched_idx`.

        The node is left stopped.
        """
        node.stop()
        time.sleep(5)  # ports need to be released before restarting
        write_operator_schedule(node, nodes, schedule)
        offsets = snapshot_log_offsets([node.props["logfile"]])
        node.start()

        exit_code = wait_until_exited(node)
        node.stop()
        assert exit_code != 0, f"a node rejecting its params must fail, exited with {exit_code}"
        wait_until_logs_match(
            offsets,
            lambda line: (
                f"registration {mismatched_idx} is missing or has conflicting historical "
                "configuration" in line
            ),
            error_msg=f"the node must name registration {mismatched_idx} as rewritten",
        )

    def _include_operator_set_update(
        self,
        dev_cli: DevCli,
        seqno: int,
        add_keys: list[str] | None = None,
        remove_indices: list[int] | None = None,
    ) -> int:
        """Mine an admin operator set update into the next block and return its activation height.

        Mining must be paused, so the update lands in exactly that block.
        """
        txid = dev_cli.send_operator_set_update(seqno, add_keys, remove_indices)
        [block_hash] = self.bitcoin_rpc.proxy.generatetoaddress(1, self.mining_address)
        block = self.bitcoin_rpc.proxy.getblock(block_hash)
        assert txid in block["tx"], f"operator set update {txid} must be mined in {block_hash}"

        activation_height = block["height"] + OPERATOR_UPDATE_DEPTH
        self.logger.info(
            f"Operator set update {txid} mined at {block['height']}, "
            f"activating at {activation_height}"
        )
        return activation_height

    @contextmanager
    def _mining_paused(self) -> Iterator[None]:
        """Pause block production for the duration of the block, resuming it afterwards."""
        self.live_env.stop_miner()
        yield
        self.live_env.start_miner(
            self.bitcoin_rpc, BLOCK_GENERATION_INTERVAL_SECS, self.mining_address
        )
