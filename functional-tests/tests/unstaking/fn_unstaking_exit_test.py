import flexitest

from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from utils.bridge import bridge_rpc_url, get_bridge_nodes_and_rpcs
from utils.covenant import wait_until_current_covenant
from utils.deposit import make_deposit, wait_until_asm_deposit
from utils.dev_cli import DevCli
from utils.network import wait_until_p2p_connected
from utils.node_config import restart_bridge_node_with_overrides
from utils.utils import read_operator_key, wait_until_bridge_ready
from utils.withdrawal import fulfill_withdrawal, wait_until_paid_out

EXITING_OPERATOR = 2

# The successor starts its deposit sequence clear of the genesis covenant's indices.
EXIT_DEPOSIT_INDEX_OFFSET = 100


@flexitest.register
class UnstakingExitTest(StrataTestBase):
    """
    Test that an unstaking intent evicts its operator without a restart, and that deposits and
    withdrawals keep working afterwards.

    Verifies that:
    - the remaining members agree on a ready successor covenant that keeps the covenant's
      activation height under a new aggregate key,
    - the exit survives a restart on params that still list the exited operator,
    - ASM records a deposit to the successor from its own offset, and
    - the deposit made before the exit, which the exited operator co-signed, and the one made
      after it are both withdrawn and paid out.
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(BridgeNetworkEnv())

    def main(self, ctx: flexitest.RunContext):
        bridge_nodes, bridge_rpcs = get_bridge_nodes_and_rpcs(ctx)
        bitcoind_service = ctx.get_service("bitcoin")
        bitcoin_rpc = bitcoind_service.create_rpc()
        asm_rpc = ctx.get_service("asm_rpc").create_rpc()
        operator_keys = [read_operator_key(i) for i in range(len(bridge_nodes))]
        dev_cli = DevCli(bitcoind_service.props, operator_keys)

        members = list(range(len(bridge_nodes)))
        genesis_covenant = wait_until_current_covenant(bridge_rpcs, members)
        genesis_height = genesis_covenant.activation_height
        pre_exit_deposit_idx = 0
        pre_exit_deposit_txid = make_deposit(
            dev_cli, bridge_rpc_url(bridge_nodes[0]), bridge_rpcs, pre_exit_deposit_idx
        )
        wait_until_asm_deposit(asm_rpc, bitcoin_rpc, pre_exit_deposit_idx)

        self.logger.info(f"Operator {EXITING_OPERATOR} unstakes")
        dev_cli.send_unstaking_intent(
            EXITING_OPERATOR,
            bridge_rpc_url(bridge_nodes[EXITING_OPERATOR]),
            operator_keys[EXITING_OPERATOR].SEED,
        )
        survivors = [idx for idx in members if idx != EXITING_OPERATOR]
        survivor_rpcs = [bridge_rpcs[idx] for idx in survivors]
        successor = wait_until_current_covenant(
            survivor_rpcs, survivors, activation_height=genesis_height
        )
        assert successor.aggregate_pubkey != genesis_covenant.aggregate_pubkey, (
            f"an exit must change the covenant's aggregate key: {successor} after "
            f"{genesis_covenant}"
        )

        # The exit itself needs no restart; this one only loads the successor's fresh offset.
        for node in bridge_nodes:
            restart_bridge_node_with_overrides(
                node,
                config_overrides={},
                params_overrides={"protocol": {"deposit_index_offset": EXIT_DEPOSIT_INDEX_OFFSET}},
            )
        for rpc in bridge_rpcs:
            wait_until_bridge_ready(rpc)
        wait_until_p2p_connected(bridge_rpcs)
        restored = wait_until_current_covenant(
            survivor_rpcs, survivors, activation_height=genesis_height
        )
        assert restored == successor, (
            f"the exit must survive a restart on params that still list operator "
            f"{EXITING_OPERATOR}: {restored} after {successor}"
        )

        post_exit_deposit_idx = EXIT_DEPOSIT_INDEX_OFFSET
        post_exit_deposit_txid = make_deposit(
            dev_cli, bridge_rpc_url(bridge_nodes[0]), survivor_rpcs, post_exit_deposit_idx
        )
        wait_until_asm_deposit(asm_rpc, bitcoin_rpc, post_exit_deposit_idx)

        # ASM assigns the oldest unassigned deposit first, so the deposits are withdrawn in the
        # order they were made; each assignee is a survivor active in that deposit's covenant.
        for deposit_idx, deposit_txid, assignee in (
            (pre_exit_deposit_idx, pre_exit_deposit_txid, survivors[0]),
            (post_exit_deposit_idx, post_exit_deposit_txid, survivors[1]),
        ):
            self.logger.info(f"Withdrawing deposit {deposit_idx} through operator {assignee}")
            fulfill_withdrawal(
                dev_cli,
                asm_rpc,
                bitcoin_rpc,
                bridge_rpcs[assignee],
                deposit_idx,
                assignee,
                genesis_height,
            )
            wait_until_paid_out(
                bitcoin_rpc,
                deposit_txid,
                deposit_idx,
                assignee,
                operator_keys[assignee].GENERAL_WALLET,
            )

        return True
