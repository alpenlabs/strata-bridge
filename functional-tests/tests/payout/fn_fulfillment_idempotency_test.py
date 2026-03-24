"""
Fulfillment Idempotency Test

Verifies that when an operator restarts after submitting a withdrawal fulfillment
transaction (but before it confirms), it reconstructs the exact same transaction.

Test flow:
1. Create deposit and wait for ASM to assign fulfillment duty
2. Capture initial fulfillment txid from operator logs, verify in mempool
3. Clear mempool by restarting bitcoind (forces operator to rebuild tx)
4. Restart operator and capture resubmitted txid from logs
5. Assert txids match (proves idempotency)
"""

import os
import re
from typing import cast

import flexitest

from constants import DT_DEPOSIT_VOUT, MAX_BRIDGE_TIMEOUT
from envs import BitcoinEnvConfig, BridgeNetworkEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import BridgeProtocolParams
from rpc.asm_types import AssignmentEntry
from rpc.types import RpcDepositStatusComplete
from utils.bridge import get_bridge_nodes_and_rpcs
from utils.deposit import (
    wait_until_deposit_status,
    wait_until_drt_recognized,
)
from utils.dev_cli import DevCli
from utils.utils import (
    read_operator_key,
    snapshot_log_offsets,
    wait_for_log_capture,
    wait_for_tx_confirmation,
    wait_until,
    wait_until_bitcoind_ready,
    wait_until_bridge_ready,
)

# Regex to capture txid from operator's fulfillment submission log
FULFILLMENT_SUBMIT_RE = re.compile(
    r"submitting withdrawal fulfillment transaction.*txid=([0-9a-f]{64})"
)


@flexitest.register
class FulfillmentIdempotencyTest(StrataTestBase):
    """
    Test that fulfillment retry after assignee restart is idempotent.
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(
            BridgeNetworkEnv(
                bridge_protocol_params=BridgeProtocolParams(contest_timelock=MAX_BRIDGE_TIMEOUT),
                bridge_config_params=BridgeConfigParams(
                    cooperative_payout_timeout=MAX_BRIDGE_TIMEOUT,
                ),
                btc_config=BitcoinEnvConfig(block_generation_interval_secs=10),
            )
        )

    def main(self, ctx: flexitest.RunContext):
        bridge_nodes, bridge_rpcs = get_bridge_nodes_and_rpcs(ctx)
        bitcoind_service = ctx.get_service("bitcoin")
        bitcoin_rpc = bitcoind_service.create_rpc()

        num_operators = len(bridge_nodes)
        musig2_keys = [read_operator_key(i).MUSIG2_KEY for i in range(num_operators)]

        asm_service = ctx.get_service("asm_rpc")
        asm_rpc = asm_service.create_rpc()

        # --- Setup: Create deposit and trigger fulfillment assignment ---
        bitcoind_props = bitcoind_service.props
        dev_cli = DevCli(bitcoind_props, musig2_keys)
        drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted DRT: {drt_txid}")

        bridge_rpc = bridge_rpcs[0]
        deposit_id = wait_until_drt_recognized(bridge_rpc, drt_txid)
        self.logger.info(f"DRT recognized, deposit_id: {deposit_id}")

        deposit_info = wait_until_deposit_status(bridge_rpc, deposit_id, RpcDepositStatusComplete)
        assert deposit_info is not None, "Deposit did not complete"
        deposit_txid = deposit_info.get("status").get("deposit_txid")
        self.logger.info(f"Deposit completed with txid: {deposit_txid}")

        # Post checkpoint to trigger ASM assignment (auto-miner will confirm it)
        recent_block_hash = bitcoin_rpc.proxy.getblockhash(bitcoin_rpc.proxy.getblockcount())
        ckp_l1_txn = dev_cli.send_mock_checkpoint_from_tip(
            asm_rpc,
            recent_block_hash,
            num_ol_slots=1,
        )
        ckp_block_hash = wait_for_tx_confirmation(bitcoin_rpc, ckp_l1_txn)
        self.logger.info(f"Checkpoint tx {ckp_l1_txn} included in block {ckp_block_hash}")

        assignment_state = {"entry": None}

        def assignment_ready():
            assignments_raw = asm_rpc.strata_asm_getAssignments(ckp_block_hash)
            for raw in assignments_raw:
                assignment = AssignmentEntry.from_dict(raw)
                if assignment.deposit_entry.deposit_idx == 0:
                    assignment_state["entry"] = assignment
                    return True
            return False

        wait_until(
            assignment_ready,
            timeout=300,
            error_msg="ASM did not produce an assignment for deposit_idx=0",
        )
        assignment = assignment_state["entry"]
        assert assignment is not None, "Assignment not found after wait_until succeeded"
        assignee_idx = assignment.current_assignee
        self.logger.info(f"Assignee for deposit_idx=0: operator-{assignee_idx}")

        # --- Capture initial fulfillment txid from logs, verify in mempool ---
        assignee_logfile = bridge_nodes[assignee_idx].props["logfile"]

        self.logger.info("Waiting for fulfillment tx submission in operator logs...")
        fulfillment_txid = wait_for_log_capture(
            assignee_logfile,
            FULFILLMENT_SUBMIT_RE,
            error_msg="Fulfillment tx submission not found in operator logs",
        ).group(1)
        self.logger.info(f"Fulfillment tx submitted: {fulfillment_txid}")

        # Verify txid exists in mempool (source of truth)
        def initial_tx_in_mempool():
            mempool = bitcoin_rpc.proxy.getrawmempool()
            return fulfillment_txid in mempool

        wait_until(
            initial_tx_in_mempool,
            timeout=30,
            error_msg=f"Fulfillment txid from logs ({fulfillment_txid}) not found in mempool",
        )
        self.logger.info("Verified fulfillment tx exists in mempool")

        # --- Stop miner and clear mempool to force retry fulfillment ---
        if not hasattr(ctx, "env") or not hasattr(ctx.env, "stop_miner"):
            raise AssertionError("Run context does not expose a stoppable miner via ctx.env")
        cast(BridgeNetworkEnv, ctx.env).stop_miner()
        self.logger.info(
            "Stopped auto miner at block height %s",
            bitcoin_rpc.proxy.getblockcount(),
        )

        tx_info_before_restart = bitcoin_rpc.proxy.getrawtransaction(fulfillment_txid, True)
        assert "blockhash" not in tx_info_before_restart, (
            "Fulfillment tx confirmed before miner stopped; increase block_generation_interval_secs"
        )
        self.logger.info("Verified fulfillment tx is unconfirmed before restart")

        # Clear mempool by deleting mempool.dat
        self.logger.info("Clearing mempool by deleting mempool.dat...")
        logfile_path = bitcoind_service.stdout
        datadir = os.path.dirname(logfile_path)
        mempool_path = os.path.join(datadir, "regtest", "mempool.dat")

        bitcoind_service.stop()
        self.logger.info("Stopped bitcoind")

        if os.path.exists(mempool_path):
            os.remove(mempool_path)
            self.logger.info(f"Deleted {mempool_path}")
        else:
            self.logger.info(f"mempool.dat not found at {mempool_path}")

        bitcoind_service.start()
        bitcoin_rpc = bitcoind_service.create_rpc()
        wait_until_bitcoind_ready(bitcoin_rpc, timeout=30)

        # Reload wallet (Bitcoin Core doesn't auto-load on restart)
        wallet_name = bitcoind_service.get_prop("walletname")
        bitcoin_rpc.proxy.loadwallet(wallet_name)
        self.logger.info(f"Loaded wallet: {wallet_name}")

        self.logger.info("Restarted bitcoind, mempool should now be empty")

        # ensure old fulfillment transaction is not in the mempool.
        mempool_after_clear = bitcoin_rpc.proxy.getrawmempool()
        assert len(mempool_after_clear) == 0, f"Mempool not empty: {mempool_after_clear}"
        assert fulfillment_txid not in mempool_after_clear
        self.logger.info("Confirmed mempool is empty and original fulfillment tx is gone")

        # ensure that deposit is not spent so that withdrawal fulfillment will be retried.
        utxo_status = bitcoin_rpc.proxy.gettxout(deposit_txid, DT_DEPOSIT_VOUT)
        assert utxo_status is not None, "Deposit UTXO should still be unspent"
        self.logger.info("Confirmed deposit UTXO is still unspent")

        # --- Restart operator and capture resubmitted fulfillment ---
        # Capture log offset before restart to catch all post-restart logs
        restart_log_offsets = snapshot_log_offsets([assignee_logfile])

        self.logger.info(f"Restarting assigned operator-{assignee_idx}")
        bridge_nodes[assignee_idx].stop()
        bridge_nodes[assignee_idx].start()
        wait_until_bridge_ready(bridge_rpcs[assignee_idx])
        self.logger.info(f"Operator-{assignee_idx} restarted and ready")

        self.logger.info("Waiting for operator to resubmit fulfillment tx (checking logs)...")
        resubmitted_txid = wait_for_log_capture(
            assignee_logfile,
            FULFILLMENT_SUBMIT_RE,
            log_offsets=restart_log_offsets,
            error_msg="Post-restart fulfillment submission not found in operator logs",
        ).group(1)
        self.logger.info(f"Fulfillment tx resubmitted with txid: {resubmitted_txid}")

        # --- Verify idempotency ---
        assert resubmitted_txid == fulfillment_txid, (
            f"IDEMPOTENCY VIOLATION: Operator rebuilt a different transaction!\n"
            f"  Original txid:    {fulfillment_txid}\n"
            f"  Resubmitted txid: {resubmitted_txid}"
        )
        self.logger.info("IDEMPOTENCY VERIFIED: Operator reconstructed the exact same transaction")

        return True
