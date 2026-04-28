import hashlib
import struct

import flexitest

from constants import MAX_BRIDGE_TIMEOUT
from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import BridgeProtocolParams
from rpc.asm_types import AsmWorkerStatus, AssignmentEntry
from rpc.types import RpcDepositStatusComplete
from utils.bridge import get_bridge_nodes_and_rpcs
from utils.deposit import (
    wait_until_deposit_status,
    wait_until_drts_recognized,
)
from utils.dev_cli import DevCli
from utils.utils import (
    read_operator_key,
    wait_for_tx_confirmation,
    wait_until,
)

# Bridge V1 container ID; matches `BRIDGE_V1_SUBPROTOCOL_ID` in the asm crate.
BRIDGE_V1_CONTAINER_ID = 2

NUM_FULFILLMENTS = 2


def operator_claim_unlock_leaf(deposit_idx: int, operator_idx: int) -> bytes:
    # `OperatorClaimUnlock` codec serialization is two big-endian u32s in
    # declaration order; the leaf is sha256 over those 8 bytes.
    buf = struct.pack(">II", deposit_idx, operator_idx)
    return hashlib.sha256(buf).digest()


@flexitest.register
class AsmProofReadinessTest(StrataTestBase):
    """
    Test that, once fulfillments are processed, the asm-runner has all three
    inputs the bridge proof needs available at the same block:

    - `MohoState`             via `strata_asm_getMohoState`
    - `MohoProof`             via `strata_asm_getMohoProof`
    - per-leaf MMR inclusion  via `strata_asm_getExportEntryMMRProof`
      for each fulfilled `OperatorClaimUnlock` leaf

    Steps:
    1. Create two deposits and wait for both to complete
    2. Post a mock checkpoint with two withdrawal commands so ASM produces two assignments
    3. Snapshot `(deposit_idx → assignee)` from the assignments — those are the
       inputs the bridge handler will hash into each `OperatorClaimUnlock` leaf
    4. Wait until both assignments clear (both fulfillments processed by ASM)
    5. For each leaf, fetch the MMR proof and assert it is non-empty
    6. Fetch `MohoState` and `MohoProof` at the same block and assert non-empty
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(
            BridgeNetworkEnv(
                bridge_protocol_params=BridgeProtocolParams(contest_timelock=MAX_BRIDGE_TIMEOUT),
                bridge_config_params=BridgeConfigParams(
                    cooperative_payout_timeout=MAX_BRIDGE_TIMEOUT,
                ),
                # `strata_asm_getExportEntryMMRProof` is gated on the asm-runner having
                # an open `MohoStateDb` + `ExportEntriesDb`; both are wired up only
                # when the proof orchestrator is configured.
                enable_asm_proof=True,
            )
        )

    def main(self, ctx: flexitest.RunContext):
        bridge_nodes, bridge_rpcs = get_bridge_nodes_and_rpcs(ctx)
        bridge_rpc = bridge_rpcs[0]

        bitcoind_service = ctx.get_service("bitcoin")
        bitcoin_rpc = bitcoind_service.create_rpc()

        num_operators = len(bridge_nodes)
        operator_key_infos = [read_operator_key(i) for i in range(num_operators)]

        asm_service = ctx.get_service("asm_rpc")
        asm_rpc = asm_service.create_rpc()

        bitcoind_props = bitcoind_service.props
        dev_cli = DevCli(bitcoind_props, operator_key_infos)

        # --- Two deposits ---
        drt_txids = [dev_cli.send_deposit_request() for _ in range(NUM_FULFILLMENTS)]
        for i, drt_txid in enumerate(drt_txids):
            self.logger.info(f"Broadcasted DRT[{i}]: {drt_txid}")

        deposit_ids = wait_until_drts_recognized(bridge_rpc, drt_txids, timeout=300)
        self.logger.info(f"Both DRTs recognized: {deposit_ids}")

        for deposit_id in deposit_ids:
            wait_until_deposit_status(bridge_rpc, deposit_id, RpcDepositStatusComplete, timeout=600)
        self.logger.info("Both deposits completed")

        # --- One checkpoint creating two withdrawal commands → two assignments ---
        recent_block_hash = bitcoin_rpc.proxy.getblockhash(bitcoin_rpc.proxy.getblockcount())
        ckp_l1_txn = dev_cli.send_mock_checkpoint_from_tip(
            asm_rpc,
            recent_block_hash,
            num_ol_slots=1,
            num_withdrawals=NUM_FULFILLMENTS,
        )
        ckp_block_hash = wait_for_tx_confirmation(bitcoin_rpc, ckp_l1_txn)
        self.logger.info(f"Checkpoint tx {ckp_l1_txn} included in block {ckp_block_hash}")

        # Wait until both assignments are visible at the checkpoint block, then
        # snapshot (deposit_idx → assignee) — that pair is what the bridge handler
        # will hash into the `OperatorClaimUnlock` leaf at fulfillment time. Long
        # `assignment_duration` and `MAX_BRIDGE_TIMEOUT` keep these stable.
        assignee_for: dict[int, int] = {}

        def assignments_ready():
            assignments = asm_rpc.strata_asm_getAssignments(ckp_block_hash)
            if len(assignments) < NUM_FULFILLMENTS:
                return False
            assignee_for.clear()
            for raw in assignments:
                entry = AssignmentEntry.from_dict(raw)
                assignee_for[entry.deposit_entry.deposit_idx] = entry.current_assignee
            return set(assignee_for.keys()) == set(range(NUM_FULFILLMENTS))

        wait_until(
            assignments_ready,
            timeout=300,
            error_msg=f"ASM did not produce {NUM_FULFILLMENTS} assignments",
        )
        for d_idx, op_idx in sorted(assignee_for.items()):
            self.logger.info(f"Assignment: deposit_idx={d_idx} → operator-{op_idx}")

        # --- Wait until both assignments are cleared (= both fulfillments processed) ---
        latest_state: dict[str, str | int | None] = {"hash": None, "height": None}

        def assignments_cleared():
            height = bitcoin_rpc.proxy.getblockcount()
            block_hash = bitcoin_rpc.proxy.getblockhash(height)
            if len(asm_rpc.strata_asm_getAssignments(block_hash)) == 0:
                latest_state["hash"] = block_hash
                latest_state["height"] = height
                return True
            return False

        wait_until(
            assignments_cleared,
            timeout=600,
            step=1,
            error_msg="Assignments did not clear — fulfillments did not complete",
        )
        target_block_hash = latest_state["hash"]
        target_height = latest_state["height"]
        assert isinstance(target_block_hash, str) and isinstance(target_height, int)
        self.logger.info(
            f"Both fulfillments processed by ASM at block {target_block_hash} "
            f"(height {target_height})"
        )

        # --- Wait for ASM's `cur_block` to reach the query height ---
        def asm_caught_up():
            status = AsmWorkerStatus.from_dict(asm_rpc.strata_asm_getStatus())
            return status.cur_block is not None and status.cur_block.height >= target_height

        wait_until(
            asm_caught_up,
            timeout=120,
            error_msg=f"ASM did not reach height {target_height}",
        )

        # --- Compute expected leaves and query each proof ---
        leaves = {
            d_idx: operator_claim_unlock_leaf(d_idx, op_idx)
            for d_idx, op_idx in assignee_for.items()
        }
        for d_idx, leaf in leaves.items():
            self.logger.info(f"Expected leaf[deposit_idx={d_idx}]: {leaf.hex()}")

        for d_idx, leaf in leaves.items():
            raw = asm_rpc.strata_asm_getExportEntryMMRProof(
                target_block_hash, BRIDGE_V1_CONTAINER_ID, list(leaf)
            )
            assert raw is not None, (
                f"strata_asm_getExportEntryMMRProof returned None for deposit_idx={d_idx}"
            )
            proof_bytes = bytes(raw)
            assert len(proof_bytes) > 0, f"empty proof for deposit_idx={d_idx}"
            self.logger.info(f"proof[d{d_idx}]: {len(proof_bytes)}B")

        # --- MohoState is produced for every processed block, query directly ---
        moho_state_raw = asm_rpc.strata_asm_getMohoState(target_block_hash)
        assert moho_state_raw is not None, (
            f"strata_asm_getMohoState returned None for {target_block_hash}"
        )
        moho_state_bytes = bytes(moho_state_raw)
        assert len(moho_state_bytes) > 0, f"empty MohoState payload at {target_block_hash}"
        self.logger.info(f"MohoState: {len(moho_state_bytes)}B")

        # --- MohoProof is recursive on top of the ASM proof; wait for it ---
        def moho_proof_ready():
            return asm_rpc.strata_asm_getMohoProof(target_block_hash) is not None

        wait_until(
            moho_proof_ready,
            timeout=600,
            step=2,
            error_msg=f"MohoProof not generated for {target_block_hash}",
        )
        moho_proof = asm_rpc.strata_asm_getMohoProof(target_block_hash)
        assert moho_proof is not None, (
            f"strata_asm_getMohoProof returned None for {target_block_hash}"
        )
        self.logger.info(f"MohoProof present at {target_block_hash}")

        return True
