import flexitest

from constants import MAX_BRIDGE_TIMEOUT
from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import BridgeProtocolParams
from rpc.types import RpcDepositStatusComplete, RpcDepositStatusFailed
from utils.bridge import bridge_rpc_url, get_bridge_nodes_and_rpcs
from utils.deposit import (
    wait_until_deposit_status,
    wait_until_deposit_utxo_spent,
    wait_until_drt_recognized,
    wait_until_drts_recognized,
)
from utils.dev_cli import DevCli
from utils.utils import (
    read_operator_key,
    wait_for_tx_confirmation,
    wait_until,
    wait_until_bridge_ready,
)

DEPOSIT_CAP = 2


@flexitest.register
class BridgeDepositCapTest(StrataTestBase):
    """
    Checks that `max_active_deposits` really limits how many deposits an operator takes part in.

    The flow: fill the cap with two deposits, send one more DRT, withdraw one of the deposits,
    then send another DRT. Along the way we check, on every operator, that the surplus DRT was
    registered under the next index but recorded as skipped (a failed deposit that never
    completes), that the DRT sent after the withdrawal takes the freed slot and completes, and
    that a restarted node comes back with the same registry.
    """

    def __init__(self, ctx: flexitest.InitContext):
        # The long timelocks keep the cooperative payout from timing out while we wait.
        ctx.set_env(
            BridgeNetworkEnv(
                bridge_protocol_params=BridgeProtocolParams(contest_timelock=MAX_BRIDGE_TIMEOUT),
                bridge_config_params=BridgeConfigParams(
                    cooperative_payout_timeout=MAX_BRIDGE_TIMEOUT,
                    max_active_deposits=DEPOSIT_CAP,
                ),
            )
        )

    def main(self, ctx: flexitest.RunContext):
        bridge_nodes, bridge_rpcs = get_bridge_nodes_and_rpcs(ctx)
        bridge_rpc = bridge_rpcs[0]

        bitcoind_service = ctx.get_service("bitcoin")
        bitcoin_rpc = bitcoind_service.create_rpc()
        asm_rpc = ctx.get_service("asm_rpc").create_rpc()
        operator_key_infos = [read_operator_key(i) for i in range(len(bridge_nodes))]
        dev_cli = DevCli(bitcoind_service.props, operator_key_infos)

        self.logger.info(f"Broadcasting {DEPOSIT_CAP} DRTs to fill the cap")
        admitted_txids = [
            dev_cli.send_deposit_request(bridge_rpc_url(bridge_nodes[0]))
            for _ in range(DEPOSIT_CAP)
        ]
        admitted_ids = wait_until_drts_recognized(bridge_rpc, admitted_txids, timeout=180)
        deposit_txids = {}
        for deposit_id in admitted_ids:
            info = wait_until_deposit_status(bridge_rpc, deposit_id, RpcDepositStatusComplete)
            assert info is not None, f"deposit {deposit_id} did not complete"
            deposit_txids[deposit_id] = info.get("status").get("deposit_txid")
        self.logger.info(f"Deposits {admitted_ids} completed; the cap is full")

        # A node whose cap is full refuses to vouch for its covenant, so the surplus DRT is built
        # without asking it.
        surplus_txid = dev_cli.send_deposit_request(unchecked=True)
        for idx, rpc in enumerate(bridge_rpcs):
            surplus_id = wait_until_drt_recognized(rpc, surplus_txid, timeout=180)
            assert surplus_id == DEPOSIT_CAP, f"operator {idx} gave the surplus DRT {surplus_id}"
            self._assert_skipped(rpc, surplus_id, f"operator {idx}")
        self.logger.info(f"Surplus DRT {surplus_txid} recorded as failed on every operator")

        # The next DRT needs the slot free on every operator, so wait for each to see the spend.
        withdrawn_id = min(admitted_ids)
        recent_block_hash = bitcoin_rpc.proxy.getblockhash(bitcoin_rpc.proxy.getblockcount())
        ckp_txid = dev_cli.send_mock_checkpoint_from_tip(asm_rpc, recent_block_hash, num_ol_slots=1)
        ckp_block_hash = wait_for_tx_confirmation(bitcoin_rpc, ckp_txid)
        wait_until(
            lambda: len(asm_rpc.strata_asm_getAssignments(ckp_block_hash)) > 0,
            timeout=300,
            error_msg="ASM did not produce an assignment",
        )
        for idx, rpc in enumerate(bridge_rpcs):
            wait_until(
                lambda rpc=rpc: withdrawn_id in rpc.stratabridge_pendingWithdrawals(),
                timeout=300,
                error_msg=f"operator {idx} never saw deposit {withdrawn_id} assigned",
            )
        wait_until_deposit_utxo_spent(bitcoin_rpc, deposit_txids[withdrawn_id], timeout=450)
        for idx, rpc in enumerate(bridge_rpcs):
            wait_until(
                lambda rpc=rpc: withdrawn_id not in rpc.stratabridge_pendingWithdrawals(),
                timeout=120,
                error_msg=f"operator {idx} still lists deposit {withdrawn_id} as pending",
            )
        self.logger.info(f"Deposit {withdrawn_id} withdrawn on every operator; the slot is free")

        next_txid = dev_cli.send_deposit_request(bridge_rpc_url(bridge_nodes[0]))
        next_id = wait_until_drt_recognized(bridge_rpc, next_txid)
        assert next_id == DEPOSIT_CAP + 1, f"expected the next index, got {next_id}"
        wait_until_deposit_status(bridge_rpc, next_id, RpcDepositStatusComplete)
        self.logger.info(f"Deposit {next_id} admitted under the freed slot and completed")

        expected_mapping = dict(zip(admitted_txids, admitted_ids, strict=True))
        expected_mapping[surplus_txid] = DEPOSIT_CAP
        expected_mapping[next_txid] = next_id
        for idx, rpc in enumerate(bridge_rpcs):
            self._assert_registry(rpc, expected_mapping, f"operator {idx}")

        self.logger.info("Restarting operator 0; the registry must come back unchanged")
        bridge_nodes[0].stop()
        bridge_nodes[0].start()
        wait_until_bridge_ready(bridge_rpcs[0])
        self._assert_registry(bridge_rpcs[0], expected_mapping, "operator 0 after restart")
        self._assert_skipped(bridge_rpcs[0], DEPOSIT_CAP, "operator 0 after restart")

        return True

    def _assert_skipped(self, rpc, deposit_id: int, who: str):
        status = rpc.stratabridge_depositInfo(deposit_id)["status"]
        assert status["status"] == RpcDepositStatusFailed.status, (
            f"{who} reports deposit {deposit_id} as {status}, expected failed"
        )
        assert status["reason"] == "Deposit cap reached", (
            f"{who} reports deposit {deposit_id} as failed for another reason: {status}"
        )

    def _assert_registry(self, rpc, expected_mapping: dict, who: str):
        # Compare the full DRT-to-index mapping: a count alone would pass an operator that
        # aborted one of the admitted DRTs instead of the surplus one.
        mapping = {
            info["deposit_request_txid"]: int(info["deposit_idx"])
            for info in (
                rpc.stratabridge_depositInfo(deposit_idx)
                for deposit_idx in rpc.stratabridge_depositIndices()
            )
        }
        assert mapping == expected_mapping, (
            f"{who} disagrees on the registry: expected {expected_mapping}, got {mapping}"
        )
