from typing import Any, cast

import flexitest

from constants import CONTEST_WATCHTOWER_0_VOUT, DT_DEPOSIT_VOUT
from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import BridgeProtocolParams
from rpc.types import RpcDepositStatusComplete
from utils.bridge import get_bridge_nodes_and_rpcs
from utils.deposit import (
    wait_until_deposit_status,
    wait_until_drts_recognized,
    wait_until_utxo_spent,
)
from utils.dev_cli import DevCli
from utils.metrics import read_prometheus_metric_sum
from utils.utils import (
    find_utxo_spender_txid,
    read_operator_key,
    wait_for_tx_confirmation,
    wait_until,
)

ACK_TIMELOCK_BLOCKS = 15
COUNTERPROOF_GENERATION_METRIC = "strata_bridge_counterproof_generation_attempts"
PAYOUT_TIMEOUT_SECS = 600


@flexitest.register
class CounterproofSkippedAfterGcConsumedTest(StrataTestBase):
    """
    Test that a watchtower does not publish a second counterproof after its GC setup
    for the same operator has already been consumed.

    Steps:
    1. Complete two deposits.
    2. Post, contest, and refute an invalid claim from operator-0 for deposit 0.
    3. Wait for every watchtower counterproof output on the first contest to be spent.
    4. Post, contest, and refute another invalid claim from operator-0 for deposit 1.
    5. Wait for the second deposit to pay out after the ack timelock while asserting
       the counterproof generation-attempt metric does not increase and no watchtower
       counterproof output on the second contest is spent.
    """

    def __init__(self, ctx: flexitest.InitContext):
        self.bridge_protocol_params = BridgeProtocolParams(
            contest_timelock=5,
            ack_timelock=ACK_TIMELOCK_BLOCKS,
        )
        ctx.set_env(
            BridgeNetworkEnv(
                bridge_protocol_params=self.bridge_protocol_params,
                bridge_config_params=BridgeConfigParams(
                    cooperative_payout_timeout=0,
                    retry_interval_secs=1,
                    prometheus_metrics=True,
                ),
            )
        )

    def main(self, ctx: flexitest.RunContext):
        bridge_nodes, bridge_rpcs = get_bridge_nodes_and_rpcs(ctx)
        bridge_rpc = bridge_rpcs[0]

        bitcoind_service = ctx.get_service("bitcoin")
        bitcoin_rpc = bitcoind_service.create_rpc()

        num_operators = len(bridge_nodes)
        operator_key_infos = [read_operator_key(i) for i in range(num_operators)]

        dev_cli = DevCli(
            bitcoind_service.props,
            operator_key_infos,
            bridge_protocol_params=self.bridge_protocol_params,
        )

        drt_txids = [dev_cli.send_deposit_request() for _ in range(2)]
        for idx, drt_txid in enumerate(drt_txids):
            self.logger.info(f"Broadcasted DRT[{idx}]: {drt_txid}")

        deposit_ids = wait_until_drts_recognized(bridge_rpc, drt_txids)
        assert set(deposit_ids) >= {0, 1}, f"expected deposits 0 and 1, got {deposit_ids}"

        deposit_txids = {}
        for deposit_id in sorted(deposit_ids):
            deposit_info = wait_until_deposit_status(
                bridge_rpc,
                deposit_id,
                RpcDepositStatusComplete,
            )
            assert deposit_info is not None, f"Deposit {deposit_id} did not complete"
            deposit_data = cast("dict[str, Any]", deposit_info)
            deposit_txids[deposit_id] = str(deposit_data["status"]["deposit_txid"])
        self.logger.info("Both deposits completed")

        dishonest_idx = 0
        dishonest_rpc_url = f"http://127.0.0.1:{bridge_nodes[dishonest_idx].props['rpc_port']}"
        dishonest_seed = read_operator_key(dishonest_idx).SEED

        first_contest_txid, _ = self.post_faulty_claim_contest_and_proof(
            bitcoin_rpc,
            dev_cli,
            deposit_idx=0,
            operator_idx=dishonest_idx,
            bridge_node_url=dishonest_rpc_url,
            seed=dishonest_seed,
        )

        num_watchtowers = num_operators - 1
        self.wait_for_all_counterproofs(bitcoin_rpc, first_contest_txid, num_watchtowers)
        counterproof_attempts = self.counterproof_generation_attempts_by_node(bridge_nodes)
        assert sum(counterproof_attempts.values()) >= num_watchtowers, (
            "first invalid proof should have generated counterproofs; "
            f"attempts by node: {counterproof_attempts}"
        )
        self.logger.info("First invalid proof consumed every watchtower GC setup")

        second_contest_txid, second_contest_block_height = self.post_faulty_claim_contest_and_proof(
            bitcoin_rpc,
            dev_cli,
            deposit_idx=1,
            operator_idx=dishonest_idx,
            bridge_node_url=dishonest_rpc_url,
            seed=dishonest_seed,
        )

        self.wait_for_contested_payout_after_ack_timelock_without_counterproof(
            bitcoin_rpc,
            bridge_nodes,
            deposit_txid=deposit_txids[1],
            contest_txid=second_contest_txid,
            contest_block_height=second_contest_block_height,
            num_watchtowers=num_watchtowers,
            counterproof_attempts=counterproof_attempts,
        )
        self.logger.info("Second invalid proof paid out without counterproof generation")

        return True

    def post_faulty_claim_contest_and_proof(
        self,
        bitcoin_rpc,
        dev_cli: DevCli,
        deposit_idx: int,
        operator_idx: int,
        bridge_node_url: str,
        seed: str,
    ) -> tuple[str, int]:
        claim_txid = dev_cli.send_claim(
            deposit_idx=deposit_idx,
            operator_idx=operator_idx,
            bridge_node_url=bridge_node_url,
            seed=seed,
        )
        self.logger.info(
            f"Broadcasted faulty claim tx from op-{operator_idx} "
            f"for deposit {deposit_idx}: {claim_txid}"
        )

        claim_block_hash = wait_for_tx_confirmation(bitcoin_rpc, claim_txid, timeout=300)
        self.logger.info(f"Faulty claim tx {claim_txid} confirmed in block {claim_block_hash}")

        wait_until_utxo_spent(bitcoin_rpc, claim_txid, vout=0, timeout=300)
        contest_txid = find_utxo_spender_txid(bitcoin_rpc, claim_txid, 0)
        contest_block_hash = wait_for_tx_confirmation(bitcoin_rpc, contest_txid, timeout=300)
        contest_block_height = self.block_height(bitcoin_rpc, contest_block_hash)
        self.logger.info(
            f"Claim {claim_txid} contested by tx {contest_txid} "
            f"confirmed in block {contest_block_hash} at height {contest_block_height}"
        )

        bridge_proof_txid = dev_cli.send_bridge_proof(
            deposit_idx=deposit_idx,
            operator_idx=operator_idx,
            bridge_node_url=bridge_node_url,
            seed=seed,
        )
        self.logger.info(
            f"Broadcasted faulty bridge proof tx from op-{operator_idx} "
            f"for deposit {deposit_idx}: {bridge_proof_txid}"
        )

        bridge_proof_block_hash = wait_for_tx_confirmation(
            bitcoin_rpc,
            bridge_proof_txid,
            timeout=300,
        )
        self.logger.info(
            f"Faulty bridge proof tx {bridge_proof_txid} "
            f"confirmed in block {bridge_proof_block_hash}"
        )

        return contest_txid, contest_block_height

    def block_height(self, bitcoin_rpc, block_hash: str) -> int:
        return int(bitcoin_rpc.proxy.getblock(block_hash)["height"])

    def wait_for_all_counterproofs(self, bitcoin_rpc, contest_txid: str, num_watchtowers: int):
        for slot in range(num_watchtowers):
            watchtower_vout = CONTEST_WATCHTOWER_0_VOUT + slot
            wait_until_utxo_spent(bitcoin_rpc, contest_txid, watchtower_vout, timeout=300)
            self.logger.info(
                f"Counterproof posted by watchtower slot {slot} (contest:{watchtower_vout} spent)"
            )

    def wait_for_contested_payout_after_ack_timelock_without_counterproof(
        self,
        bitcoin_rpc,
        bridge_nodes,
        deposit_txid: str,
        contest_txid: str,
        contest_block_height: int,
        num_watchtowers: int,
        counterproof_attempts: dict[int, int],
    ):
        payout_height_floor = contest_block_height + ACK_TIMELOCK_BLOCKS
        payout: dict[str, str | int | None] = {"txid": None, "height": None}
        invariant_error: dict[str, AssertionError | None] = {"error": None}

        def check_payout_after_ack_timelock():
            current_attempts = self.counterproof_generation_attempts_by_node(bridge_nodes)
            if current_attempts != counterproof_attempts:
                invariant_error["error"] = AssertionError(
                    "unexpected counterproof generation attempt after GC setup was consumed: "
                    f"before={counterproof_attempts}, after={current_attempts}"
                )
                return True

            for slot in range(num_watchtowers):
                watchtower_vout = CONTEST_WATCHTOWER_0_VOUT + slot
                if bitcoin_rpc.proxy.gettxout(contest_txid, watchtower_vout) is None:
                    spender = find_utxo_spender_txid(bitcoin_rpc, contest_txid, watchtower_vout)
                    invariant_error["error"] = AssertionError(
                        f"unexpected counterproof from watchtower slot {slot}: "
                        f"contest {contest_txid}:{watchtower_vout} spent by {spender}"
                    )
                    return True

            if bitcoin_rpc.proxy.gettxout(deposit_txid, DT_DEPOSIT_VOUT) is not None:
                return False

            payout_txid = find_utxo_spender_txid(bitcoin_rpc, deposit_txid, DT_DEPOSIT_VOUT)
            payout_tx = bitcoin_rpc.proxy.getrawtransaction(payout_txid, True)
            payout_block_hash = payout_tx.get("blockhash")
            if payout_block_hash is None:
                return False

            payout_height = self.block_height(bitcoin_rpc, payout_block_hash)
            if payout_height <= payout_height_floor:
                invariant_error["error"] = AssertionError(
                    f"contest payout {payout_txid} confirmed at height {payout_height}, "
                    f"expected after ack timelock height {payout_height_floor}"
                )
                return True

            payout["txid"] = payout_txid
            payout["height"] = payout_height
            return True

        wait_until(
            check_payout_after_ack_timelock,
            timeout=PAYOUT_TIMEOUT_SECS,
            step=1,
            error_msg=(
                f"deposit {deposit_txid} did not pay out after ack timelock "
                f"for contest {contest_txid}"
            ),
        )

        if invariant_error["error"] is not None:
            raise invariant_error["error"]

        self.logger.info(
            f"Contest payout {payout['txid']} confirmed at height {payout['height']} "
            f"after ack timelock height {payout_height_floor}"
        )

    def counterproof_generation_attempts_by_node(self, bridge_nodes) -> dict[int, int]:
        return {
            idx: int(
                read_prometheus_metric_sum(
                    node.props["metrics_url"], COUNTERPROOF_GENERATION_METRIC
                )
            )
            for idx, node in enumerate(bridge_nodes)
        }
