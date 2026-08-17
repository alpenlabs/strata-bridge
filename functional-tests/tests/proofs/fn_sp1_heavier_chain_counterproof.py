import os
from pathlib import Path
from typing import cast

import flexitest

from constants import (
    CONTEST_PROOF_VOUT,
    CONTEST_WATCHTOWER_0_VOUT,
    STAKE_VOUT,
)
from envs import BitcoinEnvConfig, ExternalBtcBridgeNetworkEnv
from envs.base_test import StrataTestBase
from envs.live_env import StrataLiveEnv
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import BridgeProtocolParams
from factory.common.asm_params import AsmParams
from rpc.types import RpcDepositStatusComplete
from utils.bitcoin import generate_blocks_excluding, reorg_excluding
from utils.bridge import get_bridge_nodes_and_rpcs
from utils.deposit import (
    wait_until_deposit_status,
    wait_until_drt_recognized,
    wait_until_utxo_spent,
)
from utils.dev_cli import DevCli
from utils.stake import (
    assert_slash_spends_stake,
    confirmed_stake_txid_for_operator,
    wait_until_operator_slashed,
)
from utils.utils import (
    find_utxo_spender_txid,
    read_operator_key,
    snapshot_log_offsets,
    wait_for_tx_confirmation,
    wait_until,
    wait_until_bridge_ready,
    wait_until_logs_match,
)
from utils.withdrawal import (
    wait_until_active_valid_claim,
    wait_until_bridge_proof_posted,
    wait_until_counter_proof_posted,
    wait_until_counterproof_ack,
)

HEAVIER_CHAIN_LOG_MARKER = "heavier contradicting chain detected"
COUNTERPROOF_EVAL_MARKER = "evaluating potential counterproof"


@flexitest.register
class SP1HeavierChainCounterproofTest(StrataTestBase):
    """
    SP1 counterpart of the native `HeavierChainCounterproofTest`: watchtowers counterproof a
    VALID (real SP1) bridge proof whose claim unlock only exists on an orphaned fork, via
    `CounterproofMode::HeavierChain`, under the external regtest bitcoind env with real
    Succinct-network proving.

    op-0 fulfills the withdrawal and generates a real SP1 bridge proof on fork A; the chain is
    then reverted to a strictly heavier fork B that replays every transaction except the
    fulfillment, so fork B's ASM export MMR has no `OperatorClaimUnlock` and contradicts the
    proof's commitment. The watchtowers are down for the whole life of fork A and restarted on
    fork B, so from their view there is one consistent chain that the (verifying) bridge proof
    is simply inconsistent with — the counterproof can only come from the heavier-chain path.

    1. Complete a deposit (all nodes up), then stop the watchtowers.
    2. Mock checkpoint assigns the withdrawal to op-0, which fulfills and claims on fork A. The
       fulfillment's block is the fork point.
    3. dev-cli contests on behalf of a watchtower; op-0 posts a real SP1 bridge proof anchored
       in fork A, then op-0 is stopped (cannot NACK, never sees fork B).
    4. Stop the miner and rebuild the chain from the fork point without the fulfillment, one
       block longer than fork A.
    5. Restart the watchtowers and mine (fulfillment excluded) only until each has created its
       counterproof duty, then freeze the tip: the proof verifies but its claim unlock is absent
       from their (heavier) canonical chain, so once the Moho prover catches up to the static
       anchor each publishes a heavier-chain counterproof. Mining resumes once every counterproof
       is broadcast.
    6. After the NACK timelock, a counterprover auto-publishes the ACK; verify the ACK's shape
       and that op-0 is slashed, with the fulfillment never re-confirmed.
    """

    BURY_DEPTH = 1

    # Creating the counterproof duty is block-driven (op-1's ASM pipeline only advances as new
    # blocks bury older ones), so mine until the duty exists. Then FREEZE: the counterproof
    # anchors at a now-static block height and the sequential SP1 Moho prover (~2 min/block on
    # the network) catches up to it, while op-1 re-evaluates on its ~120s timer even with no new
    # blocks. A moving tip would keep the anchor ahead of the prover, so it could never be proven.
    DUTY_MINE_INTERVAL_SECS = 60
    # Post-detection mining. The slash only publishes once the chain is contested_payout_timelock
    # (120) blocks past the contest, so mine fast to reach it within the bounded slash wait. Safe
    # to outrun the Moho prover here: the slash is bitcoin-tracked by bridge-sm (which advances
    # with the block tracker, ahead of the asm-runner), so no fresh Moho proof at the tip gates it.
    GAME_MINE_INTERVAL_SECS = 2

    def __init__(self, ctx: flexitest.InitContext):
        # Fork B's moho proof must be a real Groth16 proof for the counterproof to embed and
        # verify it; base_env only wires the SP1 asm-runner backend when both ELF paths are set.
        if not (
            os.environ.get("BRIDGE_PROOF_ASM_ELF_PATH")
            and os.environ.get("BRIDGE_PROOF_MOHO_ELF_PATH")
        ):
            raise RuntimeError(
                "fn_sp1_heavier_chain_counterproof requires full ASM proving "
                "(BRIDGE_PROOF_SP1_ASM=1); the ASM/Moho guest ELF paths are unset"
            )

        # Single source of truth: the asm-params baked by gen_asm_params_external.py determine
        # how many operator key sets the bridge subprotocol covers, so the test must launch
        # exactly that many operator nodes or N/N signing breaks.
        asm_params_path = Path(os.environ["BRIDGE_PROOF_ASM_PARAMS_DIR"]) / "asm-params.json"
        self.asm_params = AsmParams.load(asm_params_path)
        self.num_operators = len(self.asm_params.bridge.operators)

        self.bridge_protocol_params = BridgeProtocolParams(
            bury_depth=self.BURY_DEPTH,
            contest_timelock=5,
            proof_timelock=10_000,
            nack_timelock=5,
            # Slash/contested-payout fires at contest + this many blocks. It must stay well above
            # the ACK window: the contested-payout timeout is checked before the ACK duty and
            # returns early, and under the fast game-phase mining op-1's graph SM lags the tip, so
            # a tight value lets the timeout preempt the ACK and deadlock the game. 120 is proven.
            contested_payout_timelock=120,
            # The default bridge proof predicate is required: the proof must VERIFY so the
            # counterproof can only come from the heavier-chain path.
        )
        ctx.set_env(
            ExternalBtcBridgeNetworkEnv(
                bridge_protocol_params=self.bridge_protocol_params,
                bridge_config_params=BridgeConfigParams(
                    cooperative_payout_timeout=0,
                    min_withdrawal_fulfillment_window=0,
                    retry_interval_secs=120,
                ),
                btc_config=BitcoinEnvConfig(
                    mine_on_demand=True,
                    mine_on_demand_trailing_blocks=self.BURY_DEPTH,
                ),
                num_operators=self.num_operators,
            )
        )

    def main(self, ctx: flexitest.RunContext):
        bridge_nodes, bridge_rpcs = get_bridge_nodes_and_rpcs(
            ctx, num_operators=self.num_operators, stake_timeout=7200
        )

        bitcoind_service = ctx.get_service("bitcoin")
        bitcoin_rpc = bitcoind_service.create_rpc()

        asm_service = ctx.get_service("asm_rpc")
        asm_rpc = asm_service.create_rpc()

        operator_key_infos = [read_operator_key(i) for i in range(self.num_operators)]

        dev_cli = DevCli(
            bitcoind_service.props,
            operator_key_infos,
            bridge_protocol_params=self.bridge_protocol_params,
        )

        # 1. Complete a deposit while every node is up (graph setup needs all of them).
        assigned_idx = 0  # send_mock_checkpoint_from_tip assigns to node 0 by default
        assigned_rpc = bridge_rpcs[assigned_idx]
        watchtower_idxs = [i for i in range(self.num_operators) if i != assigned_idx]

        drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted DRT: {drt_txid}")
        deposit_id = wait_until_drt_recognized(assigned_rpc, drt_txid, timeout=3600)
        deposit_info = wait_until_deposit_status(
            assigned_rpc, deposit_id, RpcDepositStatusComplete, timeout=7200
        )
        assert deposit_info is not None, "Deposit did not complete"
        self.logger.info("Deposit completed")

        assigned_stake_txid = confirmed_stake_txid_for_operator(
            assigned_rpc, bitcoin_rpc, assigned_idx
        )

        # Stop the watchtowers BEFORE the assignment so they never observe fork A; on restart
        # they catch up on fork B as one consistent chain.
        for i in watchtower_idxs:
            bridge_nodes[i].stop()
        self.logger.info(f"Stopped watchtowers {watchtower_idxs} for the life of fork A")

        # 2. Assignment; op-0 fulfills and claims on fork A.
        recent_block_hash = bitcoin_rpc.proxy.getblockhash(bitcoin_rpc.proxy.getblockcount())
        ckp_l1_txn = dev_cli.send_mock_checkpoint_from_tip(
            asm_rpc,
            recent_block_hash,
            num_ol_slots=1,
            genesis_l1_height=self.asm_params.anchor.block.height,
        )
        ckp_block_hash = wait_for_tx_confirmation(bitcoin_rpc, ckp_l1_txn, timeout=3600)
        wait_until(
            lambda: len(asm_rpc.strata_asm_getAssignments(ckp_block_hash)) > 0,
            timeout=3600,
            error_msg="ASM did not produce assignment",
        )

        active_claim = wait_until_active_valid_claim(assigned_rpc, timeout=3600)
        assert active_claim.assigned_operator == assigned_idx, (
            f"expected assignment to op-{assigned_idx}, got {active_claim.assigned_operator}"
        )
        deposit_idx = active_claim.deposit_idx
        claim_txid = active_claim.claim_txid
        wait_for_tx_confirmation(bitcoin_rpc, claim_txid, timeout=3600)
        self.logger.info(f"Claim tx {claim_txid} confirmed")

        withdrawal_status = assigned_rpc.stratabridge_withdrawalStatus(deposit_idx)
        assert withdrawal_status.get("status") == "complete", (
            f"withdrawal not fulfilled: {withdrawal_status}"
        )
        fulfillment_txid = withdrawal_status["fulfillment_txid"]
        fork_block_hash = wait_for_tx_confirmation(bitcoin_rpc, fulfillment_txid, timeout=3600)
        self.logger.info(
            f"Fulfillment tx {fulfillment_txid} confirmed in fork point block {fork_block_hash}"
        )

        # 3. Contest on behalf of a watchtower (they are down; graph data comes from the
        # assigned node), then op-0 defends with a real SP1 bridge proof anchored in fork A.
        contester_idx = watchtower_idxs[0]
        assigned_rpc_url = f"http://127.0.0.1:{bridge_nodes[assigned_idx].props['rpc_port']}"
        contest_txid = dev_cli.send_contest(
            deposit_idx=deposit_idx,
            operator_idx=assigned_idx,
            bridge_node_url=assigned_rpc_url,
            contester_node_idx=contester_idx,
            seed=read_operator_key(contester_idx).SEED,
        )
        wait_for_tx_confirmation(bitcoin_rpc, contest_txid, timeout=3600)
        self.logger.info(f"Contest tx {contest_txid} confirmed on behalf of op-{contester_idx}")

        wait_until_bridge_proof_posted(assigned_rpc, deposit_idx, timeout=7200)
        bridge_proof_txid = find_utxo_spender_txid(bitcoin_rpc, contest_txid, CONTEST_PROOF_VOUT)
        wait_for_tx_confirmation(bitcoin_rpc, bridge_proof_txid, timeout=3600)
        self.logger.info(f"Valid SP1 bridge proof tx {bridge_proof_txid} posted on fork A")

        bridge_nodes[assigned_idx].stop()
        self.logger.info(f"Stopped op-{assigned_idx}; it cannot NACK and never sees fork B")

        # 4. Rebuild the chain without the fulfillment: fork B replays every fork-A tx at its
        # original height except the fulfillment (and anything spending it), then extends one
        # block past fork A's tip so it is strictly heavier than the proof's committed PoW.
        watchtower_log_offsets = {
            i: snapshot_log_offsets([bridge_nodes[i].props["logfile"]]) for i in watchtower_idxs
        }
        cast(StrataLiveEnv, ctx.env).stop_miner()
        mining_addr = bitcoin_rpc.proxy.getnewaddress()

        reorg = reorg_excluding(
            bitcoin_rpc,
            mining_addr,
            fork_block_hash,
            {fulfillment_txid},
            # One block past fork A's tip is enough to be strictly heavier (and to reorg); each
            # extra block is another sequential Moho re-proof the watchtower must wait on.
            extra_blocks=1,
        )
        self.logger.info(
            f"Reverted to fork B: fork point height {reorg.fork_height}, "
            f"old tip {reorg.old_tip_height}, new tip {reorg.new_tip_hash}, "
            f"excluded {reorg.excluded}"
        )
        for name, txid in [
            ("claim", claim_txid),
            ("contest", contest_txid),
            ("bridge proof", bridge_proof_txid),
        ]:
            assert txid not in reorg.excluded, (
                f"{name} tx {txid} descends from the fulfillment and was excluded from "
                f"fork B; the game txs must not spend fulfillment change"
            )
            # With -txindex an orphaned tx still resolves to its stale fork-A block, so require
            # positive confirmations: 0 means off the active chain, absent means mempool-only.
            tx_info = bitcoin_rpc.proxy.getrawtransaction(txid, True)
            assert tx_info.get("confirmations", 0) > 0, (
                f"{name} tx {txid} did not re-confirm on fork B "
                f"(blockhash={tx_info.get('blockhash')}, "
                f"confirmations={tx_info.get('confirmations')})"
            )
        self.logger.info("Claim, contest, and bridge proof all re-confirmed on fork B")

        # 5. Watchtowers wake up on fork B: the proof verifies, but its claim unlock is absent
        # from their heavier canonical chain -> heavier-chain counterproof.
        for i in watchtower_idxs:
            bridge_nodes[i].start()
        for i in watchtower_idxs:
            wait_until_bridge_ready(bridge_rpcs[i])
        self.logger.info(f"Restarted watchtowers {watchtower_idxs} on fork B")

        # Mine (fulfillment excluded) only until op-1's block-driven ASM pipeline has processed
        # fork B and created the counterproof duty; it is retried on op-1's ~120s timer after
        # that, so no further blocks are needed to reach detection.
        duty_miner = generate_blocks_excluding(
            bitcoin_rpc, self.DUTY_MINE_INTERVAL_SECS, mining_addr, {fulfillment_txid}
        )
        try:
            for i in watchtower_idxs:
                wait_until_logs_match(
                    watchtower_log_offsets[i],
                    lambda line: COUNTERPROOF_EVAL_MARKER in line,
                    timeout=7200,
                    error_msg=f"watchtower {i} never created the counterproof duty",
                )
                self.logger.info(f"Watchtower {i} created the counterproof duty")
        finally:
            duty_miner.stop()

        # Tip frozen: the counterproof anchors at a static block height, so the sequential SP1
        # Moho prover catches up to it and op-1's next ~120s retry succeeds. The wait runs long
        # because the asm-runner must re-prove fork B up to the anchor under real proving.
        for i in watchtower_idxs:
            wait_until_logs_match(
                watchtower_log_offsets[i],
                lambda line: HEAVIER_CHAIN_LOG_MARKER in line,
                timeout=7200,
                error_msg=f"watchtower {i} did not detect the heavier chain",
            )
            self.logger.info(f"Watchtower {i} detected the heavier contradicting chain")

        # Tip stays frozen until SP1 counterproof proving completes, so it never races the
        # contest's block-height deadlines.
        for slot in range(len(watchtower_idxs)):
            watchtower_vout = CONTEST_WATCHTOWER_0_VOUT + slot
            wait_until_utxo_spent(bitcoin_rpc, contest_txid, watchtower_vout, timeout=7200)
            self.logger.info(
                f"Counterproof broadcast by watchtower slot {slot} (contest:{watchtower_vout})"
            )

        # Resume mining to confirm the counterproofs, mature the NACK timelock, and bury the
        # ACK/slash.
        miner = generate_blocks_excluding(
            bitcoin_rpc, self.GAME_MINE_INTERVAL_SECS, mining_addr, {fulfillment_txid}
        )
        try:
            monitor_rpc = bridge_rpcs[contester_idx]
            wait_until_counter_proof_posted(monitor_rpc, deposit_idx, timeout=7200)

            # 6. The ACK auto-publishes after the NACK timelock.
            ack_txid = wait_until_counterproof_ack(bitcoin_rpc, contest_txid, timeout=7200)
            self.logger.info(f"Counterproof ACK {ack_txid} confirmed")

            slashed_stake = wait_until_operator_slashed(monitor_rpc, assigned_idx)
            assert slashed_stake.slash_txid is not None
            assert_slash_spends_stake(bitcoin_rpc, assigned_stake_txid, slashed_stake.slash_txid)
            self.logger.info(
                "Operator %s slashed by tx %s, spending stake output %s:%s",
                assigned_idx,
                slashed_stake.slash_txid,
                assigned_stake_txid,
                STAKE_VOUT,
            )

            # The fulfillment must never have re-confirmed on the active chain. With -txindex,
            # getrawtransaction still reports the stale fork-A blockhash, so check that any
            # containing block is NOT in the active chain (confirmations is -1 for stale blocks).
            fulfillment_tx = bitcoin_rpc.proxy.getrawtransaction(fulfillment_txid, True)
            fulfillment_block = fulfillment_tx.get("blockhash")
            if fulfillment_block is not None:
                confirmations = bitcoin_rpc.proxy.getblockheader(fulfillment_block)["confirmations"]
                assert confirmations < 0, (
                    f"fulfillment {fulfillment_txid} re-confirmed on the active chain in "
                    f"{fulfillment_block}"
                )
            assert bitcoin_rpc.proxy.getblockcount() > reorg.old_tip_height
        finally:
            miner.stop()

        return True
