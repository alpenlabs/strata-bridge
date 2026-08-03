from typing import cast

import flexitest

from constants import (
    CONTEST_PROOF_VOUT,
    CONTEST_WATCHTOWER_0_VOUT,
    STAKE_VOUT,
)
from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from envs.live_env import StrataLiveEnv
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import BridgeProtocolParams
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


@flexitest.register
class HeavierChainCounterproofTest(StrataTestBase):
    """
    Test that watchtowers counterproof a VALID bridge proof whose claim unlock only
    exists on an orphaned fork, via `CounterproofMode::HeavierChain`.

    The operator fulfills the withdrawal and generates a real bridge proof on fork A;
    the chain is then reverted to a strictly heavier fork B that replays every
    transaction except the fulfillment. Fork B's ASM export MMR therefore has no
    `OperatorClaimUnlock`, contradicting the proof's commitment. The watchtowers are
    stopped for the whole life of fork A and restarted on fork B, so from their view
    there is one consistent chain and the bridge proof is simply inconsistent with it.

    1. Complete a deposit (all nodes up), then stop both watchtowers.
    2. Mock checkpoint assigns the withdrawal to op-0, which fulfills and claims on
       fork A. The fulfillment's block is the fork point.
    3. dev-cli contests on behalf of a watchtower; op-0 posts a real (valid) bridge
       proof anchored in fork A, then op-0 is stopped (cannot NACK, never sees fork B).
    4. Stop the miner and rebuild the chain from the fork point without the
       fulfillment, 3 blocks longer than fork A; keep mining with the fulfillment
       excluded.
    5. Restart the watchtowers: the proof verifies but the claim unlock is absent from
       their (heavier) canonical chain, so both publish heavier-chain counterproofs.
    6. After the NACK timelock, a counterprover auto-publishes the ACK; verify the
       ACK's shape and that op-0 is slashed, with the fulfillment never re-confirmed.
    """

    def __init__(self, ctx: flexitest.InitContext):
        self.bridge_protocol_params = BridgeProtocolParams(
            contest_timelock=5,
            proof_timelock=100,  # ensure no proof timeout fires during fork surgery
            nack_timelock=5,
            contested_payout_timelock=120,
            # NOTE: (@MdTeach) the default (native Schnorr) bridge proof predicate is
            # required — the proof must VERIFY so the counterproof can only come from
            # the heavier-chain path.
        )
        ctx.set_env(
            BridgeNetworkEnv(
                bridge_protocol_params=self.bridge_protocol_params,
                bridge_config_params=BridgeConfigParams(
                    cooperative_payout_timeout=0,
                ),
            )
        )

    def main(self, ctx: flexitest.RunContext):
        bridge_nodes, bridge_rpcs = get_bridge_nodes_and_rpcs(ctx)

        bitcoind_service = ctx.get_service("bitcoin")
        bitcoin_rpc = bitcoind_service.create_rpc()

        asm_service = ctx.get_service("asm_rpc")
        asm_rpc = asm_service.create_rpc()

        num_operators = len(bridge_nodes)
        operator_key_infos = [read_operator_key(i) for i in range(num_operators)]

        dev_cli = DevCli(
            bitcoind_service.props,
            operator_key_infos,
            bridge_protocol_params=self.bridge_protocol_params,
        )

        # 1. Complete a deposit while every node is up (graph setup needs all of them).
        assigned_idx = 0  # send_mock_checkpoint_from_tip assigns to node 0 by default
        assigned_rpc = bridge_rpcs[assigned_idx]
        watchtower_idxs = [i for i in range(num_operators) if i != assigned_idx]

        drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted DRT: {drt_txid}")
        deposit_id = wait_until_drt_recognized(assigned_rpc, drt_txid)
        deposit_info = wait_until_deposit_status(assigned_rpc, deposit_id, RpcDepositStatusComplete)
        assert deposit_info is not None, "Deposit did not complete"
        self.logger.info("Deposit completed")

        assigned_stake_txid = confirmed_stake_txid_for_operator(
            assigned_rpc,
            bitcoin_rpc,
            assigned_idx,
        )

        # Stop the watchtowers BEFORE the assignment so they never observe fork A; on
        # restart they catch up on fork B as one consistent chain.
        for i in watchtower_idxs:
            bridge_nodes[i].stop()
        self.logger.info(f"Stopped watchtowers {watchtower_idxs} for the life of fork A")

        # 2. Assignment; op-0 fulfills and claims on fork A.
        recent_block_hash = bitcoin_rpc.proxy.getblockhash(bitcoin_rpc.proxy.getblockcount())
        ckp_l1_txn = dev_cli.send_mock_checkpoint_from_tip(
            asm_rpc,
            recent_block_hash,
            num_ol_slots=1,
        )
        ckp_block_hash = wait_for_tx_confirmation(bitcoin_rpc, ckp_l1_txn)
        wait_until(
            lambda: len(asm_rpc.strata_asm_getAssignments(ckp_block_hash)) > 0,
            timeout=300,
            error_msg="ASM did not produce assignment",
        )

        active_claim = wait_until_active_valid_claim(assigned_rpc)
        assert active_claim.assigned_operator == assigned_idx, (
            f"expected assignment to op-{assigned_idx}, got {active_claim.assigned_operator}"
        )
        deposit_idx = active_claim.deposit_idx
        claim_txid = active_claim.claim_txid
        wait_for_tx_confirmation(bitcoin_rpc, claim_txid, timeout=300)
        self.logger.info(f"Claim tx {claim_txid} confirmed")

        withdrawal_status = assigned_rpc.stratabridge_withdrawalStatus(deposit_idx)
        assert withdrawal_status.get("status") == "complete", (
            f"withdrawal not fulfilled: {withdrawal_status}"
        )
        fulfillment_txid = withdrawal_status["fulfillment_txid"]
        fork_block_hash = wait_for_tx_confirmation(bitcoin_rpc, fulfillment_txid)
        self.logger.info(
            f"Fulfillment tx {fulfillment_txid} confirmed in fork point block {fork_block_hash}"
        )

        # 3. Contest on behalf of a watchtower (they are down; graph data comes from the
        # assigned node), then op-0 defends with a real bridge proof anchored in fork A.
        contester_idx = watchtower_idxs[0]
        assigned_rpc_url = f"http://127.0.0.1:{bridge_nodes[assigned_idx].props['rpc_port']}"
        contest_txid = dev_cli.send_contest(
            deposit_idx=deposit_idx,
            operator_idx=assigned_idx,
            bridge_node_url=assigned_rpc_url,
            contester_node_idx=contester_idx,
            seed=read_operator_key(contester_idx).SEED,
        )
        wait_for_tx_confirmation(bitcoin_rpc, contest_txid, timeout=300)
        self.logger.info(f"Contest tx {contest_txid} confirmed on behalf of op-{contester_idx}")

        wait_until_bridge_proof_posted(assigned_rpc, deposit_idx)
        bridge_proof_txid = find_utxo_spender_txid(bitcoin_rpc, contest_txid, CONTEST_PROOF_VOUT)
        wait_for_tx_confirmation(bitcoin_rpc, bridge_proof_txid, timeout=300)
        self.logger.info(f"Valid bridge proof tx {bridge_proof_txid} posted on fork A")

        bridge_nodes[assigned_idx].stop()
        self.logger.info(f"Stopped op-{assigned_idx}; it cannot NACK and never sees fork B")

        # 4. Rebuild the chain without the fulfillment: fork B replays every fork-A tx at
        # its original height except the fulfillment (and anything spending it), then
        # extends 3 blocks past fork A's tip so it is strictly heavier than the proof's
        # committed PoW.
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
            extra_blocks=3,
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
            assert "blockhash" in bitcoin_rpc.proxy.getrawtransaction(txid, True), (
                f"{name} tx {txid} did not re-confirm on fork B"
            )
        self.logger.info("Claim, contest, and bridge proof all re-confirmed on fork B")

        # Keep mining (fulfillment always excluded) to bury fork-B txs and mature the
        # NACK timelock.
        miner = generate_blocks_excluding(bitcoin_rpc, 2, mining_addr, {fulfillment_txid})
        try:
            # 5. Watchtowers wake up on fork B: the proof verifies, but its claim unlock
            # is absent from their heavier canonical chain -> heavier-chain counterproof.
            for i in watchtower_idxs:
                bridge_nodes[i].start()
            for i in watchtower_idxs:
                wait_until_bridge_ready(bridge_rpcs[i])
            self.logger.info(f"Restarted watchtowers {watchtower_idxs} on fork B")

            for i in watchtower_idxs:
                wait_until_logs_match(
                    watchtower_log_offsets[i],
                    lambda line: HEAVIER_CHAIN_LOG_MARKER in line,
                    timeout=300,
                    error_msg=f"watchtower {i} did not detect the heavier chain",
                )
                self.logger.info(f"Watchtower {i} detected the heavier contradicting chain")

            for slot in range(len(watchtower_idxs)):
                watchtower_vout = CONTEST_WATCHTOWER_0_VOUT + slot
                wait_until_utxo_spent(bitcoin_rpc, contest_txid, watchtower_vout, timeout=600)
                self.logger.info(
                    f"Counterproof posted by watchtower slot {slot} "
                    f"(contest:{watchtower_vout} spent)"
                )

            monitor_rpc = bridge_rpcs[contester_idx]
            wait_until_counter_proof_posted(monitor_rpc, deposit_idx)

            # 6. The ACK auto-publishes after the NACK timelock.
            ack_txid = wait_until_counterproof_ack(bitcoin_rpc, contest_txid)
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

            # The fulfillment must never have re-confirmed on the active chain. With
            # -txindex, getrawtransaction still reports the stale fork-A blockhash, so
            # check that any containing block is NOT in the active chain (confirmations
            # is -1 for stale blocks).
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
