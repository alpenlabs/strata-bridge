"""
Safe-Harbour Defense Test: contest and slash stay live (hard bridge upgrade)

An operator that stalls the sweep (here: taken offline after posting its
claim) can still fire its pre-signed claim path, so the defensive duties are
the only funds defense under safe harbour and must never be suppressed:

1. A claim is posted, then the claimer goes down and the safe harbour
   activates. The sweep stalls (N-of-N without the claimer).
2. A watchtower contest is published; the bridge proof times out; the claimer
   is slashed, its stake output spent — all with safe harbour active.
3. Once the claimer restarts, the stalled sweep completes to the frozen
   safe-harbour address: the funds never leave through the claim path.

Mirrors the bridge-proof-timeout slashing flow with activation inserted after
the claim confirms.
"""

import flexitest

from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import BridgeProtocolParams
from rpc.types import RpcDepositStatusComplete
from utils.bridge import get_bridge_nodes_and_rpcs
from utils.deposit import (
    wait_until_deposit_status,
    wait_until_drt_recognized,
    wait_until_utxo_spent,
)
from utils.dev_cli import DevCli
from utils.safe_harbour import (
    activate_safe_harbour,
    assert_sweep_tx,
    wait_until_deposit_swept,
)
from utils.stake import (
    assert_slash_spends_stake,
    confirmed_stake_txid_for_operator,
    wait_until_operator_slashed,
)
from utils.utils import read_operator_key, wait_for_tx_confirmation, wait_until
from utils.withdrawal import wait_until_active_valid_claim


@flexitest.register
class SafeHarbourDefensiveDutiesLiveTest(StrataTestBase):
    """Contest and slash must proceed under safe harbour; the sweep collects the deposit."""

    def __init__(self, ctx: flexitest.InitContext):
        # Short game timelocks so the contest/timeout/slash ladder fits the test budget;
        # cooperative_payout_timeout=0 forces the claim path immediately after fulfillment.
        self.bridge_protocol_params = BridgeProtocolParams(
            contest_timelock=5,
            proof_timelock=5,
            contested_payout_timelock=15,
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
        bridge_rpc = bridge_rpcs[0]

        bitcoind_service = ctx.get_service("bitcoin")
        bitcoin_rpc = bitcoind_service.create_rpc()
        asm_rpc = ctx.get_service("asm_rpc").create_rpc()

        num_operators = len(bridge_nodes)
        operator_key_infos = [read_operator_key(i) for i in range(num_operators)]
        dev_cli = DevCli(
            bitcoind_service.props,
            operator_key_infos,
            bridge_protocol_params=self.bridge_protocol_params,
        )

        # --- One completed deposit, driven onto the claim path ---
        drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted DRT: {drt_txid}")
        deposit_id = wait_until_drt_recognized(bridge_rpc, drt_txid)
        deposit_info = wait_until_deposit_status(bridge_rpc, deposit_id, RpcDepositStatusComplete)
        assert deposit_info is not None, "Deposit did not complete"
        deposit_txid = deposit_info.get("status").get("deposit_txid")

        recent_block_hash = bitcoin_rpc.proxy.getblockhash(bitcoin_rpc.proxy.getblockcount())
        ckp_l1_txn = dev_cli.send_mock_checkpoint_from_tip(
            asm_rpc, recent_block_hash, num_ol_slots=1
        )
        ckp_block_hash = wait_for_tx_confirmation(bitcoin_rpc, ckp_l1_txn)

        wait_until(
            lambda: len(asm_rpc.strata_asm_getAssignments(ckp_block_hash)) > 0,
            timeout=300,
            error_msg="ASM did not produce assignment",
        )

        active_claim = wait_until_active_valid_claim(bridge_rpc)
        claimer_idx = active_claim.assigned_operator
        wait_for_tx_confirmation(bitcoin_rpc, active_claim.claim_txid, timeout=300)
        self.logger.info(f"Claim {active_claim.claim_txid} by operator {claimer_idx} confirmed")

        claimer_stake_txid = confirmed_stake_txid_for_operator(bridge_rpc, bitcoin_rpc, claimer_idx)

        # --- The claimer goes mute (stalling the sweep), then the safe harbour activates ---
        self.logger.info(f"Stopping claimer {claimer_idx}; its pre-signed claim path stays live")
        bridge_nodes[claimer_idx].stop()

        live_indices = [idx for idx in range(num_operators) if idx != claimer_idx]
        activate_safe_harbour(ctx, [bridge_rpcs[idx] for idx in live_indices])

        # --- The defensive ladder proceeds under safe harbour: contest, timeout, slash ---
        contester_idx = live_indices[0]
        contester_node = bridge_nodes[contester_idx]
        contest_txid = dev_cli.send_contest(
            deposit_idx=active_claim.deposit_idx,
            operator_idx=claimer_idx,
            bridge_node_url=f"http://127.0.0.1:{contester_node.props['rpc_port']}",
            contester_node_idx=contester_idx,
            seed=read_operator_key(contester_idx).SEED,
        )
        wait_for_tx_confirmation(bitcoin_rpc, contest_txid, timeout=300)
        self.logger.info(f"Contest {contest_txid} confirmed under safe harbour")

        # Only the proof-timeout tx can spend the contest-proof connector (claimer is down).
        wait_until_utxo_spent(bitcoin_rpc, contest_txid, vout=0, timeout=600)
        self.logger.info("Proof-timeout tx spent the contest-proof connector")

        # The slash fires only after the graphs process the proof timeout.
        monitor_rpc = bridge_rpcs[contester_idx]
        slashed_stake = wait_until_operator_slashed(monitor_rpc, claimer_idx)
        assert slashed_stake.slash_txid is not None
        assert_slash_spends_stake(bitcoin_rpc, claimer_stake_txid, slashed_stake.slash_txid)
        self.logger.info(f"Claimer {claimer_idx} slashed by {slashed_stake.slash_txid}")

        # --- The stalled sweep completes once the claimer returns ---
        self.logger.info(f"Restarting claimer {claimer_idx}")
        bridge_nodes[claimer_idx].start()

        sweep_tx = wait_until_deposit_swept(bitcoin_rpc, deposit_txid, timeout=600)
        self.logger.info(f"Deposit {deposit_txid} swept by {sweep_tx['txid']}")
        assert_sweep_tx(
            sweep_tx,
            deposit_txid,
            self.bridge_protocol_params.deposit_amount,
            self.bridge_protocol_params.sweep_fee_rate,
        )

        return True
