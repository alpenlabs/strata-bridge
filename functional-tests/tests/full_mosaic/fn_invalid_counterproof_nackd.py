import os
from pathlib import Path

import flexitest

from constants import (
    CONTEST_PAYOUT_VOUT,
    CONTEST_PROOF_VOUT,
    CONTEST_WATCHTOWER_0_VOUT,
    DT_DEPOSIT_VOUT,
    STAKE_VOUT,
)
from envs import BitcoinEnvConfig, ExternalBtcBridgeNetworkEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import BridgeProtocolParams
from factory.common.asm_params import AsmParams
from rpc.types import RpcDepositStatusComplete, RpcStakeStateLabel
from utils.bitcoin import generate_blocks
from utils.bridge import get_bridge_nodes_and_rpcs
from utils.deposit import (
    wait_until_deposit_status,
    wait_until_drt_recognized,
    wait_until_utxo_spent,
)
from utils.dev_cli import DevCli
from utils.mosaic import MOSAIC_WAIT_SCALE
from utils.node_config import restart_bridge_node_with_overrides
from utils.stake import confirmed_stake_txid_for_operator, get_operator_stake_status
from utils.utils import (
    find_utxo_spender_txid,
    read_operator_key,
    wait_for_tx_confirmation,
    wait_until,
    wait_until_bridge_ready,
    wait_until_logs_match,
)
from utils.withdrawal import (
    assert_contested_payout_shape,
    wait_until_all_nackd,
    wait_until_bridge_proof_posted,
    wait_until_claim_posted,
    wait_until_counter_proof_posted,
    wait_until_counterproof_nack,
)

STALE_REJECT_LOG_MARKER = "bridge proof failed verification; publishing counterproof"


@flexitest.register
class FullMosaicInvalidCounterproofNackdTest(StrataTestBase):
    """
    Full-circuit target case: an INVALID counterproof is rejected on its merits, so the
    honest operator NACKs it and is paid.

    Operator-0 genuinely fulfills its assigned withdrawal and posts a REAL, VALID SP1
    bridge proof. The watchtowers are restarted against two stale artifacts, both of which
    are load-bearing:

      * a stale `bridge_proof_predicate` in params.toml, so `verify_bridge_proof`
        (crates/bridge-exec/src/graph/counterproof.rs) fails on a proof that is in fact
        valid and the watchtower takes the `CounterproofMode::InvalidBridgeProof` branch;
      * a stale `[counterproof].elf_path` in config.toml, whose baked `bridge_proof_vk` is
        also stale, so the guest's
        `assert!(bridge_proof_vk.verify_claim_witness(..).is_err())`
        (crates/proofs/bridge-counterproof/src/statements.rs) holds and the
        counterproof is provable at all. With the canonical ELF the guest panics on a
        valid proof and no counterproof is ever broadcast.

    The counterproof that lands is therefore a well-formed SP1 proof of a *different*
    program than the one `counterproof_predicate` pins. Under the real g16 circuit the
    evaluator extracts the fault secret, op-0 signs the NACK, and the game ends in a
    contested payout with op-0's stake untouched.

    Pairs with fn_valid_counterproof_acked.py: same flow, same deposit index, opposite
    outcome. Deposit index 0 (game index 1, odd) is the index at which the toy circuit can
    NEVER produce a NACK, so a NACK appearing here is itself evidence that the real
    circuit is in play.

    1. Complete a deposit while every node is still canonical.
    2. Restart the watchtowers with the stale artifacts.
    3. Mock checkpoint assigns the withdrawal to op-0, which fulfills and claims.
    4. dev-cli contests on behalf of a watchtower; op-0 posts a real, valid bridge proof.
    5. Each stale watchtower rejects the valid proof and publishes a counterproof.
    6. op-0 NACKs every counterproof; the phase reaches all_nackd.
    7. The contested payout sweeps the deposit.
    8. Assert no ACK fired, no slash fired, and op-0's stake is untouched.
    """

    BURY_DEPTH = 1
    GAME_MINE_INTERVAL_SECS = 2
    # Deliberately the index at which the toy circuit can never yield a NACK.
    CONTESTED_DEPOSIT_IDX = 0

    def __init__(self, ctx: flexitest.InitContext):
        if os.environ.get("MOSAIC_CIRCUIT_MODE") != "full":
            raise RuntimeError(
                "tests/full_mosaic requires MOSAIC_CIRCUIT_MODE=full; "
                "see tests/full_mosaic/README.md"
            )

        self.stale_counterproof_elf = os.environ.get("BRIDGE_STALE_COUNTERPROOF_SP1_ELF")
        self.stale_bridge_proof_elf = os.environ.get("BRIDGE_STALE_PROOF_SP1_ELF")
        if not (self.stale_counterproof_elf and self.stale_bridge_proof_elf):
            raise RuntimeError(
                "this test needs the stale guest ELF pair; set "
                "BRIDGE_PROOF_SP1_STALE_ARTIFACTS=1 so sp1-setup.bash builds it"
            )

        # sp1-setup.bash already failed the run if these equal the canonical predicates.
        self.stale_bridge_proof_predicate = (
            Path(self.stale_bridge_proof_elf).with_suffix(".predicate").read_text().strip()
        )
        self.stale_counterproof_predicate = (
            Path(self.stale_counterproof_elf).with_suffix(".predicate").read_text().strip()
        )

        asm_params_path = Path(os.environ["BRIDGE_PROOF_ASM_PARAMS_DIR"]) / "asm-params.json"
        self.asm_params = AsmParams.load(asm_params_path)
        self.num_operators = len(self.asm_params.bridge.operators)

        self.bridge_protocol_params = BridgeProtocolParams(
            bury_depth=self.BURY_DEPTH,
            contest_timelock=5,
            proof_timelock=10_000,
            # The NACK is a key-path spend with no timelock, so it only has to beat the
            # ACK. Keep nack_timelock comfortably above the few blocks the NACK needs, so
            # that if the NACK ever fails the ACK shows up and fails the test loudly
            # instead of the contested payout quietly succeeding for the wrong reason.
            nack_timelock=20,
            # op-0 publishes contested_payout at contest + ack_timelock. Unlike the
            # existing SP1 tests, op-0 stays UP here, so this must be large enough that it
            # does not end the game before the watchtowers have counterproofed.
            ack_timelock=45,
            # Must stay above ack_timelock so contested_payout wins the race for the
            # contest slash output and no slash is ever possible.
            contested_payout_timelock=150,
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
            ctx,
            num_operators=self.num_operators,
            stake_timeout=7200 * MOSAIC_WAIT_SCALE,
        )
        bridge_rpc = bridge_rpcs[0]

        bitcoind_service = ctx.get_service("bitcoin")
        bitcoin_rpc = bitcoind_service.create_rpc()
        asm_rpc = ctx.get_service("asm_rpc").create_rpc()

        operator_key_infos = [read_operator_key(i) for i in range(self.num_operators)]
        dev_cli = DevCli(
            bitcoind_service.props,
            operator_key_infos,
            bridge_protocol_params=self.bridge_protocol_params,
        )

        assigned_idx = 0  # send_mock_checkpoint_from_tip assigns to node 0 by default
        watchtower_idxs = [i for i in range(self.num_operators) if i != assigned_idx]

        # 1. Complete a deposit while every node is still canonical. The stale keys touch
        # nothing in deposit handling, graph generation or N/N signing, but doing this
        # first keeps the divergence out of the setup path entirely.
        drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted DRT: {drt_txid}")
        deposit_id = wait_until_drt_recognized(bridge_rpc, drt_txid, timeout=3600)
        deposit_info = wait_until_deposit_status(
            bridge_rpc,
            deposit_id,
            RpcDepositStatusComplete,
            timeout=7200 * MOSAIC_WAIT_SCALE,
        )
        assert deposit_info is not None, "Deposit did not complete"
        contested_deposit_txid = deposit_info.get("status").get("deposit_txid")
        assert contested_deposit_txid is not None, "Completed deposit has no deposit_txid"
        assert deposit_id == self.CONTESTED_DEPOSIT_IDX, (
            f"first deposit landed at index {deposit_id}, expected "
            f"{self.CONTESTED_DEPOSIT_IDX} (see docstring)"
        )
        self.logger.info(f"Deposit {deposit_id} completed, txid {contested_deposit_txid}")

        assigned_stake_txid = confirmed_stake_txid_for_operator(
            bridge_rpc, bitcoin_rpc, assigned_idx
        )

        # 2. Restart the watchtowers with the stale artifacts.
        self.logger.info(
            f"Staling watchtowers {watchtower_idxs}: "
            f"bridge_proof_predicate={self.stale_bridge_proof_predicate}, "
            f"counterproof_predicate={self.stale_counterproof_predicate}"
        )
        watchtower_log_offsets = {
            idx: restart_bridge_node_with_overrides(
                bridge_nodes[idx],
                config_overrides={
                    "bridge_proof": {"elf_path": self.stale_bridge_proof_elf},
                    "counterproof": {"elf_path": self.stale_counterproof_elf},
                    # The circuit is bound to the CANONICAL counterproof vkey, so
                    # `verify_mosaic_vkey` would abort a stale node at startup. Only these
                    # nodes skip the checks; with BRIDGE_DEV_MODE=0 op-0 keeps them.
                    "dev": True,
                },
                params_overrides={
                    "protocol": {
                        "bridge_proof_predicate": self.stale_bridge_proof_predicate,
                        "counterproof_predicate": self.stale_counterproof_predicate,
                    }
                },
            )
            for idx in watchtower_idxs
        }
        for idx in watchtower_idxs:
            wait_until_bridge_ready(bridge_rpcs[idx], timeout=600)
        self.logger.info("Watchtowers restarted with stale artifacts")

        # 3. Assign the withdrawal to op-0, which fulfills and claims for real.
        tip_hash = bitcoin_rpc.proxy.getblockhash(bitcoin_rpc.proxy.getblockcount())
        ckp_l1_txn = dev_cli.send_mock_checkpoint_from_tip(
            asm_rpc,
            tip_hash,
            num_ol_slots=1,
            genesis_l1_height=self.asm_params.anchor.block.height,
        )
        ckp_block_hash = wait_for_tx_confirmation(bitcoin_rpc, ckp_l1_txn, timeout=3600)
        wait_until(
            lambda: len(asm_rpc.strata_asm_getAssignments(ckp_block_hash)) > 0,
            timeout=3600,
            error_msg="ASM did not produce assignment",
        )

        active_claim = wait_until_claim_posted(bridge_rpc, self.CONTESTED_DEPOSIT_IDX, timeout=3600)
        assert active_claim.assigned_operator == assigned_idx, (
            f"expected deposit {self.CONTESTED_DEPOSIT_IDX} assigned to op-{assigned_idx}, "
            f"got op-{active_claim.assigned_operator}"
        )
        claim_txid = active_claim.claim_txid
        wait_for_tx_confirmation(bitcoin_rpc, claim_txid, timeout=3600)
        self.logger.info(f"op-{assigned_idx} claimed: {claim_txid}")

        # 4. Contest on behalf of a watchtower, then let op-0 answer with a REAL proof.
        contester_idx = watchtower_idxs[0]
        contest_txid = dev_cli.send_contest(
            deposit_idx=self.CONTESTED_DEPOSIT_IDX,
            operator_idx=assigned_idx,
            bridge_node_url=f"http://127.0.0.1:{bridge_nodes[assigned_idx].props['rpc_port']}",
            contester_node_idx=contester_idx,
            seed=read_operator_key(contester_idx).SEED,
        )
        wait_for_tx_confirmation(bitcoin_rpc, contest_txid, timeout=3600)
        self.logger.info(f"Contest tx {contest_txid} confirmed")

        wait_until_bridge_proof_posted(bridge_rpc, self.CONTESTED_DEPOSIT_IDX, timeout=7200)
        bridge_proof_txid = find_utxo_spender_txid(bitcoin_rpc, contest_txid, CONTEST_PROOF_VOUT)
        wait_for_tx_confirmation(bitcoin_rpc, bridge_proof_txid, timeout=3600)
        self.logger.info(f"op-{assigned_idx} posted a VALID bridge proof: {bridge_proof_txid}")

        # 5. This log line is the causal heart of the test: reachable only via
        # `!verify_bridge_proof(stale_predicate, proof)` on a proof that verifies
        # canonically.
        for idx in watchtower_idxs:
            wait_until_logs_match(
                watchtower_log_offsets[idx],
                lambda line: STALE_REJECT_LOG_MARKER in line,
                timeout=7200,
                error_msg=(
                    f"watchtower op-{idx} never rejected the valid bridge proof; its stale "
                    "bridge_proof_predicate did not take effect"
                ),
            )
        self.logger.info("Every stale watchtower rejected the valid bridge proof")

        counterproof_txids = []
        for slot in range(len(watchtower_idxs)):
            watchtower_vout = CONTEST_WATCHTOWER_0_VOUT + slot
            wait_until_utxo_spent(
                bitcoin_rpc,
                contest_txid,
                watchtower_vout,
                timeout=7200 * MOSAIC_WAIT_SCALE,
            )
            counterproof_txid = find_utxo_spender_txid(bitcoin_rpc, contest_txid, watchtower_vout)
            wait_for_tx_confirmation(bitcoin_rpc, counterproof_txid, timeout=3600)
            counterproof_txids.append(counterproof_txid)
            self.logger.info(f"Invalid counterproof from slot {slot}: {counterproof_txid}")
        wait_until_counter_proof_posted(bridge_rpc, self.CONTESTED_DEPOSIT_IDX, timeout=7200)

        # 6. op-0 NACKs each one — the payoff the real circuit buys.
        for counterproof_txid in counterproof_txids:
            nack_txid = wait_until_counterproof_nack(bitcoin_rpc, counterproof_txid, timeout=3600)
            wait_for_tx_confirmation(bitcoin_rpc, nack_txid, timeout=3600)
            self.logger.info(f"op-{assigned_idx} NACKed {counterproof_txid} with {nack_txid}")
        wait_until_all_nackd(bridge_rpc, self.CONTESTED_DEPOSIT_IDX, timeout=1800)

        # 7. Run the tip past contest + ack_timelock so the contested payout can land.
        mining_addr = bitcoin_rpc.proxy.getnewaddress()
        miner = generate_blocks(bitcoin_rpc, self.GAME_MINE_INTERVAL_SECS, mining_addr)
        try:
            wait_until_utxo_spent(bitcoin_rpc, contest_txid, CONTEST_PAYOUT_VOUT, timeout=3600)
            contested_payout_txid = find_utxo_spender_txid(
                bitcoin_rpc, contest_txid, CONTEST_PAYOUT_VOUT
            )
            assert_contested_payout_shape(
                bitcoin_rpc,
                contested_payout_txid,
                deposit_txid=contested_deposit_txid,
                claim_txid=claim_txid,
                contest_txid=contest_txid,
            )
            wait_for_tx_confirmation(bitcoin_rpc, contested_payout_txid, timeout=3600)
            self.logger.info(f"Contested payout confirmed: {contested_payout_txid}")
        finally:
            # Stop well short of contested_payout_timelock so the slash never matures.
            miner.stop()

        # 8. Negative assertions, structural rather than timeout-based. The contested payout
        # shape above already pins the contest slash output, so no slash can have fired.
        assert bitcoin_rpc.proxy.gettxout(assigned_stake_txid, STAKE_VOUT) is not None, (
            f"op-{assigned_idx} stake {assigned_stake_txid}:{STAKE_VOUT} was spent; the honest "
            "operator must not be slashed for a counterproof that was invalid"
        )
        stake_status = get_operator_stake_status(bridge_rpc, assigned_idx)
        assert stake_status.state is not RpcStakeStateLabel.SLASHED, (
            f"op-{assigned_idx} reports stake state {stake_status.state}, expected not slashed"
        )

        assert bitcoin_rpc.proxy.gettxout(contested_deposit_txid, DT_DEPOSIT_VOUT) is None, (
            f"deposit {contested_deposit_txid}:{DT_DEPOSIT_VOUT} was not swept by the "
            "contested payout"
        )

        return True
