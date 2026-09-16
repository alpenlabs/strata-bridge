import os
from pathlib import Path

import flexitest

from constants import CONTEST_WATCHTOWER_0_VOUT, COUNTERPROOF_ACK_NACK_VOUT
from envs import BitcoinEnvConfig, ExternalBtcBridgeNetworkEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import BridgeProtocolParams
from factory.common.asm_params import AsmParams
from rpc.types import RpcDepositStatusComplete
from utils.bitcoin import generate_blocks
from utils.bridge import get_bridge_nodes_and_rpcs
from utils.deposit import (
    wait_until_deposit_status,
    wait_until_drt_recognized,
    wait_until_utxo_spent,
)
from utils.dev_cli import DevCli
from utils.mosaic import MOSAIC_WAIT_SCALE
from utils.stake import (
    assert_slash_spends_stake,
    confirmed_stake_txid_for_operator,
    wait_until_operator_slashed,
)
from utils.utils import (
    find_utxo_spender_txid,
    read_operator_key,
    wait_for_tx_confirmation,
)
from utils.withdrawal import wait_until_counterproof_ack


@flexitest.register
class FullMosaicValidCounterproofAckedTest(StrataTestBase):
    """
    Full-circuit control: a VALID counterproof is accepted, so no NACK is possible and the
    ACK path runs to slashing.

    Operator-0 posts a faulty claim and then a faulty bridge proof (dev-cli embeds 128
    zero bytes where a ProofReceipt belongs). Every watchtower legitimately rejects it and
    publishes a genuine counterproof. Under the real g16 circuit that counterproof
    *verifies*, so `evaluate_and_sign` cannot extract the fault secret
    (crates/bridge-exec/src/graph/counterproof_nack.rs) and op-0 cannot sign a NACK.
    After `nack_timelock` the counterprover's ACK takes the counterproof output, and op-0
    is slashed.

    Unlike tests/slashing/fn_counterproof_ack.py, op-0 is deliberately left RUNNING. That
    test has to stop the operator to keep it from NACKing, because under the toy circuit
    NACK-ability is decided by game-index parity rather than by the counterproof. Here the
    circuit itself is what denies the NACK, so leaving op-0 up and watching it fail to
    produce one is the actual assertion.

    Pairs with fn_invalid_counterproof_nackd.py, which runs the same flow at the same
    deposit index with a forged counterproof and must reach the opposite outcome. Deposit
    index 0 (game index 1, odd) is the index at which the toy circuit can never yield a
    NACK, so the pair only discriminates under the real circuit.

    1. Complete a deposit.
    2. Post a faulty claim from op-0 via dev-cli (no assignment, no fulfillment).
    3. Wait for an honest watchtower to auto-contest.
    4. Post a faulty bridge proof from op-0 via dev-cli.
    5. Every watchtower auto-publishes a genuine counterproof.
    6. Assert no NACK appears, then that the ACK does, then that op-0 is slashed.
    """

    BURY_DEPTH = 1
    # Blocks must keep coming for the CSV timelocks in the endgame (nack -> ack ->
    # slash) to mature; mine_on_demand freezes the tip once the mempool drains.
    GAME_MINE_INTERVAL_SECS = 2
    # Deliberately the index at which the toy circuit can never yield a NACK, so the
    # opposite outcome in fn_invalid_counterproof_nackd.py isolates counterproof validity.
    CONTESTED_DEPOSIT_IDX = 0

    def __init__(self, ctx: flexitest.InitContext):
        if os.environ.get("MOSAIC_CIRCUIT_MODE") != "full":
            raise RuntimeError(
                "tests/full_mosaic requires MOSAIC_CIRCUIT_MODE=full; "
                "see tests/full_mosaic/README.md"
            )

        # Single source of truth: the asm-params baked by gen_asm_params_external.py
        # determines how many operator key sets the bridge subprotocol covers, so the
        # test must launch exactly that many operator nodes or N/N signing breaks.
        asm_params_path = Path(os.environ["BRIDGE_PROOF_ASM_PARAMS_DIR"]) / "asm-params.json"
        self.asm_params = AsmParams.load(asm_params_path)
        self.num_operators = len(self.asm_params.bridge.operators)

        self.bridge_protocol_params = BridgeProtocolParams(
            bury_depth=self.BURY_DEPTH,
            contest_timelock=5,
            # SP1 counterproof generation takes many minutes; keep the proof timeout
            # unreachable so it never preempts the game.
            proof_timelock=10_000,
            # The ACK becomes spendable this many blocks after the counterproof confirms.
            # Small, because the ACK is the outcome under test.
            nack_timelock=5,
            # The slash becomes spendable this many blocks after the contest. Must be
            # BELOW ack_timelock so `slash` wins the race for the contest slash output
            # against `contested_payout` — the inverse of the NACK test's ordering.
            contested_payout_timelock=25,
            # op-0 publishes contested_payout at contest + ack_timelock. Keep it well
            # above contested_payout_timelock so the slash lands first; otherwise op-0
            # ends the game before the ACK and the test proves nothing.
            ack_timelock=100,
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

        operator_key_infos = [read_operator_key(i) for i in range(self.num_operators)]
        dev_cli = DevCli(
            bitcoind_service.props,
            operator_key_infos,
            bridge_protocol_params=self.bridge_protocol_params,
        )

        dishonest_idx = 0
        dishonest_node = bridge_nodes[dishonest_idx]
        dishonest_rpc_url = f"http://127.0.0.1:{dishonest_node.props['rpc_port']}"
        dishonest_seed = read_operator_key(dishonest_idx).SEED
        num_watchtowers = self.num_operators - 1

        # 1. Complete a deposit.
        drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted DRT: {drt_txid}")
        deposit_id = wait_until_drt_recognized(bridge_rpc, drt_txid, timeout=3600)
        self.logger.info(f"DRT recognized, deposit_id: {deposit_id}")

        deposit_info = wait_until_deposit_status(
            bridge_rpc,
            deposit_id,
            RpcDepositStatusComplete,
            timeout=7200 * MOSAIC_WAIT_SCALE,
        )
        assert deposit_info is not None, "Deposit did not complete"
        self.logger.info("Deposit completed")

        dishonest_stake_txid = confirmed_stake_txid_for_operator(
            bridge_rpc, bitcoin_rpc, dishonest_idx
        )
        self.logger.info(f"Recorded op-{dishonest_idx} stake txid: {dishonest_stake_txid}")

        # 2. Faulty claim from op-0: no assignment, no fulfillment behind it.
        claim_txid = dev_cli.send_claim(
            deposit_idx=self.CONTESTED_DEPOSIT_IDX,
            operator_idx=dishonest_idx,
            bridge_node_url=dishonest_rpc_url,
            seed=dishonest_seed,
        )
        self.logger.info(f"Broadcasted faulty claim from op-{dishonest_idx}: {claim_txid}")
        wait_for_tx_confirmation(bitcoin_rpc, claim_txid, timeout=3600)

        # 3. An honest watchtower contests it on its own.
        wait_until_utxo_spent(bitcoin_rpc, claim_txid, vout=0, timeout=3600)
        contest_txid = find_utxo_spender_txid(bitcoin_rpc, claim_txid, 0)
        wait_for_tx_confirmation(bitcoin_rpc, contest_txid, timeout=3600)
        self.logger.info(f"Watchtower contested: contest tx {contest_txid}")

        # 4. Faulty bridge proof from op-0.
        bridge_proof_txid = dev_cli.send_bridge_proof(
            deposit_idx=self.CONTESTED_DEPOSIT_IDX,
            operator_idx=dishonest_idx,
            bridge_node_url=dishonest_rpc_url,
            seed=dishonest_seed,
        )
        self.logger.info(f"Broadcasted faulty bridge proof: {bridge_proof_txid}")
        wait_for_tx_confirmation(bitcoin_rpc, bridge_proof_txid, timeout=3600)

        # 5. Every watchtower publishes a genuine counterproof.
        counterproof_txids = []
        for slot in range(num_watchtowers):
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
            self.logger.info(f"Watchtower slot {slot} counterproof: {counterproof_txid}")

        # 6. Run the tip forward so the endgame timelocks mature. Capture every txid we
        # still need first — find_utxo_spender_txid only scans 50 blocks back.
        mining_addr = bitcoin_rpc.proxy.getnewaddress()
        miner = generate_blocks(bitcoin_rpc, self.GAME_MINE_INTERVAL_SECS, mining_addr)
        try:
            # This wait IS the assertion: op-0 is up and still emitting NACK duties, so
            # only the circuit's acceptance of the counterproof lets the ACK win.
            ack_txid = wait_until_counterproof_ack(bitcoin_rpc, contest_txid, timeout=3600)
            wait_for_tx_confirmation(bitcoin_rpc, ack_txid, timeout=3600)
            self.logger.info(f"Counterproof ACK confirmed: {ack_txid}")

            # Only one ACK can exist (it also consumes the contest payout output), so the
            # other counterproofs' outputs stay unspent. Any spender that does appear must
            # have the 2-input ACK shape; a 1-input spender is a NACK.
            for counterproof_txid in counterproof_txids:
                if bitcoin_rpc.proxy.gettxout(counterproof_txid, COUNTERPROOF_ACK_NACK_VOUT):
                    continue
                spender = find_utxo_spender_txid(
                    bitcoin_rpc, counterproof_txid, COUNTERPROOF_ACK_NACK_VOUT
                )
                spender_tx = bitcoin_rpc.proxy.getrawtransaction(spender, True)
                assert len(spender_tx.get("vin", [])) == 2, (
                    f"counterproof {counterproof_txid} was spent by 1-input tx {spender}: "
                    "that is a NACK, but the counterproof was valid and must not be NACKable"
                )

            slashed_stake = wait_until_operator_slashed(bridge_rpc, dishonest_idx, timeout=3600)
            assert slashed_stake.slash_txid is not None
            self.logger.info(f"op-{dishonest_idx} slashed by {slashed_stake.slash_txid}")
            assert_slash_spends_stake(bitcoin_rpc, dishonest_stake_txid, slashed_stake.slash_txid)
        finally:
            miner.stop()

        return True
