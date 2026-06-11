import os
from pathlib import Path

import flexitest

from constants import (
    CONTEST_WATCHTOWER_0_VOUT,
    COUNTERPROOF_ACK_NACK_VOUT,
)
from envs import BitcoinEnvConfig, ExternalBtcBridgeNetworkEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import BridgeProtocolParams
from factory.common.asm_params import AsmParams
from rpc.types import RpcDepositStatusComplete
from utils.bridge import get_bridge_nodes_and_rpcs
from utils.deposit import (
    wait_until_deposit_status,
    wait_until_deposit_utxo_spent,
    wait_until_drts_recognized,
    wait_until_utxo_spent,
)
from utils.dev_cli import DevCli
from utils.utils import (
    find_utxo_spender_txid,
    read_operator_key,
    wait_for_tx_confirmation,
)


@flexitest.register
class SP1CounterproofTest(StrataTestBase):
    """
    Test that every watchtower publishes a real (SP1) counterproof when a
    dishonest operator posts a faulty bridge proof, under the external regtest
    bitcoind env, and that the POV operator NACKs each counterproof.

    Two deposits are created and the *second* one (deposit index 1) is contested. The
    mosaic node runs the bundled "depositidx" garbled circuit whose output is just the
    LSB of the deposit-input wire, and the bridge sets that wire to the game index
    (`deposit_idx + 1`). The POV operator can only extract the fault secret (and
    therefore sign the NACK) when that LSB is 0 — i.e. when the game index is even.
    Deposit index 1 → game index 2 (even) satisfies this; deposit index 0 → game index 1
    (odd) never would.

    1. Complete two deposits.
    2. Post a faulty claim for deposit index 1 via dev-cli from operator-0
       (no assignment, no fulfillment).
    3. Wait for an honest watchtower to auto-contest.
    4. Post a faulty bridge proof via dev-cli from operator-0.
    5. Every watchtower auto-publishes a counterproof because verification of
       the empty ProofReceipt fails. Verified by asserting every watchtower's
       counterproof output on the contest tx is spent.
    6. The POV operator NACKs each counterproof and the contested payout sweeps the
       deposit. Verified by asserting each counterproof's ack/nack output and the
       deposit UTXO are spent.
    """

    BURY_DEPTH = 1

    def __init__(self, ctx: flexitest.InitContext):
        # Single source of truth: the asm-params baked by gen_asm_params_external.py
        # determines how many operator key sets the bridge subprotocol covers, so the
        # test must launch exactly that many operator nodes or N/N signing breaks.
        asm_params_path = Path(os.environ["BRIDGE_PROOF_ASM_PARAMS_DIR"]) / "asm-params.json"
        self.asm_params = AsmParams.load(asm_params_path)
        self.num_operators = len(self.asm_params.bridge.operators)

        self.bridge_protocol_params = BridgeProtocolParams(
            bury_depth=self.BURY_DEPTH,
            contest_timelock=5,
            ack_timelock=10,
            proof_timelock=10_000,
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
        bridge_rpc = bridge_rpcs[0]

        bitcoind_service = ctx.get_service("bitcoin")
        bitcoin_rpc = bitcoind_service.create_rpc()

        operator_key_infos = [read_operator_key(i) for i in range(self.num_operators)]

        bitcoind_props = bitcoind_service.props
        dev_cli = DevCli(
            bitcoind_props,
            operator_key_infos,
            bridge_protocol_params=self.bridge_protocol_params,
        )

        # 1. Complete two deposits. Contest the second (index 1 → game index 2, even) so
        # the POV operator's mosaic evaluation can extract the fault secret and sign
        # the NACK.
        contested_deposit_idx = 1

        drt_txids = [dev_cli.send_deposit_request() for _ in range(2)]
        for i, drt_txid in enumerate(drt_txids):
            self.logger.info(f"Broadcasted DRT[{i}]: {drt_txid}")

        deposit_ids = wait_until_drts_recognized(bridge_rpc, drt_txids, timeout=3600)
        self.logger.info(f"DRTs recognized, deposit_ids: {deposit_ids}")

        # Complete both deposits. Capture the contested deposit's txid — that is the
        # UTXO we expect to be swept at the end.
        contested_deposit_txid = None
        for deposit_id in sorted(deposit_ids):
            deposit_info = wait_until_deposit_status(
                bridge_rpc, deposit_id, RpcDepositStatusComplete, timeout=7200
            )
            assert deposit_info is not None, f"Deposit {deposit_id} did not complete"
            if deposit_id == contested_deposit_idx:
                contested_deposit_txid = deposit_info.get("status").get("deposit_txid")
        assert contested_deposit_txid is not None, (
            f"contested deposit {contested_deposit_idx} did not complete"
        )
        self.logger.info("Both deposits completed")
        self.logger.info(
            f"Contesting deposit {contested_deposit_idx}, txid: {contested_deposit_txid}"
        )

        # 2. Post a faulty claim via dev-cli from operator-0 (no assignment).
        dishonest_idx = 0
        dishonest_node = bridge_nodes[dishonest_idx]
        dishonest_rpc_url = f"http://127.0.0.1:{dishonest_node.props['rpc_port']}"
        dishonest_seed = read_operator_key(dishonest_idx).SEED

        claim_txid = dev_cli.send_claim(
            deposit_idx=contested_deposit_idx,
            operator_idx=dishonest_idx,
            bridge_node_url=dishonest_rpc_url,
            seed=dishonest_seed,
        )
        self.logger.info(f"Broadcasted faulty claim tx from op-{dishonest_idx}: {claim_txid}")

        claim_block_hash = wait_for_tx_confirmation(bitcoin_rpc, claim_txid, timeout=3600)
        self.logger.info(f"Faulty claim tx {claim_txid} confirmed in block {claim_block_hash}")

        # 3. Wait for a watchtower to contest the claim (claim:vout=0 spent).
        wait_until_utxo_spent(bitcoin_rpc, claim_txid, vout=0, timeout=3600)
        contest_txid = find_utxo_spender_txid(bitcoin_rpc, claim_txid, 0)
        contest_block_hash = wait_for_tx_confirmation(bitcoin_rpc, contest_txid, timeout=3600)
        self.logger.info(
            f"Watchtower contested op-{dishonest_idx} claim: contest tx {contest_txid} "
            f"confirmed in block {contest_block_hash}"
        )

        # 4. Post a faulty bridge proof via dev-cli from operator-0.
        bridge_proof_txid = dev_cli.send_bridge_proof(
            deposit_idx=contested_deposit_idx,
            operator_idx=dishonest_idx,
            bridge_node_url=dishonest_rpc_url,
            seed=dishonest_seed,
        )
        self.logger.info(
            f"Broadcasted faulty bridge proof tx from op-{dishonest_idx}: {bridge_proof_txid}"
        )

        bridge_proof_block_hash = wait_for_tx_confirmation(
            bitcoin_rpc, bridge_proof_txid, timeout=3600
        )
        self.logger.info(
            f"Faulty bridge proof tx {bridge_proof_txid} confirmed in block "
            f"{bridge_proof_block_hash}"
        )

        # 5. Every watchtower must publish its counterproof. The contest tx has one
        # counterproof output per watchtower starting at CONTEST_WATCHTOWER_0_VOUT.
        # The POV operator then publishes a NACK that spends each counterproof's
        # ack/nack output.
        num_watchtowers = self.num_operators - 1
        for slot in range(num_watchtowers):
            watchtower_vout = CONTEST_WATCHTOWER_0_VOUT + slot
            wait_until_utxo_spent(bitcoin_rpc, contest_txid, watchtower_vout, timeout=3600)
            counterproof_txid = find_utxo_spender_txid(bitcoin_rpc, contest_txid, watchtower_vout)
            self.logger.info(f"Watchtower slot {slot} counterproof tx: {counterproof_txid}")
            wait_until_utxo_spent(
                bitcoin_rpc,
                counterproof_txid,
                COUNTERPROOF_ACK_NACK_VOUT,
                timeout=3600,
            )
            self.logger.info(
                f"Counterproof {counterproof_txid} ack/nack output spent (NACK published)"
            )

        # 6. The ack/nack vout we checked above could've been spent by either an ACK or a
        # NACK, so seeing it spent isn't enough on its own. Waiting for the deposit to get
        # swept is what tells us the NACK actually fired — only the contested-payout path
        # gets there.
        wait_until_deposit_utxo_spent(bitcoin_rpc, contested_deposit_txid, timeout=3600)
        self.logger.info("Deposit UTXO confirmed spent after counterproof NACK + contested payout")

        return True
