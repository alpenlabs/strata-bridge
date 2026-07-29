import os
from pathlib import Path

import flexitest

from constants import CONTEST_WATCHTOWER_0_VOUT
from envs import BitcoinEnvConfig, ExternalBtcBridgeNetworkEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import BridgeProtocolParams
from factory.common.asm_params import AsmParams
from rpc.types import RpcDepositStatusComplete
from utils.bridge import get_bridge_nodes_and_rpcs
from utils.deposit import (
    wait_until_deposit_status,
    wait_until_drt_recognized,
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
    bitcoind env.

    1. Complete a deposit.
    2. Post a faulty claim via dev-cli from operator-0 (no assignment, no fulfillment).
    3. Wait for an honest watchtower to auto-contest.
    4. Post a faulty bridge proof via dev-cli from operator-0.
    5. Every watchtower auto-publishes a counterproof because verification of
       the empty ProofReceipt fails. Verified by asserting every watchtower's
       counterproof output on the contest tx is spent.
    """

    BURY_DEPTH = 1

    # Full-circuit garbling of the stake/deposit graphs is hours of work (7
    # connector instances x 44 GiB garbled tables per operator), so the waits
    # scale up when MOSAIC_CIRCUIT_MODE=full.
    #
    # They must still fit the job's 6h cap. A wait longer than the remaining
    # budget can never fire: the cap kills the job first, and a *cancelled*
    # step is not a *failed* one, so the _dd log upload is skipped and the run
    # yields no diagnostics at all.
    #
    # Sized from run 30441442112, the first full run to fail on its own terms.
    # The stake chain sits behind all of mosaic setup — bootstrap() awaits
    # run_mosaic_setup before init_orchestrator, so no stake SM exists, and
    # get_stake_status returns [], until setup returns. That run measured, per
    # operator: polynomial commitments (164) 80s, shares (182) 22s, then table
    # commitments landing 8 per 4m34s without drift — ~105m for all 181. It was
    # killed at 152/181, phase 4 of a 9-phase setup, evaluator still at
    # WaitingForCommit 0/164. The phases that carry the bulk (164 commit
    # chunks, 174 challenge-response chunks, 7 garbled-table transfers) never
    # started, so setup is only bounded below: >105m, true cost unknown.
    #
    # Budget: 360m cap, less the ~114m the full phase burns on in-run g16
    # generation and builds before the test starts (worst of that run's two
    # jobs), less ~10m variance margin, leaves ~236m of waits. Nearly all of it
    # goes to the stake wait — until setup completes even once there is no
    # measurement to size anything else against.
    #
    # This deliberately leaves no room for the SP1 proving that follows the
    # deposit (~46m for fn_bridge_proof in mock run 30378188334), so a full run
    # reaching that point still fails — one phase later, with the setup cost in
    # hand.
    FULL_MOSAIC = os.environ.get("MOSAIC_CIRCUIT_MODE") == "full"
    STAKE_TIMEOUT = 13_200 if FULL_MOSAIC else 7200
    DEPOSIT_TIMEOUT = 900 if FULL_MOSAIC else 7200

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
            ctx, num_operators=self.num_operators, stake_timeout=self.STAKE_TIMEOUT
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

        # 1. Complete a deposit.
        drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted DRT: {drt_txid}")
        deposit_id = wait_until_drt_recognized(bridge_rpc, drt_txid, timeout=3600)
        self.logger.info(f"DRT recognized, deposit_id: {deposit_id}")

        deposit_info = wait_until_deposit_status(
            bridge_rpc, deposit_id, RpcDepositStatusComplete, timeout=self.DEPOSIT_TIMEOUT
        )
        assert deposit_info is not None, "Deposit did not complete"
        self.logger.info("Deposit completed")

        # 2. Post a faulty claim via dev-cli from operator-0 (no assignment).
        dishonest_idx = 0
        dishonest_node = bridge_nodes[dishonest_idx]
        dishonest_rpc_url = f"http://127.0.0.1:{dishonest_node.props['rpc_port']}"
        dishonest_seed = read_operator_key(dishonest_idx).SEED

        claim_txid = dev_cli.send_claim(
            deposit_idx=0,
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
            deposit_idx=0,
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
        num_watchtowers = self.num_operators - 1
        for slot in range(num_watchtowers):
            watchtower_vout = CONTEST_WATCHTOWER_0_VOUT + slot
            wait_until_utxo_spent(bitcoin_rpc, contest_txid, watchtower_vout, timeout=3600)
            self.logger.info(
                f"Counterproof posted by watchtower slot {slot} (contest:{watchtower_vout} spent)"
            )

        return True
