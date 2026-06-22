import os
import time
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
    wait_until,
)


@flexitest.register
class SP1InvalidClaimValidProofTest(StrataTestBase):
    """
    Unanchored-genesis attack: a dishonest operator posts a VALID SP1 bridge proof
    committing an INVALID claim (a deposit it was never assigned), and the
    watchtowers are UNABLE to counterproof it. The inverse of `fn_counterproof`:
    there the proof is garbage and watchtowers DO refute it; here the proof
    verifies (it is anchored on a forged genesis the bridge proof never checks),
    so the counterproof program cannot refute it and the fraudulent claim stands.

    PREREQUISITE: the asm-runner must be launched with
    `FORGE_GENESIS_CLAIM="<deposit_idx>:<operator_idx>"` so the forged
    OperatorClaimUnlock leaf is seeded into the genesis bridge MMR.

    1. Complete a deposit.
    2. operator-0 posts an (unassigned) faulty claim; a watchtower contests.
    3. `dev-cli forge-bridge-proof` mints AND posts a REAL bridge proof for the
       forged claim from the seeded asm-runner + the honest bridge-proof ELF.
    4. Assert NO watchtower counterproof appears (contest watchtower vouts stay UNSPENT).
    """

    BURY_DEPTH = 1
    FORGE_DEPOSIT_IDX = 0
    FORGE_OPERATOR_IDX = 0
    # Window (seconds) to wait for a (non-)counterproof after posting the valid proof.
    COUNTERPROOF_GRACE_SECS = 600
    # Window (seconds) to wait for the asm-runner's recursive Moho proof at the
    # anchor block (ASM step proof + Moho proof are network-proved, so not instant).
    MOHO_PROOF_GRACE_SECS = 1200

    def __init__(self, ctx: flexitest.InitContext):
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
        forge_spec = os.environ.get("FORGE_GENESIS_CLAIM")
        assert forge_spec == f"{self.FORGE_DEPOSIT_IDX}:{self.FORGE_OPERATOR_IDX}", (
            "asm-runner must be launched with "
            f"FORGE_GENESIS_CLAIM={self.FORGE_DEPOSIT_IDX}:{self.FORGE_OPERATOR_IDX} "
            f"(got {forge_spec!r})"
        )

        bridge_nodes, bridge_rpcs = get_bridge_nodes_and_rpcs(
            ctx, num_operators=self.num_operators, stake_timeout=7200
        )
        bridge_rpc = bridge_rpcs[0]

        bitcoind_service = ctx.get_service("bitcoin")
        bitcoin_rpc = bitcoind_service.create_rpc()

        asm_service = ctx.get_service("asm_rpc")
        asm_rpc_url = asm_service.props["rpc_url"]
        asm_rpc = asm_service.create_rpc()

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
        wait_until_deposit_status(
            bridge_rpc, deposit_id, RpcDepositStatusComplete, timeout=7200
        )
        self.logger.info("Deposit completed")

        # 2. operator-0 posts an unassigned faulty claim; a watchtower contests it.
        dishonest_idx = self.FORGE_OPERATOR_IDX
        dishonest_node = bridge_nodes[dishonest_idx]
        dishonest_rpc_url = f"http://127.0.0.1:{dishonest_node.props['rpc_port']}"
        dishonest_seed = read_operator_key(dishonest_idx).SEED

        claim_txid = dev_cli.send_claim(
            deposit_idx=self.FORGE_DEPOSIT_IDX,
            operator_idx=dishonest_idx,
            bridge_node_url=dishonest_rpc_url,
            seed=dishonest_seed,
        )
        wait_for_tx_confirmation(bitcoin_rpc, claim_txid, timeout=3600)
        wait_until_utxo_spent(bitcoin_rpc, claim_txid, vout=0, timeout=3600)
        contest_txid = find_utxo_spender_txid(bitcoin_rpc, claim_txid, 0)
        wait_for_tx_confirmation(bitcoin_rpc, contest_txid, timeout=3600)
        self.logger.info(f"Watchtower contested op-{dishonest_idx} claim: {contest_txid}")

        # 3. Forge AND post a REAL bridge proof for the forged claim. The forged
        # claim leaf lives in the genesis export MMR, so the first proven Moho
        # (genesis_height + 1) already carries it — anchor there.
        elf_path = os.environ["BRIDGE_PROOF_SP1_ELF"]
        forge_anchor_height = self.asm_params.anchor.block.height + 1

        # The asm-runner proves Moho recursively (ASM step proof → Moho proof), so
        # the anchor block's proof lands well after the block is processed. Wait for
        # it; otherwise dev-cli fails fast with "moho proof unavailable at anchor".
        # The Moho proof is last to be ready, so its presence implies the MohoState
        # and MMR-inclusion inputs are too. Mirrors fn_asm_proof_readiness_test.
        forge_anchor_hash = bitcoin_rpc.proxy.getblockhash(forge_anchor_height)
        wait_until(
            lambda: asm_rpc.strata_asm_getMohoProof(forge_anchor_hash) is not None,
            timeout=self.MOHO_PROOF_GRACE_SECS,
            step=5,
            error_msg=f"asm-runner produced no Moho proof at height {forge_anchor_height}",
        )

        self.logger.info(
            f"forging real bridge proof for INVALID claim "
            f"(deposit={self.FORGE_DEPOSIT_IDX}, operator={dishonest_idx}) "
            f"at L1 height {forge_anchor_height} (SP1 setup + prove is slow)"
        )
        bridge_proof_txid = dev_cli.forge_bridge_proof(
            deposit_idx=self.FORGE_DEPOSIT_IDX,
            operator_idx=dishonest_idx,
            bridge_node_url=dishonest_rpc_url,
            seed=dishonest_seed,
            asm_rpc_url=asm_rpc_url,
            elf_path=elf_path,
            last_block_height=forge_anchor_height,
        )
        wait_for_tx_confirmation(bitcoin_rpc, bridge_proof_txid, timeout=3600)
        self.logger.info(
            f"Posted a VALID bridge proof with an INVALID claim: {bridge_proof_txid}"
        )

        # 4. Assert NO watchtower can counterproof it. Give them a generous window
        # (mining blocks so any block-driven reaction fires); a counterproof would
        # spend a contest watchtower vout. They cannot, because the proof verifies.
        num_watchtowers = self.num_operators - 1
        watchtower_vouts = [CONTEST_WATCHTOWER_0_VOUT + slot for slot in range(num_watchtowers)]
        mine_addr = bitcoin_rpc.proxy.getnewaddress()
        deadline = time.time() + self.COUNTERPROOF_GRACE_SECS
        while time.time() < deadline:
            # advance the chain so any watchtower counterproof attempt has every chance
            bitcoin_rpc.proxy.generatetoaddress(1, mine_addr)
            spent = [
                v for v in watchtower_vouts
                if bitcoin_rpc.proxy.gettxout(contest_txid, v) is None
            ]
            assert not spent, (
                f"a watchtower COUNTERPROOFED the valid-but-invalid-claim proof "
                f"(contest vouts {spent} spent) — the attack would have been caught"
            )
            time.sleep(10)

        for v in watchtower_vouts:
            assert bitcoin_rpc.proxy.gettxout(contest_txid, v) is not None, (
                f"contest watchtower vout {v} was spent — unexpected counterproof"
            )
        self.logger.info(
            "No watchtower could counterproof the valid proof of an invalid claim: "
            "all contest watchtower vouts remain UNSPENT. The fraudulent claim stands."
        )
        return True
