import flexitest

from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import BridgeProtocolParams
from rpc.types import RpcDepositStatusComplete
from utils.bridge import get_bridge_nodes_and_rpcs
from utils.deposit import (
    wait_until_deposit_status,
    wait_until_deposit_utxo_spent,
    wait_until_drt_recognized,
)
from utils.dev_cli import DevCli
from utils.utils import (
    read_operator_key,
    wait_for_tx_confirmation,
    wait_until,
)
from utils.withdrawal import (
    wait_until_active_valid_claim,
    wait_until_bridge_proof_posted,
    wait_until_counter_proof_posted,
)


@flexitest.register
class CounterproofNackPublishedOnInvalidCounterproofTest(StrataTestBase):
    """
    Test that the POV operator publishes a counterproof NACK after watchtowers post a
    counterproof, and the contested payout path completes end-to-end.

    The bridge proof predicate is set to `NeverAccept` so every bridge proof fails
    verification and watchtowers respond with a counterproof. The POV operator then
    runs the mosaic-backed `evaluate_and_sign` flow and publishes a counterproof NACK
    transaction. Once the NACKs and contested payout confirm, the deposit UTXO is spent.

    Steps:
    1. Complete a deposit
    2. Submit a contest against the active claim
    3. Wait for the bridge proof to be posted
    4. Wait for the counterproof to be posted by watchtowers
    5. Verify the deposit UTXO is spent after the NACK + contested-payout path completes
    """

    def __init__(self, ctx: flexitest.InitContext):
        self.bridge_protocol_params = BridgeProtocolParams(
            contest_timelock=5,
            ack_timelock=10,
            bridge_proof_predicate="NeverAccept",
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

        num_operators = len(bridge_nodes)
        operator_key_infos = [read_operator_key(i) for i in range(num_operators)]

        # Init ASM rpc
        asm_service = ctx.get_service("asm_rpc")
        asm_rpc = asm_service.create_rpc()

        # Wait for DT and DRT
        bitcoind_props = bitcoind_service.props
        dev_cli = DevCli(
            bitcoind_props,
            operator_key_infos,
            bridge_protocol_params=self.bridge_protocol_params,
        )

        drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted DRT: {drt_txid}")
        deposit_id = wait_until_drt_recognized(bridge_rpc, drt_txid)
        self.logger.info(f"DRT recognized, deposit_id: {deposit_id}")

        deposit_info = wait_until_deposit_status(bridge_rpc, deposit_id, RpcDepositStatusComplete)
        assert deposit_info is not None, "Deposit did not complete"
        self.logger.info("Deposit completed")
        deposit_txid = deposit_info.get("status").get("deposit_txid")
        self.logger.info(f"Deposit txid: {deposit_txid}")

        # Now post mock checkpoint so that a withdrawal is assigned
        recent_block_hash = bitcoin_rpc.proxy.getblockhash(bitcoin_rpc.proxy.getblockcount())
        ckp_l1_txn = dev_cli.send_mock_checkpoint_from_tip(
            asm_rpc,
            recent_block_hash,
            num_ol_slots=1,
        )
        ckp_block_hash = wait_for_tx_confirmation(bitcoin_rpc, ckp_l1_txn)
        self.logger.info(f"Checkpoint tx {ckp_l1_txn} included in block {ckp_block_hash}")

        # Wait for ASM to process the checkpoint, then wait for an active claim
        wait_until(
            lambda: len(asm_rpc.strata_asm_getAssignments(ckp_block_hash)) > 0,
            timeout=300,
            error_msg="ASM did not produce assignment",
        )

        active_claim = wait_until_active_valid_claim(bridge_rpc)
        self.logger.info(
            "Active claim %s for deposit %s assigned to operator %s",
            active_claim.claim_txid,
            active_claim.deposit_idx,
            active_claim.assigned_operator,
        )

        claim_block_hash = wait_for_tx_confirmation(
            bitcoin_rpc,
            active_claim.claim_txid,
            timeout=300,
        )
        self.logger.info(
            f"Claim tx {active_claim.claim_txid} confirmed in block {claim_block_hash}"
        )

        # Use a different operator's node to contest
        contester_idx = (active_claim.assigned_operator + 1) % num_operators
        contester_node = bridge_nodes[contester_idx]
        contester_rpc_url = f"http://127.0.0.1:{contester_node.props['rpc_port']}"

        self.logger.info(f"Contesting with operator {contester_idx} via {contester_rpc_url}")
        contester_seed = read_operator_key(contester_idx).SEED

        contest_txid = dev_cli.send_contest(
            deposit_idx=active_claim.deposit_idx,
            operator_idx=active_claim.assigned_operator,
            bridge_node_url=contester_rpc_url,
            contester_node_idx=contester_idx,
            seed=contester_seed,
        )
        self.logger.info(f"Broadcasted contest_txid: {contest_txid}")
        contest_block_hash = wait_for_tx_confirmation(
            bitcoin_rpc,
            contest_txid,
            timeout=300,
        )
        self.logger.info(f"Contest tx {contest_txid} confirmed in block {contest_block_hash}")

        # The POV (assigned) operator's RPC observes the full game and emits the NACK duty.
        pov_rpc = bridge_rpcs[active_claim.assigned_operator]

        # Wait for bridge proof to be posted by the assigned operator
        wait_until_bridge_proof_posted(pov_rpc, active_claim.deposit_idx)
        self.logger.info("Bridge proof posted")

        # With NeverAccept predicate, watchtowers reject the proof and publish counterproofs.
        wait_until_counter_proof_posted(pov_rpc, active_claim.deposit_idx)
        self.logger.info("Counterproof posted — watchtowers rejected the invalid bridge proof")

        # The POV operator runs evaluate_and_sign via mosaic and publishes a NACK for each
        # watchtower's counterproof. Wait for the deposit UTXO to be spent — this fires once the
        # full contested-payout path (including the NACKs) completes and the operator sweeps the
        # deposit.
        wait_until_deposit_utxo_spent(bitcoin_rpc, deposit_txid, timeout=450)
        self.logger.info("Deposit UTXO confirmed spent after counterproof NACK + contested payout")

        return True
