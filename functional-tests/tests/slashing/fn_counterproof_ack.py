import flexitest

from constants import (
    CLAIM_CONTEST_VOUT,
    CONTEST_PAYOUT_VOUT,
    CONTEST_PROOF_VOUT,
    CONTEST_WATCHTOWER_0_VOUT,
    COUNTERPROOF_ACK_NACK_VOUT,
)
from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import BridgeProtocolParams, ProofPredicate
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
class CounterproofAckTest(StrataTestBase):
    """
    Test that a counterproof ACK is auto-published after the NACK timelock.

    Faulty-claim path with the `NeverAccept` proof predicate so every
    watchtower auto-publishes a counterproof:

    1. Complete a deposit.
    2. Op-0 posts a faulty claim via dev-cli (no assignment, no fulfillment).
    3. A watchtower auto-contests by spending the claim's contest connector.
    4. Op-0 auto-posts a (mock) bridge proof defending the contest.
    5. Every watchtower auto-publishes a counterproof.
    6. After the NACK timelock expires, a counterprover auto-publishes a
       counterproof ACK. Identify the ACK by waiting for the contest
       payout output (vout 1) to be spent and then backtracking through
       the spender's inputs to confirm one of them is a counterproof tx
       (single input spending one of the contest's per-watchtower
       outputs). This rules out false positives where another tx (e.g.
       `contested_payout`) spends the contest payout output.
    """

    def __init__(self, ctx: flexitest.InitContext):
        self.bridge_protocol_params = BridgeProtocolParams(
            contest_timelock=5,
            proof_timelock=100,  # ensure no proof timeout fires
            nack_timelock=5,
            bridge_proof_predicate=ProofPredicate.NEVER_ACCEPT,
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

        bitcoind_props = bitcoind_service.props
        dev_cli = DevCli(
            bitcoind_props,
            operator_key_infos,
            bridge_protocol_params=self.bridge_protocol_params,
        )

        # Complete a deposit.
        drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted DRT: {drt_txid}")
        deposit_id = wait_until_drt_recognized(bridge_rpc, drt_txid)
        self.logger.info(f"DRT recognized, deposit_id: {deposit_id}")

        deposit_info = wait_until_deposit_status(bridge_rpc, deposit_id, RpcDepositStatusComplete)
        assert deposit_info is not None, "Deposit did not complete"
        self.logger.info("Deposit completed")

        # Op-0 posts a faulty claim.
        graph_owner_idx = 0
        deposit_idx = 0

        owner_node = bridge_nodes[graph_owner_idx]
        owner_rpc_url = f"http://127.0.0.1:{owner_node.props['rpc_port']}"
        owner_seed = read_operator_key(graph_owner_idx).SEED

        claim_txid = dev_cli.send_claim(
            deposit_idx=deposit_idx,
            operator_idx=graph_owner_idx,
            bridge_node_url=owner_rpc_url,
            seed=owner_seed,
        )
        self.logger.info(f"Broadcasted faulty claim from op-{graph_owner_idx}: {claim_txid}")
        claim_block_hash = wait_for_tx_confirmation(bitcoin_rpc, claim_txid, timeout=300)
        self.logger.info(f"Faulty claim {claim_txid} confirmed in block {claim_block_hash}")

        # Wait for a watchtower to contest, then look up the contest txid.
        wait_until_utxo_spent(bitcoin_rpc, claim_txid, CLAIM_CONTEST_VOUT, timeout=300)
        contest_txid = find_utxo_spender_txid(bitcoin_rpc, claim_txid, CLAIM_CONTEST_VOUT)
        self.logger.info(f"Watchtower contested with contest tx: {contest_txid}")

        # Wait for the contest-proof connector to be spent (bridge proof or proof timeout).
        wait_until_utxo_spent(bitcoin_rpc, contest_txid, CONTEST_PROOF_VOUT, timeout=300)
        proof_spender_txid = find_utxo_spender_txid(bitcoin_rpc, contest_txid, CONTEST_PROOF_VOUT)
        self.logger.info(f"Contest-proof connector spent by tx: {proof_spender_txid}")

        # Stop the graph owner so it cannot publish a counterproof NACK; without a NACK before
        # `nack_timelock` matures, the counterprover's auto-published ACK wins the race.
        bridge_nodes[graph_owner_idx].stop()
        self.logger.info(f"Stopped op-{graph_owner_idx} so no counterproof NACK is published")

        # Wait for the contest payout output to be spent. The ACK candidate is the spender.
        wait_until_utxo_spent(bitcoin_rpc, contest_txid, CONTEST_PAYOUT_VOUT, timeout=600)
        ack_txid = find_utxo_spender_txid(bitcoin_rpc, contest_txid, CONTEST_PAYOUT_VOUT)

        # The ACK has exactly two inputs: the contest payout output and a counterproof's
        # ACK_NACK output.
        ack_tx = bitcoin_rpc.proxy.getrawtransaction(ack_txid, True)
        ack_inputs = [(vin["txid"], vin["vout"]) for vin in ack_tx.get("vin", [])]
        assert len(ack_inputs) == 2, (
            f"ACK candidate {ack_txid} must have 2 inputs, got {len(ack_inputs)}: {ack_inputs}"
        )
        contest_input = (contest_txid, CONTEST_PAYOUT_VOUT)
        assert contest_input in ack_inputs, (
            f"ACK candidate {ack_txid} does not spend contest payout {contest_input}"
        )
        ((counterproof_input_txid, counterproof_input_vout),) = [
            inp for inp in ack_inputs if inp != contest_input
        ]
        assert counterproof_input_vout == COUNTERPROOF_ACK_NACK_VOUT, (
            f"ACK candidate's other input is "
            f"{counterproof_input_txid}:{counterproof_input_vout}, "
            f"expected vout {COUNTERPROOF_ACK_NACK_VOUT}"
        )

        # Backtrack: the other input must itself be a counterproof tx, i.e. a single-input
        # tx spending one of the contest's per-watchtower outputs (vout >=
        # WATCHTOWER_0_VOUT). This rules out other shapes (e.g. `contested_payout`) that
        # might also spend the contest payout output.
        counterproof_candidate = bitcoin_rpc.proxy.getrawtransaction(counterproof_input_txid, True)
        cp_inputs = counterproof_candidate.get("vin", [])
        assert len(cp_inputs) == 1, (
            f"counterproof candidate {counterproof_input_txid} must have 1 input, "
            f"got {len(cp_inputs)}"
        )
        cp_in_txid = cp_inputs[0].get("txid")
        cp_in_vout = cp_inputs[0].get("vout")
        assert cp_in_txid == contest_txid and cp_in_vout >= CONTEST_WATCHTOWER_0_VOUT, (
            f"counterproof candidate {counterproof_input_txid} spends "
            f"{cp_in_txid}:{cp_in_vout}, expected contest:{CONTEST_WATCHTOWER_0_VOUT}+"
        )

        self.logger.info(
            f"Counterproof ACK {ack_txid} confirmed "
            f"(spends counterproof:{COUNTERPROOF_ACK_NACK_VOUT}="
            f"{counterproof_input_txid}:{counterproof_input_vout} + "
            f"contest:{CONTEST_PAYOUT_VOUT}; counterproof spends contest:{cp_in_vout})"
        )

        return True
