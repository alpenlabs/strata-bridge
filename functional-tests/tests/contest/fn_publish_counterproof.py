import flexitest

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

# Vout layout mirrored from the tx-graph Rust constants.
CLAIM_CONTEST_VOUT = 0
CONTEST_PROOF_VOUT = 0
CONTEST_WATCHTOWER_0_VOUT = 3


@flexitest.register
class CounterproofPublishedOnBridgeProofVerificationFailureTest(StrataTestBase):
    """
    Test that every watchtower publishes a counterproof when the bridge proof is invalid.

    Uses the faulty-claim path (no assignment, no fulfillment) so the counterproof
    mechanism is the only thing driving the game forward:

    1. Complete a deposit.
    2. Op-0 posts a faulty claim via dev-cli.
    3. A watchtower auto-contests by spending the claim's contest connector.
    4. Op-0 auto-posts a (mock) bridge proof defending the contest.
    5. Every watchtower auto-publishes a counterproof because the bridge proof
       predicate is `NeverAccept`. Verified by asserting every watchtower's
       counterproof output on the contest tx is spent.
    """

    def __init__(self, ctx: flexitest.InitContext):
        self.bridge_protocol_params = BridgeProtocolParams(
            contest_timelock=5,
            proof_timelock=100,
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

        # Op-0 posts a faulty claim (no assignment, no fulfillment).
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

        # Wait for op-0 to auto-post the (mock) bridge proof defending the contest.
        wait_until_utxo_spent(bitcoin_rpc, contest_txid, CONTEST_PROOF_VOUT, timeout=300)
        self.logger.info("Bridge proof posted (contest proof connector spent)")

        # Every watchtower must publish its counterproof. The contest tx has one
        # counterproof output per watchtower starting at WATCHTOWER_0_VOUT=3.
        num_watchtowers = num_operators - 1
        for slot in range(num_watchtowers):
            watchtower_vout = CONTEST_WATCHTOWER_0_VOUT + slot
            wait_until_utxo_spent(bitcoin_rpc, contest_txid, watchtower_vout, timeout=300)
            self.logger.info(
                f"Counterproof posted by watchtower slot {slot} (contest:{watchtower_vout} spent)"
            )

        return True
