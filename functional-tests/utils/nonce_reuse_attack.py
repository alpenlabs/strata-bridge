"""Shared helpers for the nonce reuse functional attack test."""

import re
from dataclasses import dataclass, field

# Constants from crates/tx-graph/src/musig_functor.rs
GAME_SINGLE_LEN = 11  # Non-watchtower signing inputs
GAME_WATCHTOWER_LEN = 4  # Signing inputs per watchtower
CONTEST_INDICES = [GAME_SINGLE_LEN + i * GAME_WATCHTOWER_LEN for i in range(3)]  # 11, 15, 19

# secp256k1 constants
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_GX = 55066263022277343669578718895168534326250603453777594175500187360389116729240
SECP256K1_GY = 32670510020758816978083085130507043184471273380659243275938904335757337482424


@dataclass
class OperatorSigningData:
    """Data intercepted from P2P messages for a single operator."""

    operator_idx: int
    nonces: list[str] = field(default_factory=list)  # hex-encoded PubNonces
    partials: list[str] = field(default_factory=list)  # hex-encoded PartialSignatures
    coefficients: dict[int, "SigningCoefficients"] = field(default_factory=dict)


@dataclass
class SigningCoefficients:
    """Extraction coefficients for one signature index."""

    sig_idx: int
    key_coeff: int
    binding_factor: int
    challenge: int
    nonce_parity: int  # +1 or -1


# Format: "received graph nonces/partials from operator" with graph_idx, op_idx, payload_hex
NONCES_PATTERN = re.compile(
    (
        r"received graph nonces from operator.*"
        r"graph_idx=GraphIdx\(deposit: (\d+), operator: (\d+)\).*"
        r"op_idx=(\d+).*nonces_hex=([0-9a-f,]+)"
    ),
    re.IGNORECASE,
)
PARTIALS_PATTERN = re.compile(
    (
        r"received graph partials from operator.*"
        r"graph_idx=GraphIdx\(deposit: (\d+), operator: (\d+)\).*"
        r"op_idx=(\d+).*partials_hex=([0-9a-f,]+)"
    ),
    re.IGNORECASE,
)
COEFFICIENTS_PATTERN = re.compile(
    (
        r"graph signing coefficients.*"
        r"graph_idx=GraphIdx\(deposit: (\d+), operator: (\d+)\).*"
        r"op_idx=(\d+).*sig_idx=(\d+).*key_coeff_hex=([0-9a-f]+).*"
        r"binding_factor_hex=([0-9a-f]+).*challenge_hex=([0-9a-f]+).*"
        r"nonce_parity=(-?1)"
    ),
    re.IGNORECASE,
)


def parse_signing_data_from_single_log(
    log_file: str,
) -> dict[tuple[int, int], dict[int, OperatorSigningData]]:
    """
    Parse ONE operator's log to extract nonces and partials from ALL operators.

    An attacker node sees P2P messages from all peers, so one log contains
    signing data from all operators.
    """
    signing_data_by_graph: dict[tuple[int, int], dict[int, OperatorSigningData]] = {}

    with open(log_file) as f:
        for line in f:
            match = NONCES_PATTERN.search(line)
            if match:
                deposit_idx = int(match.group(1))
                graph_operator_idx = int(match.group(2))
                op_idx = int(match.group(3))
                nonces = match.group(4).split(",")
                graph_key = (deposit_idx, graph_operator_idx)
                graph_signing_data = signing_data_by_graph.setdefault(graph_key, {})
                if op_idx not in graph_signing_data:
                    graph_signing_data[op_idx] = OperatorSigningData(operator_idx=op_idx)
                graph_signing_data[op_idx].nonces = nonces

            match = PARTIALS_PATTERN.search(line)
            if match:
                deposit_idx = int(match.group(1))
                graph_operator_idx = int(match.group(2))
                op_idx = int(match.group(3))
                partials = match.group(4).split(",")
                graph_key = (deposit_idx, graph_operator_idx)
                graph_signing_data = signing_data_by_graph.setdefault(graph_key, {})
                if op_idx not in graph_signing_data:
                    graph_signing_data[op_idx] = OperatorSigningData(operator_idx=op_idx)
                graph_signing_data[op_idx].partials = partials

            match = COEFFICIENTS_PATTERN.search(line)
            if match:
                deposit_idx = int(match.group(1))
                graph_operator_idx = int(match.group(2))
                op_idx = int(match.group(3))
                sig_idx = int(match.group(4))
                key_coeff = int(match.group(5), 16)
                binding_factor = int(match.group(6), 16)
                challenge = int(match.group(7), 16)
                nonce_parity = int(match.group(8))

                graph_key = (deposit_idx, graph_operator_idx)
                graph_signing_data = signing_data_by_graph.setdefault(graph_key, {})
                if op_idx not in graph_signing_data:
                    graph_signing_data[op_idx] = OperatorSigningData(operator_idx=op_idx)

                graph_signing_data[op_idx].coefficients[sig_idx] = SigningCoefficients(
                    sig_idx=sig_idx,
                    key_coeff=key_coeff,
                    binding_factor=binding_factor,
                    challenge=challenge,
                    nonce_parity=nonce_parity,
                )

    return signing_data_by_graph


def select_best_graph_signing_data(
    signing_data_by_graph: dict[tuple[int, int], dict[int, OperatorSigningData]],
    num_operators: int,
) -> tuple[tuple[int, int], dict[int, OperatorSigningData]] | None:
    """Pick graph context with the most complete contest-index rows."""
    best_key: tuple[int, int] | None = None
    best_score = -1

    for graph_key, graph_signing_data in signing_data_by_graph.items():
        score = 0
        for op_idx in range(num_operators):
            op_data = graph_signing_data.get(op_idx)
            if op_data is None:
                continue
            if (
                all(idx < len(op_data.nonces) for idx in CONTEST_INDICES)
                and all(idx < len(op_data.partials) for idx in CONTEST_INDICES)
                and all(idx in op_data.coefficients for idx in CONTEST_INDICES)
            ):
                score += 1

        if score > best_score:
            best_score = score
            best_key = graph_key

    if best_key is None:
        return None

    return best_key, signing_data_by_graph[best_key]


def mod_inverse(a: int, m: int) -> int:
    """Compute modular inverse using extended Euclidean algorithm."""

    def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    _, x, _ = extended_gcd(a % m, m)
    return (x % m + m) % m


def det_3x3(matrix: list[list[int]], n: int) -> int:
    """Compute 3x3 determinant mod n."""
    a, b, c = matrix[0]
    d, e, f = matrix[1]
    g, h, i = matrix[2]

    return (a * (e * i - f * h) - b * (d * i - f * g) + c * (d * h - e * g)) % n


def extract_scaled_key_cramer(
    partials: list[int],
    challenges: list[int],
    binding_factors: list[int],
    nonce_factors: list[int],
    n: int,
) -> int | None:
    """
    Extract y from 3 equations using Cramer's rule:
    s_i = n_i*k1 + n_i*b_i*k2 + e_i*y

    y is the scaled secret term y = a*n_d*x. We recover x later via x = y / a (mod n),
    which is valid up to sign (x-only pubkey ambiguity).
    """
    A = [
        [
            nonce_factors[0] % n,
            (nonce_factors[0] * binding_factors[0]) % n,
            challenges[0] % n,
        ],
        [
            nonce_factors[1] % n,
            (nonce_factors[1] * binding_factors[1]) % n,
            challenges[1] % n,
        ],
        [
            nonce_factors[2] % n,
            (nonce_factors[2] * binding_factors[2]) % n,
            challenges[2] % n,
        ],
    ]

    b = partials[:3]

    det_A = det_3x3(A, n)
    if det_A == 0:
        return None

    A_with_b = [
        [A[0][0], A[0][1], b[0]],
        [A[1][0], A[1][1], b[1]],
        [A[2][0], A[2][1], b[2]],
    ]
    det_A2 = det_3x3(A_with_b, n)

    det_A_inv = mod_inverse(det_A, n)
    y = (det_A2 * det_A_inv) % n

    return y


def secp_point_add(
    p1: tuple[int, int] | None, p2: tuple[int, int] | None
) -> tuple[int, int] | None:
    """Add two secp256k1 affine points."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and (y1 + y2) % SECP256K1_P == 0:
        return None

    if p1 == p2:
        slope = (3 * x1 * x1) * mod_inverse(2 * y1, SECP256K1_P)
    else:
        slope = (y2 - y1) * mod_inverse((x2 - x1) % SECP256K1_P, SECP256K1_P)
    slope %= SECP256K1_P

    x3 = (slope * slope - x1 - x2) % SECP256K1_P
    y3 = (slope * (x1 - x3) - y1) % SECP256K1_P
    return x3, y3


def secp_scalar_mul(k: int, point: tuple[int, int]) -> tuple[int, int] | None:
    """Multiply an affine point by scalar k on secp256k1."""
    scalar = k % SECP256K1_N
    if scalar == 0:
        return None

    result = None
    addend: tuple[int, int] | None = point

    while scalar > 0:
        if scalar & 1:
            result = secp_point_add(result, addend)
        addend = secp_point_add(addend, addend)
        scalar >>= 1

    return result


def secret_scalar_to_xonly_pubkey(secret_scalar: int) -> str:
    """Derive x-only pubkey hex from secp256k1 secret scalar."""
    point = secp_scalar_mul(secret_scalar, (SECP256K1_GX, SECP256K1_GY))
    if point is None:
        raise ValueError("Invalid zero scalar")
    x, _ = point
    return f"{x:064x}"
