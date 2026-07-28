import json
import os
from dataclasses import dataclass
from pathlib import Path

# ensure no colllsion
MOSAIC_PORT_BASE = 11900

MOSAIC_KEYS_PATH = Path(__file__).parent.parent / "artifacts" / "mosaic.json"


@dataclass
class MosaicPeerInfo:
    SIGNING_KEY: str
    PEER_ID: str


def read_mosaic_keys(operator_idx: int) -> MosaicPeerInfo:
    """
    Get mosaic peer signing key and peer_id from artifacts/mosaic.json

    Args:
        operator_idx: Index of the operator (0-based)

    Returns:
        MosaicPeerInfo containing peer signing key and peer_id
    """

    with open(MOSAIC_KEYS_PATH) as f:
        mosaic_keys = json.load(f)

    return MosaicPeerInfo(**mosaic_keys[operator_idx])


@dataclass
class PeerConfig:
    port: int
    signing_key: str
    peer_id: str


def get_peer_configs(num_operators: int) -> dict[int, PeerConfig]:
    peers = {}
    for idx in range(num_operators):
        peer_info = read_mosaic_keys(idx)
        peers[idx] = PeerConfig(
            port=MOSAIC_PORT_BASE + idx,
            signing_key=peer_info.SIGNING_KEY,
            peer_id=peer_info.PEER_ID,
        )
    return peers


def get_peer_ids(num_operators: int) -> list[str]:
    with open(MOSAIC_KEYS_PATH) as f:
        mosaic_keys = json.load(f)

    return [entry["PEER_ID"] for entry in mosaic_keys[:num_operators]]


def get_circuit_path() -> str:
    # Full-circuit mode: run_test.sh generates the real g16 circuit for this run and
    # exports its location before entry.py starts (see g16-setup.bash). The existence
    # check turns a broken export into a loud failure at env-init time instead of a
    # mosaic crash on a missing file.
    override = os.environ.get("MOSAIC_CIRCUIT_PATH")
    if override:
        path = Path(override).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"MOSAIC_CIRCUIT_PATH is set but missing: {path}")
        return str(path)

    # Full mode must fail loudly here rather than silently fall back to the
    # reduced circuit and fake the coverage the full run exists to provide.
    if os.environ.get("MOSAIC_CIRCUIT_MODE") == "full":
        raise RuntimeError(
            "MOSAIC_CIRCUIT_MODE=full but MOSAIC_CIRCUIT_PATH is unset; "
            "run via run_test.sh so g16-setup.bash generates and exports the circuit"
        )

    # Same circuit as mosaic's artifact; regenerate from g16 (branch
    # test/simple_circuit_postaudit_smallest) and re-copy from mosaic on any ckt bump.
    abs_path = (Path(__file__).parent.parent / "artifacts" / "mosaic_depositidx_ckt.v5c").resolve()
    return str(abs_path)
