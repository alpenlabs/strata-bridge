import json
import logging
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
    env_path = os.environ.get("MOSAIC_CIRCUIT_PATH")
    if env_path:
        if not os.path.isabs(env_path):
            raise ValueError(f"MOSAIC_CIRCUIT_PATH must be an absolute path, got: {env_path}")
        logging.info(f"mosaic circuit path (from MOSAIC_CIRCUIT_PATH): {env_path}")
        return env_path

    abs_path = (Path(__file__).parent.parent / "artifacts" / "mosaic_depositidx_ckt.v5c").resolve()
    logging.info(f"mosaic circuit path (default): {abs_path}")
    return str(abs_path)
