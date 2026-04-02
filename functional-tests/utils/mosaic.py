import json
from dataclasses import dataclass
from pathlib import Path

# ensure no colllsion
MOSAIC_PORT_BASE = 12900


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

    keys_path = Path(__file__).parent.parent / "artifacts" / "mosaic.json"
    with open(keys_path) as f:
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


def get_circuit_path() -> str:
    abs_path = (Path(__file__).parent.parent / "artifacts" / "mosaic_depositidx_ckt.v5c").resolve()
    return str(abs_path)
