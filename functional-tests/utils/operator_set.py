import logging
import time
from dataclasses import asdict
from pathlib import Path

import toml

from factory.bridge_operator.params_cfg import ScheduledOperator
from utils.utils import read_operator_key, snapshot_log_offsets, wait_until_bridge_ready


def scheduled_operator(
    operator_idx: int, activation_height: int, deactivation_height: int | None = None
) -> ScheduledOperator:
    """Return the params registration of fixture operator `operator_idx`."""
    key = read_operator_key(operator_idx)
    return ScheduledOperator(
        index=operator_idx,
        covenant_key=key.MUSIG2_KEY,
        p2p_key=key.P2P_KEY,
        payout_descriptor=key.GENERAL_WALLET_DESCRIPTOR,
        activation_height=activation_height,
        deactivation_height=deactivation_height,
    )


def write_operator_schedule(
    node,
    nodes: dict,
    registrations: list[ScheduledOperator],
    deposit_index_offset: int | None = None,
) -> None:
    """Rewrite `node`'s params registrations and its p2p and Mosaic peers to match them.

    A node rejects a configured peer whose operator is not registered and needs a Mosaic peer
    for every registered operator, so both files change together. `nodes` maps every
    registered operator index to its bridge node.
    """
    node_dir = Path(node.props["config_path"]).parent
    own_idx = node.props["operator_idx"]

    params_path = node_dir / "params.toml"
    params = toml.load(params_path)
    params["keys"]["operators"] = [
        {field: value for field, value in asdict(registration).items() if value is not None}
        for registration in registrations
    ]
    if deposit_index_offset is not None:
        params["protocol"]["deposit_index_offset"] = deposit_index_offset
    params_path.write_text(toml.dumps(params))

    # Listed in descending index order, like the generated config, so peer resolution never
    # depends on entry order.
    descending = sorted(registrations, key=lambda registration: -registration.index)
    config_path = node_dir / "config.toml"
    config = toml.load(config_path)
    config["p2p"]["peers"] = [
        {"operator_idx": r.index, "addrs": [nodes[r.index].props["p2p_addr"]]}
        for r in descending
        if r.index != own_idx
    ]
    config["mosaic"]["peers"] = [
        {"operator_idx": r.index, "peer_id": nodes[r.index].props["mosaic_peer_id"]}
        for r in descending
    ]
    config_path.write_text(toml.dumps(config))

    logging.info(f"Wrote operator schedule for operator {own_idx}: {registrations}")


def restart_with_operator_schedule(
    nodes: dict,
    registrations: list[ScheduledOperator],
    deposit_index_offset: int | None = None,
) -> dict[str, int]:
    """Restart the network on a new operator schedule, as a coordinated restart does.

    Every running node stops before any node is rewritten, then every registered operator's
    node starts on the new schedule, so no node runs on the old schedule alongside the new one.
    Returns log offsets of the registered nodes taken just before they start.
    """
    for node in nodes.values():
        if node.is_started():
            node.stop()
    time.sleep(5)  # ports need to be released before restarting

    registered = [nodes[registration.index] for registration in registrations]
    for node in registered:
        write_operator_schedule(node, nodes, registrations, deposit_index_offset)

    offsets = snapshot_log_offsets([node.props["logfile"] for node in registered])
    # Started in index order, which the generated heartbeat delays assume.
    for node in sorted(registered, key=lambda node: node.props["operator_idx"]):
        node.start()
    for node in registered:
        wait_until_bridge_ready(node.create_rpc())

    return offsets
