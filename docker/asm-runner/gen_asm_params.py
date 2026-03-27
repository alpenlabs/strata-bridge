#!/usr/bin/env python3

import argparse
import base64
import json
import time
import tomllib
import urllib.error
import urllib.request
from dataclasses import asdict
from pathlib import Path
import logging

from asm_params import build_genesis_l1_view


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--params", required=True)
    parser.add_argument("--bridge-params", required=True)
    parser.add_argument("--timeout-secs", type=int, default=60)
    return parser.parse_args()


def rpc_call(rpc_url: str, rpc_user: str, rpc_password: str, method: str, params: list):
    payload = json.dumps(
        {"jsonrpc": "1.0", "id": "asm-runner", "method": method, "params": params}
    ).encode()
    request = urllib.request.Request(
        rpc_url,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    auth = base64.b64encode(f"{rpc_user}:{rpc_password}".encode()).decode()
    request.add_header("Authorization", f"Basic {auth}")

    with urllib.request.urlopen(request, timeout=5) as response:
        body = json.loads(response.read().decode())

    if body.get("error") is not None:
        raise RuntimeError(body["error"])

    return body["result"]


def wait_for_bitcoind(bitcoin_cfg: dict, timeout_secs: int) -> None:
    deadline = time.time() + timeout_secs

    while time.time() < deadline:
        try:
            rpc_call(
                bitcoin_cfg["rpc_url"],
                bitcoin_cfg["rpc_user"],
                bitcoin_cfg["rpc_password"],
                "getblockcount",
                [],
            )
            return
        except (OSError, urllib.error.URLError, RuntimeError):
            time.sleep(1)

    raise RuntimeError("bitcoind did not become ready in time")


def wait_for_genesis_height(
    bitcoin_cfg: dict, genesis_height: int, timeout_secs: int
) -> None:
    deadline = time.time() + timeout_secs

    while time.time() < deadline:
        try:
            block_count = rpc_call(
                bitcoin_cfg["rpc_url"],
                bitcoin_cfg["rpc_user"],
                bitcoin_cfg["rpc_password"],
                "getblockcount",
                [],
            )
            if int(block_count) >= genesis_height:
                return
        except (OSError, urllib.error.URLError, urllib.error.HTTPError, RuntimeError):
            pass

        time.sleep(1)

    raise RuntimeError(
        f"bitcoind did not reach genesis height {genesis_height} in time"
    )


def fetch_chain_context(bitcoin_cfg: dict, genesis_height: int) -> tuple[str, dict]:
    block_hash = rpc_call(
        bitcoin_cfg["rpc_url"],
        bitcoin_cfg["rpc_user"],
        bitcoin_cfg["rpc_password"],
        "getblockhash",
        [genesis_height],
    )
    header = rpc_call(
        bitcoin_cfg["rpc_url"],
        bitcoin_cfg["rpc_user"],
        bitcoin_cfg["rpc_password"],
        "getblockheader",
        [block_hash],
    )

    return block_hash, header


def validate_params(asm_params: dict, bridge_params: dict) -> None:
    """
    Makes sure that the ASM params and the Bridge params are consistent with each other, to avoid
    subtle misconfigurations that could cause the ASM to fail to start or operate correctly.
    """
    bridge = bridge_params["protocol"]

    asm = None
    for subprotocol in asm_params["subprotocols"]:
        if "Bridge" in subprotocol:
            asm = subprotocol["Bridge"]
            break

    if asm is None:
        raise RuntimeError("params missing Bridge subprotocol")

    musig2_keys = [f"02{e['musig2']}" for e in bridge_params["keys"]["covenant"]]

    checks = [
        ("magic", asm_params["magic"], bridge["magic_bytes"]),
        (
            "genesis_height",
            # TODO: <https://atlassian.alpenlabs.net/browse/STR-2572>
            # set these to be equal after the above bug is fixed
            # for now, just check that the ASM genesis height is 1 less than the Bridge genesis height
            asm_params["l1_view"]["blk"]["height"] - 1,  # must start sooner
            bridge_params["genesis_height"],
        ),
        ("denomination", asm["denomination"], bridge["deposit_amount"]),
        ("operator_fee", asm["operator_fee"], bridge["operator_fee"]),
        ("recovery_delay", asm["recovery_delay"], bridge["recovery_delay"]),
        ("operators", asm["operators"], musig2_keys),
    ]

    mismatches = [
        f"{name}: asm={asm_val}, bridge={bridge_val}"
        for name, asm_val, bridge_val in checks
        if asm_val != bridge_val
    ]

    if mismatches:
        raise RuntimeError(
            "asm and bridge params are misaligned:\n  " + "\n  ".join(mismatches)
        )


def main() -> None:
    args = parse_args()

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    logging.info("Starting ASM params generation")

    config = tomllib.loads(Path(args.config).read_text())
    params_path = Path(args.params)
    params = json.loads(params_path.read_text())
    bridge_params = tomllib.loads(Path(args.bridge_params).read_text())

    logging.info("Validating ASM params against Bridge params")
    validate_params(params, bridge_params)

    genesis_height = params["l1_view"]["blk"]["height"]

    logging.info("Waiting for bitcoind to be ready")
    wait_for_bitcoind(config["bitcoin"], args.timeout_secs)

    logging.info(f"Waiting for bitcoind to reach genesis height {genesis_height}")
    wait_for_genesis_height(config["bitcoin"], genesis_height, args.timeout_secs)

    logging.info("Fetching chain context for genesis height")
    block_hash, header = fetch_chain_context(config["bitcoin"], genesis_height)

    logging.info("Updating ASM params with chain context")
    params["l1_view"] = asdict(
        build_genesis_l1_view(genesis_height, block_hash, header)
    )

    logging.info(f"Writing updated ASM params to {params_path}")
    params_path.write_text(json.dumps(params, indent=4) + "\n")


if __name__ == "__main__":
    main()
