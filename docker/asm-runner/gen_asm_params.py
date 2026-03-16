#!/usr/bin/env python3

import argparse
import base64
import json
import time
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

from asm_params import build_asm_params, write_asm_params_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--bridge-params", required=True)
    parser.add_argument("--output", required=True)
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


def main() -> None:
    args = parse_args()

    config = tomllib.loads(Path(args.config).read_text())
    bridge_params = tomllib.loads(Path(args.bridge_params).read_text())

    wait_for_bitcoind(config["bitcoin"], args.timeout_secs)
    protocol = bridge_params["protocol"]
    genesis_height = int(bridge_params["genesis_height"])
    wait_for_genesis_height(config["bitcoin"], genesis_height, args.timeout_secs)
    musig2_keys = [entry["musig2"] for entry in bridge_params["keys"]["covenant"]]
    block_hash, header = fetch_chain_context(config["bitcoin"], genesis_height)
    asm_params = build_asm_params(
        musig2_keys=musig2_keys,
        genesis_height=genesis_height,
        block_hash=block_hash,
        header=header,
        magic=protocol["magic_bytes"].upper(),
        denomination=protocol["deposit_amount"],
        recovery_delay=protocol["recovery_delay"],
    )

    write_asm_params_json(args.output, asm_params)


if __name__ == "__main__":
    main()
