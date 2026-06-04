#!/usr/bin/env python3
"""Fill a partial asm-params.json with live L1 anchor data.

Standalone, offline util: given a bitcoin RPC endpoint and a partial
asm-params.json (whose ``anchor`` carries the target ``height``/``network`` but
placeholder chain data), it fetches the on-chain context and writes out the
actual params. Run this once before bringing up the asm-runner container, which
then consumes the result verbatim with no post-processing of its own.

Fails fast: any RPC error, or a chain that hasn't reached the genesis height,
surfaces immediately rather than waiting.
"""

import argparse
import base64
import json
import urllib.request
from pathlib import Path

# Bitcoin's difficulty adjustment interval, in blocks. Identical across all networks
# (mainnet, testnet, signet, regtest) per Bitcoin Core's consensus params.
DIFFICULTY_ADJUSTMENT_INTERVAL = 2016


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc-url", required=True)
    parser.add_argument("--rpc-user", required=True)
    parser.add_argument("--rpc-password", required=True)
    parser.add_argument("--params", required=True, help="partial asm-params.json to read")
    parser.add_argument(
        "--output",
        help="where to write the filled params (default: overwrite --params)",
    )
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


def fetch_block_header(bitcoin_cfg: dict, height: int) -> dict:
    block_hash = rpc_call(
        bitcoin_cfg["rpc_url"],
        bitcoin_cfg["rpc_user"],
        bitcoin_cfg["rpc_password"],
        "getblockhash",
        [height],
    )
    return rpc_call(
        bitcoin_cfg["rpc_url"],
        bitcoin_cfg["rpc_user"],
        bitcoin_cfg["rpc_password"],
        "getblockheader",
        [block_hash],
    )


def build_l1_anchor(genesis_height: int, network: str, bitcoin_cfg: dict) -> dict:
    """Builds the L1 anchor dict for the ASM params from on-chain context at ``genesis_height``.

    Records ``genesis_height``'s hash and ``bits`` on the anchor, plus the timestamp of the
    block at the start of the containing difficulty epoch — matching how the ASM recomputes
    the next difficulty target.
    """
    epoch_start_height = (
        genesis_height // DIFFICULTY_ADJUSTMENT_INTERVAL
    ) * DIFFICULTY_ADJUSTMENT_INTERVAL
    epoch_start_header = fetch_block_header(bitcoin_cfg, epoch_start_height)
    genesis_header = fetch_block_header(bitcoin_cfg, genesis_height)

    return {
        "block": {"height": genesis_height, "blkid": genesis_header["hash"]},
        "next_target": int(genesis_header["bits"], 16),
        "epoch_start_timestamp": int(epoch_start_header["time"]),
        "network": network,
    }


def main() -> None:
    args = parse_args()

    bitcoin_cfg = {
        "rpc_url": args.rpc_url,
        "rpc_user": args.rpc_user,
        "rpc_password": args.rpc_password,
    }

    params_path = Path(args.params)
    output_path = Path(args.output) if args.output else params_path

    params = json.loads(params_path.read_text())

    genesis_height = params["anchor"]["block"]["height"]
    network = params["anchor"]["network"]

    print(f"Filling ASM anchor from chain context at height {genesis_height} ({network})")
    params["anchor"] = build_l1_anchor(genesis_height, network, bitcoin_cfg)

    print(f"Writing filled ASM params to {output_path}")
    output_path.write_text(json.dumps(params, indent=4) + "\n")


if __name__ == "__main__":
    main()
