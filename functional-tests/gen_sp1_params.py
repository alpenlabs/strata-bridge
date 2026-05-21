"""Generate asm-params.json (+ asm-vk.json / moho-vk.json) from an external regtest L1.

Run by run_test.sh in SP1 proving mode (BRIDGE_PROOF_SP1=1 + BRIDGE_EXTERNAL_BITCOIN=1)
*before* the guest ELF build, so the ELF bakes a genesis anchor that matches the actual
chain the test runs against. The same files are reused at runtime by the test
(see base_env._ensure_rollup_params), keeping ELF-baked params == runtime params.

Connection details come from the external-bitcoin env vars; output goes to
BRIDGE_PROOF_SP1_PARAMS_DIR; operator count from BRIDGE_PROOF_SP1_NUM_OPERATORS.
"""

import logging
import os
import sys
from pathlib import Path

from bitcoinlib.services.bitcoind import BitcoindClient

from envs.asm_config import AsmEnvConfig
from envs.btc_config import BitcoinEnvConfig
from factory.bitcoin import _read_external_btc_env
from factory.bridge_operator.asm_cfg import write_rollup_params
from utils.logging import setup_root_logger
from utils.utils import read_operator_key, wait_until_bitcoind_ready


def _ensure_chain(rpc: BitcoindClient, walletname: str, genesis_height: int) -> None:
    """Ensure the wallet exists and the chain has at least `genesis_height` blocks."""
    if walletname not in rpc.proxy.listwallets():
        try:
            rpc.proxy.loadwallet(walletname)
        except Exception:
            rpc.proxy.createwallet(walletname)

    shortfall = genesis_height - rpc.proxy.getblockcount()
    if shortfall > 0:
        addr = rpc.proxy.getnewaddress()
        rpc.proxy.generatetoaddress(shortfall, addr)


def main() -> int:
    setup_root_logger()

    out_dir = os.environ.get("BRIDGE_PROOF_SP1_PARAMS_DIR")
    if not out_dir:
        raise RuntimeError("BRIDGE_PROOF_SP1_PARAMS_DIR must be set")
    num_operators = int(os.environ.get("BRIDGE_PROOF_SP1_NUM_OPERATORS", "2"))

    props, client_url = _read_external_btc_env()
    rpc = BitcoindClient(base_url=client_url, network="regtest")
    wait_until_bitcoind_ready(rpc, timeout=30)

    genesis_height = BitcoinEnvConfig().initial_blocks
    _ensure_chain(rpc, props["walletname"], genesis_height)

    operator_key_infos = [read_operator_key(i) for i in range(num_operators)]
    # When the asm-runner runs the SP1 backend (BRIDGE_PROOF_SP1_ASM), run_test.sh
    # derives the Sp1Groth16 predicates of the asm/moho ELFs and passes them here so the
    # bridge proof verifies real Groth16 proofs. Absent -> Bip340Schnorr (native) defaults.
    asm_vk = os.environ.get("BRIDGE_PROOF_SP1_ASM_PREDICATE")
    moho_vk = os.environ.get("BRIDGE_PROOF_SP1_MOHO_PREDICATE")
    params_path, asm_vk_path, moho_vk_path = write_rollup_params(
        rpc,
        operator_key_infos,
        genesis_height,
        AsmEnvConfig(assignment_duration=144),
        Path(out_dir),
        asm_vk=asm_vk,
        moho_vk=moho_vk,
    )

    logging.info(
        "Generated SP1 params from external L1 (genesis height %d, %d operators):\n"
        "  %s\n  %s\n  %s",
        genesis_height,
        num_operators,
        params_path,
        asm_vk_path,
        moho_vk_path,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
