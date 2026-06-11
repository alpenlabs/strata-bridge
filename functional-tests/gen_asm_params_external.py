"""Generate asm-params.json + asm/moho VKs from an external regtest L1, run by
run_test.sh before the guest ELF build so the ELF bakes a matching genesis anchor."""

import logging
import os
import sys
from pathlib import Path

from bitcoinlib.services.bitcoind import BitcoindClient

from envs.asm_config import AsmEnvConfig
from envs.btc_config import BitcoinEnvConfig
from factory.bitcoin import _read_external_btc_env
from factory.bridge_operator.asm_cfg import write_asm_params
from utils.bitcoin import prepare_wallet_and_chain
from utils.logging import setup_root_logger
from utils.sp1_pre_setup import pre_fund_operators
from utils.utils import read_all_operator_keys, read_operator_key, wait_until_bitcoind_ready


def main() -> int:
    setup_root_logger()

    out_dir = os.environ["BRIDGE_PROOF_ASM_PARAMS_DIR"]
    # Must match the consuming test's operator count so the operator key set baked
    # into asm-params lines up with the operator nodes the test actually launches.
    num_operators = int(os.environ["BRIDGE_PROOF_NUM_OPERATORS"])

    props, client_url = _read_external_btc_env()
    rpc = BitcoindClient(base_url=client_url, network="regtest")
    wait_until_bitcoind_ready(rpc, timeout=30)

    btc_config = BitcoinEnvConfig()
    miner_addr = prepare_wallet_and_chain(rpc, props["walletname"], btc_config.initial_blocks)

    # Fund the bridge operator wallets.
    pre_fund_operators(rpc, miner_addr, read_all_operator_keys(), btc_config)
    genesis_height = rpc.proxy.getblockcount()

    operator_key_infos = [read_operator_key(i) for i in range(num_operators)]
    # Sp1Groth16 predicates when BRIDGE_PROOF_SP1_ASM=1, else Bip340Schnorr defaults.
    asm_vk = os.environ.get("BRIDGE_PROOF_SP1_ASM_PREDICATE")
    moho_vk = os.environ.get("BRIDGE_PROOF_SP1_MOHO_PREDICATE")
    params_path, asm_vk_path, moho_vk_path = write_asm_params(
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
