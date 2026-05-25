import argparse
import logging
import os
import subprocess
import sys

import flexitest

from constants import BRIDGE_NETWORK_SIZE, TEST_DIR
from envs import AsmEnv, BitcoinEnvConfig, BridgeNetworkEnv, ExternalBtcBridgeNetworkEnv
from envs.testenv import StrataTestRuntime
from factory.asm_rpc import AsmRpcFactory
from factory.bitcoin import BitcoinFactory
from factory.bridge_operator import BridgeOperatorFactory
from factory.fdb import FdbFactory
from factory.mosaic import MosaicFactory
from factory.s2 import S2Factory
from utils.logging import setup_root_logger

# Groups in here don't run when you just call `./run_test.sh` with no
# arguments. They're the slow / expensive ones that we never want sweeping up the default
# regression run. They still run when you ask for them — either by
# file (`-t tests/proofs/fn_bridge_proof.py`) or by group (`-g proofs`).
SKIP_GROUPS_BY_DEFAULT = frozenset({"proofs"})

parser = argparse.ArgumentParser(prog="entry.py")
parser.add_argument("-g", "--groups", nargs="*", help="Test groups (subdirectory names) to run")
parser.add_argument("-t", "--tests", nargs="*", help="Specific test files to run")


def groups_for_test(path: str) -> frozenset[str]:
    """Return the group names (subdirectories under `tests/`) on this test's path."""
    path_parts = os.path.normpath(path).split(os.sep)
    idx = next((i for i, part in enumerate(path_parts) if part == TEST_DIR), None)
    return frozenset(path_parts[idx + 1 : -1]) if idx is not None else frozenset()


def filter_tests(parsed_args, modules):
    """Pick which discovered test modules actually run."""
    arg_groups = frozenset(parsed_args.groups or [])
    arg_tests = frozenset(
        os.path.splitext(os.path.basename(t))[0] for t in (parsed_args.tests or [])
    )

    if not arg_groups and not arg_tests:
        return {
            test: path
            for test, path in modules.items()
            if not (groups_for_test(path) & SKIP_GROUPS_BY_DEFAULT)
        }

    filtered = {}
    for test, path in modules.items():
        test_groups = groups_for_test(path)

        take = False
        if arg_groups and (arg_groups & test_groups):
            take = True
        if arg_tests and test in arg_tests:
            take = True

        if take:
            filtered[test] = path

    return filtered


def main(argv):
    parsed_args = parser.parse_args(argv[1:])

    setup_root_logger()
    root_dir = os.path.dirname(os.path.abspath(__file__))
    test_dir = os.path.join(root_dir, TEST_DIR)

    # Create datadir.
    datadir_root = flexitest.create_datadir_in_workspace(os.path.join(root_dir, "_dd"))

    # gen mtls info
    gen_s2_tls_script_path = os.path.abspath(
        os.path.join(root_dir, "..", "docker", "gen_s2_tls.sh")
    )

    # generate mtls cred
    for operator_idx in range(BRIDGE_NETWORK_SIZE):
        generate_mtls_credentials(gen_s2_tls_script_path, datadir_root, operator_idx)

    # Probe and filter tests.
    modules = flexitest.runtime.scan_dir_for_modules(test_dir)
    modules = filter_tests(parsed_args, modules)
    if parsed_args.groups or parsed_args.tests:
        logging.info("Filtered tests: %s", list(modules.keys()))
    tests = flexitest.runtime.load_candidate_modules(modules)

    # Register factory
    bfac = BitcoinFactory([12300 + i for i in range(100)])
    s2fac = S2Factory([12400 + i for i in range(100)])
    bofac = BridgeOperatorFactory([12500 + i for i in range(100)])
    asmfac = AsmRpcFactory([12600 + i for i in range(100)])
    fdbfac = FdbFactory([12700 + i for i in range(100)])
    # 12800 range is used by bridge operator p2p
    mosaicfac = MosaicFactory([12900 + i for i in range(100)])
    factories = {
        "bitcoin": bfac,
        "s2": s2fac,
        "bofac": bofac,
        "asm_rpc": asmfac,
        "fdb": fdbfac,
        "mosaic": mosaicfac,
    }

    # Register envs
    asm_env = AsmEnv()
    network_env = BridgeNetworkEnv()
    external_btc_network_env = ExternalBtcBridgeNetworkEnv(
        btc_config=BitcoinEnvConfig(
            mine_on_demand=True,
            mine_on_demand_trailing_blocks=2,
        ),
    )
    env_configs = {
        "asm": asm_env,
        "network": network_env,
        "network-extbtc": external_btc_network_env,
    }

    # Set up the runtime and prepare tests.
    rt = StrataTestRuntime(env_configs, datadir_root, factories)
    rt.prepare_registered_tests()

    # Run the tests and then dump the results.
    results = rt.run_tests(tests)
    rt.save_json_file("results.json", results)
    flexitest.dump_results(results)
    flexitest.fail_on_error(results)
    return 0


def generate_mtls_credentials(gen_script_path: str, datadir_root: str, operator_index: int) -> None:
    """
    Generate credentials for an operator using the gen_s2_tls.sh script.

    Args:
        gen_script_path: Path to the gen_s2_tls.sh script
        datadir_root: Root directory for data files
        operator_index: Operator index to generate credentials for
    """
    logging.info(f"Generating MTLS credentials for operator {operator_index}")
    operator_dir = os.path.join(datadir_root, f"mtls_cred/operator_{operator_index}")
    bridge_node_path = os.path.abspath(os.path.join(operator_dir, "bridge_node"))
    secret_service_path = os.path.abspath(os.path.join(operator_dir, "secret_service"))
    cmd = ["bash", gen_script_path, bridge_node_path, secret_service_path, "127.0.0.1"]
    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        logging.error(
            "Failed to generate MTLS credentials for operator %s with command: %s",
            operator_index,
            " ".join(cmd),
        )
        logging.error("gen_s2_tls.sh stdout:\n%s", result.stdout)
        logging.error("gen_s2_tls.sh stderr:\n%s", result.stderr)
        raise subprocess.CalledProcessError(result.returncode, cmd, result.stdout, result.stderr)


if __name__ == "__main__":
    main(sys.argv)
