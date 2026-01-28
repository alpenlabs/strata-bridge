import logging
import os
import shutil
import subprocess
import sys

import flexitest

from constants import BRIDGE_NETWORK_SIZE, TEST_DIR
from envs import BasicEnv, BridgeNetworkEnv
from envs.testenv import StrataTestRuntime
from factory.asm_rpc import AsmRpcFactory
from factory.bitcoin import BitcoinFactory
from factory.bridge_operator import BridgeOperatorFactory
from factory.fdb import FdbFactory
from factory.s2 import S2Factory
from utils.logging import setup_root_logger


def main(argv):
    setup_root_logger()
    root_dir = os.path.dirname(os.path.abspath(__file__))
    test_dir = os.path.join(root_dir, TEST_DIR)

    # HACK (@MdTeach): Strata bridge DB initialization assumes migrations
    # exist in the current working directory (env::current_dir()).
    migrate_migrations(root_dir)

    # Create datadir.
    datadir_root = flexitest.create_datadir_in_workspace(os.path.join(root_dir, "_dd"))

    # gen mtls info
    gen_s2_tls_script_path = os.path.abspath(
        os.path.join(root_dir, "..", "docker", "gen_s2_tls.sh")
    )

    # generate mtls cred
    for operator_idx in range(BRIDGE_NETWORK_SIZE):
        generate_mtls_credentials(gen_s2_tls_script_path, datadir_root, operator_idx)

    # Probe tests.
    modules = flexitest.runtime.scan_dir_for_modules(test_dir)
    tests = flexitest.runtime.load_candidate_modules(modules)

    # Register factory
    bfac = BitcoinFactory([12300 + i for i in range(100)])
    s2fac = S2Factory([12400 + i for i in range(100)])
    bofac = BridgeOperatorFactory([12500 + i for i in range(100)])
    asmfac = AsmRpcFactory([12600 + i for i in range(100)])
    fdbfac = FdbFactory([12700 + i for i in range(100)])
    factories = {"bitcoin": bfac, "s2": s2fac, "bofac": bofac, "asm_rpc": asmfac, "fdb": fdbfac}

    # Register envs
    basic_env = BasicEnv()
    network_env = BridgeNetworkEnv()
    env_configs = {"basic": basic_env, "network": network_env}

    # Set up the runtime and prepare tests.
    rt = StrataTestRuntime(env_configs, datadir_root, factories)
    rt.prepare_registered_tests()

    # Run the tests and then dump the results.
    arg_test_names = argv[1:]
    if len(arg_test_names) > 0:
        tests = [extract_test_name(arg) for arg in arg_test_names]
    results = rt.run_tests(tests)
    rt.save_json_file("results.json", results)
    flexitest.dump_results(results)
    flexitest.fail_on_error(results)
    return 0


def extract_test_name(test_path):
    """Extract test module name from file path, removing extension."""
    return os.path.splitext(os.path.basename(test_path))[0]


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
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def migrate_migrations(root_dir: str) -> None:
    """
    Copy the `migrations` from workspace dir to functional test dir
    """
    # Source: one directory above root_dir
    src = os.path.abspath(os.path.join(root_dir, "..", "migrations"))
    # Destination: inside root_dir
    dst = os.path.abspath(os.path.join(root_dir, "migrations"))

    if not os.path.isdir(src):
        raise ValueError(f"Source migrations folder does not exist: {src}")

    # If dst is a file or a symlink, remove it first
    if os.path.isfile(dst) or os.path.islink(dst):
        os.remove(dst)

    # Recursively copy, allowing dst to exist and overwriting files
    shutil.copytree(src, dst, dirs_exist_ok=True)


if __name__ == "__main__":
    main(sys.argv)
