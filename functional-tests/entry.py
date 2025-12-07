import sys
import os
import flexitest
import time
from utils import TEST_DIR
from factory.bitcoin import BitcoinFactory
from factory.s2 import S2Factory
from factory.bridge_operator import BridgeOperatorFactory
from envs import BasicEnv


def main(argv):
    print("Sid got here")
    root_dir = os.path.dirname(os.path.abspath(__file__))
    test_dir = os.path.join(root_dir, TEST_DIR)

    # Create datadir.
    datadir_root = flexitest.create_datadir_in_workspace(os.path.join(root_dir, "_dd"))

    # Probe tests.
    modules = flexitest.runtime.scan_dir_for_modules(test_dir)
    tests = flexitest.runtime.load_candidate_modules(modules)

    bfac = BitcoinFactory([12300 + i for i in range(100)])
    s2fac = S2Factory([12400 + i for i in range(100)])
    bofac = BridgeOperatorFactory([12500 + i for i in range(100)])
    factories = {"bitcoin": bfac, "s2": s2fac, "bofac":bofac}

    basic_env = BasicEnv()
    env_configs = {"basic": basic_env}

    # Set up the runtime and prepare tests.
    rt = flexitest.TestRuntime(env_configs, datadir_root, factories)
    rt.prepare_registered_tests()

    # Run the tests and then dump the results.
    arg_test_names = argv[1:]
    if len(arg_test_names) > 0:
        tests = arg_test_names

    results = rt.run_tests(tests)
    rt.save_json_file("results.json", results)
    flexitest.dump_results(results)
    flexitest.fail_on_error(results)
    return 0


if __name__ == "__main__":
    main(sys.argv)
