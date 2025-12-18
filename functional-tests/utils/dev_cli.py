import os
import subprocess
import tempfile

BINARY_PATH = "dev-cli"
EE_ADDRESS = "70997970C51812dc3A010C7d01b50e0d17dc79C8"

DEV_CLI_PARAMS_TEMPLATE = """network = "regtest"
bridge_out_addr = "0x5400000000000000000000000000000000000001"
deposit_amount = 1_000_000_000                                 # 10 BTC
stake_amount = 100_000_000                                     # 1 BTC
burn_amount = 10_000_000                                       # 0.1 BTC
refund_delay = 1_008
stake_chain_delta = {{ Blocks = 6 }}
payout_timelock = 1_008

tag = "alpn"

musig2_keys = {musig2_keys}
"""


class DevCli:
    def __init__(self, bitcoind_props: dict, musig2_keys: list[str]):
        self.bitcoind_props = bitcoind_props
        self.musig2_keys = musig2_keys
        self.temp_dir = tempfile.mkdtemp()
        self.params_path = self._create_params_file()

    def _create_params_file(self) -> str:
        keys_str = "[\n"
        for key in self.musig2_keys:
            keys_str += f'  "{key}",\n'
        keys_str += "]"

        params_content = DEV_CLI_PARAMS_TEMPLATE.format(musig2_keys=keys_str)

        params_path = os.path.join(self.temp_dir, "params.toml")
        with open(params_path, "w") as f:
            f.write(params_content)

        return params_path

    def _run_command(self, args: list[str]) -> str:
        cmd = [BINARY_PATH] + args
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            error_msg = f"Command failed with exit code {e.returncode}:\n"
            error_msg += f"Command: {' '.join(cmd)}\n"
            if e.stdout:
                error_msg += f"Stdout: {e.stdout}\n"
            if e.stderr:
                error_msg += f"Stderr: {e.stderr}\n"
            raise RuntimeError(error_msg) from e

    def send_deposit_request(self):
        rpc_port = self.bitcoind_props["rpc_port"]  # fail fast if missing
        wallet = self.bitcoind_props.get("walletname", "testwallet")

        args = [
            "bridge-in",
            "--btc-url",
            f"http://127.0.0.1:{rpc_port}/wallet/{wallet}",  # <-- add /wallet/<name>
            "--btc-user",
            self.bitcoind_props.get("rpc_user", "user"),
            "--btc-pass",
            self.bitcoind_props.get("rpc_password", "password"),
            "--params",
            self.params_path,
            "--ee-address",
            EE_ADDRESS,
        ]

        res = self._run_command(args)
        return res
