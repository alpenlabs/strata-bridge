import os
import subprocess
import tempfile

from constants import ASM_MAGIC_BYTES
from rpc.asm_types import CheckpointTip

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

tag = "{tag}"

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

        params_content = DEV_CLI_PARAMS_TEMPLATE.format(tag=ASM_MAGIC_BYTES, musig2_keys=keys_str)

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

    def send_deposit_request(self) -> str:
        rpc_port = self.bitcoind_props["rpc_port"]  # fail fast if missing
        wallet = self.bitcoind_props.get("walletname", "testwallet")

        args = [
            "bridge-in",
            "--btc-url",
            f"http://127.0.0.1:{rpc_port}/wallet/{wallet}",
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
        # HACK: (@Rajil1213) parse raw stdout to extract txid
        txid = res.splitlines()[-1].split("=")[-1].strip()
        return txid

    def send_mock_checkpoint(
        self,
        checkpoint_tip: CheckpointTip | None,
        num_ol_slots: int,
        num_withdrawals: int = 1,
        genesis_l1_height: int = 101,
    ) -> str:
        ol_start_slot = checkpoint_tip.l2_commitment.slot if checkpoint_tip else 0
        ol_end_slot = ol_start_slot + num_ol_slots
        epoch = (checkpoint_tip.epoch + 1) if checkpoint_tip else 1

        rpc_port = self.bitcoind_props["rpc_port"]  # fail fast if missing
        wallet = self.bitcoind_props.get("walletname", "testwallet")

        args = [
            "create-and-publish-mock-checkpoint",
            "--btc-url",
            f"http://127.0.0.1:{rpc_port}/wallet/{wallet}",
            "--btc-user",
            self.bitcoind_props.get("rpc_user", "user"),
            "--btc-pass",
            self.bitcoind_props.get("rpc_password", "password"),
            "--num-withdrawals",
            str(num_withdrawals),
            "--genesis-l1-height",
            str(genesis_l1_height),
            "--ol-start-slot",
            str(ol_start_slot),
            "--ol-end-slot",
            str(ol_end_slot),
            "--epoch",
            str(epoch),
        ]

        res = self._run_command(args)
        # HACK: (@Rajil1213) parse raw stdout to extract txid
        txid = res.splitlines()[-1].split("=")[-1].strip()
        return txid

    def send_mock_checkpoint_from_tip(
        self, asm_rpc, block_hash: str, num_ol_slots: int, num_withdrawals=1
    ) -> str:
        """Query the current checkpoint tip and send a mock checkpoint advancing by num_ol_slots.

        If no checkpoint tip exists (first checkpoint case), defaults are used (epoch=1, slot=0).
        """
        raw_tip = asm_rpc.strata_asm_getCheckpointTip(block_hash)
        tip = CheckpointTip.from_dict(raw_tip) if raw_tip is not None else None
        return self.send_mock_checkpoint(
            checkpoint_tip=tip, num_ol_slots=num_ol_slots, num_withdrawals=num_withdrawals
        )
