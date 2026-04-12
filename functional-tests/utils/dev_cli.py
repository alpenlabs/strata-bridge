import os
import subprocess
import tempfile
from dataclasses import asdict

import toml

from factory.bridge_operator.params_cfg import (
    BridgeOperatorParams,
    BridgeProtocolParams,
    CovenantKeys,
    Keys,
)
from rpc.asm_types import CheckpointTip
from utils.utils import OperatorKeyInfo

BINARY_PATH = "dev-cli"
EE_ADDRESS = "70997970C51812dc3A010C7d01b50e0d17dc79C8"

# Default genesis height used by dev-cli params when not provided by the test.
DEFAULT_GENESIS_HEIGHT = 101


class DevCli:
    def __init__(
        self,
        bitcoind_props: dict,
        operator_key_infos: list[OperatorKeyInfo],
        bridge_protocol_params=None,
    ):
        self.bitcoind_props = bitcoind_props
        self.operator_key_infos = operator_key_infos
        self.bridge_protocol_params = bridge_protocol_params
        self.temp_dir = tempfile.mkdtemp()
        self.params_path = self._create_params_file()

    def _create_params_file(self) -> str:
        p = self.bridge_protocol_params or BridgeProtocolParams()

        covenant = [
            CovenantKeys(
                musig2=key.MUSIG2_KEY,
                p2p=key.P2P_KEY,
                adaptor=key.MUSIG2_KEY,
                watchtower_fault=key.MUSIG2_KEY,
                payout_descriptor=key.GENERAL_WALLET_DESCRIPTOR,
            )
            for key in self.operator_key_infos
        ]

        params = BridgeOperatorParams(
            network="regtest",
            genesis_height=DEFAULT_GENESIS_HEIGHT,
            keys=Keys(
                admin=self.operator_key_infos[0].MUSIG2_KEY,
                covenant=covenant,
            ),
            protocol=p,
        )

        params_path = os.path.join(self.temp_dir, "params.toml")
        with open(params_path, "w") as f:
            toml.dump(asdict(params), f)

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
        assignee_node_idx: int = 0,
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
            "--assignee-node-idx",
            str(assignee_node_idx),
        ]

        res = self._run_command(args)
        # HACK: (@Rajil1213) parse raw stdout to extract txid
        txid = res.splitlines()[-1].split("=")[-1].strip()
        return txid

    def send_mock_checkpoint_from_tip(
        self,
        asm_rpc,
        block_hash: str,
        num_ol_slots: int,
        num_withdrawals=1,
        assignee_node_idx: int = 0,
    ) -> str:
        """Query the current checkpoint tip and send a mock checkpoint advancing by num_ol_slots.

        If no checkpoint tip exists (first checkpoint case), defaults are used (epoch=1, slot=0).
        """
        raw_tip = asm_rpc.strata_asm_getCheckpointTip(block_hash)
        tip = CheckpointTip.from_dict(raw_tip) if raw_tip is not None else None
        return self.send_mock_checkpoint(
            checkpoint_tip=tip,
            num_ol_slots=num_ol_slots,
            num_withdrawals=num_withdrawals,
            assignee_node_idx=assignee_node_idx,
        )

    def send_contest(
        self,
        deposit_idx: int,
        operator_idx: int,
        bridge_node_url: str,
        contester_node_idx: int,
        seed: str = "",
    ):
        rpc_port = self.bitcoind_props["rpc_port"]  # fail fast if missing
        wallet = self.bitcoind_props.get("walletname", "testwallet")

        args = [
            "contest",
            "--btc-url",
            f"http://127.0.0.1:{rpc_port}/wallet/{wallet}",
            "--btc-user",
            self.bitcoind_props.get("rpc_user", "user"),
            "--btc-pass",
            self.bitcoind_props.get("rpc_password", "password"),
            "--params",
            self.params_path,
            "--deposit-idx",
            str(deposit_idx),
            "--operator-idx",
            str(operator_idx),
            "--bridge-node-url",
            bridge_node_url,
            "--contester-node-idx",
            str(contester_node_idx),
            "--seed",
            seed,
        ]

        res = self._run_command(args)
        # HACK: (@Rajil1213) parse raw stdout to extract txid
        txid = res.splitlines()[-1].split("=")[-1].strip()
        return txid

    def send_claim(
        self,
        deposit_idx: int,
        operator_idx: int,
        bridge_node_url: str,
        seed: str,
    ):
        rpc_port = self.bitcoind_props["rpc_port"]  # fail fast if missing
        wallet = self.bitcoind_props.get("walletname", "testwallet")

        args = [
            "claim",
            "--btc-url",
            f"http://127.0.0.1:{rpc_port}/wallet/{wallet}",
            "--btc-user",
            self.bitcoind_props.get("rpc_user", "user"),
            "--btc-pass",
            self.bitcoind_props.get("rpc_password", "password"),
            "--params",
            self.params_path,
            "--deposit-idx",
            str(deposit_idx),
            "--operator-idx",
            str(operator_idx),
            "--bridge-node-url",
            bridge_node_url,
            "--seed",
            seed,
        ]

        res = self._run_command(args)
        # HACK: (@Rajil1213) parse raw stdout to extract txid
        txid = res.splitlines()[-1].split("=")[-1].strip()
        return txid
