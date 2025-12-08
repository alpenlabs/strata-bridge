import os
import flexitest
from rpc import inject_service_create_rpc
from utils.constants import WALLETS
import toml
from pathlib import Path


class BridgeOperatorFactory(flexitest.Factory):
    def __init__(self, port_range: list[int]):
        super().__init__(port_range)

    @flexitest.with_ectx("ectx")
    def create_server(self, name: str, ectx: flexitest.EnvContext) -> flexitest.Service:
        rpc_port = self.next_port()
        dd = ectx.make_service_dir(name)

        base = Path(ectx.envdd_path)
        mtls_cred = str((base / "../operator_cred/tls").resolve())
        config_toml = str((base / name / "config.toml").resolve())
        params_toml = str((base / name / "params.toml").resolve())
        write_config_toml(config_toml, dd, mtls_cred)
        write_params_toml(params_toml)

        logfile_path = os.path.join(dd, "service.log")
        cmd = [
            "alpen-bridge",
            "--params",
            params_toml,
            "--config",
            config_toml,
        ]

        rpc_url = "http://0.0.0.0:5678"
        props = {
            "rpc_port": rpc_port,
            "logfile": logfile_path,
            "sc_wallet_address": WALLETS["OP1"]["STAKE_CHAIN_WALLET"],
            "general_wallet_address": WALLETS["OP1"]["GENERAL_WALLET"],
        }

        svc = flexitest.service.ProcService(props, cmd, stdout=logfile_path)
        svc.start()
        inject_service_create_rpc(svc, rpc_url, name)
        return svc


def write_config_toml(output_path: str, datadir: str, tls_dir: str):
    mtls_dir = Path(tls_dir)

    config = {
        "datadir": datadir,
        "is_faulty": False,
        "nag_interval": {"secs": 30, "nanos": 0},
        "min_withdrawal_fulfillment_window": 144,
        "stake_funding_pool_size": 32,
        "shutdown_timeout": {"secs": 30, "nanos": 0},
        "secret_service_client": {
            "server_addr": "127.0.0.1:69",
            "server_hostname": "secret-service",
            "timeout": 1000,
            "cert": str(mtls_dir / "cert.pem"),
            "key": str(mtls_dir / "key.pem"),
            "service_ca": str(mtls_dir / "s2.ca.pem"),
        },
        "btc_client": {
            "url": "http://127.0.0.1:18443",
            "user": "user",
            "pass": "password",
            "retry_count": 3,
            "retry_interval": 1000,
        },
        "db": {
            "max_retry_count": 3,
            "backoff_period": {"secs": 1000, "nanos": 0},
        },
        "p2p": {
            "idle_connection_timeout": {"secs": 1000, "nanos": 0},
            "listening_addr": "/ip4/127.0.0.1/tcp/5679",
            "connect_to": [],
            "num_threads": 4,
            "dial_timeout": {"secs": 0, "nanos": 250_000_000},
            "general_timeout": {"secs": 0, "nanos": 250_000_000},
            "connection_check_interval": {"secs": 0, "nanos": 500_000_000},
        },
        "rpc": {
            "rpc_addr": "127.0.0.1:5678",
            "refresh_interval": {"secs": 600, "nanos": 0},
        },
        "btc_zmq": {
            "bury_depth": 2,
            "hashblock_connection_string": "tcp://127.0.0.1:28332",
            "hashtx_connection_string": "tcp://127.0.0.1:28333",
            "rawblock_connection_string": "tcp://127.0.0.1:28334",
            "rawtx_connection_string": "tcp://127.0.0.1:28335",
            "sequence_connection_string": "tcp://127.0.0.1:28336",
        },
        "stake_tx": {
            "max_retries": 10,
            "retry_delay": {"secs": 5, "nanos": 0},
        },
    }

    with open(output_path, "w") as f:
        toml.dump(config, f)


def write_params_toml(output_path: str):
    """
    Create params.toml with fully static values, structured to match the
    expected Rust config (including sidesystem.operator_config and rollup_vk).
    """

    config = {
        "network": "regtest",
        "genesis_height": 101,
        "keys": {
            "musig2": [
                "ac407ba319846e25d69c1c0cb2a845ab75ef93ad2e9e846cdc5cf6da766e00b2"
            ],
            "p2p": [
                "0242f6ae559d2dc46b83fc820e9ba32f6ac8c387daac77f2805e930e924e3a127d"
            ],
        },
        "tx_graph": {
            "tag": "alpn",
            "deposit_amount": 1_000_000_000,
            "operator_fee": 10_000_000,
            "challenge_cost": 10_000_000,
            "refund_delay": 1008,
        },
        "stake_chain": {
            "stake_amount": 100_000_000,
            "burn_amount": 10_000_000,
            "delta": {"Blocks": 6},
            "slash_stake_count": 24,
        },
        "connectors": {
            "payout_optimistic_timelock": 1008,
            "pre_assert_timelock": 1152,
            "payout_timelock": 1008,
        },
        "sidesystem": {
            "magic_bytes": [65, 76, 80, 78],
            "block_time": 1000,
            "da_tag": "alpen-bridge-da",
            "checkpoint_tag": "alpen-bridge-checkpoint",
            "cred_rule": "unchecked",
            "horizon_l1_height": 1000,
            "genesis_l1_height": 1000,
            "l1_reorg_safe_depth": 1000,
            "target_l2_batch_size": 1000,
            "max_address_length": 20,
            "deposit_amount": 1_000_000_000,
            "dispatch_assignment_dur": 1000,
            "proof_publish_mode": "strict",
            "checkpoint_predicate": "AlwaysAccept",
            "max_deposits_in_block": 20,
            "network": "signet",
            "evm_genesis_block_hash": "0x46c0dc60fb131be4ccc55306a345fcc20e44233324950f978ba5f185aa2af4dc",
            "evm_genesis_block_state_root": "0x351714af72d74259f45cd7eab0b04527cd40e74836a45abcae50f92d919d988f",
            # This becomes:
            # [sidesystem.rollup_vk]
            # native = "0x..."
            "rollup_vk": {
                "native": "0x0000000000000000000000000000000000000000000000000000000000000000",
            },
            # This becomes:
            # [sidesystem.operator_config]
            # static = [ { signing_pk = "...", wallet_pk = "..." } ]
            "operator_config": {
                "static": [
                    {
                        "signing_pk": "0x8d86834e6fdb45ba6b7ffd067a27b9e1d67778047581d7ef757ed9e0fa474000",
                        "wallet_pk": "0xb49092f76d06f8002e0b7f1c63b5058db23fd4465b4f6954b53e1f352a04754d",
                    }
                ]
            },
            # Nested:
            # [sidesystem.genesis_l1_view]
            # ...
            # [sidesystem.genesis_l1_view.blk]
            "genesis_l1_view": {
                "blk": {
                    "height": 100,
                    "blkid": "f2c22acbe3b24e429349296b958c40b692356436086750bd7564ebfceb915100",
                },
                "next_target": 545259519,
                "epoch_start_timestamp": 1296688602,
                "last_11_timestamps": [
                    1764086031,
                    1764086031,
                    1764086032,
                    1764086032,
                    1764086032,
                    1764086032,
                    1764086032,
                    1764086032,
                    1764086033,
                    1764086033,
                    1764086033,
                ],
            },
        },
    }

    with open(output_path, "w") as f:
        toml.dump(config, f)
