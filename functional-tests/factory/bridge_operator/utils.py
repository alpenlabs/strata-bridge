from dataclasses import asdict
from pathlib import Path

import toml

from utils.utils import OperatorKeyInfo

from .config_cfg import (
    BridgeOperatorConfig,
    BtcClientConfig,
    BtcZmqConfig,
    DbConfig,
    Duration,
    P2pConfig,
    RpcConfig,
    SecretServiceClientConfig,
    StakeTxConfig,
)
from .params_cfg import BridgeOperatorParams, Connectors, Keys, Sidesystem, StakeChain, TxGraph


def generate_config_toml(output_path: str, datadir: str, tls_dir: str):
    mtls_dir = Path(tls_dir)

    config = BridgeOperatorConfig(
        datadir=datadir,
        is_faulty=False,
        nag_interval=Duration(secs=30, nanos=0),
        min_withdrawal_fulfillment_window=144,
        stake_funding_pool_size=32,
        shutdown_timeout=Duration(secs=30, nanos=0),
        secret_service_client=SecretServiceClientConfig(
            server_addr="127.0.0.1:1069",
            server_hostname="secret-service",
            timeout=1000,
            cert=str(mtls_dir / "cert.pem"),
            key=str(mtls_dir / "key.pem"),
            service_ca=str(mtls_dir / "s2.ca.pem"),
        ),
        btc_client=BtcClientConfig(
            url="http://127.0.0.1:18443",
            user="user",
            pass_="password",
            retry_count=3,
            retry_interval=1000,
        ),
        db=DbConfig(max_retry_count=3, backoff_period=Duration(secs=1000, nanos=0)),
        p2p=P2pConfig(
            idle_connection_timeout=Duration(secs=1000, nanos=0),
            listening_addr="/ip4/127.0.0.1/tcp/5679",
            connect_to=[],
            num_threads=4,
            dial_timeout=Duration(secs=0, nanos=250_000_000),
            general_timeout=Duration(secs=0, nanos=250_000_000),
            connection_check_interval=Duration(secs=0, nanos=500_000_000),
        ),
        rpc=RpcConfig(rpc_addr="127.0.0.1:5678", refresh_interval=Duration(secs=600, nanos=0)),
        btc_zmq=BtcZmqConfig(
            bury_depth=2,
            hashblock_connection_string="tcp://127.0.0.1:28332",
            hashtx_connection_string="tcp://127.0.0.1:28333",
            rawblock_connection_string="tcp://127.0.0.1:28334",
            rawtx_connection_string="tcp://127.0.0.1:28335",
            sequence_connection_string="tcp://127.0.0.1:28336",
        ),
        stake_tx=StakeTxConfig(max_retries=10, retry_delay=Duration(secs=5, nanos=0)),
    )

    with open(output_path, "w") as f:
        config_dict = asdict(config)
        # Fix the 'pass_' field name back to 'pass' for TOML
        config_dict["btc_client"]["pass"] = config_dict["btc_client"].pop("pass_")
        toml.dump(config_dict, f)


def generate_params_toml(output_path: str, operator_key: OperatorKeyInfo):
    """
    Generate bridge operator params.toml file using operator keys.

    Args:
        output_path: Path to write the params.toml file
        operator_key: OperatorKeys containing MUSIG2_KEY and P2P_KEY
    """
    params = BridgeOperatorParams(
        network="regtest",
        genesis_height=101,
        keys=Keys(
            musig2=[operator_key.MUSIG2_KEY],
            p2p=[operator_key.P2P_KEY],
        ),
        tx_graph=TxGraph(
            tag="alpn",
            deposit_amount=1_000_000_000,
            operator_fee=10_000_000,
            challenge_cost=10_000_000,
            refund_delay=1008,
        ),
        stake_chain=StakeChain(
            stake_amount=100_000_000,
            burn_amount=10_000_000,
            delta={"Blocks": 6},
            slash_stake_count=24,
        ),
        connectors=Connectors(
            payout_optimistic_timelock=1008, pre_assert_timelock=1152, payout_timelock=1008
        ),
        sidesystem=Sidesystem.default(),
    )

    with open(output_path, "w") as f:
        toml.dump(asdict(params), f)
