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

DEFAULT_INITIAL_HEARBEAT_DELAY_SECS = 10


def zmq_connection_string(port: int) -> str:
    return f"tcp://127.0.0.1:{port}"


def generate_config_toml(
    bitcoind_props: dict,
    s2_props: dict,
    rpc_port: int,
    my_p2p_addr: str,
    other_p2p_addrs: list[str],
    output_path: str,
    datadir: str,
    tls_dir: str,
    heartbeat_delay_factor: int = 1,  # no delay by default
):
    mtls_dir = Path(tls_dir)
    total_peers = len(other_p2p_addrs) + 1  # +1 for self

    config = BridgeOperatorConfig(
        datadir=datadir,
        is_faulty=False,
        nag_interval=Duration(secs=30, nanos=0),
        min_withdrawal_fulfillment_window=144,
        stake_funding_pool_size=32,
        shutdown_timeout=Duration(secs=30, nanos=0),
        secret_service_client=SecretServiceClientConfig(
            server_addr=f"127.0.0.1:{s2_props.get('s2_port')}",
            server_hostname="secret-service",
            timeout=1000,
            cert=str(mtls_dir / "cert.pem"),
            key=str(mtls_dir / "key.pem"),
            service_ca=str(mtls_dir / "s2.ca.pem"),
        ),
        btc_client=BtcClientConfig(
            url=f"http://127.0.0.1:{bitcoind_props.get('rpc_port')}",
            user="user",
            pass_="password",
            retry_count=3,
            retry_interval=1000,
        ),
        db=DbConfig(max_retry_count=3, backoff_period=Duration(secs=1000, nanos=0)),
        p2p=P2pConfig(
            idle_connection_timeout=Duration(secs=1000, nanos=0),
            listening_addr=my_p2p_addr,
            connect_to=other_p2p_addrs,
            num_threads=4,
            dial_timeout=Duration(secs=0, nanos=250_000_000),
            general_timeout=Duration(secs=0, nanos=250_000_000),
            connection_check_interval=Duration(secs=0, nanos=500_000_000),
            gossipsub_heartbeat_initial_delay=Duration(
                secs=heartbeat_delay_factor * DEFAULT_INITIAL_HEARBEAT_DELAY_SECS, nanos=0
            ),
            # Configure gossipsub mesh for small network
            # Each operator can only see n-1 peers, so mesh_n_low must be <= n-1
            gossipsub_mesh_n=total_peers - 1,
            gossipsub_mesh_n_low=1,
            gossipsub_mesh_n_high=total_peers,
            # Use permissive scoring for test networks (disables penalties for localhost testing)
            gossipsub_scoring_preset="permissive",
        ),
        rpc=RpcConfig(rpc_addr=f"127.0.0.1:{rpc_port}", refresh_interval=Duration(secs=5, nanos=0)),
        btc_zmq=BtcZmqConfig(
            bury_depth=2,
            hashblock_connection_string=zmq_connection_string(bitcoind_props["zmq_hashblock"]),
            hashtx_connection_string=zmq_connection_string(bitcoind_props["zmq_hashtx"]),
            rawblock_connection_string=zmq_connection_string(bitcoind_props["zmq_rawblock"]),
            rawtx_connection_string=zmq_connection_string(bitcoind_props["zmq_rawtx"]),
            sequence_connection_string=zmq_connection_string(bitcoind_props["zmq_sequence"]),
        ),
        stake_tx=StakeTxConfig(max_retries=10, retry_delay=Duration(secs=5, nanos=0)),
    )

    with open(output_path, "w") as f:
        config_dict = asdict(config)
        # Fix the 'pass_' field name back to 'pass' for TOML
        config_dict["btc_client"]["pass"] = config_dict["btc_client"].pop("pass_")
        toml.dump(config_dict, f)


def generate_params_toml(output_path: str, operator_key_infos: list[OperatorKeyInfo]):
    """
    Generate bridge operator params.toml file using operator keys.

    Args:
        output_path: Path to write the params.toml file
        operator_key_infos: List of OperatorKeys containing MUSIG2_KEY and P2P_KEY
    """
    params = BridgeOperatorParams(
        network="regtest",
        genesis_height=101,
        keys=Keys(
            musig2=[key.MUSIG2_KEY for key in operator_key_infos],
            p2p=[key.P2P_KEY for key in operator_key_infos],
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
