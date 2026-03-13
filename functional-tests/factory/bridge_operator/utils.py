from dataclasses import asdict
from pathlib import Path

import toml

from utils.utils import OperatorKeyInfo

from .config_cfg import (
    AsmRpcConfig,
    BridgeConfigParams,
    BridgeOperatorConfig,
    BtcClientConfig,
    BtcZmqConfig,
    DbConfig,
    Duration,
    FdbRetryConfig,
    OperatorWalletConfig,
    P2pConfig,
    RpcConfig,
    SecretServiceClientConfig,
)
from .params_cfg import BridgeOperatorParams, BridgeProtocolParams, CovenantKeys, Keys
from .sidesystem_cfg import Sidesystem

DEFAULT_INITIAL_HEARBEAT_DELAY_SECS = 10


def zmq_connection_string(port: int) -> str:
    return f"tcp://127.0.0.1:{port}"


def generate_config_toml(
    bitcoind_props: dict,
    s2_props: dict,
    fdb_props: dict,
    asm_props: dict,
    rpc_port: int,
    my_p2p_addr: str,
    other_p2p_addrs: list[str],
    output_path: str,
    tls_dir: str,
    bridge_config_params: BridgeConfigParams,
    heartbeat_delay_factor: int = 1,  # no delay by default
):
    mtls_dir = Path(tls_dir)
    total_peers = len(other_p2p_addrs) + 1  # +1 for self

    config = BridgeOperatorConfig(
        num_threads=None,
        thread_stack_size=None,
        nag_interval=Duration(secs=10, nanos=0),
        retry_interval=Duration(secs=1, nanos=0),
        min_withdrawal_fulfillment_window=bridge_config_params.min_withdrawal_fulfillment_window,
        shutdown_timeout=Duration(secs=30, nanos=0),
        cooperative_payout_timeout=bridge_config_params.cooperative_payout_timeout,
        max_fee_rate=bridge_config_params.max_fee_rate,
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
        db=DbConfig(
            cluster_file_path=fdb_props["cluster_file"],
            root_directory=fdb_props["root_directory"],
            tls=None,
            retry=FdbRetryConfig(retry_limit=5, timeout=Duration(secs=5, nanos=0)),
        ),
        p2p=P2pConfig(
            idle_connection_timeout=Duration(secs=1000, nanos=0),
            listening_addr=my_p2p_addr,
            connect_to=other_p2p_addrs,
            num_threads=4,
            dial_timeout=Duration(secs=1, nanos=0),
            general_timeout=Duration(secs=0, nanos=250_000_000),
            connection_check_interval=Duration(secs=0, nanos=100_000_000),
            gossipsub_heartbeat_initial_delay=Duration(
                secs=heartbeat_delay_factor * DEFAULT_INITIAL_HEARBEAT_DELAY_SECS, nanos=0
            ),
            gossipsub_forward_queue_duration=Duration(secs=60, nanos=0),
            gossipsub_publish_queue_duration=Duration(secs=60, nanos=0),
            # Configure gossipsub mesh for small network
            # Each operator can only see n-1 peers, so mesh_n_low must be <= n-1
            gossipsub_mesh_n=total_peers - 1,
            gossipsub_mesh_n_low=1,
            gossipsub_mesh_n_high=total_peers,
            # Use permissive scoring for test networks (disables penalties for localhost testing)
            gossipsub_scoring_preset="permissive",
        ),
        rpc=RpcConfig(rpc_addr=f"127.0.0.1:{rpc_port}", refresh_interval=Duration(secs=1, nanos=0)),
        asm_rpc=AsmRpcConfig(
            rpc_url=f"http://127.0.0.1:{asm_props['rpc_port']}",
            request_timeout=Duration(secs=2, nanos=0),
            max_retries=10,
            retry_initial_delay=Duration(secs=1, nanos=0),
            retry_max_delay=Duration(secs=60, nanos=0),
            retry_multiplier=2,
        ),
        btc_zmq=BtcZmqConfig(
            bury_depth=2,
            hashblock_connection_string=zmq_connection_string(bitcoind_props["zmq_hashblock"]),
            hashtx_connection_string=zmq_connection_string(bitcoind_props["zmq_hashtx"]),
            rawblock_connection_string=zmq_connection_string(bitcoind_props["zmq_rawblock"]),
            rawtx_connection_string=zmq_connection_string(bitcoind_props["zmq_rawtx"]),
            sequence_connection_string=zmq_connection_string(bitcoind_props["zmq_sequence"]),
        ),
        operator_wallet=OperatorWalletConfig(claim_funding_pool_size=32),
    )

    with open(output_path, "w") as f:
        config_dict = asdict(config)
        # Fix the 'pass_' field name back to 'pass' for TOML
        config_dict["btc_client"]["pass"] = config_dict["btc_client"].pop("pass_")
        toml.dump(config_dict, f)


def generate_params_toml(
    output_path: str,
    operator_key_infos: list[OperatorKeyInfo],
    sidesystem: Sidesystem,
    bridge_protocol_params: BridgeProtocolParams,
):
    """
    Generate bridge operator params.toml file using operator keys.

    Args:
        output_path: Path to write the params.toml file
        operator_key_infos: List of OperatorKeys containing MUSIG2_KEY and P2P_KEY
        sidesystem: Pre-built sidesystem params to embed
        bridge_protocol_params: Bridge parameters for this test env
    """
    covenant = [
        CovenantKeys(
            musig2=key.MUSIG2_KEY,
            p2p=key.P2P_KEY,
            adaptor=key.MUSIG2_KEY,
            watchtower_fault=key.MUSIG2_KEY,
            payout_descriptor=key.GENERAL_WALLET_DESCRIPTOR,
        )
        for key in operator_key_infos
    ]

    params = BridgeOperatorParams(
        network="regtest",
        genesis_height=sidesystem.genesis_l1_view.blk.height,
        keys=Keys(admin=operator_key_infos[0].MUSIG2_KEY, covenant=covenant),
        protocol=bridge_protocol_params,
    )

    with open(output_path, "w") as f:
        toml.dump(asdict(params), f)
