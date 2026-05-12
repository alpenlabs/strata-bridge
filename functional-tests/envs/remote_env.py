"""BridgeNetworkEnv variant that connects to a user-managed bitcoind.

Selected by `entry.py` when `BRIDGE_REMOTE_BTC_URL` is set. Everything
inherited from `BridgeNetworkEnv` works unchanged — only the bitcoin
service construction is swapped to point at the externally-running node.
"""

import os

import flexitest

from .bridge_network_env import BridgeNetworkEnv


class RemoteBridgeNetworkEnv(BridgeNetworkEnv):
    """`BridgeNetworkEnv` that targets a user-managed bitcoind RPC at
    `BRIDGE_REMOTE_BTC_URL` (must resolve to 127.0.0.1) with credentials
    from `BRIDGE_REMOTE_BTC_USER` / `BRIDGE_REMOTE_BTC_PASSWORD`. The
    user's bitcoind must publish ZMQ on the ports defined as
    `REMOTE_BTC_ZMQ_*` in `factory.bitcoin`."""

    def _create_bitcoin_service(self, ectx: flexitest.EnvContext):
        try:
            url = os.environ["BRIDGE_REMOTE_BTC_URL"]
            user = os.environ["BRIDGE_REMOTE_BTC_USER"]
            password = os.environ["BRIDGE_REMOTE_BTC_PASSWORD"]
        except KeyError as missing:
            raise RuntimeError(
                f"RemoteBridgeNetworkEnv requires {missing.args[0]} to be set"
            ) from missing
        return ectx.get_factory("bitcoin").create_remote_bitcoin(
            url=url, user=user, password=password
        )
