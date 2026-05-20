import dataclasses

from constants import BRIDGE_NETWORK_SIZE
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import BridgeProtocolParams

from .asm_config import AsmEnvConfig
from .bridge_network_env import BridgeNetworkEnv
from .btc_config import BitcoinEnvConfig


class ExternalBtcBridgeNetworkEnv(BridgeNetworkEnv):
    """BridgeNetworkEnv that attaches to an already-running external regtest bitcoind.

    Connection details (RPC url/user/password and ZMQ endpoints) are read from env
    vars by the bitcoin factory; see `connect_external_bitcoin`. Useful for slow
    real-SP1 proving runs that want to reuse a pre-launched node instead of spawning
    one. All block generation, wallet funding, and operator setup are driven exactly
    as in `BridgeNetworkEnv` — only the bitcoind service construction differs.
    """

    def __init__(
        self,
        bridge_protocol_params=BridgeProtocolParams(),  # noqa: B008
        bridge_config_params=BridgeConfigParams(),  # noqa: B008
        btc_config: BitcoinEnvConfig | None = None,
        asm_config: AsmEnvConfig | None = None,
        enable_asm_proof: bool = True,
        num_operators: int = BRIDGE_NETWORK_SIZE,
    ):
        btc_config = btc_config or BitcoinEnvConfig()
        btc_config = dataclasses.replace(btc_config, external=True)
        super().__init__(
            bridge_protocol_params,
            bridge_config_params,
            btc_config,
            asm_config,
            enable_asm_proof=enable_asm_proof,
            num_operators=num_operators,
        )
