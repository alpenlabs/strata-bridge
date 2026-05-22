import dataclasses

from constants import BRIDGE_NETWORK_SIZE
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import BridgeProtocolParams

from .asm_config import AsmEnvConfig
from .bridge_network_env import BridgeNetworkEnv
from .btc_config import BitcoinEnvConfig


class ExternalBtcBridgeNetworkEnv(BridgeNetworkEnv):
    """BridgeNetworkEnv that attaches to an already-running external regtest bitcoind.

    Connection details are read from env vars by the bitcoin factory (see
    `connect_external_bitcoin`); only bitcoind service construction differs from
    `BridgeNetworkEnv`. Useful for slow real-SP1 runs that reuse a pre-launched node.

    Attributes:
        btc_config: Bitcoin env config; `external=True` is forced on.
        bridge_protocol_params: On-chain bridge protocol parameters.
        bridge_config_params: Per-operator bridge node config.
        asm_config: ASM env config; defaults applied when None.
        enable_asm_proof: Whether operators produce ASM proofs.
        num_operators: Number of bridge operators to launch.
    """

    def __init__(
        self,
        btc_config: BitcoinEnvConfig,
        bridge_protocol_params=BridgeProtocolParams(),  # noqa: B008
        bridge_config_params=BridgeConfigParams(),  # noqa: B008
        asm_config: AsmEnvConfig | None = None,
        enable_asm_proof: bool = True,
        num_operators: int = BRIDGE_NETWORK_SIZE,
    ):
        btc_config = dataclasses.replace(btc_config, external=True)
        super().__init__(
            bridge_protocol_params,
            bridge_config_params,
            btc_config,
            asm_config,
            enable_asm_proof=enable_asm_proof,
            num_operators=num_operators,
        )
