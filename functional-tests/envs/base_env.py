import flexitest

from utils import (
    BLOCK_GENERATION_INTERVAL_SECS,
    generate_blocks,
    wait_until_bitcoind_ready,
)
from utils.utils import read_operator_key


class BaseEnv(flexitest.EnvConfig):
    """Base environment class with shared Bitcoin and operator setup logic."""

    def __init__(
        self,
        num_operators,
        p2p_port_generator,
        funding_amount=5.01,
        initial_blocks=101,
        finalization_blocks=10
    ):
        super().__init__()
        self.num_operators = num_operators
        self.funding_amount = funding_amount
        self.initial_blocks = initial_blocks
        self.finalization_blocks = finalization_blocks
        
        # Generate P2P ports for this environment
        self.p2p_ports = [next(p2p_port_generator) for _ in range(num_operators)]

        # Load all operator keys
        self.operator_key_infos = [read_operator_key(i) for i in range(num_operators)]

    def setup_bitcoin(self, ectx: flexitest.EnvContext):
        """Setup Bitcoin node with wallet and initial funding."""
        btc_fac = ectx.get_factory("bitcoin")
        bitcoind = btc_fac.create_regtest_bitcoin()
        brpc = bitcoind.create_rpc()
        wait_until_bitcoind_ready(brpc, timeout=10)

        # Create new wallet
        brpc.proxy.createwallet(bitcoind.get_prop("walletname"))
        wallet_addr = brpc.proxy.getnewaddress()

        # Mine initial blocks to have usable funds
        brpc.proxy.generatetoaddress(self.initial_blocks, wallet_addr)

        # Start automatic block generation
        generate_blocks(brpc, BLOCK_GENERATION_INTERVAL_SECS, wallet_addr)

        return bitcoind, brpc, wallet_addr

    def create_operator(self, ectx: flexitest.EnvContext, operator_idx, bitcoind_props):
        """Create a single bridge operator (S2 service + Bridge node)."""
        s2_fac = ectx.get_factory("s2")
        bo_fac = ectx.get_factory("bofac")

        # Use pre-loaded operator key
        operator_key = self.operator_key_infos[operator_idx]

        s2_service = s2_fac.create_s2_service(operator_idx, operator_key)
        bridge_operator = bo_fac.create_server(
            operator_idx, bitcoind_props, s2_service.props, self.operator_key_infos, self.p2p_ports
        )

        return s2_service, bridge_operator

    def fund_operator(self, brpc, bridge_operator_props, wallet_addr):
        """Fund an operator's wallets."""
        sc_wallet_address = bridge_operator_props["sc_wallet_address"]
        general_wallet_address = bridge_operator_props["general_wallet_address"]
        brpc.proxy.sendtoaddress(sc_wallet_address, self.funding_amount)
        brpc.proxy.sendtoaddress(general_wallet_address, self.funding_amount)

        # Generate blocks for finalization
        brpc.proxy.generatetoaddress(self.finalization_blocks, wallet_addr)
