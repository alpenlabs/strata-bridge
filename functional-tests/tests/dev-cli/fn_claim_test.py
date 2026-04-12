import flexitest

from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import BridgeProtocolParams
from rpc.types import RpcDepositStatusComplete
from utils.bridge import get_bridge_nodes_and_rpcs
from utils.deposit import (
    wait_until_deposit_status,
    wait_until_drt_recognized,
)
from utils.dev_cli import DevCli
from utils.utils import (
    read_operator_key,
    wait_for_tx_confirmation,
)


@flexitest.register
class ClaimPostTest(StrataTestBase):
    """
    Test that the dev-cli can post a claim transaction after a deposit.

    Steps:
    1. Complete a deposit
    2. Post a claim via the dev-cli using the deposit index
    3. Verify the claim transaction is confirmed
    """

    def __init__(self, ctx: flexitest.InitContext):
        self.bridge_protocol_params = BridgeProtocolParams()
        ctx.set_env(
            BridgeNetworkEnv(
                bridge_protocol_params=self.bridge_protocol_params,
                bridge_config_params=BridgeConfigParams(
                    cooperative_payout_timeout=0,
                ),
            )
        )

    def main(self, ctx: flexitest.RunContext):
        bridge_nodes, bridge_rpcs = get_bridge_nodes_and_rpcs(ctx)
        bitcoind_service = ctx.get_service("bitcoin")
        bitcoin_rpc = bitcoind_service.create_rpc()

        num_operators = len(bridge_nodes)
        operator_key_infos = [read_operator_key(i) for i in range(num_operators)]

        bitcoind_props = bitcoind_service.props
        dev_cli = DevCli(
            bitcoind_props,
            operator_key_infos,
            bridge_protocol_params=self.bridge_protocol_params,
        )

        # Send deposit request and wait for completion
        drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted DRT: {drt_txid}")

        bridge_rpc = bridge_rpcs[0]
        deposit_id = wait_until_drt_recognized(bridge_rpc, drt_txid)
        self.logger.info(f"DRT recognized, deposit_id: {deposit_id}")

        deposit_info = wait_until_deposit_status(bridge_rpc, deposit_id, RpcDepositStatusComplete)
        assert deposit_info is not None, "Deposit did not complete"
        self.logger.info("Deposit completed")

        # Post the claim via dev-cli right after deposit
        operator_idx = 0
        operator_node = bridge_nodes[operator_idx]
        operator_rpc_url = f"http://127.0.0.1:{operator_node.props['rpc_port']}"
        operator_seed = read_operator_key(operator_idx).SEED

        claim_txid = dev_cli.send_claim(
            deposit_idx=0,
            operator_idx=operator_idx,
            bridge_node_url=operator_rpc_url,
            seed=operator_seed,
        )
        self.logger.info(f"Broadcasted claim tx: {claim_txid}")

        claim_block_hash = wait_for_tx_confirmation(
            bitcoin_rpc,
            claim_txid,
            timeout=300,
        )
        self.logger.info(f"Claim tx {claim_txid} confirmed in block {claim_block_hash}")

        return True
