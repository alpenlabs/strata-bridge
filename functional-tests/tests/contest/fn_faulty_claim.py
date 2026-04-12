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
    wait_until_utxo_spent,
)
from utils.dev_cli import DevCli
from utils.utils import (
    read_operator_key,
    wait_for_tx_confirmation,
)


@flexitest.register
class FaultyClaimContestedTest(StrataTestBase):
    """
    Test that a watchtower automatically contests a faulty claim.

    A faulty claim is one posted without a prior fulfillment transaction.

    Steps:
    1. Complete a deposit
    2. Post a claim via dev-cli for operator-0 (no fulfillment => faulty)
    3. Wait for a watchtower to automatically contest it by confirming the
       claim tx's contest connector (vout 0) is spent on bitcoin
    """

    def __init__(self, ctx: flexitest.InitContext):
        self.bridge_protocol_params = BridgeProtocolParams(
            contest_timelock=5,
        )
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

        # 1. Send deposit request and wait for completion
        drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted DRT: {drt_txid}")

        bridge_rpc = bridge_rpcs[0]
        deposit_id = wait_until_drt_recognized(bridge_rpc, drt_txid)
        self.logger.info(f"DRT recognized, deposit_id: {deposit_id}")

        deposit_info = wait_until_deposit_status(bridge_rpc, deposit_id, RpcDepositStatusComplete)
        assert deposit_info is not None, "Deposit did not complete"
        self.logger.info("Deposit completed")

        # 2. Post a faulty claim via dev-cli (no fulfillment)
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
        self.logger.info(f"Broadcasted faulty claim tx: {claim_txid}")

        claim_block_hash = wait_for_tx_confirmation(
            bitcoin_rpc,
            claim_txid,
            timeout=300,
        )
        self.logger.info(f"Faulty claim tx {claim_txid} confirmed in block {claim_block_hash}")

        # 3. Wait for a watchtower to contest by spending the claim's contest connector (vout 0)
        wait_until_utxo_spent(bitcoin_rpc, claim_txid, vout=0, timeout=300)
        self.logger.info("Claim contest connector (vout 0) spent — watchtower contested")

        return True
