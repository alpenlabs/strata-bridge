import flexitest

from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from rpc.types import RpcDepositStatusComplete
from utils.bridge import get_bridge_nodes_and_rpcs
from utils.deposit import (
    wait_until_deposit_status,
    wait_until_drt_recognized,
)
from utils.dev_cli import DevCli
from utils.utils import (
    read_operator_key,
)


@flexitest.register
class AsmDepositTest(StrataTestBase):
    """
    Test that ASM parses bridge DRT and DT
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(BridgeNetworkEnv())

    def main(self, ctx: flexitest.RunContext):
        bridge_nodes, bridge_rpcs = get_bridge_nodes_and_rpcs(ctx)
        bitcoind_service = ctx.get_service("bitcoin")
        bitcoin_rpc = bitcoind_service.create_rpc()

        num_operators = len(bridge_nodes)
        musig2_keys = [read_operator_key(i).MUSIG2_KEY for i in range(num_operators)]

        # Wait for DT and DRT
        bitcoind_props = bitcoind_service.props
        dev_cli = DevCli(bitcoind_props, musig2_keys)
        drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted DRT: {drt_txid}")

        bridge_rpc = bridge_rpcs[0]
        deposit_id = wait_until_drt_recognized(bridge_rpc, drt_txid)
        self.logger.info(f"DRT recognized, deposit_id: {deposit_id}")

        wait_until_deposit_status(bridge_rpc, deposit_id, RpcDepositStatusComplete)
        self.logger.info("Deposit completed")

        # Assert ASM has the deposit entry
        asm_service = ctx.get_service("asm_rpc")
        asm_rpc = asm_service.create_rpc()
        recent_block_num = bitcoin_rpc.proxy.getblockcount()
        recent_block_hash = bitcoin_rpc.proxy.getblockhash(recent_block_num)
        deposits = asm_rpc.strata_asm_getDeposits(recent_block_hash)
        self.logger.info(f"ASM deposits at block {recent_block_num}: {len(deposits)}")

        assert len(deposits) == 1

        return True
