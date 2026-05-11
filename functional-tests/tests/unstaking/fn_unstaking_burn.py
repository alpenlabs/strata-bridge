import flexitest

from constants import CLAIM_CONTEST_VOUT, CLAIM_PAYOUT_VOUT, MAX_BRIDGE_TIMEOUT
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
    find_utxo_spender_txid,
    read_operator_key,
    wait_for_tx_confirmation,
    wait_until,
)
from utils.withdrawal import wait_until_active_valid_claim


@flexitest.register
class UnstakingBurnTest(StrataTestBase):
    """
    Test that an operator unstaking intent lets a watchtower burn the claim payout connector.
    """

    def __init__(self, ctx: flexitest.InitContext):
        self.bridge_protocol_params = BridgeProtocolParams(contest_timelock=MAX_BRIDGE_TIMEOUT)
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
        bridge_rpc = bridge_rpcs[0]

        bitcoind_service = ctx.get_service("bitcoin")
        bitcoin_rpc = bitcoind_service.create_rpc()

        num_operators = len(bridge_nodes)
        operator_key_infos = [read_operator_key(i) for i in range(num_operators)]

        asm_service = ctx.get_service("asm_rpc")
        asm_rpc = asm_service.create_rpc()

        dev_cli = DevCli(
            bitcoind_service.props,
            operator_key_infos,
            bridge_protocol_params=self.bridge_protocol_params,
        )

        drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted DRT: {drt_txid}")
        deposit_id = wait_until_drt_recognized(bridge_rpc, drt_txid)
        self.logger.info(f"DRT recognized, deposit_id: {deposit_id}")

        deposit_info = wait_until_deposit_status(bridge_rpc, deposit_id, RpcDepositStatusComplete)
        assert deposit_info is not None, "Deposit did not complete"
        self.logger.info("Deposit completed")

        recent_block_hash = bitcoin_rpc.proxy.getblockhash(bitcoin_rpc.proxy.getblockcount())
        ckp_l1_txn = dev_cli.send_mock_checkpoint_from_tip(
            asm_rpc,
            recent_block_hash,
            num_ol_slots=1,
        )
        ckp_block_hash = wait_for_tx_confirmation(bitcoin_rpc, ckp_l1_txn)
        self.logger.info(f"Checkpoint tx {ckp_l1_txn} included in block {ckp_block_hash}")

        wait_until(
            lambda: len(asm_rpc.strata_asm_getAssignments(ckp_block_hash)) > 0,
            timeout=300,
            error_msg="ASM did not produce assignment",
        )

        active_claim = wait_until_active_valid_claim(bridge_rpc)
        self.logger.info(
            "Active claim %s for deposit %s assigned to operator %s",
            active_claim.claim_txid,
            active_claim.deposit_idx,
            active_claim.assigned_operator,
        )

        claim_block_hash = wait_for_tx_confirmation(
            bitcoin_rpc,
            active_claim.claim_txid,
            timeout=300,
        )
        self.logger.info(
            f"Claim tx {active_claim.claim_txid} confirmed in block {claim_block_hash}"
        )

        owner_idx = active_claim.assigned_operator
        owner_rpc_url = f"http://127.0.0.1:{bridge_nodes[owner_idx].props['rpc_port']}"
        unstaking_intent_txid = dev_cli.send_unstaking_intent(
            operator_idx=owner_idx,
            bridge_node_url=owner_rpc_url,
            seed=operator_key_infos[owner_idx].SEED,
        )
        self.logger.info(f"Broadcasted unstaking intent tx: {unstaking_intent_txid}")

        unstaking_intent_block_hash = wait_for_tx_confirmation(
            bitcoin_rpc,
            unstaking_intent_txid,
            timeout=300,
        )
        self.logger.info(
            "Unstaking intent tx %s confirmed in block %s",
            unstaking_intent_txid,
            unstaking_intent_block_hash,
        )

        wait_until_utxo_spent(
            bitcoin_rpc,
            active_claim.claim_txid,
            CLAIM_PAYOUT_VOUT,
            timeout=450,
        )
        burn_txid = find_utxo_spender_txid(
            bitcoin_rpc,
            active_claim.claim_txid,
            CLAIM_PAYOUT_VOUT,
        )
        burn_block_hash = wait_for_tx_confirmation(bitcoin_rpc, burn_txid, timeout=300)
        self.logger.info(f"Unstaking burn tx {burn_txid} confirmed in block {burn_block_hash}")

        burn_tx = bitcoin_rpc.proxy.getrawtransaction(burn_txid, True)
        burn_inputs = [(vin["txid"], vin["vout"]) for vin in burn_tx.get("vin", [])]
        assert len(burn_inputs) == 2, "Unstaking burn should have connector and wallet inputs"
        assert burn_inputs[0] == (
            active_claim.claim_txid,
            CLAIM_PAYOUT_VOUT,
        ), "Unstaking burn first input should spend the claim payout connector"
        assert (
            active_claim.claim_txid,
            CLAIM_CONTEST_VOUT,
        ) not in burn_inputs, "Unstaking burn should not spend the claim contest connector"
        assert len(burn_tx.get("vout", [])) == 1, "Unstaking burn should have one wallet output"

        return True
