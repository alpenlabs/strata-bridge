import flexitest

from envs import BridgeNetworkEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import BridgeProtocolParams
from rpc.types import RpcDepositStatusComplete
from utils.bridge import get_bridge_nodes_and_rpcs
from utils.deposit import (
    wait_until_deposit_status,
    wait_until_deposit_utxo_spent,
    wait_until_drt_recognized,
)
from utils.dev_cli import DevCli
from utils.utils import (
    read_operator_key,
    wait_for_tx_confirmation,
    wait_until,
)
from utils.withdrawal import wait_until_active_valid_claim


@flexitest.register
class PublishContestTest(StrataTestBase):
    """
    Test that contests can be published successfully in a bridge network environment.
    """

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(
            BridgeNetworkEnv(
                bridge_protocol_params=BridgeProtocolParams(
                    contest_timelock=5,
                    ack_timelock=10,
                ),
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
        musig2_keys = [read_operator_key(i).MUSIG2_KEY for i in range(num_operators)]

        # Init ASM rpc
        asm_service = ctx.get_service("asm_rpc")
        asm_rpc = asm_service.create_rpc()

        # Wait for DT and DRT
        bitcoind_props = bitcoind_service.props
        dev_cli = DevCli(
            bitcoind_props,
            musig2_keys,
            bridge_protocol_params=BridgeProtocolParams(
                contest_timelock=5,
                ack_timelock=10,
            ),
        )
        drt_txid = dev_cli.send_deposit_request()
        self.logger.info(f"Broadcasted DRT: {drt_txid}")

        bridge_rpc = bridge_rpcs[0]
        deposit_id = wait_until_drt_recognized(bridge_rpc, drt_txid)
        self.logger.info(f"DRT recognized, deposit_id: {deposit_id}")

        deposit_info = wait_until_deposit_status(bridge_rpc, deposit_id, RpcDepositStatusComplete)
        assert deposit_info is not None, "Deposit did not complete"
        self.logger.info("Deposit completed")
        deposit_txid = deposit_info.get("status").get("deposit_txid")
        self.logger.info(f"Deposit txid: {deposit_txid}")

        # Stop one of the bridge node so we trigger contested path
        bridge_nodes[-1].stop()

        # Now post mock checkpoint so that a withdrawal is assigned
        recent_block_hash = bitcoin_rpc.proxy.getblockhash(bitcoin_rpc.proxy.getblockcount())
        ckp_l1_txn = dev_cli.send_mock_checkpoint_from_tip(
            asm_rpc,
            recent_block_hash,
            num_ol_slots=1,
        )
        ckp_block_hash = wait_for_tx_confirmation(bitcoin_rpc, ckp_l1_txn)
        self.logger.info(f"Checkpoint tx {ckp_l1_txn} included in block {ckp_block_hash}")

        # Wait for ASM to process the checkpoint, then wait for an active claim
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

        # Use a different operator's node to contest
        contester_idx = (active_claim.assigned_operator + 1) % num_operators
        contester_node = bridge_nodes[contester_idx]
        contester_rpc_url = f"http://127.0.0.1:{contester_node.props['rpc_port']}"

        self.logger.info(f"Contesting with operator {contester_idx} via {contester_rpc_url}")
        contester_seed = read_operator_key(contester_idx).SEED

        contest_txid = dev_cli.send_contest(
            deposit_idx=active_claim.deposit_idx,
            operator_idx=active_claim.assigned_operator,
            bridge_node_url=contester_rpc_url,
            contester_node_idx=contester_idx,
            seed=contester_seed,
        )
        self.logger.info(f"Broadcasted contest_txid: {contest_txid}")
        contest_block_hash = wait_for_tx_confirmation(
            bitcoin_rpc,
            contest_txid,
            timeout=300,
        )
        self.logger.info(f"Contest tx {contest_txid} confirmed in block {contest_block_hash}")

        # Wait for the deposit UTXO to be spent after the contested payout path completes.
        wait_until_deposit_utxo_spent(bitcoin_rpc, deposit_txid, timeout=450)
        self.logger.info("Deposit UTXO confirmed spent after contested payout")

        return True
