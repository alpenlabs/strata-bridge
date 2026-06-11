from pathlib import Path
from typing import cast

import flexitest

from constants import BLOCK_GENERATION_INTERVAL_SECS, BRIDGE_NETWORK_SIZE
from envs import BridgeNetworkEnv, StrataLiveEnv
from envs.base_test import StrataTestBase
from factory.bridge_operator.config_cfg import BridgeConfigParams
from factory.bridge_operator.params_cfg import BridgeProtocolParams
from rpc.types import RpcDepositStatusComplete
from utils.bridge import get_bridge_nodes_and_rpcs
from utils.deposit import wait_until_deposit_status, wait_until_drts_recognized
from utils.dev_cli import DevCli
from utils.utils import read_operator_key, wait_until

BATCHED_DRT_COUNT = 2
GRAPH_NAG_INTERVAL_MS = 900  # set this to a lower value on more powerful machines
GRAPH_BLOCK_GENERATION_INTERVAL_SECS = 3


@flexitest.register
class BatchedDepositTest(StrataTestBase):
    """Batched deposits must complete when graph nags duplicate initial duties."""

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(
            BridgeNetworkEnv(
                bridge_config_params=BridgeConfigParams(
                    nag_interval_ms=GRAPH_NAG_INTERVAL_MS,
                ),
                bridge_protocol_params=BridgeProtocolParams(bury_depth=1),
            )
        )

    def main(self, ctx: flexitest.RunContext):
        bridge_nodes, bridge_rpcs = get_bridge_nodes_and_rpcs(ctx)
        bridge_rpc = bridge_rpcs[0]

        bitcoind_service = ctx.get_service("bitcoin")
        bitcoind_props = bitcoind_service.props
        bitcoin_rpc = bitcoind_service.create_rpc()
        miner_addr = bitcoin_rpc.proxy.getnewaddress()
        live_env = cast(StrataLiveEnv, ctx.env)

        operator_key_infos = [read_operator_key(i) for i in range(BRIDGE_NETWORK_SIZE)]
        dev_cli = DevCli(bitcoind_props, operator_key_infos)

        self.logger.info("Stopping miner before broadcasting the warm-up DRT")
        live_env.stop_miner()
        self._wait_until_mempool_empty(bitcoin_rpc)

        warmup_drt_txid = self._send_deposit_request(dev_cli, bitcoin_rpc)
        self.logger.info(f"Broadcasted warm-up DRT: {warmup_drt_txid}")
        self._mine_drt_batch(bitcoin_rpc, miner_addr, [warmup_drt_txid])

        live_env.start_miner(bitcoin_rpc, BLOCK_GENERATION_INTERVAL_SECS, miner_addr)
        try:
            warmup_deposit_id = wait_until_drts_recognized(
                bridge_rpc,
                [warmup_drt_txid],
                timeout=60,
            )[0]
            wait_until_deposit_status(
                bridge_rpc,
                warmup_deposit_id,
                RpcDepositStatusComplete,
                timeout=450,
            )
            self.logger.info(f"Warm-up deposit completed: deposit_idx={warmup_deposit_id}")
        except Exception as e:
            self.logger.error(
                "Error during warm-up deposit processing, \
                checking for DepositAborted logs"
            )
            self._log_deposit_aborts(bridge_nodes)
            raise e
        finally:
            live_env.stop_miner()

        self._wait_until_mempool_empty(bitcoin_rpc)

        # If the first deposit goes through, then increase the likelihood of parallel duty execution
        # by broadcasting multiple DRTs in quick succession before mining them in a batch block.
        self.logger.info(f"Broadcasting {BATCHED_DRT_COUNT} DRTs before mining a batch block")
        drt_txids = [
            self._send_deposit_request(dev_cli, bitcoin_rpc) for _ in range(BATCHED_DRT_COUNT)
        ]
        for drt_txid in drt_txids:
            self.logger.info(f"Broadcasted DRT: {drt_txid}")

        self._mine_drt_batch(bitcoin_rpc, miner_addr, drt_txids)

        live_env.start_miner(bitcoin_rpc, GRAPH_BLOCK_GENERATION_INTERVAL_SECS, miner_addr)
        try:
            try:
                deposit_ids = wait_until_drts_recognized(bridge_rpc, drt_txids, timeout=180)
                self.logger.info(f"Batched DRTs recognized as deposits: {deposit_ids}")

                for deposit_id in deposit_ids:
                    wait_until_deposit_status(
                        bridge_rpc,
                        deposit_id,
                        RpcDepositStatusComplete,
                        timeout=900,
                    )
                    self.logger.info(f"Batched deposit completed: deposit_idx={deposit_id}")
            except Exception as e:
                self.logger.error(
                    "Error during deposit processing, \
                    checking for DepositAborted logs"
                )
                self._log_deposit_aborts(bridge_nodes)
                raise e
        finally:
            live_env.stop_miner()

        return True

    def _wait_until_mempool_empty(self, bitcoin_rpc):
        wait_until(
            lambda: len(bitcoin_rpc.proxy.getrawmempool()) == 0,
            timeout=60,
            error_msg="Mempool did not clear before DRT broadcast",
        )

    def _mine_drt_batch(self, bitcoin_rpc, miner_addr: str, drt_txids: list[str]):
        wait_until(
            lambda: all(txid in bitcoin_rpc.proxy.getrawmempool() for txid in drt_txids),
            timeout=60,
            error_msg="Not all DRTs reached the mempool before batch mining",
        )

        batch_block_hash = bitcoin_rpc.proxy.generatetoaddress(1, miner_addr)[0]
        batch_block = bitcoin_rpc.proxy.getblock(batch_block_hash)
        missing_txids = [txid for txid in drt_txids if txid not in batch_block["tx"]]
        assert not missing_txids, (
            f"Batch block {batch_block_hash} did not include all DRTs; missing {missing_txids}"
        )
        self.logger.info(f"Batch block {batch_block_hash} included all DRTs: {drt_txids}")

    def _log_deposit_aborts(self, bridge_nodes):
        abort_log_count = 0

        for operator_idx, bridge_node in enumerate(bridge_nodes):
            logfile = bridge_node.props["logfile"]
            log_path = Path(logfile)
            if not log_path.exists():
                self.logger.warning(f"Operator log file does not exist: {log_path}")
                continue

            with log_path.open(encoding="utf-8", errors="ignore") as f:
                for line_no, line in enumerate(f, start=1):
                    if "DepositAborted" not in line:
                        continue

                    abort_log_count += 1
                    self.logger.warning(
                        "Observed DepositAborted in operator log "
                        f"operator_idx={operator_idx} path={log_path} line={line_no}"
                    )

        if abort_log_count == 0:
            self.logger.info("No DepositAborted messages found in bridge operator logs")
        else:
            self.logger.warning(
                f"Found {abort_log_count} DepositAborted messages in bridge operator logs"
            )

    def _send_deposit_request(self, dev_cli: DevCli, bitcoin_rpc) -> str:
        mempool_before = set(bitcoin_rpc.proxy.getrawmempool())
        try:
            return dev_cli.send_deposit_request()
        except IndexError:
            pass

        result: dict[str, str | None] = {"txid": None}

        def check():
            new_txids = sorted(set(bitcoin_rpc.proxy.getrawmempool()) - mempool_before)
            if len(new_txids) == 1:
                result["txid"] = new_txids[0]
                return True
            return False

        wait_until(
            check,
            timeout=10,
            error_msg="Deposit request broadcast did not add exactly one txid to the mempool",
        )
        assert result["txid"] is not None
        return result["txid"]
