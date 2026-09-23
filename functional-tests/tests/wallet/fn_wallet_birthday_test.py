"""
Wallet Birthday: dev-cli Bootstrap Checkpoint Test

Verifies `dev-cli wallet-birthday`, which turns the node's UTXO set into the
`operator_wallet.bootstrap_*` pair: the block holding the oldest output either wallet still has
unspent. The env funds every operator's general wallet before any test runs and the node refills
the reserved pool at once, so a "reserved older than general" layout cannot be built from a live
operator. Two fresh P2TR addresses of the miner wallet stand in; the scan cannot tell them from the
real ones.

Test flow:
1. Pay the reserved stand-in and mine a block (B), then pay the general stand-in and mine a block
   (A = B + 1). The tool must report B and its hash: reporting A would mean the reserved address
   was skipped. `--rpc-timeout` takes a positive number of seconds.
2. Verify mode accepts (B, hash of B) and rejects A on its own and B with a foreign hash.
3. With an explorer stub answering from the same node the tool reports B again; with one answering
   a foreign hash it exits non-zero.
4. Two never-paid addresses yield the UTXO-set tip.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import cast

import flexitest

from envs import AsmEnv
from envs.base_test import StrataTestBase
from envs.live_env import StrataLiveEnv
from utils.dev_cli import DevCli

WRONG_HASH = "00000000000000000000000000000000000000000000000000000000deadbeef"


class _ExplorerStub:
    """Answers `/block-height/<h>` like a mempool API, from bitcoind or with a fixed hash."""

    def __init__(self, bitcoin_rpc, fixed_hash: str | None = None):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                prefix = "/block-height/"
                if not self.path.startswith(prefix):
                    self.send_error(404)
                    return
                height = int(self.path[len(prefix) :])
                body = fixed_hash or bitcoin_rpc.proxy.getblockhash(height)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(body.encode())

            def log_message(self, *_):
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self._server.shutdown()
        self._server.server_close()


@flexitest.register
class WalletBirthdayTest(StrataTestBase):
    """`dev-cli wallet-birthday` reports the oldest unspent output across both addresses."""

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env(AsmEnv())

    def main(self, ctx: flexitest.RunContext):
        bitcoind = ctx.get_service("bitcoin")
        rpc = bitcoind.create_rpc()
        # The env's miner would move the heights under the test.
        cast(StrataLiveEnv, ctx.env).stop_miner()
        dev_cli = DevCli(bitcoind.props)

        miner_addr = rpc.proxy.getnewaddress()
        reserved = rpc.proxy.getnewaddress("", "bech32m")
        general = rpc.proxy.getnewaddress("", "bech32m")

        # --- 1. The birthday is the reserved stand-in's block, the older of the two ---
        reserved_txid = rpc.proxy.sendtoaddress(reserved, 0.5)
        rpc.proxy.generatetoaddress(1, miner_addr)
        reserved_height = rpc.proxy.getblockcount()
        reserved_hash = rpc.proxy.getblockhash(reserved_height)
        # The miner wallet owns the stand-ins too, so lock the reserved output or the next payment
        # may pick it as an input and leave the reserved address with nothing unspent.
        reserved_vout = next(
            out["n"]
            for out in rpc.proxy.getrawtransaction(reserved_txid, True)["vout"]
            if out["scriptPubKey"].get("address") == reserved
        )
        rpc.proxy.lockunspent(False, [{"txid": reserved_txid, "vout": reserved_vout}])
        rpc.proxy.sendtoaddress(general, 0.5)
        rpc.proxy.generatetoaddress(1, miner_addr)
        general_height = rpc.proxy.getblockcount()
        assert general_height == reserved_height + 1

        checkpoint = dev_cli.wallet_birthday(general, reserved)
        assert checkpoint == {
            "bootstrap_height": reserved_height,
            "bootstrap_block_hash": reserved_hash,
        }, f"expected block {reserved_height}, got {checkpoint}"
        assert dev_cli.wallet_birthday(general, reserved, rpc_timeout=86400) == checkpoint
        try:
            dev_cli.wallet_birthday(general, reserved, rpc_timeout=0)
        except RuntimeError:
            pass
        else:
            raise AssertionError("--rpc-timeout 0 was accepted")
        self.logger.info(f"birthday is block {reserved_height} ({reserved_hash})")

        # --- 2. Verify mode ---
        assert dev_cli.verify_wallet_birthday(general, reserved, reserved_height, reserved_hash)
        assert not dev_cli.verify_wallet_birthday(general, reserved, general_height)
        assert not dev_cli.verify_wallet_birthday(general, reserved, reserved_height, WRONG_HASH)
        assert not dev_cli.verify_wallet_birthday(general, reserved, 0, rpc.proxy.getblockhash(0))
        self.logger.info("verify mode accepts the pair and rejects a higher height or foreign hash")

        # --- 3. Explorer cross-check ---
        with _ExplorerStub(bitcoind.create_rpc()) as honest:
            agreed = dev_cli.wallet_birthday(general, reserved, explorer_url=honest.url)
        assert agreed["bootstrap_height"] == reserved_height

        with _ExplorerStub(bitcoind.create_rpc(), fixed_hash=WRONG_HASH) as lying:
            try:
                dev_cli.wallet_birthday(general, reserved, explorer_url=lying.url)
            except RuntimeError:
                pass
            else:
                raise AssertionError("an explorer hash mismatch did not fail the command")
        self.logger.info("explorer agreement passes and a mismatch fails the command")

        # --- 4. Never-paid addresses fall back to the UTXO-set tip ---
        unpaid = [rpc.proxy.getnewaddress("", "bech32m") for _ in range(2)]
        fallback = dev_cli.wallet_birthday(*unpaid)
        assert fallback == {
            "bootstrap_height": rpc.proxy.getblockcount(),
            "bootstrap_block_hash": rpc.proxy.getbestblockhash(),
        }, f"unexpected fallback {fallback}"

        self.logger.info(
            "WALLET BIRTHDAY VERIFIED: the reserved address is scanned, the pair verifies, the "
            "explorer check is enforced, and never-paid wallets fall back to the tip"
        )
        return True
