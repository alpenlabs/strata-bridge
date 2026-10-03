"""Thread-safety regression test for `make_bitcoind_client`.

Runs against an in-process fake JSON-RPC server, so no bitcoind is needed. Run from
`functional-tests/` with `uv run python -m unittest discover -s unit -t .`.
"""

import base64
import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from factory.bitcoin import _FreshHTTPConnection, make_bitcoind_client

USER = "user"
PASSWORD = "password"
AUTH = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
THREADS = 4
ITERATIONS = 5
# A simulated slow TCP handshake. It widens the window in which a connection shared between
# threads gets torn down or written to by another thread, so the race is hit on the first call.
CONNECT_LATENCY_SECS = 0.05
RESPONSE_DELAY_SECS = 0.01


class _EchoRpcHandler(BaseHTTPRequestHandler):
    """Answers every JSON-RPC call with its own params as the result."""

    protocol_version = "HTTP/1.1"  # keep-alive, like bitcoind

    def do_POST(self):
        if self.headers.get("Authorization") != AUTH:
            self.send_error(401)
            return
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        time.sleep(RESPONSE_DELAY_SECS)
        response = {"result": request["params"], "error": None, "id": request["id"]}
        body = json.dumps(response).encode()
        self.send_response(200)
        # `AuthServiceProxy._get_response` compares the content type by exact equality.
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


_real_connect = _FreshHTTPConnection.connect


def _slow_connect(self):
    _real_connect(self)
    time.sleep(CONNECT_LATENCY_SECS)


class BitcoindClientThreadSafetyTest(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _EchoRpcHandler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        port = self.server.server_address[1]
        self.client = make_bitcoind_client(f"http://{USER}:{PASSWORD}@127.0.0.1:{port}", timeout=5)

    def test_one_client_shared_by_threads_delivers_each_call_its_own_result(self):
        barrier = threading.Barrier(THREADS)
        errors: list[tuple[int, int, str]] = []
        results: list[tuple[int, int, object]] = []

        def worker(t: int):
            barrier.wait()
            for i in range(ITERATIONS):
                try:
                    results.append((t, i, self.client.proxy.echo(f"t{t}", i)))
                except Exception as e:
                    errors.append((t, i, repr(e)))

        with mock.patch.object(_FreshHTTPConnection, "connect", _slow_connect):
            threads = [threading.Thread(target=worker, args=(t,)) for t in range(THREADS)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=30)

        self.assertEqual(errors, [])
        self.assertEqual(len(results), THREADS * ITERATIONS)
        for t, i, got in results:
            # bitcoinlib ignores the JSON-RPC id, so a cross-delivered response would otherwise
            # pass silently.
            self.assertEqual(got, [f"t{t}", i])
