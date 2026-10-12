"""Persistent stdio client: one stdout reader per child, routing by JSON-RPC id."""

import sys
import unittest

import anyio

from agenthooksprotocol.runtime import ProtocolError
from agenthooksprotocol.transports import StdioTransport

LOGGER = "agenthooksprotocol.transports.stdio"

# Answers requests by id. Every notification first triggers unsolicited output:
# a frame with an unknown id, a frame without an id, and a non-JSON line.
CHATTY = r"""
import json, sys
for line in sys.stdin:
    message = json.loads(line)
    if "id" not in message:
        print(json.dumps({"jsonrpc": "2.0", "id": "bogus", "result": {}}))
        print(json.dumps({"jsonrpc": "2.0", "method": "log"}))
        print("not json")
        sys.stdout.flush()
        continue
    if message.get("wrong_first"):
        print(json.dumps({"jsonrpc": "2.0", "id": "stale", "result": {}}))
    if message.get("overlong"):
        print("x" * 4096, flush=True)
        continue
    print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": {}}), flush=True)
"""

# Writes far more than a pipe buffer after every notification.
FLOOD = r"""
import json, sys
chunk = json.dumps({"jsonrpc": "2.0", "id": "noise", "result": {"pad": "x" * 1000}})
for line in sys.stdin:
    message = json.loads(line)
    if "id" not in message:
        sys.stdout.write((chunk + "\n") * 256)
        sys.stdout.flush()
        continue
    print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": {}}), flush=True)
"""


def request(id, **extra):
    return {"jsonrpc": "2.0", "id": id, "method": "hooks/intercept", **extra}


NOTE = {"jsonrpc": "2.0", "method": "hooks/observe", "params": {"pad": "y" * 1000}}


class StdioTransportTests(unittest.TestCase):
    def both(self, function):
        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(function, backend=backend)

    def test_unsolicited_frame_after_notification_is_discarded(self):
        async def run():
            transport = StdioTransport(sys.executable, ["-u", "-c", CHATTY])
            try:
                with self.assertLogs(LOGGER, "WARNING") as logs:
                    with anyio.fail_after(10):
                        await transport.notify(NOTE)
                        pid = transport._process.pid
                        reply = await transport.request(request("first"))
                        self.assertEqual(reply["id"], "first")
                        reply = await transport.request(
                            request("second", wrong_first=True)
                        )
                        self.assertEqual(reply["id"], "second")
                        self.assertEqual(transport._process.pid, pid)
                self.assertGreaterEqual(len(logs.output), 4)
                # Diagnostics never echo frame content.
                self.assertFalse(any("bogus" in line for line in logs.output))
            finally:
                await transport.aclose()

        self.both(run)

    def test_heavy_output_after_notifications_does_not_deadlock(self):
        async def run():
            transport = StdioTransport(sys.executable, ["-u", "-c", FLOOD])
            try:
                with self.assertLogs(LOGGER, "WARNING"):
                    with anyio.fail_after(30):
                        for _ in range(200):
                            await transport.notify(NOTE)
                        reply = await transport.request(request("after"))
                self.assertEqual(reply["id"], "after")
            finally:
                await transport.aclose()

        self.both(run)

    def test_overlong_frame_fails_request_and_replaces_child(self):
        async def run():
            transport = StdioTransport(
                sys.executable, ["-u", "-c", CHATTY], max_response_bytes=1024
            )
            try:
                with anyio.fail_after(10):
                    with self.assertRaises(ProtocolError):
                        await transport.request(request("big", overlong=True))
                    self.assertIsNone(transport._process)
                    reply = await transport.request(request("next"))
                    self.assertEqual(reply["id"], "next")
            finally:
                await transport.aclose()

        self.both(run)

    def test_exit_fails_pending_request_and_close_is_clean(self):
        async def run():
            transport = StdioTransport(
                sys.executable, ["-c", "import sys; sys.stdin.readline()"]
            )
            with anyio.fail_after(10):
                with self.assertRaises(ProtocolError):
                    await transport.request(request("lost"))
                self.assertIsNone(transport._process)
                await transport.aclose()
                with self.assertRaises(RuntimeError):
                    await transport.request(request("closed"))

        self.both(run)


if __name__ == "__main__":
    unittest.main()
