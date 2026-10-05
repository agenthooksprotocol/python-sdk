"""HTTP framing regressions for the canonical compaction receiver fixture."""

import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import unittest
from urllib.request import Request, urlopen

from test_interop import request


class CompactionWireTests(unittest.TestCase):
    def test_intercept_responses_advertise_json(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory)
            config = store / "subscriptions.json"
            config.write_text(json.dumps({"test": {"kind": "effects", "effects": []}}))
            with subprocess.Popen(
                [
                    sys.executable,
                    str(root / "interop/compaction_wire.py"),
                    "server",
                    str(root.parent / "agent-hooks-protocol/schema/draft"),
                    str(store),
                    str(config),
                ],
                env={
                    **os.environ,
                    "AHP_COMPACTION_TOKENS": json.dumps({"test-token": "test"}),
                },
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            ) as process:
                try:
                    with selectors.DefaultSelector() as selector:
                        selector.register(process.stdout, selectors.EVENT_READ)
                        self.assertTrue(selector.select(10), "receiver startup timeout")
                    endpoint = json.loads(process.stdout.readline())["endpoint"]
                    for envelope, member in (
                        (request(), "result"),
                        ({"id": "invalid"}, "error"),
                    ):
                        with self.subTest(member=member):
                            message = Request(
                                endpoint + "/hooks/intercept",
                                json.dumps(envelope).encode(),
                                {
                                    "Authorization": "Bearer test-token",
                                    "Content-Type": "application/json",
                                },
                            )
                            with urlopen(message, timeout=5) as response:
                                self.assertEqual(response.status, 200)
                                self.assertEqual(
                                    response.headers.get_all("Content-Type"),
                                    ["application/json"],
                                )
                                raw = response.read()
                                self.assertEqual(
                                    int(response.headers["Content-Length"]), len(raw)
                                )
                                body = json.loads(raw)
                                self.assertEqual(body["id"], envelope["id"])
                                self.assertIn(member, body)
                finally:
                    process.terminate()
                    process.communicate(timeout=5)
