"""Receiver evidence for SDK-owned chain cancellation over real HTTP and stdio."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from agenthooksprotocol.interop import fixture_notify
from agenthooksprotocol.lifecycle_client import Transport
from agenthooksprotocol.observation_chain import run_chain
from agenthooksprotocol.runtime import Validator
from test_interop import request


class ObservationChainTransportTests(unittest.TestCase):
    def test_cancelled_chain_stops_delivery_but_standalone_observe_is_independent(self):
        for mode in ("http", "stdio"):
            with (
                self.subTest(transport=mode),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                original = request()
                ident = "cancelled-chain"
                original["id"] = original["params"]["event"]["id"] = ident
                original["params"]["event"]["tool"]["input"] = {"value": "original"}
                original["params"]["state"] = {"permission": "allow", "candidate": None}
                original["params"]["capabilities"] = {
                    "effects": ["deny", "modify"],
                    "modify": {"input": {"replace": True, "merge": False}},
                }
                subscriptions = [
                    {
                        "id": name,
                        "backend": "shared",
                        "mode": delivery,
                        "failurePolicy": "fail-open",
                        "content": "metadata",
                    }
                    for name, delivery in (
                        ("first", "intercept"),
                        ("second", "intercept"),
                        ("third", "intercept"),
                        ("audit", "observe"),
                    )
                ]
                scenario = {
                    "id": ident,
                    "requests": {"a": original},
                    "responses": {
                        "a": {
                            "jsonrpc": "2.0",
                            "id": ident,
                            "result": {
                                "protocolVersion": "draft",
                                "effects": [
                                    {
                                        "type": "modify",
                                        "target": "input",
                                        "operation": "replace",
                                        "value": {"value": "late"},
                                    },
                                    {"type": "deny", "reason": "late response"},
                                ],
                            },
                        }
                    },
                    "chain": {"subscriptions": subscriptions, "interrupt": True},
                    "expected": {"unused": "not an adapter oracle"},
                }
                fixture = root / "scenarios.json"
                fixture.write_text(json.dumps({"version": 1, "scenarios": [scenario]}))
                ready = root / "ready.json"
                server_config = root / "server.json"
                server_config.write_text(
                    json.dumps(
                        {
                            "transport": mode,
                            "scenarioFile": str(fixture),
                            "readinessFile": str(ready),
                            "auth": {"mode": "none"},
                        }
                    )
                )
                command = [sys.executable, "-m", "agenthooksprotocol.lifecycle_server"]
                config = {
                    "transport": mode,
                    "scenarioFile": str(fixture),
                    "serverConfig": str(server_config),
                    "serverCommand": command,
                    "auth": {"mode": "none"},
                }
                process, transport = None, None
                try:
                    if mode == "http":
                        process = subprocess.Popen(
                            command + ["--config", str(server_config)]
                        )
                        deadline = time.monotonic() + 10
                        while not ready.exists():
                            self.assertIsNone(process.poll())
                            self.assertLess(time.monotonic(), deadline)
                            threading.Event().wait(0.01)
                        config.update(json.loads(ready.read_text()))
                    transport = Transport(config)
                    actual = run_chain(scenario, transport, Validator())
                    self.assertEqual(
                        actual,
                        {
                            "called": ["first"],
                            "failures": [],
                            "observations": [],
                            "input": {"value": "original"},
                        },
                    )
                    entries = transport.control("/receipts")["entries"]
                    self.assertEqual(
                        [entry["kind"] for entry in entries],
                        ["received", "cancelled", "chain-settled", "replied"],
                    )
                    self.assertEqual(entries[0]["message"], original)
                    self.assertEqual(entries[1]["scenario"], ident)
                    self.assertEqual(entries[2]["scenario"], ident)
                    self.assertFalse(
                        any(
                            entry["kind"] in ("observed", "observer-blocked")
                            for entry in entries
                        )
                    )

                    # This is a NEW caller-owned operation, not an automatic
                    # observation started by the interrupted chain.
                    event = deepcopy(original["params"]["event"])
                    event["id"] = "standalone-observe"
                    note = {
                        "jsonrpc": "2.0",
                        "method": "hooks/observe",
                        "params": {"protocolVersion": "draft", "event": event},
                    }
                    self.assertEqual(fixture_notify(note, transport.observe), [])
                    transport.control(
                        "/wait-observed", {"eventId": event["id"], "count": 1}
                    )
                    entries = transport.control("/receipts")["entries"]
                    self.assertEqual(
                        [
                            entry["message"]
                            for entry in entries
                            if entry["kind"] == "observed"
                        ],
                        [note],
                    )
                finally:
                    if transport is not None:
                        if process is not None:
                            transport.control("/shutdown", {})
                        transport.close()
                    if process is not None:
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)
