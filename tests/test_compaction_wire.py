"""HTTP framing regressions for the canonical compaction receiver fixture."""

import importlib.util
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
from agenthooksprotocol.compaction import compaction_capabilities, text_parts
from agenthooksprotocol.runtime import Validator


class CompactionWireTests(unittest.TestCase):
    def test_inline_exchange_needs_no_upload_credentials_or_text_store(self):
        root = Path(__file__).resolve().parents[1]
        spec = importlib.util.spec_from_file_location(
            "compaction_wire_fixture", root / "interop/compaction_wire.py"
        )
        wire = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(wire)
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory)
            config = store / "subscriptions.json"
            config.write_text(
                json.dumps(
                    {
                        "test": {
                            "kind": "append",
                            "target": "instructions",
                            "suffix": " appended",
                        }
                    }
                )
            )
            validator = Validator()
            schema = self.schema_directory(store)
            plan = {
                "transport": "stdio",
                "credentials": {"test": {}},
                "receiverCommand": [
                    sys.executable,
                    str(root / "interop/compaction_wire.py"),
                    str(schema),
                    str(store),
                    str(config),
                ],
            }
            trace = []
            settled = wire.exchange(
                plan,
                "test",
                "inline",
                {
                    "boundary": "before",
                    "instructions": text_parts("base"),
                    "candidate": None,
                    "summary": None,
                    "capabilities": compaction_capabilities("before"),
                },
                validator,
                trace,
            )
            self.assertEqual(
                settled.event["instructions"],
                text_parts("base appended", "instructions:appended"),
            )
            self.assertEqual(
                trace[0]["request"]["params"]["event"]["instructions"],
                text_parts("base"),
            )
            receipt = json.loads((store / "receipts.jsonl").read_text())
            self.assertNotIn("bodies", receipt)
            self.assertEqual(
                sorted(p.name for p in store.iterdir()),
                ["receipts.jsonl", "schema", "subscriptions.json"],
            )

    def test_host_downstream_reads_settled_inline_summary_only_when_applied(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory)
            schema = self.schema_directory(store)
            config = store / "subscriptions.json"
            supplied = text_parts("supplied", "first") + text_parts(
                " summary", "second"
            )
            tail = text_parts(" appended", "tail")
            config.write_text(
                json.dumps(
                    {
                        "supply": {
                            "kind": "effects",
                            "effects": [{"type": "return", "value": supplied}],
                        },
                        "append": {
                            "kind": "effects",
                            "effects": [
                                {
                                    "type": "modify",
                                    "target": "summary",
                                    "operation": "merge",
                                    "value": tail,
                                }
                            ],
                        },
                        "deny": {
                            "kind": "effects",
                            "effects": [{"type": "deny", "reason": "blocked"}],
                        },
                    }
                )
            )

            def hook(supplier):
                return {"supplier": supplier, "failurePolicy": "fail-closed"}

            plan = {
                "schema": str(schema),
                "transport": "stdio",
                "credentials": {
                    supplier: {} for supplier in ("supply", "append", "deny")
                },
                "receiverCommand": [
                    sys.executable,
                    str(root / "interop/compaction_wire.py"),
                    str(schema),
                    str(store),
                    str(config),
                ],
                "cases": [
                    {
                        "name": "inline",
                        "instructions": text_parts("base"),
                        "before": [hook("supply")],
                        "after": [hook("append")],
                    },
                    {
                        "name": "blocked",
                        "instructions": text_parts("base"),
                        "before": [hook("deny")],
                        "after": [],
                    },
                ],
            }
            process = subprocess.run(
                [sys.executable, str(root / "interop/compaction_wire.py"), "host"],
                input=json.dumps(plan),
                text=True,
                capture_output=True,
                timeout=20,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            delivered, blocked = json.loads(process.stdout)
            self.assertTrue(delivered["result"]["applied"])
            self.assertEqual(delivered["result"]["summary"], supplied + tail)
            self.assertEqual(delivered["downstream"], ["supplied summary appended"])
            self.assertNotIn("bodies", delivered["result"])
            self.assertFalse(blocked["result"]["applied"])
            self.assertEqual(blocked["downstream"], [])
            self.assertEqual(
                sorted(p.name for p in store.iterdir()),
                ["receipts.jsonl", "schema", "subscriptions.json"],
            )

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
                    str(self.schema_directory(store)),
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
                        (self.compaction_request(), "result"),
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

    @staticmethod
    def compaction_request():
        envelope = request()
        event = envelope["params"]["event"]
        envelope["params"]["event"] = {
            "id": envelope["id"],
            "source": event["source"],
            "time": event["time"],
            "session": event["session"],
            "type": "context.compact.before",
            "trigger": "manual",
            "items": [],
            "instructions": text_parts("base"),
        }
        envelope["params"]["capabilities"] = compaction_capabilities("before")
        return envelope

    @staticmethod
    def schema_directory(store):
        # Exercise the installed canonical generation, not an unrelated checkout.
        from agenthooksprotocol import runtime

        directory = store / "schema"
        directory.mkdir()
        for schema in json.loads(
            Path(runtime.__file__).with_name("schemas.json").read_text()
        ):
            (directory / schema["$id"].rsplit("/", 1)[-1]).write_text(
                json.dumps(schema)
            )
        return directory
