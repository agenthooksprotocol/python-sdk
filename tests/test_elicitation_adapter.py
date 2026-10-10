"""Production elicitation receiver regressions over loopback HTTP."""

import base64
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import unittest
from urllib.request import Request, urlopen

from agenthooksprotocol import runtime
from test_public_content import Store, elicitation


class ElicitationAdapterTests(unittest.TestCase):
    def test_inline_request_receipt_preserves_utf8_without_upload(self):
        sdk = Path(__file__).resolve().parents[1]
        request, result = elicitation(Store())
        part = request["params"]["event"]["elicitation"]["request"]
        payload = json.loads(part["text"])
        payload["message"] = "Répondez 日本語 🐍"
        part["text"] = json.dumps(payload, ensure_ascii=False, indent=2)
        with tempfile.TemporaryDirectory() as temporary:
            schema_dir = Path(temporary)
            for schema in json.loads(
                Path(runtime.__file__).with_name("schemas.json").read_text()
            ):
                (schema_dir / schema["$id"].rsplit("/", 1)[-1]).write_text(
                    json.dumps(schema)
                )
            env = {**os.environ, "AHP_ELICITATION_TOKEN": "test-event-token"}
            env.pop("AHP_ELICITATION_UPLOAD_TOKEN", None)
            child = subprocess.Popen(
                [
                    sys.executable,
                    str(sdk / "interop/elicitation.py"),
                    "server",
                    str(schema_dir),
                    "test-principal",
                ],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ)
                    self.assertTrue(selector.select(5), "Receiver startup timeout")
                    endpoint = json.loads(child.stdout.readline())["endpoint"]

                def post(path, message):
                    req = Request(
                        endpoint + path,
                        data=json.dumps(message).encode("utf-8"),
                        headers={
                            "Authorization": "Bearer test-event-token",
                            "Content-Type": "application/json",
                        },
                        method="POST",
                    )
                    with urlopen(req, timeout=5) as response:
                        self.assertEqual(response.status, 200)
                        return json.load(response)

                post("/hooks/intercept", request)
                post("/hooks/intercept", result)
                receipts = post("/receipts", {})
                self.assertEqual(len(receipts), 2)
                self.assertEqual(receipts[0]["summary"], {"request": payload})
                for receipt, message, target in zip(
                    receipts, (request, result), ("request", "result")
                ):
                    text = message["params"]["event"]["elicitation"][target]["text"]
                    self.assertEqual(
                        base64.b64decode(receipt["bytes"]), text.encode("utf-8")
                    )
                    self.assertEqual(receipt["message"], message)
            finally:
                child.terminate()
                child.communicate(timeout=5)
