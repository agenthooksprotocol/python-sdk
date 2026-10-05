"""Run real consumer programs against the installed public package."""

import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PublicExamplesTests(unittest.TestCase):
    def run_example(self, name):
        run = subprocess.run(
            [sys.executable, str(ROOT / "examples" / name)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        return json.loads(run.stdout)

    def test_typed_tool_real_asgi_handler(self):
        result = self.run_example("typed_tool.py")
        self.assertTrue(result["sdkAccepted"])
        self.assertTrue(result["hostAccepted"])
        self.assertEqual(result["effectiveInput"]["command"], "echo reviewed")
        self.assertFalse(result["executed"])

    def test_actual_owned_stdio_backend(self):
        result = self.run_example("stdio_tool.py")
        self.assertEqual(result["decision"], "deny")
        self.assertFalse(result["executed"])

    def test_streamed_upload_and_no_metadata_reads(self):
        result = self.run_example("upload.py")
        self.assertTrue(result["verified"])
        self.assertTrue(result["committed"])
        self.assertEqual(result["bodyReads"], 1)

    def test_observation_wait_and_child_cancellation(self):
        result = self.run_example("lifecycle.py")
        self.assertTrue(result["S09"]["nonGating"])
        self.assertTrue(result["S09"]["waitCompleted"])
        self.assertTrue(result["S10"]["cancelled"])
        self.assertTrue(result["S10"]["childReaped"])
        self.assertFalse(result["S10"]["executed"])

    def test_real_http_and_auth_scope(self):
        result = self.run_example("http_auth.py")
        self.assertTrue(result["S12"]["actualHTTP"])
        self.assertTrue(result["S12"]["correlated"])
        self.assertTrue(result["S14"]["eventCredentialBound"])
        self.assertTrue(result["S14"]["uploadCredentialIsolated"])

    def test_public_examples_on_trio(self):
        for module in (
            "typed_tool",
            "stdio_tool",
            "upload",
            "common_cases",
            "lifecycle",
            "http_auth",
        ):
            with self.subTest(example=module):
                script = (
                    "import sys, anyio; sys.path.insert(0, 'examples'); "
                    f"import {module}; anyio.run({module}.main, backend='trio')"
                )
                result = subprocess.run(
                    [sys.executable, "-c", script],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIsNotNone(json.loads(result.stdout))

    def test_protocol_settlement_is_not_host_input_validation(self):
        results = {row["id"]: row for row in self.run_example("common_cases.py")}
        self.assertEqual(len(results), 10)
        rejected = results["S04"]
        self.assertTrue(rejected["sdkAccepted"])
        self.assertFalse(rejected["hostAccepted"])
        self.assertEqual(rejected["rejectionLayer"], "host-input-schema")
        self.assertFalse(rejected["executed"])
        self.assertEqual(rejected["effectiveInput"]["command"], 42)
        self.assertEqual(results["S02"]["executionCount"], 1)


if __name__ == "__main__":
    unittest.main()
