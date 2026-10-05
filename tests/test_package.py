import unittest
from unittest.mock import patch
from pathlib import Path
import json

from agenthooksprotocol.runtime import Validator, ProtocolError

import agenthooksprotocol


class PackageTest(unittest.TestCase):
    def test_generated_module_is_exposed(self) -> None:
        self.assertIsNotNone(agenthooksprotocol.generated)

    def test_runtime_uses_bundled_canonical_schemas(self):
        with patch.dict("os.environ", {}, clear=True):
            validator = Validator()
        value = {"effects": [], "futureCapability": {"enabled": True}}
        self.assertIs(validator.validate("capabilities", value), value)
        with self.assertRaises(ProtocolError):
            validator.validate("capabilities", {"effects": "deny"})

    def test_bundle_includes_every_locked_schema(self):
        package = Path(agenthooksprotocol.__file__).parent
        bundled = json.loads((package / "schemas.json").read_text())
        lock = json.loads((package / "ahp-codegen.lock.json").read_text())
        self.assertEqual(len(bundled), len(lock["documents"]))
        self.assertEqual(len({schema["$id"] for schema in bundled}), len(bundled))
        self.assertEqual(
            lock["schemaRevision"], agenthooksprotocol.generated.SCHEMA_REVISION
        )

    def test_core_import_does_not_require_optional_frameworks(self):
        import subprocess
        import sys

        script = """
import importlib.abc, sys
class Block(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in ('httpx', 'pydantic', 'starlette', 'fastapi'):
            raise ImportError('optional dependency deliberately absent')
sys.meta_path.insert(0, Block())
import agenthooksprotocol
from agenthooksprotocol.server import hooks, asgi, stdio, attachments
"""
        result = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, text=True, timeout=10
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
