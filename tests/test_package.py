import unittest
from unittest.mock import patch
from pathlib import Path
import json

from agent_hooks_protocol.runtime import Validator, ProtocolError

import agent_hooks_protocol


class PackageTest(unittest.TestCase):
    def test_generated_module_is_exposed(self) -> None:
        self.assertIsNotNone(agent_hooks_protocol.generated)

    def test_runtime_uses_bundled_canonical_schemas(self):
        with patch.dict('os.environ', {}, clear=True):
            validator = Validator()
        value = {'effects': [], 'futureCapability': {'enabled': True}}
        self.assertIs(validator.validate('capabilities', value), value)
        with self.assertRaises(ProtocolError):
            validator.validate('capabilities', {'effects': 'deny'})

    def test_bundle_includes_every_locked_schema(self):
        package = Path(agent_hooks_protocol.__file__).parent
        bundled = json.loads((package / 'schemas.json').read_text())
        lock = json.loads((package / 'ahp-codegen.lock.json').read_text())
        self.assertEqual(len(bundled), len(lock['documents']))
        self.assertEqual(len({schema['$id'] for schema in bundled}), len(bundled))
        self.assertEqual(lock['schemaRevision'], agent_hooks_protocol.generated.SCHEMA_REVISION)


if __name__ == "__main__":
    unittest.main()
