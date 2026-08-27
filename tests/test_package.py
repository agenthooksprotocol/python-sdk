import unittest

import agent_hooks_protocol


class PackageTest(unittest.TestCase):
    def test_generated_module_is_exposed(self) -> None:
        self.assertIsNotNone(agent_hooks_protocol.generated)


if __name__ == "__main__":
    unittest.main()
