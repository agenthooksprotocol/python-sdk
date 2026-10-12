"""Registration stdio env: minimal base environment plus literal entries."""

import os
import sys
import unittest
from unittest.mock import patch

import anyio

from agenthooksprotocol import Hooks
from agenthooksprotocol.runtime import Validator
from agenthooksprotocol.transports import StdioTransport
from agenthooksprotocol.transports.stdio import child_environment

from test_public_hooks import capabilities, config

# Answers each request with the child's environment.
ECHO_ENV = (
    "import json, os, sys\n"
    "for line in sys.stdin:\n"
    "    message = json.loads(line)\n"
    "    print(json.dumps({'id': message['id'], 'env': dict(os.environ)}), flush=True)\n"
)

HOST = {
    "PATH": "/usr/bin",
    "HOME": "/home/me",
    "LANG": "C.UTF-8",
    "LC_CTYPE": "UTF-8",
    "AHP_HOST_SECRET": "host-only",
}


class ChildEnvironmentTests(unittest.TestCase):
    def test_base_allowlist_then_literal_entries(self):
        env = child_environment(
            {"AHP_BACKEND_MODE": "$HOME", "PATH": "/opt/bin"}, host=HOST, windows=False
        )
        self.assertEqual(
            env,
            {
                "PATH": "/opt/bin",
                "HOME": "/home/me",
                "LANG": "C.UTF-8",
                "LC_CTYPE": "UTF-8",
                "AHP_BACKEND_MODE": "$HOME",
            },
        )

    def test_inherit_environment_opt_out(self):
        env = child_environment(
            {"PATH": "/opt/bin"}, inherit_environment=True, host=HOST
        )
        self.assertEqual(env, {**HOST, "PATH": "/opt/bin"})

    def test_windows_names_are_case_insensitive(self):
        host = {"Path": "C:\\Windows", "SystemRoot": "C:\\Windows", "Other": "x"}
        env = child_environment({"PATH": "C:\\bin"}, host=host, windows=True)
        self.assertEqual(env, {"SystemRoot": "C:\\Windows", "PATH": "C:\\bin"})

    def test_registration_schema_accepts_only_string_env(self):
        registration = config()
        registration["hooks"][0]["transport"] = {
            "type": "stdio",
            "command": "backend",
            "lifecycle": "persistent",
            "env": {"MODE": "strict"},
        }
        Validator().validate("registration", registration)
        registration["hooks"][0]["transport"]["env"] = {"MODE": 1}
        with self.assertRaises(Exception):
            Validator().validate("registration", registration)


class StdioEnvironmentTests(unittest.TestCase):
    def both(self, function):
        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(function, backend=backend)

    def child_env(self, **options):
        async def run():
            transport = StdioTransport(sys.executable, ["-c", ECHO_ENV], **options)
            try:
                with anyio.fail_after(10):
                    return (await transport.request({"id": "env"}))["env"]
            finally:
                await transport.aclose()

        results = []

        async def collect():
            results.append(await run())

        self.both(collect)
        return results

    def test_env_reaches_child_and_host_only_vars_do_not(self):
        with patch.dict(os.environ, {"AHP_HOST_SECRET": "host-only"}):
            for env in self.child_env(env={"AHP_BACKEND_MODE": "strict"}):
                self.assertEqual(env["AHP_BACKEND_MODE"], "strict")
                self.assertNotIn("AHP_HOST_SECRET", env)

    def test_env_overrides_base_value(self):
        with patch.dict(os.environ, {"LANG": "C"}):
            for env in self.child_env(env={"LANG": "en_US.UTF-8"}):
                self.assertEqual(env["LANG"], "en_US.UTF-8")

    def test_inherit_environment_opt_out(self):
        with patch.dict(os.environ, {"AHP_HOST_SECRET": "host-only"}):
            for env in self.child_env(inherit_environment=True):
                self.assertEqual(env["AHP_HOST_SECRET"], "host-only")

    def test_hooks_pass_registration_env_and_opt_out(self):
        def registration():
            value = config()
            value["hooks"][0]["transport"] = {
                "type": "stdio",
                "command": sys.executable,
                "args": ["-c", ECHO_ENV],
                "lifecycle": "persistent",
                "env": {"AHP_BACKEND_MODE": "strict"},
            }
            return value

        async def run():
            for inherit in (False, True):
                hooks = Hooks(
                    registration(),
                    source="urn:host",
                    capabilities=capabilities(),
                    inherit_environment=inherit,
                )
                try:
                    await hooks._ensure_ready()
                    (transport,) = hooks._transports.values()
                    with anyio.fail_after(10):
                        env = (await transport.request({"id": "env"}))["env"]
                    self.assertEqual(env["AHP_BACKEND_MODE"], "strict")
                    self.assertEqual("AHP_HOST_SECRET" in env, inherit)
                finally:
                    await hooks.aclose()

        with patch.dict(os.environ, {"AHP_HOST_SECRET": "host-only"}):
            self.both(run)

    def test_env_values_are_not_in_repr(self):
        transport = StdioTransport("backend", env={"TOKEN": "literal-value"})
        self.assertNotIn("literal-value", repr(transport))


if __name__ == "__main__":
    unittest.main()
