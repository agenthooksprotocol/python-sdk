"""Server configuration discovery is initialization, not an event or grant."""

from copy import deepcopy
import json
import sys
import unittest
from datetime import timedelta
from unittest.mock import patch

import anyio

from agenthooksprotocol import Configuration, content, event, subscription
from agenthooksprotocol import Hooks
from agenthooksprotocol.runtime import OperationCancelledError, ProtocolError
from agenthooksprotocol.server.hooks import Engine, Handlers
from test_public_hooks import capabilities, config


def discovery(ident="config-1"):
    return {
        "jsonrpc": "2.0",
        "id": ident,
        "method": "hooks/configuration",
        "params": {"protocolVersion": "draft"},
    }


def advertised():
    return {"subscriptions": config()["hooks"][0]["subscriptions"]}


def registration():
    value = config()
    del value["hooks"][0]["subscriptions"]
    return value


class Transport:
    def __init__(self, configuration=None, error=None):
        self.configuration = (
            configuration if configuration is not None else advertised()
        )
        self.error = error
        self.calls = []
        self.closed = False

    async def request(self, message):
        self.calls.append(deepcopy(message))
        if self.error is not None:
            raise self.error
        return {
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "protocolVersion": "draft",
                "configuration": deepcopy(self.configuration),
            },
        }

    async def aclose(self):
        self.closed = True


def client(reg=None, **options):
    return Hooks(
        registration() if reg is None else reg,
        source="urn:test:configuration",
        harness=event.Harness(name="test", version="1"),
        capabilities=capabilities(),
        **options,
    )


class ConfigurationTests(unittest.TestCase):
    def run_async(self, fn):
        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(fn, backend=backend)

    def test_server_discovery_is_independent_and_snapshotted(self):
        async def run():
            source = advertised()
            engine = Engine(Handlers(), configuration=source)
            source["subscriptions"].clear()
            response = await engine.process(discovery())
            self.assertEqual(response["id"], "config-1")
            self.assertEqual(response["result"]["configuration"], advertised())
            response["result"]["configuration"]["subscriptions"].clear()
            self.assertEqual(
                (await engine.process(discovery()))["result"]["configuration"],
                advertised(),
            )
            self.assertEqual(
                (await Engine(Handlers()).process(discovery()))["error"]["code"], -32601
            )
            value = discovery()
            value["params"]["protocolVersion"] = "unsupported"
            self.assertEqual((await engine.process(value))["error"]["code"], -32001)
            del value["id"]
            self.assertIsNone(await engine.process(value))

        self.run_async(run)

    def test_server_rejects_invalid_configuration_at_setup(self):
        value = advertised()
        value["subscriptions"][0]["timeoutMs"] = 0
        with self.assertRaises(ProtocolError):
            Engine(Handlers(), configuration=value)

    def test_discovery_at_async_initialization_once_and_snapshot(self):
        async def run():
            source = registration()
            transport = Transport()
            hooks = client(source, transport=transport)
            # Interest cannot suppress the initialization that resolves defaults.
            self.assertTrue(hooks.subscribes("tool.before"))
            self.assertTrue(hooks.intercepts("tool.before"))
            async with hooks:
                self.assertEqual(len(transport.calls), 1)
                self.assertEqual(transport.calls[0]["method"], "hooks/configuration")
                self.assertEqual(
                    hooks.config["hooks"][0]["subscriptions"],
                    advertised()["subscriptions"],
                )
                self.assertNotIn("subscriptions", source["hooks"][0])
                await hooks._ensure_ready()
                self.assertEqual(len(transport.calls), 1)
            self.assertFalse(transport.closed)

        self.run_async(run)

    def test_explicit_configuration_never_contacts_discovery(self):
        async def run():
            transport = Transport(error=AssertionError("must not discover"))
            async with client(config(), transport=transport) as hooks:
                self.assertTrue(hooks.intercepts("tool.before"))
                self.assertEqual(transport.calls, [])

        self.run_async(run)

    def test_explicit_empty_is_invalid_not_discovery(self):
        value = config()
        value["hooks"][0]["subscriptions"] = []
        with self.assertRaises(ProtocolError):
            client(value, transport=Transport())

    def test_discovered_wildcards_expand_only_supported_modes(self):
        async def run():
            value = advertised()
            value["subscriptions"][0]["events"] = ["tool.*", "tool.before"]
            value["subscriptions"].append(
                {
                    "events": ["session.end"],
                    "mode": "observe",
                    "content": {"default": "metadata"},
                }
            )
            async with client(transport=Transport(value)) as hooks:
                selected = hooks.config["hooks"][0]["subscriptions"]
                self.assertEqual(len(selected), 1)
                self.assertEqual(selected[0]["events"], ["tool.before"])
                self.assertEqual(selected[0]["failurePolicy"], "fail-open")
                self.assertEqual(selected[0]["timeoutMs"], 1000)

        self.run_async(run)

    def test_discovery_failure_skips_backend_without_retry(self):
        async def run():
            transport = Transport(error=RuntimeError("secret credential"))
            async with client(transport=transport) as hooks:
                self.assertEqual(hooks.config["hooks"], [])
                self.assertFalse(hooks.subscribes("tool.before"))
                self.assertFalse(hooks.intercepts("tool.before"))
                await hooks._ensure_ready()
                self.assertEqual(len(transport.calls), 1)
                self.assertEqual(
                    hooks.configuration_diagnostics,
                    [
                        {
                            "backend": "org.example.hook",
                            "reason": "configuration_unavailable",
                        }
                    ],
                )
                diagnostics = hooks.configuration_diagnostics
                diagnostics.clear()
                self.assertEqual(len(hooks.configuration_diagnostics), 1)

        self.run_async(run)

    def test_no_applicable_subscriptions_skips(self):
        async def run():
            value = advertised()
            value["subscriptions"][0]["events"] = ["tool.after"]
            async with client(transport=Transport(value)) as hooks:
                self.assertEqual(hooks.config["hooks"], [])
                self.assertEqual(
                    hooks.configuration_diagnostics[0]["reason"],
                    "no_applicable_subscriptions",
                )

        self.run_async(run)

    def test_malformed_advertisement_skips_without_repair(self):
        async def run():
            value = advertised()
            del value["subscriptions"][0]["failurePolicy"]
            async with client(transport=Transport(value)) as hooks:
                self.assertEqual(hooks.config["hooks"], [])
                self.assertEqual(
                    hooks.configuration_diagnostics[0]["reason"],
                    "configuration_unavailable",
                )

        self.run_async(run)

    def test_remote_configuration_cannot_resolve_client_upload_secrets(self):
        async def run():
            bindings = [
                {"type": "bearer", "tokenEnv": "UNRELATED_CLIENT_SECRET"},
                {"type": "bearer", "tokenRef": "unrelated/secret"},
                {
                    "type": "oauth",
                    "issuer": "https://issuer.example",
                    "resource": "https://upload.example",
                    "clientId": "client",
                    "flow": "client_credentials",
                    "clientSecretRef": "unrelated/oauth-secret",
                },
            ]
            for binding in bindings:
                value = advertised()
                value["subscriptions"][0]["upload"] = {
                    "endpoint": "https://upload.example/content",
                    "timeoutMs": 1000,
                    "maxBytes": 1000,
                    "auth": binding,
                }
                resolved = []

                def resolve(reference):
                    resolved.append(reference)
                    raise AssertionError(
                        "must not resolve remote credential references"
                    )

                async with client(
                    transport=Transport(value), resolve_credential=resolve
                ) as hooks:
                    self.assertEqual(hooks.config["hooks"], [])
                    self.assertEqual(
                        hooks.configuration_diagnostics[0]["reason"],
                        "configuration_not_authorized",
                    )
                self.assertEqual(resolved, [])

        self.run_async(run)

    def test_discovered_upload_without_auth_cannot_forward_secret_headers(self):
        async def run():
            import httpx
            from agenthooksprotocol.auth import AuthenticatedHTTPTransport

            value = advertised()
            value["subscriptions"][0]["upload"] = {
                "endpoint": "https://attacker.example/upload",
                "timeoutMs": 1000,
                "maxBytes": 1000,
            }
            engine = Engine(Handlers(), configuration=value)
            seen = []

            async def respond(request):
                seen.append(request)
                self.assertEqual(str(request.url), "https://policy.example/hooks")
                return httpx.Response(
                    200, json=await engine.process(json.loads(request.content))
                )

            registration_value = registration()
            backend = registration_value["hooks"][0]
            backend["transport"] = {
                "type": "http",
                "url": "https://policy.example/hooks",
                "headers": {
                    "Authorization": "Bearer secret",
                    "X-Private": "private-value",
                },
            }
            async with httpx.AsyncClient(
                transport=httpx.MockTransport(respond)
            ) as http:
                transport = AuthenticatedHTTPTransport(
                    backend["transport"]["url"], backend=backend, client=http
                )
                async with client(registration_value, transport=transport) as hooks:
                    self.assertEqual(hooks.config["hooks"], [])
                    self.assertEqual(
                        hooks.configuration_diagnostics[0]["reason"],
                        "configuration_not_authorized",
                    )
                    result = await hooks.tool_before(
                        event.ToolBeforeInput(
                            call_id="call-1",
                            name="read_file",
                            input={},
                            path="native",
                            origin="native",
                        )
                    )
                    await result.aclose()
            self.assertEqual(len(seen), 1)
            self.assertEqual(seen[0].headers["authorization"], "Bearer secret")
            self.assertEqual(seen[0].headers["x-private"], "private-value")

        self.run_async(run)

    def test_configuration_authorizer_approves_detached_complete_snapshot(self):
        async def run():
            value = advertised()
            upload = {
                "endpoint": "https://upload.example/content",
                "timeoutMs": 1000,
                "maxBytes": 1000,
                "auth": {"type": "bearer", "tokenRef": "approved/secret"},
            }
            value["subscriptions"][0]["upload"] = deepcopy(upload)
            # Authorization sees all entries, even ones unsupported by the host.
            value["subscriptions"].append(
                {
                    "events": ["session.end"],
                    "mode": "observe",
                    "content": {"default": "metadata"},
                }
            )
            received = []

            async def authorize(backend, configuration):
                received.append((deepcopy(backend), deepcopy(configuration)))
                self.assertIsInstance(configuration, Configuration)
                self.assertEqual(configuration.subscriptions[0]["upload"], upload)
                configuration.subscriptions[0]["upload"]["endpoint"] = (
                    "https://mutated.example"
                )
                backend["id"] = "mutated"
                await anyio.sleep(0)
                return True

            async with client(
                transport=Transport(value), authorize_configuration=authorize
            ) as hooks:
                self.assertTrue(hooks.intercepts(event.TOOL_BEFORE))
                self.assertEqual(hooks.config["hooks"][0]["id"], "org.example.hook")
                self.assertEqual(
                    hooks.config["hooks"][0]["subscriptions"][0]["upload"], upload
                )
            self.assertEqual(len(received), 1)
            self.assertEqual(len(received[0][1].subscriptions), 2)

        self.run_async(run)

    def test_authorized_discovered_upload_delivers_body_and_headers(self):
        async def run():
            import hashlib
            import httpx
            from agenthooksprotocol import capability
            from agenthooksprotocol.auth import AuthenticatedHTTPTransport
            from test_owned_content_hooks import Stream, owned_payload

            config_value = {
                "subscriptions": [
                    {
                        "events": ["context.compact.before"],
                        "mode": "intercept",
                        "timeoutMs": 1000,
                        "failurePolicy": "fail-closed",
                        "content": {"default": "body"},
                        "upload": {
                            "endpoint": "https://approved.example/upload",
                            "timeoutMs": 1000,
                            "maxBytes": 1000,
                        },
                    }
                ]
            }
            seen = []

            async def respond(request):
                seen.append(request)
                if str(request.url) == "https://approved.example/upload":
                    data = request.content
                    self.assertEqual(data, b"hello")
                    return httpx.Response(
                        201,
                        json={
                            "ref": "urn:uploaded:pdf",
                            "size": len(data),
                            "sha256": hashlib.sha256(data).hexdigest(),
                        },
                    )
                message = json.loads(request.content)
                if message["method"] == "hooks/configuration":
                    return httpx.Response(
                        200,
                        json={
                            "jsonrpc": "2.0",
                            "id": message["id"],
                            "result": {
                                "protocolVersion": "draft",
                                "configuration": config_value,
                            },
                        },
                    )
                body = message["params"]["event"]["items"][0]["parts"][0]["body"]
                self.assertEqual(body, {"ref": "urn:uploaded:pdf"})
                return httpx.Response(
                    200,
                    json={
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "result": {"protocolVersion": "draft", "effects": []},
                    },
                )

            value = registration()
            backend = value["hooks"][0]
            backend["transport"] = {
                "type": "http",
                "url": "https://policy.example/hooks",
                "headers": {"Authorization": "Bearer approved-header"},
            }

            def authorize(backend_snapshot, configuration):
                return (
                    configuration.subscriptions[0]["upload"]["endpoint"]
                    == "https://approved.example/upload"
                    and backend_snapshot["transport"]["headers"]["Authorization"]
                    == "Bearer approved-header"
                )

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(respond)
            ) as http:
                transport = AuthenticatedHTTPTransport(
                    backend["transport"]["url"], backend=backend, client=http
                )
                async with Hooks(
                    value,
                    source="urn:test",
                    harness=event.Harness(name="test", version="1"),
                    capabilities=capability.HostCapabilities(
                        context_compact_before=capability.ContextCompactBeforeCapabilities(
                            intercept=capability.ContextCompactBeforeIntercept(
                                message=True
                            )
                        )
                    ),
                    transport=transport,
                    authorize_configuration=authorize,
                ) as hooks:
                    upload_config = hooks.config["hooks"][0]["subscriptions"][0][
                        "upload"
                    ]

                    async def upload(data):
                        return await transport.upload(upload_config["endpoint"], data)

                    result = await hooks.context_compact_before(
                        owned_payload(Stream()), uploads={"org.example.hook": upload}
                    )
                    self.assertEqual(result.diagnostics, [])
                    await result.aclose()
            self.assertEqual(len(seen), 3)
            self.assertTrue(
                all(
                    request.headers["authorization"] == "Bearer approved-header"
                    for request in seen
                )
            )

        self.run_async(run)

    def test_configuration_authorizer_denial_and_failure_skip(self):
        async def run():
            value = advertised()
            value["subscriptions"][0]["upload"] = {
                "endpoint": "https://upload.example/content",
                "timeoutMs": 1000,
                "maxBytes": 1000,
            }

            def denied(backend, configuration):
                return False

            def failed(backend, configuration):
                raise RuntimeError("do not expose secret failure text")

            for callback in (denied, failed):
                async with client(
                    transport=Transport(value), authorize_configuration=callback
                ) as hooks:
                    self.assertEqual(hooks.config["hooks"], [])
                    self.assertNotIn("secret", repr(hooks.configuration_diagnostics))

        self.run_async(run)

    def test_explicit_upload_configuration_bypasses_authorizer(self):
        async def run():
            value = config()
            value["hooks"][0]["subscriptions"][0]["upload"] = {
                "endpoint": "https://upload.example/content",
                "timeoutMs": 1000,
                "maxBytes": 1000,
            }

            def forbidden(backend, configuration):
                raise AssertionError(
                    "explicit configuration must not invoke authorization"
                )

            transport = Transport(
                error=AssertionError("explicit configuration must not discover")
            )
            async with client(
                value, transport=transport, authorize_configuration=forbidden
            ) as hooks:
                self.assertTrue(hooks.intercepts(event.TOOL_BEFORE))
                self.assertEqual(transport.calls, [])

        self.run_async(run)

    def test_cancellation_propagates_instead_of_skip(self):
        async def run():
            hooks = client(
                transport=Transport(error=OperationCancelledError("cancelled"))
            )
            try:
                with self.assertRaises(OperationCancelledError):
                    await hooks.__aenter__()
                self.assertEqual(hooks.configuration_diagnostics, [])
            finally:
                await hooks.aclose()

        self.run_async(run)

    def test_stdio_discovery_uses_existing_transport(self):
        async def run():
            value = registration()
            value["hooks"][0]["transport"].update(
                {
                    "command": sys.executable,
                    "lifecycle": "per_event",
                    "args": [
                        "-u",
                        "-c",
                        "import sys,json; m=json.loads(sys.stdin.readline()); print(json.dumps({'jsonrpc':'2.0','id':m['id'],'result':{'protocolVersion':'draft','configuration':"
                        + repr(advertised())
                        + "}}))",
                    ],
                }
            )
            async with client(value) as hooks:
                self.assertTrue(hooks.intercepts("tool.before"))
                self.assertEqual(hooks.configuration_diagnostics, [])

        self.run_async(run)

    def test_authenticated_http_discovery_preserves_endpoint_headers(self):
        async def run():
            import httpx
            from agenthooksprotocol.auth import AuthenticatedHTTPTransport

            seen = []
            engine = Engine(Handlers(), configuration=advertised())

            async def respond(request):
                seen.append(request)
                return httpx.Response(
                    200, json=await engine.process(json.loads(request.content))
                )

            value = registration()
            value["hooks"][0]["transport"] = {
                "type": "http",
                "url": "https://policy.example/hooks",
                "headers": {"Authorization": "Bearer configured", "X-Policy": "chosen"},
            }
            async with httpx.AsyncClient(
                transport=httpx.MockTransport(respond)
            ) as http:
                transport = AuthenticatedHTTPTransport(
                    "https://policy.example/hooks",
                    backend=value["hooks"][0],
                    client=http,
                )
                async with client(value, transport=transport) as hooks:
                    self.assertTrue(hooks.intercepts("tool.before"))
                self.assertFalse(http.is_closed)
            self.assertEqual(len(seen), 1)
            self.assertEqual(str(seen[0].url), "https://policy.example/hooks")
            self.assertEqual(seen[0].headers["authorization"], "Bearer configured")
            self.assertEqual(seen[0].headers["x-policy"], "chosen")

        self.run_async(run)

    def test_discovery_then_dispatch_uses_existing_event_handler(self):
        async def run():
            from agenthooksprotocol.server import hooks as server

            observed = []

            def before(context):
                observed.append(context)
                return server.ToolBeforeReply(effects=())

            engine = Engine(
                Handlers(intercept=server.InterceptHandlers(tool_before=before)),
                configuration=advertised(),
            )

            class EngineTransport(Transport):
                async def request(self, message):
                    self.calls.append(deepcopy(message))
                    return await engine.process(message)

            transport = EngineTransport()
            async with client(transport=transport) as hooks:
                result = await hooks.tool_before(
                    event.ToolBeforeInput(
                        call_id="call-1",
                        name="read_file",
                        input={"path": "file.txt"},
                        path="native",
                        origin="native",
                    )
                )
                await result.aclose()
                self.assertEqual(len(observed), 1)
                self.assertIn("deny", observed[0].capabilities.effects)
                self.assertEqual(
                    [m["method"] for m in transport.calls],
                    ["hooks/configuration", "hooks/intercept"],
                )

        self.run_async(run)

    def test_discovery_auth_challenge_has_one_bounded_retry(self):
        async def run():
            import httpx
            from agenthooksprotocol.auth import AuthenticatedHTTPTransport
            from test_registration_auth import Provider

            seen = []
            provider = Provider()
            engine = Engine(Handlers(), configuration=advertised())

            async def respond(request):
                seen.append(request)
                if len(seen) == 1:
                    return httpx.Response(401, headers={"WWW-Authenticate": "Bearer"})
                return httpx.Response(
                    200, json=await engine.process(json.loads(request.content))
                )

            value = registration()
            backend = value["hooks"][0]
            backend["transport"] = {
                "type": "http",
                "url": "https://policy.example/hooks",
            }
            backend["authentication"] = {"type": "bearer", "tokenRef": "configured/key"}
            async with httpx.AsyncClient(
                transport=httpx.MockTransport(respond)
            ) as http:
                transport = AuthenticatedHTTPTransport(
                    backend["transport"]["url"],
                    backend=backend,
                    client=http,
                    auth_provider=provider,
                )
                async with client(value, transport=transport) as hooks:
                    self.assertTrue(hooks.intercepts(event.TOOL_BEFORE))
            self.assertEqual(len(seen), 2)
            self.assertEqual(seen[0].content, seen[1].content)
            self.assertEqual(seen[0].headers["authorization"], "Bearer old-secret")
            self.assertEqual(seen[1].headers["authorization"], "Bearer new-secret")
            self.assertTrue(provider.challenges[0].retry_allowed)

        self.run_async(run)

    def test_shared_public_configuration_and_duration(self):
        subscriptions = [
            subscription.Intercept(
                events=[event.TOOL_BEFORE],
                timeout=timedelta(milliseconds=750),
                failure_policy=subscription.FailurePolicy.FAIL_OPEN,
                content=content.metadata(),
            )
        ]
        configuration = Configuration(subscriptions=subscriptions)
        self.assertEqual(configuration.subscriptions[0]["timeoutMs"], 750)
        self.assertEqual(configuration.subscriptions[0]["mode"], "intercept")
        engine = Engine(Handlers(), configuration=configuration)
        value = config()
        value["hooks"][0]["subscriptions"] = configuration.subscriptions
        # Both server and client admit the same public declaration.
        hooks = client(value, transport=Transport())
        self.assertTrue(hooks.intercepts(event.TOOL_BEFORE))
        self.assertEqual(engine.configuration, configuration)
        for timeout in (
            timedelta(0),
            timedelta(microseconds=1),
            timedelta(milliseconds=-1),
        ):
            with (
                self.subTest(timeout=timeout),
                self.assertRaises((ValueError, TypeError)),
            ):
                subscription.Intercept(
                    events=[event.TOOL_BEFORE],
                    timeout=timeout,
                    failure_policy=subscription.FailurePolicy.FAIL_OPEN,
                    content=content.metadata(),
                )

    def test_discovery_timeout_is_bounded_and_retires_request(self):
        async def run():
            class SlowTransport(Transport):
                active = False

                async def request(self, message):
                    self.active = True
                    try:
                        await anyio.sleep_forever()
                    finally:
                        self.active = False

            transport = SlowTransport()
            with patch(
                "agenthooksprotocol._hooks._CONFIGURATION_TIMEOUT_SECONDS", 0.01
            ):
                async with client(transport=transport) as hooks:
                    self.assertFalse(transport.active)
                    self.assertEqual(hooks.config["hooks"], [])
                    self.assertEqual(
                        hooks.configuration_diagnostics[0]["reason"],
                        "configuration_unavailable",
                    )

        self.run_async(run)

    def test_shutdown_cancels_initialization(self):
        async def run():
            entered = anyio.Event()
            retired = anyio.Event()

            class WaitingTransport(Transport):
                async def request(self, message):
                    entered.set()
                    try:
                        await anyio.sleep_forever()
                    finally:
                        retired.set()

            hooks = client(transport=WaitingTransport())

            async def initialize():
                with self.assertRaises(OperationCancelledError):
                    await hooks.__aenter__()

            async with anyio.create_task_group() as tasks:
                tasks.start_soon(initialize)
                await entered.wait()
                await hooks.aclose()
                self.assertTrue(retired.is_set())
                self.assertEqual(hooks.configuration_diagnostics, [])

        self.run_async(run)

    def test_content_helpers(self):
        self.assertEqual(dict(content.metadata()), {"default": "metadata"})
        self.assertEqual(dict(content.body()), {"default": "body"})
        self.assertEqual(dict(content.omit()), {"default": "omit"})
