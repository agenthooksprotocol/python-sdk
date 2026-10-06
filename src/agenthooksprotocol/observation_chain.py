"""Exercise the public SDK chain over the fixture's real, controlled transports.

The adapter owns receiver barriers and the deliberately late cancelled-response
probe. Hooks owns serial interception, failure policy, content projection and
observation selection. Local reports come from actual transport invocations and
settled SDK results, never from the scenario's expected receipt lists.
"""

from copy import deepcopy
from functools import partial

import anyio

from . import Hooks


def run_chain(scenario, transport, validator):
    async def run():
        chain = scenario["chain"]
        original = deepcopy(scenario["requests"]["a"])
        validator.validate("intercept-request", original)
        event = original["params"]["event"]
        ident = original["id"]
        called, observed, pending = [], [], []
        registrations, adapters, subscription_ids = [], {}, {}
        result = None

        async def control(path, value):
            return await anyio.to_thread.run_sync(transport.control, path, value)

        class ChainTransport:
            def __init__(self, subscription):
                self.subscription = subscription

            async def request(self, message):
                called.append(self.subscription["id"])
                future = transport.send(message)
                pending.append(future)
                await control("/wait", {"id": ident, "count": len(called)})
                if chain.get("interrupt"):
                    await control(
                        "/mark",
                        {
                            "scenario": scenario["id"],
                            "kind": "cancelled",
                            "id": ident,
                        },
                    )
                    # Cancel the owning SDK operation while the receiver still
                    # holds its response. No settlement or observation loop is
                    # implemented in this adapter.
                    call_scope.cancel()
                    await anyio.lowlevel.checkpoint()
                await control("/release", {"id": ident})
                try:
                    return await anyio.to_thread.run_sync(
                        partial(future.result, timeout=15)
                    )
                finally:
                    pending.remove(future)

            async def notify(self, message):
                observed.append(self.subscription["id"])
                # The fixture can deliberately block receiver processing. Its
                # release is host-owned synchronization, scoped to this send.
                async with anyio.create_task_group() as group:
                    group.start_soon(
                        anyio.to_thread.run_sync, transport.observe, message
                    )
                    await control(
                        "/wait-observed", {"eventId": ident, "count": len(observed)}
                    )
                    if chain.get("holdObservers"):
                        await control("/release", {"id": ident + ":observers"})

        for index, subscription in enumerate(chain["subscriptions"]):
            # Preserve authored subscription order, including registrations
            # sharing one physical endpoint. These IDs stay SDK-local.
            backend = f"org.agenthooksprotocol.chain{index}"
            subscription_ids[backend] = subscription["id"]
            adapters[backend] = ChainTransport(subscription)
            declaration = {
                "events": [event["type"]],
                "mode": subscription["mode"],
                "content": {"default": subscription["content"]},
            }
            if subscription["mode"] == "intercept":
                declaration.update(
                    timeoutMs=15000, failurePolicy=subscription["failurePolicy"]
                )
            registrations.append(
                {
                    "id": backend,
                    "transport": {"type": "http", "url": "http://127.0.0.1/fixture"},
                    "subscriptions": [declaration],
                }
            )

        async with Hooks(
            {
                "protocolVersion": original["params"]["protocolVersion"],
                "hooks": registrations,
            },
            source=event["source"],
            capabilities={
                event["type"]: {
                    "modes": ["intercept", "observe"],
                    "capabilities": original["params"]["capabilities"],
                }
            },
            transport=adapters,
        ) as hooks:
            with anyio.CancelScope() as call_scope:
                result = await hooks.dispatch(
                    event["type"],
                    event,
                    initial_state=original["params"].get("state"),
                    event_id=ident,
                )
            await control(
                "/mark",
                {
                    "scenario": scenario["id"],
                    "kind": "chain-settled",
                    "id": ident,
                },
            )
            # Only the adversarial transport probe survives cancellation: its
            # late response is drained after the stopped milestone and is never
            # offered to SDK acceptance or used to initiate another delivery.
            if pending:
                await control("/release", {"id": ident})
                for future in pending:
                    await anyio.to_thread.run_sync(partial(future.result, timeout=15))

        return {
            "called": called,
            "failures": []
            if result is None
            else [
                subscription_ids[diagnostic["backend"]]
                for diagnostic in result.diagnostics
                if diagnostic["mode"] == "intercept"
            ],
            "observations": observed,
            "input": deepcopy(event["tool"]["input"])
            if result is None
            else result.input,
        }

    return anyio.run(run)
