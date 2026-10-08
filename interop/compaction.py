#!/usr/bin/env python3
"""Offline host fixture. Actual SDK runtime; orchestration is not AHP wire API."""

import json, os, subprocess, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.request import Request
from agenthooksprotocol.interop import run_fixture_compaction
from agenthooksprotocol.interop import open_local, loads, LIMIT


def settle(snapshot, row):
    """Run one offline backend through the same public content lifecycle as wire."""
    from agenthooksprotocol import ContentContext
    from agenthooksprotocol.server.hooks import Handler, InterceptResult
    from agenthooksprotocol.interop import fixture_hooks
    import anyio
    import hashlib
    import uuid

    store = {}

    async def upload(data):
        reference = {
            "ref": "urn:fixture:" + str(uuid.uuid4()),
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        store[reference["ref"]] = data
        return reference

    async def resolve(reference):
        return store[reference["ref"]]

    async def invoke():
        boundary = snapshot["boundary"]
        target = "instructions" if boundary == "before" else "summary"
        text = (
            snapshot["instructions"]
            if boundary == "before"
            else snapshot["bodies"][snapshot["summary"]["ref"]]
        )
        event = {
            "id": "fixture:" + boundary,
            "source": "urn:ahp:compaction-host",
            "time": "2026-09-15T12:00:00Z",
            "session": {"id": "fixture"},
            "type": "context.compact." + boundary,
        }
        event[target] = {
            "id": target,
            "kind": target,
            "mediaType": "text/plain",
            "role": "system" if boundary == "before" else "assistant",
            "selection": "body",
            "body": {"ref": (await upload(text.encode("utf-8")))["ref"]},
        }
        if boundary == "before":
            event.update(trigger="manual", items=[])
        else:
            event.update(
                parentEventId="fixture:before",
                removed=[],
                execution={"status": "executed"},
            )
        note = {
            "jsonrpc": "2.0",
            "method": "hooks/observe",
            "params": {"protocolVersion": "draft", "event": event},
        }

        async def respond(message):
            if row.get("throw", False):
                raise ValueError("hook failed")
            return InterceptResult(effects=row["effects"])

        async def observe(message):
            if row.get("throw", False):
                raise ValueError("observer failed")
            # Notification callbacks have no response/effect authority.

        if snapshot.get("applied"):

            class NotificationTransport:
                async def notify(self, message):
                    await Handler(observe=observe).process(message)

            async with fixture_hooks(note, NotificationTransport()) as hooks:
                await hooks.notify(note)
            return None
        candidate = snapshot["candidate"]
        request = {
            "jsonrpc": "2.0",
            "id": event["id"],
            "method": "hooks/intercept",
            "params": {
                "protocolVersion": "draft",
                "event": event,
                "capabilities": snapshot["capabilities"],
                "state": {
                    "permission": "none",
                    "candidate": {"value": candidate["body"]} if candidate else None,
                },
            },
        }

        class Transport:
            async def request(self, message):
                return await Handler(intercept=respond).process(message)

        context = ContentContext(
            resolve=resolve,
            upload=upload,
            bindings={target: (target,)},
            principal=row["supplier"],
        )
        async with fixture_hooks(request, Transport()) as hooks:
            return await hooks.exchange(request, content=context)

    return anyio.run(invoke)


def receive(request):
    try:
        if request.get("jsonrpc") != "2.0" or request.get("method") != "compaction/run":
            raise ValueError("invalid request")
        p = request["params"]

        def hooks(boundary):
            rows = p.get(boundary, [])
            if not isinstance(rows, list):
                raise ValueError("invalid hooks")
            result = []
            for row in rows:

                def run(snapshot, row=row):
                    return settle(snapshot, row)

                result.append(
                    (row["supplier"], row.get("failurePolicy", "fail-closed"), run)
                )
            return result

        result = run_fixture_compaction(
            p["instructions"],
            hooks("before"),
            hooks("after"),
            item_id=p.get("itemId", "summary-1"),
            observe_only=p.get("observeOnly", False),
        )
        return {"jsonrpc": "2.0", "id": request.get("id"), "result": result}
    except Exception:
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "error": {"code": -32602, "message": "invalid request"},
        }


def main():
    mode = sys.argv[1]
    if mode == "stdio":
        for line in sys.stdin:
            print(json.dumps(receive(json.loads(line)), ensure_ascii=False), flush=True)
    elif mode == "server":

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                if (
                    len(self.headers.get_all("Authorization", [])) != 1
                    or self.headers.get("Authorization")
                    != "Bearer " + os.environ["AHP_COMPACTION_TOKEN"]
                ):
                    self.send_response(401)
                    self.end_headers()
                    return
                try:
                    self.connection.settimeout(10)
                    size = int(self.headers.get("Content-Length", "-1"))
                    if size < 0 or size > LIMIT:
                        raise ValueError("invalid size")
                    raw = self.rfile.read(size)
                    if len(raw) != size:
                        raise ValueError("invalid length")
                    request = loads(raw)
                except (ValueError, OSError):
                    self.send_response(400)
                    self.end_headers()
                    return
                body = json.dumps(receive(request), ensure_ascii=False).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = HTTPServer(("127.0.0.1", 0), Handler)
        print(
            json.dumps({"endpoint": "http://127.0.0.1:" + str(server.server_port)}),
            flush=True,
        )
        server.serve_forever()
    elif mode == "client":
        plan = json.load(sys.stdin)
        if plan["transport"] == "stdio":
            payload = "".join(
                json.dumps(r, ensure_ascii=False) + "\n" for r in plan["requests"]
            )
            out = subprocess.run(
                plan["command"] + ["stdio"],
                input=payload,
                capture_output=True,
                text=True,
                timeout=60,
                check=True,
            )
            replies = [json.loads(line) for line in out.stdout.splitlines()]
        else:
            replies = []
            for request in plan["requests"]:
                wire = Request(
                    plan["endpoint"],
                    json.dumps(request, ensure_ascii=False).encode(),
                    {
                        "Authorization": "Bearer " + plan["token"],
                        "Content-Type": "application/json",
                    },
                )
                with open_local(wire) as response:
                    replies.append(loads(response.read(LIMIT + 1)))
        print(json.dumps(replies, ensure_ascii=False))
    else:
        raise ValueError("unknown mode")


if __name__ == "__main__":
    main()
