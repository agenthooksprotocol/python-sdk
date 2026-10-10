#!/usr/bin/env python3
"""Canonical hooks/intercept fixture. Scheduling is local, never a wire method."""

import hashlib, json, os, subprocess, sys, uuid
import anyio
from agenthooksprotocol.server.hooks import Handler as HookHandler, InterceptResult
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.request import Request
from agenthooksprotocol.interop import run_fixture_compaction
from agenthooksprotocol.runtime import Validator
from agenthooksprotocol.interop import (
    open_local,
    loads,
    validate_upload_framing,
)


def digest(b):
    return hashlib.sha256(b).hexdigest()


def location(store, scope, ref):
    return Path(store) / digest((scope + "\0" + ref).encode())


def receive(request, sub, config, store, validator):
    try:
        validator.validate("intercept-request", request)
        if request["id"] != request["params"]["event"]["id"]:
            raise ValueError("correlation")

        async def intercept(message):
            event = message["params"]["event"]
            action = config[sub]
            if action["kind"] == "append":
                item = event[action["target"]]
                effects = [
                    {
                        "type": "modify",
                        "target": action["target"],
                        "operation": "replace",
                        "value": [
                            {
                                "id": action["target"] + ":appended",
                                "kind": "text",
                                "mediaType": "text/plain",
                                "selection": "body",
                                "text": "".join(part["text"] for part in item)
                                + action["suffix"],
                            }
                        ],
                    }
                ]
            else:
                effects = action["effects"]
            return InterceptResult(effects=effects)

        async def process():
            return await HookHandler(intercept=intercept).process(request)

        response = anyio.run(process)
        with open(Path(store) / "receipts.jsonl", "a") as f:
            f.write(
                json.dumps(
                    {
                        "subscription": sub,
                        "request": request,
                        "response": response,
                    }
                )
                + "\n"
            )
        return response
    except Exception:
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "error": {"code": -32602, "message": "Invalid compaction request"},
        }


def exchange(plan, sub, name, snapshot, validator, trace):
    credential = plan["credentials"][sub]
    event = {
        "id": name + ":" + snapshot["boundary"],
        "source": "urn:ahp:compaction-host",
        "time": "2026-09-15T12:00:00Z",
        "session": {"id": name},
        "type": "context.compact." + snapshot["boundary"],
    }

    if snapshot["boundary"] == "before":
        event.update(
            trigger="manual",
            items=[
                {
                    "id": name + ":context",
                    "role": "user",
                    "parts": [
                        {
                            "id": name + ":context:text",
                            "kind": "text",
                            "mediaType": "text/plain",
                            "selection": "body",
                            "text": "conversation",
                        }
                    ],
                }
            ],
            instructions=snapshot["instructions"],
        )
    else:
        candidate = snapshot["candidate"]
        event.update(
            parentEventId=name + ":before",
            summary=snapshot["summary"],
            removed=[{"id": name + ":context"}],
            execution={"status": "executed"}
            if candidate is None
            else {"status": "skipped", "reason": "supplied_result"},
        )
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
                "candidate": {"value": snapshot["candidate"]["value"]}
                if snapshot["candidate"]
                else None,
            },
        },
    }
    validator.validate("intercept-request", request)
    if plan["transport"] == "http":
        headers = {
            "Authorization": "Bearer " + credential["token"],
            "Content-Type": "application/json",
        }
        with open_local(
            Request(
                plan["endpoint"] + "/hooks/intercept",
                json.dumps(request).encode(),
                headers,
            )
        ) as r:
            response = loads(r.read(4 * 1024 * 1024 + 1))
    else:
        child = subprocess.run(
            plan["receiverCommand"] + ["stdio", sub],
            input=json.dumps(request) + "\n",
            text=True,
            capture_output=True,
            check=True,
            timeout=20,
        )
        response = json.loads(child.stdout)
    trace.append({"subscription": sub, "request": request, "response": response})
    validator.validate("intercept-response", response)
    if response["id"] != request["id"]:
        raise ValueError("correlation")
    from agenthooksprotocol.interop import fixture_hooks

    async def settle():
        invocation = fixture_hooks(request).begin(request)
        invocation.receive(response)
        return invocation.accept()

    return anyio.run(settle)


def main():
    mode = sys.argv[1]
    if mode == "host":
        plan = json.load(sys.stdin)
        validator = Validator(plan["schema"])
        out = []
        for row in plan["cases"]:
            trace = []

            def hooks(boundary):
                return [
                    (
                        h["supplier"],
                        h["failurePolicy"],
                        lambda snapshot, h=h: exchange(
                            plan, h["supplier"], row["name"], snapshot, validator, trace
                        ),
                    )
                    for h in row[boundary]
                ]

            result = run_fixture_compaction(
                "base",
                hooks("before"),
                hooks("after"),
                item_id=row["name"] + ":summary",
            )
            downstream = []
            if result["applied"]:
                # The fixture delivery trace remains plain text; settled state is inline.
                downstream.append("".join(part["text"] for part in result["summary"]))
            out.append(
                {
                    "name": row["name"],
                    "result": result,
                    "trace": trace,
                    "downstream": downstream,
                }
            )
        print(json.dumps(out))
        return
    schema, store, config_path = sys.argv[2:5]
    validator = Validator(schema)
    config = json.loads(Path(config_path).read_text())
    if mode == "stdio":
        sub = sys.argv[5]
        for line in sys.stdin:
            print(
                json.dumps(receive(json.loads(line), sub, config, store, validator)),
                flush=True,
            )
        return

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            upload = self.path == "/upload"
            credentials = json.loads(
                os.environ.get(
                    "AHP_COMPACTION_UPLOAD_TOKENS"
                    if upload
                    else "AHP_COMPACTION_TOKENS",
                    "{}",
                )
            )
            authorization = self.headers.get("Authorization", "")
            sub = (
                credentials.get(authorization[7:])
                if authorization.startswith("Bearer ")
                else None
            )
            if len(self.headers.get_all("Authorization", [])) != 1 or sub is None:
                self.send_response(401)
                self.end_headers()
                return
            if sub not in config:
                self.send_response(403)
                self.end_headers()
                return
            if self.path not in ("/upload", "/hooks/intercept"):
                self.send_response(404)
                self.end_headers()
                return
            try:
                if len(self.headers.get_all("Authorization", [])) != 1:
                    raise ValueError("authorization")
                size = int(self.headers.get("Content-Length", "-1"))
                if size < 0 or size > 4 * 1024 * 1024:
                    raise ValueError("size")
                self.connection.settimeout(10)
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise ValueError("length")
                if upload:
                    validate_upload_framing(self.headers, raw)
                    ref = "urn:uuid:" + str(uuid.uuid4())
                    path = location(store, sub, ref)
                    with path.open("xb") as output:
                        output.write(raw)
                    body = json.dumps(
                        {"ref": ref, "size": len(raw), "sha256": digest(raw)}
                    ).encode()
                    self.send_response(201)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                response = receive(json.loads(raw), sub, config, store, validator)
                body = json.dumps(response).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except Exception:
                self.send_response(400)
                self.end_headers()

    server = HTTPServer(("127.0.0.1", 0), Handler)
    print(
        json.dumps({"endpoint": "http://127.0.0.1:" + str(server.server_port)}),
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    # Receiver command carries immutable local startup configuration before mode.
    if len(sys.argv) > 1 and sys.argv[1] not in ("host", "server", "stdio"):
        sys.argv = [sys.argv[0], sys.argv[4], *sys.argv[1:4], *sys.argv[5:]]
    main()
