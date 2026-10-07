"""Optional HTTPX transport (install agenthooksprotocol[http])."""

from typing import Any, AsyncIterable
from ..runtime import ProtocolError, Validator, validate_intercept_response


class HTTPTransport:
    def __init__(
        self,
        url: str,
        *,
        client: Any = None,
        headers: dict[str, str] | None = None,
        validator: Any = None,
    ) -> None:
        self._validator = validator if validator is not None else Validator()
        self.url = url
        self.headers = dict(headers or {})
        self._client = client
        self._owned = client is None

    def _ready(self):
        if self._client is None:
            try:
                import httpx
            except ImportError as exc:
                raise ImportError(
                    "HTTP transport requires agenthooksprotocol[http]"
                ) from exc
            self._client = httpx.AsyncClient(follow_redirects=False)
        return self._client

    async def request(self, message: dict[str, Any]) -> dict[str, Any]:
        response = await self._ready().post(
            self.url, json=message, headers=self.headers, follow_redirects=False
        )
        try:
            result = response.json()
        except (ValueError, UnicodeError):
            response.raise_for_status()
            raise ProtocolError("Malformed HTTP protocol response") from None
        if (
            message.get("method") == "hooks/intercept"
            and isinstance(result, dict)
            and "error" in result
        ):
            validate_intercept_response(self._validator, message, result)
        response.raise_for_status()
        if not isinstance(result, dict) or result.get("id") != message["id"]:
            raise ProtocolError("HTTP response correlation mismatch")
        if message.get("method") == "hooks/intercept":
            validate_intercept_response(self._validator, message, result)
        return result

    async def notify(self, message: dict[str, Any]) -> None:
        response = await self._ready().post(
            self.url, json=message, headers=self.headers, follow_redirects=False
        )
        response.raise_for_status()
        # Never parse or grant authority to an observation acknowledgment.
        if response.content:
            raise ProtocolError("Unexpected observation response body")

    async def aclose(self) -> None:
        if self._owned and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def upload(
        self,
        url: str,
        body: bytes | AsyncIterable[bytes],
        *,
        headers: dict[str, str] | None = None,
        selection: str = "body",
        size: int | None = None,
        sha256: str | None = None,
    ) -> dict[str, Any] | None:
        """Upload bytes or an async byte stream; streams require size and sha256.

        Metadata/omit never read the body. Receiver credentials are explicit and
        isolated from event headers. Publication requires verified stream EOF.
        """
        if selection in ("metadata", "omit"):
            return None
        if selection != "body":
            raise ValueError("Unknown content selection")
        import hashlib
        import json
        import httpx

        validator = self._validator
        actual = hashlib.sha256()
        count = 0
        complete = False
        if isinstance(body, bytes):
            digest = hashlib.sha256(body).hexdigest()
            if (size is not None and size != len(body)) or (
                sha256 is not None and sha256 != digest
            ):
                raise ProtocolError("Content declaration does not match bytes")
            size, sha256 = len(body), digest
        elif size is None or sha256 is None or size < 0:
            raise ProtocolError("Stream upload requires size and sha256")

        async def stream():
            nonlocal count, complete
            if isinstance(body, bytes):
                actual.update(body)
                count = len(body)
                yield body
            else:
                async for chunk in body:
                    if not isinstance(chunk, bytes):
                        raise TypeError("Content stream must yield bytes")
                    count += len(chunk)
                    if count > size:
                        raise ProtocolError("Content stream exceeds declared size")
                    actual.update(chunk)
                    yield chunk
            if count != size or actual.hexdigest() != sha256:
                raise ProtocolError("Content stream EOF does not match declaration")
            complete = True

        upload_headers = dict(headers or {})
        upload_headers.update(
            {
                "Content-Type": "application/octet-stream",
                "Content-Length": str(size),
                "AHP-Content-SHA256": sha256,
            }
        )
        # Fresh request bypasses borrowed-client default headers/cookies/auth.
        request = httpx.Request("POST", url, content=stream(), headers=upload_headers)
        response = await self._ready().send(request, auth=None, follow_redirects=False)
        if not complete:
            raise ProtocolError("Receiver replied before valid content EOF")
        if response.status_code != 201:
            raise ProtocolError("Content upload requires a 201 descriptor response")
        descriptor = json.loads(response.content)
        validator.validate("content-reference", descriptor)
        if descriptor["size"] != count or descriptor["sha256"] != actual.hexdigest():
            raise ProtocolError("Content descriptor does not match uploaded bytes")
        return descriptor
