"""Canonical attachment framing checks, independent of fixture transports."""

import hashlib
import re

from ..runtime import ProtocolError


def validate_upload_framing(headers, data):
    for name in (
        "Content-Type",
        "Content-Length",
        "AHP-Content-SHA256",
        "Authorization",
    ):
        if len(headers.get_all(name, [])) > 1:
            raise ProtocolError("Duplicate upload framing")
    if (
        headers.get("Content-Type") != "application/octet-stream"
        or any(
            headers.get(name) is not None
            for name in (
                "Content-Encoding",
                "Transfer-Encoding",
                "AHP-Subscription",
                "AHP-Content-Ref",
            )
        )
        or not re.fullmatch(r"0|[1-9][0-9]*", headers.get("Content-Length", ""))
        or int(headers["Content-Length"]) != len(data)
        or headers.get("AHP-Content-SHA256") != hashlib.sha256(data).hexdigest()
    ):
        raise ProtocolError("Invalid upload framing")
