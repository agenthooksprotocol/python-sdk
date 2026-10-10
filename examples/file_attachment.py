"""Keep a lazily read local file with a typed event result after Hooks closes.

Run: uv run python examples/file_attachment.py path/to/report.pdf
The attachment is the sole byte owner; no receiver or content store is needed.
"""

from pathlib import Path
import sys

import anyio

from agenthooksprotocol import Attachment, Hooks
from agenthooksprotocol.event import ContextCompactBeforeInput


async def main(path: Path) -> None:
    async def load() -> bytes:
        # Bound the allocation as well as the attachment's accepted size.
        async with await anyio.open_file(path, "rb") as stream:
            return await stream.read(4 * 1024 * 1024 + 1)

    attachment = Attachment.lazy(load)
    event = ContextCompactBeforeInput(
        trigger="manual",
        items=[
            {
                "role": "user",
                "parts": [
                    {"kind": "text", "text": "Review this report."},
                    {
                        "kind": "attachment",
                        "mediaType": "application/pdf",
                        "body": attachment,
                    },
                ],
            }
        ],
    )
    async with Hooks(
        {
            "protocolVersion": "draft",
            "hooks": [
                {
                    "id": "org.example.review",
                    "transport": {
                        "type": "http",
                        "url": "https://review.example/hooks",
                    },
                    "subscriptions": [
                        {
                            "events": ["context.compact.after"],
                            "mode": "observe",
                            "content": {"default": "metadata"},
                        }
                    ],
                }
            ],
        },
        source="urn:example:file-review",
        max_concurrent_uploads=8,
        capabilities={
            "context.compact.after": {
                "modes": ["observe"],
                "capabilities": {"effects": []},
            },
            "context.compact.before": {
                "modes": ["intercept"],
                "capabilities": {"effects": []},
            },
        },
    ) as hooks:
        result = await hooks.context_compact_before(event)
        # No matching receiver: the file has not been opened.
    async with result:
        body = await result.attachments.read("context.compact.before.items_parts[0][1]")
        print(f"Retained {path.name}: {len(body)} bytes")


if __name__ == "__main__":
    anyio.run(main, Path(sys.argv[1]))
