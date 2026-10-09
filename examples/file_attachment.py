"""Keep a lazily read local file with a typed event result after Hooks closes.

Run: uv run python examples/file_attachment.py path/to/report.pdf
No receiver or external content store is needed for this standalone example.
"""

from pathlib import Path
import sys

import anyio

from agenthooksprotocol import Attachment, Hooks, ModelVisibleItemMetadata
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
            ModelVisibleItemMetadata(
                id="report",
                kind="content",
                role="user",
                media_type="application/pdf",
                selection="metadata",
            )
        ],
    ).bind_items_source(attachment, index=0)
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
        body = await result.attachments.read("context.compact.before.items[0]")
        print(f"Retained {path.name}: {len(body)} bytes")


if __name__ == "__main__":
    anyio.run(main, Path(sys.argv[1]))
