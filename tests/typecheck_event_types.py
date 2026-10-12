"""Compile external event-name consumers against the installed SDK."""

from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import get_args

from agenthooksprotocol.event import EventType


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    names = get_args(EventType)
    assert len(names) == 32 and len(set(names)) == 32
    lines = [
        "from typing import assert_type",
        "from agenthooksprotocol import Hooks, EventType",
        "from agenthooksprotocol.response import response_for_request",
        "async def positive(h: Hooks) -> None:",
    ]
    for name in names:
        lines.extend(
            [
                f"    name: EventType = {name!r}"
                if name == names[0]
                else f"    name = {name!r}",
                "    assert_type(h.subscribes(name), bool)",
                "    await h.dispatch(name, {})",
                "    response_for_request(name, {})",
            ]
        )
    lines.extend(
        [
            "async def negative(h: Hooks, dynamic: str) -> None:",
            "    h.subscribes(dynamic)  # type-error",
            "    h.subscribes('unknown.event')  # type-error",
            "    h.subscribes('tool.*')  # type-error",
            "    await h.dispatch(dynamic, {})  # type-error",
            "    await h.dispatch('unknown.event', {})  # type-error",
            "    response_for_request(dynamic, {})  # type-error",
            "    response_for_request('unknown.event', {})  # type-error",
        ]
    )
    expected = {index for index, line in enumerate(lines, 1) if "# type-error" in line}
    with tempfile.TemporaryDirectory(prefix="ahp-event-consumer-") as temporary:
        consumer = Path(temporary) / "consumer.py"
        consumer.write_text("\n".join(lines) + "\n")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "mypy",
                "--strict",
                "--follow-imports=silent",
                str(consumer),
            ],
            cwd=root,
            text=True,
            capture_output=True,
            timeout=60,
        )
        actual = {
            int(line)
            for line in re.findall(r"consumer.py:(\d+): error:", result.stdout)
        }
        assert result.returncode != 0 and actual == expected, (
            result.stdout + result.stderr
        )
    print(
        "EventType consumers: all 32 names pass; all 7 dynamic/unknown/selector negatives rejected"
    )


if __name__ == "__main__":
    main()
