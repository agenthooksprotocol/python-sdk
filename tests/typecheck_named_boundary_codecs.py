"""Check all generated codec combinations against the real SDK (no seam stubs).

Run with the SDK source on PYTHONPATH and mypy installed in the interpreter.
"""

from __future__ import annotations

import ast
from pathlib import Path
import subprocess
import sys
import tempfile


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    tree = ast.parse((root / "src/agenthooksprotocol/_boundaries.py").read_text())
    methods = [
        node.name
        for owner in tree.body
        if isinstance(owner, ast.ClassDef)
        for node in owner.body
        if isinstance(node, ast.AsyncFunctionDef) and not node.decorator_list
    ]
    assert len(methods) == 32
    lines = [
        "from typing import assert_type",
        "from agenthooksprotocol import Hooks, HookResult, Codec, Candidate",
        "from agenthooksprotocol import _models as m",
        "async def check(h: Hooks, i: Codec[int], r: Codec[str], p: Codec[bool]) -> None:",
    ]
    for method in methods:
        default = {
            "model_request_before": "m.CanonicalMessages",
            "context_compact_before": "m.TextParts",
            "user_elicitation_request": "m.McpElicitationElicitResult",
        }.get(method, "object")
        for mask in range(8):
            args = [
                f"{name}_codec={codec}"
                for index, (name, codec) in enumerate(
                    [("input", "i"), ("result", "r"), ("provenance", "p")]
                )
                if mask & (1 << index)
            ]
            types = [
                "int" if mask & 1 else "object",
                "str" if mask & 2 else default,
                "bool" if mask & 4 else "object",
            ]
            name = f"{method}_{mask}"
            lines.extend(
                [
                    f"    {name} = await h.{method}({{}}, {', '.join(args)})",
                    f"    assert_type({name}, HookResult[{', '.join(types)}])",
                    f"    assert_type({name}.decoded_result, {types[1]})",
                    f"    assert_type({name}.decoded_candidate, Candidate[{types[1]}, {types[2]}] | None)",
                ]
            )
        lines.append(
            f"    bad_{method}: HookResult[int, str, bool] = await h.{method}({{}})  # type: ignore[assignment]"
        )
    for mask in range(8):
        args = [
            f"{name}_codec={codec}"
            for index, (name, codec) in enumerate(
                [("input", "i"), ("result", "r"), ("provenance", "p")]
            )
            if mask & (1 << index)
        ]
        types = [
            "int" if mask & 1 else "object",
            "str" if mask & 2 else "object",
            "bool" if mask & 4 else "object",
        ]
        lines.extend(
            [
                f"    dispatch_{mask} = await h.dispatch('tool.before', {{}}, {', '.join(args)})",
                f"    assert_type(dispatch_{mask}, HookResult[{', '.join(types)}])",
            ]
        )
    lines.append(
        "    bad_dispatch: HookResult[int, str, bool] = await h.dispatch('tool.before', {})  # type: ignore[assignment]"
    )
    with tempfile.TemporaryDirectory(prefix="ahp-real-boundary-types-") as directory:
        consumer = Path(directory) / "consumer.py"
        consumer.write_text("\n".join(lines) + "\n")
        subprocess.run(
            [
                sys.executable,
                "-m",
                "mypy",
                "--strict",
                "--follow-imports=silent",
                "--warn-unused-ignores",
                str(consumer),
            ],
            cwd=root,
            check=True,
        )
    print(
        "Real SDK overlay: 32 origins, 256 codec combinations; codec-free contextual casts rejected"
    )


if __name__ == "__main__":
    main()
