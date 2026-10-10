import unittest
from threading import Event, Thread
from agenthooksprotocol.compaction import (
    run_compaction,
    compaction_capabilities,
    text_parts,
)


def modify(target, value):
    return {
        "type": "modify",
        "target": target,
        "operation": "replace",
        "value": text_parts(value) if isinstance(value, str) else value,
    }


class CompactionTests(unittest.TestCase):
    def test_callbacks_receive_effective_input_and_result(self):
        generated = []

        def edit(snapshot):
            snapshot["instructions"] = "malicious snapshot mutation"
            return [modify("instructions", "new")]

        def generate(instructions):
            generated.append(instructions)
            return text_parts(
                "generated:" + "".join(part["text"] for part in instructions)
            )

        def redact(snapshot):
            self.assertEqual(snapshot["instructions"], text_parts("new"))
            return [
                modify(
                    "summary",
                    "".join(part["text"] for part in snapshot["summary"]) + ":redacted",
                )
            ]

        def watch(snapshot):
            self.assertEqual(
                "".join(part["text"] for part in snapshot["summary"]),
                "generated:new:redacted",
            )
            return []

        r = run_compaction(
            "old",
            [("edit", "fail-closed", edit)],
            [("redact", "fail-closed", redact), ("watch", "fail-closed", watch)],
            generate=generate,
        )
        self.assertEqual(generated, [text_parts("new")])
        self.assertTrue(r["applied"])
        self.assertEqual(r["failures"], [])
        self.assertNotIn("bodies", r)
        self.assertEqual(r["seen"][1]["summary"][0]["id"], r["summary"][0]["id"])
        self.assertNotEqual(r["seen"][1]["summary"], r["summary"])

    def test_atomic_rollback_preserves_candidate(self):
        r = run_compaction(
            "old",
            [
                (
                    "cache",
                    "fail-closed",
                    lambda _: [{"type": "return", "value": text_parts("cached")}],
                ),
                (
                    "bad",
                    "fail-open",
                    lambda _: [
                        modify("instructions", "leak"),
                        {"type": "message", "text": "leak"},
                        modify("summary", "invalid"),
                    ],
                ),
            ],
            [("redact", "fail-closed", lambda _: [modify("summary", "safe")])],
            generate=lambda _: self.fail("supplied candidate must skip generator"),
        )
        self.assertEqual(r["instructions"], text_parts("old", "instructions"))
        self.assertEqual(r["messages"], [])
        self.assertEqual("".join(part["text"] for part in r["summary"]), "safe")
        self.assertEqual(r["provenance"], {"kind": "supplied", "supplier": "cache"})
        self.assertTrue(r["applied"])

    def test_merge_appends_and_changed_instructions_invalidate_candidate(self):
        initial = text_parts("base", "base")
        extra = text_parts(" extra", "extra")
        generated = []

        def generate(parts):
            generated.append(parts)
            return text_parts("generated", "generated")

        r = run_compaction(
            initial,
            [
                (
                    "supply",
                    "fail-closed",
                    lambda _: [{"type": "return", "value": text_parts("stale")}],
                ),
                (
                    "append",
                    "fail-closed",
                    lambda _: [
                        {
                            "type": "modify",
                            "target": "instructions",
                            "operation": "merge",
                            "value": extra,
                        }
                    ],
                ),
            ],
            [
                (
                    "append-summary",
                    "fail-closed",
                    lambda _: [
                        {
                            "type": "modify",
                            "target": "summary",
                            "operation": "merge",
                            "value": text_parts(" tail", "tail"),
                        }
                    ],
                )
            ],
            generate=generate,
        )
        self.assertEqual(r["instructions"], initial + extra)
        self.assertEqual(generated, [initial + extra])
        self.assertIsNone(r["candidate"])
        self.assertEqual(r["provenance"], {"kind": "generated"})
        self.assertEqual(
            r["summary"],
            text_parts("generated", "generated") + text_parts(" tail", "tail"),
        )
        self.assertTrue(r["applied"])
        self.assertNotIn("bodies", r)
        self.assertEqual(initial, text_parts("base", "base"))

    def test_return_binds_to_final_response_instructions_and_is_detached(self):
        supplied = text_parts("supplied", "supplied")
        r = run_compaction(
            "base",
            [
                (
                    "supplier",
                    "fail-closed",
                    lambda _: [
                        {"type": "return", "value": supplied},
                        modify("instructions", "changed"),
                    ],
                )
            ],
            generate=lambda _: self.fail("valid candidate should skip generation"),
        )
        self.assertEqual(r["instructions"], text_parts("changed"))
        self.assertEqual(r["summary"], supplied)
        self.assertEqual(r["candidate"], {"value": supplied, "supplier": "supplier"})
        supplied[0]["text"] = "mutated"
        self.assertEqual(r["summary"][0]["text"], "supplied")

    def test_non_inline_values_roll_back_entire_response(self):
        invalid = [
            "legacy string",
            [
                {
                    "id": "ref",
                    "kind": "text",
                    "mediaType": "text/plain",
                    "selection": "body",
                    "body": {"ref": "urn:legacy"},
                }
            ],
            [
                {
                    "id": "meta",
                    "kind": "text",
                    "mediaType": "text/plain",
                    "selection": "metadata",
                }
            ],
        ]
        for value in invalid:
            with self.subTest(value=value):
                r = run_compaction(
                    "base",
                    [
                        (
                            "supplier",
                            "fail-closed",
                            lambda _: [{"type": "return", "value": text_parts("safe")}],
                        ),
                        (
                            "invalid",
                            "fail-open",
                            lambda _: [
                                modify("instructions", "leaked"),
                                {"type": "return", "value": value},
                            ],
                        ),
                    ],
                    generate=lambda _: self.fail("candidate must survive"),
                )
                self.assertTrue(r["applied"])
                self.assertEqual(r["instructions"], text_parts("base", "instructions"))
                self.assertEqual(r["summary"], text_parts("safe"))
                self.assertEqual(
                    r["failures"], [{"boundary": "before", "supplier": "invalid"}]
                )

    def test_after_failure_prevents_delivery(self):
        r = run_compaction(
            "old",
            after=[
                (
                    "bad",
                    "fail-closed",
                    lambda _: [
                        modify("summary", "leak"),
                        modify("instructions", "wrong"),
                    ],
                )
            ],
        )
        self.assertFalse(r["applied"])
        self.assertNotIn("leak", [part["text"] for part in r["summary"]])
        self.assertEqual(
            compaction_capabilities("after", True), {"effects": [], "modify": {}}
        )


class DetachedCompactionTests(unittest.TestCase):
    def test_blocked_observers_do_not_gate_settlement_or_downstream(self):
        entered, release, finished, settled, raised = (Event() for _ in range(5))
        output = {}

        def blocked(snapshot):
            output["snapshot"] = snapshot
            entered.set()
            release.wait()
            snapshot["summary"].clear()
            snapshot["instructions"] = "observer mutation"
            finished.set()
            return [modify("summary", "forbidden")]

        def throwing(snapshot):
            raised.set()
            raise RuntimeError("observer failure")

        def host():
            r = run_compaction(
                "base",
                after=[
                    ("slow", "fail-closed", blocked),
                    ("throw", "fail-closed", throwing),
                ],
                observe_only=True,
            )
            output["result"] = r
            output["downstream"] = (
                ["".join(part["text"] for part in r["summary"])] if r["applied"] else []
            )
            settled.set()

        worker = Thread(target=host, daemon=True)
        worker.start()
        try:
            self.assertTrue(entered.wait(5), "observer did not start")
            self.assertTrue(settled.wait(5), "blocked observer delayed settlement")
            self.assertFalse(finished.is_set())
            self.assertTrue(
                raised.wait(5), "observers were serialized behind blocked callback"
            )
            self.assertEqual(output["downstream"], ["summary:base"])
            self.assertTrue(output["snapshot"]["applied"])
            self.assertEqual(
                output["snapshot"]["capabilities"], {"effects": [], "modify": {}}
            )
            before = __import__("copy").deepcopy(output["result"])
        finally:
            release.set()
            worker.join(5)
        self.assertTrue(finished.wait(5))
        self.assertEqual(output["result"], before)
        self.assertEqual(output["result"]["failures"], [])

    def test_unknown_effect_fields_types_and_operations_roll_back_response(self):
        invalid = [
            {"type": "message", "text": "ignored", "futureField": True},
            {"type": "future-effect"},
            {
                "type": "modify",
                "target": "instructions",
                "operation": "future-operation",
                "value": "bad",
            },
        ]
        for effect in invalid:
            with self.subTest(effect=effect):
                actual = run_compaction(
                    "original",
                    [
                        (
                            "cache",
                            "fail-closed",
                            lambda _: [
                                {"type": "return", "value": text_parts("cached")}
                            ],
                        ),
                        (
                            "invalid",
                            "fail-open",
                            lambda _: [
                                modify("instructions", "leaked"),
                                {"type": "message", "text": "leaked"},
                                effect,
                            ],
                        ),
                    ],
                    generate=lambda _: self.fail(
                        "Accepted candidate must survive rejection"
                    ),
                )
                self.assertTrue(actual["applied"])
                self.assertEqual(
                    actual["instructions"], text_parts("original", "instructions")
                )
                self.assertEqual(actual["messages"], [])
                self.assertEqual(
                    "".join(part["text"] for part in actual["summary"]), "cached"
                )
                self.assertEqual(
                    actual["failures"], [{"boundary": "before", "supplier": "invalid"}]
                )


if __name__ == "__main__":
    unittest.main()
