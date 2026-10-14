"""Acceptance and diagnostics stay identical to stock Draft 2020-12."""

import json
from pathlib import Path
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from agenthooksprotocol._validator import canonical_backend
from agenthooksprotocol.runtime import ProtocolError, Validator


DIALECT = Draft202012Validator.META_SCHEMA["$id"]
ROOT = Path(__file__).resolve().parents[1]


def registry_for(schemas):
    return Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema)) for schema in schemas
    )


def errors(validator, value):
    def signature(error):
        return (
            error.message,
            tuple(error.path),
            tuple(error.schema_path),
            error.validator,
            tuple(signature(child) for child in error.context),
        )

    return [signature(error) for error in validator.iter_errors(value)]


def branch(tag, **extra):
    return {
        "type": "object",
        "required": ["type", "value"],
        "properties": {"type": {"const": tag}, "value": {"type": "integer"}},
        "additionalProperties": False,
        **extra,
    }


class OptimizationTests(unittest.TestCase):
    def pair(self, body, extra=()):
        schema = {"$schema": DIALECT, "$id": "urn:test:root", **body}
        schemas = [schema, *extra]
        registry = registry_for(schemas)
        backend = canonical_backend(schemas, registry)
        return (
            backend(schema, registry=registry, format_checker=FormatChecker()),
            Draft202012Validator(
                schema, registry=registry, format_checker=FormatChecker()
            ),
        )

    def equivalent(self, body, values, extra=()):
        optimized, stock = self.pair(body, extra)
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(errors(optimized, value), errors(stock, value))
        return optimized

    def test_factory_graph_ownership_constructor_evolve_and_resolver_substitution(self):
        schema = {
            "$schema": DIALECT,
            "$id": "https://e.test/root",
            "oneOf": [
                {"properties": {"type": {"$ref": "tag"}}},
                {"properties": {"type": {"const": "b"}}},
            ],
        }
        targets = [
            {"$schema": DIALECT, "$id": "https://e.test/tag", "const": tag}
            for tag in ("a", "b")
        ]
        registry_a, registry_b = [registry_for([schema, target]) for target in targets]
        backend = canonical_backend([schema, targets[0]], registry_a)
        original = backend(schema, registry=registry_a)
        self.assertTrue(original.is_valid({"type": "a"}))  # warm factory-A plans
        stock_a = Draft202012Validator(schema, registry=registry_a)
        stock_b = Draft202012Validator(schema, registry=registry_b)
        variants = [
            (backend(schema, registry=registry_b), stock_b),
            (original.evolve(registry=registry_b), stock_a.evolve(registry=registry_b)),
            (
                original.evolve(registry=registry_b, _resolver=stock_b._resolver),
                stock_b,
            ),
            (
                backend(schema, registry=registry_a, _resolver=stock_b._resolver),
                stock_b,
            ),
            (original.evolve(_resolver=stock_b._resolver), stock_b),
        ]
        self.assertFalse(stock_b.is_valid({"type": "b"}))
        for optimized, stock in variants:
            for value in ({"type": "a"}, {"type": "b"}, {"type": "unknown"}, {}):
                self.assertEqual(errors(optimized, value), errors(stock, value))

    def test_derived_graph_compatibility_is_identity_based_bounded_and_cached(self):
        from attrs import evolve

        schema = {
            "$schema": DIALECT,
            "$id": "urn:test:graph",
            "oneOf": [branch("a"), branch("b")],
        }
        registry = registry_for([schema])
        original = Draft202012Validator.VALIDATORS["oneOf"]
        with patch.dict(
            Draft202012Validator.VALIDATORS,
            {
                "oneOf": unittest.mock.Mock(wraps=original),
            },
        ):
            recorder = Draft202012Validator.VALIDATORS["oneOf"]
            backend = canonical_backend([schema], registry)
        optimized = backend(schema, registry=registry)
        handler = backend.VALIDATORS["oneOf"]
        bindings = dict(
            zip(
                handler.__code__.co_freevars,
                (cell.cell_contents for cell in handler.__closure__),
            )
        )
        compatible = bindings["compatible_registry"]
        state = dict(
            zip(
                compatible.__code__.co_freevars,
                (cell.cell_contents for cell in compatible.__closure__),
            )
        )
        self.assertEqual(state["expected_graph"], [])  # still lazy at construction
        value = {"type": "a", "value": 1}
        self.assertTrue(optimized.is_valid(value))
        self.assertEqual(recorder.call_count, 0)
        actual = optimized._resolver._registry
        self.assertTrue(compatible(actual))
        with patch.object(
            type(actual), "crawl", side_effect=AssertionError("cached graph")
        ):
            self.assertTrue(compatible(actual))
        extra = actual.with_resource(
            "urn:test:extra", Resource.from_contents({"$schema": DIALECT})
        )
        resolver = evolve(optimized._resolver, registry=extra)
        self.assertTrue(optimized.evolve(_resolver=resolver).is_valid(value))
        self.assertEqual(recorder.call_count, 1)
        self.assertFalse(compatible(extra))
        # Matching content equality is not enough: compiler requires identity.
        clone_schema = json.loads(json.dumps(schema))
        altered = actual.with_resource(
            schema["$id"], Resource.from_contents(clone_schema)
        )
        self.assertFalse(compatible(altered))
        crawled = actual.crawl()
        retained = [evolve(crawled) for _ in range(257)]
        for graph in retained:
            self.assertTrue(compatible(graph))
        cache = state["compatibility_cache"]
        self.assertEqual(len(cache), 256)
        self.assertNotIn(id(retained[0]), cache)
        self.assertIn(id(retained[-1]), cache)
        self.assertTrue(all(key == id(record[0]) for key, record in cache.items()))

    def test_compilation_is_lazy_and_backend_caches_are_isolated(self):
        a, _ = self.pair({"oneOf": [branch("a"), branch("b")]})
        b, _ = self.pair({"oneOf": [branch("a"), branch("b")]})

        def state(validator):
            handler = type(validator).VALIDATORS["oneOf"]
            bindings = dict(
                zip(
                    handler.__code__.co_freevars,
                    (cell.cell_contents for cell in handler.__closure__),
                )
            )
            prepare = bindings["prepare"]
            compiler = dict(
                zip(
                    prepare.__code__.co_freevars,
                    (cell.cell_contents for cell in prepare.__closure__),
                )
            )
            safe = compiler["safe_graph"]
            safety = dict(
                zip(
                    safe.__code__.co_freevars,
                    (cell.cell_contents for cell in safe.__closure__),
                )
            )
            return bindings["plans"], safety["safety"]

        a_plans, a_safety = state(a)
        b_plans, b_safety = state(b)
        self.assertEqual((a_plans, a_safety, b_plans, b_safety), ({}, {}, {}, {}))
        self.assertIsNot(a_plans, b_plans)
        self.assertTrue(a.is_valid({"type": "a", "value": 1}))
        self.assertTrue(a_plans)
        self.assertTrue(a_safety)
        self.assertEqual((b_plans, b_safety), ({}, {}))
        before = (len(a_plans), len(a_safety))
        self.assertTrue(a.is_valid({"type": "b", "value": 2}))
        self.assertEqual((len(a_plans), len(a_safety)), before)
        self.assertTrue(all(record[0] is not None for record in a_safety.values()))

    def test_lazy_compiler_cannot_use_original_registry_retriever(self):
        schema = {
            "$schema": DIALECT,
            "$id": "https://local.example/root",
            "oneOf": [
                branch("a"),
                branch("b"),
                {"$ref": "https://remote.example/schema"},
            ],
        }
        remote = unittest.mock.Mock(
            return_value=Resource.from_contents(
                {
                    "$schema": DIALECT,
                    "properties": {"type": {"const": "c"}},
                }
            )
        )
        registry = Registry(retrieve=remote).with_resources(
            [
                (schema["$id"], Resource.from_contents(schema)),
            ]
        )
        backend = canonical_backend([schema], registry)
        optimized = backend(schema, registry=registry)
        self.assertEqual(remote.call_count, 0)
        # Compiler marks the remote branch unsafe without fetching it. Original
        # validation then calls the fake retriever exactly once, like stock.
        self.assertTrue(optimized.is_valid({"type": "a", "value": 1}))
        self.assertEqual(remote.call_count, 1)
        remote.reset_mock()
        self.assertTrue(
            Draft202012Validator(schema, registry=registry).is_valid(
                {"type": "a", "value": 1}
            )
        )
        self.assertEqual(remote.call_count, 1)

    def test_reused_relative_constraints_are_prefixed_per_property(self):
        shared = {
            "$schema": DIALECT,
            "$id": "urn:test:tag",
            "properties": {"tag": {"const": "x"}},
        }
        self.equivalent(
            {
                "oneOf": [
                    {
                        "properties": {
                            "type": {"const": "a"},
                            "left": {"$ref": "urn:test:tag"},
                        }
                    },
                    {
                        "properties": {
                            "type": {"const": "b"},
                            "right": {"$ref": "urn:test:tag"},
                        }
                    },
                ]
            },
            [
                {"type": "a", "left": {"tag": "x"}, "right": {"tag": "bad"}},
                {"type": "a", "left": {"tag": "bad"}},
                {"type": "b", "right": {"tag": "x"}, "left": {"tag": "bad"}},
                {"type": "b", "right": {"tag": "bad"}},
                {},
                {"type": "a"},
                {"type": "unknown"},
            ],
            [shared],
        )

    def test_unowned_evolved_schema_uses_stock_without_compilation(self):
        original = Draft202012Validator.VALIDATORS["oneOf"]
        with patch.dict(
            Draft202012Validator.VALIDATORS,
            {
                "oneOf": unittest.mock.Mock(wraps=original),
            },
        ):
            recorder = Draft202012Validator.VALIDATORS["oneOf"]
            optimized, _ = self.pair({"oneOf": [branch("a"), branch("b")]})
        unowned = {"oneOf": [branch("c"), branch("d")]}
        self.assertTrue(
            optimized.evolve(schema=unowned).is_valid({"type": "c", "value": 1})
        )
        self.assertEqual(recorder.call_count, 1)

    def test_tagged_values_and_full_branch_validation(self):
        self.equivalent(
            {"oneOf": [branch("a"), branch("b")]},
            [
                {"type": "a", "value": 1},
                {"type": "b", "value": 2},
                {"type": "unknown", "value": 1},
                {"value": 1},
                {},
                {"type": "a"},
                {"type": "a", "value": False},
                {"type": "a", "value": 1, "extra": True},
                {"type": None, "value": 1},
                {"type": ["a"], "value": 1},
                None,
                [],
                "a",
                1,
                True,
            ],
        )

    def test_overlap_preserves_exact_one_of_uniqueness(self):
        self.equivalent(
            {"oneOf": [branch("a"), branch("a")]},
            [
                {"type": "a", "value": 1},
                {"type": "b", "value": 1},
                {},
            ],
        )
        # An unconstrained branch is never eliminated by a guessed tag.
        self.equivalent(
            {"oneOf": [branch("a"), {"type": "object"}]},
            [
                {"type": "a", "value": 1},
                {"type": "b", "value": 1},
                {},
            ],
        )
        # properties does not imply required.
        self.equivalent(
            {
                "oneOf": [
                    {"properties": {"type": {"const": "a"}}},
                    {"properties": {"type": {"const": "b"}}},
                ]
            },
            [{}, {"type": "a"}, {"type": "other"}, None],
        )

    def test_static_ref_all_of_nested_const_and_ref_siblings(self):
        remote = {
            "$schema": DIALECT,
            "$id": "urn:test:shared",
            "$defs": {
                "a": {
                    "allOf": [
                        {
                            "properties": {
                                "meta": {"properties": {"tag": {"const": "a"}}}
                            }
                        },
                        {
                            "required": ["value"],
                            "properties": {"value": {"type": "integer"}},
                        },
                    ]
                }
            },
        }
        body = {
            "oneOf": [
                {
                    "$ref": "urn:test:shared#/$defs/a",
                    "properties": {"value": {"minimum": 2}},
                },
                {"properties": {"meta": {"properties": {"tag": {"const": "b"}}}}},
            ]
        }
        self.equivalent(
            body,
            [
                {"meta": {"tag": "a"}, "value": 2},
                {"meta": {"tag": "a"}, "value": 1},
                {"meta": {"tag": "a"}},
                {"meta": {"tag": "b"}},
                {"meta": {"tag": "unknown"}},
                {"meta": {}},
                {"meta": None},
                {},
            ],
            [remote],
        )
        # A ref within properties may itself carry a string const.
        self.equivalent(
            {
                "$defs": {"tag": {"const": "a"}},
                "oneOf": [
                    {"properties": {"type": {"$ref": "#/$defs/tag"}}},
                    branch("b"),
                ],
            },
            [{"type": "a"}, {"type": "b", "value": 1}, {}],
        )

    def test_direct_branch_id_preserves_stock_one_of_scope_behavior(self):
        plain = {"properties": {"type": {"const": "a"}}}
        scoped = {
            "$id": "nested/branch",
            "properties": {"type": {"$ref": "tag"}},
        }
        tags = [
            {"$schema": DIALECT, "$id": "https://e.test/tag", "const": "a"},
            {"$schema": DIALECT, "$id": "https://e.test/nested/tag", "const": "b"},
        ]
        original = Draft202012Validator.VALIDATORS["oneOf"]
        for branches, a_valid in (([plain, scoped], False), ([scoped, plain], True)):
            with self.subTest(branches=branches):
                with patch.dict(
                    Draft202012Validator.VALIDATORS,
                    {"oneOf": unittest.mock.Mock(wraps=original)},
                ):
                    recorder = Draft202012Validator.VALIDATORS["oneOf"]
                    optimized, stock = self.pair(
                        {"$id": "https://e.test/root", "oneOf": branches}, tags
                    )
                self.assertEqual(stock.is_valid({"type": "a"}), a_valid)
                self.assertTrue(stock.is_valid({"type": "b"}))
                for value in ({"type": "a"}, {"type": "b"}, {"type": "unknown"}, {}):
                    expected = errors(stock, value)
                    before = recorder.call_count
                    self.assertEqual(errors(optimized, value), expected)
                    self.assertEqual(recorder.call_count, before + 1)

    def test_shared_schema_identity_has_separate_resolver_scope_plans(self):
        shared = {
            "oneOf": [
                {"properties": {"type": {"$ref": "tag"}}},
                {"properties": {"type": {"const": "a"}}},
            ],
        }
        roots = [
            {
                "$schema": DIALECT,
                "$id": "https://scope.test/" + scope + "/root",
                "properties": {"payload": shared},
            }
            for scope in ("a", "b")
        ]
        tags = [
            {
                "$schema": DIALECT,
                "$id": "https://scope.test/" + tag + "/tag",
                "const": tag,
            }
            for tag in ("a", "b")
        ]
        schemas = roots + tags
        registry = registry_for(schemas)
        backend = canonical_backend(schemas, registry)
        for root in roots:
            optimized = backend(root, registry=registry)
            stock = Draft202012Validator(root, registry=registry)
            for tag in ("a", "b", "unknown"):
                value = {"payload": {"type": tag}}
                self.assertEqual(errors(optimized, value), errors(stock, value))
        self.assertFalse(
            backend(roots[0], registry=registry).is_valid({"payload": {"type": "a"}})
        )

    def test_nested_ids_and_relative_static_refs_keep_resolver_scope(self):
        body = {
            "$id": "https://local.example/root",
            "$defs": {
                "a": {
                    "$id": "nested/a",
                    "required": ["type", "value"],
                    "properties": {
                        "type": {"const": "a"},
                        "value": {"$ref": "value"},
                    },
                },
            },
            "oneOf": [{"$ref": "#/$defs/a"}, branch("b")],
        }
        value_schema = {
            "$schema": DIALECT,
            "$id": "https://local.example/nested/value",
            "type": "integer",
            "minimum": 2,
        }
        self.equivalent(
            body,
            [
                {"type": "a", "value": 2},
                {"type": "a", "value": 1},
                {"type": "a", "value": "bad"},
                {"type": "b", "value": 1},
                {},
            ],
            [value_schema],
        )

    def test_unevaluated_constraints_and_nested_one_of(self):
        self.equivalent(
            {
                "oneOf": [branch("a"), branch("b")],
                "unevaluatedProperties": False,
            },
            [{"type": "a", "value": 1}, {"type": "a", "value": 1, "x": 1}],
        )
        self.equivalent(
            {"properties": {"nested": {"oneOf": [branch("a"), branch("b")]}}},
            [
                {"nested": {"type": "a", "value": "bad"}},
                {"nested": {"type": "b", "value": 1}},
            ],
        )

    def test_fast_path_and_fallback_are_observable_without_global_registration(self):
        original = Draft202012Validator.VALIDATORS["oneOf"]
        with patch.dict(
            Draft202012Validator.VALIDATORS,
            {"oneOf": unittest.mock.Mock(wraps=original)},
        ):
            recorder = Draft202012Validator.VALIDATORS["oneOf"]
            optimized, _ = self.pair({"oneOf": [branch("a"), branch("b")]})
        self.assertIs(Draft202012Validator.VALIDATORS["oneOf"], original)
        self.assertTrue(optimized.is_valid({"type": "a", "value": 1}))
        self.assertEqual(recorder.call_count, 0)
        for value in ({"type": "a"}, {"value": 1}, {"type": "unknown", "value": 1}, []):
            optimized.is_valid(value)
        self.assertEqual(recorder.call_count, 4)
        self.assertIs(type(optimized.evolve(schema=optimized.schema)), type(optimized))
        self.assertIs(
            type(
                Draft202012Validator(optimized.schema).evolve(schema=optimized.schema)
            ),
            Draft202012Validator,
        )

    def test_dynamic_unresolved_and_cyclic_refs_do_not_prune(self):
        original = Draft202012Validator.VALIDATORS["oneOf"]
        bodies = [
            {
                "$defs": {"tag": {"$dynamicAnchor": "tag", "const": "b"}},
                "oneOf": [
                    branch("a"),
                    {"properties": {"type": {"$dynamicRef": "#tag"}}},
                ],
            },
            {"oneOf": [branch("a"), {"$ref": "https://invalid.example/not-fetched"}]},
            {
                "$defs": {"loop": {"$ref": "#/$defs/loop"}},
                "oneOf": [branch("a"), {"$ref": "#/$defs/loop"}],
            },
            {
                "oneOf": [
                    branch("a"),
                    {
                        "$schema": "http://json-schema.org/draft-07/schema#",
                        "properties": {"type": {"const": "b"}},
                    },
                ]
            },
        ]
        for body in bodies:
            with self.subTest(body=body):
                with patch.dict(
                    Draft202012Validator.VALIDATORS,
                    {"oneOf": unittest.mock.Mock(wraps=original)},
                ):
                    recorder = Draft202012Validator.VALIDATORS["oneOf"]
                    optimized, stock = self.pair(body)
                value = {"type": "a", "value": 1}
                try:
                    expected = errors(stock, value)
                except Exception as exc:
                    with self.assertRaises(type(exc)):
                        errors(optimized, value)
                else:
                    self.assertEqual(errors(optimized, value), expected)
                self.assertGreater(recorder.call_count, 0)

    def test_partial_plans_validate_dynamic_branch_and_preserve_uniqueness(self):
        body = {
            "$defs": {"tag": {"$dynamicAnchor": "tag", "const": "c"}},
            "oneOf": [
                branch("a"),
                branch("b"),
                {"properties": {"type": {"$dynamicRef": "#tag"}}},
            ],
        }
        optimized, stock = self.pair(body)
        original = type(optimized).VALIDATORS["$dynamicRef"]
        with patch.dict(
            type(optimized).VALIDATORS,
            {
                "$dynamicRef": unittest.mock.Mock(wraps=original),
            },
        ):
            recorder = type(optimized).VALIDATORS["$dynamicRef"]
            for value in (
                {"type": "a", "value": 1},
                {"type": "b", "value": 1},
                {"type": "c", "value": 1},
                {"type": "unknown"},
                {},
            ):
                before = recorder.call_count
                self.assertEqual(errors(optimized, value), errors(stock, value))
                if "type" in value:
                    self.assertGreater(recorder.call_count, before)
        # Unsafe dynamic branch can overlap the safe selected branch. The full
        # stock message must report both winners, not silently accept one.
        body["$defs"]["tag"]["const"] = "a"
        self.equivalent(body, [{"type": "a", "value": 1}, {"type": "b", "value": 1}])

    def test_partial_plans_preserve_unsafe_reference_exceptions_and_order(self):
        unsafe_branches = [
            {"$ref": "https://invalid.example/not-fetched"},
            {"$ref": "#/$defs/loop"},
            {
                "properties": {
                    "early": {"type": "integer"},
                    "late": {"$ref": "https://invalid.example/not-fetched"},
                }
            },
        ]
        for unsafe in unsafe_branches:
            for branches in (
                [unsafe, branch("a"), branch("b")],
                [branch("a"), branch("b"), unsafe],
            ):
                body = {"$defs": {"loop": {"$ref": "#/$defs/loop"}}, "oneOf": branches}
                optimized, stock = self.pair(body)
                for value in (
                    {"type": "a", "value": 1},
                    {"type": "a", "value": 1, "early": "bad", "late": 1},
                    {"type": "unknown", "early": "bad", "late": 1},
                ):
                    with self.subTest(branches=branches, value=value):
                        try:
                            expected = errors(stock, value)
                        except Exception as exc:
                            with self.assertRaises(type(exc)):
                                errors(optimized, value)
                        else:
                            self.assertEqual(errors(optimized, value), expected)

    def test_unused_definitions_do_not_disable_safe_discriminators(self):
        original = Draft202012Validator.VALIDATORS["oneOf"]
        with patch.dict(
            Draft202012Validator.VALIDATORS,
            {
                "oneOf": unittest.mock.Mock(wraps=original),
            },
        ):
            recorder = Draft202012Validator.VALIDATORS["oneOf"]
            optimized, stock = self.pair(
                {
                    "oneOf": [
                        branch(
                            "a",
                            **{
                                "$defs": {
                                    "cycle": {"$ref": "#"},
                                    "unresolved": {
                                        "$ref": "https://invalid.example/not-fetched"
                                    },
                                    "dynamic": {"$dynamicRef": "#missing"},
                                }
                            },
                        ),
                        branch("b"),
                    ]
                }
            )
        value = {"type": "a", "value": 1}
        self.assertTrue(optimized.is_valid(value))
        self.assertEqual(recorder.call_count, 0)
        self.assertEqual(errors(optimized, value), errors(stock, value))

    def test_nested_branch_id_scope_exception_cannot_be_pruned(self):
        body = {
            "$id": "https://e.test/root",
            "oneOf": [
                {
                    "properties": {
                        "type": {"const": "c"},
                        "payload": {
                            "oneOf": [
                                {"properties": {"type": {"const": "a"}}},
                                {
                                    "$id": "nested/branch",
                                    "properties": {"type": {"$ref": "tag"}},
                                },
                            ]
                        },
                    }
                },
                branch("a", additionalProperties=True),
                branch("b"),
            ],
        }
        optimized, stock = self.pair(
            body,
            [
                {
                    "$schema": DIALECT,
                    "$id": "https://e.test/nested/tag",
                    "const": "b",
                }
            ],
        )
        value = {"type": "a", "value": 1, "payload": {"type": "a"}}
        with self.assertRaises(Exception) as caught:
            errors(stock, value)
        with self.assertRaises(type(caught.exception)):
            errors(optimized, value)

    def test_partial_plan_skips_proven_impossible_branches(self):
        original = Draft202012Validator.VALIDATORS["oneOf"]
        with patch.dict(
            Draft202012Validator.VALIDATORS,
            {
                "oneOf": unittest.mock.Mock(wraps=original),
            },
        ):
            recorder = Draft202012Validator.VALIDATORS["oneOf"]
            optimized, _ = self.pair(
                {
                    "$defs": {"tag": {"$dynamicAnchor": "tag", "const": "c"}},
                    "oneOf": [
                        branch("a"),
                        branch("b"),
                        {
                            "properties": {"type": {"$dynamicRef": "#tag"}},
                        },
                    ],
                }
            )
        self.assertTrue(optimized.is_valid({"type": "a", "value": 1}))
        self.assertEqual(recorder.call_count, 0)
        # Missing fields leave every branch in play: use stock directly.
        optimized.is_valid({})
        self.assertEqual(recorder.call_count, 1)

    def test_isolation_between_bundles_and_full_ref_dialect_evolution(self):
        a, _ = self.pair({"oneOf": [branch("a"), branch("b")]})
        b, _ = self.pair({"oneOf": [branch("c"), branch("d")]})
        self.assertIsNot(type(a), type(b))
        schema = {
            "$schema": DIALECT,
            "$id": "urn:test:shared",
            "oneOf": [branch("a"), branch("b")],
        }
        optimized = self.equivalent(
            {"$ref": "urn:test:shared"},
            [
                {"type": "a", "value": 1},
                {"type": "a"},
                {},
            ],
            [schema],
        )
        self.assertIs(type(optimized.evolve(schema=schema)), type(optimized))


class ReferenceCacheTests(unittest.TestCase):
    def build(self, schema, extra=(), **options):
        schemas = [schema, *extra]
        registry = registry_for(schemas)
        backend = canonical_backend(schemas, registry, **options)
        return backend(schema, registry=registry), Draft202012Validator(
            schema, registry=registry
        )

    def cache(self, validator):
        handler = type(validator).VALIDATORS["$ref"]
        return dict(
            zip(
                handler.__code__.co_freevars,
                (cell.cell_contents for cell in handler.__closure__),
            )
        )["resolution_cache"]

    def test_reference_hits_and_lru_eviction_are_bounded_and_retain_sources(self):
        schema = {
            "$schema": DIALECT,
            "$id": "urn:test:cache",
            "$defs": {"s" + str(i): {"const": i} for i in range(257)},
        }
        optimized, _ = self.build(schema, optimize_unions=False)
        source = optimized._resolver
        original = type(source).lookup
        lookups = []

        def lookup(resolver, ref):
            if resolver is source:
                lookups.append(ref)
            return original(resolver, ref)

        def validate(index):
            return optimized.evolve(schema={"$ref": "#/$defs/s" + str(index)}).is_valid(
                index
            )

        with patch.object(type(source), "lookup", lookup):
            self.assertTrue(validate(0))
            self.assertTrue(validate(1))
            self.assertTrue(validate(0))
            self.assertEqual(len(lookups), 2)
            for index in range(2, 257):
                self.assertTrue(validate(index))
            cache = self.cache(optimized)
            self.assertEqual(len(cache), 256)
            self.assertIn((id(source), "#/$defs/s0"), cache)
            self.assertNotIn((id(source), "#/$defs/s1"), cache)
            for key, (retained, resolved) in cache.items():
                self.assertIs(retained, source)
                self.assertEqual(key[0], id(retained))
                self.assertIsNotNone(resolved.resolver)
            before = len(lookups)
            self.assertTrue(validate(1))
            self.assertEqual(len(lookups), before + 1)
            self.assertEqual(len(cache), 256)

    def test_reference_cache_never_caches_mutable_value_validation(self):
        schema = {
            "$schema": DIALECT,
            "$id": "urn:test:mutable",
            "$defs": {
                "value": {
                    "type": "object",
                    "required": ["n"],
                    "properties": {"n": {"type": "integer"}},
                }
            },
            "$ref": "#/$defs/value",
        }
        optimized, stock = self.build(schema, optimize_unions=False)
        value = {"n": 1}
        self.assertEqual(errors(optimized, value), errors(stock, value))
        cache = self.cache(optimized)
        self.assertEqual(len(cache), 1)
        resolved = next(iter(cache.values()))[1]
        for n in ("bad", False, [], 2):
            value["n"] = n
            self.assertEqual(errors(optimized, value), errors(stock, value))
            self.assertIs(next(iter(cache.values()))[1], resolved)
        value.clear()
        self.assertEqual(errors(optimized, value), errors(stock, value))

    def test_exact_source_identity_separates_same_base_and_different_registries(self):
        schema = {"$schema": DIALECT, "$id": "urn:test:root", "$ref": "urn:test:target"}
        targets = [
            {"$schema": DIALECT, "$id": "urn:test:target", "type": kind}
            for kind in ("integer", "string")
        ]
        registries = [registry_for([schema, target]) for target in targets]
        backend = canonical_backend(
            [schema, targets[0]], registries[0], optimize_unions=False
        )
        optimized = [backend(schema, registry=registry) for registry in registries]
        self.assertIsNot(optimized[0]._resolver, optimized[1]._resolver)
        for validator, registry in zip(optimized, registries):
            stock = Draft202012Validator(schema, registry=registry)
            for value in (1, "one", False):
                self.assertEqual(errors(validator, value), errors(stock, value))
        cache = self.cache(optimized[0])
        self.assertEqual(len(cache), 2)
        self.assertEqual(
            {key[0] for key in cache}, {id(v._resolver) for v in optimized}
        )
        independent = canonical_backend(
            [schema, targets[0]], registries[0], optimize_unions=False
        )
        self.assertEqual(self.cache(independent(schema, registry=registries[0])), {})

    def test_complete_resolution_preserves_dynamic_anchor_scope(self):
        tree = {
            "$schema": DIALECT,
            "$id": "https://scope.test/tree",
            "$dynamicAnchor": "node",
            "type": "object",
            "properties": {
                "children": {"type": "array", "items": {"$dynamicRef": "#node"}}
            },
        }
        strict = {
            "$schema": DIALECT,
            "$id": "https://scope.test/strict",
            "$dynamicAnchor": "node",
            "$ref": "tree",
            "unevaluatedProperties": False,
        }
        registry = registry_for([strict, tree])
        backend = canonical_backend([strict, tree], registry, optimize_unions=False)
        for schema in (strict, tree, strict):
            optimized = backend(schema, registry=registry)
            stock = Draft202012Validator(schema, registry=registry)
            for value in (
                {},
                {"children": [{}]},
                {"children": [{"extra": 1}]},
                {"children": [{"children": [{"extra": 1}]}]},
            ):
                self.assertEqual(errors(optimized, value), errors(stock, value))
                self.assertEqual(errors(optimized, value), errors(stock, value))
            if schema is strict:
                record = self.cache(optimized)[(id(optimized._resolver), "tree")]
                self.assertIs(record[0], optimized._resolver)
                self.assertTrue(list(record[1].resolver.dynamic_scope()))

    def test_lookup_failure_uses_stock_wrapping_and_is_never_cached(self):
        schema = {
            "$schema": DIALECT,
            "$id": "urn:test:failure",
            "$ref": "https://invalid.example/not-fetched",
        }
        optimized, stock = self.build(schema, optimize_unions=False)
        with self.assertRaises(Exception) as expected:
            errors(stock, {})
        source = optimized._resolver
        original = type(source).lookup
        calls = []

        def lookup(resolver, ref):
            if resolver is source:
                calls.append(ref)
            return original(resolver, ref)

        with patch.object(type(source), "lookup", lookup):
            for value in ({}, 1):
                with self.assertRaises(type(expected.exception)) as actual:
                    errors(optimized, value)
                self.assertEqual(str(actual.exception), str(expected.exception))
        self.assertEqual(len(calls), 2)
        self.assertEqual(self.cache(optimized), {})

    def test_remote_retriever_results_are_never_cached(self):
        schema = {
            "$schema": DIALECT,
            "$id": "urn:test:changing-remote",
            "$ref": "https://remote.example/schema",
        }
        resources = [
            Resource.from_contents({"$schema": DIALECT, "const": n}) for n in (1, 2, 1)
        ]
        optimized_retrieve = unittest.mock.Mock(side_effect=list(resources))
        stock_retrieve = unittest.mock.Mock(side_effect=list(resources))

        def registered(retrieve):
            return Registry(retrieve=retrieve).with_resources(
                [
                    (schema["$id"], Resource.from_contents(schema)),
                ]
            )

        registry = registered(optimized_retrieve)
        backend = canonical_backend([schema], registry, optimize_unions=False)
        optimized = backend(schema, registry=registry)
        stock = Draft202012Validator(schema, registry=registered(stock_retrieve))
        for _ in range(3):
            self.assertEqual(errors(optimized, 1), errors(stock, 1))
        self.assertEqual(optimized_retrieve.call_count, 3)
        self.assertEqual(stock_retrieve.call_count, 3)
        self.assertEqual(self.cache(optimized), {})

    def test_stateful_remote_union_overlap_and_zero_winners_stay_stock(self):
        schema = {
            "$schema": DIALECT,
            "$id": "urn:test:stateful-union",
            "oneOf": [
                branch("a"),
                branch("b"),
                {"$ref": "https://remote.example/schema"},
            ],
        }
        for tag, outcomes in (
            ("a", (True, False, True)),
            ("unknown", (False, True, False)),
        ):
            resources = [
                Resource.from_contents(
                    {"$schema": DIALECT} if valid else {"$schema": DIALECT, "not": {}}
                )
                for valid in outcomes
            ]
            optimized_retrieve = unittest.mock.Mock(side_effect=list(resources))
            stock_retrieve = unittest.mock.Mock(side_effect=list(resources))

            def registered(retrieve):
                return Registry(retrieve=retrieve).with_resources(
                    [
                        (schema["$id"], Resource.from_contents(schema)),
                    ]
                )

            registry = registered(optimized_retrieve)
            backend = canonical_backend([schema], registry)
            optimized = backend(schema, registry=registry)
            stock = Draft202012Validator(schema, registry=registered(stock_retrieve))
            value = {"type": tag, "value": 1}
            with self.subTest(tag=tag):
                for index, valid in enumerate((False, True, False), start=1):
                    actual = errors(optimized, value)
                    expected = errors(stock, value)
                    self.assertEqual(actual, expected)
                    self.assertEqual(actual == [], valid)
                    self.assertEqual(optimized_retrieve.call_count, index)
                    self.assertEqual(stock_retrieve.call_count, index)
                self.assertEqual(self.cache(optimized), {})

    def test_remote_first_failure_then_success_does_not_retry_or_cache(self):
        from referencing.exceptions import NoSuchResource

        schema = {
            "$schema": DIALECT,
            "$id": "urn:test:remote-retry",
            "$ref": "https://remote.example/schema",
        }
        resource = Resource.from_contents({"$schema": DIALECT, "const": 1})

        def registered():
            retrieve = unittest.mock.Mock(
                side_effect=[
                    NoSuchResource(ref=schema["$ref"]),
                    resource,
                ]
            )
            return Registry(retrieve=retrieve).with_resources(
                [
                    (schema["$id"], Resource.from_contents(schema)),
                ]
            ), retrieve

        registry, retrieve = registered()
        stock_registry, stock_retrieve = registered()
        backend = canonical_backend([schema], registry, optimize_unions=False)
        optimized = backend(schema, registry=registry)
        stock = Draft202012Validator(schema, registry=stock_registry)
        with self.assertRaises(Exception) as expected:
            errors(stock, 1)
        with self.assertRaises(type(expected.exception)) as actual:
            errors(optimized, 1)
        self.assertEqual(str(actual.exception), str(expected.exception))
        self.assertEqual(retrieve.call_count, 1)
        self.assertEqual(errors(optimized, 1), errors(stock, 1))
        self.assertEqual(retrieve.call_count, 2)
        self.assertEqual(stock_retrieve.call_count, 2)
        self.assertEqual(self.cache(optimized), {})

    def test_registered_real_lookup_failure_is_not_retried(self):
        from jsonschema.exceptions import _WrappedReferencingError
        from referencing.exceptions import Unresolvable

        schema = {
            "$schema": DIALECT,
            "$id": "urn:test:registered-failure",
            "$defs": {"value": {"const": 1}},
            "$ref": "#/$defs/value",
        }
        for failure, expected in (
            (Unresolvable(ref=schema["$ref"]), _WrappedReferencingError),
            (RuntimeError("transient"), RuntimeError),
        ):
            optimized, _ = self.build(schema, optimize_unions=False)
            source = optimized._resolver
            original = type(source).lookup
            calls = []

            def lookup(resolver, ref):
                if resolver is source:
                    calls.append(ref)
                    if len(calls) == 1:
                        raise failure
                return original(resolver, ref)

            with patch.object(type(source), "lookup", lookup):
                with self.assertRaises(expected):
                    errors(optimized, 1)
                self.assertEqual(len(calls), 1)
                self.assertEqual(self.cache(optimized), {})
                self.assertTrue(optimized.is_valid(1))
                self.assertEqual(len(calls), 2)
                self.assertEqual(len(self.cache(optimized)), 1)

    def test_legacy_resolver_delegates_to_stock_callback(self):
        schema = {
            "$schema": DIALECT,
            "$id": "urn:test:legacy",
            "$ref": "#/$defs/value",
            "$defs": {"value": {"type": "integer"}},
        }
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from jsonschema import RefResolver

            legacy = RefResolver.from_schema(schema)
        original = Draft202012Validator.VALIDATORS["$ref"]
        with patch.dict(
            Draft202012Validator.VALIDATORS,
            {
                "$ref": unittest.mock.Mock(wraps=original),
            },
        ):
            recorder = Draft202012Validator.VALIDATORS["$ref"]
            registry = registry_for([schema])
            backend = canonical_backend([schema], registry, optimize_unions=False)
        optimized = backend(schema, registry=registry, resolver=legacy)
        self.assertTrue(optimized.is_valid(1))
        self.assertFalse(optimized.is_valid("bad"))
        self.assertEqual(recorder.call_count, 2)
        self.assertEqual(self.cache(optimized), {})

    def test_ablation_options_keep_stock_callbacks_and_isolated_evolution(self):
        schema = {
            "$schema": DIALECT,
            "$id": "urn:test:flags",
            "oneOf": [branch("a"), branch("b")],
        }
        for union_flag in (False, True):
            for ref_flag in (False, True):
                optimized, stock = self.build(
                    schema, optimize_unions=union_flag, cache_references=ref_flag
                )
                handlers = type(optimized).VALIDATORS
                self.assertEqual(
                    handlers["oneOf"] is Draft202012Validator.VALIDATORS["oneOf"],
                    not union_flag,
                )
                self.assertEqual(
                    handlers["$ref"] is Draft202012Validator.VALIDATORS["$ref"],
                    not ref_flag,
                )
                self.assertIs(type(optimized.evolve(schema=schema)), type(optimized))
                for value in ({"type": "a", "value": 1}, {"type": "a"}, {}):
                    self.assertEqual(errors(optimized, value), errors(stock, value))


class CanonicalCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runtime = Validator()
        cls.schemas = json.loads(
            (ROOT / "src/agenthooksprotocol/schemas.json").read_text()
        )
        registry = registry_for(cls.schemas)
        cls.stock = {
            schema["$id"].rsplit("/", 1)[-1]: Draft202012Validator(
                schema, registry=registry, format_checker=FormatChecker()
            )
            for schema in cls.schemas
        }

    def compare(self, name, value):
        with self.subTest(schema=name, value=value):
            self.assertEqual(
                errors(self.runtime.validators[name], value),
                errors(self.stock[name], value),
            )

    def test_hot_event_unions_skip_stock_kernel_for_known_fixture_tag(self):
        original = Draft202012Validator.VALIDATORS["oneOf"]
        with patch.dict(
            Draft202012Validator.VALIDATORS,
            {
                "oneOf": unittest.mock.Mock(wraps=original),
            },
        ):
            recorder = Draft202012Validator.VALIDATORS["oneOf"]
            runtime = Validator()
        cases = json.loads((ROOT / "tests/structural-acceptance.json").read_text())[
            "cases"
        ]
        value = next(
            case["value"] for case in cases if case["id"] == "ordinary-request"
        )
        event_validator = runtime.validators["event.schema.json"]
        self.assertTrue(event_validator.is_valid(value["params"]["event"]))
        runtime.validate("intercept-request", value)
        event_union = runtime.validators["intercept-request.schema.json"].schema[
            "allOf"
        ][1]["properties"]["params"]["properties"]["event"]
        hot_schemas = (event_validator.schema, event_union)
        self.assertFalse(
            any(
                call.args[3] is schema
                for call in recorder.call_args_list
                for schema in hot_schemas
            )
        )

    def test_all_schema_roots_and_structural_corpus(self):
        for name in self.stock:
            for value in (None, False, 0, "", [], {}, {"type": "unknown"}):
                self.compare(name, value)
        cases = json.loads((ROOT / "tests/structural-acceptance.json").read_text())[
            "cases"
        ]
        for case in cases:
            name = case["root"].replace("_", "-") + ".schema.json"
            if name in self.stock:
                self.compare(name, case["value"])

    def test_pinned_sibling_fixture_corpus(self):
        sibling = ROOT.parent / "agent-hooks-protocol"
        manifest = sibling / "fixtures/draft/manifest.json"
        if not manifest.exists():
            self.skipTest("pinned sibling protocol checkout not available")
        checked = 0
        for case in json.loads(manifest.read_text())["cases"]:
            name = Path(case["schema"]).name
            if name not in self.stock:
                continue
            raw = (sibling / case["path"]).read_text()
            try:
                values = [json.loads(raw)]
            except json.JSONDecodeError:
                values = []
                for line in raw.splitlines():
                    try:
                        values.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass  # malformed transport framing is not schema input
            for value in values:
                self.compare(name, value)
                checked += 1
                # Canonical errors must preserve first-error ProtocolError paths.
                kind = name.removesuffix(".schema.json")
                stock_error = next(self.stock[name].iter_errors(value), None)
                if stock_error is not None and kind in (
                    "intercept-request",
                    "intercept-response",
                    "observe-notification",
                ):
                    with self.assertRaises(ProtocolError) as caught:
                        self.runtime.validate(kind, value)
                    expected = (
                        "Canonical schema rejected "
                        + kind
                        + ": "
                        + "/".join(map(str, stock_error.path))
                    )
                    self.assertEqual(str(caught.exception), expected)
        self.assertGreater(checked, 50)

    def test_single_error_pass_and_generated_codec_still_required(self):
        validator = self.runtime.validators["intercept-response.schema.json"]
        with patch.object(
            type(validator), "is_valid", side_effect=AssertionError("double validation")
        ):
            # {} has no oneOf successful branches requiring stock is_valid.
            with self.assertRaises(ProtocolError):
                self.runtime.validate("intercept-response", {})
        from agenthooksprotocol import generated

        cases = json.loads((ROOT / "tests/structural-acceptance.json").read_text())[
            "cases"
        ]
        value = next(
            case["value"] for case in cases if case["id"] == "ordinary-request"
        )
        with patch.object(
            generated, "parse_intercept_request", return_value={"ok": False}
        ):
            with self.assertRaisesRegex(ProtocolError, "Generated codec rejected"):
                self.runtime.validate("intercept-request", value)

    def test_form_answer_remains_stock_and_remote_resolution_blocked(self):
        with patch(
            "agenthooksprotocol.runtime.Draft202012Validator",
            wraps=Draft202012Validator,
        ) as stock:
            value = {
                "schema": {"oneOf": [branch("a"), branch("a")]},
                "value": {"type": "a", "value": 1},
            }
            with self.assertRaises(Exception) as caught:
                self.runtime.validate("form-answer", value)
            self.assertEqual(type(caught.exception).__name__, "ValidationError")
            self.assertEqual(stock.call_count, 1)
        with self.assertRaises(Exception) as caught:
            self.runtime.validate(
                "form-answer",
                {
                    "schema": {"$ref": "https://invalid.example/not-fetched"},
                    "value": {},
                },
            )
        self.assertIn(
            "Unresolvable", type(caught.exception).__name__ + str(caught.exception)
        )

    def test_fragment_validators_are_prebound_and_equivalent(self):
        for kind, optimized in self.runtime._fragments.items():
            stock = self.stock["mcp-elicitation.schema.json"].evolve(
                schema=optimized.schema
            )
            for value in (
                None,
                {},
                {"action": "accept", "content": {}},
                {
                    "mode": "form",
                    "message": "m",
                    "requestedSchema": {"type": "object", "properties": {}},
                },
            ):
                self.assertEqual(errors(optimized, value), errors(stock, value))


if __name__ == "__main__":
    unittest.main()
