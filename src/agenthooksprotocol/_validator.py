"""Private, per-bundle oneOf pruning; never changes schemas or global validators."""

from collections import OrderedDict
from threading import Lock

from attrs import evolve as attrs_evolve, fields
from jsonschema import Draft202012Validator, exceptions, validators
from referencing import Registry
from referencing.exceptions import NoSuchResource, Unresolvable
from referencing.jsonschema import DRAFT202012


class _UnsafePlan(Exception):
    pass


def canonical_backend(
    schemas, registry, *, optimize_unions=True, cache_references=True
):
    """Lazily compile original canonical schemas, never caller form schemas.

    Constraints are necessary conditions, not replacement validation. Missing
    properties prove nothing. Unsafe branches remain unconditional candidates.
    Schemas must remain unchanged after construction. All schema-only caches are
    per backend and retain schema identities. Compiler caches include base URI;
    the bounded runtime reference cache instead retains exact source resolvers
    and complete resolution results, including dynamic scope and registry.
    """
    plans = {}
    safety = {}
    extracted = {}
    references = {}
    owned = {id(schema): schema for schema in schemas}
    indexed = set()
    stock_one_of = Draft202012Validator.VALIDATORS["oneOf"]
    stock_ref = Draft202012Validator.VALIDATORS["$ref"]
    default_retrieve = getattr(Registry(), "_retrieve", None)
    resolution_cache = OrderedDict()
    resolution_lock = Lock()
    compatibility_cache = OrderedDict()
    compatibility_lock = Lock()
    expected_graph = []

    def deny_retrieval(uri):
        raise NoSuchResource(ref=uri)

    # Persistent registry copy shares existing resources; compiler lookups never
    # invoke even a caller-provided retriever. Runtime resolution stays original.
    compiler_registry = attrs_evolve(registry, retrieve=deny_retrieval)

    def plan_key(schema, resolver):
        # referencing has no public base-URI accessor. If it changes, disable
        # pruning rather than sharing a plan across scopes.
        base_uri = getattr(resolver, "_base_uri", None)
        if isinstance(base_uri, str):
            return id(schema), base_uri
        return None

    def child_resolver(schema, resolver):
        return resolver.in_subresource(DRAFT202012.create_resource(schema))

    def resolve(ref, resolver):
        if not isinstance(ref, str):
            raise _UnsafePlan
        key = (getattr(resolver, "_base_uri", None), ref)
        if key not in references:
            try:
                references[key] = resolver.lookup(ref)
            except Exception:
                references[key] = None
        resolved = references[key]
        if resolved is None:
            raise _UnsafePlan
        return resolved

    def index_owned(schema):
        if id(schema) in indexed:
            return
        indexed.add(id(schema))
        owned[id(schema)] = schema
        for resource in DRAFT202012.create_resource(schema).subresources():
            index_owned(resource.contents)

    def is_owned(schema, resolver):
        if owned.get(id(schema)) is schema:
            return True
        key = plan_key(schema, resolver)
        if key is None:
            return False
        try:
            resource = resolve(key[1], resolver).contents
        except _UnsafePlan:
            return False
        if owned.get(id(resource)) is resource:
            # Index only a resource actually visited by validation, not all
            # bundle documents. Definitions establish ownership, not safety.
            index_owned(resource)
        return owned.get(id(schema)) is schema

    def safe_graph(schema, resolver, active):
        if not isinstance(schema, dict):
            return
        key = plan_key(schema, resolver)
        if key is None or id(schema) in active:
            raise _UnsafePlan
        record = safety.get(key)
        if record is not None and record[0] is schema:
            if not record[1]:
                raise _UnsafePlan
            return
        try:
            if (
                "$dynamicRef" in schema
                or "$recursiveRef" in schema
                or any(
                    isinstance(branch, dict) and "$id" in branch
                    for branch in schema.get("oneOf", ())
                )
                or schema.get("$schema", Draft202012Validator.META_SCHEMA["$id"])
                != Draft202012Validator.META_SCHEMA["$id"]
            ):
                raise _UnsafePlan
            active = active | {id(schema)}
            if "$ref" in schema:
                resolved = resolve(schema["$ref"], resolver)
                safe_graph(resolved.contents, resolved.resolver, active)
            # Definition containers are inert. Follow their schemas only via
            # actual refs, avoiding artificial cycles through unused definitions.
            evaluated = {
                key: value
                for key, value in schema.items()
                if key not in {"$defs", "definitions"}
            }
            for resource in DRAFT202012.create_resource(evaluated).subresources():
                safe_graph(resource.contents, resolver.in_subresource(resource), active)
        except _UnsafePlan:
            safety[key] = schema, False
            raise
        safety[key] = schema, True

    def constraints(schema, resolver):
        if not isinstance(schema, dict):
            return ()
        key = plan_key(schema, resolver)
        record = extracted.get(key)
        if record is not None and record[0] is schema:
            return record[1]
        result = []
        if isinstance(schema.get("const"), str):
            result.append(((), schema["const"]))
        if "$ref" in schema:
            resolved = resolve(schema["$ref"], resolver)
            result.extend(constraints(resolved.contents, resolved.resolver))
        for branch in schema.get("allOf", ()):
            result.extend(constraints(branch, child_resolver(branch, resolver)))
        for name, subschema in schema.get("properties", {}).items():
            result.extend(
                ((name,) + path, tag)
                for path, tag in constraints(
                    subschema, child_resolver(subschema, resolver)
                )
            )
        result = tuple(result)
        extracted[key] = schema, result
        return result

    def prepare(schema, resolver):
        # Stock initial branches enter $id scopes; remaining branches evolve
        # without doing so. Never compile a union affected by that scope quirk.
        if any(
            isinstance(branch, dict) and "$id" in branch for branch in schema["oneOf"]
        ):
            return None
        branches = []
        for branch in schema["oneOf"]:
            try:
                scoped = child_resolver(branch, resolver)
                safe_graph(branch, scoped, set())
                conditions = constraints(branch, scoped)
            except _UnsafePlan:
                conditions = ()
            branches.append(conditions)
        return tuple(branches)

    def matches(instance, constraint, validator):
        path, tag = constraint
        for name in path:
            if not validator.is_type(instance, "object") or name not in instance:
                return None
            instance = instance[name]
        return instance == tag

    def compatible_registry(actual):
        if actual is None:
            return False
        with compatibility_lock:
            record = compatibility_cache.get(id(actual))
            if record is not None and record[0] is actual:
                compatibility_cache.move_to_end(id(actual))
                return record[1]
            if not expected_graph:
                expected = validators.SPECIFICATIONS.combine(registry).crawl()
                expected_graph.append({uri: expected[uri].contents for uri in expected})
            expected = expected_graph[0]
        try:
            crawled = actual.crawl()
            compatible = len(crawled) == len(expected) and all(
                uri in crawled and crawled[uri].contents is contents
                for uri, contents in expected.items()
            )
        except Exception:
            compatible = False
        with compatibility_lock:
            compatibility_cache[id(actual)] = actual, compatible
            compatibility_cache.move_to_end(id(actual))
            if len(compatibility_cache) > 256:
                compatibility_cache.popitem(last=False)
        return compatible

    def one_of(validator, branches, instance, schema):
        actual_registry = getattr(validator._resolver, "_registry", None)
        retrieve = getattr(actual_registry, "_retrieve", None)
        if (
            getattr(validator, "_registry", None) is not registry
            or default_retrieve is None
            or retrieve is not default_retrieve
            or validator._ref_resolver is not None
            or not validator.is_type(instance, "object")
            or not compatible_registry(actual_registry)
        ):
            # Plans belong to the construction graph. Registry substitutions,
            # extra resources, and stateful retrieval must retain stock behavior.
            yield from stock_one_of(validator, branches, instance, schema)
            return
        plan = None
        key = plan_key(schema, validator._resolver)
        if (
            key is not None
            and validator._ref_resolver is None
            and validator.is_type(instance, "object")
        ):
            record = plans.get(key)
            if record is None:
                resolver = compiler_registry.resolver(base_uri=key[1])
                plan = prepare(schema, resolver) if is_owned(schema, resolver) else None
                record = plans[key] = schema, plan
            if record[0] is schema:
                plan = record[1]
        if plan is not None:
            candidates = []
            for index, conditions in enumerate(plan):
                if not any(
                    matches(instance, condition, validator) is False
                    for condition in conditions
                ):
                    candidates.append(index)
            if len(candidates) < len(branches):
                valid_count = 0
                for index in candidates:
                    if valid_count:
                        # Match stock remaining-branch scope and traversal even
                        # after a second winner: a later branch may raise.
                        valid = validator.evolve(schema=branches[index]).is_valid(
                            instance
                        )
                    else:
                        errors = validator.descend(
                            instance, branches[index], schema_path=index
                        )
                        if plan[index]:
                            valid = next(errors, None) is None
                        else:
                            # Exhaust unsafe initial branches just like stock:
                            # refs after an earlier error must still raise.
                            valid = not list(errors)
                    if valid:
                        valid_count += 1
                if valid_count == 1:
                    return
        yield from stock_one_of(validator, branches, instance, schema)

    def reference(validator, ref, instance, schema):
        if validator._ref_resolver is not None or not isinstance(ref, str):
            yield from stock_ref(validator, ref, instance, schema)
            return
        source = validator._resolver
        key = id(source), ref
        with resolution_lock:
            record = resolution_cache.get(key)
            if record is not None and record[0] is source:
                resolution_cache.move_to_end(key)
                resolved = record[1]
            else:
                resolved = None
        if resolved is None:
            try:
                # Only resources already registered in this exact resolver's
                # immutable registry are cacheable. Retrieval may be stateful.
                probe = attrs_evolve(
                    source,
                    registry=attrs_evolve(source._registry, retrieve=deny_retrieval),
                )
                probe.lookup(ref)
            except Exception:
                yield from stock_ref(validator, ref, instance, schema)
                return
            try:
                resolved = source.lookup(ref)
            except Unresolvable as err:
                # Match stock wrapping, without retrying a failed real lookup.
                raise exceptions._WrappedReferencingError(err) from err
            with resolution_lock:
                resolution_cache[key] = source, resolved
                resolution_cache.move_to_end(key)
                if len(resolution_cache) > 256:
                    resolution_cache.popitem(last=False)
        yield from validator.descend(
            instance, resolved.contents, resolver=resolved.resolver
        )

    backend = validators.extend(
        Draft202012Validator,
        {
            "oneOf": one_of if optimize_unions else stock_one_of,
            "$ref": reference if cache_references else stock_ref,
        },
    )

    def evolve(self, **changes):
        # Preserve isolated backend across explicit 2020-12 $schema evolution,
        # retaining stock dialect selection for other schema dialects.
        schema = changes.setdefault("schema", self.schema)
        target = validators.validator_for(schema, default=backend)
        if target is Draft202012Validator:
            target = backend
        for field in fields(backend):
            if field.init and field.alias not in changes:
                changes[field.alias] = getattr(self, field.name)
        return target(**changes)

    backend.evolve = evolve
    return backend
