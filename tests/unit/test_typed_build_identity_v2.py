from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from enum import IntEnum
from typing import TYPE_CHECKING

import pytest
from mypy.options import Options

from fastapi_endpoint_detector.models.typed_build_identity import (
    CacheDisposition,
    CacheReason,
    IdentityError,
    TypedBuildIdentityV2,
    _record_value,
    canonical_bytes,
    digest,
    semantic_mypy_options,
)

if TYPE_CHECKING:
    from collections.abc import Callable

_VERSION = "1.19.1"


class _FixtureOptionEnum(IntEnum):
    ENABLED = 1


def _options() -> dict[str, object]:
    options = Options()
    names = Options.__mypyc_attrs__  # type: ignore[attr-defined]
    return {name: getattr(options, name) for name in names}


def _semantic_context() -> dict[str, object]:
    return {
        "canonical_root": "/repo",
        "search_paths": ["/repo/src", "/deps"],
        "import_roots": ["/repo/src"],
        "resolved_modules": [
            {
                "fullname": "pkg.api",
                "path": "/repo/src/pkg/api.py",
                "side": "project",
                "origin": "source",
            },
            {
                "fullname": "fastapi.applications",
                "path": "/deps/fastapi/applications.py",
                "side": "dependency",
                "origin": "source",
            },
        ],
        "plugins": ["plugin-x@1.2"],
        "analyzer_config": {"max_depth": 12},
        "toolchain": {
            "python_implementation": "CPython",
            "python_version": "3.11.16",
            "platform": "linux-x86_64",
        },
    }


def _identity(**overrides: object) -> TypedBuildIdentityV2:
    values: dict[str, object] = {
        "semantic_context": _semantic_context(),
        "mypy_options": _options(),
        "mypy_version": _VERSION,
        "actual_build_context": {
            "engine": "mypy-build",
            "engine_version": _VERSION,
            "python": "CPython-3.11.16",
            "config_sha256": "sha256:" + "a" * 64,
            "module_root": "/repo",
            "invocation_mode": "cold",
        },
        "source_inventory": [
            {
                "fullname": "pkg.api",
                "path": "/repo/src/pkg/api.py",
                "origin": "source",
                "side": "project",
                "source_sha256": "sha256:" + "b" * 64,
            },
            {
                "fullname": "fastapi.applications",
                "path": "/deps/fastapi/applications.py",
                "origin": "source",
                "side": "dependency",
                "source_sha256": "sha256:" + "f" * 64,
            },
        ],
        "provider_semantic_context": {"graph_sha256": "c" * 64},
        "build_provenance": {
            "schema": "typed-build-provenance-facts-v1",
            "fresh_modules": ["pkg.api"],
            "result": "success",
        },
    }
    values.update(overrides)
    return TypedBuildIdentityV2.create(**values)  # type: ignore[arg-type]


def _shape_limits(value: object) -> tuple[int, int]:
    pending: list[tuple[object, int]] = [(value, 0)]
    count = 0
    max_depth = 0
    while pending:
        current, depth = pending.pop()
        count += 1
        max_depth = max(max_depth, depth)
        if isinstance(current, dict):
            pending.extend((key, depth + 1) for key in current)
            pending.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, (list, tuple, set, frozenset)):
            pending.extend((item, depth + 1) for item in current)
    return count, max_depth


def test_domain_and_typed_encodings_are_stable_and_distinct() -> None:
    assert canonical_bytes([1, "1"], domain="x") != canonical_bytes((1, "1"), domain="x")
    assert digest({"x": True}, domain="semantic") != digest({"x": 1}, domain="semantic")
    assert digest({"x": _FixtureOptionEnum.ENABLED}, domain="semantic") != digest(
        {"x": 1}, domain="semantic"
    )
    assert digest({"x": {1}}, domain="semantic") != digest({"x": frozenset({1})}, domain="semantic")
    assert digest({"x": 1}, domain="semantic") != digest({"x": 1}, domain="provenance")
    assert canonical_bytes({"b": 2, "a": 1}, domain="x") == canonical_bytes(
        {"a": 1, "b": 2}, domain="x"
    )
    assert canonical_bytes({1, 2}, domain="x") == canonical_bytes({2, 1}, domain="x")


@pytest.mark.parametrize("value", [float("nan"), float("inf"), object()])
def test_unsupported_values_fail_closed(value: object) -> None:
    with pytest.raises(IdentityError):
        canonical_bytes({"value": value}, domain="test")


def test_canonical_bounds_reject_deep_and_oversized_values() -> None:
    value: object = "leaf"
    for _ in range(18):
        value = [value]
    with pytest.raises(IdentityError, match="depth"):
        canonical_bytes(value, domain="test")
    with pytest.raises(IdentityError, match="byte length"):
        canonical_bytes("x" * 70_000, domain="test")
    with pytest.raises(IdentityError, match="byte length"):
        canonical_bytes(["x" * 60_000 for _ in range(20)], domain="test")
    with pytest.raises(IdentityError, match="item count"):
        canonical_bytes([None] * 10_001, domain="test")


def test_canonical_bounds_accept_exact_depth_and_item_limits() -> None:
    value: object = "leaf"
    for _ in range(16):
        value = [value]
    depth_record = canonical_bytes(value, domain="test").decode()
    item_record = canonical_bytes([None] * 9_999, domain="test").decode()
    assert _record_value(depth_record, "test") == value
    assert _record_value(item_record, "test") == [None] * 9_999
    assert _record_value(canonical_bytes("x" * 65_536, domain="test").decode(), "test") == (
        "x" * 65_536
    )
    with pytest.raises(IdentityError, match="domain"):
        canonical_bytes(None, domain="x" * 129)


def test_identity_create_and_json_roundtrip_accept_exact_depth_and_item_limits() -> None:
    base = _identity()
    base_facts = _record_value(base.provenance_record, "typed-build-provenance-v2")
    base_count, _ = _shape_limits(base_facts)
    item_identity = _identity(provider_semantic_context={"items": [None] * (10_000 - base_count)})
    item_facts = _record_value(item_identity.provenance_record, "typed-build-provenance-v2")
    item_count, _ = _shape_limits(item_facts)
    assert item_count == 10_000

    nested: object = "leaf"
    depth_identity = base
    for _ in range(1, 17):
        nested = [nested]
        try:
            candidate = _identity(provider_semantic_context={"boundary": nested})
        except IdentityError:
            break
        candidate_facts = _record_value(candidate.provenance_record, "typed-build-provenance-v2")
        if _shape_limits(candidate_facts)[1] == 16:
            depth_identity = candidate
            break
    assert (
        _shape_limits(_record_value(depth_identity.provenance_record, "typed-build-provenance-v2"))[
            1
        ]
        == 16
    )

    for identity in (item_identity, depth_identity):
        encoded = identity.to_json()
        assert TypedBuildIdentityV2.from_json(encoded) == identity
        assert TypedBuildIdentityV2.from_dict(identity.to_dict()) == identity


def _reseal_provenance(
    identity: TypedBuildIdentityV2, mutate: Callable[[list[object]], None]
) -> dict[str, object]:
    envelope = json.loads(identity.provenance_record)
    assert isinstance(envelope, list)

    def find_build_provenance(node: object) -> list[object] | None:
        if isinstance(node, list):
            if (
                len(node) == 2
                and node[0] == ["str", "build_provenance"]
                and isinstance(node[1], list)
            ):
                return node[1]
            for child in node:
                found = find_build_provenance(child)
                if found is not None:
                    return found
        return None

    typed_build_provenance = find_build_provenance(envelope[2])
    assert typed_build_provenance is not None
    mutate(typed_build_provenance)
    record = json.dumps(envelope, ensure_ascii=False, separators=(",", ":"))
    values = identity.to_dict()
    values["provenance_record"] = record
    values["typed_build_provenance_sha256"] = (
        "sha256:" + hashlib.sha256(record.encode()).hexdigest()
    )
    return values


def test_outer_json_depth_is_bounded_and_normalized() -> None:
    with pytest.raises(IdentityError, match="nesting depth"):
        TypedBuildIdentityV2.from_json("[" * 1_500 + "0" + "]" * 1_500)


def test_typed_sets_require_hashable_unique_canonical_members() -> None:
    for encoded_set in (
        ["set", [["list", [["int", "1"]]]]],
        ["set", [["int", "2"], ["int", "1"]]],
        ["set", [["int", "1"], ["int", "1"]]],
    ):
        envelope = ["fed-canonical-json-v1", "malformed-set", encoded_set]
        record = json.dumps(envelope, separators=(",", ":"))
        with pytest.raises(IdentityError):
            _record_value(record, "malformed-set")
    out_of_order_mapping = [
        "fed-canonical-json-v1",
        "malformed-map",
        [
            "mapping",
            [
                [["str", "z"], ["int", "1"]],
                [["str", "a"], ["int", "2"]],
            ],
        ],
    ]
    with pytest.raises(IdentityError, match="out of order"):
        _record_value(json.dumps(out_of_order_mapping, separators=(",", ":")), "malformed-map")


@pytest.mark.parametrize(
    "bad_set",
    [
        ["set", [["list", [["str", "pkg.api"]]]]],
        ["set", [["str", "pkg.api"], ["str", "pkg.api"]]],
        ["set", [["str", "z"], ["str", "a"]]],
    ],
)
def test_resealed_bad_typed_sets_fail_all_public_constructors(bad_set: list[object]) -> None:
    identity = _identity()

    def replace_fresh_modules(build: list[object]) -> None:
        entries = build[1]
        assert isinstance(entries, list)
        for pair in entries:
            assert isinstance(pair, list)
            if pair[0] == ["str", "fresh_modules"]:
                pair[1] = bad_set
                return
        raise AssertionError("fresh_modules field missing")

    resealed = _reseal_provenance(identity, replace_fresh_modules)
    with pytest.raises(IdentityError):
        TypedBuildIdentityV2.from_dict(resealed)
    with pytest.raises(IdentityError):
        TypedBuildIdentityV2.from_json(json.dumps(resealed, separators=(",", ":")))
    with pytest.raises(IdentityError):
        bad_record = resealed["provenance_record"]
        bad_digest = resealed["typed_build_provenance_sha256"]
        assert isinstance(bad_record, str) and isinstance(bad_digest, str)
        replace(
            identity,
            provenance_record=bad_record,
            typed_build_provenance_sha256=bad_digest,
        )


@pytest.mark.parametrize(
    ("field_name", "typed_value"),
    [("result", ["str", "failure"]), ("fresh_modules", ["list", [["str", "unrelated.module"]]])],
)
def test_resealed_hit_build_fact_contradictions_fail_all_constructors(
    field_name: str, typed_value: list[object]
) -> None:
    hit = _identity(
        cache_disposition=CacheDisposition.AUTHENTICATED_DEPENDENCY_HIT,
        cache_reason=None,
        cache_attestation_sha256="sha256:" + "d" * 64,
        cache_claim_facts={
            "cache_manifest_sha256": "sha256:" + "e" * 64,
            "trust_id": "fixture-only-trust-label",
            "observed_cache_hit": True,
            "fresh_project_modules": ["pkg.api"],
            "selected_consumers": ["fixture consumer"],
            "source_recheck_complete": True,
        },
        actual_build_context={
            "engine": "mypy-build",
            "engine_version": _VERSION,
            "python": "CPython-3.11.16",
            "config_sha256": "sha256:" + "a" * 64,
            "module_root": "/repo",
            "invocation_mode": "authenticated_dependency_hit",
        },
    )

    def alter_build_fact(build: list[object]) -> None:
        entries = build[1]
        assert isinstance(entries, list)
        for pair in entries:
            assert isinstance(pair, list)
            if pair[0] == ["str", field_name]:
                pair[1] = typed_value
                return
        raise AssertionError(f"{field_name} field missing")

    resealed = _reseal_provenance(hit, alter_build_fact)
    with pytest.raises(IdentityError):
        TypedBuildIdentityV2.from_dict(resealed)
    with pytest.raises(IdentityError):
        TypedBuildIdentityV2.from_json(json.dumps(resealed, separators=(",", ":")))
    with pytest.raises(IdentityError):
        replace(
            hit,
            provenance_record=resealed["provenance_record"],  # type: ignore[arg-type]
            typed_build_provenance_sha256=resealed["typed_build_provenance_sha256"],  # type: ignore[arg-type]
        )


def test_resealed_wrong_domain_is_rejected() -> None:
    identity = _identity()
    envelope = json.loads(identity.provenance_record)
    envelope[1] = "typed-build-provenance-v99"
    record = json.dumps(envelope, separators=(",", ":"))
    with pytest.raises(IdentityError, match="unknown encoding or domain"):
        replace(
            identity,
            provenance_record=record,
            typed_build_provenance_sha256="sha256:" + hashlib.sha256(record.encode()).hexdigest(),
        )


def test_resealed_hit_with_cold_invocation_mode_fails_all_constructors() -> None:
    hit = _identity(
        cache_disposition=CacheDisposition.AUTHENTICATED_DEPENDENCY_HIT,
        cache_reason=None,
        cache_attestation_sha256="sha256:" + "d" * 64,
        cache_claim_facts={
            "cache_manifest_sha256": "sha256:" + "e" * 64,
            "trust_id": "fixture-only-trust-label",
            "observed_cache_hit": True,
            "fresh_project_modules": ["pkg.api"],
            "selected_consumers": ["fixture consumer"],
            "source_recheck_complete": True,
        },
        actual_build_context={
            "engine": "mypy-build",
            "engine_version": _VERSION,
            "python": "CPython-3.11.16",
            "config_sha256": "sha256:" + "a" * 64,
            "module_root": "/repo",
            "invocation_mode": "authenticated_dependency_hit",
        },
    )

    def replace_typed_mapping_value(node: object, key: str, value: list[object]) -> None:
        if not isinstance(node, list):
            return
        if len(node) == 2 and node[0] == "mapping" and isinstance(node[1], list):
            for pair in node[1]:
                if isinstance(pair, list) and len(pair) == 2:
                    if pair[0] == ["str", key]:
                        pair[1] = value
                    else:
                        replace_typed_mapping_value(pair[1], key, value)
        else:
            for child in node:
                replace_typed_mapping_value(child, key, value)

    actual_envelope = json.loads(hit.actual_options_record)
    replace_typed_mapping_value(actual_envelope[2], "invocation_mode", ["str", "cold"])
    actual_record = json.dumps(actual_envelope, separators=(",", ":"))
    actual_digest = "sha256:" + hashlib.sha256(actual_record.encode()).hexdigest()
    provenance_envelope = json.loads(hit.provenance_record)
    replace_typed_mapping_value(provenance_envelope[2], "invocation_mode", ["str", "cold"])
    replace_typed_mapping_value(
        provenance_envelope[2], "actual_build_options_sha256", ["str", actual_digest]
    )
    provenance_record = json.dumps(provenance_envelope, separators=(",", ":"))
    provenance_digest = "sha256:" + hashlib.sha256(provenance_record.encode()).hexdigest()
    resealed = hit.to_dict() | {
        "actual_options_record": actual_record,
        "actual_build_options_sha256": actual_digest,
        "provenance_record": provenance_record,
        "typed_build_provenance_sha256": provenance_digest,
    }
    with pytest.raises(IdentityError, match="invocation mode"):
        TypedBuildIdentityV2.from_dict(resealed)
    with pytest.raises(IdentityError, match="invocation mode"):
        TypedBuildIdentityV2.from_json(json.dumps(resealed, separators=(",", ":")))
    with pytest.raises(IdentityError, match="invocation mode"):
        replace(
            hit,
            actual_options_record=actual_record,
            actual_build_options_sha256=actual_digest,
            provenance_record=provenance_record,
            typed_build_provenance_sha256=provenance_digest,
        )


def test_build_provenance_rejects_contradictory_and_unknown_cache_claims() -> None:
    contradictory = {
        "schema": "typed-build-provenance-facts-v1",
        "fresh_modules": ["pkg.api"],
        "result": "success",
        "cache_disposition": "authenticated_dependency_hit",
        "cache_attestation_sha256": "sha256:" + "9" * 64,
        "observed_cache_hit": True,
    }
    with pytest.raises(IdentityError, match="unknown fields"):
        _identity(build_provenance=contradictory)
    with pytest.raises(IdentityError, match="unknown schema"):
        _identity(build_provenance={"schema": "v2", "fresh_modules": [], "result": "success"})


def test_fully_resealed_deep_provenance_is_bounded_before_decode() -> None:
    identity = _identity()
    envelope = json.loads(identity.provenance_record)
    mapping_pairs = envelope[2][1]
    for pair in mapping_pairs:
        if pair[0] == ["str", "build_provenance"]:
            pair[1] = ["str", "DEPTH_MARKER"]
            break
    deep_json = "[" * 1_200 + "0" + "]" * 1_200
    record = json.dumps(envelope, ensure_ascii=False, separators=(",", ":")).replace(
        '"DEPTH_MARKER"', deep_json
    )
    sealed = identity.to_dict() | {
        "provenance_record": record,
        "typed_build_provenance_sha256": "sha256:" + hashlib.sha256(record.encode()).hexdigest(),
    }
    encoded = json.dumps(sealed, ensure_ascii=False, separators=(",", ":"))
    with pytest.raises(IdentityError, match="nesting depth"):
        TypedBuildIdentityV2.from_dict(sealed)
    with pytest.raises(IdentityError, match="nesting depth"):
        TypedBuildIdentityV2.from_json(encoded)
    with pytest.raises(IdentityError, match="nesting depth"):
        replace(
            identity,
            provenance_record=record,
            typed_build_provenance_sha256=("sha256:" + hashlib.sha256(record.encode()).hexdigest()),
        )


def test_mypy_projection_excludes_only_three_pinned_cache_controls() -> None:
    options = _options()
    semantic = semantic_mypy_options(options, mypy_version=_VERSION)
    assert set(options) - set(semantic) == {"incremental", "cache_dir", "cache_map"}
    assert "export_types" in semantic and "follow_imports" in semantic
    with pytest.raises(IdentityError, match="version"):
        semantic_mypy_options(options, mypy_version="1.20.0")
    unknown = options | {"future_option": False}
    with pytest.raises(IdentityError, match="schema"):
        semantic_mypy_options(unknown, mypy_version=_VERSION)
    wrong_type = options | {"incremental": "yes"}
    with pytest.raises(IdentityError, match="value type"):
        semantic_mypy_options(wrong_type, mypy_version=_VERSION)
    known_value = options | {"config_file": "/repo/pyproject.toml", "files": ["pkg.api"]}
    assert semantic_mypy_options(known_value, mypy_version=_VERSION)["config_file"] == (
        "/repo/pyproject.toml"
    )
    unsupported_value = options | {"transform_source": lambda source: source}
    with pytest.raises(IdentityError, match="unsupported"):
        semantic_mypy_options(unsupported_value, mypy_version=_VERSION)


def test_identity_partition_retains_actual_options_and_resolution_context() -> None:
    baseline = _identity()
    enum_context = _identity(provider_semantic_context={"fixture": _FixtureOptionEnum.ENABLED})
    assert enum_context == TypedBuildIdentityV2.from_json(enum_context.to_json())
    changed_cache = _options()
    changed_cache["incremental"] = not bool(changed_cache["incremental"])
    cache_variant = _identity(mypy_options=changed_cache)
    assert baseline.semantic_config_sha256 == cache_variant.semantic_config_sha256
    assert baseline.actual_build_options_sha256 != cache_variant.actual_build_options_sha256
    assert baseline.typed_build_provenance_sha256 != cache_variant.typed_build_provenance_sha256
    changed_semantic = _options()
    changed_semantic["export_types"] = not bool(changed_semantic["export_types"])
    semantic_variant = _identity(mypy_options=changed_semantic)
    assert baseline.semantic_config_sha256 != semantic_variant.semantic_config_sha256
    assert baseline.actual_build_options_sha256 != semantic_variant.actual_build_options_sha256
    changed_context = _semantic_context()
    changed_context["canonical_root"] = "/other"
    changed_actual = {
        "engine": "mypy-build",
        "engine_version": _VERSION,
        "python": "CPython-3.11.16",
        "config_sha256": "sha256:" + "a" * 64,
        "module_root": "/other",
        "invocation_mode": "cold",
    }
    changed_root = _identity(semantic_context=changed_context, actual_build_context=changed_actual)
    assert baseline.semantic_config_sha256 != changed_root.semantic_config_sha256
    assert baseline.actual_options_record.startswith('["fed-canonical-json-v1"')
    assert "effective_mypy_options" in baseline.actual_options_record
    mismatched_inventory = [
        {
            "fullname": "pkg.api",
            "path": "/elsewhere/api.py",
            "origin": "source",
            "side": "project",
            "source_sha256": "sha256:" + "b" * 64,
        },
        {
            "fullname": "fastapi.applications",
            "path": "/deps/fastapi/applications.py",
            "origin": "source",
            "side": "dependency",
            "source_sha256": "sha256:" + "f" * 64,
        },
    ]
    with pytest.raises(IdentityError, match="does not match"):
        _identity(source_inventory=mismatched_inventory)
    with pytest.raises(IdentityError, match="normalized"):
        _identity(semantic_context=_semantic_context() | {"canonical_root": "/repo/../repo"})


def test_identity_strict_roundtrip_and_disposition_nullability() -> None:
    identity = _identity()
    assert TypedBuildIdentityV2.from_dict(identity.to_dict()) == identity
    assert TypedBuildIdentityV2.from_json(identity.to_json()) == identity
    with pytest.raises(IdentityError, match="duplicate"):
        TypedBuildIdentityV2.from_json('{"x":1,"x":2}')
    with pytest.raises(IdentityError, match="constant"):
        TypedBuildIdentityV2.from_json('{"x":NaN}')
    altered = copy.deepcopy(identity.to_dict())
    altered["unexpected"] = True
    with pytest.raises(IdentityError, match="unknown"):
        TypedBuildIdentityV2.from_dict(altered)
    altered = identity.to_dict()
    altered["actual_options_record"] = "tampered"
    with pytest.raises(IdentityError, match="does not match"):
        TypedBuildIdentityV2.from_dict(altered)
    with pytest.raises(IdentityError, match="disposition or reason"):
        TypedBuildIdentityV2(
            identity.semantic_config_sha256,
            identity.actual_build_options_sha256,
            identity.source_inventory_sha256,
            identity.typed_provider_semantic_sha256,
            identity.typed_build_provenance_sha256,
            None,
            CacheDisposition.AUTHENTICATED_DEPENDENCY_HIT,
            None,
            identity.actual_options_record,
            identity.provenance_record,
        )
    fallback = _identity(
        cache_disposition=CacheDisposition.COLD_FALLBACK,
        cache_reason=CacheReason.SOURCE_CHANGED,
        actual_build_context={
            "engine": "mypy-build",
            "engine_version": _VERSION,
            "python": "CPython-3.11.16",
            "config_sha256": "sha256:" + "a" * 64,
            "module_root": "/repo",
            "invocation_mode": "cold_fallback",
        },
    )
    assert fallback.to_dict()["cache_attestation_sha256"] is None
    with pytest.raises(IdentityError, match="fact set"):
        _identity(
            cache_disposition=CacheDisposition.AUTHENTICATED_DEPENDENCY_HIT,
            cache_reason=None,
            cache_attestation_sha256="d" * 71,
        )
    hit = _identity(
        cache_disposition=CacheDisposition.AUTHENTICATED_DEPENDENCY_HIT,
        cache_reason=None,
        cache_attestation_sha256="sha256:" + "d" * 64,
        cache_claim_facts={
            "cache_manifest_sha256": "sha256:" + "e" * 64,
            "trust_id": "fixture-only-trust-label",
            "observed_cache_hit": True,
            "fresh_project_modules": ["pkg.api"],
            "selected_consumers": ["fixture consumer"],
            "source_recheck_complete": True,
        },
        actual_build_context={
            "engine": "mypy-build",
            "engine_version": _VERSION,
            "python": "CPython-3.11.16",
            "config_sha256": "sha256:" + "a" * 64,
            "module_root": "/repo",
            "invocation_mode": "authenticated_dependency_hit",
        },
    )
    assert hit.cache_disposition is CacheDisposition.AUTHENTICATED_DEPENDENCY_HIT


def test_hit_facts_must_match_mode_result_and_project_freshness() -> None:
    hit_facts = {
        "cache_manifest_sha256": "sha256:" + "e" * 64,
        "trust_id": "fixture-only-trust-label",
        "observed_cache_hit": True,
        "fresh_project_modules": ["pkg.api"],
        "selected_consumers": ["fixture consumer"],
        "source_recheck_complete": True,
    }
    hit_context = {
        "engine": "mypy-build",
        "engine_version": _VERSION,
        "python": "CPython-3.11.16",
        "config_sha256": "sha256:" + "a" * 64,
        "module_root": "/repo",
        "invocation_mode": "authenticated_dependency_hit",
    }
    kwargs = {
        "cache_disposition": CacheDisposition.AUTHENTICATED_DEPENDENCY_HIT,
        "cache_reason": None,
        "cache_attestation_sha256": "sha256:" + "d" * 64,
        "cache_claim_facts": hit_facts,
        "actual_build_context": hit_context,
    }
    with pytest.raises(IdentityError, match="invocation mode"):
        _identity(**(kwargs | {"actual_build_context": {**hit_context, "invocation_mode": "cold"}}))
    with pytest.raises(IdentityError, match="successful build"):
        _identity(
            **(
                kwargs
                | {
                    "build_provenance": {
                        "schema": "typed-build-provenance-facts-v1",
                        "fresh_modules": ["pkg.api"],
                        "result": "failure",
                    }
                }
            )
        )
    with pytest.raises(IdentityError, match="exactly match"):
        _identity(
            **(
                kwargs
                | {
                    "build_provenance": {
                        "schema": "typed-build-provenance-facts-v1",
                        "fresh_modules": ["unrelated.module"],
                        "result": "success",
                    }
                }
            )
        )
    with pytest.raises(IdentityError, match="fresh project modules"):
        _identity(
            **(
                kwargs
                | {"cache_claim_facts": hit_facts | {"fresh_project_modules": ["different.module"]}}
            )
        )


def _record_payload(record: str) -> object:
    return json.loads(record)[2]


def test_outer_identity_fields_are_bound_to_retained_records() -> None:
    identity = _identity()
    for field, value in (
        ("semantic_config_sha256", "sha256:" + "1" * 64),
        ("source_inventory_sha256", "sha256:" + "2" * 64),
        ("typed_provider_semantic_sha256", "sha256:" + "3" * 64),
        ("cache_attestation_sha256", "sha256:" + "4" * 64),
        ("cache_disposition", CacheDisposition.COLD_FALLBACK),
        ("cache_reason", CacheReason.SOURCE_CHANGED),
    ):
        with pytest.raises(IdentityError):
            replace(identity, **{field: value})  # type: ignore[arg-type]
        serialized = identity.to_dict()
        serialized[field] = (
            value.value if isinstance(value, CacheDisposition | CacheReason) else value
        )
        with pytest.raises(IdentityError):
            TypedBuildIdentityV2.from_dict(serialized)

    provenance = _record_payload(identity.provenance_record)
    assert isinstance(provenance, list) and provenance[0] == "mapping"
    # A self-consistently resealed but structurally invalid provenance record
    # must still fail the semantic record decoder.
    malformed = copy.deepcopy(provenance)
    malformed[1] = []
    # Build a valid record envelope with the wrong top-level shape.
    record = json.dumps(
        ["fed-canonical-json-v1", "typed-build-provenance-v2", malformed], separators=(",", ":")
    )
    digest_value = "sha256:" + hashlib.sha256(record.encode()).hexdigest()
    with pytest.raises(IdentityError, match="shape"):
        replace(identity, provenance_record=record, typed_build_provenance_sha256=digest_value)


def test_actual_options_and_source_graph_tampering_rejected() -> None:
    identity = _identity()
    actual = json.loads(identity.actual_options_record)
    altered = copy.deepcopy(actual)
    altered[2] = ["mapping", []]
    raw = json.dumps(altered, separators=(",", ":"))
    raw_digest = "sha256:" + hashlib.sha256(raw.encode()).hexdigest()
    with pytest.raises(IdentityError):
        replace(identity, actual_options_record=raw, actual_build_options_sha256=raw_digest)
