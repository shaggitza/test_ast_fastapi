from __future__ import annotations

import copy
from enum import IntEnum

import pytest
from mypy.options import Options

from fastapi_endpoint_detector.models.typed_build_identity import (
    CacheDisposition,
    CacheReason,
    IdentityError,
    TypedBuildIdentityV2,
    canonical_bytes,
    digest,
    semantic_mypy_options,
)

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
        "build_provenance": {"fresh_modules": ["pkg.api"], "result": "success"},
    }
    values.update(overrides)
    return TypedBuildIdentityV2.create(**values)  # type: ignore[arg-type]


def test_domain_and_typed_encodings_are_stable_and_distinct() -> None:
    assert canonical_bytes([1, "1"], domain="x") != canonical_bytes((1, "1"), domain="x")
    assert digest({"x": True}, domain="semantic") != digest({"x": 1}, domain="semantic")
    assert digest({"x": _FixtureOptionEnum.ENABLED}, domain="semantic") != digest(
        {"x": 1}, domain="semantic"
    )
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
    with pytest.raises(IdentityError, match="dependency hit"):
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
    )
    assert hit.cache_disposition is CacheDisposition.AUTHENTICATED_DEPENDENCY_HIT
