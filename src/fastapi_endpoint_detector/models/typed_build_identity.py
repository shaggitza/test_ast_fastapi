"""Strict, versioned identity primitives for a future typed-build cache protocol.

This module describes identity claims only. It does not validate cache custody,
prove build equivalence, or enable cache admission.
"""

from __future__ import annotations

import hashlib
import json
import math
import ntpath
import posixpath
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import TypeAlias

IDENTITY_SCHEMA = "typed-build-identity-v2"
CANONICAL_ENCODING = "fed-canonical-json-v1"
MAX_CANONICAL_BYTES = 1_048_576
MAX_DEPTH = 16
MAX_ITEMS = 10_000
MAX_STRING_BYTES = 65_536
MYPY_VERSION_POLICY = "1.19.1"
SEMANTIC_OPTION_EXCLUSIONS = frozenset({"incremental", "cache_dir", "cache_map"})
_NULLABLE_OPTION_TYPES: dict[str, type] = {
    "custom_typing_module": str,
    "custom_typeshed_dir": str,
    "abs_custom_typeshed_dir": str,
    "config_file": str,
    "quickstart_file": str,
    "files": list,
    "packages": list,
    "modules": list,
    "junit_xml": str,
    "timing_stats": str,
    "line_checking_stats": str,
    "shadow_file": list,
    "output": str,
    "mypyc_annotation_file": str,
}

CanonicalValue: TypeAlias = (
    bool
    | int
    | float
    | str
    | bytes
    | list["CanonicalValue"]
    | tuple["CanonicalValue", ...]
    | set["CanonicalValue"]
    | frozenset["CanonicalValue"]
    | Mapping[str, "CanonicalValue"]
    | None
)


class IdentityError(ValueError):
    """Raised when identity inputs cannot be represented without ambiguity."""


class CacheDisposition(str, Enum):
    COLD = "cold"
    AUTHENTICATED_DEPENDENCY_HIT = "authenticated_dependency_hit"
    COLD_FALLBACK = "cold_fallback"


class CacheReason(str, Enum):
    DISABLED = "disabled"
    UNSUPPORTED = "unsupported"
    IDENTITY_MISMATCH = "identity_mismatch"
    SOURCE_CHANGED = "source_changed"
    TRUST_UNAVAILABLE = "trust_unavailable"
    CONSUMER_UNPROVEN = "consumer_unproven"
    CACHE_INVALID = "cache_invalid"


def _typed(value: object, depth: int, counter: list[int]) -> object:  # noqa: PLR0911, PLR0912, PLR0915
    if depth > MAX_DEPTH:
        raise IdentityError("canonical value exceeds maximum nesting depth")
    counter[0] += 1
    if counter[0] > MAX_ITEMS:
        raise IdentityError("canonical value exceeds maximum item count")
    counter[1] += 24
    if counter[1] > MAX_CANONICAL_BYTES:
        raise IdentityError("canonical value exceeds maximum byte length")
    if value is None:
        return ["null"]
    if isinstance(value, Enum):
        enum_type = type(value)
        enum_name = enum_type.__module__ + "." + enum_type.__qualname__
        if len(enum_name) > MAX_STRING_BYTES:
            raise IdentityError("canonical enum name exceeds maximum byte length")
        counter[1] += 6 * len(enum_name)
        if counter[1] > MAX_CANONICAL_BYTES:
            raise IdentityError("canonical value exceeds maximum byte length")
        return [
            "enum",
            enum_name,
            _typed(value.value, depth + 1, counter),
        ]
    if isinstance(value, bool):
        return ["bool", value]
    if isinstance(value, int):
        if value.bit_length() > MAX_STRING_BYTES * 4:
            raise IdentityError("canonical integer exceeds maximum byte length")
        encoded_int = str(value)
        counter[1] += len(encoded_int)
        if counter[1] > MAX_CANONICAL_BYTES:
            raise IdentityError("canonical value exceeds maximum byte length")
        return ["int", encoded_int]
    if isinstance(value, float):
        if not math.isfinite(value):
            raise IdentityError("non-finite floats are unsupported")
        return ["float64", value.hex()]
    if isinstance(value, str):
        if len(value) > MAX_STRING_BYTES:
            raise IdentityError("canonical string exceeds maximum byte length")
        if len(value.encode("utf-8")) > MAX_STRING_BYTES:
            raise IdentityError("canonical string exceeds maximum byte length")
        counter[1] += 6 * len(value)
        if counter[1] > MAX_CANONICAL_BYTES:
            raise IdentityError("canonical value exceeds maximum byte length")
        return ["str", value]
    if isinstance(value, bytes):
        if len(value) > MAX_STRING_BYTES:
            raise IdentityError("canonical bytes exceed maximum byte length")
        counter[1] += 2 * len(value)
        if counter[1] > MAX_CANONICAL_BYTES:
            raise IdentityError("canonical value exceeds maximum byte length")
        return ["bytes-hex", value.hex()]
    if isinstance(value, list):
        if len(value) > MAX_ITEMS:
            raise IdentityError("canonical value exceeds maximum item count")
        return ["list", [_typed(item, depth + 1, counter) for item in value]]
    if isinstance(value, tuple):
        if len(value) > MAX_ITEMS:
            raise IdentityError("canonical value exceeds maximum item count")
        return ["tuple", [_typed(item, depth + 1, counter) for item in value]]
    if isinstance(value, (set, frozenset)):
        if len(value) > MAX_ITEMS:
            raise IdentityError("canonical value exceeds maximum item count")
        encoded = [_typed(item, depth + 1, counter) for item in value]
        encoded.sort(key=_dump)
        return ["frozenset" if isinstance(value, frozenset) else "set", encoded]
    if isinstance(value, Mapping):
        if len(value) > MAX_ITEMS:
            raise IdentityError("canonical value exceeds maximum item count")
        if any(not isinstance(key, str) for key in value):
            raise IdentityError("mapping keys must be strings")
        if any(len(key) > MAX_STRING_BYTES for key in value):
            raise IdentityError("canonical mapping key exceeds maximum byte length")
        if len(value) != len(set(value)):
            raise IdentityError("duplicate mapping keys")
        pairs = [
            [_typed(key, depth + 1, counter), _typed(item, depth + 1, counter)]
            for key, item in sorted(value.items(), key=lambda pair: pair[0])
        ]
        return ["mapping", pairs]
    raise IdentityError(f"unsupported canonical value type: {type(value).__name__}")


def _preflight_value(value: object) -> None:
    """Bound caller-owned containers iteratively before recursive encoding."""
    pending: list[tuple[object, int]] = [(value, 0)]
    items = 0
    while pending:
        current, depth = pending.pop()
        items += 1
        if items > MAX_ITEMS:
            raise IdentityError("canonical value exceeds maximum item count")
        if depth > MAX_DEPTH:
            raise IdentityError("canonical value exceeds maximum nesting depth")
        if isinstance(current, Enum):
            pending.append((current.value, depth + 1))
        elif isinstance(current, (list, tuple, set, frozenset, Mapping)):
            if len(current) > MAX_ITEMS:
                raise IdentityError("canonical value exceeds maximum item count")
            if isinstance(current, Mapping):
                pending.extend((key, depth + 1) for key in current)
                pending.extend((item, depth + 1) for item in current.values())
            else:
                pending.extend((item, depth + 1) for item in current)


def _dump(value: object) -> bytes:
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    return encoded.encode("utf-8")


def _preflight_json_depth(encoded: str) -> None:
    """Reject excessive JSON nesting before the recursive stdlib parser runs."""
    depth = 0
    quoted = False
    escaped = False
    for char in encoded:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH * 3 + 8:
                raise IdentityError("serialized identity exceeds maximum nesting depth")
        elif char in "]}":
            depth -= 1


def canonical_bytes(value: object, *, domain: str) -> bytes:
    """Encode a supported value with explicit type tags and a domain/version tag."""
    if not domain or len(domain) > 128 or len(domain.encode("utf-8")) > 128:
        raise IdentityError("invalid canonical hash domain")
    _preflight_value(value)
    payload = _dump([CANONICAL_ENCODING, domain, _typed(value, 0, [0, 0])])
    if len(payload) > MAX_CANONICAL_BYTES:
        raise IdentityError("canonical payload exceeds maximum byte length")
    return payload


def digest(value: object, *, domain: str) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value, domain=domain)).hexdigest()


def semantic_mypy_options(options: Mapping[str, object], *, mypy_version: str) -> dict[str, object]:
    """Return the pinned semantic projection, rejecting unknown versions/fields."""
    if mypy_version != MYPY_VERSION_POLICY:
        raise IdentityError("unsupported Mypy version for semantic option policy")
    try:
        from mypy.options import Options  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover - dependency is pinned in project
        raise IdentityError("Mypy option schema is unavailable") from exc
    defaults = Options()
    option_names = getattr(Options, "__mypyc_attrs__", None)
    if not isinstance(option_names, tuple) or not all(
        isinstance(name, str) for name in option_names
    ):
        raise IdentityError("Mypy compiled option schema is unavailable")
    expected = {name: getattr(defaults, name) for name in option_names}
    if set(options) != set(expected):
        raise IdentityError("effective Mypy options do not match the pinned option schema")
    # Canonicalize the entire map first: actual options are always retained and
    # unsupported values cannot disappear merely because they are excluded.
    canonical_bytes(dict(options), domain="mypy-actual-options-v1")
    for name, default in expected.items():
        actual = options[name]
        if default is None and actual is not None:
            accepted_type = _NULLABLE_OPTION_TYPES.get(name)
            if accepted_type is None or type(actual) is not accepted_type:
                raise IdentityError(f"unclassified non-null value for Mypy option {name}")
            if name in {"files", "packages", "modules"} and (
                not isinstance(actual, list) or any(type(item) is not str for item in actual)
            ):
                raise IdentityError(f"unsupported sequence value for Mypy option {name}")
            if name == "shadow_file" and (
                not isinstance(actual, list)
                or any(
                    type(row) is not list or any(type(item) is not str for item in row)
                    for row in actual
                )
            ):
                raise IdentityError("unsupported nested sequence for Mypy option shadow_file")
        if default is not None and type(actual) is not type(default):
            raise IdentityError(f"unsupported value type for Mypy option {name}")
    return {
        name: value for name, value in options.items() if name not in SEMANTIC_OPTION_EXCLUSIONS
    }


def _validate_hit_claim(facts: Mapping[str, object] | None) -> None:
    required = {
        "cache_manifest_sha256",
        "trust_id",
        "observed_cache_hit",
        "fresh_project_modules",
        "selected_consumers",
        "source_recheck_complete",
    }
    if facts is None or set(facts) != required:
        raise IdentityError("dependency-hit claim requires the complete supplied fact set")
    manifest_digest = facts["cache_manifest_sha256"]
    trust_id = facts["trust_id"]
    fresh_modules = facts["fresh_project_modules"]
    consumers = facts["selected_consumers"]
    if not isinstance(manifest_digest, str):
        raise IdentityError("cache manifest identity must be a digest")
    _validate_digest(manifest_digest)
    if not isinstance(trust_id, str) or not trust_id or len(trust_id.encode("utf-8")) > 256:
        raise IdentityError("cache trust identifier must be bounded and non-empty")
    if facts["observed_cache_hit"] is not True or facts["source_recheck_complete"] is not True:
        raise IdentityError("dependency-hit claim requires supplied successful recheck facts")
    for name, value in (
        ("fresh_project_modules", fresh_modules),
        ("selected_consumers", consumers),
    ):
        if (
            not isinstance(value, (list, tuple))
            or not value
            or len(value) > MAX_ITEMS
            or any(not isinstance(item, str) or not item for item in value)
        ):
            raise IdentityError(f"{name} must be a non-empty bounded string sequence")
    canonical_bytes(dict(facts), domain="typed-cache-hit-claim-facts-v2")


def _validate_build_provenance(value: object) -> dict[str, object]:
    """Validate retained build facts; cache claims live in outer typed fields."""
    fields = {"schema", "fresh_modules", "result"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise IdentityError("build provenance has missing or unknown fields")
    if value["schema"] != "typed-build-provenance-facts-v1":
        raise IdentityError("build provenance has an unknown schema")
    result = value["result"]
    if type(result) is not str or result not in {"success", "failure"}:
        raise IdentityError("build provenance result must be success or failure")
    fresh_modules = _string_sequence(value["fresh_modules"], "fresh_modules")
    canonical_bytes(dict(value), domain="typed-build-provenance-facts-v1")
    return {"schema": value["schema"], "fresh_modules": fresh_modules, "result": result}


def _validate_record(record: str, *, domain: str, expected_digest: str) -> None:  # noqa: PLR0912
    try:
        raw = record.encode("utf-8")
    except UnicodeError as exc:
        raise IdentityError("canonical record is not valid UTF-8") from exc
    if len(raw) > MAX_CANONICAL_BYTES:
        raise IdentityError("canonical record exceeds maximum byte length")
    if "sha256:" + hashlib.sha256(raw).hexdigest() != expected_digest:
        raise IdentityError("canonical record does not match its digest")

    # Canonical typed values expand each logical level into several JSON
    # arrays.  This lexical pass bounds parser nesting before json.loads can
    # recurse; exact typed depth and item limits are checked by the decoder.
    depth = 0
    quoted = False
    escaped = False
    for char in record:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH * 3 + 8:
                raise IdentityError("canonical record exceeds maximum nesting depth")
        elif char in "]}":
            depth -= 1

    def reject_constant(constant: str) -> object:
        raise IdentityError(f"unsupported canonical JSON constant: {constant}")

    try:
        value = json.loads(record, parse_constant=reject_constant)
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise IdentityError("canonical record is not valid JSON") from exc
    if not isinstance(value, list) or len(value) != 3:
        raise IdentityError("canonical record has an invalid envelope")
    if value[0] != CANONICAL_ENCODING or value[1] != domain:
        raise IdentityError("canonical record has an unknown encoding or domain")
    if _dump(value).decode("utf-8") != record:
        raise IdentityError("canonical record is not in canonical JSON form")


def _decode_typed(  # noqa: PLR0911, PLR0912, PLR0915
    value: object, depth: int = 0, counter: list[int] | None = None
) -> object:
    """Decode the bounded tagged representation used by canonical records."""
    if depth > MAX_DEPTH:
        raise IdentityError("canonical value exceeds maximum nesting depth")
    if counter is None:
        counter = [0]
    counter[0] += 1
    if counter[0] > MAX_ITEMS:
        raise IdentityError("canonical value exceeds maximum item count")
    if not isinstance(value, list) or not value or not isinstance(value[0], str):
        raise IdentityError("canonical record contains a malformed typed value")
    tag = value[0]
    if tag == "null" and len(value) == 1:
        return None
    if tag == "bool" and len(value) == 2 and type(value[1]) is bool:
        return value[1]
    if tag == "int" and len(value) == 2 and isinstance(value[1], str):
        if len(value[1]) > MAX_STRING_BYTES * 4:
            raise IdentityError("canonical integer exceeds maximum byte length")
        try:
            decoded_int = int(value[1])
        except ValueError as exc:
            raise IdentityError("canonical integer is malformed") from exc
        if str(decoded_int) != value[1]:
            raise IdentityError("canonical integer is not normalized")
        return decoded_int
    if tag == "float64" and len(value) == 2 and isinstance(value[1], str):
        try:
            decoded_float = float.fromhex(value[1])
        except ValueError as exc:
            raise IdentityError("canonical float is malformed") from exc
        if not math.isfinite(decoded_float):
            raise IdentityError("canonical float is non-finite")
        if decoded_float.hex() != value[1]:
            raise IdentityError("canonical float is not normalized")
        return decoded_float
    if tag == "str" and len(value) == 2 and isinstance(value[1], str):
        try:
            string_size = len(value[1].encode("utf-8"))
        except UnicodeError as exc:
            raise IdentityError("canonical string is not valid UTF-8") from exc
        if string_size > MAX_STRING_BYTES:
            raise IdentityError("canonical string exceeds maximum byte length")
        return value[1]
    if tag == "bytes-hex" and len(value) == 2 and isinstance(value[1], str):
        if len(value[1]) > MAX_STRING_BYTES * 2:
            raise IdentityError("canonical bytes exceed maximum byte length")
        try:
            decoded_bytes = bytes.fromhex(value[1])
        except ValueError as exc:
            raise IdentityError("canonical bytes are malformed") from exc
        if decoded_bytes.hex() != value[1]:
            raise IdentityError("canonical bytes are not normalized")
        return decoded_bytes
    if tag == "enum" and len(value) == 3 and isinstance(value[1], str):
        try:
            enum_name_size = len(value[1].encode("utf-8"))
        except UnicodeError as exc:
            raise IdentityError("canonical enum name is not valid UTF-8") from exc
        if enum_name_size > MAX_STRING_BYTES:
            raise IdentityError("canonical enum name exceeds maximum byte length")
        module, separator, qualified_name = value[1].rpartition(".")
        if not separator or not module or not qualified_name:
            raise IdentityError("canonical enum identity is malformed")
        enum_type = Enum(  # type: ignore[misc]
            qualified_name.rsplit(".", maxsplit=1)[-1],
            {"_CANONICAL_VALUE": _decode_typed(value[2], depth + 1, counter)},
            module=module,
        )
        enum_type.__qualname__ = qualified_name
        return next(iter(enum_type))
    if (
        tag in {"list", "tuple", "set", "frozenset"}
        and len(value) == 2
        and isinstance(value[1], list)
    ):
        if len(value[1]) > MAX_ITEMS:
            raise IdentityError("canonical value exceeds maximum item count")
        items = [_decode_typed(item, depth + 1, counter) for item in value[1]]
        if tag == "list":
            return items
        if tag == "tuple":
            return tuple(items)
        if tag in {"set", "frozenset"}:
            encoded_items = [_dump(item) for item in value[1]]
            if encoded_items != sorted(encoded_items) or len(set(encoded_items)) != len(
                encoded_items
            ):
                raise IdentityError("canonical set members are duplicated or out of order")
            try:
                return set(items) if tag == "set" else frozenset(items)
            except (TypeError, ValueError) as exc:
                raise IdentityError("canonical set member is not hashable") from exc
        raise IdentityError("canonical record contains an unknown typed sequence")
    if tag == "mapping" and len(value) == 2 and isinstance(value[1], list):
        mapping_result: dict[str, object] = {}
        previous_key: str | None = None
        for pair in value[1]:
            if not isinstance(pair, list) or len(pair) != 2:
                raise IdentityError("canonical mapping entry is malformed")
            key = _decode_typed(pair[0], depth + 1, counter)
            if not isinstance(key, str) or key in mapping_result:
                raise IdentityError("canonical mapping key is invalid")
            if previous_key is not None and key <= previous_key:
                raise IdentityError("canonical mapping keys are out of order")
            previous_key = key
            mapping_result[key] = _decode_typed(pair[1], depth + 1, counter)
        return mapping_result
    raise IdentityError("canonical record contains an unknown typed value")


def _record_value(record: str, domain: str) -> object:
    _validate_record(
        record,
        domain=domain,
        expected_digest="sha256:" + hashlib.sha256(record.encode("utf-8")).hexdigest(),
    )
    envelope = json.loads(record)
    if (
        not isinstance(envelope, list)
        or len(envelope) != 3
        or envelope[:2] != [CANONICAL_ENCODING, domain]
    ):
        raise IdentityError("canonical record has an invalid envelope")
    return _decode_typed(envelope[2])


def _string_sequence(value: object, name: str) -> list[str]:
    if (
        not isinstance(value, (list, tuple))
        or len(value) > MAX_ITEMS
        or any(type(item) is not str or not item for item in value)
    ):
        raise IdentityError(f"{name} must be a bounded string sequence")
    return list(value)


def _require_canonical_path(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise IdentityError(f"{name} must be a non-empty absolute path")
    if posixpath.isabs(value):
        if posixpath.normpath(value) != value:
            raise IdentityError(f"{name} must be normalized")
    elif ntpath.isabs(value):
        if ntpath.normpath(value) != value:
            raise IdentityError(f"{name} must be normalized")
    else:
        raise IdentityError(f"{name} must be absolute")
    return value


def _validated_context(  # noqa: PLR0912, PLR0915
    semantic_context: object, source_inventory: object, actual_build_context: object
) -> tuple[dict[str, object], list[dict[str, object]], dict[str, object]]:
    semantic_fields = {
        "canonical_root",
        "search_paths",
        "import_roots",
        "resolved_modules",
        "analyzer_config",
        "plugins",
        "toolchain",
    }
    actual_fields = {
        "engine",
        "engine_version",
        "python",
        "config_sha256",
        "module_root",
        "invocation_mode",
    }
    if not isinstance(semantic_context, Mapping) or set(semantic_context) != semantic_fields:
        raise IdentityError("semantic context lacks required resolution and toolchain fields")
    if not isinstance(actual_build_context, Mapping) or set(actual_build_context) != actual_fields:
        raise IdentityError("actual build context lacks required engine/runtime fields")
    root = _require_canonical_path(semantic_context["canonical_root"], "canonical_root")
    module_root = actual_build_context["module_root"]
    if module_root != root:
        raise IdentityError("actual module root must match semantic canonical root")
    if any(
        not isinstance(actual_build_context[name], str) or not actual_build_context[name]
        for name in ("engine", "engine_version", "python", "invocation_mode")
    ):
        raise IdentityError("actual engine/runtime fields must be non-empty strings")
    if actual_build_context["invocation_mode"] not in {
        "cold",
        "authenticated_dependency_hit",
        "cold_fallback",
    }:
        raise IdentityError("actual invocation mode is unknown")
    _validate_digest(actual_build_context["config_sha256"])
    search_paths = _string_sequence(semantic_context["search_paths"], "search_paths")
    import_roots = _string_sequence(semantic_context["import_roots"], "import_roots")
    for path in search_paths:
        _require_canonical_path(path, "search path")
    for path in import_roots:
        _require_canonical_path(path, "import root")
    plugins = semantic_context["plugins"]
    if not isinstance(plugins, (list, tuple)):
        raise IdentityError("plugins must be a bounded sequence")
    if not isinstance(semantic_context["analyzer_config"], Mapping):
        raise IdentityError("analyzer_config must be a mapping")
    toolchain = semantic_context["toolchain"]
    if not isinstance(toolchain, Mapping) or not {
        "python_implementation",
        "python_version",
        "platform",
    }.issubset(toolchain):
        raise IdentityError("toolchain lacks Python/runtime identity fields")
    if not isinstance(source_inventory, (list, tuple)) or not source_inventory:
        raise IdentityError("source inventory must be a non-empty sequence")
    modules = semantic_context["resolved_modules"]
    if not isinstance(modules, (list, tuple)) or not modules:
        raise IdentityError("resolved module graph must be a non-empty sequence")
    module_fields = {"fullname", "path", "origin", "side"}
    source_fields = module_fields | {"source_sha256"}
    graph: dict[str, tuple[str, str, str]] = {}
    for module in modules:
        if not isinstance(module, Mapping) or set(module) != module_fields:
            raise IdentityError("resolved module entry has missing or unknown fields")
        fullname, path, origin, side = (
            module[name] for name in ("fullname", "path", "origin", "side")
        )
        if any(not isinstance(item, str) or not item for item in (fullname, path, origin, side)):
            raise IdentityError("resolved module identity fields must be non-empty strings")
        _require_canonical_path(path, "resolved module path")
        if fullname in graph:
            raise IdentityError("duplicate resolved module fullname")
        graph[fullname] = (path, origin, side)
    normalized_sources: list[dict[str, object]] = []
    seen_sources: set[str] = set()
    for source in source_inventory:
        if not isinstance(source, Mapping) or set(source) != source_fields:
            raise IdentityError("source inventory entry has missing or unknown fields")
        fullname = source["fullname"]
        if not isinstance(fullname, str) or fullname in seen_sources:
            raise IdentityError("source inventory has duplicate or invalid module fullname")
        _require_canonical_path(source["path"], "source inventory path")
        _validate_digest(source["source_sha256"])
        graph_identity = (source["path"], source["origin"], source["side"])
        if graph.get(fullname) != graph_identity:
            raise IdentityError("source inventory does not match resolved module graph")
        seen_sources.add(fullname)
        normalized_sources.append(dict(source))
    if seen_sources != set(graph):
        raise IdentityError("source inventory is incomplete for resolved module graph")
    normalized_sources.sort(key=lambda item: str(item["fullname"]))
    normalized_context = dict(semantic_context)
    normalized_context["search_paths"] = search_paths
    normalized_context["import_roots"] = import_roots
    normalized_context["resolved_modules"] = sorted(
        (dict(module) for module in modules), key=lambda item: str(item["fullname"])
    )
    canonical_bytes(normalized_context, domain="typed-context-validation-v2")
    canonical_bytes(dict(actual_build_context), domain="typed-actual-context-validation-v2")
    return normalized_context, normalized_sources, dict(actual_build_context)


@dataclass(frozen=True, slots=True)
class TypedBuildIdentityV2:
    """Immutable identity declaration; it is not a cache trust/equivalence proof."""

    semantic_config_sha256: str
    actual_build_options_sha256: str
    source_inventory_sha256: str
    typed_provider_semantic_sha256: str
    typed_build_provenance_sha256: str
    cache_attestation_sha256: str | None
    cache_disposition: CacheDisposition
    cache_reason: CacheReason | None
    actual_options_record: str
    provenance_record: str
    schema: str = IDENTITY_SCHEMA
    canonical_encoding: str = CANONICAL_ENCODING

    def __post_init__(self) -> None:  # noqa: PLR0912, PLR0915
        if self.schema != IDENTITY_SCHEMA or self.canonical_encoding != CANONICAL_ENCODING:
            raise IdentityError("unsupported typed-build identity schema or encoding")
        if not isinstance(self.cache_disposition, CacheDisposition):
            raise IdentityError("unknown cache disposition")
        if self.cache_reason is not None and not isinstance(self.cache_reason, CacheReason):
            raise IdentityError("unknown cache reason")
        for value in (
            self.semantic_config_sha256,
            self.actual_build_options_sha256,
            self.source_inventory_sha256,
            self.typed_provider_semantic_sha256,
            self.typed_build_provenance_sha256,
        ):
            _validate_digest(value)
        if self.cache_attestation_sha256 is not None:
            _validate_digest(self.cache_attestation_sha256)
        if not isinstance(self.actual_options_record, str) or not isinstance(
            self.provenance_record, str
        ):
            raise IdentityError("inspectable records must be strings")
        if len(self.actual_options_record.encode("utf-8")) > MAX_CANONICAL_BYTES:
            raise IdentityError("actual options record exceeds maximum byte length")
        if len(self.provenance_record.encode("utf-8")) > MAX_CANONICAL_BYTES:
            raise IdentityError("provenance record exceeds maximum byte length")
        _validate_record(
            self.actual_options_record,
            domain="typed-actual-build-options-v2",
            expected_digest=self.actual_build_options_sha256,
        )
        _validate_record(
            self.provenance_record,
            domain="typed-build-provenance-v2",
            expected_digest=self.typed_build_provenance_sha256,
        )
        actual = _record_value(self.actual_options_record, "typed-actual-build-options-v2")
        provenance = _record_value(self.provenance_record, "typed-build-provenance-v2")
        if not isinstance(actual, Mapping) or set(actual) != {
            "mypy_version",
            "effective_mypy_options",
            "actual_build_context",
        }:
            raise IdentityError("actual options record has an invalid shape")
        provenance_fields = {
            "mypy_version",
            "semantic_context",
            "semantic_mypy_options",
            "actual_options",
            "actual_build_context",
            "source_inventory",
            "provider_semantic_context",
            "build_provenance",
            "actual_build_options_sha256",
            "source_inventory_sha256",
            "typed_provider_semantic_sha256",
            "cache_attestation_sha256",
            "cache_disposition",
            "cache_reason",
            "cache_claim_facts",
        }
        if not isinstance(provenance, Mapping) or set(provenance) != provenance_fields:
            raise IdentityError("provenance record has an invalid shape")
        if (
            actual["effective_mypy_options"] != provenance["actual_options"]
            or actual["actual_build_context"] != provenance["actual_build_context"]
            or actual["mypy_version"] != provenance["mypy_version"]
        ):
            raise IdentityError("actual options and provenance records disagree")
        if provenance["actual_build_options_sha256"] != self.actual_build_options_sha256:
            raise IdentityError("provenance actual-options digest disagrees")
        if provenance["source_inventory_sha256"] != self.source_inventory_sha256:
            raise IdentityError("provenance source digest disagrees")
        if provenance["typed_provider_semantic_sha256"] != self.typed_provider_semantic_sha256:
            raise IdentityError("provenance provider digest disagrees")
        if provenance["cache_attestation_sha256"] != self.cache_attestation_sha256:
            raise IdentityError("provenance cache attestation disagrees")
        if provenance["cache_disposition"] != self.cache_disposition.value or provenance[
            "cache_reason"
        ] != (self.cache_reason.value if self.cache_reason is not None else None):
            raise IdentityError("provenance disposition or reason disagrees")
        if self.cache_disposition is CacheDisposition.AUTHENTICATED_DEPENDENCY_HIT:
            _validate_hit_claim(provenance["cache_claim_facts"])
        elif provenance["cache_claim_facts"] is not None:
            raise IdentityError("non-hit disposition cannot retain cache hit claims")
        version, options, build_context = (
            provenance["mypy_version"],
            actual["effective_mypy_options"],
            actual["actual_build_context"],
        )
        semantic_context = provenance["semantic_context"]
        inventory = provenance["source_inventory"]
        provider_context = provenance["provider_semantic_context"]
        build_provenance = provenance["build_provenance"]
        if (
            not isinstance(version, str)
            or not isinstance(options, Mapping)
            or not isinstance(build_context, Mapping)
        ):
            raise IdentityError("actual options record has invalid field types")
        if (
            not isinstance(inventory, list)
            or not isinstance(provider_context, Mapping)
            or not isinstance(build_provenance, Mapping)
        ):
            raise IdentityError("provenance source/provider records have invalid types")
        _validate_build_provenance(build_provenance)
        invocation_mode = build_context.get("invocation_mode")
        build_result = build_provenance["result"]
        fresh_modules = build_provenance["fresh_modules"]
        if invocation_mode != self.cache_disposition.value:
            raise IdentityError("actual invocation mode disagrees with cache disposition")
        project_modules = sorted(
            str(item["fullname"])
            for item in inventory
            if isinstance(item, Mapping) and item.get("side") == "project"
        )
        if fresh_modules != project_modules:
            raise IdentityError("fresh modules must exactly match project inventory modules")
        if self.cache_disposition is CacheDisposition.AUTHENTICATED_DEPENDENCY_HIT:
            if build_result != "success":
                raise IdentityError("dependency hit requires a successful build")
            claim_facts = provenance["cache_claim_facts"]
            if not isinstance(claim_facts, Mapping):
                raise IdentityError("dependency hit lacks validated cache claim facts")
            claim_fresh = claim_facts["fresh_project_modules"]
            if claim_fresh != project_modules:
                raise IdentityError("fresh project modules disagree with build provenance")
        if (
            digest(actual, domain="typed-actual-build-options-v2")
            != self.actual_build_options_sha256
        ):
            raise IdentityError("actual options digest is inconsistent")
        normalized_context, normalized_inventory, _ = _validated_context(
            semantic_context, inventory, build_context
        )
        if normalized_context != semantic_context or normalized_inventory != inventory:
            raise IdentityError("provenance context or inventory is not canonical")
        source_digest = digest(inventory, domain="typed-source-inventory-v2")
        if source_digest != self.source_inventory_sha256:
            raise IdentityError("source inventory digest is inconsistent")
        semantic_options = semantic_mypy_options(options, mypy_version=version)
        if provenance["semantic_mypy_options"] != semantic_options:
            raise IdentityError("provenance semantic options are inconsistent")
        semantic_digest = digest(
            {
                "mypy_version": version,
                "semantic_mypy_options": semantic_options,
                "analysis_context": semantic_context,
                "source_inventory_sha256": source_digest,
            },
            domain="typed-semantic-config-v2",
        )
        if semantic_digest != self.semantic_config_sha256:
            raise IdentityError("semantic config digest is inconsistent")
        provider_digest = digest(
            {
                "semantic_config_sha256": semantic_digest,
                "source_inventory_sha256": source_digest,
                "context": provider_context,
            },
            domain="typed-provider-semantic-v2",
        )
        if provider_digest != self.typed_provider_semantic_sha256:
            raise IdentityError("provider semantic digest is inconsistent")
        if self.cache_disposition is CacheDisposition.COLD:
            if (
                self.cache_attestation_sha256 is not None
                or self.cache_reason is not CacheReason.DISABLED
            ):
                raise IdentityError(
                    "cold disposition requires null attestation and disabled reason"
                )
        elif self.cache_disposition is CacheDisposition.AUTHENTICATED_DEPENDENCY_HIT:
            if self.cache_attestation_sha256 is None or self.cache_reason is not None:
                raise IdentityError("dependency hit requires attestation and null reason")
        elif self.cache_disposition is CacheDisposition.COLD_FALLBACK and (
            self.cache_attestation_sha256 is not None or self.cache_reason is None
        ):
            raise IdentityError("cold fallback requires null attestation and a reason")

    @classmethod
    def create(
        cls,
        *,
        semantic_context: object,
        mypy_options: Mapping[str, object],
        mypy_version: str,
        actual_build_context: object,
        source_inventory: object,
        provider_semantic_context: object,
        build_provenance: object,
        cache_attestation_sha256: str | None = None,
        cache_disposition: CacheDisposition = CacheDisposition.COLD,
        cache_reason: CacheReason | None = CacheReason.DISABLED,
        cache_claim_facts: Mapping[str, object] | None = None,
    ) -> TypedBuildIdentityV2:
        """Create namespaced digests from bounded inspectable input records."""
        # Keep all source facts in semantic identity in addition to their
        # separately inspectable inventory digest.
        if not isinstance(cache_disposition, CacheDisposition):
            raise IdentityError("unknown cache disposition")
        if cache_reason is not None and not isinstance(cache_reason, CacheReason):
            raise IdentityError("unknown cache reason")
        semantic_context, source_inventory, actual_build_context = _validated_context(
            semantic_context, source_inventory, actual_build_context
        )
        build_provenance = _validate_build_provenance(build_provenance)
        source_digest = digest(source_inventory, domain="typed-source-inventory-v2")
        semantic_options = semantic_mypy_options(mypy_options, mypy_version=mypy_version)
        if cache_disposition is CacheDisposition.AUTHENTICATED_DEPENDENCY_HIT:
            _validate_hit_claim(cache_claim_facts)
        elif cache_claim_facts is not None:
            raise IdentityError("cache claim facts are only valid for dependency-hit disposition")
        semantic_value = {
            "mypy_version": mypy_version,
            "semantic_mypy_options": semantic_options,
            "analysis_context": semantic_context,
            "source_inventory_sha256": source_digest,
        }
        semantic_digest = digest(semantic_value, domain="typed-semantic-config-v2")
        actual_value = {
            "mypy_version": mypy_version,
            "effective_mypy_options": dict(mypy_options),
            "actual_build_context": actual_build_context,
        }
        actual_encoded = canonical_bytes(actual_value, domain="typed-actual-build-options-v2")
        actual_digest = "sha256:" + hashlib.sha256(actual_encoded).hexdigest()
        provider_digest = digest(
            {
                "semantic_config_sha256": semantic_digest,
                "source_inventory_sha256": source_digest,
                "context": provider_semantic_context,
            },
            domain="typed-provider-semantic-v2",
        )
        provenance_value = {
            "mypy_version": mypy_version,
            "semantic_context": semantic_context,
            "semantic_mypy_options": semantic_options,
            "actual_options": dict(mypy_options),
            "actual_build_context": actual_build_context,
            "source_inventory": source_inventory,
            "provider_semantic_context": provider_semantic_context,
            "build_provenance": build_provenance,
            "actual_build_options_sha256": actual_digest,
            "source_inventory_sha256": source_digest,
            "typed_provider_semantic_sha256": provider_digest,
            "cache_attestation_sha256": cache_attestation_sha256,
            "cache_disposition": cache_disposition.value,
            "cache_reason": cache_reason.value if cache_reason is not None else None,
            "cache_claim_facts": dict(cache_claim_facts) if cache_claim_facts is not None else None,
        }
        provenance_encoded = canonical_bytes(provenance_value, domain="typed-build-provenance-v2")
        provenance_digest = "sha256:" + hashlib.sha256(provenance_encoded).hexdigest()
        return cls(
            semantic_digest,
            actual_digest,
            source_digest,
            provider_digest,
            provenance_digest,
            cache_attestation_sha256,
            cache_disposition,
            cache_reason,
            actual_encoded.decode("utf-8"),
            provenance_encoded.decode("utf-8"),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "identity_schema": self.schema,
            "canonical_encoding": self.canonical_encoding,
            "semantic_config_sha256": self.semantic_config_sha256,
            "actual_build_options_sha256": self.actual_build_options_sha256,
            "source_inventory_sha256": self.source_inventory_sha256,
            "typed_provider_semantic_sha256": self.typed_provider_semantic_sha256,
            "typed_build_provenance_sha256": self.typed_build_provenance_sha256,
            "cache_attestation_sha256": self.cache_attestation_sha256,
            "cache_disposition": self.cache_disposition.value,
            "cache_reason": self.cache_reason.value if self.cache_reason is not None else None,
            "actual_options_record": self.actual_options_record,
            "provenance_record": self.provenance_record,
        }

    def to_json(self) -> str:
        """Serialize the strict object without permitting NaN or key ambiguity."""
        encoded = json.dumps(
            self.to_dict(), ensure_ascii=False, separators=(",", ":"), allow_nan=False
        )
        if len(encoded.encode("utf-8")) > MAX_CANONICAL_BYTES:
            raise IdentityError("serialized identity exceeds maximum byte length")
        return encoded

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> TypedBuildIdentityV2:
        fields = {
            "identity_schema",
            "canonical_encoding",
            "semantic_config_sha256",
            "actual_build_options_sha256",
            "source_inventory_sha256",
            "typed_provider_semantic_sha256",
            "typed_build_provenance_sha256",
            "cache_attestation_sha256",
            "cache_disposition",
            "cache_reason",
            "actual_options_record",
            "provenance_record",
        }
        if set(value) != fields:
            raise IdentityError("identity fields are missing or unknown")
        try:
            disposition = CacheDisposition(value["cache_disposition"])
            reason_value = value["cache_reason"]
            reason = CacheReason(reason_value) if reason_value is not None else None
            return cls(
                semantic_config_sha256=_string(value, "semantic_config_sha256"),
                actual_build_options_sha256=_string(value, "actual_build_options_sha256"),
                source_inventory_sha256=_string(value, "source_inventory_sha256"),
                typed_provider_semantic_sha256=_string(value, "typed_provider_semantic_sha256"),
                typed_build_provenance_sha256=_string(value, "typed_build_provenance_sha256"),
                cache_attestation_sha256=(
                    _string(value, "cache_attestation_sha256")
                    if value["cache_attestation_sha256"] is not None
                    else None
                ),
                cache_disposition=disposition,
                cache_reason=reason,
                schema=_string(value, "identity_schema"),
                canonical_encoding=_string(value, "canonical_encoding"),
                actual_options_record=_string(value, "actual_options_record"),
                provenance_record=_string(value, "provenance_record"),
            )
        except (ValueError, TypeError) as exc:
            if isinstance(exc, IdentityError):
                raise
            raise IdentityError("invalid typed-build identity value") from exc

    @classmethod
    def from_json(cls, encoded: str) -> TypedBuildIdentityV2:
        try:
            encoded_size = len(encoded.encode("utf-8"))
        except UnicodeError as exc:
            raise IdentityError("serialized identity is not valid UTF-8") from exc
        if encoded_size > MAX_CANONICAL_BYTES:
            raise IdentityError("serialized identity exceeds maximum byte length")

        def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, item in pairs:
                if key in result:
                    raise IdentityError("duplicate serialized identity field")
                result[key] = item
            return result

        def reject_constant(constant: str) -> object:
            raise IdentityError(f"unsupported JSON constant: {constant}")

        try:
            _preflight_json_depth(encoded)
            value = json.loads(
                encoded, object_pairs_hook=unique_object, parse_constant=reject_constant
            )
        except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
            raise IdentityError("invalid serialized identity JSON") from exc
        if not isinstance(value, Mapping):
            raise IdentityError("serialized identity must be an object")
        return cls.from_dict(value)


def _validate_digest(value: object) -> None:
    if not isinstance(value, str):
        raise IdentityError("digest must be a string")
    if len(value) != 71 or not value.startswith("sha256:"):
        raise IdentityError("digest must use sha256:<64 lowercase hex>")
    if any(char not in "0123456789abcdef" for char in value[7:]):
        raise IdentityError("digest must use sha256:<64 lowercase hex>")


def _string(value: Mapping[str, object], key: str) -> str:
    result = value[key]
    if not isinstance(result, str):
        raise IdentityError(f"{key} must be a string")
    return result
