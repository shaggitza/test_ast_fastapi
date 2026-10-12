#!/usr/bin/env python3
"""Cross-row semantic checks for GH97 inventory JSON (after JSON Schema validation)."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any, cast

from fastapi_endpoint_detector.models.artifact_validation import (
    BenchmarkSchemaError,
    strict_json_loads,
)
from fastapi_endpoint_detector.models.effect_contract_audit import EffectContractAudit


def validate_rows(
    rows: list[dict[str, Any]],
    output_bytes_by_hash: dict[str, bytes] | None = None,
    mapping: dict[str, Any] | None = None,
    source_bytes_by_identity: dict[tuple[str, str], bytes] | None = None,
) -> list[str]:
    """Validate inventory semantics and, when supplied, authenticated CLI row mappings."""
    errors: list[str] = _validate_source_bytes(rows, source_bytes_by_identity)
    for index, row in enumerate(rows):
        where = f"row[{index}]"
        start, end, size = row.get("start_byte"), row.get("end_byte"), row.get("file_bytes")
        if _has_int_span(start, end, size) and not (
            0 <= cast("int", start) < cast("int", end) <= cast("int", size)
        ):
            errors.append(f"{where}: expected 0 <= start_byte < end_byte <= file_bytes")

        source_path, source_hash = row.get("path"), row.get("source_sha256")
        for kind, parts in (
            ("binding", row.get("bindings", [])),
            ("resource", row.get("resource_components", [])),
        ):
            for part_index, part in enumerate(parts):
                part_where = f"{where}: {kind}[{part_index}]"
                part_start, part_end = part.get("span_start"), part.get("span_end")
                part_path, part_hash = part.get("source_path"), part.get("source_sha256")
                part_size = part.get("source_file_bytes")
                if not _has_int_span(part_start, part_end, part_size) or not (
                    0 <= part_start < part_end <= part_size
                ):
                    errors.append(f"{part_where}: invalid source span bounds")
                    continue
                if not isinstance(part_path, str) or not isinstance(part_hash, str):
                    errors.append(f"{part_where}: source path and source SHA-256 are required")
                elif kind == "binding" and (
                    part_path != source_path
                    or part_hash != source_hash
                    or part_size != row.get("file_bytes")
                    or not (start <= part_start < part_end <= end)
                ):
                    errors.append(
                        f"{part_where}: binding evidence must be within its call source span"
                    )
                elif part_path == source_path and part_hash != source_hash:
                    errors.append(f"{part_where}: same source path has conflicting SHA-256")
                elif (
                    part_path == source_path
                    and part_hash == source_hash
                    and not (
                        part_size == row.get("file_bytes") and start <= part_start < part_end <= end
                    )
                ):
                    errors.append(f"{part_where}: same-file evidence span must be within call span")

        errors.extend(_validate_row_states(row, where))

    # Same physical identity in separate cases is valid.
    seen_by_case: set[tuple[str, str, str, int, int, str]] = set()
    for index, row in enumerate(rows):
        values = (
            row.get("case_id"),
            row.get("packet_sha256"),
            row.get("path"),
            row.get("start_byte"),
            row.get("end_byte"),
            row.get("call_ast_sha256"),
        )
        if all(value is not None for value in values):
            key = cast("tuple[str, str, str, int, int, str]", values)
            if key in seen_by_case:
                errors.append(
                    f"row[{index}]: duplicate call key within case {row.get('case_id')!r}"
                )
            seen_by_case.add(key)
    errors.extend(_validate_mapping(rows, output_bytes_by_hash, mapping))
    return errors


def _has_int_span(start: Any, end: Any, size: Any) -> bool:
    return all(
        isinstance(value, int) and not isinstance(value, bool) for value in (start, end, size)
    )


def _validate_row_states(  # noqa: PLR0912 -- explicit closed outcome/status table.
    row: dict[str, Any], where: str
) -> list[str]:
    errors: list[str] = []
    applicability = cast("dict[str, Any]", row.get("applicability", {}))
    distribution, version = applicability.get("distribution"), applicability.get("version")
    if (distribution is None) != (version is None):
        errors.append(f"{where}: applicability package and version must both be null or populated")
    preset = cast("dict[str, Any]", row.get("preset", {}))
    identity = tuple(
        preset.get(key) for key in ("id", "version", "revision", "config_sha256", "contract_id")
    )
    preset_is_complete = all(value is not None for value in identity)
    if not (all(value is None for value in identity) or preset_is_complete):
        errors.append(f"{where}: preset identity fields must be all null or all populated")
    outcome = row.get("outcome")
    cli = cast("dict[str, Any]", row.get("cli_observation", {}))
    status = cli.get("status")
    if outcome == "unsupported" and status != "unsupported":
        errors.append(f"{where}: unsupported outcome requires unsupported CLI status")
    invocation, output_hash, row_key = (
        cli.get("invocation_id"),
        cli.get("output_sha256"),
        cli.get("row_key"),
    )
    if outcome in {"supported_match", "supported_nonmatch"} and (
        distribution is None or not preset_is_complete
    ):
        errors.append(
            f"{where}: supported outcome requires exact package/version and preset identity"
        )
    if outcome in {"supported_match", "supported_nonmatch"} and status != "observed":
        errors.append(f"{where}: supported outcomes require an observed CLI row")
    for outcome_name, status_name in (
        ("unobserved_by_cli", "unobserved_by_cli"),
        ("not_run", "not_run"),
        ("unavailable", "unavailable"),
    ):
        if outcome == outcome_name and status != status_name:
            errors.append(f"{where}: {outcome_name} outcome requires matching CLI status")
    if status == "observed":
        errors.append(
            f"{where}: exact observed status is unsupported by public audit schema v1; "
            "it omits source byte/hash/call-AST identity"
        )
    if status == "unobserved_by_cli":
        errors.append(
            f"{where}: absence cannot be proven by endpoint-reachable public audit schema v1"
        )
    if status == "observed" and not all(
        value is not None for value in (invocation, output_hash, row_key)
    ):
        errors.append(f"{where}: observed CLI row requires invocation, output hash, and row key")
    if status == "observed" and any(
        not isinstance(value, str) or not value for value in (invocation, output_hash, row_key)
    ):
        errors.append(f"{where}: observed CLI identity values must be non-empty strings")
    if status == "unobserved_by_cli" and (
        invocation is None or output_hash is None or row_key is not None
    ):
        errors.append(
            f"{where}: unobserved CLI status requires completed invocation and null row key"
        )
    if status == "unobserved_by_cli" and (
        not isinstance(invocation, str)
        or not invocation
        or not isinstance(output_hash, str)
        or len(output_hash) != 64
        or any(char not in "0123456789abcdef" for char in output_hash)
    ):
        errors.append(f"{where}: unobserved CLI status requires non-empty invocation and SHA-256")
    if status == "not_run" and any(
        value is not None for value in (invocation, output_hash, row_key)
    ):
        errors.append(
            f"{where}: not_run CLI status requires null invocation, output hash, and row key"
        )
    if status == "unavailable" and any(
        value is not None for value in (invocation, output_hash, row_key)
    ):
        errors.append(
            f"{where}: unavailable CLI status requires null invocation, output hash, and row key"
        )
    if status == "unsupported":
        if outcome != "unsupported":
            errors.append(f"{where}: unsupported CLI projection requires unsupported outcome")
        if (
            not isinstance(invocation, str)
            or not invocation
            or not isinstance(output_hash, str)
            or len(output_hash) != 64
            or any(char not in "0123456789abcdef" for char in output_hash)
            or row_key is not None
        ):
            errors.append(
                f"{where}: unsupported CLI projection requires invocation/output hash "
                "and null row key"
            )
    if status not in {"observed", "unobserved_by_cli", "not_run", "unavailable", "unsupported"}:
        errors.append(f"{where}: unknown CLI status")
    return errors


def _canonical_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(payload).hexdigest()


def _validate_source_bytes(
    rows: list[dict[str, Any]],
    sources: dict[tuple[str, str], bytes] | None,
) -> list[str]:
    if sources is None:
        return []
    errors: list[str] = []
    identities: dict[tuple[str, str], set[tuple[str, int]]] = {}
    for row in rows:
        case_id = cast("str", row.get("case_id"))
        identity = (case_id, cast("str", row.get("path")))
        identities.setdefault(identity, set()).add(
            (cast("str", row.get("source_sha256")), cast("int", row.get("file_bytes")))
        )
        for group in (row.get("bindings", []), row.get("resource_components", [])):
            for item in group:
                identity = (case_id, cast("str", item.get("source_path")))
                identities.setdefault(identity, set()).add(
                    (
                        cast("str", item.get("source_sha256")),
                        cast("int", item.get("source_file_bytes")),
                    )
                )
    for (case_id, path), expected_identities in identities.items():
        source = sources.get((case_id, path))
        if source is None:
            errors.append(f"missing frozen source bytes for {case_id}:{path}")
        else:
            actual = (hashlib.sha256(source).hexdigest(), len(source))
            if len(expected_identities) != 1 or actual not in expected_identities:
                errors.append(f"frozen source byte identity mismatch for {case_id}:{path}")
    return errors


def _pointer(value: Any, pointer: Any) -> Any:
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise ValueError("JSON pointer must be an absolute pointer")
    current = value
    for raw_token in pointer[1:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        current = current[int(token)] if isinstance(current, list) else current[token]
    return current


def _validate_mapping(  # noqa: PLR0911, PLR0912, PLR0915 -- keep fail-closed checks together.
    rows: list[dict[str, Any]],
    output_bytes_by_hash: dict[str, bytes] | None,
    mapping: dict[str, Any] | None,
) -> list[str]:
    unsupported = [
        row for row in rows if row.get("cli_observation", {}).get("status") == "unsupported"
    ]
    observed = [row for row in rows if row.get("cli_observation", {}).get("status") == "observed"]
    unobserved = [
        row for row in rows if row.get("cli_observation", {}).get("status") == "unobserved_by_cli"
    ]
    if (
        not observed
        and not unobserved
        and not unsupported
        and mapping is None
        and output_bytes_by_hash is None
    ):
        return []
    errors: list[str] = []
    if unsupported:
        if mapping is not None:
            errors.append("public audit schema v1 does not support caller-defined row mappings")
        if output_bytes_by_hash is None:
            return [*errors, "unsupported CLI projection requires authenticated output bytes"]
        expected_hashes = {
            row.get("cli_observation", {}).get("output_sha256") for row in unsupported
        }
        for digest in expected_hashes:
            raw = output_bytes_by_hash.get(cast("str", digest))
            if raw is None or hashlib.sha256(raw).hexdigest() != digest:
                errors.append("unsupported CLI projection output bytes missing or hash mismatch")
                continue
            try:
                report = strict_json_loads(raw, f"authenticated public audit output {digest}")
            except BenchmarkSchemaError:
                errors.append("public audit output is not valid JSON")
                continue
            errors.extend(_validate_public_audit_v1(report))
        return errors
    if mapping is None or output_bytes_by_hash is None:
        return ["observed/unobserved CLI rows require output bytes and a frozen mapping artifact"]
    if set(mapping) != {"schema_version", "invocations"} or mapping.get("schema_version") != 1:
        errors.append("mapping artifact must use schema_version 1 and its closed top-level shape")
        return errors
    invocations = mapping.get("invocations")
    if not isinstance(invocations, list):
        return ["mapping invocations must be an array"]
    mapped: set[tuple[str, str, str, int, int, str]] = set()
    mapped_ptrs: set[tuple[str, str]] = set()
    for invocation in invocations:
        if not isinstance(invocation, dict) or set(invocation) != {
            "invocation_id",
            "output_sha256",
            "rows",
            "unobserved_rows",
        }:
            errors.append("mapping invocation has invalid closed shape")
            continue
        digest = invocation["output_sha256"]
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(c not in "0123456789abcdef" for c in digest)
        ):
            errors.append("mapping invocation output_sha256 is invalid")
            continue
        raw = output_bytes_by_hash.get(digest)
        if raw is None or hashlib.sha256(raw).hexdigest() != digest:
            errors.append(f"mapping output bytes missing or hash mismatch: {digest}")
            continue
        try:
            output = strict_json_loads(raw, f"authenticated mapping output {digest}")
        except BenchmarkSchemaError:
            errors.append(f"mapping output is not valid JSON: {digest}")
            continue
        if not isinstance(invocation["rows"], list) or not isinstance(
            invocation["unobserved_rows"], list
        ):
            errors.append("mapping invocation row collections must be arrays")
            continue
        for item in invocation["rows"]:
            if not isinstance(item, dict) or set(item) != {
                "inventory_key",
                "rows_pointer",
                "output_pointer",
                "row_sha256",
                "fields",
            }:
                errors.append("mapping row has invalid closed shape")
                continue
            key_values = item["inventory_key"]
            if not isinstance(key_values, list) or len(key_values) != 6:
                errors.append("mapping inventory_key must contain the six physical identity fields")
                continue
            if (
                not isinstance(item["output_pointer"], str)
                or not isinstance(item["row_sha256"], str)
                or not isinstance(item["fields"], dict)
                or not isinstance(item["rows_pointer"], str)
            ):
                errors.append("mapping row pointer, row hash, or fields have invalid types")
                continue
            key = tuple(key_values)
            target = next((r for r in observed if _call_key(r) == key), None)
            if (
                target is None
                or target["cli_observation"].get("invocation_id") != invocation["invocation_id"]
                or target["cli_observation"].get("output_sha256") != digest
            ):
                errors.append(
                    "mapping key does not identify an observed inventory row in this invocation"
                )
                continue
            locator = (digest, item["output_pointer"])
            if key in mapped or locator in mapped_ptrs:
                errors.append("duplicate inventory mapping or output row mapping")
                continue
            mapped.add(key)
            mapped_ptrs.add(locator)
            try:
                output_row = _pointer(output, item["output_pointer"])
                if _canonical_hash(output_row) != item["row_sha256"]:
                    errors.append("mapped output row canonical hash mismatch")
                fields = item["fields"]
                if set(fields) != {
                    "row_key",
                    "path",
                    "source_sha256",
                    "start_byte",
                    "end_byte",
                    "call_ast_sha256",
                    "callee_syntax",
                }:
                    raise ValueError("mapped physical field pointers have invalid shape")
                expected = {
                    "row_key": target["cli_observation"]["row_key"],
                    "path": target["path"],
                    "source_sha256": target["source_sha256"],
                    "start_byte": target["start_byte"],
                    "end_byte": target["end_byte"],
                    "call_ast_sha256": target["call_ast_sha256"],
                    "callee_syntax": target["callee_syntax"],
                }
                output_rows = _pointer(output, item["rows_pointer"])
                if not isinstance(output_rows, list):
                    raise ValueError("mapped output collection must be an array")
                physical_matches = [
                    candidate
                    for candidate in output_rows
                    if all(
                        _pointer(candidate, pointer) == expected[name]
                        for name, pointer in fields.items()
                    )
                ]
                if len(physical_matches) != 1 or physical_matches[0] != output_row:
                    errors.append("mapped physical output row is not unique in parsed output")
                for name, pointer in fields.items():
                    if _pointer(output_row, pointer) != expected[name]:
                        errors.append(f"mapped output physical field mismatch: {name}")
            except (KeyError, IndexError, TypeError, ValueError):
                errors.append("mapping output pointer or physical field pointer is invalid")
        for item in invocation["unobserved_rows"]:
            if not isinstance(item, dict) or set(item) != {
                "inventory_key",
                "rows_pointer",
                "fields",
            }:
                errors.append("unobserved mapping row has invalid closed shape")
                continue
            key_values = item["inventory_key"]
            if not isinstance(key_values, list) or len(key_values) != 6:
                errors.append("unobserved inventory_key must contain six physical identity fields")
                continue
            key = tuple(key_values)
            target = next((r for r in unobserved if _call_key(r) == key), None)
            if (
                target is None
                or target["cli_observation"].get("invocation_id") != invocation["invocation_id"]
                or target["cli_observation"].get("output_sha256") != digest
            ):
                errors.append("unobserved mapping key does not identify this completed invocation")
                continue
            if key in mapped:
                errors.append("duplicate inventory mapping proof")
                continue
            mapped.add(key)
            try:
                output_rows = _pointer(output, item["rows_pointer"])
                fields = item["fields"]
                expected_names = {
                    "path",
                    "source_sha256",
                    "start_byte",
                    "end_byte",
                    "call_ast_sha256",
                    "callee_syntax",
                }
                if not isinstance(output_rows, list) or set(fields) != expected_names:
                    raise ValueError("unobserved physical row fields have invalid shape")
                expected = {
                    "path": target["path"],
                    "source_sha256": target["source_sha256"],
                    "start_byte": target["start_byte"],
                    "end_byte": target["end_byte"],
                    "call_ast_sha256": target["call_ast_sha256"],
                    "callee_syntax": target["callee_syntax"],
                }
                for output_row in output_rows:
                    if all(
                        _pointer(output_row, pointer) == expected[name]
                        for name, pointer in fields.items()
                    ):
                        errors.append("unobserved inventory row is present in CLI output")
                        break
            except (KeyError, IndexError, TypeError, ValueError):
                errors.append("unobserved output collection or physical field pointer is invalid")
    expected_keys = {_call_key(row) for row in observed}
    expected_keys.update(_call_key(row) for row in unobserved)
    if mapped != expected_keys:
        errors.append("mapping must prove each observed row or unobserved-row absence exactly once")
    return errors


def _validate_public_audit_v1(
    report: Any,
) -> list[str]:
    """Validate public v1 with the exact model used by the CLI serializer."""
    try:
        audit = EffectContractAudit.model_validate(report)
    except (TypeError, ValueError) as exc:
        return [f"public audit report violates EffectContractAudit: {exc}"]
    serialized = audit.model_dump(mode="json", exclude_none=True)
    try:
        report_json = _strict_json_encoding(report)
        serialized_json = _strict_json_encoding(serialized)
    except (TypeError, ValueError):
        return ["public audit report is not an exclude_none CLI model serialization"]
    if report_json != serialized_json:
        return ["public audit report is not an exclude_none CLI model serialization"]
    # Version 1 has no byte offsets, source hashes, or call AST hashes.
    return []


def _strict_json_encoding(value: Any) -> str:
    """Canonicalize JSON values without Python's bool/int equality or non-finite numbers."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _call_key(row: dict[str, Any]) -> tuple[Any, ...]:
    return (
        row.get("case_id"),
        row.get("packet_sha256"),
        row.get("path"),
        row.get("start_byte"),
        row.get("end_byte"),
        row.get("call_ast_sha256"),
    )


def main() -> int:
    if len(sys.argv) != 5:
        print(
            f"usage: {Path(sys.argv[0]).name} rows.json mapping.json|- outputs sources-dir",
            file=sys.stderr,
        )
        return 2
    try:
        rows = strict_json_loads(Path(sys.argv[1]).read_bytes(), "inventory")
    except (OSError, BenchmarkSchemaError) as exc:
        print(f"cannot read inventory JSON: {exc}", file=sys.stderr)
        return 2
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        print("inventory must be a JSON array of row objects", file=sys.stderr)
        return 2
    try:
        mapping = (
            None
            if sys.argv[2] == "-"
            else strict_json_loads(Path(sys.argv[2]).read_bytes(), "mapping")
        )
        if mapping is not None and not isinstance(mapping, dict):
            raise ValueError("mapping artifact must be a JSON object")
        output_path = Path(sys.argv[3])
        output_paths = sorted(output_path.glob("*.json")) if output_path.is_dir() else [output_path]
        output_bytes_by_hash = {
            hashlib.sha256(path.read_bytes()).hexdigest(): path.read_bytes()
            for path in output_paths
        }
        sources_dir = Path(sys.argv[4])
        source_bytes_by_identity: dict[tuple[str, str], bytes] = {}
        for row in rows:
            references = [(row["case_id"], row["path"])]
            references.extend(
                (row["case_id"], item["source_path"])
                for group in (row["bindings"], row["resource_components"])
                for item in group
            )
            for case_id, relative_path in references:
                relative = Path(relative_path)
                case_directory = Path(case_id)
                if (
                    relative.is_absolute()
                    or ".." in relative.parts
                    or case_directory.is_absolute()
                    or ".." in case_directory.parts
                ):
                    raise ValueError("source paths must be relative and cannot traverse parents")
                identity = (case_id, relative_path)
                if identity not in source_bytes_by_identity:
                    source_bytes_by_identity[identity] = (
                        sources_dir / case_id / relative
                    ).read_bytes()
    except (OSError, BenchmarkSchemaError, KeyError, TypeError, ValueError) as exc:
        print(f"cannot read mapping/output: {exc}", file=sys.stderr)
        return 2
    errors = validate_rows(rows, output_bytes_by_hash, mapping, source_bytes_by_identity)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"semantic validation passed for {len(rows)} inventory rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
