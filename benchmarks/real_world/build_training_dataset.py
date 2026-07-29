#!/usr/bin/env python3
"""Build inexpensive exploratory fine-tuning data from PR metadata and labels.

This is deliberately separate from publication-grade blind-review and production
custody workflows. It joins an existing corpus with completed legacy review JSONL
or a v2 compatibility projection, optionally fetches PR diffs, and emits ordinary
JSONL examples. It never writes canonical truth or treats incomplete labels as
negative examples.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, cast
from urllib.error import URLError
from urllib.request import Request, urlopen

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.real_world._secure_publish import (
    SecurePathError,
    ensure_publishable,
    publish_exclusive_bytes,
    read_secure_regular_file,
)
from benchmarks.real_world.benchmark_schema import BenchmarkSchemaError, strict_json_loads
from benchmarks.real_world.benchmark_scope import SCOPES, filter_record

HERE = Path(__file__).resolve().parent
DEFAULT_OUTPUT = HERE / "blast-radius-dataset.jsonl"
MAX_DIFF_BYTES = 8 * 1024 * 1024

TARGET_FIELDS = (
    "status",
    "affected_entrypoints",
    "changed_symbols",
    "affected_tests",
    "contract_changes",
    "unknowns",
    "orphans",
)
_LIST_TARGET_FIELDS = TARGET_FIELDS[1:]
_LEGACY_REQUIRED_LIST_FIELDS = (*_LIST_TARGET_FIELDS, "cross_repository_consumers")
_COMPLETED_LEGACY_STATUSES = {"reviewed", "adjudicated"}
_SKIPPABLE_STATUSES = {"pending", "pending_double_review", "unknown", "not_evaluable"}
_ALLOWED_CONFIDENCE = {"confirmed", "probable", "possible"}
_ALLOWED_KINDS = {"http", "graphql", "task", "event", "cli", "cron", "sdk", "other"}
_PROTECTED_ARTIFACTS = (
    HERE / "corpus.json",
    HERE / "review-a.jsonl",
    HERE / "review-b.jsonl",
    HERE / "adjudicated.jsonl",
    HERE / "adjudication-amendments.jsonl",
    HERE / "reachability-supplements.jsonl",
    HERE / "review-queue.json",
)
_PROTECTED_ROOTS = tuple(
    HERE / name
    for name in (
        "expansion",
        "ground_truth_v2",
        "pilot_v2",
        "pilot_v3",
        "production_v1",
        "scopes",
        "verification_sets",
    )
)


class DatasetError(ValueError):
    """Raised when corpus or label data cannot form a safe training example."""


def _strict_json(content: str, source: str) -> Any:
    try:
        return strict_json_loads(content, source)
    except BenchmarkSchemaError as error:
        raise DatasetError(str(error)) from error


def _protected_files(input_paths: tuple[Path, ...]) -> tuple[Path, ...]:
    return (*_PROTECTED_ARTIFACTS, *input_paths)


def _validate_destination(path: Path, *, input_paths: tuple[Path, ...] = ()) -> None:
    absolute = Path(path).expanduser().absolute()
    if absolute in {item.expanduser().absolute() for item in input_paths}:
        raise DatasetError(f"refusing to overwrite input file: {path}")
    if absolute in {item.expanduser().absolute() for item in _PROTECTED_ARTIFACTS} or any(
        absolute.is_relative_to(root.expanduser().absolute()) for root in _PROTECTED_ROOTS
    ):
        raise DatasetError(f"refusing to target frozen benchmark artifact: {path}")
    try:
        ensure_publishable(
            path,
            forbidden_files=_protected_files(input_paths),
            forbidden_roots=_PROTECTED_ROOTS,
        )
    except SecurePathError as error:
        raise DatasetError(str(error)) from error


def _publish_exclusive_bytes(
    destination: Path,
    content: bytes,
    *,
    input_paths: tuple[Path, ...] = (),
) -> None:
    """Durably publish exact bytes through a stable destination-directory FD."""
    try:
        publish_exclusive_bytes(
            destination,
            content,
            forbidden_files=_protected_files(input_paths),
            forbidden_roots=_PROTECTED_ROOTS,
        )
    except SecurePathError as error:
        raise DatasetError(str(error)) from error


def record_key(record: dict[str, Any]) -> tuple[str, int]:
    repository = record.get("repository")
    if (
        "pr" in record
        and "number" in record
        and (type(record["pr"]) is not type(record["number"]) or record["pr"] != record["number"])
    ):
        raise DatasetError(f"record has conflicting pr and number aliases for {repository}")
    raw_pr = record.get("pr", record.get("number"))
    if not isinstance(repository, str) or not repository.strip():
        raise DatasetError("record has no repository")
    if type(raw_pr) is not int or raw_pr < 1:
        raise DatasetError(f"record has invalid PR number for {repository}")
    return repository, raw_pr


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise DatasetError(f"cannot read {path}: {error}") from error

    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        value = _strict_json(line, f"{path}:{line_number}")
        if not isinstance(value, dict):
            raise DatasetError(f"{path}:{line_number} must contain a JSON object")
        records.append(value)
    return records


def load_corpus(path: Path) -> list[dict[str, Any]]:
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise DatasetError(f"cannot read corpus {path}: {error}") from error
    value = _strict_json(content, str(path))
    if not isinstance(value, dict) or not isinstance(value.get("entries"), list):
        raise DatasetError("corpus must be an object with an entries list")

    entries: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for entry in value["entries"]:
        if not isinstance(entry, dict):
            raise DatasetError("corpus entries must be objects")
        key = record_key(entry)
        merge_sha(entry)
        if key in seen:
            raise DatasetError(f"duplicate corpus entry: {key[0]}#{key[1]}")
        seen.add(key)
        entries.append(entry)
    return entries


def _validate_string_list(label: dict[str, Any], field: str, identity: str) -> None:
    value = label.get(field)
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise DatasetError(f"completed label {identity} requires {field} as a string list")


def _validate_entrypoints(
    value: object,
    identity: str,
    *,
    require_evidence: bool,
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise DatasetError(f"completed label {identity} requires affected_entrypoints as a list")
    seen: set[str] = set()
    for index, item in enumerate(value):
        location = f"completed label {identity} affected_entrypoints[{index}]"
        if not isinstance(item, dict):
            raise DatasetError(f"{location} must be an object")
        entrypoint_id = item.get("id")
        if not isinstance(entrypoint_id, str) or not entrypoint_id.strip():
            raise DatasetError(f"{location}.id must be a non-empty string")
        if entrypoint_id in seen:
            raise DatasetError(f"completed label {identity} has duplicate entrypoint id")
        seen.add(entrypoint_id)
        if item.get("kind") not in _ALLOWED_KINDS:
            raise DatasetError(f"{location}.kind is invalid")
        if item.get("confidence") not in _ALLOWED_CONFIDENCE:
            raise DatasetError(f"{location}.confidence is invalid")
        if require_evidence:
            evidence = item.get("evidence")
            if (
                not isinstance(evidence, list)
                or not evidence
                or any(
                    not isinstance(fragment, str) or not fragment.strip() for fragment in evidence
                )
            ):
                raise DatasetError(f"{location}.evidence must contain non-empty strings")
    return value


def _validate_reviewer(label: dict[str, Any], identity: str) -> None:
    reviewer = label.get("reviewer")
    if not isinstance(reviewer, dict):
        raise DatasetError(f"completed label {identity} requires reviewer provenance")
    if reviewer.get("kind") not in {"agent", "human"}:
        raise DatasetError(f"completed label {identity} reviewer.kind is invalid")
    for field in ("name", "version"):
        value = reviewer.get(field)
        if not isinstance(value, str) or not value.strip():
            raise DatasetError(f"completed label {identity} reviewer.{field} is required")


def classify_label(label: dict[str, Any]) -> tuple[str, str | None]:
    """Classify a label as completed or explicitly skippable, rejecting ambiguity."""
    status = label.get("status")
    if not isinstance(status, str):
        raise DatasetError("label status must be a string")
    has_terminal = "terminal_status" in label
    terminal_status = label.get("terminal_status")
    if has_terminal and not isinstance(terminal_status, str):
        raise DatasetError("label terminal_status must be a string when present")

    if not has_terminal and status in _COMPLETED_LEGACY_STATUSES:
        return "completed", status
    if status == "adjudicated" and terminal_status in {"positive", "negative_control"}:
        return "completed", cast("str", terminal_status)
    if not has_terminal and status in _SKIPPABLE_STATUSES:
        return "skippable", None
    if status in {"unknown", "not_evaluable"} and terminal_status == status:
        return "skippable", None
    supported = sorted(_COMPLETED_LEGACY_STATUSES | _SKIPPABLE_STATUSES)
    raise DatasetError(
        f"invalid status/terminal_status combination: status={status!r}, "
        f"terminal_status={terminal_status!r}; supported statuses are {supported}"
    )


def completed_label_status(label: dict[str, Any]) -> str | None:
    """Return a validated completed target status, or None for an explicit skip."""
    classification, target_status = classify_label(label)
    return target_status if classification == "completed" else None


def _validate_optional_v2_targets(label: dict[str, Any], identity: str) -> None:
    if "affected_entrypoints" in label:
        _validate_entrypoints(label["affected_entrypoints"], identity, require_evidence=False)
    for field in _LIST_TARGET_FIELDS:
        if field != "affected_entrypoints" and field in label:
            _validate_string_list(label, field, identity)


def _validate_skippable_label(label: dict[str, Any]) -> None:
    repository, pr = record_key(label)
    identity = f"{repository}#{pr}"
    status = cast("str", label["status"])
    if "terminal_status" in label:
        _validate_optional_v2_targets(label, identity)
        if label.get("affected_entrypoints") != []:
            raise DatasetError(f"skippable v2 label {identity} requires no affected entrypoints")
    elif status in {"unknown", "not_evaluable"} and "affected_entrypoints" in label:
        _validate_optional_v2_targets(label, identity)


def validate_completed_label(label: dict[str, Any]) -> str:
    """Validate one completed legacy review or real v2 compatibility projection."""
    repository, pr = record_key(label)
    identity = f"{repository}#{pr}"
    target_status = completed_label_status(label)
    if target_status is None:
        raise DatasetError(f"label {identity} is not a completed review")

    if target_status in {"positive", "negative_control"}:
        _validate_optional_v2_targets(label, identity)
        entrypoints = label.get("affected_entrypoints")
        if not isinstance(entrypoints, list):
            raise DatasetError(
                f"completed v2 label {identity} requires affected_entrypoints as a list"
            )
        if target_status == "positive" and not entrypoints:
            raise DatasetError(f"completed v2 positive label {identity} requires entrypoints")
        if target_status == "negative_control" and entrypoints:
            raise DatasetError(
                f"completed v2 negative-control label {identity} forbids entrypoints"
            )
        return target_status

    _validate_reviewer(label, identity)
    _validate_entrypoints(label.get("affected_entrypoints"), identity, require_evidence=True)
    for field in _LEGACY_REQUIRED_LIST_FIELDS:
        if field != "affected_entrypoints":
            _validate_string_list(label, field, identity)
    notes = label.get("notes")
    if not isinstance(notes, str):
        raise DatasetError(f"completed label {identity} requires notes as a string")
    return target_status


def load_labels(path: Path) -> dict[tuple[str, int], dict[str, Any]]:
    labels: dict[tuple[str, int], dict[str, Any]] = {}
    seen: set[tuple[str, int]] = set()
    for label in read_jsonl(path):
        key = record_key(label)
        if key in seen:
            raise DatasetError(f"duplicate label: {key[0]}#{key[1]}")
        seen.add(key)
        classification, _target_status = classify_label(label)
        if classification == "skippable":
            # Only explicit pending/unknown/not-evaluable rows are absent from
            # the join; malformed status shapes fail closed above.
            _validate_skippable_label(label)
            continue
        validate_completed_label(label)
        labels[key] = label
    return labels


def _normalized_oid(value: object, location: str) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", value) is None
    ):
        raise DatasetError(f"{location} must be a full 40- or 64-character hexadecimal Git OID")
    return value.lower()


def merge_sha(entry: dict[str, Any]) -> str | None:
    """Return a normalized corpus merge OID, rejecting every malformed present value."""
    if "mergeCommit" not in entry or entry["mergeCommit"] is None:
        return None
    value = entry["mergeCommit"]
    if isinstance(value, dict):
        if set(value) != {"oid"}:
            raise DatasetError("corpus mergeCommit must contain only an oid")
        return _normalized_oid(value["oid"], "corpus mergeCommit.oid")
    if isinstance(value, str):
        return _normalized_oid(value, "corpus mergeCommit")
    raise DatasetError("corpus mergeCommit must be an object with an oid, a Git OID, or null")


def diff_filename(repository: str, pr: int, merge_commit: str | None = None) -> str:
    """Return one separator-free cache basename bound to the full target commit."""
    normalized_commit = (
        _normalized_oid(merge_commit, "cache merge commit") if merge_commit is not None else None
    )
    repository_component = repository.replace("/", "--").replace("\\", "--")
    suffix = f"--{normalized_commit}" if normalized_commit else ""
    name = f"{repository_component}--{pr}{suffix}.diff"
    if name in {".", ".."} or "/" in name or "\\" in name or Path(name).name != name:
        raise DatasetError("diff cache name must be a single separator-free basename")
    return name


def _diff_cache_path(
    diff_dir: Path,
    repository: str,
    pr: int,
    merge_commit: str | None,
) -> Path:
    cache_root = diff_dir.expanduser().absolute()
    candidate = (cache_root / diff_filename(repository, pr, merge_commit)).absolute()
    if candidate.parent != cache_root:
        raise DatasetError(f"diff cache path escapes --diff-dir: {candidate}")
    return candidate


def _read_diff(
    path: Path,
    *,
    input_paths: tuple[Path, ...] = (),
) -> str | None:
    try:
        raw = read_secure_regular_file(
            path,
            forbidden_files=_protected_files(input_paths),
        )
    except SecurePathError as error:
        raise DatasetError(str(error)) from error
    if raw is None:
        return None
    if len(raw) > MAX_DIFF_BYTES:
        raise DatasetError(f"diff is larger than {MAX_DIFF_BYTES} bytes: {path}")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise DatasetError(f"diff is not valid UTF-8: {path}") from error


def fetch_diff(
    url: str,
    destination: Path,
    timeout: float = 30.0,
    *,
    input_paths: tuple[Path, ...] = (),
) -> str:
    """Fetch one public diff and publish its cache entry without clobbering."""
    _validate_destination(destination, input_paths=input_paths)
    request = Request(url, headers={"Accept": "text/plain", "User-Agent": "blast-radius-dataset"})
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = cast("bytes", response.read(MAX_DIFF_BYTES + 1))
    except (OSError, URLError) as error:
        raise DatasetError(f"cannot fetch diff {url}: {error}") from error
    if len(raw) > MAX_DIFF_BYTES:
        raise DatasetError(f"diff is larger than {MAX_DIFF_BYTES} bytes: {url}")
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise DatasetError(f"downloaded diff is not valid UTF-8: {url}") from error
    _publish_exclusive_bytes(destination, raw, input_paths=input_paths)
    return decoded


def _embedded_diff(entry: dict[str, Any]) -> str | None:
    value = entry.get("diff", entry.get("patch"))
    return value if isinstance(value, str) else None


def get_diff(
    entry: dict[str, Any],
    *,
    diff_dir: Path | None,
    fetch_missing: bool,
    input_paths: tuple[Path, ...] = (),
) -> tuple[str | None, str]:
    embedded = _embedded_diff(entry)
    if embedded is not None:
        return embedded, "corpus"

    repository, pr = record_key(entry)
    target_commit = merge_sha(entry)
    if diff_dir is not None:
        cached = _diff_cache_path(diff_dir, repository, pr, target_commit)
        cached_diff = _read_diff(cached, input_paths=input_paths)
        if cached_diff is not None:
            return cached_diff, "cache"

    if not fetch_missing:
        return None, "missing"

    # Construct the URL from the validated repository identity instead of
    # following an arbitrary URL embedded in a corpus record.
    url = f"https://github.com/{repository}/pull/{pr}.diff"
    if diff_dir is None:
        raise DatasetError("--fetch-diffs requires --diff-dir")
    return (
        fetch_diff(
            url,
            _diff_cache_path(diff_dir, repository, pr, target_commit),
            input_paths=input_paths,
        ),
        # Serialized provenance describes stable data availability, not whether
        # this invocation happened to populate the cache.
        "cache",
    )


def target_from_label(label: dict[str, Any], scope: str) -> dict[str, Any]:
    validate_completed_label(label)
    filtered = filter_record(label, scope)
    target: dict[str, Any] = {"status": label["status"]}
    if "terminal_status" in label:
        target["terminal_status"] = label["terminal_status"]
    for field in _LIST_TARGET_FIELDS:
        if field in filtered:
            target[field] = filtered[field]
    return target


def build_examples(
    corpus: list[dict[str, Any]],
    labels: dict[tuple[str, int], dict[str, Any]],
    *,
    scope: str = "fastapi",
    diff_dir: Path | None = None,
    fetch_missing: bool = False,
    limit: int | None = None,
    input_paths: tuple[Path, ...] = (),
) -> tuple[list[dict[str, Any]], int]:
    """Join corpus and completed labels, returning examples and missing count."""
    if scope not in SCOPES:
        raise DatasetError(f"unknown scope: {scope}")
    # Callers may construct corpus records directly instead of using load_corpus;
    # validate all merge identities before filtering, cache lookup, or fetching.
    for entry in corpus:
        merge_sha(entry)
    examples: list[dict[str, Any]] = []
    missing_labels = 0
    for entry in corpus:
        key = record_key(entry)
        label = labels.get(key)
        if label is None or completed_label_status(label) is None:
            missing_labels += 1
            continue
        validate_completed_label(label)
        if limit is not None and len(examples) >= limit:
            break
        diff, diff_source = get_diff(
            entry,
            diff_dir=diff_dir,
            fetch_missing=fetch_missing,
            input_paths=input_paths,
        )
        target = target_from_label(label, scope)
        examples.append(
            {
                "schema_version": 1,
                "id": f"{key[0]}#{key[1]}",
                "input": {
                    "repository": key[0],
                    "pr": key[1],
                    "title": entry.get("title", ""),
                    "body": entry.get("body", ""),
                    "changed_files": entry.get("files", []),
                    "diff": diff,
                },
                "target": target,
                "metadata": {
                    "label_source_status": label["status"],
                    "label_terminal_status": label.get("terminal_status"),
                    "diff_source": diff_source,
                    "diff_sha256": hashlib.sha256(diff.encode("utf-8")).hexdigest()
                    if diff is not None
                    else None,
                    "merge_commit": entry.get("mergeCommit"),
                    "base_ref": entry.get("baseRefName"),
                    "head_ref": entry.get("headRefName"),
                },
            }
        )
    return examples, missing_labels


def _write_jsonl(
    path: Path,
    records: list[dict[str, Any]],
    *,
    input_paths: tuple[Path, ...] = (),
) -> None:
    _validate_destination(path, input_paths=input_paths)
    try:
        content = "".join(
            json.dumps(record, sort_keys=True, allow_nan=False) + "\n" for record in records
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise DatasetError(f"dataset output is not strict JSON: {error}") from error
    _publish_exclusive_bytes(path, content, input_paths=input_paths)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build exploratory blast-radius fine-tuning JSONL without production gates."
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        required=True,
        help="Exploratory corpus metadata JSON (frozen destinations remain protected).",
    )
    parser.add_argument(
        "--labels",
        type=Path,
        required=True,
        help="Completed review JSONL or a v2 compatibility projection.",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--diff-dir", type=Path)
    parser.add_argument(
        "--fetch-diffs",
        action="store_true",
        help="Fetch missing public PR diffs into --diff-dir (otherwise diff is null).",
    )
    parser.add_argument("--scope", choices=SCOPES, default="fastapi")
    parser.add_argument("--limit", type=int)
    args = parser.parse_args(argv)

    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be positive")
    if args.fetch_diffs and args.diff_dir is None:
        parser.error("--fetch-diffs requires --diff-dir")

    input_paths = (args.corpus, args.labels)
    cache_protected_paths = (*input_paths, args.output)
    try:
        _validate_destination(args.output, input_paths=input_paths)
        corpus = load_corpus(args.corpus)
        labels = load_labels(args.labels)
        examples, missing_labels = build_examples(
            corpus,
            labels,
            scope=args.scope,
            diff_dir=args.diff_dir,
            fetch_missing=args.fetch_diffs,
            limit=args.limit,
            input_paths=cache_protected_paths,
        )
        _write_jsonl(args.output, examples, input_paths=input_paths)
    except DatasetError as error:
        parser.error(str(error))

    missing_diffs = sum(example["metadata"]["diff_source"] == "missing" for example in examples)
    print(
        json.dumps(
            {
                "examples": len(examples),
                "missing_labels": missing_labels,
                "missing_diffs": missing_diffs,
                "scope": args.scope,
                "output": str(args.output),
            },
            sort_keys=True,
            allow_nan=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
