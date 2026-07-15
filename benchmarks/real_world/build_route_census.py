#!/usr/bin/env python3
"""Build an execution-free dual-snapshot FastAPI route census."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.real_world.run_current import (
    HERE,
    PROJECT_ROOT,
    RunnerError,
    add_detached_worktree,
    atomic_write,
    candidate_metadata,
    command,
    ensure_cache,
    merge_parents,
    parse_app_entries,
    parse_app_roots,
    prediction_identity,
    remove_worktree,
    resolve_base_parent,
    safe_app_root,
    select_entries,
    utc_now,
    validate_sha,
)

SCHEMA_VERSION = 2
HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"}


@dataclass(frozen=True)
class CensusConfig:
    cache: Path
    output: Path
    manifest: Path
    candidate_root: Path
    timeout: float
    default_app_root: str
    app_roots: dict[str, str]
    app_entries: dict[str, str] = field(default_factory=dict)
    bootstrap_entries: dict[str, str] = field(default_factory=dict)


def _normalized_path(value: str) -> str:
    return re.sub(r"/{2,}", "/", f"/{value.strip().lstrip('/')}")


def _relative_source(worktree: Path, value: object) -> tuple[str | None, str | None]:
    if not isinstance(value, str) or not value or "\x00" in value:
        return None, "handler file is missing or malformed"
    source = Path(value)
    candidate = source if source.is_absolute() else worktree / source
    try:
        resolved = candidate.resolve(strict=True)
        relative = resolved.relative_to(worktree.resolve())
    except (OSError, ValueError):
        return None, f"handler file escapes or is absent: {value!r}"
    if not resolved.is_file():
        return None, f"handler source is not a file: {value!r}"
    return relative.as_posix(), None


def normalize_inventory(  # noqa: PLR0912, PLR0915
    report: object, worktree: Path, configured_root: str
) -> tuple[list[dict[str, Any]], list[str], str, list[dict[str, Any]]]:
    """Normalize secure list output while retaining occurrence and inventory strength."""
    if not isinstance(report, dict) or not isinstance(report.get("endpoints"), list):
        raise RunnerError("secure list JSON must contain an endpoints list")
    has_status = "inventory_status" in report
    has_limitations = "inventory_limitations" in report
    if has_status != has_limitations:
        raise RunnerError("secure list inventory metadata must be complete")
    inventory_status = report.get("inventory_status", "established")
    raw_limitations = report.get("inventory_limitations", [])
    if inventory_status not in {"established", "conditional", "unavailable"}:
        raise RunnerError("secure list has invalid inventory status")
    if (
        not isinstance(raw_limitations, list)
        or (inventory_status == "established" and raw_limitations)
        or (inventory_status != "established" and not raw_limitations)
    ):
        raise RunnerError("secure list has invalid inventory limitations")
    normalized_limitations: list[dict[str, Any]] = []
    for index, limitation in enumerate(raw_limitations):
        if not isinstance(limitation, dict):
            raise RunnerError(f"inventory_limitation[{index}] must be an object")
        source, source_error = _relative_source(worktree, limitation.get("source_path"))
        source_line = limitation.get("source_line")
        reason = limitation.get("reason")
        if (
            source_error is not None
            or type(source_line) is not int
            or source_line < 1
            or not isinstance(reason, str)
            or not reason.strip()
        ):
            raise RunnerError(f"inventory_limitation[{index}] is invalid")
        normalized_limitations.append({"source": source, "line": source_line, "reason": reason})
    normalized_limitations.sort(key=lambda item: (item["source"], item["line"], item["reason"]))
    grouped: dict[str, dict[str, Any]] = {}
    unresolved: list[str] = []
    for index, raw in enumerate(report["endpoints"]):
        if not isinstance(raw, dict):
            unresolved.append(f"endpoint[{index}]: expected object")
            continue
        path = raw.get("path")
        methods = raw.get("methods")
        handler = raw.get("handler")
        if not isinstance(path, str) or not path.strip():
            unresolved.append(f"endpoint[{index}]: missing path")
            continue
        if isinstance(methods, str):
            methods = [methods]
        if not isinstance(methods, list) or not methods:
            unresolved.append(f"endpoint[{index}]: missing methods")
            continue
        if not isinstance(handler, dict):
            unresolved.append(f"endpoint[{index}]: missing handler")
            continue
        relative_file, path_error = _relative_source(worktree, handler.get("file"))
        if path_error is not None:
            unresolved.append(f"endpoint[{index}]: {path_error}")
            continue
        line = handler.get("line")
        end_line = handler.get("end_line")
        name = handler.get("name")
        module = handler.get("module")
        if type(line) is not int or line < 1:
            unresolved.append(f"endpoint[{index}]: invalid handler line")
            continue
        if end_line is not None and (type(end_line) is not int or end_line < line):
            unresolved.append(f"endpoint[{index}]: invalid handler end line")
            continue
        if not isinstance(name, str) or not isinstance(module, str):
            unresolved.append(f"endpoint[{index}]: invalid handler identity")
            continue
        discovery_status = raw.get("discovery_status", "established")
        discovery_conditions = raw.get("discovery_conditions", [])
        if discovery_status not in {"established", "conditional"}:
            unresolved.append(f"endpoint[{index}]: invalid discovery status")
            continue
        if not isinstance(discovery_conditions, list) or (
            discovery_status == "conditional" and not discovery_conditions
        ):
            unresolved.append(f"endpoint[{index}]: invalid discovery conditions")
            continue
        if discovery_status == "established" and discovery_conditions:
            unresolved.append(f"endpoint[{index}]: established route has discovery conditions")
            continue
        normalized_conditions: list[dict[str, Any]] = []
        condition_error = False
        for condition_index, condition in enumerate(discovery_conditions):
            if not isinstance(condition, dict):
                unresolved.append(
                    f"endpoint[{index}].discovery_conditions[{condition_index}]: expected object"
                )
                condition_error = True
                continue
            source, source_error = _relative_source(worktree, condition.get("source_path"))
            source_line = condition.get("source_line")
            reason = condition.get("reason")
            if (
                source_error is not None
                or type(source_line) is not int
                or source_line < 1
                or not isinstance(reason, str)
                or not reason
            ):
                unresolved.append(
                    f"endpoint[{index}].discovery_conditions[{condition_index}]: invalid condition"
                )
                condition_error = True
                continue
            normalized_conditions.append({"source": source, "line": source_line, "reason": reason})
        if condition_error:
            continue
        normalized_conditions.sort(key=lambda item: (item["source"], item["line"], item["reason"]))
        occurrence = {
            "file": relative_file,
            "line": line,
            "end_line": end_line,
            "handler": name,
            "module": module,
            "root": configured_root,
            "discovery_status": discovery_status,
            "discovery_conditions": normalized_conditions,
        }
        for method in methods:
            if not isinstance(method, str) or not method.strip():
                unresolved.append(f"endpoint[{index}]: invalid method {method!r}")
                continue
            normalized_method = method.strip().upper()
            normalized_path = _normalized_path(path)
            if normalized_method == "WEBSOCKET":
                identifier = f"WEBSOCKET {normalized_path}"
                kind = "event"
            elif normalized_method in HTTP_METHODS:
                identifier = f"HTTP {normalized_method} {normalized_path}"
                kind = "http"
            else:
                unresolved.append(f"endpoint[{index}]: unsupported method {normalized_method!r}")
                continue
            item = grouped.setdefault(
                identifier,
                {"id": identifier, "kind": kind, "occurrences": []},
            )
            if occurrence not in item["occurrences"]:
                item["occurrences"].append(dict(occurrence))
    for item in grouped.values():
        item["occurrences"].sort(
            key=lambda occurrence: (
                occurrence["file"],
                occurrence["line"],
                occurrence["end_line"] or occurrence["line"],
                occurrence["handler"],
                occurrence["module"],
                occurrence["root"],
            )
        )
    if inventory_status == "unavailable" and any(
        occurrence["discovery_status"] == "established"
        for item in grouped.values()
        for occurrence in item["occurrences"]
    ):
        raise RunnerError("unavailable inventory cannot contain established endpoints")
    if not has_status:
        inferred_limitations = {
            (condition["source"], condition["line"], condition["reason"]): condition
            for item in grouped.values()
            for occurrence in item["occurrences"]
            if occurrence["discovery_status"] == "conditional"
            for condition in occurrence["discovery_conditions"]
        }
        if inferred_limitations:
            inventory_status = "conditional"
            normalized_limitations = [
                inferred_limitations[key] for key in sorted(inferred_limitations)
            ]
    return (
        [grouped[identifier] for identifier in sorted(grouped)],
        sorted(set(unresolved)),
        inventory_status,
        normalized_limitations,
    )


def invoke_secure_list(
    candidate_root: Path,
    app_root: Path,
    worktree: Path,
    configured_root: str,
    output_path: Path,
    timeout: float,
    app_entry: str | None = None,
    bootstrap_entry: str | None = None,
) -> tuple[list[dict[str, Any]], list[str], str, list[dict[str, Any]], float]:
    """Invoke only the execution-free secure list command."""
    args = [
        sys.executable,
        "-m",
        "fastapi_endpoint_detector",
        "list",
        "--app",
        str(app_root),
        "--format",
        "json",
        "--secure-ast",
    ]
    if app_entry is not None:
        args.extend(["--app-entry", app_entry])
    if bootstrap_entry is not None:
        args.extend(["--bootstrap-entry", bootstrap_entry])
    args.extend(["--output", str(output_path)])
    started = time.monotonic()
    try:
        result = command(args, cwd=candidate_root, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        raise RunnerError(f"secure route census timed out after {timeout:g} seconds") from error
    elapsed = time.monotonic() - started
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic output"
        raise RunnerError(f"secure route census failed ({result.returncode}): {detail}")
    try:
        report = json.loads(output_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RunnerError(f"secure route census output is invalid: {error}") from error
    inventory, unresolved, inventory_status, limitations = normalize_inventory(
        report, worktree, configured_root
    )
    return inventory, unresolved, inventory_status, limitations, elapsed


def _unresolved_side(reason: str) -> dict[str, Any]:
    return {
        "status": "unresolved",
        "inventory_status": "unavailable",
        "inventory_limitations": [],
        "entrypoints": [],
        "unresolved": [reason],
    }


def _extract_side(
    repository_cache: Path,
    sha: str,
    worktree: Path,
    configured_root: str,
    config: CensusConfig,
    label: str,
    app_entry: str | None = None,
    bootstrap_entry: str | None = None,
) -> tuple[dict[str, Any], float]:
    added = False
    started = time.monotonic()
    try:
        added = True
        add_detached_worktree(repository_cache, worktree, sha)
        app_root = safe_app_root(worktree, configured_root)
        output_path = worktree.parent / f"{label}-routes.json"
        inventory, unresolved, inventory_status, limitations, elapsed = invoke_secure_list(
            config.candidate_root,
            app_root,
            worktree,
            configured_root,
            output_path,
            config.timeout,
            app_entry,
            bootstrap_entry,
        )
        side_status = {
            "established": "completed",
            "conditional": "partial",
            "unavailable": "unresolved",
        }[inventory_status]
        if unresolved and side_status == "completed":
            side_status = "partial"
        return (
            {
                "status": side_status,
                "inventory_status": inventory_status,
                "inventory_limitations": limitations,
                "entrypoints": inventory,
                "unresolved": unresolved,
            },
            elapsed,
        )
    except (RunnerError, OSError) as error:
        return _unresolved_side(str(error)), time.monotonic() - started
    finally:
        if added:
            remove_worktree(repository_cache, worktree)


def process_entry(
    entry: dict[str, Any], config: CensusConfig, candidate_id: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    repository, pr = prediction_identity(entry)
    configured_root = config.app_roots.get(repository, config.default_app_root)
    configured_entry = config.app_entries.get(repository)
    configured_bootstrap = config.bootstrap_entries.get(repository)
    started = time.monotonic()
    merge_sha: str | None = None
    base_sha: str | None = None
    target = _unresolved_side("snapshot was not resolved")
    baseline = _unresolved_side("snapshot was not resolved")
    try:
        merge = entry.get("mergeCommit")
        if not isinstance(merge, dict):
            raise RunnerError("corpus entry has no mergeCommit object")
        merge_sha = validate_sha(merge.get("oid"), "merge SHA")
        repository_cache = ensure_cache(config.cache, repository, merge_sha)
        commits = entry.get("commits", [])
        if not isinstance(commits, list):
            raise RunnerError("corpus entry commits must be a list")
        base_sha = resolve_base_parent(merge_parents(repository_cache, merge_sha), commits)
        with tempfile.TemporaryDirectory(prefix="route-census-") as temporary_name:
            temporary = Path(temporary_name)
            target, target_seconds = _extract_side(
                repository_cache,
                merge_sha,
                temporary / "target",
                configured_root,
                config,
                "target",
                configured_entry,
                configured_bootstrap,
            )
            baseline, baseline_seconds = _extract_side(
                repository_cache,
                base_sha,
                temporary / "baseline",
                configured_root,
                config,
                "baseline",
                configured_entry,
                configured_bootstrap,
            )
    except (RunnerError, OSError) as error:
        reason = str(error)
        target = _unresolved_side(reason)
        baseline = _unresolved_side(reason)
        target_seconds = baseline_seconds = 0.0
    complete = target["status"] == baseline["status"] == "completed"
    if complete:
        status = "completed"
    elif target["status"] == baseline["status"] == "unresolved":
        status = "unresolved"
    else:
        status = "partial"
    record = {
        "schema_version": SCHEMA_VERSION,
        "repository": repository,
        "pr": pr,
        "candidate": candidate_id,
        "configured_app_root": configured_root,
        "configured_app_entry": configured_entry,
        "configured_bootstrap_entry": configured_bootstrap,
        "merge_sha": merge_sha,
        "base_sha": base_sha,
        "status": status,
        "complete": complete,
        "target": target,
        "baseline": baseline,
    }
    manifest_record = {
        "repository": repository,
        "pr": pr,
        "merge_sha": merge_sha,
        "base_sha": base_sha,
        "configured_app_entry": configured_entry,
        "configured_bootstrap_entry": configured_bootstrap,
        "status": status,
        "target_status": target["status"],
        "baseline_status": baseline["status"],
        "target_entrypoints": len(target["entrypoints"]),
        "baseline_entrypoints": len(baseline["entrypoints"]),
        "timing_seconds": {
            "target": target_seconds,
            "baseline": baseline_seconds,
            "total": time.monotonic() - started,
        },
    }
    return record, manifest_record


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=HERE / "corpus.json")
    parser.add_argument(
        "--cache", type=Path, default=Path.home() / ".cache" / "current-analyzer-corpus"
    )
    parser.add_argument("--candidate-root", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--output", type=Path, default=HERE / "route-census.jsonl")
    parser.add_argument("--manifest", type=Path, default=HERE / "route-census-manifest.json")
    parser.add_argument("--timeout", type=float, default=600.0)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--repository", action="append", default=[])
    parser.add_argument("--pr", type=int, action="append", default=[])
    parser.add_argument("--app-root", action="append", default=[])
    parser.add_argument("--app-entry", action="append", default=[])
    parser.add_argument("--bootstrap-entry", action="append", default=[])
    parser.add_argument("--default-app-root", default=".")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if args.limit is not None and args.limit < 0:
        parser.error("--limit must not be negative")
    try:
        paths = {args.corpus.resolve(), args.output.resolve(), args.manifest.resolve()}
        if len(paths) != 3:
            raise RunnerError("--corpus, --output, and --manifest must be distinct")
        corpus_bytes = args.corpus.read_bytes()
        corpus = json.loads(corpus_bytes)
        if not isinstance(corpus, dict):
            raise RunnerError("corpus JSON must be an object")
        roots = parse_app_roots(args.app_root)
        app_entries = parse_app_entries(args.app_entry)
        bootstrap_entries = parse_app_entries(args.bootstrap_entry, "--bootstrap-entry")
        entries = select_entries(corpus, args.repository, args.pr, args.limit)
    except (RunnerError, OSError, json.JSONDecodeError, argparse.ArgumentTypeError) as error:
        parser.error(str(error))
    config = CensusConfig(
        cache=args.cache.resolve(),
        output=args.output.resolve(),
        manifest=args.manifest.resolve(),
        candidate_root=args.candidate_root.resolve(),
        timeout=args.timeout,
        default_app_root=args.default_app_root,
        app_roots=roots,
        app_entries=app_entries,
        bootstrap_entries=bootstrap_entries,
    )
    candidate = candidate_metadata(
        config.candidate_root,
        roots,
        args.default_app_root,
        False,
        False,
        app_entries,
        bootstrap_entries,
    )
    candidate["command"] = (
        "uv run --frozen fastapi-endpoint-detector list --secure-ast --format json"
    )
    started = time.monotonic()
    records: list[dict[str, Any]] = []
    pr_manifest: list[dict[str, Any]] = []
    for entry in entries:
        record, item = process_entry(entry, config, candidate["id"])
        records.append(record)
        pr_manifest.append(item)
    identities = [(item["repository"], item["pr"]) for item in records]
    if len(identities) != len(set(identities)) or len(records) != len(entries):
        raise AssertionError("census did not produce exactly one unique record per selected PR")
    jsonl = "".join(json.dumps(record, sort_keys=True) + "\n" for record in records)
    status_counts = Counter(record["status"] for record in records)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "created_at": utc_now(),
        "candidate": candidate,
        "corpus": {
            "path": str(args.corpus.resolve()),
            "sha256": hashlib.sha256(corpus_bytes).hexdigest(),
        },
        "root_config": {
            "default": args.default_app_root,
            "repositories": dict(sorted(roots.items())),
        },
        "app_entry_config": dict(sorted(app_entries.items())),
        "bootstrap_entry_config": dict(sorted(bootstrap_entries.items())),
        "command_contract": [
            "uv",
            "run",
            "--frozen",
            "fastapi-endpoint-detector",
            "list",
            "--app",
            "<snapshot-root>",
            "--format",
            "json",
            "--secure-ast",
            "--app-entry",
            "<optional-module:symbol>",
            "--bootstrap-entry",
            "<optional-module:function>",
            "--output",
            "<temporary-file>",
        ],
        "selection_count": len(entries),
        "status_counts": dict(sorted(status_counts.items())),
        "prs": pr_manifest,
        "timing_seconds": {"total": time.monotonic() - started},
        "output_sha256": hashlib.sha256(jsonl.encode()).hexdigest(),
    }
    atomic_write(config.output, jsonl)
    atomic_write(config.manifest, json.dumps(manifest, indent=2) + "\n")
    print(f"Wrote {len(records)} census records to {config.output}")
    print(f"Wrote manifest to {config.manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
