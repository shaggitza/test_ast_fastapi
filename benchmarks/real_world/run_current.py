#!/usr/bin/env python3
"""Run the current endpoint detector against the frozen real-world corpus.

The runner checks out only immutable Git objects in detached worktrees. The
current analyzer imports application modules, so execution is refused by default
and requires an explicit, manifest-recorded unsafe opt-in.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Sequence

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parents[1]
SHA_RE = re.compile(r"[0-9a-fA-F]{40}")
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
PERFORMANCE_PHASES = (
    "baseline_target_preparation",
    "cold_build",
    "warm_no_change",
    "one_file_incremental_update",
)
FROZEN_OUTPUT_FILES = (
    HERE / "corpus.json",
    HERE / "adjudicated.jsonl",
    HERE / "review-a.jsonl",
    HERE / "review-b.jsonl",
)
FROZEN_OUTPUT_ROOTS = (PROJECT_ROOT / "benchmarks" / "results",)


class RunnerError(RuntimeError):
    """An expected per-PR runner failure."""


@dataclass(frozen=True)
class RunConfig:
    """Resolved command-line configuration."""

    cache: Path
    output: Path
    manifest: Path
    timeout: float
    dry_run: bool
    allow_upstream_execution: bool
    use_scip: bool
    default_app_root: str
    app_roots: dict[str, str]
    candidate_root: Path = PROJECT_ROOT
    app_entries: dict[str, str] = dataclass_field(default_factory=dict)
    bootstrap_entries: dict[str, str] = dataclass_field(default_factory=dict)


def utc_now() -> str:
    """Return an auditable UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def validate_output_destination(path: Path, field: str) -> None:
    """Reject runner output aliases into frozen benchmark artifacts."""
    resolved = path.resolve(strict=False)
    if resolved in {item.resolve(strict=False) for item in FROZEN_OUTPUT_FILES} or any(
        resolved == root.resolve(strict=False)
        or resolved.is_relative_to(root.resolve(strict=False))
        for root in FROZEN_OUTPUT_ROOTS
    ):
        raise RunnerError(f"{field} cannot target a frozen benchmark artifact: {path}")


def atomic_write(path: Path, content: str) -> None:
    """Replace *path* atomically with UTF-8 text."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def command(
    args: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a command without a shell and capture its output."""
    command_args = list(args)
    process = subprocess.Popen(
        command_args,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise
    return subprocess.CompletedProcess(command_args, process.returncode, stdout, stderr)


def checked_command(args: Sequence[str], *, cwd: Path | None = None) -> str:
    """Run a command and return stdout, raising a stable runner error."""
    result = command(args, cwd=cwd)
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic output"
        raise RunnerError(f"command failed ({result.returncode}): {' '.join(args)}: {detail}")
    return result.stdout


def validate_repository(repository: str) -> None:
    if not REPOSITORY_RE.fullmatch(repository):
        raise RunnerError(f"invalid repository name: {repository!r}")


def validate_sha(value: object, name: str) -> str:
    sha = str(value or "")
    if not SHA_RE.fullmatch(sha):
        raise RunnerError(f"invalid {name}: {sha!r}")
    return sha.lower()


def cache_path(cache: Path, repository: str) -> Path:
    """Return a collision-resistant bare-repository cache path."""
    suffix = hashlib.sha256(repository.encode()).hexdigest()[:12]
    return cache / f"{repository.replace('/', '--')}-{suffix}.git"


def ensure_cache(cache: Path, repository: str, merge_sha: str) -> Path:
    """Clone once, then fetch only the immutable merge object requested."""
    validate_repository(repository)
    remote = f"https://github.com/{repository}.git"
    repository_cache = cache_path(cache, repository)
    cache.mkdir(parents=True, exist_ok=True)

    if not repository_cache.exists():
        temporary = repository_cache.with_name(
            f".{repository_cache.name}.clone-{os.getpid()}-{time.time_ns()}"
        )
        try:
            checked_command(
                ["git", "clone", "--bare", "--filter=blob:none", remote, str(temporary)]
            )
            try:
                temporary.replace(repository_cache)
            except FileExistsError:
                # Another runner completed the same immutable cache clone first.
                shutil.rmtree(temporary, ignore_errors=True)
        finally:
            shutil.rmtree(temporary, ignore_errors=True)

    actual_remote = checked_command(
        ["git", "--git-dir", str(repository_cache), "config", "--get", "remote.origin.url"]
    ).strip()
    if actual_remote != remote:
        raise RunnerError(
            f"cache remote mismatch for {repository}: expected {remote!r}, got {actual_remote!r}"
        )

    checked_command(
        [
            "git",
            "--git-dir",
            str(repository_cache),
            "fetch",
            "--no-tags",
            "--force",
            "origin",
            merge_sha,
        ]
    )
    checked_command(
        ["git", "--git-dir", str(repository_cache), "cat-file", "-e", f"{merge_sha}^{{commit}}"]
    )
    return repository_cache


def merge_parents(repository_cache: Path, merge_sha: str) -> list[str]:
    """Read parents directly from the fetched immutable merge object."""
    line = checked_command(
        [
            "git",
            "--git-dir",
            str(repository_cache),
            "rev-list",
            "--parents",
            "-n",
            "1",
            merge_sha,
        ]
    ).strip()
    fields = line.split()
    if not fields or fields[0].lower() != merge_sha:
        raise RunnerError(f"could not inspect merge commit {merge_sha}")
    return [validate_sha(parent, "parent SHA") for parent in fields[1:]]


def resolve_base_parent(parents: Sequence[str], pr_commits: Sequence[object]) -> str:
    """Resolve the sole parent which is not one of the PR's own commits."""
    normalized_parents = [validate_sha(parent, "parent SHA") for parent in parents]
    normalized_commits = {
        validate_sha(commit, "PR commit SHA") for commit in pr_commits if commit is not None
    }
    candidates = [parent for parent in normalized_parents if parent not in normalized_commits]
    if len(candidates) != 1:
        raise RunnerError(
            "base parent is unresolved: expected exactly one parent outside the PR commit set, "
            f"found {len(candidates)} of {len(normalized_parents)} parents"
        )
    return candidates[0]


def add_detached_worktree(repository_cache: Path, worktree: Path, base_sha: str) -> None:
    checked_command(
        [
            "git",
            "--git-dir",
            str(repository_cache),
            "worktree",
            "add",
            "--detach",
            str(worktree),
            base_sha,
        ]
    )


def remove_worktree(repository_cache: Path, worktree: Path) -> None:
    result = command(
        [
            "git",
            "--git-dir",
            str(repository_cache),
            "worktree",
            "remove",
            "--force",
            str(worktree),
        ]
    )
    if result.returncode:
        # The temporary directory is removed independently; prune stale metadata.
        command(["git", "--git-dir", str(repository_cache), "worktree", "prune"])


def write_local_diff(
    repository_cache: Path, base_sha: str, merge_sha: str, patch_path: Path
) -> None:
    """Generate the analyzed patch locally from the two immutable revisions."""
    patch = checked_command(
        [
            "git",
            "--git-dir",
            str(repository_cache),
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            base_sha,
            merge_sha,
            "--",
        ]
    )
    patch_path.write_text(patch, encoding="utf-8")


def safe_app_root(worktree: Path, configured_root: str) -> Path:
    """Resolve a repository-relative app root without escaping the checkout."""
    root = Path(configured_root)
    if root.is_absolute():
        raise RunnerError(f"app root must be repository-relative: {configured_root!r}")
    checkout = worktree.resolve()
    resolved = (worktree / root).resolve()
    try:
        resolved.relative_to(checkout)
    except ValueError as error:
        raise RunnerError(f"app root escapes detached worktree: {configured_root!r}") from error
    if not resolved.exists():
        raise RunnerError(f"configured app root does not exist: {configured_root!r}")
    return resolved


def normalize_endpoints(report: object) -> tuple[list[dict[str, Any]], list[str]]:
    """Explode endpoint methods into sorted, deduplicated benchmark IDs."""
    if not isinstance(report, dict):
        raise RunnerError("analyzer JSON must be an object")
    raw_endpoints = report.get("affected_endpoints")
    if not isinstance(raw_endpoints, list):
        raise RunnerError("analyzer JSON has no affected_endpoints list")

    identifiers: dict[str, str] = {}
    unresolved: list[str] = []
    for index, raw in enumerate(raw_endpoints):
        endpoint = raw.get("endpoint") if isinstance(raw, dict) else None
        if not isinstance(endpoint, dict):
            unresolved.append(f"invalid_endpoint[{index}]: missing endpoint object")
            continue
        path = endpoint.get("path")
        methods = endpoint.get("methods")
        if not isinstance(path, str) or not path.strip():
            unresolved.append(f"invalid_endpoint[{index}]: missing path")
            continue
        if isinstance(methods, str):
            methods = [methods]
        if not isinstance(methods, list) or not methods:
            unresolved.append(f"invalid_endpoint[{index}]: missing methods")
            continue
        normalized_path = path.strip()
        if not normalized_path.startswith("/"):
            normalized_path = f"/{normalized_path}"
        normalized_path = re.sub(r"/{2,}", "/", normalized_path)
        for method in methods:
            if not isinstance(method, str) or not method.strip():
                unresolved.append(f"invalid_endpoint[{index}]: invalid method {method!r}")
                continue
            normalized_method = method.strip().upper()
            if normalized_method == "WEBSOCKET":
                identifier = f"WEBSOCKET {normalized_path}"
                identifiers[identifier] = "event"
            else:
                identifier = f"HTTP {normalized_method} {normalized_path}"
                identifiers[identifier] = "http"

    return (
        [
            {"id": identifier, "kind": identifiers[identifier], "evidence": []}
            for identifier in sorted(identifiers)
        ],
        unresolved,
    )


def normalize_candidate_endpoints(  # noqa: PLR0912, PLR0915
    report: object,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Preserve every ranked candidate, choosing the strongest duplicate tier."""
    if not isinstance(report, dict):
        raise RunnerError("analyzer JSON must be an object")
    raw_candidates = report.get("candidate_endpoints")
    if not isinstance(raw_candidates, list) or not raw_candidates:
        raw_candidates = report.get("affected_endpoints")
    if not isinstance(raw_candidates, list):
        raise RunnerError("analyzer JSON has no candidate_endpoints list")

    rank = {"low": 0, "medium": 1, "high": 2}
    candidates: dict[str, dict[str, Any]] = {}
    unresolved: list[str] = []
    for index, raw in enumerate(raw_candidates):
        endpoint = raw.get("endpoint") if isinstance(raw, dict) else None
        if not isinstance(endpoint, dict):
            unresolved.append(f"invalid_candidate[{index}]: missing endpoint object")
            continue
        path = endpoint.get("path")
        methods = endpoint.get("methods")
        if not isinstance(path, str) or not path.strip():
            unresolved.append(f"invalid_candidate[{index}]: missing path")
            continue
        if isinstance(methods, str):
            methods = [methods]
        if not isinstance(methods, list) or not methods:
            unresolved.append(f"invalid_candidate[{index}]: missing methods")
            continue
        confidence = raw.get("confidence", "medium")
        if confidence not in rank:
            unresolved.append(f"invalid_candidate[{index}]: invalid confidence {confidence!r}")
            continue
        raw_evidence = raw.get("effect_evidence", [])
        if not isinstance(raw_evidence, list):
            unresolved.append(f"invalid_candidate[{index}]: effect_evidence must be a list")
            raw_evidence = []
        evidence: list[dict[str, Any]] = []
        evidence_keys: set[str] = set()
        for evidence_index, item in enumerate(raw_evidence):
            if not isinstance(item, dict):
                unresolved.append(
                    f"invalid_candidate[{index}].effect_evidence[{evidence_index}]: expected object"
                )
                continue
            evidence_key = json.dumps(item, sort_keys=True)
            if evidence_key not in evidence_keys:
                evidence.append(item)
                evidence_keys.add(evidence_key)
        normalized_path = re.sub(r"/{2,}", "/", f"/{path.strip().lstrip('/')}")
        for method in methods:
            if not isinstance(method, str) or not method.strip():
                unresolved.append(f"invalid_candidate[{index}]: invalid method {method!r}")
                continue
            normalized_method = method.strip().upper()
            identifier = (
                f"WEBSOCKET {normalized_path}"
                if normalized_method == "WEBSOCKET"
                else f"HTTP {normalized_method} {normalized_path}"
            )
            kind = "event" if normalized_method == "WEBSOCKET" else "http"
            existing = candidates.get(identifier)
            if existing is None:
                candidates[identifier] = {
                    "id": identifier,
                    "kind": kind,
                    "confidence": confidence,
                    "effect_evidence": evidence,
                }
                continue
            if rank[confidence] > rank[existing["confidence"]]:
                existing["confidence"] = confidence
            known = {json.dumps(item, sort_keys=True) for item in existing["effect_evidence"]}
            existing["effect_evidence"].extend(
                item for item in evidence if json.dumps(item, sort_keys=True) not in known
            )
    return [candidates[key] for key in sorted(candidates)], unresolved


def report_unresolved(report: dict[str, Any]) -> list[str]:
    """Preserve analyzer-reported errors and warnings in prediction coverage."""
    unresolved: list[str] = []
    for field in ("errors", "warnings"):
        values = report.get(field, [])
        if values is None:
            continue
        if not isinstance(values, list):
            values = [values]
        for value in values:
            rendered = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
            unresolved.append(f"analyzer_{field[:-1]}: {rendered}")
    return unresolved


def invoke_analyzer(
    candidate_root: Path,
    app_root: Path,
    patch_path: Path,
    timeout: float,
    *,
    secure_ast: bool,
    use_scip: bool,
    app_entry: str | None = None,
    bootstrap_entry: str | None = None,
    baseline_app_root: Path | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str], float]:
    """Invoke the frozen candidate in secure or explicitly unsafe mode."""
    args = [
        "uv",
        "run",
        "--frozen",
        "fastapi-endpoint-detector",
        "analyze",
        "--app",
        str(app_root),
        "--diff",
        str(patch_path),
        "--format",
        "json",
        "--no-cache",
    ]
    if secure_ast:
        args.append("--secure-ast")
    if app_entry is not None:
        if not secure_ast:
            raise RunnerError("app entry requires secure AST analysis")
        args.extend(["--app-entry", app_entry])
    if bootstrap_entry is not None:
        if not secure_ast:
            raise RunnerError("bootstrap entry requires secure AST analysis")
        args.extend(["--bootstrap-entry", bootstrap_entry])
    if use_scip:
        args.append("--scip")
        if baseline_app_root is not None:
            args.extend(["--baseline-app", str(baseline_app_root)])
    started = time.monotonic()
    try:
        result = command(args, cwd=candidate_root, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        elapsed = time.monotonic() - started
        raise RunnerError(f"analyzer timed out after {timeout:g} seconds") from error
    elapsed = time.monotonic() - started
    if result.returncode:
        streams = []
        if result.stdout.strip():
            streams.append(f"stdout:\n{result.stdout.strip()}")
        if result.stderr.strip():
            streams.append(f"stderr:\n{result.stderr.strip()}")
        detail = "\n".join(streams) or "no diagnostic output"
        raise RunnerError(f"analyzer failed ({result.returncode}): {detail}")
    try:
        decoded = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RunnerError(f"analyzer returned invalid JSON: {error}") from error
    endpoints, unresolved = normalize_endpoints(decoded)
    candidates, candidate_unresolved = normalize_candidate_endpoints(decoded)
    unresolved.extend(candidate_unresolved)
    unresolved.extend(report_unresolved(decoded))
    return endpoints, candidates, unresolved, elapsed


def is_python_change(entry: dict[str, Any]) -> bool:
    files = entry.get("files", [])
    return isinstance(files, list) and any(
        isinstance(item, dict)
        and isinstance(item.get("path"), str)
        and item["path"].lower().endswith(".py")
        for item in files
    )


def prediction_identity(entry: dict[str, Any]) -> tuple[str, int]:
    repository = entry.get("repository")
    pr = entry.get("number")
    if not isinstance(repository, str) or not isinstance(pr, (str, int)) or isinstance(pr, bool):
        raise RunnerError("corpus entry is missing repository or PR number")
    try:
        number = int(pr)
    except (TypeError, ValueError) as error:
        raise RunnerError(f"invalid PR number: {pr!r}") from error
    return repository, number


def _not_measured(reason: str) -> dict[str, str]:
    return {"status": "not_measured", "reason": reason}


def _measured(seconds: float) -> dict[str, str | float]:
    return {"status": "measured", "seconds": seconds}


def new_phase_telemetry() -> dict[str, dict[str, Any]]:
    """Return the complete truthful phase contract before any work is measured."""
    return {
        "baseline_target_preparation": _not_measured("source_preparation_not_completed"),
        "cold_build": _not_measured("cold_analyzer_not_completed"),
        "warm_no_change": _not_measured("backend_cache_reuse_not_implemented"),
        "one_file_incremental_update": _not_measured(
            "backend_invalidation_telemetry_not_implemented"
        ),
    }


def aggregate_phase_telemetry(
    records: Sequence[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Validate and aggregate measured PR samples without inventing values."""
    samples_by_phase: dict[str, list[float]] = {phase: [] for phase in PERFORMANCE_PHASES}
    for record in records:
        telemetry = record.get("phase_telemetry")
        if not isinstance(telemetry, dict) or set(telemetry) != set(PERFORMANCE_PHASES):
            raise RunnerError("manifest PR phase telemetry is incomplete")
        for phase in PERFORMANCE_PHASES:
            state = telemetry[phase]
            if not isinstance(state, dict):
                raise RunnerError(f"manifest PR phase {phase} must be an object")
            if state.get("status") == "measured":
                seconds = state.get("seconds")
                if (
                    set(state) != {"status", "seconds"}
                    or isinstance(seconds, bool)
                    or not isinstance(seconds, (int, float))
                    or not math.isfinite(seconds)
                    or seconds < 0
                ):
                    raise RunnerError(f"manifest PR measured phase {phase} is invalid")
                samples_by_phase[phase].append(float(seconds))
            elif state.get("status") == "not_measured":
                if (
                    set(state) != {"status", "reason"}
                    or not isinstance(state.get("reason"), str)
                    or not state["reason"].strip()
                ):
                    raise RunnerError(f"manifest PR not_measured phase {phase} is invalid")
            else:
                raise RunnerError(f"manifest PR phase {phase} status is invalid")
    return {
        phase: (
            {"status": "measured", "samples": samples}
            if (samples := samples_by_phase[phase])
            else _not_measured("no_measured_pr_samples")
        )
        for phase in PERFORMANCE_PHASES
    }


def unresolved_prediction(
    repository: str, pr: int, candidate_id: str, reason: str
) -> dict[str, Any]:
    return {
        "schema_version": 3,
        "repository": repository,
        "pr": pr,
        "candidate": candidate_id,
        "adapter": "fastapi-adapter-v1",
        "status": "unresolved",
        "affected_entrypoints": [],
        "candidate_entrypoints": [],
        "unresolved": [reason],
        "timing_seconds": {},
    }


def process_entry(  # noqa: PLR0915
    entry: dict[str, Any], config: RunConfig, candidate_id: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Produce exactly one prediction and one manifest record for a corpus PR."""
    repository, pr = prediction_identity(entry)
    started = time.monotonic()
    phase_started = started
    timings: dict[str, float] = {}
    phase_telemetry = new_phase_telemetry()
    merge_sha: str | None = None
    base_sha: str | None = None
    configured_root = config.app_roots.get(repository, config.default_app_root)
    configured_entry = config.app_entries.get(repository)
    configured_bootstrap = config.bootstrap_entries.get(repository)
    manifest_record: dict[str, Any] = {
        "repository": repository,
        "pr": pr,
        "configured_app_root": configured_root,
        "configured_app_entry": configured_entry,
        "configured_bootstrap_entry": configured_bootstrap,
        "merge_sha": None,
        "base_sha": None,
        "status": "unresolved",
        "timing_seconds": timings,
        "phase_telemetry": phase_telemetry,
    }
    merge_data = entry.get("mergeCommit")
    if isinstance(merge_data, dict):
        raw_merge_sha = merge_data.get("oid")
        if isinstance(raw_merge_sha, str) and SHA_RE.fullmatch(raw_merge_sha):
            merge_sha = raw_merge_sha.lower()
            manifest_record["merge_sha"] = merge_sha

    if not is_python_change(entry):
        elapsed = time.monotonic() - started
        timings["total"] = elapsed
        manifest_record["reason"] = "non_python_change"
        return (
            unresolved_prediction(repository, pr, candidate_id, "non_python_change"),
            manifest_record,
        )

    try:
        if not isinstance(merge_data, dict):
            raise RunnerError("corpus entry has no mergeCommit object")
        merge_sha = validate_sha(merge_data.get("oid"), "merge SHA")
        manifest_record["merge_sha"] = merge_sha
        if config.dry_run:
            raise RunnerError("dry_run: analysis was not executed")

        repository_cache = ensure_cache(config.cache, repository, merge_sha)
        timings["cache_fetch"] = time.monotonic() - phase_started
        phase_started = time.monotonic()

        parents = merge_parents(repository_cache, merge_sha)
        commits = entry.get("commits", [])
        if not isinstance(commits, list):
            raise RunnerError("corpus entry commits must be a list")
        base_sha = resolve_base_parent(parents, commits)
        manifest_record["base_sha"] = base_sha
        timings["parent_resolution"] = time.monotonic() - phase_started
        phase_started = time.monotonic()

        preparation_started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="current-analyzer-") as temporary_name:
            temporary = Path(temporary_name)
            worktree = temporary / "target"
            baseline_worktree = temporary / "baseline"
            patch_path = temporary / "change.diff"
            worktree_added = False
            baseline_worktree_added = False
            try:
                # Changed/added line numbers and endpoint discovery are target-side.
                # Baseline analysis, when added, must use a separate explicit snapshot.
                worktree_added = True
                add_detached_worktree(repository_cache, worktree, merge_sha)
                app_root = safe_app_root(worktree, configured_root)
                baseline_app_root: Path | None = None
                if config.use_scip:
                    baseline_worktree_added = True
                    add_detached_worktree(repository_cache, baseline_worktree, base_sha)
                    baseline_app_root = safe_app_root(baseline_worktree, configured_root)
                timings["worktree"] = time.monotonic() - phase_started
                phase_started = time.monotonic()

                write_local_diff(repository_cache, base_sha, merge_sha, patch_path)
                timings["diff"] = time.monotonic() - phase_started
                preparation_seconds = time.monotonic() - preparation_started
                timings["baseline_target_preparation"] = preparation_seconds
                phase_telemetry["baseline_target_preparation"] = _measured(preparation_seconds)

                endpoints, candidates, unresolved, analyzer_seconds = invoke_analyzer(
                    config.candidate_root,
                    app_root,
                    patch_path,
                    config.timeout,
                    secure_ast=not config.allow_upstream_execution,
                    use_scip=config.use_scip,
                    app_entry=configured_entry,
                    bootstrap_entry=configured_bootstrap,
                    baseline_app_root=baseline_app_root,
                )
                timings["analyzer"] = analyzer_seconds
                phase_telemetry["cold_build"] = _measured(analyzer_seconds)
            finally:
                if baseline_worktree_added:
                    remove_worktree(repository_cache, baseline_worktree)
                if worktree_added:
                    remove_worktree(repository_cache, worktree)

        elapsed = time.monotonic() - started
        timings["total"] = elapsed
        manifest_record["status"] = "completed" if not unresolved else "completed_with_unresolved"
        manifest_record["candidate_endpoint_count"] = len(candidates)
        manifest_record["candidate_confidence_counts"] = {
            confidence: sum(1 for candidate in candidates if candidate["confidence"] == confidence)
            for confidence in ("high", "medium", "low")
        }
        manifest_record["effect_evidence_count"] = sum(
            len(candidate["effect_evidence"]) for candidate in candidates
        )
        prediction = {
            "repository": repository,
            "pr": pr,
            "candidate": candidate_id,
            "adapter": "fastapi-adapter-v1",
            "schema_version": 3,
            "status": "completed" if not unresolved else "partial",
            "affected_entrypoints": endpoints,
            "candidate_entrypoints": candidates,
            "unresolved": unresolved,
            "timing_seconds": {"cold_no_cache_analyzer_wall": timings["analyzer"]},
        }
        return prediction, manifest_record
    except (RunnerError, OSError) as error:
        elapsed = time.monotonic() - started
        timings["total"] = elapsed
        reason = str(error)
        manifest_record["merge_sha"] = merge_sha
        manifest_record["base_sha"] = base_sha
        manifest_record["reason"] = reason
        return unresolved_prediction(repository, pr, candidate_id, reason), manifest_record


def parse_app_roots(values: Sequence[str]) -> dict[str, str]:
    roots: dict[str, str] = {}
    for value in values:
        repository, separator, root = value.partition("=")
        if not separator or not root:
            raise argparse.ArgumentTypeError(
                f"invalid --app-root {value!r}; expected REPOSITORY=RELATIVE_PATH"
            )
        validate_repository(repository)
        if repository in roots:
            raise argparse.ArgumentTypeError(f"duplicate --app-root for {repository}")
        roots[repository] = root
    return roots


def parse_app_entries(values: Sequence[str], option_name: str = "--app-entry") -> dict[str, str]:
    entries: dict[str, str] = {}
    for value in values:
        repository, separator, entry = value.partition("=")
        if not separator or not entry:
            raise argparse.ArgumentTypeError(
                f"invalid {option_name} {value!r}; expected REPOSITORY=MODULE:SYMBOL"
            )
        validate_repository(repository)
        parts = entry.split(":")
        if (
            len(parts) != 2
            or any(not part.isidentifier() for part in parts[0].split("."))
            or not parts[1].isidentifier()
        ):
            raise argparse.ArgumentTypeError(
                f"invalid {option_name} {value!r}; expected REPOSITORY=MODULE:SYMBOL"
            )
        if repository in entries:
            raise argparse.ArgumentTypeError(f"duplicate {option_name} for {repository}")
        entries[repository] = entry
    return entries


def select_entries(
    corpus: dict[str, Any], repositories: Sequence[str], prs: Sequence[int], limit: int | None
) -> list[dict[str, Any]]:
    entries = corpus.get("entries")
    if not isinstance(entries, list):
        raise RunnerError("corpus JSON has no entries list")
    repository_filter = set(repositories)
    pr_filter = set(prs)
    selected: list[dict[str, Any]] = []
    if limit == 0:
        return selected
    seen: set[tuple[str, int]] = set()
    for raw_entry in entries:
        if not isinstance(raw_entry, dict):
            raise RunnerError("corpus entry must be a JSON object")
        identity = prediction_identity(raw_entry)
        if repository_filter and identity[0] not in repository_filter:
            continue
        if pr_filter and identity[1] not in pr_filter:
            continue
        if identity in seen:
            raise RunnerError(f"duplicate selected corpus PR: {identity[0]}#{identity[1]}")
        seen.add(identity)
        selected.append(raw_entry)
        if limit is not None and len(selected) >= limit:
            break
    return selected


def candidate_metadata(
    candidate_root: Path,
    roots: dict[str, str],
    default_root: str,
    allow_upstream_execution: bool,
    use_scip: bool,
    app_entries: dict[str, str] | None = None,
    bootstrap_entries: dict[str, str] | None = None,
) -> dict[str, Any]:
    try:
        version = importlib.metadata.version("fastapi-endpoint-detector")
    except importlib.metadata.PackageNotFoundError:
        pyproject = candidate_root / "pyproject.toml"
        try:
            match = re.search(
                r'^version\s*=\s*["\']([^"\']+)["\']',
                pyproject.read_text(encoding="utf-8"),
                flags=re.MULTILINE,
            )
            version = match.group(1) if match else "unknown"
        except OSError:
            version = "unknown"
    git_result = command(["git", "rev-parse", "HEAD"], cwd=candidate_root)
    git_sha = git_result.stdout.strip() if git_result.returncode == 0 else "unknown"
    status_result = command(["git", "status", "--porcelain"], cwd=candidate_root)
    dirty = bool(status_result.stdout.strip()) if status_result.returncode == 0 else None
    dirty_sha256: str | None = None
    if dirty:
        digest = hashlib.sha256(status_result.stdout.encode())
        diff_result = command(["git", "diff", "--binary", "HEAD"], cwd=candidate_root)
        digest.update(diff_result.stdout.encode())
        untracked = command(
            ["git", "ls-files", "--others", "--exclude-standard", "-z"],
            cwd=candidate_root,
        )
        for relative in sorted(path for path in untracked.stdout.split("\0") if path):
            path_bytes = relative.encode()
            digest.update(len(path_bytes).to_bytes(8, "big"))
            digest.update(path_bytes)
            candidate_file = candidate_root / relative
            content = candidate_file.read_bytes() if candidate_file.is_file() else b""
            digest.update(len(content).to_bytes(8, "big"))
            digest.update(content)
        dirty_sha256 = digest.hexdigest()
    lock_path = candidate_root / "uv.lock"
    lock_sha256 = hashlib.sha256(lock_path.read_bytes()).hexdigest() if lock_path.exists() else None
    uv_result = command(["uv", "--version"], cwd=candidate_root)
    uv_version = uv_result.stdout.strip() if uv_result.returncode == 0 else "unknown"
    candidate_config = json.dumps(
        {
            "allow_upstream_execution": allow_upstream_execution,
            "use_scip": use_scip,
            "root_config": {"default": default_root, "repositories": roots},
            "app_entry_config": dict(sorted((app_entries or {}).items())),
            "bootstrap_entry_config": dict(sorted((bootstrap_entries or {}).items())),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    config_hash = hashlib.sha256(candidate_config.encode()).hexdigest()[:12]
    source_id = git_sha[:12]
    if dirty_sha256 is not None:
        source_id = f"{source_id}+dirty.{dirty_sha256[:12]}"
    candidate_id = f"fastapi-endpoint-detector/{version}/{source_id}/{config_hash}"
    return {
        "id": candidate_id,
        "name": "fastapi-endpoint-detector",
        "version": version,
        "adapter": "fastapi-adapter-v1",
        "git_sha": git_sha,
        "config_hash": config_hash,
        "dirty": dirty,
        "dirty_sha256": dirty_sha256,
        "uv_lock_sha256": lock_sha256,
        "uv_version": uv_version,
        "command": "uv run --frozen fastapi-endpoint-detector analyze --no-cache",
        "performance_protocol": {
            "id": "cold-no-cache-analyzer-wall-v1",
            "cache_enabled": False,
            "incremental_valid": False,
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=HERE / "corpus.json")
    parser.add_argument(
        "--cache", type=Path, default=Path.home() / ".cache" / "current-analyzer-corpus"
    )
    parser.add_argument("--output", type=Path, default=HERE / "current-predictions.jsonl")
    parser.add_argument("--manifest", type=Path, default=HERE / "current-manifest.json")
    parser.add_argument("--timeout", type=float, default=600.0)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--repository", action="append", default=[])
    parser.add_argument("--pr", type=int, action="append", default=[])
    parser.add_argument(
        "--app-root",
        action="append",
        default=[],
        metavar="REPOSITORY=RELATIVE_PATH",
        help="repository-relative analyzer root (repeatable)",
    )
    parser.add_argument("--default-app-root", default=".")
    parser.add_argument(
        "--app-entry",
        action="append",
        default=[],
        metavar="REPOSITORY=MODULE:SYMBOL",
        help="exact secure-AST app object/factory entry (repeatable)",
    )
    parser.add_argument(
        "--bootstrap-entry",
        action="append",
        default=[],
        metavar="REPOSITORY=MODULE:FUNCTION",
        help="exact secure-AST bootstrap function entry (repeatable)",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--scip",
        action="store_true",
        help="Run the opt-in SCIP backend instead of mypy.",
    )
    parser.add_argument(
        "--allow-upstream-execution",
        action="store_true",
        help=(
            "UNSAFE: allow the current analyzer to import/execute code from the detached "
            "upstream checkout"
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if args.limit is not None and args.limit < 0:
        parser.error("--limit must not be negative")
    try:
        artifact_paths = {
            args.corpus.resolve(),
            args.output.resolve(),
            args.manifest.resolve(),
        }
        if len(artifact_paths) != 3:
            raise RunnerError("--corpus, --output, and --manifest must be distinct paths")
        validate_output_destination(args.output, "--output")
        validate_output_destination(args.manifest, "--manifest")
        app_roots = parse_app_roots(args.app_root)
        app_entries = parse_app_entries(args.app_entry)
        bootstrap_entries = parse_app_entries(args.bootstrap_entry, "--bootstrap-entry")
        if args.allow_upstream_execution and (app_entries or bootstrap_entries):
            raise RunnerError(
                "secure entry configuration cannot be used with --allow-upstream-execution"
            )
        corpus_bytes = args.corpus.read_bytes()
        corpus = json.loads(corpus_bytes)
        if not isinstance(corpus, dict):
            raise RunnerError("corpus JSON must be an object")
        entries = select_entries(corpus, args.repository, args.pr, args.limit)
    except (argparse.ArgumentTypeError, RunnerError, OSError, json.JSONDecodeError) as error:
        parser.error(str(error))

    config = RunConfig(
        cache=args.cache.resolve(),
        output=args.output.resolve(),
        manifest=args.manifest.resolve(),
        timeout=args.timeout,
        dry_run=args.dry_run,
        allow_upstream_execution=args.allow_upstream_execution,
        use_scip=args.scip,
        default_app_root=args.default_app_root,
        app_roots=app_roots,
        app_entries=app_entries,
        bootstrap_entries=bootstrap_entries,
    )
    candidate = candidate_metadata(
        config.candidate_root,
        app_roots,
        args.default_app_root,
        args.allow_upstream_execution,
        args.scip,
        app_entries,
        bootstrap_entries,
    )
    started_wall = utc_now()
    started = time.monotonic()
    predictions: list[dict[str, Any]] = []
    pr_manifest: list[dict[str, Any]] = []
    for entry in entries:
        prediction, record = process_entry(entry, config, candidate["id"])
        predictions.append(prediction)
        pr_manifest.append(record)

    identities = [(item["repository"], item["pr"]) for item in predictions]
    if len(identities) != len(set(identities)) or len(predictions) != len(entries):
        raise AssertionError("runner did not produce exactly one unique prediction per selected PR")

    jsonl = "".join(json.dumps(item, sort_keys=True) + "\n" for item in predictions)
    prediction_sha256 = hashlib.sha256(jsonl.encode()).hexdigest()
    manifest = {
        "schema_version": 4,
        "prediction_schema_version": 3,
        "created_at": utc_now(),
        "candidate": candidate,
        "git": {"candidate_sha": candidate["git_sha"]},
        "prediction_output": {
            "path": str(config.output),
            "sha256": prediction_sha256,
            "records": len(predictions),
        },
        "selected_keys": [
            {"repository": item["repository"], "pr": item["pr"]} for item in predictions
        ],
        "python": sys.version,
        "platform": platform.platform(),
        "corpus": {
            "path": str(args.corpus.resolve()),
            "sha256": hashlib.sha256(corpus_bytes).hexdigest(),
        },
        "root_config": {
            "default": args.default_app_root,
            "repositories": dict(sorted(app_roots.items())),
        },
        "app_entry_config": dict(sorted(app_entries.items())),
        "bootstrap_entry_config": dict(sorted(bootstrap_entries.items())),
        "configuration": {
            "cache": str(config.cache),
            "output": str(config.output),
            "manifest": str(config.manifest),
            "timeout_seconds": config.timeout,
            "dry_run": config.dry_run,
            "allow_upstream_execution": config.allow_upstream_execution,
            "use_scip": config.use_scip,
            "filters": {
                "limit": args.limit,
                "repositories": args.repository,
                "prs": args.pr,
            },
        },
        "selection_count": len(entries),
        "prs": pr_manifest,
        "timing": {
            "started_at": started_wall,
            "finished_at": utc_now(),
            "total_seconds": time.monotonic() - started,
            "protocol": "phase-telemetry-v1",
            "incremental_valid": False,
            "phases": aggregate_phase_telemetry(pr_manifest),
            "resources": {
                "peak_rss_bytes": _not_measured("process_tree_rss_not_sampled"),
                "cache_size_bytes": _not_measured("backend_cache_size_not_measured"),
            },
        },
    }
    atomic_write(config.output, jsonl)
    atomic_write(config.manifest, json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(f"Wrote {len(predictions)} predictions to {config.output}")
    print(f"Wrote manifest to {config.manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
