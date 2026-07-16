#!/usr/bin/env python3
"""Preregister and collect the bounded 50x50 OSS PR corpus without source execution."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import signal
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from itertools import islice
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, NoReturn, TypeGuard

if TYPE_CHECKING:
    from collections.abc import Iterator
    from types import FrameType

_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_MAX_LOCAL_BYTES: Final = 64 * 1024 * 1024
_MANIFEST_ID: Final = "oss-expansion-50x50-v2"
_LOCK_ID: Final = "oss-expansion-50x50-lock-v2"
_SELECTION: Final = "merged_at descending, then pull-request number descending"
_V1_MANIFEST = "benchmarks/real_world/expansion/projects-50-v1.json"
_V1_LONGLIST = "benchmarks/real_world/expansion/longlist-60-v1.json"
_V1_LOCK = "benchmarks/real_world/expansion/pr-lock-100-v1.json"
_V1_COLLECTOR = "benchmarks/real_world/expansion_protocol.py"
_V1_SENTINELS: Final = {
    _V1_MANIFEST: "194afecc671535639cf51b4b98e6fbe2d36a6159c882de1ae2bd3a4df1a28fe0",
    _V1_LONGLIST: "271011f84984972c04cf3984a3e608399f3663c9ce493be9a12817968e63abe1",
    _V1_LOCK: "6df3dc426888e0c8a97a079dbac8ca48ee421fa8ecd1ce63ddd7bf825a61291f",
    _V1_COLLECTOR: "633200e3c540ac7b38210f02eeac2f2b9db5814bc3848a5c2ec5ab439fa887a3",
}


class CorpusV2Error(ValueError):
    """Raised when v2 provenance, completeness, or safety cannot be proved."""


class DenseShardError(CorpusV2Error):
    """Raised when one GitHub search interval exceeds the complete-result ceiling."""


@dataclass(frozen=True, order=True)
class Candidate:
    """One merged PR identity observed in a complete merged-time shard."""

    merged_at: datetime
    number: int
    html_url: str


@dataclass(frozen=True)
class CompleteShard:
    """A half-open merged-time interval fully enumerated in one GitHub response."""

    start: datetime
    end: datetime
    total_count: int
    candidates: tuple[Candidate, ...]
    response_hash: str


@dataclass
class NetworkBudget:
    """Strict aggregate request, byte, diff, and wall-clock budgets."""

    max_requests: int
    max_response_bytes: int
    max_diff_bytes: int
    max_total_diff_bytes: int
    max_wall_seconds: int
    started: float = field(default_factory=time.monotonic)
    requests: int = 0
    response_bytes: int = 0
    diff_bytes: int = 0

    def remaining_wall_seconds(self) -> float:
        remaining = self.max_wall_seconds - (time.monotonic() - self.started)
        if remaining <= 0:
            raise CorpusV2Error("collection exceeded wall-clock budget")
        return remaining

    def check_wall(self) -> None:
        self.remaining_wall_seconds()

    def reserve(self) -> None:
        self.check_wall()
        if (
            self.requests >= self.max_requests
            or self.response_bytes > self.max_response_bytes
            or self.diff_bytes > self.max_total_diff_bytes
        ):
            raise CorpusV2Error("collection exhausted a persisted aggregate budget")
        self.requests += 1

    def consume(self, size: int, *, diff: bool = False) -> None:
        if size < 0:
            raise CorpusV2Error("negative response size")
        response_total = self.response_bytes + size
        diff_total = self.diff_bytes + size if diff else self.diff_bytes
        if response_total > self.max_response_bytes:
            raise CorpusV2Error("collection exceeded response-byte budget")
        if diff_total > self.max_total_diff_bytes:
            raise CorpusV2Error("collection exceeded total diff-byte budget")
        self.response_bytes = response_total
        self.diff_bytes = diff_total
        self.check_wall()


def _wall_timeout(_signum: int, _frame: FrameType | None) -> NoReturn:
    raise TimeoutError("collection exceeded wall-clock budget during blocking I/O")


@contextmanager
def _wall_deadline(budget: NetworkBudget) -> Iterator[None]:
    """Interrupt blocking I/O at the aggregate deadline or fail closed."""
    if threading.current_thread() is not threading.main_thread() or not hasattr(
        signal, "setitimer"
    ):
        raise CorpusV2Error("exact wall deadline requires POSIX main-thread collection")
    remaining = budget.remaining_wall_seconds()
    previous_handler = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, _wall_timeout)
    started = time.monotonic()
    previous_delay, previous_interval = signal.setitimer(signal.ITIMER_REAL, remaining)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_delay > 0:
            elapsed = time.monotonic() - started
            signal.setitimer(
                signal.ITIMER_REAL,
                max(0.000001, previous_delay - elapsed),
                previous_interval,
            )


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl


class _SafeDiffRedirects(urllib.request.HTTPRedirectHandler):
    """Follow only the exact credential-free redirect for one selected PR diff."""

    def __init__(self, repository: str, number: int) -> None:
        self._repository = repository
        self._number = number

    def _validate(self, url: str) -> None:
        parsed = urllib.parse.urlsplit(url)
        canonical = f"/{self._repository}/pull/{self._number}.diff"
        patch = f"/raw/{self._repository}/pull/{self._number}.diff"
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
            or parsed.query
            or parsed.fragment
            or (parsed.hostname, parsed.path)
            not in {("github.com", canonical), ("patch-diff.githubusercontent.com", patch)}
        ):
            raise CorpusV2Error("diff redirect did not preserve exact PR identity")

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request:
        del fp, code, msg, headers
        self._validate(newurl)
        safe_headers = {
            key: value
            for key, value in req.header_items()
            if key.casefold() not in {"authorization", "cookie", "host", "proxy-authorization"}
        }
        return urllib.request.Request(newurl, headers=safe_headers, method="GET")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CorpusV2Error(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _strict_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise CorpusV2Error(
            f"invalid {label} keys; missing={sorted(expected - set(value))}, "
            f"unknown={sorted(set(value) - expected)}"
        )


def _is_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _parse_utc(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise CorpusV2Error(f"{label} must be a canonical UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise CorpusV2Error(f"invalid {label}") from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise CorpusV2Error(f"{label} must use UTC")
    return parsed


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _json_hash(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _read_bounded(path: Path, limit: int = _MAX_LOCAL_BYTES) -> bytes:
    with path.open("rb") as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise CorpusV2Error(f"{path.name} exceeds its local byte limit")
    return raw


def _load_json(path: Path, *, limit: int = _MAX_LOCAL_BYTES) -> tuple[dict[str, Any], bytes]:
    raw = _read_bounded(path, limit)
    try:
        payload = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CorpusV2Error(f"invalid JSON in {path}") from exc
    if not isinstance(payload, dict):
        raise CorpusV2Error(f"{path} root must be an object")
    return payload, raw


def validate_v1_sentinels(root: Path = Path()) -> None:
    """Prove the additive v2 phase did not mutate any v1 frozen byte stream."""
    for relative, expected in _V1_SENTINELS.items():
        actual = hashlib.sha256(_read_bounded(root / relative)).hexdigest()
        if actual != expected:
            raise CorpusV2Error(f"v1 byte sentinel changed: {relative}")


def load_manifest(path: Path) -> tuple[dict[str, Any], str]:
    payload, raw = _load_json(path)
    validate_manifest(payload)
    return payload, f"sha256:{hashlib.sha256(raw).hexdigest()}"


def load_preregistration(path: Path, manifest_hash: str) -> dict[str, Any]:
    """Validate the independent pre-live-collection checksum profile."""
    payload, _raw = _load_json(path)
    _strict_keys(
        payload,
        {
            "schema_version",
            "id",
            "manifest_hash",
            "collector_hash",
            "v1_sentinels",
            "live_lock_status",
            "lock_hash",
        },
        "preregistration",
    )
    if payload["schema_version"] != 2 or payload["id"] != (
        "oss-expansion-50x50-preregistration-v2"
    ):
        raise CorpusV2Error("unsupported preregistration profile")
    if payload["manifest_hash"] != manifest_hash or payload["collector_hash"] != collector_hash():
        raise CorpusV2Error("preregistration provenance mismatch")
    expected_v1 = {
        "manifest_hash": f"sha256:{_V1_SENTINELS[_V1_MANIFEST]}",
        "longlist_hash": f"sha256:{_V1_SENTINELS[_V1_LONGLIST]}",
        "lock_hash": f"sha256:{_V1_SENTINELS[_V1_LOCK]}",
        "collector_hash": f"sha256:{_V1_SENTINELS[_V1_COLLECTOR]}",
    }
    if payload["v1_sentinels"] != expected_v1:
        raise CorpusV2Error("preregistration v1 sentinels changed")
    if payload["live_lock_status"] != "not_collected" or payload["lock_hash"] is not None:
        raise CorpusV2Error("preregistration must not claim a live lock")
    return payload


def _v1_population() -> list[tuple[str, str, str]]:
    path = Path(__file__).resolve().parents[2] / _V1_MANIFEST
    raw = _read_bounded(path)
    if hashlib.sha256(raw).hexdigest() != _V1_SENTINELS[_V1_MANIFEST]:
        raise CorpusV2Error("v1 population sentinel changed")
    try:
        payload = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CorpusV2Error("v1 population manifest is invalid") from exc
    projects = payload.get("projects") if isinstance(payload, dict) else None
    if not isinstance(projects, list):
        raise CorpusV2Error("v1 population projects are unavailable")
    result: list[tuple[str, str, str]] = []
    for project in projects:
        if not isinstance(project, dict):
            raise CorpusV2Error("v1 population project is invalid")
        repository = project.get("repository")
        partition = project.get("partition")
        survey_commit = project.get("survey_commit")
        if not (
            isinstance(repository, str)
            and isinstance(partition, str)
            and isinstance(survey_commit, str)
        ):
            raise CorpusV2Error("v1 population identity is invalid")
        result.append((repository, partition, survey_commit))
    return result


def validate_manifest(payload: dict[str, Any]) -> None:  # noqa: PLR0912, PLR0915
    """Validate fixed v2 policy; the document cannot weaken its own gates."""
    _strict_keys(
        payload,
        {
            "schema_version",
            "id",
            "frozen_at",
            "source_population",
            "policy",
            "sharding",
            "bounds",
            "terminal_project_statuses",
            "projects",
        },
        "manifest",
    )
    if payload["schema_version"] != 2 or isinstance(payload["schema_version"], bool):
        raise CorpusV2Error("unsupported manifest schema_version")
    if payload["id"] != _MANIFEST_ID:
        raise CorpusV2Error("unsupported manifest id")
    frozen_at = _parse_utc(payload["frozen_at"], "frozen_at")
    source = payload["source_population"]
    if not isinstance(source, dict):
        raise CorpusV2Error("source_population must be an object")
    _strict_keys(source, {"manifest_id", "manifest_hash", "longlist_hash"}, "source")
    expected_source = {
        "manifest_id": "oss-expansion-50-v1",
        "manifest_hash": f"sha256:{_V1_SENTINELS[_V1_MANIFEST]}",
        "longlist_hash": f"sha256:{_V1_SENTINELS[_V1_LONGLIST]}",
    }
    if source != expected_source:
        raise CorpusV2Error("source population provenance changed")
    policy = payload["policy"]
    if not isinstance(policy, dict):
        raise CorpusV2Error("policy must be an object")
    expected_policy = {
        "project_count": 50,
        "target_prs_per_project": 50,
        "merged_before": "2026-06-15T00:00:00Z",
        "selection": _SELECTION,
        "content_filtering_allowed": False,
        "not_evaluable_retained": True,
        "runtime_execution_allowed": False,
        "baseline_rule": "first_parent_of_merge_commit",
        "target_rule": "head_sha",
        "diff_rule": "github_pull_diff_media_exact_bytes",
        "underfill_rule": (
            "only after complete merged-time coverage reaches repository creation time"
        ),
        "unavailable_rule": (
            "budget, API, redirect, dense-shard, identity, or diff failure is terminal "
            "unavailable; never underfill"
        ),
        "draft_rule": "merged PRs are eligible regardless of prior draft history",
        "merge_queue_rule": (
            "merge-queue PRs are eligible when immutable merge identity and diff evidence exist"
        ),
        "bot_rule": "bot-authored PRs are eligible",
        "revert_rule": "revert PRs are eligible",
        "repository_identity_rule": (
            "renamed, transferred, deleted, inaccessible, or redirecting repositories are "
            "terminal unavailable; never substitute"
        ),
    }
    if policy != expected_policy:
        raise CorpusV2Error("frozen policy changed")
    cutoff = _parse_utc(policy["merged_before"], "merged_before")
    if cutoff >= frozen_at:
        raise CorpusV2Error("cutoff must precede protocol freeze")
    expected_sharding = {
        "field": "merged_at",
        "direction": "newest_first",
        "initial_window_days": 30,
        "maximum_results_per_complete_shard": 100,
        "split_dense_shards": True,
        "contiguous_from_cutoff": True,
        "overlap_deduplicated_by_pr_number": True,
    }
    if payload["sharding"] != expected_sharding:
        raise CorpusV2Error("sharding policy changed")
    bounds = payload["bounds"]
    expected_bound_keys = {
        "max_requests",
        "max_response_bytes",
        "max_diff_bytes",
        "max_total_diff_bytes",
        "max_wall_seconds",
        "request_timeout_seconds",
        "max_rate_limit_wait_seconds",
        "max_retries_per_request",
        "max_search_pages_per_shard",
        "max_shards_per_project",
        "max_api_response_bytes",
        "max_checkpoint_bytes",
        "max_lock_bytes",
        "max_checkpoint_files",
        "max_candidates_per_project",
        "max_diagnostics_per_project",
        "max_diagnostic_chars",
    }
    if not isinstance(bounds, dict):
        raise CorpusV2Error("bounds must be an object")
    _strict_keys(bounds, expected_bound_keys, "bounds")
    if any(not _is_int(value) or value <= 0 for value in bounds.values()):
        raise CorpusV2Error("bounds must be positive non-boolean integers")
    if bounds["max_diff_bytes"] > bounds["max_total_diff_bytes"]:
        raise CorpusV2Error("one-diff bound exceeds aggregate diff bound")
    if bounds["max_search_pages_per_shard"] != 1:
        raise CorpusV2Error("complete shards must fit one immutable search response")
    if bounds["max_checkpoint_files"] != 100:
        raise CorpusV2Error("checkpoint file bound must equal two files per project")
    if payload["terminal_project_statuses"] != ["complete", "underfilled", "unavailable"]:
        raise CorpusV2Error("terminal project statuses changed")
    projects = payload["projects"]
    if not isinstance(projects, list) or len(projects) != 50:
        raise CorpusV2Error("manifest must contain exactly 50 projects")
    names: set[str] = set()
    partitions = {"verification": 0, "stress": 0}
    for project in projects:
        if not isinstance(project, dict):
            raise CorpusV2Error("project must be an object")
        _strict_keys(project, {"repository", "partition", "survey_commit"}, "project")
        repository = project["repository"]
        normalized = repository.casefold() if isinstance(repository, str) else ""
        if (
            not isinstance(repository, str)
            or _REPOSITORY.fullmatch(repository) is None
            or normalized in names
        ):
            raise CorpusV2Error(f"invalid or duplicate repository: {repository!r}")
        names.add(normalized)
        if project["partition"] not in partitions:
            raise CorpusV2Error(f"invalid partition for {repository}")
        partitions[project["partition"]] += 1
        if _SHA.fullmatch(str(project["survey_commit"])) is None:
            raise CorpusV2Error(f"invalid survey commit for {repository}")
    if partitions != {"verification": 40, "stress": 10}:
        raise CorpusV2Error("partition counts changed")
    actual_population = [
        (project["repository"], project["partition"], project["survey_commit"])
        for project in projects
    ]
    if actual_population != _v1_population():
        raise CorpusV2Error("v2 projects must exactly match the frozen v1 population")


def select_from_complete_shards(
    shards: list[CompleteShard],
    *,
    cutoff: datetime,
    target: int,
    repository_created_at: datetime,
) -> tuple[str, list[Candidate], datetime]:
    """Select only after proving contiguous newest-first merged-time coverage."""
    if target <= 0 or not shards:
        raise CorpusV2Error("selection requires a positive target and complete shards")
    expected_end = cutoff
    by_number: dict[int, Candidate] = {}
    coverage_start = cutoff
    for shard in shards:
        if shard.end != expected_end or shard.start >= shard.end:
            raise CorpusV2Error("shards are not contiguous newest-first")
        if shard.total_count != len(shard.candidates) or shard.total_count > 100:
            raise CorpusV2Error("shard completeness count is invalid")
        if _DIGEST.fullmatch(shard.response_hash) is None:
            raise CorpusV2Error("shard response evidence hash is invalid")
        numbers: set[int] = set()
        for candidate in shard.candidates:
            if candidate.number <= 0 or candidate.number in numbers:
                raise CorpusV2Error("duplicate or invalid PR number inside shard")
            numbers.add(candidate.number)
            if not (shard.start <= candidate.merged_at < shard.end):
                raise CorpusV2Error("candidate lies outside its complete shard")
            existing = by_number.get(candidate.number)
            if existing is not None and existing != candidate:
                raise CorpusV2Error("cross-shard PR identity changed")
            by_number[candidate.number] = candidate
        coverage_start = shard.start
        expected_end = shard.start
        ordered = sorted(
            by_number.values(), key=lambda item: (item.merged_at, item.number), reverse=True
        )
        if len(ordered) >= target:
            return "complete", ordered[:target], coverage_start
    if coverage_start <= repository_created_at:
        ordered = sorted(
            by_number.values(), key=lambda item: (item.merged_at, item.number), reverse=True
        )
        return "underfilled", ordered, coverage_start
    raise CorpusV2Error(
        "coverage ended before target or repository creation; status is unavailable"
    )


def _record_keys() -> set[str]:
    return {
        "rank",
        "pr",
        "merged_at",
        "html_url",
        "base_sha",
        "head_sha",
        "merge_commit_sha",
        "merge_parent_shas",
        "baseline_sha",
        "target_sha",
        "baseline_rule",
        "target_rule",
        "pull_response_sha256",
        "commit_response_sha256",
        "diff_sha256",
        "diff_bytes",
        "diff_final_url",
        "diff_content_type",
        "review_a",
        "review_b",
        "adjudication",
        "pr_type",
    }


def _shard_payload(shard: CompleteShard) -> dict[str, Any]:
    return {
        "start": _utc_text(shard.start),
        "end": _utc_text(shard.end),
        "total_count": shard.total_count,
        "response_hash": shard.response_hash,
        "candidates": [
            {
                "merged_at": _utc_text(candidate.merged_at),
                "pr": candidate.number,
                "html_url": candidate.html_url,
            }
            for candidate in sorted(
                shard.candidates,
                key=lambda item: (item.merged_at, item.number),
                reverse=True,
            )
        ],
    }


def _shards_from_payload(
    repository: str, rows: object, *, maximum: int, candidate_maximum: int
) -> list[CompleteShard]:
    if not isinstance(rows, list) or len(rows) > maximum:
        raise CorpusV2Error("selection evidence exceeds shard bound")
    shards: list[CompleteShard] = []
    candidate_count = 0
    for row in rows:
        if not isinstance(row, dict):
            raise CorpusV2Error("selection shard must be an object")
        _strict_keys(
            row,
            {"start", "end", "total_count", "response_hash", "candidates"},
            "selection shard",
        )
        candidates = row["candidates"]
        if not _is_int(row["total_count"]) or row["total_count"] < 0:
            raise CorpusV2Error("selection shard total is invalid")
        if not isinstance(row["response_hash"], str):
            raise CorpusV2Error("selection shard response hash is invalid")
        if not isinstance(candidates, list) or len(candidates) > 100:
            raise CorpusV2Error("selection shard candidate count is invalid")
        candidate_count += len(candidates)
        if candidate_count > candidate_maximum:
            raise CorpusV2Error("selection evidence exceeds candidate bound")
        parsed: list[Candidate] = []
        for candidate in candidates:
            if not isinstance(candidate, dict):
                raise CorpusV2Error("selection candidate must be an object")
            _strict_keys(candidate, {"merged_at", "pr", "html_url"}, "selection candidate")
            number = candidate["pr"]
            if not _is_int(number) or number <= 0:
                raise CorpusV2Error("selection candidate PR is invalid")
            url = f"https://github.com/{repository}/pull/{number}"
            if candidate["html_url"] != url:
                raise CorpusV2Error("selection candidate URL is noncanonical")
            parsed.append(
                Candidate(_parse_utc(candidate["merged_at"], "candidate merged_at"), number, url)
            )
        shards.append(
            CompleteShard(
                _parse_utc(row["start"], "shard start"),
                _parse_utc(row["end"], "shard end"),
                row["total_count"],
                tuple(parsed),
                row["response_hash"],
            )
        )
    return shards


def validate_lock(payload: dict[str, Any], manifest: dict[str, Any], manifest_hash: str) -> None:  # noqa: PLR0912, PLR0915
    """Validate every terminal repository and immutable PR identity in a v2 lock."""
    _strict_keys(
        payload,
        {
            "schema_version",
            "id",
            "manifest_id",
            "manifest_hash",
            "collector_hash",
            "collected_at",
            "selection",
            "projects",
            "network_budget",
        },
        "lock",
    )
    if payload["schema_version"] != 2 or isinstance(payload["schema_version"], bool):
        raise CorpusV2Error("unsupported lock schema_version")
    if payload["id"] != _LOCK_ID or payload["manifest_id"] != manifest["id"]:
        raise CorpusV2Error("lock identity does not match manifest")
    if payload["manifest_hash"] != manifest_hash or payload["collector_hash"] != collector_hash():
        raise CorpusV2Error("lock provenance hash mismatch")
    _parse_utc(payload["collected_at"], "collected_at")
    if payload["selection"] != _SELECTION:
        raise CorpusV2Error("lock selection changed")
    projects = payload["projects"]
    manifest_projects = manifest["projects"]
    if not isinstance(projects, list) or len(projects) != len(manifest_projects):
        raise CorpusV2Error("lock project count mismatch")
    global_ids: set[tuple[str, int]] = set()
    cutoff = _parse_utc(manifest["policy"]["merged_before"], "merged_before")
    for expected, project in zip(manifest_projects, projects, strict=True):
        if not isinstance(project, dict):
            raise CorpusV2Error("lock project must be an object")
        _strict_keys(
            project,
            {
                "repository",
                "status",
                "repository_created_at",
                "coverage_start",
                "coverage_end",
                "selected_count",
                "shortfall_reason",
                "records",
                "selection_evidence",
                "diagnostics",
            },
            "lock project",
        )
        repository = project["repository"]
        if repository != expected["repository"]:
            raise CorpusV2Error("lock repository order or identity changed")
        status = project["status"]
        if status not in {"complete", "underfilled", "unavailable"}:
            raise CorpusV2Error(f"invalid project status for {repository}")
        created = (
            _parse_utc(project["repository_created_at"], "repository_created_at")
            if project["repository_created_at"] is not None
            else None
        )
        coverage_start = (
            _parse_utc(project["coverage_start"], "coverage_start")
            if project["coverage_start"] is not None
            else None
        )
        if created is not None and created >= cutoff:
            raise CorpusV2Error("repository creation time is after cutoff")
        if coverage_start is not None and coverage_start > cutoff:
            raise CorpusV2Error("coverage time is after cutoff")
        if project["coverage_end"] is not None and (
            _parse_utc(project["coverage_end"], "coverage_end") != cutoff
        ):
            raise CorpusV2Error("coverage must end at the frozen cutoff")
        shards = _shards_from_payload(
            repository,
            project["selection_evidence"],
            maximum=manifest["bounds"]["max_shards_per_project"],
            candidate_maximum=manifest["bounds"]["max_candidates_per_project"],
        )
        records = project["records"]
        if (
            not isinstance(records, list)
            or not _is_int(project["selected_count"])
            or project["selected_count"] != len(records)
        ):
            raise CorpusV2Error("selected_count mismatch")
        if status in {"complete", "underfilled"} and (
            created is None or coverage_start is None or project["coverage_end"] is None
        ):
            raise CorpusV2Error("terminal selection lacks repository/coverage evidence")
        if status == "complete" and (len(records) != 50 or project["shortfall_reason"] is not None):
            raise CorpusV2Error("complete project must contain exactly 50 records")
        if status == "underfilled" and (
            len(records) >= 50
            or created is None
            or coverage_start is None
            or coverage_start > created
            or project["shortfall_reason"] != "history_exhausted"
        ):
            raise CorpusV2Error("underfill is not proven by complete history")
        unavailable_reasons = {
            "api_failure",
            "budget_exceeded",
            "dense_shard",
            "diff_unavailable",
            "identity_unavailable",
            "repository_unavailable",
            "redirect_rejected",
            "timeout",
        }
        if status == "unavailable" and (
            records
            or project["selected_count"] != 0
            or project["shortfall_reason"] not in unavailable_reasons
        ):
            raise CorpusV2Error("unavailable project must be empty with a structured reason")
        diagnostics = project["diagnostics"]
        if (
            not isinstance(diagnostics, list)
            or len(diagnostics) > manifest["bounds"]["max_diagnostics_per_project"]
            or any(
                not isinstance(item, str)
                or not item
                or len(item) > manifest["bounds"]["max_diagnostic_chars"]
                for item in diagnostics
            )
            or (status == "unavailable" and not diagnostics)
        ):
            raise CorpusV2Error("project diagnostics are invalid or missing")
        if status != "unavailable":
            assert created is not None and coverage_start is not None
            recomputed_status, recomputed, recomputed_coverage = select_from_complete_shards(
                shards,
                cutoff=cutoff,
                target=50,
                repository_created_at=created,
            )
            if (
                recomputed_status != status
                or recomputed_coverage != coverage_start
                or [(item.number, item.merged_at) for item in recomputed]
                != [
                    (record["pr"], _parse_utc(record["merged_at"], "record merged_at"))
                    for record in records
                ]
            ):
                raise CorpusV2Error("records do not match complete selection evidence")
        previous: tuple[datetime, int] | None = None
        for index, record in enumerate(records, 1):
            if not isinstance(record, dict):
                raise CorpusV2Error("lock record must be an object")
            _strict_keys(record, _record_keys(), "lock record")
            if record["rank"] != index or not _is_int(record["pr"]) or record["pr"] <= 0:
                raise CorpusV2Error("invalid rank or PR number")
            identity = (repository.casefold(), record["pr"])
            if identity in global_ids:
                raise CorpusV2Error("duplicate corpus PR identity")
            global_ids.add(identity)
            merged = _parse_utc(record["merged_at"], "record merged_at")
            order_key = (merged, record["pr"])
            if previous is not None and order_key >= previous:
                raise CorpusV2Error("records are not strictly ranked by merged_at and PR")
            previous = order_key
            if merged >= cutoff or (coverage_start is not None and merged < coverage_start):
                raise CorpusV2Error("record merged outside proven coverage")
            if record["html_url"] != f"https://github.com/{repository}/pull/{record['pr']}":
                raise CorpusV2Error("noncanonical PR URL")
            for field_name in (
                "base_sha",
                "head_sha",
                "merge_commit_sha",
                "baseline_sha",
                "target_sha",
            ):
                if _SHA.fullmatch(str(record[field_name])) is None:
                    raise CorpusV2Error(f"invalid {field_name}")
            parents = record["merge_parent_shas"]
            if (
                not isinstance(parents, list)
                or not parents
                or any(_SHA.fullmatch(str(parent)) is None for parent in parents)
                or len(parents) != len(set(parents))
            ):
                raise CorpusV2Error("invalid merge parents")
            if record["baseline_sha"] != parents[0] or record["target_sha"] != record["head_sha"]:
                raise CorpusV2Error("baseline/target identity rule mismatch")
            if (
                record["baseline_rule"] != "first_parent_of_merge_commit"
                or record["target_rule"] != "head_sha"
            ):
                raise CorpusV2Error("baseline/target rule changed")
            for evidence_hash in (
                "pull_response_sha256",
                "commit_response_sha256",
                "diff_sha256",
            ):
                if _DIGEST.fullmatch(str(record[evidence_hash])) is None:
                    raise CorpusV2Error(f"invalid {evidence_hash}")
            if not _is_int(record["diff_bytes"]) or record["diff_bytes"] < 0:
                raise CorpusV2Error("invalid diff byte count")
            canonical_diff = f"https://github.com/{repository}/pull/{record['pr']}.diff"
            patch_diff = (
                f"https://patch-diff.githubusercontent.com/raw/{repository}/pull/"
                f"{record['pr']}.diff"
            )
            if record["diff_final_url"] not in {canonical_diff, patch_diff}:
                raise CorpusV2Error("diff final URL changed PR identity")
            if not isinstance(record["diff_content_type"], str) or not (
                record["diff_content_type"].startswith("text/plain")
                or record["diff_content_type"].startswith("text/x-diff")
            ):
                raise CorpusV2Error("diff response content type is invalid")
            if (
                record["review_a"],
                record["review_b"],
                record["adjudication"],
                record["pr_type"],
            ) != (
                "pending",
                "pending",
                "pending",
                "unclassified",
            ):
                raise CorpusV2Error("collector may only emit pending review state")
    budget = payload["network_budget"]
    if not isinstance(budget, dict) or set(budget) != {
        "requests",
        "response_bytes",
        "diff_bytes",
        "elapsed_seconds",
    }:
        raise CorpusV2Error("invalid network budget evidence")
    if any(not _is_int(value) or value < 0 for value in budget.values()):
        raise CorpusV2Error("network budget counters must be nonnegative integers")
    if budget["requests"] < len(projects):
        raise CorpusV2Error("network budget cannot evidence one repository lookup per project")
    if any(project["status"] == "unavailable" for project in projects) and budget["requests"] == 0:
        raise CorpusV2Error("unavailable projects require nonzero collection evidence")
    recorded_diff_bytes = sum(
        record["diff_bytes"] for project in projects for record in project["records"]
    )
    if (
        budget["diff_bytes"] < recorded_diff_bytes
        or budget["response_bytes"] < budget["diff_bytes"]
    ):
        raise CorpusV2Error("network byte evidence is inconsistent with selected records")
    for field_name, manifest_name in (
        ("requests", "max_requests"),
        ("response_bytes", "max_response_bytes"),
        ("diff_bytes", "max_total_diff_bytes"),
        ("elapsed_seconds", "max_wall_seconds"),
    ):
        if budget[field_name] > manifest["bounds"][manifest_name]:
            raise CorpusV2Error(f"reported {field_name} exceeds frozen bound")


def collector_hash() -> str:
    return f"sha256:{hashlib.sha256(_read_bounded(Path(__file__))).hexdigest()}"


def load_lock_authenticated(
    lock_path: Path,
    manifest_path: Path,
    checksums_path: Path,
) -> tuple[dict[str, Any], str]:
    """Authenticate exact bytes against an independent profile before JSON parsing."""
    manifest, manifest_hash = load_manifest(manifest_path)
    checksums, _raw = _load_json(checksums_path)
    _strict_keys(
        checksums,
        {"schema_version", "id", "manifest_hash", "collector_hash", "lock_hash"},
        "checksum profile",
    )
    if checksums["schema_version"] != 2 or checksums["id"] != "oss-expansion-50x50-checksums-v2":
        raise CorpusV2Error("unsupported checksum profile")
    lock_raw = _read_bounded(lock_path)
    lock_hash = f"sha256:{hashlib.sha256(lock_raw).hexdigest()}"
    expected = {
        "manifest_hash": manifest_hash,
        "collector_hash": collector_hash(),
        "lock_hash": lock_hash,
    }
    for key, value in expected.items():
        if checksums[key] != value:
            raise CorpusV2Error(f"frozen checksum mismatch: {key}")
    try:
        payload = json.loads(lock_raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CorpusV2Error("invalid authenticated lock JSON") from exc
    if not isinstance(payload, dict):
        raise CorpusV2Error("lock root must be an object")
    validate_lock(payload, manifest, manifest_hash)
    return payload, lock_hash


def _publish_no_clobber(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise CorpusV2Error(f"refusing to overwrite {path}") from exc
    finally:
        temporary.unlink(missing_ok=True)


def hash_stream(chunks: list[bytes], budget: NetworkBudget) -> tuple[str, int]:
    """Hash bounded exact diff bytes without retaining them."""
    digest = hashlib.sha256()
    size = 0
    for chunk in chunks:
        size += len(chunk)
        if size > budget.max_diff_bytes:
            raise CorpusV2Error("one diff exceeded its byte budget")
        budget.consume(len(chunk), diff=True)
        digest.update(chunk)
    return f"sha256:{digest.hexdigest()}", size


class GitHubTransport:
    """Bounded metadata/diff transport; upstream bytes are never executed."""

    def __init__(
        self,
        token: str,
        budget: NetworkBudget,
        timeout: int,
        max_api_response_bytes: int = 16 * 1024 * 1024,
        max_rate_limit_wait_seconds: int = 3700,
        max_retries_per_request: int = 3,
    ) -> None:
        self._token = token
        self.budget = budget
        self._timeout = timeout
        self._max_api_response_bytes = max_api_response_bytes
        self._max_rate_limit_wait_seconds = max_rate_limit_wait_seconds
        self._max_retries_per_request = max_retries_per_request
        self._api_opener = urllib.request.build_opener(_RejectRedirects())

    def _rate_limit_delay(self, exc: urllib.error.HTTPError, attempt: int) -> int | None:
        if attempt >= self._max_retries_per_request or exc.code not in {403, 429}:
            return None
        retry_after = exc.headers.get("Retry-After")
        remaining = exc.headers.get("X-RateLimit-Remaining")
        if retry_after is None and remaining != "0" and exc.code != 429:
            return None
        if retry_after is not None and retry_after.isdigit():
            delay = int(retry_after)
        else:
            reset = exc.headers.get("X-RateLimit-Reset")
            delay = max(1, int(reset) - int(time.time()) + 1) if reset and reset.isdigit() else 60
        if delay > self._max_rate_limit_wait_seconds:
            raise CorpusV2Error("GitHub rate-limit wait exceeds frozen bound") from exc
        if time.monotonic() - self.budget.started + delay > self.budget.max_wall_seconds:
            raise CorpusV2Error("GitHub rate-limit wait exceeds aggregate wall budget") from exc
        return delay

    def get_json(self, url: str) -> dict[str, Any]:
        parsed = urllib.parse.urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.hostname != "api.github.com"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
            or parsed.fragment
        ):
            raise CorpusV2Error("API request left canonical https://api.github.com")
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "User-Agent": "fastapi-endpoint-detector-benchmark-v2/1",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        raw: bytes | None = None
        for attempt in range(self._max_retries_per_request + 1):
            self.budget.reserve()
            try:
                timeout = min(self._timeout, self.budget.remaining_wall_seconds())
                with (
                    _wall_deadline(self.budget),
                    self._api_opener.open(request, timeout=timeout) as response,
                ):
                    if response.geturl() != url:
                        raise CorpusV2Error("GitHub API response URL changed")
                    chunks: list[bytes] = []
                    size = 0
                    while chunk := response.read(64 * 1024):
                        size += len(chunk)
                        if size > self._max_api_response_bytes:
                            raise CorpusV2Error("one API response exceeded its frozen byte bound")
                        chunks.append(chunk)
                    raw = b"".join(chunks)
                break
            except urllib.error.HTTPError as exc:
                delay = self._rate_limit_delay(exc, attempt)
                if delay is None:
                    raise CorpusV2Error(f"GitHub API request failed: {url}") from exc
                with _wall_deadline(self.budget):
                    time.sleep(delay)
            except (urllib.error.URLError, TimeoutError) as exc:
                raise CorpusV2Error(f"GitHub API request failed: {url}") from exc
        if raw is None:
            raise CorpusV2Error(f"GitHub API retries exhausted: {url}")
        self.budget.consume(len(raw))
        try:
            payload = json.loads(raw, object_pairs_hook=_unique_object)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CorpusV2Error("GitHub API returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise CorpusV2Error("GitHub API response root must be an object")
        return payload

    def hash_diff(self, repository: str, number: int) -> tuple[str, int, str, str]:
        url = f"https://github.com/{repository}/pull/{number}.diff"
        handler = _SafeDiffRedirects(repository, number)
        opener = urllib.request.build_opener(handler)
        self.budget.reserve()
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github.v3.diff",
                "User-Agent": "fastapi-endpoint-detector-benchmark-v2/1",
            },
        )
        digest = hashlib.sha256()
        size = 0
        try:
            timeout = min(self._timeout, self.budget.remaining_wall_seconds())
            with (
                _wall_deadline(self.budget),
                opener.open(request, timeout=timeout) as response,
            ):
                final_url = response.geturl()
                handler._validate(final_url)
                content_type = response.headers.get("Content-Type", "")
                if not (
                    content_type.startswith("text/plain") or content_type.startswith("text/x-diff")
                ):
                    raise CorpusV2Error("GitHub diff response has an invalid content type")
                while chunk := response.read(64 * 1024):
                    next_size = size + len(chunk)
                    if next_size > self.budget.max_diff_bytes:
                        raise CorpusV2Error("one diff exceeded its byte budget")
                    self.budget.consume(len(chunk), diff=True)
                    size = next_size
                    digest.update(chunk)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
            raise CorpusV2Error(f"GitHub diff request failed: {url}") from exc
        return f"sha256:{digest.hexdigest()}", size, final_url, content_type

    def repository_created_at(self, repository: str) -> datetime:
        quoted = urllib.parse.quote(repository, safe="/")
        payload = self.get_json(f"https://api.github.com/repos/{quoted}")
        return _parse_utc(payload.get("created_at"), "repository created_at")

    def search_shard(self, repository: str, start: datetime, end: datetime) -> CompleteShard:
        if start >= end:
            raise CorpusV2Error("invalid search shard interval")
        if end - start < timedelta(seconds=1):
            raise CorpusV2Error("search shard interval is below one second")
        query_end = end - timedelta(seconds=1)
        query = (
            f"repo:{repository} is:pr is:merged merged:{_utc_text(start)}..{_utc_text(query_end)}"
        )
        base = "https://api.github.com/search/issues?" + urllib.parse.urlencode(
            {"q": query, "sort": "updated", "order": "desc", "per_page": 100}
        )
        first = self.get_json(base + "&page=1")
        total = first.get("total_count")
        if not _is_int(total) or total < 0:
            raise CorpusV2Error("search total_count is invalid")
        if first.get("incomplete_results") is not False:
            raise CorpusV2Error("GitHub search reported incomplete results")
        if total > 100:
            raise DenseShardError("search shard exceeds the one-response completeness ceiling")
        candidates: dict[int, Candidate] = {}
        items = first.get("items")
        if not isinstance(items, list):
            raise CorpusV2Error("search items must be a list")
        for item in items:
            if not isinstance(item, dict):
                raise CorpusV2Error("search item must be an object")
            number = item.get("number")
            pull = item.get("pull_request")
            merged_text = pull.get("merged_at") if isinstance(pull, dict) else None
            merged = _parse_utc(merged_text, "search merged_at")
            url = item.get("html_url")
            if (
                not _is_int(number)
                or number <= 0
                or url != f"https://github.com/{repository}/pull/{number}"
                or not (start <= merged < end)
            ):
                raise CorpusV2Error("search item identity or interval is invalid")
            candidate = Candidate(merged, number, url)
            existing = candidates.get(number)
            if existing is not None and existing != candidate:
                raise CorpusV2Error("search PR identity changed")
            candidates[number] = candidate
        if len(candidates) != total:
            raise CorpusV2Error("search shard cardinality does not prove completeness")
        response_hash = _json_hash(first)
        return CompleteShard(start, end, total, tuple(candidates.values()), response_hash)

    def record(self, repository: str, candidate: Candidate, rank: int) -> dict[str, Any]:
        quoted = urllib.parse.quote(repository, safe="/")
        pull = self.get_json(f"https://api.github.com/repos/{quoted}/pulls/{candidate.number}")
        base = pull.get("base")
        head = pull.get("head")
        base_sha = base.get("sha") if isinstance(base, dict) else None
        head_sha = head.get("sha") if isinstance(head, dict) else None
        merge_sha = pull.get("merge_commit_sha")
        if any(_SHA.fullmatch(str(value)) is None for value in (base_sha, head_sha, merge_sha)):
            raise CorpusV2Error("pull detail lacks immutable SHA identity")
        if (
            pull.get("number") != candidate.number
            or pull.get("html_url") != candidate.html_url
            or _parse_utc(pull.get("merged_at"), "pull merged_at") != candidate.merged_at
        ):
            raise CorpusV2Error("pull identity changed from complete shard")
        pull_hash = _json_hash(pull)
        commit = self.get_json(f"https://api.github.com/repos/{quoted}/commits/{merge_sha}")
        if commit.get("sha") != merge_sha:
            raise CorpusV2Error("merge commit response SHA changed")
        parent_rows = commit.get("parents")
        if not isinstance(parent_rows, list) or not parent_rows:
            raise CorpusV2Error("merge commit has no parent identity")
        parents = [row.get("sha") if isinstance(row, dict) else None for row in parent_rows]
        if any(_SHA.fullmatch(str(value)) is None for value in parents):
            raise CorpusV2Error("merge parent identity is invalid")
        commit_hash = _json_hash(commit)
        diff_hash, diff_bytes, diff_final_url, diff_content_type = self.hash_diff(
            repository, candidate.number
        )
        return {
            "rank": rank,
            "pr": candidate.number,
            "merged_at": _utc_text(candidate.merged_at),
            "html_url": candidate.html_url,
            "base_sha": base_sha,
            "head_sha": head_sha,
            "merge_commit_sha": merge_sha,
            "merge_parent_shas": parents,
            "baseline_sha": parents[0],
            "target_sha": head_sha,
            "baseline_rule": "first_parent_of_merge_commit",
            "target_rule": "head_sha",
            "pull_response_sha256": pull_hash,
            "commit_response_sha256": commit_hash,
            "diff_sha256": diff_hash,
            "diff_bytes": diff_bytes,
            "diff_final_url": diff_final_url,
            "diff_content_type": diff_content_type,
            "review_a": "pending",
            "review_b": "pending",
            "adjudication": "pending",
            "pr_type": "unclassified",
        }


def _complete_interval(
    transport: GitHubTransport,
    repository: str,
    start: datetime,
    end: datetime,
    *,
    shard_budget: int,
    candidate_budget: int,
) -> list[CompleteShard]:
    if shard_budget <= 0 or candidate_budget < 0:
        raise CorpusV2Error("project exceeded shard or candidate budget")
    try:
        shard = transport.search_shard(repository, start, end)
        if len(shard.candidates) > candidate_budget:
            raise CorpusV2Error("project exceeded candidate budget")
        return [shard]
    except DenseShardError:
        if shard_budget < 2:
            raise CorpusV2Error("project exceeded shard budget") from None
        if end - start <= timedelta(seconds=1):
            raise CorpusV2Error("one-second merged-time shard remains too dense") from None
        midpoint_timestamp = int(start.timestamp() + (end.timestamp() - start.timestamp()) / 2)
        midpoint = datetime.fromtimestamp(midpoint_timestamp, timezone.utc)
        if midpoint <= start or midpoint >= end:
            raise CorpusV2Error("dense shard cannot be split further") from None
        newer = _complete_interval(
            transport,
            repository,
            midpoint,
            end,
            shard_budget=shard_budget - 1,
            candidate_budget=candidate_budget,
        )
        newer_candidates = sum(len(shard.candidates) for shard in newer)
        older = _complete_interval(
            transport,
            repository,
            start,
            midpoint,
            shard_budget=shard_budget - len(newer),
            candidate_budget=candidate_budget - newer_candidates,
        )
        return [*newer, *older]


def _unavailable_reason(message: str) -> str:
    lowered = message.casefold()
    categories = (
        (("budget", "wall-clock"), "budget_exceeded"),
        (("redirect",), "redirect_rejected"),
        (("timeout",), "timeout"),
        (("dense", "shard"), "dense_shard"),
        (("diff",), "diff_unavailable"),
        (("identity", "parent", "commit"), "identity_unavailable"),
        (("repository", "created_at"), "repository_unavailable"),
    )
    return next(
        (reason for needles, reason in categories if any(item in lowered for item in needles)),
        "api_failure",
    )


def collect_project(
    transport: GitHubTransport,
    repository: str,
    *,
    cutoff: datetime,
    target: int,
    window_days: int,
    max_shards: int,
    max_candidates: int,
) -> dict[str, Any]:
    """Collect one terminal repository result from contiguous complete shards."""
    created: datetime | None = None
    end = cutoff
    shards: list[CompleteShard] = []
    coverage_start: datetime | None = None
    try:
        created = transport.repository_created_at(repository)
        while len(shards) < max_shards:
            start = max(created, end - timedelta(days=window_days))
            interval = _complete_interval(
                transport,
                repository,
                start,
                end,
                shard_budget=max_shards - len(shards),
                candidate_budget=max_candidates - sum(len(shard.candidates) for shard in shards),
            )
            if len(shards) + len(interval) > max_shards:
                raise CorpusV2Error("project exceeded shard budget")
            shards.extend(interval)
            try:
                status, selected, coverage_start = select_from_complete_shards(
                    shards,
                    cutoff=cutoff,
                    target=target,
                    repository_created_at=created,
                )
                break
            except CorpusV2Error as exc:
                if "coverage ended" not in str(exc):
                    raise
            if start == created:
                raise CorpusV2Error("history exhausted without terminal selector result")
            end = start
        else:
            raise CorpusV2Error("project exceeded shard budget")
        records = [
            transport.record(repository, candidate, rank)
            for rank, candidate in enumerate(selected, 1)
        ]
        return {
            "repository": repository,
            "status": status,
            "repository_created_at": _utc_text(created),
            "coverage_start": _utc_text(coverage_start),
            "coverage_end": _utc_text(cutoff),
            "selected_count": len(records),
            "shortfall_reason": None if status == "complete" else "history_exhausted",
            "records": records,
            "selection_evidence": [_shard_payload(shard) for shard in shards],
            "diagnostics": [],
        }
    except (CorpusV2Error, urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
        message = str(exc) or type(exc).__name__
        return {
            "repository": repository,
            "status": "unavailable",
            "repository_created_at": _utc_text(created) if created is not None else None,
            "coverage_start": _utc_text(shards[-1].start) if shards else None,
            "coverage_end": _utc_text(cutoff) if created is not None else None,
            "selected_count": 0,
            "shortfall_reason": _unavailable_reason(message),
            "records": [],
            "selection_evidence": [_shard_payload(shard) for shard in shards],
            "diagnostics": [message[:1000]],
        }


def _validate_checkpoint_project(
    project: object,
    *,
    repository: str,
    bounds: dict[str, Any],
) -> None:
    if not isinstance(project, dict):
        raise CorpusV2Error("checkpoint project is invalid")
    if (
        len(json.dumps(project, sort_keys=True, separators=(",", ":")).encode())
        > bounds["max_checkpoint_bytes"]
    ):
        raise CorpusV2Error("checkpoint project exceeds its byte bound")
    _strict_keys(
        project,
        {
            "repository",
            "status",
            "repository_created_at",
            "coverage_start",
            "coverage_end",
            "selected_count",
            "shortfall_reason",
            "records",
            "selection_evidence",
            "diagnostics",
        },
        "checkpoint project",
    )
    if project["repository"] != repository or project["status"] not in {
        "complete",
        "underfilled",
        "unavailable",
    }:
        raise CorpusV2Error("checkpoint repository/status mismatch")
    records = project["records"]
    if not isinstance(records, list) or len(records) > 50:
        raise CorpusV2Error("checkpoint record count exceeds bound")
    if any(not isinstance(record, dict) or set(record) != _record_keys() for record in records):
        raise CorpusV2Error("checkpoint record shape is invalid")
    _shards_from_payload(
        repository,
        project["selection_evidence"],
        maximum=bounds["max_shards_per_project"],
        candidate_maximum=bounds["max_candidates_per_project"],
    )
    diagnostics = project["diagnostics"]
    if (
        not isinstance(diagnostics, list)
        or len(diagnostics) > bounds["max_diagnostics_per_project"]
        or any(
            not isinstance(item, str) or len(item) > bounds["max_diagnostic_chars"]
            for item in diagnostics
        )
    ):
        raise CorpusV2Error("checkpoint diagnostics exceed bounds")


def _checkpoint_paths(directory: Path, index: int) -> tuple[Path, Path]:
    stem = f"{index:02d}.json"
    return directory / stem, directory / f"{stem}.sha256"


def _write_checkpoint(
    directory: Path, index: int, payload: dict[str, Any], *, max_bytes: int
) -> None:
    checkpoint, checksum = _checkpoint_paths(directory, index)
    encoded = json.dumps(payload, indent=2, sort_keys=True).encode()
    if len(encoded) + 1 > max_bytes:
        raise CorpusV2Error("checkpoint exceeds its frozen byte bound")
    _publish_no_clobber(checkpoint, payload)
    digest = hashlib.sha256(checkpoint.read_bytes()).hexdigest()
    try:
        _publish_no_clobber(checksum, {"sha256": digest})
    except Exception:
        checkpoint.unlink(missing_ok=True)
        raise


def _validate_checkpoint_semantics(
    checkpoint: dict[str, Any],
    *,
    manifest: dict[str, Any],
    manifest_hash: str,
    index: int,
) -> None:
    mini_manifest = {**manifest, "projects": [manifest["projects"][index - 1]]}
    mini_lock = {
        "schema_version": 2,
        "id": _LOCK_ID,
        "manifest_id": manifest["id"],
        "manifest_hash": manifest_hash,
        "collector_hash": collector_hash(),
        "collected_at": manifest["frozen_at"],
        "selection": _SELECTION,
        "projects": [checkpoint["project"]],
        "network_budget": checkpoint["network_budget"],
    }
    validate_lock(mini_lock, mini_manifest, manifest_hash)


def _load_checkpoint(
    directory: Path,
    index: int,
    *,
    repository: str,
    bounds: dict[str, Any],
    manifest: dict[str, Any],
    manifest_hash: str,
) -> dict[str, Any] | None:
    checkpoint, checksum = _checkpoint_paths(directory, index)
    if not checkpoint.exists() and not checksum.exists():
        return None
    if not checkpoint.exists() or not checksum.exists():
        raise CorpusV2Error("partial checkpoint pair")
    checksum_payload, _raw = _load_json(checksum)
    _strict_keys(checksum_payload, {"sha256"}, "checkpoint checksum")
    actual = hashlib.sha256(_read_bounded(checkpoint, bounds["max_checkpoint_bytes"])).hexdigest()
    if checksum_payload["sha256"] != actual:
        raise CorpusV2Error("checkpoint checksum mismatch")
    payload, _raw = _load_json(checkpoint, limit=bounds["max_checkpoint_bytes"])
    _strict_keys(
        payload,
        {"schema_version", "collector_hash", "index", "project", "network_budget"},
        "checkpoint",
    )
    if (
        payload["schema_version"] != 2
        or payload["collector_hash"] != collector_hash()
        or payload["index"] != index
    ):
        raise CorpusV2Error("checkpoint provenance mismatch")
    checkpoint_budget = payload["network_budget"]
    if not isinstance(checkpoint_budget, dict) or set(checkpoint_budget) != {
        "requests",
        "response_bytes",
        "diff_bytes",
        "elapsed_seconds",
    }:
        raise CorpusV2Error("checkpoint budget evidence is invalid")
    if any(not _is_int(value) or value < 0 for value in checkpoint_budget.values()):
        raise CorpusV2Error("checkpoint budget counters are invalid")
    for field_name, manifest_name in (
        ("requests", "max_requests"),
        ("response_bytes", "max_response_bytes"),
        ("diff_bytes", "max_total_diff_bytes"),
        ("elapsed_seconds", "max_wall_seconds"),
    ):
        if checkpoint_budget[field_name] > bounds[manifest_name]:
            raise CorpusV2Error("checkpoint budget exceeds frozen aggregate bound")
    _validate_checkpoint_project(payload["project"], repository=repository, bounds=bounds)
    _validate_checkpoint_semantics(
        payload,
        manifest=manifest,
        manifest_hash=manifest_hash,
        index=index,
    )
    return payload


def collect_live(
    manifest: dict[str, Any],
    manifest_hash: str,
    *,
    token: str,
    checkpoint_dir: Path,
    output: Path,
) -> dict[str, Any]:
    """Resume validated checkpoints under one aggregate budget and publish a terminal lock."""
    bounds = manifest["bounds"]
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    allowed_names = {
        name for index in range(1, 51) for name in (f"{index:02d}.json", f"{index:02d}.json.sha256")
    }
    entries = list(islice(checkpoint_dir.iterdir(), bounds["max_checkpoint_files"] + 1))
    if len(entries) > bounds["max_checkpoint_files"] or any(
        entry.name not in allowed_names or not entry.is_file() for entry in entries
    ):
        raise CorpusV2Error("checkpoint directory exceeds file/name bounds")

    persisted = {"requests": 0, "response_bytes": 0, "diff_bytes": 0, "elapsed_seconds": 0}
    checkpoint_present: list[bool] = []
    for index, project in enumerate(manifest["projects"], 1):
        checkpoint = _load_checkpoint(
            checkpoint_dir,
            index,
            repository=project["repository"],
            bounds=bounds,
            manifest=manifest,
            manifest_hash=manifest_hash,
        )
        checkpoint_present.append(checkpoint is not None)
        if checkpoint is not None:
            for field_name in persisted:
                persisted[field_name] += checkpoint["network_budget"][field_name]
    for field_name, manifest_name in (
        ("requests", "max_requests"),
        ("response_bytes", "max_response_bytes"),
        ("diff_bytes", "max_total_diff_bytes"),
        ("elapsed_seconds", "max_wall_seconds"),
    ):
        if persisted[field_name] > bounds[manifest_name]:
            raise CorpusV2Error("resumed checkpoints exceed frozen aggregate bounds")
    if not all(checkpoint_present) and any(
        persisted[field_name] >= bounds[manifest_name]
        for field_name, manifest_name in (
            ("requests", "max_requests"),
            ("response_bytes", "max_response_bytes"),
            ("diff_bytes", "max_total_diff_bytes"),
            ("elapsed_seconds", "max_wall_seconds"),
        )
    ):
        raise CorpusV2Error("resumed checkpoints leave no aggregate budget for missing projects")

    budget = NetworkBudget(
        max_requests=bounds["max_requests"],
        max_response_bytes=bounds["max_response_bytes"],
        max_diff_bytes=bounds["max_diff_bytes"],
        max_total_diff_bytes=bounds["max_total_diff_bytes"],
        max_wall_seconds=bounds["max_wall_seconds"],
        started=time.monotonic() - persisted["elapsed_seconds"],
        requests=persisted["requests"],
        response_bytes=persisted["response_bytes"],
        diff_bytes=persisted["diff_bytes"],
    )
    transport = GitHubTransport(
        token,
        budget,
        bounds["request_timeout_seconds"],
        bounds["max_api_response_bytes"],
        bounds["max_rate_limit_wait_seconds"],
        bounds["max_retries_per_request"],
    )
    projects: list[dict[str, Any]] = []
    cutoff = _parse_utc(manifest["policy"]["merged_before"], "merged_before")
    for index, (project, present) in enumerate(
        zip(manifest["projects"], checkpoint_present, strict=True), 1
    ):
        checkpoint = (
            _load_checkpoint(
                checkpoint_dir,
                index,
                repository=project["repository"],
                bounds=bounds,
                manifest=manifest,
                manifest_hash=manifest_hash,
            )
            if present
            else None
        )
        if checkpoint is None:
            before = (budget.requests, budget.response_bytes, budget.diff_bytes)
            started = time.monotonic()
            project_result = collect_project(
                transport,
                project["repository"],
                cutoff=cutoff,
                target=manifest["policy"]["target_prs_per_project"],
                window_days=manifest["sharding"]["initial_window_days"],
                max_shards=bounds["max_shards_per_project"],
                max_candidates=bounds["max_candidates_per_project"],
            )
            _validate_checkpoint_project(
                project_result,
                repository=project["repository"],
                bounds=bounds,
            )
            checkpoint = {
                "schema_version": 2,
                "collector_hash": collector_hash(),
                "index": index,
                "project": project_result,
                "network_budget": {
                    "requests": budget.requests - before[0],
                    "response_bytes": budget.response_bytes - before[1],
                    "diff_bytes": budget.diff_bytes - before[2],
                    "elapsed_seconds": math.ceil(time.monotonic() - started),
                },
            }
            _write_checkpoint(
                checkpoint_dir,
                index,
                checkpoint,
                max_bytes=bounds["max_checkpoint_bytes"],
            )
        projects.append(checkpoint["project"])
    elapsed = math.ceil(time.monotonic() - budget.started)
    payload = {
        "schema_version": 2,
        "id": _LOCK_ID,
        "manifest_id": manifest["id"],
        "manifest_hash": manifest_hash,
        "collector_hash": collector_hash(),
        "collected_at": _utc_text(datetime.now(timezone.utc)),
        "selection": _SELECTION,
        "projects": projects,
        "network_budget": {
            "requests": budget.requests,
            "response_bytes": budget.response_bytes,
            "diff_bytes": budget.diff_bytes,
            "elapsed_seconds": elapsed,
        },
    }
    validate_lock(payload, manifest, manifest_hash)
    if len(json.dumps(payload, indent=2, sort_keys=True).encode()) + 1 > bounds["max_lock_bytes"]:
        raise CorpusV2Error("terminal lock exceeds its frozen output bound")
    _publish_no_clobber(output, payload)
    return payload


def _manifest_summary(manifest: dict[str, Any], digest: str) -> dict[str, Any]:
    return {
        "id": manifest["id"],
        "projects": len(manifest["projects"]),
        "target_records": len(manifest["projects"]) * manifest["policy"]["target_prs_per_project"],
        "hash": digest,
        "collector_hash": collector_hash(),
        "live_collection_status": "not_run",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("benchmarks/real_world/expansion/projects-50x50-v2.json"),
    )
    parser.add_argument(
        "--preregistration",
        type=Path,
        default=Path("benchmarks/real_world/expansion/checksums-50x50-v2-preregistered.json"),
    )
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--validate-lock", type=Path)
    parser.add_argument("--checksums", type=Path)
    parser.add_argument("--collect-live", action="store_true")
    parser.add_argument("--checkpoint-dir", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    validate_v1_sentinels()
    manifest, digest = load_manifest(args.manifest)
    load_preregistration(args.preregistration, digest)
    if args.validate_only:
        print(json.dumps(_manifest_summary(manifest, digest), sort_keys=True))
        return 0
    if args.validate_lock is not None:
        if args.checksums is None:
            parser.error("--checksums is required with --validate-lock")
        lock, lock_hash = load_lock_authenticated(args.validate_lock, args.manifest, args.checksums)
        print(json.dumps({"projects": len(lock["projects"]), "hash": lock_hash}, sort_keys=True))
        return 0
    if args.collect_live:
        if args.checkpoint_dir is None or args.output is None:
            parser.error("--checkpoint-dir and --output are required with --collect-live")
        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            parser.error("GITHUB_TOKEN is required with --collect-live")
        lock = collect_live(
            manifest,
            digest,
            token=token,
            checkpoint_dir=args.checkpoint_dir,
            output=args.output,
        )
        print(json.dumps({"projects": len(lock["projects"]), "output": str(args.output)}))
        return 0
    parser.error("choose --validate-only, --validate-lock, or --collect-live")


if __name__ == "__main__":
    raise SystemExit(main())
