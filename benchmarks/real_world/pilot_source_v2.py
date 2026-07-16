#!/usr/bin/env python3
"""Collect and authenticate immutable source bindings for the three-PR pilot."""

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
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn, Protocol, TypeGuard

from benchmarks.real_world import pilot_protocol_v2

if TYPE_CHECKING:
    from collections.abc import Iterator
    from types import FrameType

_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_LOCAL_BYTES = 8 * 1024 * 1024
_MAX_API_BYTES = 8 * 1024 * 1024
_MAX_REDIRECT_BODY_BYTES = 64 * 1024
_MAX_DIFF_BYTES = 16 * 1024 * 1024
_MAX_TOTAL_BYTES = 64 * 1024 * 1024
_MAX_OUTPUT_BYTES = 2 * 1024 * 1024
_MAX_REQUESTS = 45
_MAX_WALL_SECONDS = 600
_REQUEST_TIMEOUT_SECONDS = 30
_MAX_RETRIES = 2
_PILOT_PROFILE_SHA256 = "sha256:beac156227a700497f1fb9588e91d8c4f80a1dac88bb9e831433eea167c20c8e"
_BINDINGS_ID = "blind-review-pilot-source-bindings-v1"
_CHECKSUM_ID = "blind-review-pilot-source-bindings-checksums-v1"


class PilotSourceError(ValueError):
    """Raised when source-binding provenance or transport is invalid."""


@dataclass
class NetworkBudget:
    """Strict aggregate request, byte, diff, and wall-clock limits."""

    max_requests: int = _MAX_REQUESTS
    max_response_bytes: int = _MAX_TOTAL_BYTES
    max_diff_bytes: int = _MAX_DIFF_BYTES
    max_total_diff_bytes: int = _MAX_TOTAL_BYTES
    max_wall_seconds: int = _MAX_WALL_SECONDS
    started: float = field(default_factory=time.monotonic)
    requests: int = 0
    response_bytes: int = 0
    diff_bytes: int = 0

    def remaining_wall_seconds(self) -> float:
        remaining = self.max_wall_seconds - (time.monotonic() - self.started)
        if remaining <= 0:
            raise PilotSourceError("source collection exceeded wall-clock budget")
        return remaining

    def reserve_request(self) -> None:
        self.remaining_wall_seconds()
        if self.requests >= self.max_requests:
            raise PilotSourceError("source collection exceeded request budget")
        self.requests += 1

    def consume(self, size: int, *, diff: bool = False) -> None:
        if size < 0:
            raise PilotSourceError("negative transport byte count")
        response_total = self.response_bytes + size
        diff_total = self.diff_bytes + size if diff else self.diff_bytes
        if response_total > self.max_response_bytes:
            raise PilotSourceError("source collection exceeded response-byte budget")
        if diff_total > self.max_total_diff_bytes:
            raise PilotSourceError("source collection exceeded total diff-byte budget")
        self.response_bytes = response_total
        self.diff_bytes = diff_total
        self.remaining_wall_seconds()


class SourceTransport(Protocol):
    """Narrow transport contract used by collection and fake tests."""

    def get_json(self, url: str) -> tuple[dict[str, Any], str]: ...

    def hash_diff(self, repository: str, number: int) -> tuple[str, int, str, str]: ...


def _is_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PilotSourceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    raise PilotSourceError(f"non-finite JSON constant is forbidden: {value}")


def _reject_nesting(raw: bytes, *, maximum: int = 100) -> None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PilotSourceError("JSON is not UTF-8") from exc
    depth = 0
    quoted = False
    escaped = False
    for character in text:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
            if depth > maximum:
                raise PilotSourceError("JSON nesting exceeds limit")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise PilotSourceError("JSON structure is unbalanced")
    if depth != 0 or quoted:
        raise PilotSourceError("JSON structure is unbalanced")


def _parse_json(raw: bytes, label: str) -> dict[str, Any]:
    _reject_nesting(raw)
    try:
        payload = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, MemoryError) as exc:
        raise PilotSourceError(f"invalid JSON in {label}") from exc
    if not isinstance(payload, dict):
        raise PilotSourceError(f"{label} root must be an object")
    return payload


def _read_bounded(path: Path, limit: int = _MAX_LOCAL_BYTES) -> bytes:
    try:
        with path.open("rb") as handle:
            raw = handle.read(limit + 1)
    except OSError as exc:
        raise PilotSourceError(f"cannot read {path}") from exc
    if len(raw) > limit:
        raise PilotSourceError(f"{path.name} exceeds byte limit")
    return raw


def _sha256(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _canonical_utc(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise PilotSourceError(f"{label} must be a canonical UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise PilotSourceError(f"invalid {label}") from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise PilotSourceError(f"{label} must use UTC")
    canonical = parsed.isoformat().replace("+00:00", "Z")
    if canonical != value:
        raise PilotSourceError(f"{label} is not canonically encoded")
    return value


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise PilotSourceError(f"invalid {label}")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise PilotSourceError(f"invalid {label}")
    return value


def _wall_timeout(_signum: int, _frame: FrameType | None) -> NoReturn:
    raise TimeoutError("source collection exceeded wall-clock budget during I/O")


@contextmanager
def _wall_deadline(budget: NetworkBudget) -> Iterator[None]:
    if threading.current_thread() is not threading.main_thread() or not hasattr(
        signal, "setitimer"
    ):
        raise PilotSourceError("exact wall deadline requires POSIX main-thread collection")
    remaining = budget.remaining_wall_seconds()
    previous_handler = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, _wall_timeout)
    previous_delay, previous_interval = signal.setitimer(signal.ITIMER_REAL, remaining)
    started = time.monotonic()
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
    """Follow exactly one bounded GitHub-to-patch redirect without credentials."""

    def __init__(self, repository: str, number: int, budget: NetworkBudget) -> None:
        self.repository = repository
        self.number = number
        self.budget = budget
        self.followed = False

    @property
    def origin_url(self) -> str:
        return f"https://github.com/{self.repository}/pull/{self.number}.diff"

    @property
    def patch_url(self) -> str:
        return f"https://patch-diff.githubusercontent.com/raw/{self.repository}/pull/{self.number}.diff"

    def validate_final(self, url: str) -> None:
        if url != self.patch_url:
            raise PilotSourceError("diff redirect did not preserve exact PR identity")

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request:
        del fp, msg, headers
        if (
            self.followed
            or code != 302
            or req.full_url != self.origin_url
            or newurl != self.patch_url
        ):
            raise PilotSourceError("diff redirect did not preserve exact PR identity")
        safe_headers = {
            key: value
            for key, value in req.header_items()
            if key.casefold() not in {"authorization", "cookie", "host", "proxy-authorization"}
        }
        return urllib.request.Request(newurl, headers=safe_headers, method="GET")

    def http_error_302(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
    ) -> Any:
        try:
            body = fp.read(_MAX_REDIRECT_BODY_BYTES + 1)
            self.budget.consume(len(body))
        finally:
            fp.close()
        if len(body) > _MAX_REDIRECT_BODY_BYTES:
            raise PilotSourceError("diff redirect response body exceeded byte bound")
        location = headers.get("Location")
        if not isinstance(location, str):
            raise PilotSourceError("diff redirect is missing Location")
        newurl = urllib.parse.urljoin(req.full_url, location)
        redirected = self.redirect_request(req, fp, code, msg, headers, newurl)
        self.followed = True
        self.budget.reserve_request()
        timeout = min(_REQUEST_TIMEOUT_SECONDS, self.budget.remaining_wall_seconds())
        return self.parent.open(redirected, timeout=timeout)


class GitHubTransport:
    """Bounded credential-safe GitHub metadata and exact diff transport."""

    def __init__(self, token: str, budget: NetworkBudget) -> None:
        self.token = token
        self.budget = budget
        self.api_opener = urllib.request.build_opener(_RejectRedirects())

    @staticmethod
    def _validate_api_url(url: str) -> None:
        parsed = urllib.parse.urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.hostname != "api.github.com"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
            or parsed.query
            or parsed.fragment
            or not parsed.path.startswith("/repos/")
        ):
            raise PilotSourceError("API request left canonical GitHub repository endpoints")

    def _sleep(self, attempt: int) -> None:
        delay = min(1 << attempt, 4)
        if delay >= self.budget.remaining_wall_seconds():
            raise PilotSourceError("retry delay exceeds wall budget")
        with _wall_deadline(self.budget):
            time.sleep(delay)

    def _consume_http_error(self, error: urllib.error.HTTPError) -> None:
        try:
            try:
                with _wall_deadline(self.budget):
                    raw = error.read(_MAX_API_BYTES + 1)
                    self.budget.consume(len(raw))
            except TimeoutError as exc:
                raise PilotSourceError("HTTP error response exceeded wall-clock budget") from exc
        finally:
            error.close()
        if len(raw) > _MAX_API_BYTES:
            raise PilotSourceError("HTTP error response exceeded byte bound")

    def get_json(self, url: str) -> tuple[dict[str, Any], str]:
        self._validate_api_url(url)
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "User-Agent": "fastapi-endpoint-detector-pilot-source-v1/1",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        for attempt in range(_MAX_RETRIES + 1):
            self.budget.reserve_request()
            try:
                timeout = min(_REQUEST_TIMEOUT_SECONDS, self.budget.remaining_wall_seconds())
                with (
                    _wall_deadline(self.budget),
                    self.api_opener.open(request, timeout=timeout) as response,
                ):
                    if response.geturl() != url:
                        raise PilotSourceError("GitHub API response URL changed")
                    chunks: list[bytes] = []
                    size = 0
                    while chunk := response.read(64 * 1024):
                        size += len(chunk)
                        self.budget.consume(len(chunk))
                        if size > _MAX_API_BYTES:
                            raise PilotSourceError("one API response exceeded byte bound")
                        chunks.append(chunk)
                raw = b"".join(chunks)
                return _parse_json(raw, url), _sha256(raw)
            except urllib.error.HTTPError as exc:
                self._consume_http_error(exc)
                if attempt >= _MAX_RETRIES or exc.code not in {403, 429, 500, 502, 503, 504}:
                    raise PilotSourceError(f"GitHub API request failed: {url}") from exc
                self._sleep(attempt)
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                if attempt >= _MAX_RETRIES:
                    raise PilotSourceError(f"GitHub API request failed: {url}") from exc
                self._sleep(attempt)
        raise PilotSourceError("GitHub API retries exhausted")

    def hash_diff(self, repository: str, number: int) -> tuple[str, int, str, str]:
        url = f"https://github.com/{repository}/pull/{number}.diff"
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github.v3.diff",
                "User-Agent": "fastapi-endpoint-detector-pilot-source-v1/1",
            },
        )
        for attempt in range(_MAX_RETRIES + 1):
            self.budget.reserve_request()
            redirects = _SafeDiffRedirects(repository, number, self.budget)
            opener = urllib.request.build_opener(redirects)
            digest = hashlib.sha256()
            size = 0
            try:
                timeout = min(_REQUEST_TIMEOUT_SECONDS, self.budget.remaining_wall_seconds())
                with (
                    _wall_deadline(self.budget),
                    opener.open(request, timeout=timeout) as response,
                ):
                    final_url = response.geturl()
                    redirects.validate_final(final_url)
                    if not redirects.followed:
                        raise PilotSourceError(
                            "diff response did not use the required exact redirect"
                        )
                    content_type = response.headers.get("Content-Type", "")
                    if not (
                        content_type.startswith("text/plain")
                        or content_type.startswith("text/x-diff")
                    ):
                        raise PilotSourceError("diff response content type is invalid")
                    while chunk := response.read(64 * 1024):
                        size += len(chunk)
                        self.budget.consume(len(chunk), diff=True)
                        if size > self.budget.max_diff_bytes:
                            raise PilotSourceError("one diff exceeded byte bound")
                        digest.update(chunk)
                return f"sha256:{digest.hexdigest()}", size, final_url, content_type
            except urllib.error.HTTPError as exc:
                self._consume_http_error(exc)
                if attempt >= _MAX_RETRIES or exc.code not in {403, 429, 500, 502, 503, 504}:
                    raise PilotSourceError(f"GitHub diff request failed: {url}") from exc
                self._sleep(attempt)
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                if attempt >= _MAX_RETRIES:
                    raise PilotSourceError(f"GitHub diff request failed: {url}") from exc
                self._sleep(attempt)
        raise PilotSourceError("GitHub diff retries exhausted")


def _nested_object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PilotSourceError(f"{label} must be an object")
    return value


def _api_url(repository: str, suffix: str) -> str:
    quoted = urllib.parse.quote(repository, safe="/")
    return f"https://api.github.com/repos/{quoted}/{suffix}"


def _commit_binding(
    transport: SourceTransport, repository: str, commit: str, label: str
) -> tuple[str, str]:
    payload, response_hash = transport.get_json(_api_url(repository, f"git/commits/{commit}"))
    if _sha(payload.get("sha"), f"{label} commit SHA") != commit:
        raise PilotSourceError(f"{label} commit response identity mismatch")
    tree = _nested_object(payload.get("tree"), f"{label} tree")
    return _sha(tree.get("sha"), f"{label} tree SHA"), _digest(
        response_hash, f"{label} response hash"
    )


def _pull_identity(
    pull: dict[str, Any], repository: str, number: int, expected_merged_at: object
) -> tuple[str, str, str, str]:
    if pull.get("number") != number:
        raise PilotSourceError("pull response PR identity mismatch")
    expected_html = f"https://github.com/{repository}/pull/{number}"
    if pull.get("html_url") != expected_html:
        raise PilotSourceError("pull response repository identity mismatch")
    merged_at = _canonical_utc(pull.get("merged_at"), "pull merged_at")
    if merged_at != expected_merged_at:
        raise PilotSourceError("pull merged_at differs from frozen selection evidence")
    base = _nested_object(pull.get("base"), "pull base")
    head = _nested_object(pull.get("head"), "pull head")
    return (
        merged_at,
        _sha(base.get("sha"), "pull base SHA"),
        _sha(head.get("sha"), "pull head SHA"),
        _sha(pull.get("merge_commit_sha"), "pull merge commit SHA"),
    )


def collect_source_bindings(
    selected: list[dict[str, object]],
    transport: SourceTransport,
    budget: NetworkBudget,
    *,
    collected_at: str,
    collector_sha256: str,
) -> dict[str, Any]:
    """Collect exact immutable metadata for only the frozen pilot identities."""
    _canonical_utc(collected_at, "collected_at")
    records: list[dict[str, Any]] = []
    for frozen in selected:
        repository = frozen.get("repository")
        number = frozen.get("number")
        expected_merged_at = frozen.get("merged_at")
        if not isinstance(repository, str) or not _is_int(number):
            raise PilotSourceError("frozen pilot identity is invalid")
        pull_url = _api_url(repository, f"pulls/{number}")
        pull, pull_hash = transport.get_json(pull_url)
        merged_at, base_sha, target_commit, merge_commit = _pull_identity(
            pull, repository, number, expected_merged_at
        )

        merge_payload, merge_hash = transport.get_json(
            _api_url(repository, f"git/commits/{merge_commit}")
        )
        if _sha(merge_payload.get("sha"), "merge commit response SHA") != merge_commit:
            raise PilotSourceError("merge commit response identity mismatch")
        parents = merge_payload.get("parents")
        if not isinstance(parents, list) or not parents:
            raise PilotSourceError("merge commit has no first parent")
        parent_shas = [
            _sha(_nested_object(parent, "merge parent").get("sha"), "merge parent SHA")
            for parent in parents
        ]
        if len(parent_shas) not in {1, 2}:
            raise PilotSourceError("merge commit parent cardinality is unsupported")
        baseline_commit = parent_shas[0]
        baseline_tree, baseline_hash = _commit_binding(
            transport, repository, baseline_commit, "baseline"
        )
        target_tree, target_hash = _commit_binding(transport, repository, target_commit, "target")
        diff_hash, diff_bytes, final_url, content_type = transport.hash_diff(repository, number)
        if diff_bytes < 0 or diff_bytes > budget.max_diff_bytes:
            raise PilotSourceError("diff byte count is invalid")
        confirmation, confirmation_hash = transport.get_json(pull_url)
        if _pull_identity(confirmation, repository, number, expected_merged_at) != (
            merged_at,
            base_sha,
            target_commit,
            merge_commit,
        ):
            raise PilotSourceError("pull identity changed while streaming diff")
        records.append(
            {
                "repository": repository,
                "pr": number,
                "merged_at": merged_at,
                "base_sha": base_sha,
                "target_commit": target_commit,
                "target_tree": target_tree,
                "merge_commit": merge_commit,
                "merge_parent_shas": parent_shas,
                "baseline_rule": "first_parent_of_merge_commit",
                "baseline_commit": baseline_commit,
                "baseline_tree": baseline_tree,
                "target_rule": "head_sha",
                "diff_sha256": _digest(diff_hash, "diff hash"),
                "diff_bytes": diff_bytes,
                "diff_final_url": final_url,
                "diff_content_type": content_type,
                "initial_pull_response_sha256": _digest(pull_hash, "initial pull response hash"),
                "confirmation_pull_response_sha256": _digest(
                    confirmation_hash, "confirmation pull response hash"
                ),
                "merge_commit_response_sha256": _digest(merge_hash, "merge commit response hash"),
                "baseline_commit_response_sha256": baseline_hash,
                "target_commit_response_sha256": target_hash,
            }
        )
    budget.remaining_wall_seconds()
    elapsed = math.ceil(time.monotonic() - budget.started)
    return {
        "schema_version": 1,
        "id": _BINDINGS_ID,
        "phase": "source_bindings_frozen_reviews_not_run",
        "preregistration_profile_sha256": _PILOT_PROFILE_SHA256,
        "collector_sha256": _digest(collector_sha256, "collector hash"),
        "collected_at": collected_at,
        "records": records,
        "network_budget": {
            "requests": budget.requests,
            "response_bytes": budget.response_bytes,
            "diff_bytes": budget.diff_bytes,
            "selected_diff_bytes": sum(record["diff_bytes"] for record in records),
            "elapsed_seconds": elapsed,
            "limits": {
                "max_requests": budget.max_requests,
                "max_response_bytes": budget.max_response_bytes,
                "max_diff_bytes": budget.max_diff_bytes,
                "max_total_diff_bytes": budget.max_total_diff_bytes,
                "max_wall_seconds": budget.max_wall_seconds,
                "request_timeout_seconds": _REQUEST_TIMEOUT_SECONDS,
                "max_retries_per_request": _MAX_RETRIES,
            },
        },
    }


def _validate_record(record: dict[str, Any], frozen: dict[str, object]) -> None:
    expected_keys = {
        "repository",
        "pr",
        "merged_at",
        "base_sha",
        "target_commit",
        "target_tree",
        "merge_commit",
        "merge_parent_shas",
        "baseline_rule",
        "baseline_commit",
        "baseline_tree",
        "target_rule",
        "diff_sha256",
        "diff_bytes",
        "diff_final_url",
        "diff_content_type",
        "initial_pull_response_sha256",
        "confirmation_pull_response_sha256",
        "merge_commit_response_sha256",
        "baseline_commit_response_sha256",
        "target_commit_response_sha256",
    }
    if set(record) != expected_keys:
        raise PilotSourceError("source-binding record keys are invalid")
    if (
        record["repository"] != frozen["repository"]
        or record["pr"] != frozen["number"]
        or record["merged_at"] != frozen["merged_at"]
    ):
        raise PilotSourceError("source-binding identity differs from preregistration")
    for name in (
        "base_sha",
        "target_commit",
        "target_tree",
        "merge_commit",
        "baseline_commit",
        "baseline_tree",
    ):
        _sha(record[name], name)
    parents = record["merge_parent_shas"]
    if not isinstance(parents, list) or len(parents) not in {1, 2}:
        raise PilotSourceError("source-binding merge parents are invalid")
    validated_parents = [_sha(item, "merge parent") for item in parents]
    if validated_parents[0] != record["baseline_commit"]:
        raise PilotSourceError("baseline is not merge first parent")
    if (
        record["baseline_rule"] != "first_parent_of_merge_commit"
        or record["target_rule"] != "head_sha"
    ):
        raise PilotSourceError("snapshot rules changed")
    for name in (
        "diff_sha256",
        "initial_pull_response_sha256",
        "confirmation_pull_response_sha256",
        "merge_commit_response_sha256",
        "baseline_commit_response_sha256",
        "target_commit_response_sha256",
    ):
        _digest(record[name], name)
    if not _is_int(record["diff_bytes"]) or not 0 <= record["diff_bytes"] <= _MAX_DIFF_BYTES:
        raise PilotSourceError("source-binding diff byte count is invalid")
    expected_diff_url = (
        f"https://patch-diff.githubusercontent.com/raw/{record['repository']}"
        f"/pull/{record['pr']}.diff"
    )
    if record["diff_final_url"] != expected_diff_url:
        raise PilotSourceError("diff redirect did not preserve exact PR identity")
    content_type = record["diff_content_type"]
    if not isinstance(content_type, str) or not (
        content_type.startswith("text/plain") or content_type.startswith("text/x-diff")
    ):
        raise PilotSourceError("source-binding diff content type is invalid")
    _canonical_utc(record["merged_at"], "source-binding merged_at")


def validate_payload(payload: dict[str, Any], selected: list[dict[str, object]]) -> None:
    expected_keys = {
        "schema_version",
        "id",
        "phase",
        "preregistration_profile_sha256",
        "collector_sha256",
        "collected_at",
        "records",
        "network_budget",
    }
    if set(payload) != expected_keys:
        raise PilotSourceError("source-binding root keys are invalid")
    if (
        payload["schema_version"] != 1
        or payload["id"] != _BINDINGS_ID
        or payload["phase"] != "source_bindings_frozen_reviews_not_run"
        or payload["preregistration_profile_sha256"] != _PILOT_PROFILE_SHA256
    ):
        raise PilotSourceError("source-binding provenance changed")
    _digest(payload["collector_sha256"], "collector hash")
    _canonical_utc(payload["collected_at"], "collected_at")
    records = payload["records"]
    if not isinstance(records, list) or len(records) != len(selected):
        raise PilotSourceError("source-binding record coverage is incomplete")
    for record, frozen in zip(records, selected, strict=True):
        if not isinstance(record, dict):
            raise PilotSourceError("source-binding record is not an object")
        _validate_record(record, frozen)
    budget = _nested_object(payload["network_budget"], "network budget")
    if set(budget) != {
        "requests",
        "response_bytes",
        "diff_bytes",
        "selected_diff_bytes",
        "elapsed_seconds",
        "limits",
    }:
        raise PilotSourceError("source-binding network budget keys are invalid")
    for name in (
        "requests",
        "response_bytes",
        "diff_bytes",
        "selected_diff_bytes",
        "elapsed_seconds",
    ):
        if not _is_int(budget[name]) or budget[name] < 0:
            raise PilotSourceError("source-binding network totals are invalid")
    limits = _nested_object(budget["limits"], "network limits")
    expected_limits = {
        "max_requests": _MAX_REQUESTS,
        "max_response_bytes": _MAX_TOTAL_BYTES,
        "max_diff_bytes": _MAX_DIFF_BYTES,
        "max_total_diff_bytes": _MAX_TOTAL_BYTES,
        "max_wall_seconds": _MAX_WALL_SECONDS,
        "request_timeout_seconds": _REQUEST_TIMEOUT_SECONDS,
        "max_retries_per_request": _MAX_RETRIES,
    }
    if limits != expected_limits:
        raise PilotSourceError("source-binding network limits changed")
    if (
        budget["requests"] < 21
        or budget["requests"] > _MAX_REQUESTS
        or budget["response_bytes"] < budget["diff_bytes"]
        or budget["response_bytes"] > _MAX_TOTAL_BYTES
        or budget["diff_bytes"] > _MAX_TOTAL_BYTES
        or budget["elapsed_seconds"] > _MAX_WALL_SECONDS
    ):
        raise PilotSourceError("source-binding network totals exceed limits")
    if sum(record["diff_bytes"] for record in records) != budget["selected_diff_bytes"]:
        raise PilotSourceError("source-binding selected diff totals are inconsistent")
    if budget["selected_diff_bytes"] > budget["diff_bytes"]:
        raise PilotSourceError("source-binding transport diff total is inconsistent")


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    raw = (json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
    if len(raw) > _MAX_OUTPUT_BYTES:
        raise PilotSourceError("source-binding output exceeds byte bound")
    return raw


def _publish_no_clobber(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise PilotSourceError(f"refusing to overwrite {path}") from exc
    finally:
        temporary.unlink(missing_ok=True)


def _authenticate_preregistration(root: Path) -> list[dict[str, object]]:
    try:
        summary = pilot_protocol_v2.validate_preregistration(root)
    except pilot_protocol_v2.PilotProtocolError as exc:
        raise PilotSourceError("pilot preregistration authentication failed") from exc
    selected = summary.get("selected")
    if not isinstance(selected, list) or len(selected) != 3:
        raise PilotSourceError("pilot preregistration selection is invalid")
    return selected


def collector_sha256() -> str:
    return _sha256(Path(__file__).read_bytes())


def validate_authenticated(root: Path, bindings_path: Path, checksums_path: Path) -> dict[str, Any]:
    selected = _authenticate_preregistration(root)
    profile_raw = _read_bounded(checksums_path)
    profile = _parse_json(profile_raw, str(checksums_path))
    expected_keys = {
        "schema_version",
        "id",
        "preregistration_profile_sha256",
        "collector_sha256",
        "source_bindings_sha256",
    }
    if set(profile) != expected_keys:
        raise PilotSourceError("source-binding checksum profile keys are invalid")
    bindings_raw = _read_bounded(bindings_path, _MAX_OUTPUT_BYTES)
    expected = {
        "schema_version": 1,
        "id": _CHECKSUM_ID,
        "preregistration_profile_sha256": _PILOT_PROFILE_SHA256,
        "collector_sha256": collector_sha256(),
        "source_bindings_sha256": _sha256(bindings_raw),
    }
    if profile != expected:
        raise PilotSourceError("source-binding exact-byte checksum mismatch")
    payload = _parse_json(bindings_raw, str(bindings_path))
    validate_payload(payload, selected)
    if payload["collector_sha256"] != expected["collector_sha256"]:
        raise PilotSourceError("source-binding embedded collector hash mismatch")
    return payload


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--collect", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--validate", type=Path)
    parser.add_argument("--checksums", type=Path)
    args = parser.parse_args()
    if args.collect:
        if args.output is None or args.validate is not None or args.checksums is not None:
            parser.error("--collect requires only --output")
        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            parser.error("GITHUB_TOKEN is required with --collect")
        selected = _authenticate_preregistration(args.root)
        budget = NetworkBudget()
        payload = collect_source_bindings(
            selected,
            GitHubTransport(token, budget),
            budget,
            collected_at=_utc_now(),
            collector_sha256=collector_sha256(),
        )
        validate_payload(payload, selected)
        _publish_no_clobber(args.output, _canonical_bytes(payload))
        print(json.dumps({"records": len(payload["records"]), "output": str(args.output)}))
        return 0
    if args.validate is not None:
        if args.checksums is None or args.output is not None:
            parser.error("--validate requires --checksums")
        payload = validate_authenticated(args.root, args.validate, args.checksums)
        print(
            json.dumps(
                {
                    "records": len(payload["records"]),
                    "hash": _sha256(_read_bounded(args.validate, _MAX_OUTPUT_BYTES)),
                },
                sort_keys=True,
            )
        )
        return 0
    parser.error("choose --collect or --validate")


if __name__ == "__main__":
    raise SystemExit(main())
