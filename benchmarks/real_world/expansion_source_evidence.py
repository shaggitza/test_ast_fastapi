#!/usr/bin/env python3
"""Collect bounded, inert source declarations for the frozen GH #103 v1 lock."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from benchmarks.real_world import expansion_protocol as frozen

if TYPE_CHECKING:
    from collections.abc import Callable

SCHEMA_VERSION = 2
POLICY_ID = "gh103-source-evidence-policy-v1"
POLICY_PROFILE = Path(__file__).with_name("expansion") / "source-evidence-v1-policy.json"
MAX_REQUESTS = 1500
TREE_REQUESTS = 200
BLOB_REQUESTS = 1200
OVERHEAD_REQUESTS = 100
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_WALL_SECONDS = 20 * 60
MAX_FILE_BYTES = 1024 * 1024
MAX_SIDE_SOURCE_BYTES = 8 * 1024 * 1024
MAX_REPORT_BYTES = 20 * 1024 * 1024
MAX_RECEIPT_BYTES = 1024 * 1024
MAX_TREE_ENTRIES = 1_000_000
MAX_TREE_PAGES_PER_SIDE = 10
MAX_CANDIDATES_PER_SIDE = 6
DIAGNOSTIC_MAX_REQUESTS = 25
DIAGNOSTIC_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
DIAGNOSTIC_MAX_TOTAL_BYTES = 20 * 1024 * 1024
DIAGNOSTIC_MAX_WALL_SECONDS = 10 * 60
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
API_ROUTE_RE = re.compile(
    r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/"
    r"(?:git/trees/[0-9a-f]{40}(?:\?recursive=1)?|git/blobs/[0-9a-f]{40}|commits/[0-9a-f]{40})$"
)
STATUSES = {"observed", "missing", "uncertain", "multiple_or_conflicting", "unsupported"}
REASON_CODES = {
    "candidate_limit",
    "file_oversize",
    "invalid_utf8",
    "multiple_evidence_items",
    "no_candidate_paths",
    "parse_error",
    "source_byte_limit",
    "source_unavailable_http_301",
    "source_unavailable_http_404",
    "source_unavailable_http_410",
    "tree_entry_limit",
    "tree_incomplete",
    "tree_page_limit",
    "tree_page_truncated",
    "tree_page_unavailable",
    "tree_repeated_sha",
    "tree_truncation_flag_invalid",
    "unsupported_syntax",
}
PYTHON_FILES = {"pyproject.toml", "setup.cfg", "tox.ini", ".python-version"}
LICENSE_NAMES = {"license", "licence", "copying", "notice"}
DEPENDENCY_RE = re.compile(
    r"^(?:requirements(?:[-_.].*)?|constraints(?:[-_.].*)?|Pipfile|poetry\.lock|uv\.lock|pdm\.lock|"
    r"conda.*\.ya?ml|environment.*\.ya?ml|pyproject\.toml|setup\.py|setup\.cfg|tox\.ini)$",
    re.IGNORECASE,
)
REQ_LINE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*(\[[^]]+\])?\s*([<>=!~].*)?\s*$")


class EvidenceError(ValueError):
    """Fail-closed collection or validation failure; messages never contain URLs or secrets."""


def _http_status_code(status: int) -> str:
    """Map finite response statuses to sanitized outcomes."""
    if status in {301, 404, 410}:
        return f"source_unavailable_http_{status}"
    if status in {401, 403}:
        return f"github_http_{status}"
    return "github_transport_failure"


@dataclass
class Budget:
    started: float
    max_requests: int = MAX_REQUESTS
    max_response_bytes: int = MAX_RESPONSE_BYTES
    max_total_bytes: int = MAX_TOTAL_BYTES
    max_wall_seconds: int = MAX_WALL_SECONDS
    requests: int = 0
    tree_requests: int = 0
    blob_requests: int = 0
    overhead_requests: int = 0
    response_bytes: int = 0
    response_bytes_unknown: bool = False
    pages: int = 0
    attempts: list[dict[str, Any]] | None = None

    def reserve(self, kind: str) -> None:
        elapsed = time.monotonic() - self.started
        if elapsed > self.max_wall_seconds:
            raise EvidenceError("wall_budget_exhausted")
        if self.requests >= self.max_requests:
            raise EvidenceError("request_budget_exhausted")
        if kind == "tree":
            if self.tree_requests >= TREE_REQUESTS:
                raise EvidenceError("tree_request_budget_exhausted")
            self.tree_requests += 1
        elif kind == "blob":
            if self.blob_requests >= BLOB_REQUESTS:
                raise EvidenceError("blob_request_budget_exhausted")
            self.blob_requests += 1
        else:
            if self.overhead_requests >= OVERHEAD_REQUESTS:
                raise EvidenceError("overhead_request_budget_exhausted")
            self.overhead_requests += 1
        self.requests += 1
        self.pages += 1
        if self.attempts is not None:
            self.attempts.append(
                {
                    "kind": kind,
                    "response_status": None,
                    "response_bytes": None,
                    "response_bytes_complete": False,
                    "error_class": None,
                }
            )

    def finish_attempt(
        self,
        status: int | None,
        size: int | None,
        error_class: str | None = None,
        complete: bool = True,
    ) -> None:
        if self.attempts is not None and self.attempts:
            attempt = self.attempts[-1]
            attempt["response_status"] = status
            attempt["response_bytes"] = size
            attempt["response_bytes_complete"] = complete
            attempt["error_class"] = error_class

    def read_limit(self) -> int:
        return max(0, min(self.max_response_bytes, self.max_total_bytes - self.response_bytes))

    def consume(self, size: int) -> None:
        self.response_bytes += size
        if self.response_bytes > self.max_total_bytes:
            raise EvidenceError("response_byte_budget_exhausted")

    def report(self) -> dict[str, int | float]:
        elapsed = time.monotonic() - self.started
        if elapsed > self.max_wall_seconds:
            raise EvidenceError("wall_budget_exhausted")
        return {
            "requests": self.requests,
            "tree_requests": self.tree_requests,
            "blob_requests": self.blob_requests,
            "overhead_requests": self.overhead_requests,
            "pages": self.pages,
            "response_bytes": self.response_bytes,
            "wall_seconds": round(elapsed, 3),
        }


class GitHubTransport:
    """Fixed-origin GitHub API client. Caller may inject an inert synthetic responder."""

    def __init__(
        self, token: str | None, budget: Budget, responder: Callable[[str], bytes] | None = None
    ):
        self._token = token
        self._budget = budget
        self._responder = responder

    def get_json(self, route: str, kind: str) -> Any:  # noqa: PLR0912, PLR0915
        if not API_ROUTE_RE.fullmatch(route):
            raise EvidenceError("endpoint_rejected")
        self._budget.reserve(kind)
        url = "https://api.github.com" + route
        if self._responder is not None:
            try:
                raw = self._responder(url)
            except urllib.error.HTTPError as exc:
                read_limit = self._budget.read_limit()
                try:
                    error_body = exc.read(read_limit + 1)
                except OSError:
                    self._budget.finish_attempt(exc.code, None, "http_error_read_error", False)
                    self._budget.response_bytes_unknown = True
                    raise EvidenceError("github_transport_failure") from None
                self._budget.finish_attempt(
                    exc.code, len(error_body), "http_error", len(error_body) <= read_limit
                )
                self._budget.consume(len(error_body))
                if len(error_body) > read_limit:
                    raise EvidenceError("response_limit_exceeded") from None
                raise EvidenceError(_http_status_code(exc.code)) from None
            except Exception:
                self._budget.finish_attempt(None, None, "synthetic_transport_error", False)
                self._budget.response_bytes_unknown = True
                raise EvidenceError("synthetic_transport_failure") from None
            read_limit = self._budget.read_limit()
            raw = raw[: read_limit + 1]
            attempt_error = (
                "response_limit_exceeded"
                if len(raw) > read_limit and read_limit == self._budget.max_response_bytes
                else "response_byte_budget_exhausted"
                if self._budget.response_bytes + len(raw) > self._budget.max_total_bytes
                else None
            )
            self._budget.finish_attempt(200, len(raw), attempt_error, len(raw) <= read_limit)
        else:
            request = urllib.request.Request(
                url,
                headers={
                    "Accept": "application/vnd.github+json",
                    "User-Agent": "gh103-source-evidence-v1",
                    "X-GitHub-Api-Version": "2022-11-28",
                    **({"Authorization": f"Bearer {self._token}"} if self._token else {}),
                },
            )
            opener = urllib.request.build_opener(_NoRedirect())
            try:
                with opener.open(request, timeout=20) as response:
                    if response.geturl() != url:
                        self._budget.finish_attempt(
                            getattr(response, "status", None), 0, "redirect"
                        )
                        raise EvidenceError("redirect_rejected")
                    read_limit = self._budget.read_limit()
                    try:
                        raw = response.read(read_limit + 1)
                    except OSError as exc:
                        partial = getattr(exc, "partial", None)
                        known = len(partial) if isinstance(partial, bytes) else None
                        self._budget.finish_attempt(
                            getattr(response, "status", 200), known, "os_error", False
                        )
                        if known is None:
                            self._budget.response_bytes_unknown = True
                        else:
                            self._budget.consume(known)
                        raise EvidenceError("github_transport_failure") from None
                    attempt_error = (
                        "response_limit_exceeded"
                        if len(raw) > read_limit and read_limit == self._budget.max_response_bytes
                        else "response_byte_budget_exhausted"
                        if len(raw) > read_limit
                        else None
                    )
                    self._budget.finish_attempt(
                        getattr(response, "status", 200),
                        len(raw),
                        attempt_error,
                        len(raw) <= read_limit,
                    )
                    self._budget.consume(len(raw))
                    if len(raw) > read_limit:
                        raise EvidenceError("response_limit_exceeded")
            except EvidenceError:
                raise
            except urllib.error.HTTPError as exc:
                read_limit = self._budget.read_limit()
                try:
                    error_body = exc.read(read_limit + 1)
                except OSError as read_exc:
                    partial = getattr(read_exc, "partial", None)
                    known = len(partial) if isinstance(partial, bytes) else None
                    self._budget.finish_attempt(exc.code, known, "http_error_read_error", False)
                    if known is None:
                        self._budget.response_bytes_unknown = True
                    else:
                        self._budget.consume(known)
                    raise EvidenceError("github_transport_failure") from None
                self._budget.finish_attempt(
                    exc.code, len(error_body), "http_error", len(error_body) <= read_limit
                )
                self._budget.consume(len(error_body))
                if len(error_body) > read_limit:
                    raise EvidenceError("response_limit_exceeded") from None
                raise EvidenceError(_http_status_code(exc.code)) from None
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                error_class = (
                    "timeout"
                    if isinstance(exc, TimeoutError)
                    else "url_error"
                    if isinstance(exc, urllib.error.URLError)
                    else "os_error"
                )
                self._budget.finish_attempt(None, None, error_class, False)
                self._budget.response_bytes_unknown = True
                raise EvidenceError("github_transport_failure") from None
        if self._responder is not None:
            self._budget.consume(len(raw))
        if len(raw) > self._budget.max_response_bytes:
            raise EvidenceError("response_limit_exceeded")
        try:
            return json.loads(raw, object_pairs_hook=_unique_object)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise EvidenceError("invalid_api_json") from None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        del req, fp, code, msg, headers, newurl


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("duplicate_json_key")
        result[key] = value
    return result


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_identity_digest(lock: dict[str, Any]) -> str:
    identities = [
        {key: row[key] for key in ("repository", "pr", "base_sha", "head_sha")}
        for row in lock["records"]
    ]
    encoded = json.dumps(identities, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{_sha256(encoded)}"


def _git_blob_sha(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def _safe_path(path: object) -> bool:
    if not isinstance(path, str) or not path or "\x00" in path or path.startswith("/"):
        return False
    parts = path.split("/")
    return all(part not in {"", ".", ".."} for part in parts)


def _license_candidate(path: str) -> bool:
    name = path.rsplit("/", 1)[-1].casefold()
    return any(
        name == stem
        or name.startswith(f"{stem}.")
        or name.startswith(f"{stem}-")
        or name.startswith(f"{stem}_")
        for stem in LICENSE_NAMES
    )


def _candidate_groups(paths: list[str]) -> dict[str, list[str]]:
    python = sorted(path for path in paths if path.casefold() in PYTHON_FILES)
    license = sorted(
        (path for path in paths if _license_candidate(path)),
        key=lambda p: ("/" in p, p.casefold(), p),
    )
    deps = sorted(path for path in paths if DEPENDENCY_RE.fullmatch(path.rsplit("/", 1)[-1]))
    return {"python_versions": python, "license": license, "dependencies": deps}


def _select_candidates(groups: dict[str, list[str]]) -> tuple[list[str], dict[str, int]]:
    # Root Python metadata, root licenses, root dependency files, then lexical remainder.
    ordered = list(
        dict.fromkeys(
            path
            for group in ("python_versions", "license", "dependencies")
            for path in sorted(groups[group])
            if "/" not in path
        )
    )
    ordered.extend(
        path
        for path in sorted({path for candidates in groups.values() for path in candidates})
        if path not in ordered
    )
    selected = ordered[:MAX_CANDIDATES_PER_SIDE]
    omitted = {key: sum(path not in selected for path in values) for key, values in groups.items()}
    return selected, omitted


def _enumerate_tree(  # noqa: PLR0912, PLR0915
    repo: str, commit: str, api: GitHubTransport
) -> tuple[list[dict[str, Any]], bool, list[str]]:
    owner, name = repo.split("/", 1)
    quoted = urllib.parse.quote
    force_walk = False
    try:
        initial = api.get_json(
            f"/repos/{quoted(owner)}/{quoted(name)}/git/trees/{commit}?recursive=1", "tree"
        )
    except EvidenceError as exc:
        if str(exc) != "response_limit_exceeded":
            raise
        commit_data = api.get_json(
            f"/repos/{quoted(owner)}/{quoted(name)}/commits/{commit}", "overhead"
        )
        if not isinstance(commit_data, dict) or commit_data.get("sha") != commit:
            raise EvidenceError("commit_identity_invalid") from None
        commit_tree = commit_data.get("commit", {}).get("tree", {})
        tree_sha = commit_tree.get("sha") if isinstance(commit_tree, dict) else None
        if not isinstance(tree_sha, str) or not SHA_RE.fullmatch(tree_sha):
            raise EvidenceError("tree_identity_invalid") from None
        initial = {"sha": tree_sha, "tree": [], "truncated": True}
        force_walk = True
    if (
        not isinstance(initial, dict)
        or not isinstance(initial.get("tree"), list)
        or not SHA_RE.fullmatch(str(initial.get("sha", "")))
    ):
        raise EvidenceError("tree_identity_invalid")
    entries: list[dict[str, Any]] = []
    errors: list[str] = []
    seen: set[str] = set()

    def ingest(tree: Any) -> None:
        if not isinstance(tree, list):
            raise EvidenceError("tree_shape_invalid")
        for item in tree:
            if not isinstance(item, dict) or not _safe_path(item.get("path")):
                raise EvidenceError("tree_path_invalid")
            path = item["path"]
            if item.get("type") not in {"blob", "tree", "commit"}:
                raise EvidenceError("tree_entry_type_invalid")
            if item["type"] == "blob":
                if (
                    not SHA_RE.fullmatch(str(item.get("sha", "")))
                    or type(item.get("size")) is not int
                    or item["size"] < 0
                ):
                    raise EvidenceError("tree_blob_identity_invalid")
                entries.append(
                    {"path": path, "sha": item["sha"], "size": item["size"], "type": "blob"}
                )
            elif item["type"] == "tree":
                if not SHA_RE.fullmatch(str(item.get("sha", ""))):
                    raise EvidenceError("tree_identity_invalid")
                seen.add(item["sha"])

    truncated_flag = initial.get("truncated")
    if type(truncated_flag) is not bool:
        return [], False, ["tree_truncation_flag_invalid"]
    ingest(initial["tree"])
    truncated = force_walk or truncated_flag
    if truncated:
        queue: deque[tuple[str, str]] = deque()
        for item in initial["tree"]:
            if item.get("type") == "tree":
                queue.append((item["path"], item["sha"]))
        # The recursive response can be partial; re-traverse from the root tree SHA.
        queue.clear()
        queue.append(("", initial["sha"]))
        entries.clear()
        seen = set()
        tree_pages = 0
        while queue:
            if tree_pages >= MAX_TREE_PAGES_PER_SIDE:
                errors.append("tree_page_limit")
                break
            prefix, tree_sha = queue.popleft()
            if tree_sha in seen:
                errors.append("tree_repeated_sha")
                continue
            seen.add(tree_sha)
            try:
                result = api.get_json(
                    f"/repos/{quoted(owner)}/{quoted(name)}/git/trees/{tree_sha}", "overhead"
                )
                tree_pages += 1
            except EvidenceError as exc:
                reason = str(exc)
                if reason in {
                    "source_unavailable_http_301",
                    "source_unavailable_http_404",
                    "source_unavailable_http_410",
                }:
                    errors.extend(("tree_page_unavailable", reason))
                    break
                if reason == "response_limit_exceeded":
                    errors.append("tree_page_unavailable")
                    break
                raise
            if (
                not isinstance(result, dict)
                or result.get("sha") != tree_sha
                or not isinstance(result.get("tree"), list)
            ):
                errors.append("tree_incomplete")
                break
            page_truncated = result.get("truncated")
            if type(page_truncated) is not bool:
                errors.append("tree_truncation_flag_invalid")
                break
            if page_truncated:
                errors.append("tree_page_truncated")
                break
            for item in result["tree"]:
                if not isinstance(item, dict) or not _safe_path(item.get("path")):
                    raise EvidenceError("tree_path_invalid")
                path = f"{prefix}/{item['path']}" if prefix else item["path"]
                if item.get("type") == "tree":
                    if not SHA_RE.fullmatch(str(item.get("sha", ""))):
                        raise EvidenceError("tree_identity_invalid")
                    if item["sha"] in seen or any(
                        queued_sha == item["sha"] for _, queued_sha in queue
                    ):
                        errors.append("tree_repeated_sha")
                    else:
                        queue.append((path, item["sha"]))
                elif item.get("type") == "blob":
                    if (
                        not SHA_RE.fullmatch(str(item.get("sha", "")))
                        or type(item.get("size")) is not int
                        or item["size"] < 0
                    ):
                        raise EvidenceError("tree_blob_identity_invalid")
                    entries.append(
                        {"path": path, "sha": item["sha"], "size": item["size"], "type": "blob"}
                    )
                else:
                    raise EvidenceError("tree_entry_type_invalid")
                if len(entries) + len(queue) > MAX_TREE_ENTRIES:
                    errors.append("tree_entry_limit")
                    queue.clear()
                    break
    if len(entries) > MAX_TREE_ENTRIES:
        errors.append("tree_entry_limit")
        entries = entries[:MAX_TREE_ENTRIES]
    paths_seen: set[str] = set()
    for item in entries:
        if item["path"] in paths_seen:
            raise EvidenceError("duplicate_tree_path")
        paths_seen.add(item["path"])
    return sorted(entries, key=lambda item: item["path"]), not errors, errors


def _fetch_blob(repo: str, entry: dict[str, Any], api: GitHubTransport) -> bytes:
    owner, name = repo.split("/", 1)
    result = api.get_json(
        f"/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(name)}/git/blobs/{entry['sha']}",
        "blob",
    )
    if (
        not isinstance(result, dict)
        or result.get("sha") != entry["sha"]
        or result.get("encoding") != "base64"
    ):
        raise EvidenceError("blob_reference_mismatch")
    if type(result.get("size")) is not int or result["size"] != entry["size"]:
        raise EvidenceError("blob_size_mismatch")
    encoded = result.get("content")
    if not isinstance(encoded, str):
        raise EvidenceError("blob_content_invalid")
    try:
        # GitHub may line-wrap base64; accept CR/LF only as representation whitespace.
        if any(char.isspace() and char not in "\r\n" for char in encoded):
            raise ValueError
        raw = base64.b64decode(encoded.replace("\r", "").replace("\n", ""), validate=True)
    except (ValueError, binascii.Error):
        raise EvidenceError("blob_base64_invalid") from None
    if len(raw) != entry["size"] or _git_blob_sha(raw) != entry["sha"]:
        raise EvidenceError("blob_identity_mismatch")
    return raw


def _source_ref(commit: str, path: str, entry: dict[str, Any], raw: bytes) -> dict[str, Any]:
    return {
        "commit_sha": commit,
        "path": path,
        "blob_sha": entry["sha"],
        "size": len(raw),
        "content_sha256": _sha256(raw),
    }


def _valid_python_constraint(value: str) -> bool:
    spec = r"(?:===|==|!=|~=|<=|>=|<|>)\s*\d+(?:\.\d+){0,2}(?:\.\*)?"
    return bool(value.strip()) and all(
        re.fullmatch(spec, part.strip()) for part in value.split(",")
    )


def _valid_spdx_expression(value: str) -> bool:  # noqa: PLR0911, PLR0912
    token_pattern = re.compile(r"\s*(\(|\)|[A-Za-z0-9][A-Za-z0-9.+:-]*)")
    tokens = []
    offset = 0
    while offset < len(value):
        match = token_pattern.match(value, offset)
        if match is None:
            return False
        tokens.append(match.group(1))
        offset = match.end()
    if not tokens:
        return False
    depth = 0
    expect_operand = True
    for token in tokens:
        if token == "(":
            if not expect_operand:
                return False
            depth += 1
        elif token == ")":
            if expect_operand:
                return False
            depth -= 1
            if depth < 0:
                return False
        elif token.upper() in {"AND", "OR", "WITH"}:
            if expect_operand:
                return False
            expect_operand = True
        else:
            if not expect_operand:
                return False
            expect_operand = False
    return depth == 0 and not expect_operand


def _parse_python(path: str, text: str) -> list[dict[str, Any]]:  # noqa: PLR0912
    facts: list[dict[str, Any]] = []
    if path == ".python-version":
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        value = lines[0] if len(lines) == 1 else ""
        if not re.fullmatch(r"\d+\.\d+(?:\.\d+)?", value):
            raise NotImplementedError
        facts.append({"kind": "literal", "value": value, "rule_id": "python-version-literal-v1"})
    elif path.endswith("pyproject.toml"):
        data = tomllib.loads(text)
        raw_value = (
            data.get("project", {}).get("requires-python")
            if isinstance(data.get("project"), dict)
            else None
        )
        requires_value: str | None = raw_value if isinstance(raw_value, str) else None
        if raw_value is not None and requires_value is None:
            raise NotImplementedError
        if requires_value is not None:
            if not _valid_python_constraint(requires_value):
                raise NotImplementedError
            facts.append(
                {
                    "kind": "requires-python",
                    "expression": requires_value,
                    "rule_id": "pyproject-requires-python-v1",
                }
            )
    elif path.endswith("setup.cfg"):
        section = ""
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                section = stripped[1:-1].casefold()
            elif (
                section == "options"
                and stripped.casefold().startswith("python_requires")
                and "=" in stripped
            ):
                value = stripped.split("=", 1)[1].strip()
                if not _valid_python_constraint(value):
                    raise NotImplementedError
                facts.append(
                    {
                        "kind": "python_requires",
                        "expression": value,
                        "rule_id": "setup-cfg-python-requires-v1",
                    }
                )
    elif path.endswith("tox.ini"):
        section = ""
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                section = stripped[1:-1].casefold()
            elif section == "tox" and stripped.casefold().startswith("envlist") and "=" in stripped:
                value = stripped.split("=", 1)[1].strip()
                tokens = [token.strip() for token in value.split(",")]
                factors: list[str] = []
                for token in tokens:
                    match = re.fullmatch(r"py(3(?:\.\d+|\d{1,2})?)(?:-[A-Za-z0-9_.-]+)?", token)
                    if match is None:
                        raise NotImplementedError
                    raw_factor = match.group(1)
                    normalized = (
                        f"3.{raw_factor[1:]}"
                        if "." not in raw_factor and len(raw_factor) > 1
                        else raw_factor
                    )
                    factors.append(normalized)
                if not factors or any(ch in value for ch in "{}$"):
                    raise NotImplementedError
                factors = sorted(set(factors))
                facts.append(
                    {
                        "kind": "tox-envlist",
                        "values": factors,
                        "rule_id": "tox-envlist-python-factors-v1",
                    }
                )
    return facts


def _group_result(  # noqa: PLR0912, PLR0915
    group: str,
    paths: list[str],
    selected: set[str],
    omitted: int,
    tree_complete: bool,
    contents: dict[str, tuple[dict[str, Any], bytes]],
    commit: str,
    tree_errors: list[str],
    unavailable: dict[str, str],
) -> dict[str, Any]:
    candidates = [path for path in paths if path in selected]
    refs: list[dict[str, Any]] = []
    facts: list[dict[str, Any]] = []
    reasons: set[str] = set()
    parsed_count = 0
    unsupported_count = 0
    for path in candidates:
        if path not in contents:
            reasons.add(unavailable.get(path, "file_oversize"))
            continue
        entry, raw = contents[path]
        refs.append(_source_ref(commit, path, entry, raw))
        if len(raw) > MAX_FILE_BYTES:
            reasons.add("file_oversize")
            continue
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            reasons.add("invalid_utf8")
            continue
        try:
            if group == "python_versions":
                found = _parse_python(path, text)
            elif group == "license":
                expressions = re.findall(r"(?im)^\s*SPDX-License-Identifier:\s*([^\r\n]+)", text)
                if any(not _valid_spdx_expression(item.strip()) for item in expressions):
                    raise ValueError("spdx_expression_invalid")
                found = [
                    {
                        "kind": "spdx_identifier_expression",
                        "expression": item.strip(),
                        "rule_id": "spdx-line-v1",
                    }
                    for item in expressions
                ]
                if not found:
                    found = [{"kind": "license_file_present", "rule_id": "license-presence-v1"}]
            else:
                found = _parse_dependencies(path, text)
            if found:
                if any(fact.get("form") == "dynamic_or_unsupported" for fact in found):
                    unsupported_count += 1
                    reasons.add("unsupported_syntax")
                else:
                    parsed_count += 1
                facts.extend({"path": path, **fact} for fact in found)
            else:
                unsupported_count += 1
        except (NotImplementedError, TypeError):
            unsupported_count += 1
            reasons.add("unsupported_syntax")
        except ValueError:
            reasons.add("parse_error")
    if omitted:
        reasons.add("candidate_limit")
    if not tree_complete:
        reasons.add("tree_incomplete")
        reasons.update(tree_errors)
    if reasons & {
        "file_oversize",
        "source_byte_limit",
        "invalid_utf8",
        "parse_error",
        "candidate_limit",
        "tree_incomplete",
        "source_unavailable_http_301",
        "source_unavailable_http_404",
        "source_unavailable_http_410",
    }:
        status = "uncertain"
    elif parsed_count and unsupported_count:
        # Recognized facts remain observed; unsupported files are counted separately.
        status = "observed"
    elif parsed_count:
        status = "observed"
    elif unsupported_count:
        status = "unsupported"
        reasons.add("unsupported_syntax")
    elif paths and not candidates:
        status = "uncertain"
        reasons.add("candidate_limit")
    elif not tree_complete:
        status = "uncertain"
    else:
        status = "missing"
        reasons.add("no_candidate_paths")
    if group == "dependencies":
        declarations: bool | None = True if facts else (False if status == "missing" else None)
    else:
        declarations = None
    if status == "observed":
        conflict = False
        if group == "license":
            conflict = len(refs) > 1
        elif group == "python_versions":
            values = {json.dumps(fact, sort_keys=True) for fact in facts}
            conflict = len(values) > 1
        else:
            specs: dict[str, set[str]] = {}
            for fact in facts:
                if fact.get("kind") == "declared_dependency":
                    specs.setdefault(str(fact.get("name", "")).casefold(), set()).add(
                        str(fact.get("specifier", ""))
                    )
            conflict = any(len(items) > 1 for items in specs.values())
        if conflict:
            status = "multiple_or_conflicting"
            reasons.add("multiple_evidence_items")
    return {
        "status": status,
        "reason_codes": sorted(reasons),
        "declarations_present": declarations,
        "candidate_count": len(paths),
        "omitted_candidate_count": omitted,
        "omitted_candidate_paths": sorted(path for path in paths if path not in selected),
        "unknown_count": (
            None
            if any(
                reason in reasons
                for reason in (
                    "source_unavailable_http_301",
                    "source_unavailable_http_404",
                    "source_unavailable_http_410",
                )
            )
            else unsupported_count
        ),
        "sources": refs,
        "facts": facts,
    }


def _parse_dependencies(path: str, text: str) -> list[dict[str, Any]]:
    if path.rsplit("/", 1)[-1].casefold() == "setup.py":
        return [
            {
                "kind": "declaration_file_present",
                "form": "dynamic_or_unsupported",
                "rule_id": "setup-py-inert-presence-v1",
            }
        ]
    if path.endswith("pyproject.toml"):
        data = tomllib.loads(text)
        project = data.get("project", {})
        deps = project.get("dependencies", []) if isinstance(project, dict) else []
        optional = project.get("optional-dependencies", {}) if isinstance(project, dict) else {}
        if not isinstance(deps, list) or not isinstance(optional, dict):
            raise NotImplementedError
        if any(not isinstance(group, list) for group in optional.values()):
            raise NotImplementedError
        names = []
        for item in deps + [
            dep for group in optional.values() if isinstance(group, list) for dep in group
        ]:
            if not isinstance(item, str):
                raise NotImplementedError
            match = REQ_LINE.fullmatch(item)
            if not match:
                raise NotImplementedError
            names.append({"name": match.group(1), "specifier": match.group(3) or ""})
        return [
            {"kind": "declared_dependency", **item, "rule_id": "pyproject-static-dependencies-v1"}
            for item in names
        ]
    if path.rsplit("/", 1)[-1].casefold().startswith(
        ("requirements", "constraints")
    ) and path.casefold().endswith(".txt"):
        facts = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("-"):
                raise NotImplementedError
            match = REQ_LINE.fullmatch(line)
            if not match:
                raise NotImplementedError
            facts.append(
                {
                    "kind": "declared_dependency",
                    "name": match.group(1),
                    "specifier": match.group(3) or "",
                    "rule_id": "requirements-static-line-v1",
                }
            )
        return facts or [
            {
                "kind": "declaration_file_present",
                "form": "empty_requirements_file",
                "rule_id": "requirements-presence-v1",
            }
        ]
    return [
        {
            "kind": "declaration_file_present",
            "form": "format_present_unparsed",
            "rule_id": "declaration-file-presence-v1",
        }
    ]


def collect_side(repo: str, commit: str, api: GitHubTransport) -> dict[str, Any]:
    try:
        entries, complete, tree_errors = _enumerate_tree(repo, commit, api)
    except EvidenceError as exc:
        if str(exc) not in {
            "source_unavailable_http_301",
            "source_unavailable_http_404",
            "source_unavailable_http_410",
        }:
            raise
        reason = str(exc)
        return {
            group: {
                "status": "uncertain",
                "reason_codes": sorted(["tree_incomplete", reason]),
                "declarations_present": None,
                "candidate_count": None,
                "omitted_candidate_count": None,
                "omitted_candidate_paths": [],
                "unknown_count": None,
                "sources": [],
                "facts": [],
            }
            for group in ("python_versions", "license", "dependencies")
        }
    paths = [item["path"] for item in entries if item["type"] == "blob"]
    groups = _candidate_groups(paths)
    selected_paths, omitted = _select_candidates(groups)
    entry_by_path = {item["path"]: item for item in entries}
    contents: dict[str, tuple[dict[str, Any], bytes]] = {}
    unavailable: dict[str, str] = {}
    bytes_used = 0
    for path in selected_paths:
        entry = entry_by_path[path]
        if entry["size"] > MAX_FILE_BYTES:
            unavailable[path] = "file_oversize"
            continue
        if bytes_used + entry["size"] > MAX_SIDE_SOURCE_BYTES:
            unavailable[path] = "source_byte_limit"
            continue
        try:
            raw = _fetch_blob(repo, entry, api)
        except EvidenceError as exc:
            if str(exc) not in {
                "source_unavailable_http_301",
                "source_unavailable_http_404",
                "source_unavailable_http_410",
            }:
                raise
            unavailable[path] = str(exc)
            continue
        bytes_used += len(raw)
        contents[path] = (entry, raw)
    return {
        group: _group_result(
            group,
            candidate_paths,
            set(selected_paths),
            omitted[group],
            complete,
            contents,
            commit,
            tree_errors,
            unavailable,
        )
        for group, candidate_paths in groups.items()
    }


def build_report(
    lock: dict[str, Any], hashes: dict[str, str], api: GitHubTransport, budget: Budget
) -> dict[str, Any]:
    records = []
    for locked in lock["records"]:
        sides = {}
        for side in ("base", "head"):
            commit = locked[f"{side}_sha"]
            sides[side] = {
                "commit_sha": commit,
                **collect_side(locked["repository"], commit, api),
            }
        records.append(
            {
                "identity": {
                    key: locked[key] for key in ("repository", "pr", "base_sha", "head_sha")
                },
                **sides,
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "id": "gh103-v2-source-evidence",
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source_evidence_collector_sha256": f"sha256:{_sha256(Path(__file__).read_bytes())}",
        "source_policy_sha256": f"sha256:{_sha256(POLICY_PROFILE.read_bytes())}",
        "lock_sha256": hashes["lock"],
        "manifest_sha256": hashes["manifest"],
        "longlist_sha256": hashes["longlist"],
        "source_policy_id": POLICY_ID,
        "network_budget": {
            **budget.report(),
            "limits": {
                "requests": MAX_REQUESTS,
                "tree_requests": TREE_REQUESTS,
                "blob_requests": BLOB_REQUESTS,
                "overhead_requests": OVERHEAD_REQUESTS,
                "response_bytes": MAX_TOTAL_BYTES,
                "wall_seconds": MAX_WALL_SECONDS,
            },
        },
        "records": records,
    }


def validate_report(  # noqa: PLR0912
    report: dict[str, Any], lock: dict[str, Any], expected_lock_sha256: str
) -> None:
    _validate_serialized_report(report)
    expected = {
        "schema_version",
        "id",
        "created_at",
        "source_evidence_collector_sha256",
        "source_policy_sha256",
        "lock_sha256",
        "manifest_sha256",
        "longlist_sha256",
        "source_policy_id",
        "network_budget",
        "records",
    }
    if (
        set(report) != expected
        or report["schema_version"] != SCHEMA_VERSION
        or report["id"] != "gh103-v2-source-evidence"
        or report["source_policy_id"] != POLICY_ID
    ):
        raise EvidenceError("report_schema_invalid")
    if len(report["records"]) != 100 or len(lock["records"]) != 100:
        raise EvidenceError("report_identity_count_invalid")
    if (
        report["manifest_sha256"] != lock["manifest_hash"]
        or report["longlist_sha256"] != lock["longlist_hash"]
        or report["lock_sha256"] != expected_lock_sha256
        or report["source_policy_sha256"] != f"sha256:{_sha256(POLICY_PROFILE.read_bytes())}"
        or report["source_evidence_collector_sha256"]
        != f"sha256:{_sha256(Path(__file__).read_bytes())}"
    ):
        raise EvidenceError("report_provenance_mismatch")
    for evidence, frozen_record in zip(report["records"], lock["records"], strict=True):
        identity = {key: frozen_record[key] for key in ("repository", "pr", "base_sha", "head_sha")}
        if evidence.get("identity") != identity:
            raise EvidenceError("report_lock_identity_mismatch")
        for side in ("base", "head"):
            facts = evidence.get(side)
            if (
                not isinstance(facts, dict)
                or facts.get("commit_sha") != frozen_record[f"{side}_sha"]
            ):
                raise EvidenceError("report_side_identity_mismatch")
            for group in ("python_versions", "license", "dependencies"):
                item = facts.get(group)
                if (
                    not isinstance(item, dict)
                    or not isinstance(item.get("status"), str)
                    or item["status"] not in STATUSES
                ):
                    raise EvidenceError("report_status_invalid")
                if (
                    not isinstance(item.get("reason_codes"), list)
                    or any(not isinstance(code, str) for code in item["reason_codes"])
                    or any(code not in REASON_CODES for code in item["reason_codes"])
                    or (item["status"] != "observed" and not item["reason_codes"])
                ):
                    raise EvidenceError("report_reason_missing")
                sources = item.get("sources")
                facts_list = item.get("facts")
                if not isinstance(sources, list) or not isinstance(facts_list, list):
                    raise EvidenceError("report_group_content_invalid")
                if any(
                    not isinstance(source, dict)
                    or source.get("commit_sha") != frozen_record[f"{side}_sha"]
                    for source in sources
                ):
                    raise EvidenceError("report_source_commit_mismatch")
                for fact in facts_list:
                    _validate_fact(group, fact)


def _validate_serialized_report(report: Any) -> None:  # noqa: PLR0912, PLR0915
    expected = {
        "schema_version",
        "id",
        "created_at",
        "source_evidence_collector_sha256",
        "source_policy_sha256",
        "lock_sha256",
        "manifest_sha256",
        "longlist_sha256",
        "source_policy_id",
        "network_budget",
        "records",
    }
    if not isinstance(report, dict) or set(report) != expected:
        raise EvidenceError("report_schema_invalid")
    if (
        report.get("schema_version") != SCHEMA_VERSION
        or type(report.get("schema_version")) is not int
        or report.get("id") != "gh103-v2-source-evidence"
        or report.get("source_policy_id") != POLICY_ID
    ):
        raise EvidenceError("report_version_invalid")
    try:
        created = datetime.fromisoformat(str(report["created_at"]).replace("Z", "+00:00"))
    except ValueError:
        raise EvidenceError("report_timestamp_invalid") from None
    if created.utcoffset() != timezone.utc.utcoffset(created):
        raise EvidenceError("report_timestamp_invalid")
    for key in (
        "source_evidence_collector_sha256",
        "source_policy_sha256",
        "lock_sha256",
        "manifest_sha256",
        "longlist_sha256",
    ):
        if not isinstance(report[key], str) or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", report[key]
        ):
            raise EvidenceError("report_digest_invalid")
    budget = report["network_budget"]
    if not isinstance(budget, dict) or set(budget) != {
        "requests",
        "tree_requests",
        "blob_requests",
        "overhead_requests",
        "pages",
        "response_bytes",
        "wall_seconds",
        "limits",
    }:
        raise EvidenceError("report_budget_schema_invalid")
    expected_limits = {
        "requests": MAX_REQUESTS,
        "tree_requests": TREE_REQUESTS,
        "blob_requests": BLOB_REQUESTS,
        "overhead_requests": OVERHEAD_REQUESTS,
        "response_bytes": MAX_TOTAL_BYTES,
        "wall_seconds": MAX_WALL_SECONDS,
    }
    if budget["limits"] != expected_limits:
        raise EvidenceError("report_budget_limits_invalid")
    for name, maximum in (
        ("requests", MAX_REQUESTS),
        ("tree_requests", TREE_REQUESTS),
        ("blob_requests", BLOB_REQUESTS),
        ("overhead_requests", OVERHEAD_REQUESTS),
        ("pages", MAX_REQUESTS),
        ("response_bytes", MAX_TOTAL_BYTES),
    ):
        if type(budget[name]) is not int or not 0 <= budget[name] <= maximum:
            raise EvidenceError("report_budget_counter_invalid")
    if (
        budget["requests"]
        != budget["tree_requests"] + budget["blob_requests"] + budget["overhead_requests"]
        or budget["pages"] != budget["requests"]
        or type(budget["wall_seconds"]) not in (int, float)
        or not 0 <= budget["wall_seconds"] <= MAX_WALL_SECONDS
    ):
        raise EvidenceError("report_budget_counter_invalid")
    if not isinstance(report["records"], list) or len(report["records"]) != 100:
        raise EvidenceError("report_identity_count_invalid")
    for record in report["records"]:
        if not isinstance(record, dict) or set(record) != {"identity", "base", "head"}:
            raise EvidenceError("report_record_schema_invalid")
        identity = record["identity"]
        if not isinstance(identity, dict) or set(identity) != {
            "repository",
            "pr",
            "base_sha",
            "head_sha",
        }:
            raise EvidenceError("report_identity_schema_invalid")
        if (
            not isinstance(identity["repository"], str)
            or not frozen._REPOSITORY.fullmatch(identity["repository"])
            or type(identity["pr"]) is not int
            or identity["pr"] <= 0
            or any(not SHA_RE.fullmatch(str(identity[key])) for key in ("base_sha", "head_sha"))
        ):
            raise EvidenceError("report_identity_schema_invalid")
        for side in ("base", "head"):
            side_data = record[side]
            if not isinstance(side_data, dict) or set(side_data) != {
                "commit_sha",
                "python_versions",
                "license",
                "dependencies",
            }:
                raise EvidenceError("report_side_schema_invalid")
            if not SHA_RE.fullmatch(str(side_data["commit_sha"])):
                raise EvidenceError("report_side_identity_invalid")
            for group in ("python_versions", "license", "dependencies"):
                result = side_data[group]
                if not isinstance(result, dict) or set(result) != {
                    "status",
                    "reason_codes",
                    "declarations_present",
                    "candidate_count",
                    "omitted_candidate_count",
                    "omitted_candidate_paths",
                    "unknown_count",
                    "sources",
                    "facts",
                }:
                    raise EvidenceError("report_group_schema_invalid")
                if not isinstance(result["status"], str) or result["status"] not in STATUSES:
                    raise EvidenceError("report_status_invalid")
                if (
                    not isinstance(result["reason_codes"], list)
                    or any(not isinstance(code, str) for code in result["reason_codes"])
                    or any(code not in REASON_CODES for code in result["reason_codes"])
                    or result["reason_codes"] != sorted(set(result["reason_codes"]))
                    or (
                        result["candidate_count"] is not None
                        and type(result["candidate_count"]) is not int
                    )
                    or (
                        result["omitted_candidate_count"] is not None
                        and type(result["omitted_candidate_count"]) is not int
                    )
                    or (
                        result["unknown_count"] is not None
                        and type(result["unknown_count"]) is not int
                    )
                    or type(result["declarations_present"]) not in (bool, type(None))
                    or not isinstance(result["facts"], list)
                    or (
                        result["omitted_candidate_count"] is not None
                        and result["candidate_count"] is not None
                        and result["omitted_candidate_count"] > result["candidate_count"]
                    )
                    or any(
                        not isinstance(path, str) or not _safe_path(path)
                        for path in result["omitted_candidate_paths"]
                    )
                    or any(
                        type(result[field]) is int and result[field] < 0
                        for field in ("candidate_count", "omitted_candidate_count", "unknown_count")
                    )
                    or not isinstance(result["omitted_candidate_paths"], list)
                    or result["omitted_candidate_paths"]
                    != sorted(set(result["omitted_candidate_paths"]))
                    or (
                        result["omitted_candidate_count"] is not None
                        and result["omitted_candidate_count"]
                        != len(result["omitted_candidate_paths"])
                    )
                ):
                    raise EvidenceError("report_group_counter_invalid")
                if result["status"] != "observed" and not result["reason_codes"]:
                    raise EvidenceError("report_reason_missing")
                if not isinstance(result["sources"], list) or not isinstance(result["facts"], list):
                    raise EvidenceError("report_group_content_invalid")
                for source in result["sources"]:
                    if not isinstance(source, dict) or set(source) != {
                        "commit_sha",
                        "path",
                        "blob_sha",
                        "size",
                        "content_sha256",
                    }:
                        raise EvidenceError("report_source_schema_invalid")
                    if (
                        not SHA_RE.fullmatch(str(source["commit_sha"]))
                        or not _safe_path(source["path"])
                        or not SHA_RE.fullmatch(str(source["blob_sha"]))
                        or type(source["size"]) is not int
                        or source["size"] < 0
                        or not re.fullmatch(r"[0-9a-f]{64}", str(source["content_sha256"]))
                    ):
                        raise EvidenceError("report_source_identity_invalid")
                for fact in result["facts"]:
                    _validate_fact(group, fact)


def _validate_fact(group: str, fact: Any) -> None:
    """Validate the finite, group-specific inert fact vocabulary."""
    if not isinstance(fact, dict) or not isinstance(fact.get("path"), str):
        raise EvidenceError("report_fact_schema_invalid")
    if not _safe_path(fact["path"]):
        raise EvidenceError("report_fact_schema_invalid")
    kind = fact.get("kind")
    rule = fact.get("rule_id")
    contracts: dict[str, dict[str, tuple[set[str], set[str]]]] = {
        "python_versions": {
            "literal": ({"kind", "path", "value", "rule_id"}, {"python-version-literal-v1"}),
            "requires-python": (
                {"kind", "path", "expression", "rule_id"},
                {"pyproject-requires-python-v1"},
            ),
            "python_requires": (
                {"kind", "path", "expression", "rule_id"},
                {"setup-cfg-python-requires-v1"},
            ),
            "tox-envlist": (
                {"kind", "path", "values", "rule_id"},
                {"tox-envlist-python-factors-v1"},
            ),
        },
        "license": {
            "spdx_identifier_expression": (
                {"kind", "path", "expression", "rule_id"},
                {"spdx-line-v1"},
            ),
            "license_file_present": ({"kind", "path", "rule_id"}, {"license-presence-v1"}),
        },
        "dependencies": {
            "declared_dependency": (
                {"kind", "path", "name", "specifier", "rule_id"},
                {"pyproject-static-dependencies-v1", "requirements-static-line-v1"},
            ),
            "declaration_file_present": (
                {"kind", "path", "form", "rule_id"},
                {
                    "setup-py-inert-presence-v1",
                    "requirements-presence-v1",
                    "declaration-file-presence-v1",
                },
            ),
        },
    }
    if group not in contracts:
        raise EvidenceError("report_fact_schema_invalid")
    contract = contracts[group].get(kind) if isinstance(kind, str) else None
    if (
        contract is None
        or set(fact) != contract[0]
        or not isinstance(rule, str)
        or rule not in contract[1]
    ):
        raise EvidenceError("report_fact_schema_invalid")
    if kind in {
        "literal",
        "expression",
        "python_requires",
        "requires-python",
        "spdx_identifier_expression",
    }:
        value = fact.get("value", fact.get("expression"))
        if not isinstance(value, str):
            raise EvidenceError("report_fact_schema_invalid")
    elif kind == "tox-envlist":
        values = fact.get("values")
        if (
            not isinstance(values, list)
            or not values
            or any(not isinstance(item, str) for item in values)
        ):
            raise EvidenceError("report_fact_schema_invalid")
    elif kind == "declared_dependency":
        if not isinstance(fact.get("name"), str) or not isinstance(fact.get("specifier"), str):
            raise EvidenceError("report_fact_schema_invalid")
    elif kind == "declaration_file_present":
        form = fact.get("form")
        if not isinstance(form, str) or form not in {
            "dynamic_or_unsupported",
            "empty_requirements_file",
            "format_present_unparsed",
        }:
            raise EvidenceError("report_fact_schema_invalid")


def _publish(
    path: Path, report: dict[str, Any], lock: dict[str, Any], expected_lock_sha256: str
) -> None:
    if path.exists():
        raise EvidenceError("output_exists_no_clobber")
    raw = (json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")
    if len(raw) > MAX_REPORT_BYTES:
        raise EvidenceError("report_size_budget_exhausted")
    try:
        decoded = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise EvidenceError("serialized_report_invalid") from None
    _validate_serialized_report(decoded)
    validate_report(decoded, lock, expected_lock_sha256)
    if decoded != report:
        raise EvidenceError("serialized_report_changed")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temp, path)
        except FileExistsError:
            raise EvidenceError("output_exists_no_clobber") from None
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        temp.unlink(missing_ok=True)


def run(
    lock_path: Path,
    checksums_path: Path,
    output: Path,
    token: str | None = None,
    responder: Callable[[str], bytes] | None = None,
) -> dict[str, Any]:
    base = lock_path.parent
    manifest_path = base / "projects-50-v1.json"
    longlist_path = base / "longlist-60-v1.json"
    try:
        lock, lock_hash = frozen.load_lock(lock_path, manifest_path, longlist_path, checksums_path)
    except Exception:
        raise EvidenceError("frozen_input_authentication_failed") from None
    hashes = {
        "lock": lock_hash,
        "manifest": frozen.load_manifest(manifest_path)[1],
        "longlist": frozen.load_longlist(longlist_path, frozen.load_manifest(manifest_path)[0])[1],
        "source_policy": _sha256(POLICY_PROFILE.read_bytes()),
        "collector": _sha256(Path(__file__).read_bytes()),
    }
    receipt_path = output.with_name(output.name + ".attempts.json")
    frozen_paths = {
        p.resolve()
        for p in (
            lock_path,
            checksums_path,
            manifest_path,
            longlist_path,
            Path(__file__),
            POLICY_PROFILE,
        )
    }
    if output.resolve() in frozen_paths or receipt_path.resolve() in frozen_paths:
        raise EvidenceError("output_is_frozen_input")
    if os.path.lexists(receipt_path):
        raise EvidenceError("receipt_exists_no_clobber")
    started = time.monotonic()
    started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    budget = Budget(started, attempts=[])
    try:
        report = build_report(lock, hashes, GitHubTransport(token, budget, responder), budget)
        expected_lock_sha256 = lock_hash
        validate_report(report, lock, expected_lock_sha256)
        _publish(output, report, lock, expected_lock_sha256)
    except Exception as exc:
        error_code = str(exc) if isinstance(exc, EvidenceError) else "unexpected_collector_error"
        receipt = _attempt_receipt(
            lock, hashes, budget, started_at, "incomplete", error_code, "gh103-source-v1"
        )
        try:
            _publish_diagnostic_receipt(receipt_path, receipt)
        except Exception as receipt_error:
            # A concurrent receipt creator can only win after preflight. Preserve
            # the original normalized failure; this run is not durably accounted.
            if not (
                isinstance(receipt_error, EvidenceError)
                and str(receipt_error) == "receipt_exists_no_clobber"
            ):
                raise EvidenceError("attempt_receipt_persistence_failed") from None
        if isinstance(exc, EvidenceError):
            raise EvidenceError(str(exc)) from None
        raise EvidenceError("unexpected_collector_error") from None
    receipt = _attempt_receipt(
        lock, hashes, budget, started_at, "complete", None, "gh103-source-v1"
    )
    _publish_diagnostic_receipt(receipt_path, receipt)
    return report


def _authenticated_sources(
    lock_path: Path, checksums_path: Path
) -> tuple[dict[str, Any], dict[str, str]]:
    base = lock_path.parent
    manifest_path = base / "projects-50-v1.json"
    longlist_path = base / "longlist-60-v1.json"
    lock, lock_hash = frozen.load_lock(lock_path, manifest_path, longlist_path, checksums_path)
    manifest, manifest_hash = frozen.load_manifest(manifest_path)
    _, longlist_hash = frozen.load_longlist(longlist_path, manifest)
    return lock, {
        "lock": lock_hash,
        "manifest": manifest_hash,
        "longlist": longlist_hash,
        "source_policy": _sha256(POLICY_PROFILE.read_bytes()),
        "collector": _sha256(Path(__file__).read_bytes()),
    }


def _publish_diagnostic_receipt(path: Path, receipt: dict[str, Any]) -> None:
    if path.exists():
        raise EvidenceError("receipt_exists_no_clobber")
    raw = (json.dumps(receipt, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")
    if len(raw) > MAX_RECEIPT_BYTES:
        raise EvidenceError("receipt_size_budget_exhausted")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temp, path)
        except FileExistsError:
            raise EvidenceError("receipt_exists_no_clobber") from None
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        temp.unlink(missing_ok=True)


def _attempt_receipt(
    lock: dict[str, Any],
    hashes: dict[str, str],
    budget: Budget,
    started_at: str,
    outcome: str,
    error_code: str | None,
    profile: str,
) -> dict[str, Any]:
    attempts = budget.attempts or []
    return {
        "receipt_schema_version": 1,
        "profile": profile,
        "run_id": str(uuid.uuid4()),
        "started_at": started_at,
        "outcome": outcome,
        "error_code": error_code,
        "source_ids": {
            key: value if value.startswith("sha256:") else f"sha256:{value}"
            for key, value in hashes.items()
        },
        "canonical_identity_sha256": _canonical_identity_digest(lock),
        "authenticated_lock_record_count": len(lock["records"]),
        "attempts": attempts,
        "counters": {
            "requests": budget.requests,
            "tree_requests": budget.tree_requests,
            "blob_requests": budget.blob_requests,
            "overhead_requests": budget.overhead_requests,
            "responses": sum(attempt["response_status"] is not None for attempt in attempts),
            "response_bytes": None if budget.response_bytes_unknown else budget.response_bytes,
            "response_bytes_lower_bound": budget.response_bytes,
            "response_bytes_complete": not budget.response_bytes_unknown
            and all(attempt["response_bytes_complete"] for attempt in attempts),
            "wall_seconds": round(time.monotonic() - budget.started, 3),
        },
        "limits": {
            "requests": budget.max_requests,
            "response_bytes_per_request": budget.max_response_bytes,
            "response_bytes_total": budget.max_total_bytes,
            "wall_seconds": budget.max_wall_seconds,
            "detection_bytes_per_response": 1,
        },
    }


def run_diagnostic(
    lock_path: Path,
    checksums_path: Path,
    receipt_path: Path,
    token: str | None = None,
    responder: Callable[[str], bytes] | None = None,
) -> dict[str, Any]:
    """Run a separately capped public-read diagnostic and persist outcome counters only."""
    try:
        lock, hashes = _authenticated_sources(lock_path, checksums_path)
    except Exception:
        raise EvidenceError("frozen_input_authentication_failed") from None
    frozen_paths = {
        lock_path.resolve(),
        checksums_path.resolve(),
        (lock_path.parent / "projects-50-v1.json").resolve(),
        (lock_path.parent / "longlist-60-v1.json").resolve(),
        Path(__file__).resolve(),
        POLICY_PROFILE.resolve(),
    }
    if receipt_path.resolve() in frozen_paths:
        raise EvidenceError("output_is_frozen_input")
    if os.path.lexists(receipt_path):
        raise EvidenceError("receipt_exists_no_clobber")
    run_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    budget = Budget(
        started=time.monotonic(),
        max_requests=DIAGNOSTIC_MAX_REQUESTS,
        max_response_bytes=DIAGNOSTIC_MAX_RESPONSE_BYTES,
        max_total_bytes=DIAGNOSTIC_MAX_TOTAL_BYTES,
        max_wall_seconds=DIAGNOSTIC_MAX_WALL_SECONDS,
        attempts=[],
    )
    outcome = "completed_within_diagnostic_cap"
    error_code: str | None = None
    try:
        build_report(lock, hashes, GitHubTransport(token, budget, responder), budget)
    except EvidenceError as exc:
        outcome = "incomplete"
        error_code = str(exc)
    except Exception:
        outcome = "incomplete"
        error_code = "unexpected_collector_error"
    receipt = _attempt_receipt(
        lock,
        hashes,
        budget,
        started_at,
        outcome,
        error_code,
        "gh103-transport-diagnostic-v1",
    )
    receipt["diagnostic_profile"] = receipt.pop("profile")
    receipt["run_id"] = run_id
    _publish_diagnostic_receipt(receipt_path, receipt)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--lock", type=Path, default=Path("benchmarks/real_world/expansion/pr-lock-100-v1.json")
    )
    parser.add_argument(
        "--checksums", type=Path, default=Path("benchmarks/real_world/expansion/checksums-v1.json")
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--diagnostic", action="store_true", help="run the separately capped transport diagnostic"
    )
    args = parser.parse_args()
    try:
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if args.diagnostic:
            receipt = run_diagnostic(args.lock, args.checksums, args.output, token=token)
            if receipt["outcome"] == "incomplete":
                print("transport diagnostic receipt published (incomplete)")
                return 2
        else:
            run(args.lock, args.checksums, args.output, token=token)
    except EvidenceError as exc:
        print(f"source-evidence collection failed: {exc}")
        return 2
    print(
        "transport diagnostic receipt published"
        if args.diagnostic
        else "source-evidence report published"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
