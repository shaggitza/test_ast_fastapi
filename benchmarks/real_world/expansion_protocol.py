#!/usr/bin/env python3
"""Validate and collect the frozen 50-project OSS expansion without source execution."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final, TypeGuard

_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_HTTPS_GITHUB = re.compile(r"^https://(?:api|github)\.com/")
_MAX_MANIFEST_BYTES: Final = 2 * 1024 * 1024
_MAX_RESPONSE_BYTES: Final = 4 * 1024 * 1024
_MAX_REQUESTS: Final = 250
_MAX_TOTAL_BYTES: Final = 256 * 1024 * 1024
_MAX_WALL_SECONDS: Final = 15 * 60
_MAX_PAGES_PER_PROJECT: Final = 20
_REQUEST_TIMEOUT_SECONDS: Final = 20

_REQUIRED_DIVERSITY: Final = {
    "frameworks": ["fastapi", "starlette", "django", "flask", "mcp", "worker"],
    "surfaces": ["http", "mcp", "task", "rabbitmq", "kafka", "scheduler", "cli"],
    "effects": ["redis", "mongodb", "sql", "filesystem", "http", "object_storage"],
    "size_bands": ["small", "medium", "large"],
    "partitions": ["verification", "stress"],
}
_POLICY_KEYS = {
    "project_count",
    "per_project_pr_cap",
    "merged_before",
    "selection",
    "immutable_fields",
    "reviews",
    "not_evaluable_retained",
    "runtime_execution_allowed",
}
_PROJECT_KEYS = {
    "repository",
    "default_branch",
    "license_spdx",
    "github_size_kib",
    "survey_commit",
    "survey_evidence",
    "license_evidence",
    "dependency_feasibility",
    "frameworks",
    "surfaces",
    "effects",
    "size_band",
    "typing",
    "layout",
    "partition",
    "collection_eligibility",
    "runtime_eligibility",
}
_ALLOWED_LICENSES = {"Apache-2.0", "BSD-3-Clause", "LGPL-3.0", "MIT"}
_ALLOWED_TYPING = {"mixed", "strong"}
_ALLOWED_LAYOUT = {"package", "monorepo"}
_ALLOWED_FRAMEWORKS = {
    "application_or_tooling",
    "asgi",
    "cli",
    "client_or_state_library",
    "django",
    "falcon",
    "fastapi",
    "flask",
    "litestar",
    "mcp",
    "sanic",
    "starlette",
    "worker",
}
_ALLOWED_SURFACES = {
    "cli",
    "event",
    "http",
    "kafka",
    "library",
    "mcp",
    "rabbitmq",
    "scheduler",
    "task",
}
_ALLOWED_EFFECTS = {"filesystem", "http", "mongodb", "object_storage", "redis", "sql"}


class ExpansionProtocolError(ValueError):
    """Raised when frozen selection or immutable collection evidence is invalid."""


@dataclass
class RequestBudget:
    """Bound aggregate network use for one collection."""

    started: float
    requests: int = 0
    response_bytes: int = 0

    def reserve(self) -> None:
        if time.monotonic() - self.started > _MAX_WALL_SECONDS:
            raise ExpansionProtocolError("GitHub collection exceeded its wall-clock budget")
        if self.requests >= _MAX_REQUESTS:
            raise ExpansionProtocolError("GitHub collection exceeded its request budget")
        self.requests += 1

    def consume(self, size: int) -> None:
        self.response_bytes += size
        if self.response_bytes > _MAX_TOTAL_BYTES:
            raise ExpansionProtocolError("GitHub collection exceeded its byte budget")


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    """Never forward the benchmark bearer credential through redirects."""

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


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ExpansionProtocolError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_bounded(path: Path, limit: int) -> bytes:
    with path.open("rb") as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise ExpansionProtocolError(f"{path.name} exceeds {limit} bytes")
    return raw


def _strict_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        unknown = sorted(set(value) - expected)
        raise ExpansionProtocolError(f"invalid {label} keys; missing={missing}, unknown={unknown}")


def _is_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _parse_utc(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ExpansionProtocolError(f"{label} must be a canonical UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise ExpansionProtocolError(f"{label} must be an ISO timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ExpansionProtocolError(f"{label} must use UTC")
    return parsed


def load_longlist(  # noqa: PLR0912
    path: Path, manifest: dict[str, Any]
) -> tuple[dict[str, Any], str]:
    """Validate the frozen selected/excluded population and anti-hacking attestation."""
    raw = _read_bounded(path, _MAX_MANIFEST_BYTES)
    try:
        payload = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExpansionProtocolError(f"invalid expansion longlist: {exc}") from exc
    if not isinstance(payload, dict):
        raise ExpansionProtocolError("expansion longlist root must be an object")
    _strict_keys(
        payload,
        {
            "schema_version",
            "id",
            "frozen_at",
            "manifest_id",
            "selection_attestation",
            "selected",
            "excluded",
        },
        "longlist",
    )
    if payload["schema_version"] != 1 or isinstance(payload["schema_version"], bool):
        raise ExpansionProtocolError("unsupported longlist schema version")
    if payload["id"] != "oss-expansion-longlist-60-v1":
        raise ExpansionProtocolError("unsupported longlist id")
    if payload["manifest_id"] != manifest["id"]:
        raise ExpansionProtocolError("longlist does not identify its manifest")
    if payload["frozen_at"] != manifest["frozen_at"]:
        raise ExpansionProtocolError("longlist and manifest freeze times differ")
    if payload["selection_attestation"] != (
        "Frozen before expansion predictions; no analyzer result was consulted for inclusion, "
        "exclusion, or partition assignment."
    ):
        raise ExpansionProtocolError("anti-hacking selection attestation changed")
    selected = payload["selected"]
    expected_selected = [project["repository"] for project in manifest["projects"]]
    if selected != expected_selected:
        raise ExpansionProtocolError("longlist selected projects do not exactly match manifest")
    excluded = payload["excluded"]
    if not isinstance(excluded, list) or len(excluded) != 10:
        raise ExpansionProtocolError("longlist must contain exactly ten exclusions")
    names = {repository.casefold() for repository in selected}
    reason_codes = {
        "dependency_feasibility",
        "language_dominance",
        "license_feasibility",
        "pull_metadata_unavailable",
        "repository_superseded",
        "stratum_quota",
    }
    for record in excluded:
        if not isinstance(record, dict):
            raise ExpansionProtocolError("longlist exclusions must be objects")
        _strict_keys(record, {"repository", "reason_code", "reason"}, "exclusion")
        repository = record["repository"]
        if (
            not isinstance(repository, str)
            or _REPOSITORY.fullmatch(repository) is None
            or repository.casefold() in names
        ):
            raise ExpansionProtocolError(
                f"invalid or duplicate longlist repository: {repository!r}"
            )
        names.add(repository.casefold())
        if record["reason_code"] not in reason_codes:
            raise ExpansionProtocolError(f"invalid exclusion reason for {repository}")
        if not isinstance(record["reason"], str) or len(record["reason"].strip()) < 20:
            raise ExpansionProtocolError(f"missing exclusion rationale for {repository}")
    return payload, f"sha256:{hashlib.sha256(raw).hexdigest()}"


def load_checksums(path: Path) -> dict[str, Any]:
    """Load the independent exact-byte profile for frozen expansion artifacts."""
    raw = _read_bounded(path, _MAX_MANIFEST_BYTES)
    try:
        payload = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExpansionProtocolError(f"invalid expansion checksum profile: {exc}") from exc
    if not isinstance(payload, dict):
        raise ExpansionProtocolError("expansion checksum profile root must be an object")
    _strict_keys(
        payload,
        {
            "schema_version",
            "id",
            "manifest_id",
            "manifest_hash",
            "longlist_hash",
            "collector_hash",
            "lock_hash",
        },
        "checksum profile",
    )
    if payload["schema_version"] != 1 or isinstance(payload["schema_version"], bool):
        raise ExpansionProtocolError("unsupported checksum profile schema version")
    if payload["id"] != "oss-expansion-checksums-v1":
        raise ExpansionProtocolError("unsupported checksum profile id")
    for field in ("manifest_hash", "longlist_hash", "collector_hash", "lock_hash"):
        if _DIGEST.fullmatch(str(payload[field])) is None:
            raise ExpansionProtocolError(f"invalid checksum profile field: {field}")
    return payload


def load_manifest(path: Path) -> tuple[dict[str, Any], str]:
    """Load bounded JSON and return validated content plus its exact-byte hash."""
    raw = _read_bounded(path, _MAX_MANIFEST_BYTES)
    try:
        payload = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExpansionProtocolError(f"invalid expansion manifest: {exc}") from exc
    if not isinstance(payload, dict):
        raise ExpansionProtocolError("expansion manifest root must be an object")
    validate_manifest(payload)
    return payload, f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _validate_string_list(
    project: dict[str, Any], field: str, allowed: set[str], repository: str
) -> list[str]:
    values = project.get(field)
    if (
        not isinstance(values, list)
        or not values
        or any(not isinstance(item, str) for item in values)
        or len(values) != len(set(values))
        or values != sorted(values)
        or not set(values) <= allowed
    ):
        raise ExpansionProtocolError(f"invalid sorted unique {field} for {repository}")
    return values


def validate_manifest(payload: dict[str, Any]) -> None:  # noqa: PLR0912, PLR0915
    """Enforce fixed schema, protocol constants, provenance, and diversity gates."""
    _strict_keys(
        payload,
        {"schema_version", "id", "frozen_at", "policy", "required_diversity", "projects"},
        "manifest",
    )
    if payload["schema_version"] != 1 or isinstance(payload["schema_version"], bool):
        raise ExpansionProtocolError("unsupported expansion schema version")
    if payload["id"] != "oss-expansion-50-v1":
        raise ExpansionProtocolError("unsupported expansion manifest id")
    _parse_utc(payload["frozen_at"], "frozen_at")

    policy = payload["policy"]
    projects = payload["projects"]
    if not isinstance(policy, dict) or not isinstance(projects, list):
        raise ExpansionProtocolError("manifest policy and projects must be structured")
    _strict_keys(policy, _POLICY_KEYS, "policy")
    expected_policy = {
        "project_count": 50,
        "per_project_pr_cap": 2,
        "selection": (
            "highest pull-request numbers among merged PRs before cutoff; no title, size, "
            "file, author, or analyzer-result filtering"
        ),
        "immutable_fields": ["base_sha", "head_sha", "merge_commit_sha"],
        "reviews": ["blind-review-a", "blind-review-b", "source-adjudication"],
        "not_evaluable_retained": True,
        "runtime_execution_allowed": False,
    }
    for key, expected in expected_policy.items():
        if policy[key] != expected or (_is_int(expected) and not _is_int(policy[key])):
            raise ExpansionProtocolError(f"frozen policy field changed: {key}")
    cutoff = _parse_utc(policy["merged_before"], "merged_before")
    if cutoff >= _parse_utc(payload["frozen_at"], "frozen_at"):
        raise ExpansionProtocolError("merge cutoff must precede protocol freeze")
    if len(projects) != 50:
        raise ExpansionProtocolError("expansion must contain exactly 50 projects")
    if payload["required_diversity"] != _REQUIRED_DIVERSITY:
        raise ExpansionProtocolError("required diversity contract changed")

    names: set[str] = set()
    partitions = {"verification": 0, "stress": 0}
    observed: dict[str, set[str]] = {field: set() for field in _REQUIRED_DIVERSITY}
    for project in projects:
        if not isinstance(project, dict):
            raise ExpansionProtocolError("project records must be objects")
        _strict_keys(project, _PROJECT_KEYS, "project")
        name = project["repository"]
        normalized_name = name.casefold() if isinstance(name, str) else ""
        if (
            not isinstance(name, str)
            or _REPOSITORY.fullmatch(name) is None
            or normalized_name in names
        ):
            raise ExpansionProtocolError(f"invalid or duplicate repository: {name!r}")
        names.add(normalized_name)
        if name.casefold() in {
            "open-webui/open-webui",
            "langflow-ai/langflow",
            "khoj-ai/khoj",
        }:
            raise ExpansionProtocolError("expansion must remain disjoint from the original corpus")
        if not isinstance(project["default_branch"], str) or not project["default_branch"]:
            raise ExpansionProtocolError(f"invalid default branch for {name}")
        if _SHA.fullmatch(str(project["survey_commit"])) is None:
            raise ExpansionProtocolError(f"invalid survey commit for {name}")
        quoted = urllib.parse.quote(name, safe="/")
        commit = project["survey_commit"]
        if project["survey_evidence"] != f"https://api.github.com/repos/{quoted}/commits/{commit}":
            raise ExpansionProtocolError(f"invalid survey evidence for {name}")
        if project["license_evidence"] != f"https://api.github.com/repos/{quoted}":
            raise ExpansionProtocolError(f"invalid license evidence for {name}")
        if project["license_spdx"] not in _ALLOWED_LICENSES:
            raise ExpansionProtocolError(f"unsupported license assertion for {name}")
        if not _is_int(project["github_size_kib"]) or project["github_size_kib"] <= 0:
            raise ExpansionProtocolError(f"invalid repository size for {name}")
        if project["dependency_feasibility"] != "metadata_only_no_install":
            raise ExpansionProtocolError(f"unsafe dependency feasibility for {name}")
        if project["collection_eligibility"] != "source_only":
            raise ExpansionProtocolError(f"collection eligibility is not source-only for {name}")
        if project["runtime_eligibility"] != "blocked_pending_isolated_image":
            raise ExpansionProtocolError(f"runtime eligibility is unsafe for {name}")
        if project["typing"] not in _ALLOWED_TYPING or project["layout"] not in _ALLOWED_LAYOUT:
            raise ExpansionProtocolError(f"invalid typing/layout taxonomy for {name}")
        size_band = project["size_band"]
        if size_band not in {"small", "medium", "large"}:
            raise ExpansionProtocolError(f"invalid size band for {name}")
        observed["size_bands"].add(size_band)
        partition = project["partition"]
        if partition not in partitions:
            raise ExpansionProtocolError(f"invalid partition for {name}")
        partitions[partition] += 1
        observed["partitions"].add(partition)
        observed["frameworks"].update(
            _validate_string_list(project, "frameworks", _ALLOWED_FRAMEWORKS, name)
        )
        observed["surfaces"].update(
            _validate_string_list(project, "surfaces", _ALLOWED_SURFACES, name)
        )
        observed["effects"].update(
            _validate_string_list(project, "effects", _ALLOWED_EFFECTS, name)
        )
    if partitions != {"verification": 40, "stress": 10}:
        raise ExpansionProtocolError(
            "partitions must contain 40 verification and 10 stress projects"
        )
    for field, expected in _REQUIRED_DIVERSITY.items():
        if not set(expected) <= observed[field]:
            raise ExpansionProtocolError(f"required diversity is not covered: {field}")


def _github_json(url: str, token: str, budget: RequestBudget) -> Any:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "api.github.com":
        raise ExpansionProtocolError("GitHub requests must target https://api.github.com")
    budget.reserve()
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "fastapi-endpoint-detector-benchmark/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    opener = urllib.request.build_opener(_RejectRedirects())
    try:
        with opener.open(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response:
            if response.geturl() != url:
                raise ExpansionProtocolError("GitHub request redirected unexpectedly")
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
        raise ExpansionProtocolError(f"GitHub request failed for {url}: {exc}") from exc
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise ExpansionProtocolError("GitHub response exceeds 4 MiB")
    budget.consume(len(raw))
    try:
        return json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExpansionProtocolError(f"GitHub returned invalid JSON for {url}") from exc


def _verify_project_evidence(project: dict[str, Any], token: str, budget: RequestBudget) -> None:
    repository = project["repository"]
    commit = _github_json(project["survey_evidence"], token, budget)
    if not isinstance(commit, dict) or commit.get("sha") != project["survey_commit"]:
        raise ExpansionProtocolError(f"survey commit evidence mismatch for {repository}")
    license_payload = _github_json(project["license_evidence"], token, budget)
    license_data = license_payload.get("license") if isinstance(license_payload, dict) else None
    if not isinstance(license_data, dict) or license_data.get("spdx_id") != project["license_spdx"]:
        raise ExpansionProtocolError(f"license evidence mismatch for {repository}")


def _validated_pull(
    repository: str, pull: dict[str, Any], cutoff: datetime
) -> dict[str, Any] | None:
    if pull.get("merged_at") is None:
        return None
    merged_at = _parse_utc(pull["merged_at"], f"{repository} merged_at")
    if merged_at >= cutoff:
        return None
    number = pull.get("number")
    if not _is_int(number) or number <= 0:
        raise ExpansionProtocolError(f"invalid pull number for {repository}")
    base = pull.get("base")
    head = pull.get("head")
    immutable = {
        "base_sha": base.get("sha") if isinstance(base, dict) else None,
        "head_sha": head.get("sha") if isinstance(head, dict) else None,
        "merge_commit_sha": pull.get("merge_commit_sha"),
    }
    if any(_SHA.fullmatch(str(value)) is None for value in immutable.values()):
        raise ExpansionProtocolError(f"PR {repository}#{number} lacks immutable commit identity")
    html_url = pull.get("html_url")
    expected_url = f"https://github.com/{repository}/pull/{number}"
    if html_url != expected_url or _HTTPS_GITHUB.match(str(html_url)) is None:
        raise ExpansionProtocolError(f"invalid pull URL for {repository}#{number}")
    return {
        "repository": repository,
        "pr": number,
        "merged_at": merged_at.isoformat().replace("+00:00", "Z"),
        "html_url": html_url,
        **immutable,
        "review_a": "pending",
        "review_b": "pending",
        "adjudication": "pending",
        "pr_type": "unclassified",
    }


def _project_prs(
    repository: str,
    *,
    cutoff: datetime,
    cap: int,
    token: str,
    budget: RequestBudget,
) -> list[dict[str, Any]]:
    selected: dict[int, dict[str, Any]] = {}
    quoted = urllib.parse.quote(repository, safe="/")
    for page in range(1, _MAX_PAGES_PER_PROJECT + 1):
        url = (
            f"https://api.github.com/repos/{quoted}/pulls?state=closed&sort=created&"
            f"direction=desc&per_page=100&page={page}"
        )
        response = _github_json(url, token, budget)
        if not isinstance(response, list):
            raise ExpansionProtocolError(f"GitHub pull response is not a list for {repository}")
        for item in response:
            if not isinstance(item, dict):
                raise ExpansionProtocolError(
                    f"GitHub pull record is not an object for {repository}"
                )
            record = _validated_pull(repository, item, cutoff)
            if record is not None:
                selected[record["pr"]] = record
        if len(selected) >= cap:
            return [selected[number] for number in sorted(selected, reverse=True)[:cap]]
        if len(response) < 100:
            break
    raise ExpansionProtocolError(
        f"fewer than {cap} eligible merged PRs found within "
        f"{_MAX_PAGES_PER_PROJECT} pages for {repository}"
    )


def _collector_hash() -> str:
    raw = _read_bounded(Path(__file__), _MAX_MANIFEST_BYTES)
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def validate_lock(  # noqa: PLR0912, PLR0915
    payload: dict[str, Any],
    manifest: dict[str, Any],
    manifest_hash: str,
    longlist: dict[str, Any],
    longlist_hash: str,
) -> None:
    """Validate a collected lock against its exact manifest and fixed output schema."""
    expected_keys = {
        "schema_version",
        "manifest_id",
        "manifest_hash",
        "longlist_id",
        "longlist_hash",
        "collector_hash",
        "collected_at",
        "selection",
        "records",
        "network_budget",
        "survey_verification",
    }
    _strict_keys(payload, expected_keys, "lock")
    if payload["schema_version"] != 1 or isinstance(payload["schema_version"], bool):
        raise ExpansionProtocolError("unsupported lock schema version")
    if payload["manifest_id"] != manifest["id"] or payload["manifest_hash"] != manifest_hash:
        raise ExpansionProtocolError("lock does not match its exact manifest")
    if payload["longlist_id"] != longlist["id"] or payload["longlist_hash"] != longlist_hash:
        raise ExpansionProtocolError("lock does not match its exact longlist")
    if payload["collector_hash"] != _collector_hash():
        raise ExpansionProtocolError("lock was not produced by this exact collector")
    _parse_utc(payload["collected_at"], "collected_at")
    if payload["selection"] != manifest["policy"]["selection"]:
        raise ExpansionProtocolError("lock selection does not match manifest")
    records = payload["records"]
    expected_count = len(manifest["projects"]) * manifest["policy"]["per_project_pr_cap"]
    if not isinstance(records, list) or len(records) != expected_count:
        raise ExpansionProtocolError("lock record count does not match the frozen quota")
    expected_repositories = {item["repository"] for item in manifest["projects"]}
    seen: set[tuple[str, int]] = set()
    counts: dict[str, int] = dict.fromkeys(expected_repositories, 0)
    cutoff = _parse_utc(manifest["policy"]["merged_before"], "merged_before")
    for record in records:
        if not isinstance(record, dict):
            raise ExpansionProtocolError("lock records must be objects")
        _strict_keys(
            record,
            {
                "repository",
                "pr",
                "merged_at",
                "html_url",
                "base_sha",
                "head_sha",
                "merge_commit_sha",
                "review_a",
                "review_b",
                "adjudication",
                "pr_type",
            },
            "lock record",
        )
        repository = record["repository"]
        number = record["pr"]
        if repository not in expected_repositories or not _is_int(number) or number <= 0:
            raise ExpansionProtocolError("lock record has invalid identity")
        identity = (repository, number)
        if identity in seen:
            raise ExpansionProtocolError(f"duplicate lock record: {identity}")
        seen.add(identity)
        counts[repository] += 1
        if record["html_url"] != f"https://github.com/{repository}/pull/{number}":
            raise ExpansionProtocolError(f"invalid lock URL for {identity}")
        if _parse_utc(record["merged_at"], f"{identity} merged_at") >= cutoff:
            raise ExpansionProtocolError(f"lock record is after cutoff: {identity}")
        for field in ("base_sha", "head_sha", "merge_commit_sha"):
            if _SHA.fullmatch(str(record[field])) is None:
                raise ExpansionProtocolError(f"invalid {field} for {identity}")
        if (record["review_a"], record["review_b"], record["adjudication"]) != (
            "pending",
            "pending",
            "pending",
        ):
            raise ExpansionProtocolError("collector may only create pending blind-review state")
        if record["pr_type"] != "unclassified":
            raise ExpansionProtocolError("collector may not classify PR type")
    if set(counts.values()) != {manifest["policy"]["per_project_pr_cap"]}:
        raise ExpansionProtocolError("lock does not satisfy the per-project quota")
    if payload["survey_verification"] != {
        "projects": 50,
        "status": "verified_from_github_api",
    }:
        raise ExpansionProtocolError("survey evidence was not completely verified")
    budget = payload["network_budget"]
    if not isinstance(budget, dict) or set(budget) != {"requests", "response_bytes"}:
        raise ExpansionProtocolError("invalid network budget evidence")
    if not all(_is_int(value) and value >= 0 for value in budget.values()):
        raise ExpansionProtocolError("invalid network budget counters")
    if budget["requests"] > _MAX_REQUESTS or budget["response_bytes"] > _MAX_TOTAL_BYTES:
        raise ExpansionProtocolError("lock reports an exceeded network budget")


def _publish_no_clobber(output: Path, payload: dict[str, Any]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, output)
        except FileExistsError as exc:
            raise ExpansionProtocolError(f"refusing to overwrite frozen output: {output}") from exc
        directory_fd = os.open(output.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def collect(
    manifest_path: Path,
    longlist_path: Path,
    output: Path,
    *,
    token: str,
) -> dict[str, Any]:
    """Collect atomically; never import, clone, install, or execute upstream source."""
    manifest, manifest_hash = load_manifest(manifest_path)
    longlist, longlist_hash = load_longlist(longlist_path, manifest)
    budget = RequestBudget(started=time.monotonic())
    cutoff = _parse_utc(manifest["policy"]["merged_before"], "merged_before")
    records: list[dict[str, Any]] = []
    for project in manifest["projects"]:
        _verify_project_evidence(project, token, budget)
        records.extend(
            _project_prs(
                project["repository"],
                cutoff=cutoff,
                cap=manifest["policy"]["per_project_pr_cap"],
                token=token,
                budget=budget,
            )
        )
    records.sort(key=lambda item: (item["repository"].casefold(), -item["pr"]))
    payload = {
        "schema_version": 1,
        "manifest_id": manifest["id"],
        "manifest_hash": manifest_hash,
        "longlist_id": longlist["id"],
        "longlist_hash": longlist_hash,
        "collector_hash": _collector_hash(),
        "collected_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "selection": manifest["policy"]["selection"],
        "records": records,
        "network_budget": {
            "requests": budget.requests,
            "response_bytes": budget.response_bytes,
        },
        "survey_verification": {
            "projects": 50,
            "status": "verified_from_github_api",
        },
    }
    validate_lock(payload, manifest, manifest_hash, longlist, longlist_hash)
    _publish_no_clobber(output, payload)
    return payload


def load_lock(
    path: Path,
    manifest_path: Path,
    longlist_path: Path,
    checksums_path: Path,
) -> tuple[dict[str, Any], str]:
    """Authenticate exact frozen bytes, then validate the collected lock structure."""
    manifest, manifest_hash = load_manifest(manifest_path)
    longlist, longlist_hash = load_longlist(longlist_path, manifest)
    checksums = load_checksums(checksums_path)
    raw = _read_bounded(path, _MAX_MANIFEST_BYTES)
    lock_hash = f"sha256:{hashlib.sha256(raw).hexdigest()}"
    expected_profile = {
        "manifest_id": manifest["id"],
        "manifest_hash": manifest_hash,
        "longlist_hash": longlist_hash,
        "collector_hash": _collector_hash(),
        "lock_hash": lock_hash,
    }
    for field, expected in expected_profile.items():
        if checksums[field] != expected:
            raise ExpansionProtocolError(f"frozen checksum mismatch: {field}")
    try:
        payload = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExpansionProtocolError(f"invalid expansion lock: {exc}") from exc
    if not isinstance(payload, dict):
        raise ExpansionProtocolError("expansion lock root must be an object")
    validate_lock(payload, manifest, manifest_hash, longlist, longlist_hash)
    return payload, lock_hash


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("benchmarks/real_world/expansion/projects-50-v1.json"),
    )
    parser.add_argument(
        "--longlist",
        type=Path,
        default=Path("benchmarks/real_world/expansion/longlist-60-v1.json"),
    )
    parser.add_argument(
        "--checksums",
        type=Path,
        default=Path("benchmarks/real_world/expansion/checksums-v1.json"),
    )
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--validate-lock", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    manifest, digest = load_manifest(args.manifest)
    _longlist, longlist_digest = load_longlist(args.longlist, manifest)
    if args.validate_only:
        print(
            json.dumps(
                {
                    "id": manifest["id"],
                    "projects": 50,
                    "hash": digest,
                    "longlist_hash": longlist_digest,
                },
                sort_keys=True,
            )
        )
        return 0
    if args.validate_lock is not None:
        lock, lock_hash = load_lock(
            args.validate_lock,
            args.manifest,
            args.longlist,
            args.checksums,
        )
        print(json.dumps({"records": len(lock["records"]), "hash": lock_hash}, sort_keys=True))
        return 0
    if args.output is None:
        parser.error("--output is required unless a validation mode is used")
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        parser.error("GITHUB_TOKEN is required for collection")
    payload = collect(args.manifest, args.longlist, args.output, token=token)
    print(json.dumps({"records": len(payload["records"]), "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
