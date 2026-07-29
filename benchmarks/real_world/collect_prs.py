#!/usr/bin/env python3
"""Collect a cheap exploratory corpus of recent merged PRs.

Requires an authenticated GitHub CLI (`gh`). The collector stores PR and commit
identifiers plus changed-file metadata, but not third-party source. The latest-N
selection is intentionally a convenient sampling strategy, not a publication
lock; diffs can be fetched later from each PR's diff URL.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.real_world._secure_publish import (
    SecurePathError,
    ensure_publishable,
    publish_exclusive_bytes,
)

HERE = Path(__file__).resolve().parent
DEFAULT_OUTPUT = HERE / "candidate-corpus.json"

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


class CollectorError(ValueError):
    """Raised when exploratory collection input or publication is unsafe."""


def _reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise CollectorError(f"duplicate JSON key: {name}")
        result[name] = value
    return result


def _reject_non_finite(token: str) -> None:
    raise CollectorError(f"non-finite JSON number: {token}")


def _strict_json_loads(content: str, source: str) -> Any:
    try:
        return json.loads(
            content,
            object_pairs_hook=_reject_duplicate_members,
            parse_constant=_reject_non_finite,
        )
    except (json.JSONDecodeError, CollectorError) as error:
        raise CollectorError(f"invalid JSON in {source}: {error}") from error


def _protected_files(input_paths: tuple[Path, ...]) -> tuple[Path, ...]:
    return (*_PROTECTED_ARTIFACTS, *input_paths)


def _validate_destination(path: Path, *, input_paths: tuple[Path, ...] = ()) -> None:
    absolute = Path(path).expanduser().absolute()
    if absolute in {item.expanduser().absolute() for item in input_paths}:
        raise CollectorError(f"refusing to overwrite input file: {path}")
    if absolute in {item.expanduser().absolute() for item in _PROTECTED_ARTIFACTS} or any(
        absolute.is_relative_to(root.expanduser().absolute()) for root in _PROTECTED_ROOTS
    ):
        raise CollectorError(f"refusing to target frozen benchmark artifact: {path}")
    try:
        ensure_publishable(
            path,
            forbidden_files=_protected_files(input_paths),
            forbidden_roots=_PROTECTED_ROOTS,
        )
    except SecurePathError as error:
        raise CollectorError(str(error)) from error


def _publish_exclusive_bytes(
    output: Path,
    content: bytes,
    *,
    input_paths: tuple[Path, ...] = (),
) -> None:
    """Durably publish exact bytes through a stable destination-directory FD."""
    _validate_destination(output, input_paths=input_paths)
    try:
        publish_exclusive_bytes(
            output,
            content,
            forbidden_files=_protected_files(input_paths),
            forbidden_roots=_PROTECTED_ROOTS,
        )
    except SecurePathError as error:
        raise CollectorError(str(error)) from error


def _publish_output(
    output: Path,
    payload: dict[str, Any],
    *,
    input_paths: tuple[Path, ...] = (),
) -> None:
    try:
        content = (json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n").encode(
            "utf-8"
        )
    except (TypeError, ValueError) as error:
        raise CollectorError(f"collector output is not strict JSON: {error}") from error
    _publish_exclusive_bytes(output, content, input_paths=input_paths)


def gh_json(*args: str) -> Any:
    """Run gh and strictly decode its JSON response as UTF-8."""
    try:
        result = subprocess.run(
            ["gh", *args],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
        )
    except UnicodeError as error:
        raise CollectorError("gh response is not valid UTF-8") from error
    return _strict_json_loads(result.stdout, "gh response")


def _positive_integer(value: object, location: str) -> int:
    if type(value) is not int or value < 1:
        raise CollectorError(f"{location} must be a positive integer")
    return value


def _nonnegative_integer(value: object, location: str) -> int:
    if type(value) is not int or value < 0:
        raise CollectorError(f"{location} must be a nonnegative integer")
    return value


def _required_string(record: dict[str, Any], field: str, location: str) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value.strip():
        raise CollectorError(f"{location}.{field} must be a non-empty string")
    return value


def _oid(value: object, location: str) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", value) is None
    ):
        raise CollectorError(f"{location} must be a Git object ID")
    return value


def _validate_author(value: object, location: str) -> None:
    if value is None:
        return
    if not isinstance(value, dict):
        raise CollectorError(f"{location} must be an object or null")
    _required_string(value, "id", location)
    _required_string(value, "login", location)
    if "name" not in value:
        raise CollectorError(f"{location}.name is required")
    name = value.get("name")
    if name is not None and not isinstance(name, str):
        raise CollectorError(f"{location}.name must be a string or null")
    if not isinstance(value.get("is_bot"), bool):
        raise CollectorError(f"{location}.is_bot must be a boolean")


def _normalized_author(value: object) -> dict[str, object] | None:
    if value is None:
        return None
    assert isinstance(value, dict)
    return {field: value[field] for field in ("id", "is_bot", "login", "name")}


def _validate_pr_summary(pr: dict[str, Any], repository: str, index: int) -> int:
    location = f"gh PR list {repository}[{index}]"
    number = _positive_integer(pr.get("number"), f"{location}.number")
    for field in ("title", "url", "mergedAt", "baseRefName", "headRefName"):
        _required_string(pr, field, location)
    merge_commit = pr.get("mergeCommit")
    if not isinstance(merge_commit, dict):
        raise CollectorError(f"{location}.mergeCommit must be an object")
    _oid(merge_commit.get("oid"), f"{location}.mergeCommit.oid")
    if "author" not in pr:
        raise CollectorError(f"{location}.author is required")
    _validate_author(pr["author"], f"{location}.author")
    return number


def _validate_detail(detail: dict[str, Any], identity: str) -> None:
    for field in ("additions", "deletions", "changedFiles"):
        _nonnegative_integer(detail.get(field), f"gh PR detail {identity}.{field}")
    body = detail.get("body")
    if not isinstance(body, str):
        raise CollectorError(f"gh PR detail {identity}.body must be a string")
    files = detail.get("files")
    if not isinstance(files, list):
        raise CollectorError(f"gh PR detail {identity}.files must be a list")
    seen_paths: set[str] = set()
    for index, item in enumerate(files):
        location = f"gh PR detail {identity}.files[{index}]"
        if not isinstance(item, dict):
            raise CollectorError(f"{location} must be an object")
        path = _required_string(item, "path", location)
        if path in seen_paths:
            raise CollectorError(f"gh PR detail {identity} has duplicate file path: {path}")
        seen_paths.add(path)
        for field in ("additions", "deletions"):
            _nonnegative_integer(item.get(field), f"{location}.{field}")
        _required_string(item, "changeType", location)
    commits = detail.get("commits")
    if not isinstance(commits, list) or not commits:
        raise CollectorError(f"gh PR detail {identity}.commits must be a non-empty list")
    seen_oids: set[str] = set()
    for index, commit in enumerate(commits):
        location = f"gh PR detail {identity}.commits[{index}]"
        if not isinstance(commit, dict):
            raise CollectorError(f"{location} must be an object")
        oid = _oid(commit.get("oid"), f"{location}.oid")
        if oid in seen_oids:
            raise CollectorError(f"gh PR detail {identity} has duplicate commit OID")
        seen_oids.add(oid)


def _validate_collected_entry(entry: dict[str, Any], index: int) -> tuple[str, int]:
    location = f"collector entries[{index}]"
    repository = _required_string(entry, "repository", location)
    number = _validate_pr_summary(entry, repository, index)
    for field in ("additions", "deletions", "changedFiles"):
        _nonnegative_integer(entry.get(field), f"{location}.{field}")
    if not isinstance(entry.get("body"), str):
        raise CollectorError(f"{location}.body must be a string")
    files = entry.get("files")
    if not isinstance(files, list):
        raise CollectorError(f"{location}.files must be a list")
    seen_paths: set[str] = set()
    for file_index, item in enumerate(files):
        file_location = f"{location}.files[{file_index}]"
        if not isinstance(item, dict):
            raise CollectorError(f"{file_location} must be an object")
        path = _required_string(item, "path", file_location)
        if path in seen_paths:
            raise CollectorError(f"{location} has duplicate file path: {path}")
        seen_paths.add(path)
        for field in ("additions", "deletions"):
            _nonnegative_integer(item.get(field), f"{file_location}.{field}")
        _required_string(item, "changeType", file_location)
    commits = entry.get("commits")
    if not isinstance(commits, list) or not commits:
        raise CollectorError(f"{location}.commits must be a non-empty list")
    seen_oids: set[str] = set()
    for commit_index, commit in enumerate(commits):
        oid = _oid(commit, f"{location}.commits[{commit_index}]")
        if oid in seen_oids:
            raise CollectorError(f"{location} has duplicate commit OID")
        seen_oids.add(oid)
    expected_url = f"https://github.com/{repository}/pull/{number}.diff"
    if entry.get("diff_url") != expected_url:
        raise CollectorError(f"{location}.diff_url does not match its identity")
    ground_truth = entry.get("ground_truth")
    if ground_truth != {
        "status": "pending_double_review",
        "review_a": None,
        "review_b": None,
        "adjudicated": None,
    }:
        raise CollectorError(f"{location}.ground_truth has an invalid pending shape")
    return repository, number


def _validate_output_payload(payload: dict[str, Any]) -> None:
    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise CollectorError("collector output entries must be a list")
    seen: set[tuple[str, int]] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise CollectorError(f"collector entries[{index}] must be an object")
        identity = _validate_collected_entry(entry, index)
        if identity in seen:
            raise CollectorError(f"collector output has duplicate PR: {identity[0]}#{identity[1]}")
        seen.add(identity)


def collect_repository(repository: str, limit: int) -> list[dict[str, Any]]:
    """Collect the latest merged PRs and stable metadata for one repository."""
    prs = gh_json(
        "pr",
        "list",
        "--repo",
        repository,
        "--state",
        "merged",
        "--limit",
        str(limit),
        "--json",
        "number,title,url,mergedAt,mergeCommit,baseRefName,headRefName,author",
    )
    if not isinstance(prs, list) or any(not isinstance(pr, dict) for pr in prs):
        raise CollectorError(f"gh returned an invalid PR list for {repository}")

    corpus: list[dict[str, Any]] = []
    seen_numbers: set[int] = set()
    validated: list[tuple[dict[str, Any], int]] = []
    for index, pr in enumerate(prs):
        number = _validate_pr_summary(pr, repository, index)
        if number in seen_numbers:
            raise CollectorError(f"gh returned duplicate PR number for {repository}: {number}")
        seen_numbers.add(number)
        validated.append((pr, number))

    for pr, number in validated:
        detail = gh_json(
            "pr",
            "view",
            str(pr["number"]),
            "--repo",
            repository,
            "--json",
            "additions,deletions,changedFiles,files,body,commits",
        )
        if not isinstance(detail, dict):
            raise CollectorError(f"gh returned invalid PR detail for {repository}#{number}")
        _validate_detail(detail, f"{repository}#{number}")
        corpus.append(
            {
                "repository": repository,
                "number": number,
                "title": pr["title"],
                "url": pr["url"],
                "mergedAt": pr["mergedAt"],
                "mergeCommit": {"oid": pr["mergeCommit"]["oid"]},
                "baseRefName": pr["baseRefName"],
                "headRefName": pr["headRefName"],
                "author": _normalized_author(pr["author"]),
                "additions": detail["additions"],
                "deletions": detail["deletions"],
                "changedFiles": detail["changedFiles"],
                "files": [
                    {
                        "path": item["path"],
                        "additions": item["additions"],
                        "deletions": item["deletions"],
                        "changeType": item["changeType"],
                    }
                    for item in detail["files"]
                ],
                "body": detail["body"],
                "commits": [commit["oid"] for commit in detail["commits"]],
                "diff_url": f"https://github.com/{repository}/pull/{pr['number']}.diff",
                "ground_truth": {
                    "status": "pending_double_review",
                    "review_a": None,
                    "review_b": None,
                    "adjudicated": None,
                },
            }
        )
    return corpus


def _validate_config(config: dict[str, Any]) -> dict[str, Any]:
    limit = config.get("prs_per_repository")
    if type(limit) is not int or limit < 1:
        raise CollectorError("prs_per_repository must be a positive integer")
    repositories = config.get("repositories")
    if not isinstance(repositories, list) or not repositories:
        raise CollectorError("repositories must be a non-empty list of objects")
    for index, repository in enumerate(repositories):
        if not isinstance(repository, dict):
            raise CollectorError(f"repositories[{index}] must be an object")
        name = repository.get("name")
        if not isinstance(name, str) or not name.strip():
            raise CollectorError(f"repositories[{index}].name must be a non-empty string")
    return config


def _resolve_config(
    path: Path,
    repositories: list[str] | None,
    limit: int | None,
) -> dict[str, Any]:
    try:
        raw_config = _strict_json_loads(path.read_text(encoding="utf-8"), str(path))
    except (OSError, UnicodeError) as error:
        raise CollectorError(f"cannot read config {path}: {error}") from error
    if not isinstance(raw_config, dict):
        raise CollectorError("config must be a JSON object")
    config: dict[str, Any] = raw_config
    if repositories:
        config = {
            **config,
            "repositories": [{"name": repository} for repository in repositories],
        }
    if limit is not None:
        config = {**config, "prs_per_repository": limit}
    return _validate_config(config)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Collect a cheap, exploratory PR metadata corpus without changing frozen artifacts."
        )
    )
    parser.add_argument("--config", type=Path, default=HERE / "repos.json")
    parser.add_argument(
        "--repository",
        action="append",
        dest="repositories",
        help="Repository to collect (repeatable); overrides repositories in --config.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Merged PRs per repository; overrides prs_per_repository in --config.",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)

    try:
        _validate_destination(args.output, input_paths=(args.config,))
        config = _resolve_config(args.config, args.repositories, args.limit)
        limit = config["prs_per_repository"]
        entries: list[dict[str, Any]] = []
        for repository in config["repositories"]:
            entries.extend(collect_repository(repository["name"], limit))

        output = {
            "schema_version": 1,
            "dataset_kind": "exploratory_pr_metadata",
            "selection": (
                "Latest N merged PRs returned by GitHub at collection time; no content filtering."
            ),
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "config": config,
            "entries": entries,
        }
        _validate_output_payload(output)
        _publish_output(args.output, output, input_paths=(args.config,))
    except (CollectorError, OSError, subprocess.SubprocessError, KeyError, TypeError) as error:
        parser.error(str(error))

    print(f"Wrote {len(entries)} PRs to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
