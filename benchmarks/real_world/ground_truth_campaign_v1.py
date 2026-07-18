#!/usr/bin/env python3
"""Build and authenticate offline production-v1 review campaign state."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, NoReturn, cast

from benchmarks.real_world import expansion_protocol_v2
from benchmarks.real_world.ground_truth_v2.schema import canonical_json

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

_PROFILE_DIR: Final = "benchmarks/real_world/production_v1"
_ASSIGNMENTS: Final = f"{_PROFILE_DIR}/assignments-v1.json"
_POLICY: Final = f"{_PROFILE_DIR}/campaign-policy-v1.json"
_SCHEMA: Final = f"{_PROFILE_DIR}/campaign-manifest-schema-v1.json"
_README: Final = f"{_PROFILE_DIR}/README.md"
_CHECKSUMS: Final = f"{_PROFILE_DIR}/checksums-v1.json"
_MODULE: Final = "benchmarks/real_world/ground_truth_campaign_v1.py"
_SOURCE_MODULE: Final = "benchmarks/real_world/ground_truth_source_v1.py"
_SOURCE_POLICY: Final = f"{_PROFILE_DIR}/source-policy-v1.json"
_SOURCE_SCHEMA: Final = f"{_PROFILE_DIR}/source-bindings-schema-v1.json"
_PACKET_MODULE: Final = "benchmarks/real_world/ground_truth_packet_v1.py"
_PACKET_POLICY: Final = f"{_PROFILE_DIR}/packet-policy-v1.json"
_PACKET_SCHEMA: Final = f"{_PROFILE_DIR}/packet-manifest-schema-v1.json"
_PACKET_AUTH_SCHEMA: Final = f"{_PROFILE_DIR}/packet-authorization-schema-v1.json"
_PACKET_PUBLICATION_SCHEMA: Final = f"{_PROFILE_DIR}/packet-publication-schema-v1.json"
_PACKET_AGGREGATE_SCHEMA: Final = f"{_PROFILE_DIR}/packet-aggregate-schema-v1.json"
_PILOT_PACKET_DEPENDENCY: Final = "benchmarks/real_world/pilot_packet_v2.py"
_SUBMIT_MODULE: Final = "benchmarks/real_world/ground_truth_submit_v1.py"
_SUBMIT_POLICY: Final = f"{_PROFILE_DIR}/submission-policy-v1.json"
_SUBMIT_SCHEMA: Final = f"{_PROFILE_DIR}/submission-binding-schema-v1.json"
_REVIEW_PROMPT: Final = f"{_PROFILE_DIR}/review-prompt-v1.md"
_REVIEW_MODEL_POLICY: Final = f"{_PROFILE_DIR}/model-policy-review-v1.json"
_REVIEW_TOOL_POLICY: Final = f"{_PROFILE_DIR}/tool-policy-review-v1.json"
_REVIEW_SOURCE_POLICY: Final = f"{_PROFILE_DIR}/review-source-policy-v1.json"
_SUBMIT_EXTENSION: Final = (
    "benchmarks/real_world/production_v1/extensions/ground-truth-review-submit/index.ts"
)
_SUBMIT_EXTENSION_SCHEMA: Final = (
    "benchmarks/real_world/production_v1/extensions/ground-truth-review-submit/review-schema.ts"
)
_MANIFEST: Final = "benchmarks/real_world/expansion/projects-50x50-v2.json"
_LOCK: Final = "benchmarks/real_world/expansion/pr-lock-2500-v2.json"
_LOCK_CHECKSUMS: Final = "benchmarks/real_world/expansion/checksums-50x50-v2.json"
_MAX_BYTES: Final = 64 * 1024 * 1024
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_ATTEMPT = re.compile(r"^prod-v1-i[0-9]{3}-rank[0-9]{3}-pr[0-9]+-[AB]$")
_ZERO_HASH: Final = "sha256:" + "0" * 64


class CampaignV1Error(RuntimeError):
    """Raised when production campaign custody or provenance is invalid."""


def _fail(message: str) -> NoReturn:
    raise CampaignV1Error(message)


def _sha(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    _fail(f"non-finite JSON value is forbidden: {value}")


def _strict(value: dict[str, Any], keys: set[str], label: str) -> None:
    if set(value) != keys:
        _fail(f"invalid {label} keys")


def _no_floats(value: object) -> None:
    if isinstance(value, float):
        _fail("floats are forbidden")
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            _fail("JSON object key is not a string")
        for item in value.values():
            _no_floats(item)
    elif isinstance(value, list):
        for item in value:
            _no_floats(item)


def _read_with_status(path: Path, *, modes: set[int] | None = None) -> tuple[bytes, os.stat_result]:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise CampaignV1Error(f"cannot open {path}") from exc
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_uid != os.getuid():
            _fail(f"invalid owner or type: {path}")
        if modes is not None and stat.S_IMODE(status.st_mode) not in modes:
            _fail(f"invalid mode: {path}")
        chunks: list[bytes] = []
        total = 0
        while total <= _MAX_BYTES:
            chunk = os.read(descriptor, min(64 * 1024, _MAX_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(raw) > _MAX_BYTES:
        _fail(f"file exceeds bound: {path}")
    return raw, status


def _read(path: Path, *, modes: set[int] | None = None) -> bytes:
    return _read_with_status(path, modes=modes)[0]


def _parse_json(raw: bytes, path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_unique,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise CampaignV1Error(f"invalid JSON: {path}") from exc
    if not isinstance(value, dict):
        _fail(f"JSON root is not an object: {path}")
    _no_floats(value)
    return value


def _json(path: Path, *, modes: set[int] | None = None) -> tuple[dict[str, Any], bytes]:
    raw = _read(path, modes=modes)
    return _parse_json(raw, path), raw


def _authenticate_profile(root: Path) -> dict[str, Any]:
    profile, _ = _json(root / _CHECKSUMS)
    _strict(profile, {"schema_version", "id", "files"}, "checksum profile")
    files = profile["files"]
    expected_files = {
        _ASSIGNMENTS,
        _POLICY,
        _SCHEMA,
        _README,
        _MODULE,
        _SOURCE_MODULE,
        _SOURCE_POLICY,
        _SOURCE_SCHEMA,
        _PACKET_MODULE,
        _PACKET_POLICY,
        _PACKET_SCHEMA,
        _PACKET_AUTH_SCHEMA,
        _PACKET_PUBLICATION_SCHEMA,
        _PACKET_AGGREGATE_SCHEMA,
        _PILOT_PACKET_DEPENDENCY,
        _SUBMIT_MODULE,
        _SUBMIT_POLICY,
        _SUBMIT_SCHEMA,
        _REVIEW_PROMPT,
        _REVIEW_MODEL_POLICY,
        _REVIEW_TOOL_POLICY,
        _REVIEW_SOURCE_POLICY,
        _SUBMIT_EXTENSION,
        _SUBMIT_EXTENSION_SCHEMA,
    }
    if (
        profile["schema_version"] != 1
        or profile["id"] != "ground-truth-production-checksums-v1"
        or not isinstance(files, dict)
        or set(files) != expected_files
    ):
        _fail("unsupported production checksum profile")
    for relative in sorted(expected_files):
        expected = files[relative]
        if not isinstance(expected, str) or not _DIGEST.fullmatch(expected):
            _fail("invalid production checksum")
        if _sha(_read(root / relative)) != expected:
            _fail(f"production checksum mismatch: {relative}")
    return profile


def _source_identity(status: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_uid,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def _source_snapshot(
    root: Path,
) -> dict[str, tuple[bytes, tuple[int, int, int, int, int, int, int]]]:
    result: dict[str, tuple[bytes, tuple[int, int, int, int, int, int, int]]] = {}
    for relative in (_LOCK, _MANIFEST, _LOCK_CHECKSUMS):
        path = root / relative
        raw, opened_status = _read_with_status(path)
        try:
            current_status = path.stat(follow_symlinks=False)
        except OSError as exc:
            raise CampaignV1Error(f"cannot restat {path}") from exc
        opened_identity = _source_identity(opened_status)
        if opened_identity != _source_identity(current_status):
            _fail("frozen expansion input drifted while capturing source snapshot")
        result[relative] = (raw, opened_identity)
    return result


def _load_sources(root: Path) -> tuple[dict[str, Any], str, dict[str, Any], dict[str, Any]]:
    _authenticate_profile(root)
    before = _source_snapshot(root)
    loader_error: expansion_protocol_v2.CorpusV2Error | None = None
    lock: dict[str, Any] | None = None
    manifest: dict[str, Any] | None = None
    lock_hash = ""
    manifest_hash = ""
    try:
        lock, lock_hash = expansion_protocol_v2.load_lock_authenticated(
            root / _LOCK,
            root / _MANIFEST,
            root / _LOCK_CHECKSUMS,
        )
        manifest, manifest_hash = expansion_protocol_v2.load_manifest(root / _MANIFEST)
    except expansion_protocol_v2.CorpusV2Error as exc:
        loader_error = exc
    after = _source_snapshot(root)
    if before != after:
        _fail("frozen expansion inputs drifted during authentication")
    if loader_error is not None:
        raise CampaignV1Error("frozen expansion inputs failed authentication") from loader_error
    if lock is None or manifest is None:
        _fail("frozen expansion loaders returned no value")

    checksums = _parse_json(before[_LOCK_CHECKSUMS][0], root / _LOCK_CHECKSUMS)
    _strict(
        checksums,
        {"schema_version", "id", "manifest_hash", "collector_hash", "lock_hash"},
        "expansion checksum profile",
    )
    if (
        checksums["schema_version"] != 2
        or checksums["id"] != "oss-expansion-50x50-checksums-v2"
        or any(
            not isinstance(checksums[key], str) or not _DIGEST.fullmatch(checksums[key])
            for key in ("manifest_hash", "collector_hash", "lock_hash")
        )
    ):
        _fail("invalid expansion checksum profile")
    captured_lock_hash = _sha(before[_LOCK][0])
    captured_manifest_hash = _sha(before[_MANIFEST][0])
    if (
        lock_hash != captured_lock_hash
        or manifest_hash != captured_manifest_hash
        or checksums["lock_hash"] != captured_lock_hash
        or checksums["manifest_hash"] != captured_manifest_hash
    ):
        _fail("expansion loader hashes are not bound to captured source bytes")

    assignment, _ = _json(root / _ASSIGNMENTS)
    _validate_assignments(assignment, lock)
    return lock, lock_hash, manifest, {"payload": assignment, "manifest_hash": manifest_hash}


def _validate_assignments(value: dict[str, Any], lock: dict[str, Any]) -> None:
    _strict(value, {"schema_version", "id", "lock_id", "assignments"}, "assignment")
    rows = value["assignments"]
    projects = lock["projects"]
    if (
        value["schema_version"] != 1
        or value["id"] != "ground-truth-production-assignments-v1"
        or value["lock_id"] != lock["id"]
        or not isinstance(rows, list)
        or len(rows) != 50
        or len(projects) != 50
    ):
        _fail("assignment identity or cardinality is invalid")
    for index, (row, project) in enumerate(zip(rows, projects, strict=True), 1):
        if not isinstance(row, dict):
            _fail("assignment row is invalid")
        _strict(row, {"ordinal", "issue", "repository"}, "assignment row")
        if row != {
            "ordinal": index,
            "issue": 148 + index,
            "repository": project["repository"],
        }:
            _fail("assignment order or repository does not match authenticated lock")


def _record(project: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
    return {
        "rank": source["rank"],
        "repository": project["repository"],
        "pr": source["pr"],
        "merged_at": source["merged_at"],
        "baseline_rule": source["baseline_rule"],
        "baseline_commit": source["baseline_sha"],
        "base_sha": source["base_sha"],
        "target_rule": source["target_rule"],
        "target_commit": source["target_sha"],
        "merge_commit": source["merge_commit_sha"],
        "merge_parent_shas": source["merge_parent_shas"],
        "pull_response_sha256": source["pull_response_sha256"],
        "commit_response_sha256": source["commit_response_sha256"],
        "diff_sha256": source["diff_sha256"],
        "diff_bytes": source["diff_bytes"],
        "diff_content_type": source["diff_content_type"],
        "diff_final_url": source["diff_final_url"],
        "source_packet_state": "pending",
    }


def _lane(issue: int, record: dict[str, Any], lane: str) -> dict[str, Any]:
    rank = cast("int", record["rank"])
    pr = cast("int", record["pr"])
    repository = cast("str", record["repository"])
    suffix = f"i{issue:03}-rank{rank:03}-pr{pr}-{lane}"
    return {
        "lane_key": f"{repository}#{pr}:{lane}",
        "repository": repository,
        "pr": pr,
        "rank": rank,
        "lane": lane,
        "attempt_id": f"prod-v1-{suffix}",
        "reviewer": {
            "name": f"production-blind-reviewer-{suffix}",
            "version": f"ground-truth-production-v1-{suffix}",
        },
        "state": "planned",
    }


def build_manifest(root: Path, issue: int, repository: str) -> dict[str, Any]:
    lock, lock_hash, manifest, source = _load_sources(root)
    assignments = source["payload"]["assignments"]
    matches = [row for row in assignments if row["issue"] == issue]
    if len(matches) != 1 or matches[0]["repository"] != repository:
        _fail("issue and repository do not match frozen assignment")
    project_matches = [row for row in lock["projects"] if row["repository"] == repository]
    if len(project_matches) != 1:
        _fail("repository is not unique in authenticated lock")
    project = project_matches[0]
    if project["status"] != "complete" or project["selected_count"] != 50:
        _fail("production campaign requires one complete 50-record slice")
    records = [_record(project, row) for row in project["records"]]
    lanes = [_lane(issue, record, lane) for record in records for lane in ("A", "B")]
    result = {
        "schema_version": 1,
        "id": f"ground-truth-production-v1-issue-{issue}",
        "authorization": {
            "live_launch_authorized": False,
            "canonical_import_authorized": False,
            "source_packet_materialization_authorized": False,
        },
        "corpus": {
            "id": lock["id"],
            "lock_sha256": lock_hash,
            "manifest_id": manifest["id"],
            "manifest_sha256": source["manifest_hash"],
            "selection": lock["selection"],
        },
        "assignment": {
            "ordinal": matches[0]["ordinal"],
            "issue": issue,
            "repository": repository,
        },
        "protocol": {
            "id": "ground-truth-production-native-v1",
            "max_global_concurrency": 3,
            "model": "openai-codex/gpt-5.6-luna",
            "thinking": "medium",
            "pi_subagents_version": "0.35.1",
            "fresh_context_per_lane": True,
            "independent_lanes": ["A", "B"],
        },
        "records": records,
        "lanes": lanes,
    }
    validate_manifest(root, result)
    return result


def validate_manifest(root: Path, value: dict[str, Any]) -> None:
    lock, lock_hash, manifest, source = _load_sources(root)
    _strict(
        value,
        {
            "schema_version",
            "id",
            "authorization",
            "corpus",
            "assignment",
            "protocol",
            "records",
            "lanes",
        },
        "campaign manifest",
    )
    assignment = value["assignment"]
    authorization = value["authorization"]
    corpus = value["corpus"]
    protocol = value["protocol"]
    records = value["records"]
    lanes = value["lanes"]
    if not all(isinstance(item, dict) for item in (assignment, authorization, corpus, protocol)):
        _fail("campaign manifest sections are invalid")
    _strict(assignment, {"ordinal", "issue", "repository"}, "campaign assignment")
    _strict(
        authorization,
        {
            "live_launch_authorized",
            "canonical_import_authorized",
            "source_packet_materialization_authorized",
        },
        "authorization",
    )
    _strict(corpus, {"id", "lock_sha256", "manifest_id", "manifest_sha256", "selection"}, "corpus")
    _strict(
        protocol,
        {
            "id",
            "max_global_concurrency",
            "model",
            "thinking",
            "pi_subagents_version",
            "fresh_context_per_lane",
            "independent_lanes",
        },
        "protocol",
    )
    issue = assignment.get("issue")
    repository = assignment.get("repository")
    if (
        value["schema_version"] != 1
        or value["id"] != f"ground-truth-production-v1-issue-{issue}"
        or authorization
        != {
            "live_launch_authorized": False,
            "canonical_import_authorized": False,
            "source_packet_materialization_authorized": False,
        }
        or corpus
        != {
            "id": lock["id"],
            "lock_sha256": lock_hash,
            "manifest_id": manifest["id"],
            "manifest_sha256": source["manifest_hash"],
            "selection": lock["selection"],
        }
        or protocol
        != {
            "id": "ground-truth-production-native-v1",
            "max_global_concurrency": 3,
            "model": "openai-codex/gpt-5.6-luna",
            "thinking": "medium",
            "pi_subagents_version": "0.35.1",
            "fresh_context_per_lane": True,
            "independent_lanes": ["A", "B"],
        }
        or not isinstance(issue, int)
        or isinstance(issue, bool)
        or not isinstance(repository, str)
        or not _REPOSITORY.fullmatch(repository)
    ):
        _fail("campaign identity, authorization, corpus, or protocol is invalid")
    expected_assignments = source["payload"]["assignments"]
    matches = [row for row in expected_assignments if row["issue"] == issue]
    if len(matches) != 1 or assignment != matches[0]:
        _fail("campaign assignment is invalid")
    projects = [row for row in lock["projects"] if row["repository"] == repository]
    if len(projects) != 1 or projects[0]["status"] != "complete":
        _fail("campaign repository slice is invalid")
    expected_records = [_record(projects[0], row) for row in projects[0]["records"]]
    if not isinstance(records, list) or records != expected_records or len(records) != 50:
        _fail("campaign records differ from exact authenticated slice")
    expected_lanes = [
        _lane(issue, record, lane) for record in expected_records for lane in ("A", "B")
    ]
    if not isinstance(lanes, list) or lanes != expected_lanes or len(lanes) != 100:
        _fail("campaign lanes are incomplete, duplicated, or reordered")
    keys = [row["lane_key"] for row in lanes]
    attempts = [row["attempt_id"] for row in lanes]
    reviewers = [(row["reviewer"]["name"], row["reviewer"]["version"]) for row in lanes]
    if (
        len(set(keys)) != 100
        or len(set(attempts)) != 100
        or len(set(reviewers)) != 100
        or any(not _ATTEMPT.fullmatch(item) for item in attempts)
    ):
        _fail("campaign lane identities are not distinct")
    for record in records:
        if (
            not _SHA.fullmatch(record["baseline_commit"])
            or not _SHA.fullmatch(record["target_commit"])
            or not _DIGEST.fullmatch(record["diff_sha256"])
            or record["source_packet_state"] != "pending"
        ):
            _fail("campaign source identity is invalid")
    _no_floats(value)


def _publish(path: Path, payload: dict[str, Any]) -> None:
    if not path.is_absolute():
        _fail("output path must be absolute")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        os.fchmod(descriptor, 0o400)
        raw = canonical_json(payload)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise CampaignV1Error(f"refusing to overwrite {path}") from exc
        path.chmod(0o400, follow_symlinks=False)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _private_root(root: Path) -> Path:
    if not root.is_absolute():
        _fail("ledger root must be absolute")
    current = Path(root.anchor)
    for part in root.parts[1:]:
        current /= part
        try:
            status = current.lstat()
        except OSError as exc:
            raise CampaignV1Error("ledger root or ancestor is unavailable") from exc
        if stat.S_ISLNK(status.st_mode):
            _fail("ledger root has a symlink ancestor")
    resolved = root.resolve(strict=True)
    status = resolved.stat()
    if (
        resolved != root
        or not stat.S_ISDIR(status.st_mode)
        or status.st_uid != os.getuid()
        or stat.S_IMODE(status.st_mode) != 0o700
    ):
        _fail("ledger root must be an owned mode-0700 directory")
    return resolved


@contextmanager
def _ledger_lock(root: Path) -> Iterator[None]:
    path = root / ".ledger.lock"
    descriptor = os.open(
        path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_uid != os.getuid()
            or stat.S_IMODE(status.st_mode) != 0o600
        ):
            _fail("ledger lock is invalid")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def _manifest_file(root: Path, path: Path) -> tuple[dict[str, Any], bytes, os.stat_result]:
    if not path.is_absolute():
        _fail("campaign manifest path must be absolute")
    raw, status = _read_with_status(path, modes={0o400})
    value = _parse_json(raw, path)
    validate_manifest(root, value)
    return value, raw, status


def init_ledger(root: Path, campaign_path: Path, repository_root: Path) -> dict[str, Any]:
    private = _private_root(root)
    with _ledger_lock(private):
        campaign, raw, status = _manifest_file(repository_root, campaign_path)
        states = {
            "schema_version": 1,
            "campaign_id": campaign["id"],
            "states": [
                {
                    "ordinal": index,
                    "lane_key": lane["lane_key"],
                    "attempt_id": lane["attempt_id"],
                    "state": "planned",
                }
                for index, lane in enumerate(campaign["lanes"], 1)
            ],
        }
        states_raw = canonical_json(states)
        genesis_base = {
            "schema_version": 1,
            "protocol": "ground-truth-production-ledger-v1",
            "campaign_id": campaign["id"],
            "campaign_manifest_path": str(campaign_path),
            "campaign_manifest_sha256": _sha(raw),
            "campaign_manifest_device": status.st_dev,
            "campaign_manifest_inode": status.st_ino,
            "lane_count": 100,
            "states_sha256": _sha(states_raw),
            "previous_hash": _ZERO_HASH,
        }
        genesis = {**genesis_base, "entry_hash": _sha(canonical_json(genesis_base))}
        _publish(private / "lane-states.json", states)
        try:
            _publish(private / "ledger-genesis.json", genesis)
        except Exception:
            (private / "lane-states.json").unlink(missing_ok=True)
            raise
    return validate_ledger(private, repository_root)


def _validate_ledger_unlocked(root: Path, repository_root: Path) -> dict[str, Any]:
    states, states_raw = _json(root / "lane-states.json", modes={0o400})
    genesis, _ = _json(root / "ledger-genesis.json", modes={0o400})
    _strict(states, {"schema_version", "campaign_id", "states"}, "lane states")
    _strict(
        genesis,
        {
            "schema_version",
            "protocol",
            "campaign_id",
            "campaign_manifest_path",
            "campaign_manifest_sha256",
            "campaign_manifest_device",
            "campaign_manifest_inode",
            "lane_count",
            "states_sha256",
            "previous_hash",
            "entry_hash",
        },
        "ledger genesis",
    )
    campaign_path = Path(genesis["campaign_manifest_path"])
    campaign, campaign_raw, campaign_status = _manifest_file(repository_root, campaign_path)
    rows = states["states"]
    if not isinstance(rows, list) or len(rows) != 100:
        _fail("ledger state cardinality is invalid")
    expected_rows = [
        {
            "ordinal": index,
            "lane_key": lane["lane_key"],
            "attempt_id": lane["attempt_id"],
            "state": "planned",
        }
        for index, lane in enumerate(campaign["lanes"], 1)
    ]
    if states != {"schema_version": 1, "campaign_id": campaign["id"], "states": expected_rows}:
        _fail("ledger states differ from campaign lanes")
    base = {key: value for key, value in genesis.items() if key != "entry_hash"}
    if (
        genesis["schema_version"] != 1
        or genesis["protocol"] != "ground-truth-production-ledger-v1"
        or genesis["campaign_id"] != campaign["id"]
        or genesis["campaign_manifest_sha256"] != _sha(campaign_raw)
        or genesis["campaign_manifest_device"] != campaign_status.st_dev
        or genesis["campaign_manifest_inode"] != campaign_status.st_ino
        or genesis["lane_count"] != 100
        or genesis["states_sha256"] != _sha(states_raw)
        or genesis["previous_hash"] != _ZERO_HASH
        or genesis["entry_hash"] != _sha(canonical_json(base))
    ):
        _fail("ledger genesis binding or hash chain is invalid")
    head = genesis["entry_hash"]
    transition_path = root / "packet-materialization-authorization.json"
    transition_present = transition_path.exists() or transition_path.is_symlink()
    authorization_hash: str | None = None
    if transition_present:
        transition, transition_raw = _json(transition_path, modes={0o400})
        required = {
            "schema_version",
            "protocol",
            "campaign_id",
            "campaign_manifest_sha256",
            "source_bindings_sha256",
            "cache_content_sha256",
            "cache_device",
            "cache_inode",
            "issue",
            "repository",
            "pr_count",
            "lane_count",
            "production_profile_sha256",
            "output_parent",
            "output_basename",
            "output_parent_device",
            "output_parent_inode",
            "limits",
            "authorizations",
            "issued_at",
            "expires_at",
            "previous_hash",
            "entry_hash",
        }
        _strict(transition, required, "packet authorization transition")
        transition_base = {key: value for key, value in transition.items() if key != "entry_hash"}
        expected_hash = _sha(
            b"packet-materialization-authorization-v1\0" + canonical_json(transition_base)
        )
        if (
            canonical_json(transition) != transition_raw
            or transition["schema_version"] != 1
            or transition["protocol"] != "packet-materialization-authorization-v1"
            or transition["campaign_id"] != campaign["id"]
            or transition["campaign_manifest_sha256"] != _sha(campaign_raw)
            or transition["issue"] != campaign["assignment"]["issue"]
            or transition["repository"] != campaign["assignment"]["repository"]
            or transition["pr_count"] != 50
            or transition["lane_count"] != 100
            or transition["authorizations"]
            != {"packet_materialization": True, "live_launch": False, "canonical_import": False}
            or transition["previous_hash"] != head
            or transition["entry_hash"] != expected_hash
        ):
            _fail("packet authorization ledger transition is invalid")
        head = transition["entry_hash"]
        authorization_hash = transition["entry_hash"]
    publication_path = root / "packet-materialization-publication.json"
    publication_present = publication_path.exists() or publication_path.is_symlink()
    publication_hash: str | None = None
    if publication_present:
        if authorization_hash is None:
            _fail("packet publication exists without authorization")
        publication, publication_raw = _json(publication_path, modes={0o400})
        required_publication = {
            "schema_version",
            "protocol",
            "campaign_id",
            "campaign_manifest_sha256",
            "authorization_entry_hash",
            "source_bindings_sha256",
            "output_path",
            "output_device",
            "output_inode",
            "aggregate_manifest_sha256",
            "aggregate_root_sha256",
            "inventory_sha256",
            "payload_entries",
            "payload_bytes",
            "publication_timestamp",
            "previous_hash",
            "entry_hash",
        }
        _strict(publication, required_publication, "packet publication transition")
        publication_base = {key: value for key, value in publication.items() if key != "entry_hash"}
        expected_publication_hash = _sha(
            b"packet-materialization-publication-v1\0" + canonical_json(publication_base)
        )
        if (
            canonical_json(publication) != publication_raw
            or publication["schema_version"] != 1
            or publication["protocol"] != "packet-materialization-publication-v1"
            or publication["campaign_id"] != campaign["id"]
            or publication["campaign_manifest_sha256"] != _sha(campaign_raw)
            or publication["authorization_entry_hash"] != authorization_hash
            or publication["previous_hash"] != head
            or publication["entry_hash"] != expected_publication_hash
        ):
            _fail("packet publication ledger transition is invalid")
        head = publication["entry_hash"]
        publication_hash = publication["entry_hash"]
    return {
        "schema_version": 1,
        "campaign_id": campaign["id"],
        "campaign_manifest_sha256": genesis["campaign_manifest_sha256"],
        "lane_count": 100,
        "planned": 100,
        "entry_hash": head,
        "packet_authorization_present": transition_present,
        "packet_authorization_entry_hash": authorization_hash,
        "packet_publication_present": publication_present,
        "packet_publication_entry_hash": publication_hash,
        "genesis_entry_hash": genesis["entry_hash"],
    }


def validate_ledger(root: Path, repository_root: Path) -> dict[str, Any]:
    private = _private_root(root)
    with _ledger_lock(private):
        return _validate_ledger_unlocked(private, repository_root)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build-manifest")
    build.add_argument("--issue", type=int, required=True)
    build.add_argument("--repository", required=True)
    build.add_argument("--output", type=Path, required=True)
    validate = sub.add_parser("validate-manifest")
    validate.add_argument("--manifest", type=Path, required=True)
    init = sub.add_parser("init-ledger")
    init.add_argument("--manifest", type=Path, required=True)
    init.add_argument("--ledger-root", type=Path, required=True)
    audit = sub.add_parser("validate-ledger")
    audit.add_argument("--ledger-root", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    repository_root = args.root.resolve(strict=True)
    if args.command == "build-manifest":
        payload = build_manifest(repository_root, args.issue, args.repository)
        _publish(args.output, payload)
        result: dict[str, Any] = {
            "manifest": str(args.output),
            "sha256": _sha(canonical_json(payload)),
            "records": 50,
            "lanes": 100,
            "live_launch_authorized": False,
        }
    elif args.command == "validate-manifest":
        payload, raw = _json(args.manifest, modes={0o400})
        validate_manifest(repository_root, payload)
        result = {"manifest": str(args.manifest), "sha256": _sha(raw), "valid": True}
    elif args.command == "init-ledger":
        result = init_ledger(args.ledger_root, args.manifest, repository_root)
    else:
        result = validate_ledger(args.ledger_root, repository_root)
    print(canonical_json(result).decode(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
