#!/usr/bin/env python3
"""Authorize, build, and regenerate production-v1 immutable review packets."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, Final, NoReturn, cast

from benchmarks.real_world import ground_truth_campaign_v1 as campaign_v1
from benchmarks.real_world import ground_truth_source_v1 as source_v1
from benchmarks.real_world import pilot_packet_v2 as packet_primitives
from benchmarks.real_world.ground_truth_v2.schema import canonical_json

if TYPE_CHECKING:
    from collections.abc import Sequence

_PROFILE_DIR: Final = "benchmarks/real_world/production_v1"
_CHECKSUMS: Final = f"{_PROFILE_DIR}/checksums-v1.json"
_POLICY: Final = f"{_PROFILE_DIR}/packet-policy-v1.json"
_SCHEMA: Final = f"{_PROFILE_DIR}/packet-manifest-schema-v1.json"
_AUTH_SCHEMA: Final = f"{_PROFILE_DIR}/packet-authorization-schema-v1.json"
_PUBLICATION_SCHEMA: Final = f"{_PROFILE_DIR}/packet-publication-schema-v1.json"
_AGGREGATE_SCHEMA: Final = f"{_PROFILE_DIR}/packet-aggregate-schema-v1.json"
_MODULE: Final = "benchmarks/real_world/ground_truth_packet_v1.py"
_DEPENDENCY: Final = "benchmarks/real_world/pilot_packet_v2.py"
_AUTH_FILE: Final = "packet-materialization-authorization.json"
_PUBLICATION_FILE: Final = "packet-materialization-publication.json"
_PACKET_POLICY_FILES: Final = ("packet-policy-v1.json", "packet-manifest-schema-v1.json")
_PACKET_ID: Final = "ground-truth-production-review-packet-v1"
_AGGREGATE_ID: Final = "ground-truth-production-packet-aggregate-v1"
_AUTH_PROTOCOL: Final = "packet-materialization-authorization-v1"
_PUBLICATION_PROTOCOL: Final = "packet-materialization-publication-v1"
_MAX_JSON: Final = 64 * 1024 * 1024
_MAX_PACKETS: Final = 50
_MAX_COMMITS: Final = 100
_MAX_FILES_PACKET: Final = 10_000
_MAX_BLOB: Final = 32 * 1024 * 1024
_MAX_SNAPSHOT: Final = 256 * 1024 * 1024
_MAX_PACKET: Final = 512 * 1024 * 1024
_MAX_DIFF: Final = 32 * 1024 * 1024
_MAX_AGGREGATE_ENTRIES: Final = 500_000
_MAX_AGGREGATE_PAYLOAD: Final = 50 * _MAX_PACKET
_SPOOL: Final = 260 * 1024 * 1024
_TREE_SPOOL: Final = 64 * 1024 * 1024
_DIFF_SPOOL: Final = 32 * 1024 * 1024
_METADATA: Final = 4096
_HEADROOM: Final = 256 * 1024 * 1024
_STAGING_LIMIT: Final = (
    _MAX_AGGREGATE_PAYLOAD + _SPOOL + _TREE_SPOOL + _DIFF_SPOOL + _MAX_AGGREGATE_ENTRIES * _METADATA
)
_MAX_COMMANDS: Final = 250
_DEADLINE_SECONDS: Final = 21_600
_AUTH_SECONDS: Final = 86_400
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_FORBIDDEN_PACKET_KEYS: Final = {
    "lane",
    "lane_key",
    "reviewer",
    "reviewers",
    "attempt_id",
    "ledger",
    "rank",
    "truth",
    "prediction",
    "analyzer",
    "adjudication",
    "capability",
    "cache_path",
    "host_path",
}
_GIT_VERSION: Final = "git version 2.43.0"
_DIFF_ARGS: Final = (
    "diff",
    "--no-ext-diff",
    "--no-textconv",
    "--no-color",
    "--no-renames",
    "--binary",
    "--full-index",
)


@dataclass(frozen=True)
class ProfileSnapshot:
    value: dict[str, Any]
    raw: bytes
    files: dict[str, bytes]


class PacketV1Error(RuntimeError):
    """Raised when production packet authorization or custody is invalid."""


def _fail(message: str) -> NoReturn:
    raise PacketV1Error(message)


def _sha(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _constant(value: str) -> NoReturn:
    _fail(f"non-finite JSON value is forbidden: {value}")


def _read(
    path: Path, limit: int = _MAX_JSON, *, modes: set[int] | None = None
) -> tuple[bytes, os.stat_result]:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise PacketV1Error(f"cannot open {path}") from exc
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_uid != os.getuid():
            _fail(f"invalid file owner or type: {path}")
        if modes is not None and stat.S_IMODE(status.st_mode) not in modes:
            _fail(f"invalid file mode: {path}")
        chunks: list[bytes] = []
        total = 0
        while total <= limit:
            chunk = os.read(descriptor, min(64 * 1024, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    if len(raw) > limit:
        _fail(f"file exceeds bound: {path}")
    return raw, status


def _json(
    path: Path, *, modes: set[int] | None = None
) -> tuple[dict[str, Any], bytes, os.stat_result]:
    raw, status = _read(path, modes=modes)
    try:
        value = json.loads(raw, object_pairs_hook=_unique, parse_constant=_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise PacketV1Error(f"invalid JSON: {path}") from exc
    if not isinstance(value, dict):
        _fail(f"JSON root is not an object: {path}")
    return value, raw, status


def _strict(value: dict[str, Any], keys: set[str], label: str) -> None:
    if set(value) != keys:
        _fail(f"invalid {label} keys")


def _identity(status: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_uid,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def _profile(root: Path) -> ProfileSnapshot:
    profile_path = root / _CHECKSUMS
    profile, raw, profile_opened = _json(profile_path)
    _strict(profile, {"schema_version", "id", "files"}, "production profile")
    files = profile.get("files")
    required = {
        _MODULE,
        _POLICY,
        _SCHEMA,
        _AUTH_SCHEMA,
        _PUBLICATION_SCHEMA,
        _AGGREGATE_SCHEMA,
        _DEPENDENCY,
    }
    if (
        profile.get("schema_version") != 1
        or profile.get("id") != "ground-truth-production-checksums-v1"
        or not isinstance(files, dict)
        or not required <= set(files)
    ):
        _fail("unsupported packet production profile")
    snapshots: list[tuple[Path, tuple[int, int, int, int, int, int, int]]] = []
    captured: dict[str, bytes] = {}
    for relative in required:
        expected = files.get(relative)
        if not isinstance(expected, str) or not _DIGEST.fullmatch(expected):
            _fail("invalid packet profile digest")
        path = root / relative
        actual, opened = _read(path)
        if _sha(actual) != expected:
            _fail(f"packet profile checksum mismatch: {relative}")
        captured[relative] = actual
        snapshots.append((path, _identity(opened)))
    if _identity(profile_opened) != _identity(profile_path.stat(follow_symlinks=False)):
        _fail("packet profile drifted during authentication")
    for path, expected_identity in snapshots:
        if _identity(path.stat(follow_symlinks=False)) != expected_identity:
            _fail("packet dependency drifted during authentication")
    return ProfileSnapshot(profile, raw, captured)


def _campaign(root: Path, path: Path) -> tuple[dict[str, Any], bytes]:
    value, raw, opened = _json(path, modes={0o400})
    try:
        campaign_v1.validate_manifest(root, value)
    except campaign_v1.CampaignV1Error as exc:
        raise PacketV1Error("campaign authentication failed") from exc
    current = path.stat(follow_symlinks=False)
    if (opened.st_dev, opened.st_ino, opened.st_ctime_ns) != (
        current.st_dev,
        current.st_ino,
        current.st_ctime_ns,
    ):
        _fail("campaign drifted while opening")
    if canonical_json(value) != raw or value.get("authorization") != {
        "canonical_import_authorized": False,
        "live_launch_authorized": False,
        "source_packet_materialization_authorized": False,
    }:
        _fail("campaign false gates or canonical bytes are invalid")
    return value, raw


def _bindings(
    root: Path, campaign_path: Path, cache: Path, path: Path
) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    try:
        authenticated = source_v1.validate_source_bindings(root, campaign_path, cache, path)
        cache_summary = source_v1.validate_cache(root, campaign_path, cache)
        value, raw, opened = source_v1._read_json(path, modes={0o400})
    except source_v1.SourceV1Error as exc:
        raise PacketV1Error("source/cache authentication failed") from exc
    current = path.stat(follow_symlinks=False)
    if (opened.st_dev, opened.st_ino, opened.st_ctime_ns) != (
        current.st_dev,
        current.st_ino,
        current.st_ctime_ns,
    ):
        _fail("source bindings drifted while opening")
    if authenticated.get("sha256") != _sha(raw):
        _fail("source bindings changed after authenticated validation")
    if value.get("authorization") != {
        "packet_materialization_authorized": False,
        "live_launch_authorized": False,
        "canonical_import_authorized": False,
    }:
        _fail("source bindings false gates are invalid")
    if value.get("corpus_id") != "oss-expansion-50x50-lock-v2":
        _fail("source bindings corpus is invalid")
    return value, raw, cache_summary


def _private_parent(path: Path, *, absent: bool) -> tuple[Path, os.stat_result]:
    if not path.is_absolute() or (absent and (path.exists() or path.is_symlink())):
        _fail("output must be an absent absolute path")
    parent = path.parent
    current = Path(parent.anchor)
    for part in parent.parts[1:]:
        current /= part
        status = current.lstat()
        if stat.S_ISLNK(status.st_mode):
            _fail("output parent has a symlink ancestor")
    status = parent.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(status.st_mode)
        or status.st_uid != os.getuid()
        or stat.S_IMODE(status.st_mode) != 0o700
    ):
        _fail("output parent must be owned mode 0700")
    return parent, status


def _timestamp(now: datetime | None = None) -> str:
    value = datetime.now(timezone.utc) if now is None else now.astimezone(timezone.utc)
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail("authorization timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise PacketV1Error("authorization timestamp is invalid") from exc
    if parsed.microsecond or parsed.tzinfo is None:
        _fail("authorization timestamp is not canonical")
    return parsed


def _limits() -> dict[str, int]:
    return {
        "packets": _MAX_PACKETS,
        "unique_commits": _MAX_COMMITS,
        "files_per_packet": _MAX_FILES_PACKET,
        "blob_bytes": _MAX_BLOB,
        "snapshot_bytes": _MAX_SNAPSHOT,
        "packet_payload_bytes": _MAX_PACKET,
        "diff_bytes": _MAX_DIFF,
        "aggregate_entries": _MAX_AGGREGATE_ENTRIES,
        "aggregate_payload_bytes": _MAX_AGGREGATE_PAYLOAD,
        "staging_bytes": _STAGING_LIMIT,
        "commands_per_pass": _MAX_COMMANDS,
        "command_timeout_seconds": 180,
        "aggregate_deadline_seconds": _DEADLINE_SECONDS,
    }


def _authorization_hash(base: dict[str, Any]) -> str:
    return _sha(b"packet-materialization-authorization-v1\0" + canonical_json(base))


def authorize_packets(
    root: Path,
    campaign_path: Path,
    bindings_path: Path,
    cache: Path,
    ledger_root: Path,
    output_root: Path,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    profile = _profile(root)
    campaign, campaign_raw = _campaign(root, campaign_path)
    bindings, bindings_raw, cache_summary = _bindings(root, campaign_path, cache, bindings_path)
    parent, parent_status = _private_parent(output_root, absent=True)
    inventory_before = source_v1._inventory(cache)
    if bindings["cache"]["inventory_sha256"] != inventory_before["inventory_sha256"]:
        _fail("authorization cache inventory binding mismatch")
    if len(campaign["records"]) != 50 or len(campaign["lanes"]) != 100:
        _fail("campaign cardinality is invalid")
    issued_dt = datetime.now(timezone.utc) if now is None else now.astimezone(timezone.utc)
    issued = _timestamp(issued_dt)
    expires = _timestamp(issued_dt + timedelta(seconds=_AUTH_SECONDS))
    private = campaign_v1._private_root(ledger_root)
    with campaign_v1._ledger_lock(private):
        ledger = campaign_v1._validate_ledger_unlocked(private, root)
        if ledger["packet_authorization_present"] or ledger["packet_publication_present"]:
            _fail("packet authorization transition already exists")
        # Reauthenticate every fallible binding before the durable append. Nothing
        # after _publish may invalidate an already-recorded authorization.
        current_profile = _profile(root)
        if current_profile != profile:
            _fail("production profile drifted before authorization")
        current_bindings, current_bindings_raw, current_cache = _bindings(
            root, campaign_path, cache, bindings_path
        )
        current_inventory = source_v1._inventory(cache)
        current_parent = parent.stat(follow_symlinks=False)
        if (
            current_bindings != bindings
            or current_bindings_raw != bindings_raw
            or current_cache != cache_summary
            or current_inventory != inventory_before
            or _identity(current_parent) != _identity(parent_status)
            or output_root.exists()
            or output_root.is_symlink()
        ):
            _fail("packet authorization precondition drifted")
        base = {
            "schema_version": 1,
            "protocol": _AUTH_PROTOCOL,
            "campaign_id": campaign["id"],
            "campaign_manifest_sha256": _sha(campaign_raw),
            "source_bindings_sha256": _sha(bindings_raw),
            "cache_content_sha256": cache_summary["content_sha256"],
            "cache_device": cache_summary["cache_device"],
            "cache_inode": cache_summary["cache_inode"],
            "issue": campaign["assignment"]["issue"],
            "repository": campaign["assignment"]["repository"],
            "pr_count": 50,
            "lane_count": 100,
            "production_profile_sha256": _sha(profile.raw),
            "output_parent": str(parent),
            "output_basename": output_root.name,
            "output_parent_device": parent_status.st_dev,
            "output_parent_inode": parent_status.st_ino,
            "limits": _limits(),
            "authorizations": {
                "packet_materialization": True,
                "live_launch": False,
                "canonical_import": False,
            },
            "issued_at": issued,
            "expires_at": expires,
            "previous_hash": ledger["entry_hash"],
        }
        receipt = {**base, "entry_hash": _authorization_hash(base)}
        result = {
            "authorized": True,
            "entry_hash": receipt["entry_hash"],
            "expires_at": expires,
            "output": str(output_root),
            "live_launch_authorized": False,
            "canonical_import_authorized": False,
        }
        campaign_v1._publish(private / _AUTH_FILE, receipt)
    return result


def _receipt(
    root: Path,
    campaign_path: Path,
    bindings_path: Path,
    cache: Path,
    ledger_root: Path,
    output_root: Path,
    *,
    require_unused: bool,
    allow_expired: bool,
    publication_timestamp: str | None = None,
    now: datetime | None = None,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    bytes,
    dict[str, Any],
    bytes,
    dict[str, Any],
    ProfileSnapshot,
    dict[str, Any],
]:
    profile = _profile(root)
    campaign, campaign_raw = _campaign(root, campaign_path)
    bindings, bindings_raw, cache_summary = _bindings(root, campaign_path, cache, bindings_path)
    ledger = campaign_v1.validate_ledger(ledger_root, root)
    if not ledger["packet_authorization_present"]:
        _fail("packet authorization transition is absent")
    if require_unused and ledger["packet_publication_present"]:
        _fail("packet authorization has already been consumed")
    if not require_unused and not ledger["packet_publication_present"]:
        _fail("packet publication transition is absent")
    receipt, receipt_raw, _ = _json(ledger_root / _AUTH_FILE, modes={0o400})
    base = {key: value for key, value in receipt.items() if key != "entry_hash"}
    parent, parent_status = _private_parent(output_root, absent=False)
    expected = {
        "campaign_id": campaign["id"],
        "campaign_manifest_sha256": _sha(campaign_raw),
        "source_bindings_sha256": _sha(bindings_raw),
        "cache_content_sha256": cache_summary["content_sha256"],
        "cache_device": cache_summary["cache_device"],
        "cache_inode": cache_summary["cache_inode"],
        "issue": campaign["assignment"]["issue"],
        "repository": campaign["assignment"]["repository"],
        "pr_count": 50,
        "lane_count": 100,
        "production_profile_sha256": _sha(profile.raw),
        "output_parent": str(parent),
        "output_basename": output_root.name,
        "output_parent_device": parent_status.st_dev,
        "output_parent_inode": parent_status.st_ino,
        "limits": _limits(),
        "authorizations": {
            "packet_materialization": True,
            "live_launch": False,
            "canonical_import": False,
        },
        "previous_hash": ledger["genesis_entry_hash"],
    }
    if (
        receipt.get("schema_version") != 1
        or receipt.get("protocol") != _AUTH_PROTOCOL
        or receipt.get("entry_hash") != _authorization_hash(base)
        or ledger["packet_authorization_entry_hash"] != receipt.get("entry_hash")
        or any(receipt.get(key) != value for key, value in expected.items())
        or canonical_json(receipt) != receipt_raw
    ):
        _fail("packet authorization binding is invalid or stale")
    issued = _parse_timestamp(receipt.get("issued_at"))
    expires = _parse_timestamp(receipt.get("expires_at"))
    if expires - issued != timedelta(seconds=_AUTH_SECONDS):
        _fail("packet authorization validity interval is invalid")
    reference = datetime.now(timezone.utc) if now is None else now.astimezone(timezone.utc)
    if reference > expires:
        if not allow_expired or publication_timestamp is None:
            _fail("packet authorization expired")
        published = _parse_timestamp(publication_timestamp)
        if published < issued or published > expires:
            _fail("packet publication did not occur within authorization interval")
    return (
        receipt,
        campaign,
        campaign_raw,
        bindings,
        bindings_raw,
        cache_summary,
        profile,
        ledger,
    )


def _packet_name(record: dict[str, Any]) -> str:
    slug = str(record["repository"]).replace("/", "--")
    identity = f"{record['repository'].casefold()}#{record['pr']}"
    return f"{slug}--{record['pr']}--{hashlib.sha256(identity.encode()).hexdigest()[:16]}"


def _inventory(root: Path, *, limit: int, max_entries: int) -> dict[str, Any]:
    root_status = root.stat(follow_symlinks=False)
    if not stat.S_ISDIR(root_status.st_mode) or root_status.st_uid != os.getuid():
        _fail("inventory root is invalid")
    digest = hashlib.sha256()
    total = 0
    entries = 1
    rows: list[dict[str, Any]] = []
    for directory, names, filenames in os.walk(root, topdown=True, followlinks=False):
        names.sort()
        filenames.sort()
        base = Path(directory)
        for name in names:
            path = base / name
            status = path.lstat()
            if not stat.S_ISDIR(status.st_mode):
                _fail("inventory contains symlink or special directory")
            if entries + 1 > max_entries:
                _fail("aggregate inventory bound exceeded")
            relative = path.relative_to(root).as_posix()
            row = {
                "path": relative,
                "type": "directory",
                "mode": f"{stat.S_IMODE(status.st_mode):04o}",
            }
            rows.append(row)
            digest.update(canonical_json(row))
            entries += 1
        for name in filenames:
            path = base / name
            status = path.lstat()
            if not stat.S_ISREG(status.st_mode):
                _fail("inventory contains symlink or special file")
            if entries + 1 > max_entries or total + status.st_size > limit:
                _fail("aggregate inventory bound exceeded")
            relative = path.relative_to(root).as_posix()
            file_hash, size = packet_primitives._hash_file(path, max(_MAX_BLOB, _MAX_JSON))
            total += size
            file_row: dict[str, Any] = {
                "path": relative,
                "type": "file",
                "mode": f"{stat.S_IMODE(status.st_mode):04o}",
                "bytes": size,
                "sha256": file_hash,
            }
            rows.append(file_row)
            digest.update(canonical_json(file_row))
            entries += 1
        if entries > max_entries or total > limit:
            _fail("aggregate inventory bound exceeded")
    return {
        "entries": entries,
        "bytes": total,
        "sha256": f"sha256:{digest.hexdigest()}",
        "rows": rows,
    }


class ProductionGitRunner(packet_primitives.GitRunner):
    """Pilot runner with a fresh 180-second cap for every production command."""

    def __init__(self, *, aggregate_deadline: float, aggregate_counter: list[int]) -> None:
        super().__init__(deadline=aggregate_deadline)
        self.aggregate_deadline = aggregate_deadline
        self.aggregate_counter = aggregate_counter

    def run_to_path(self, *args: Any, **kwargs: Any) -> None:
        self.aggregate_counter[0] += 1
        if self.aggregate_counter[0] > _MAX_COMMANDS:
            _fail("aggregate Git command budget exceeded")
        original = self.deadline
        self.deadline = min(self.aggregate_deadline, time.monotonic() + 180)
        try:
            super().run_to_path(*args, **kwargs)
        finally:
            self.deadline = original


class AggregateBudget:
    """Pilot-compatible monotonic budget with production aggregate bounds."""

    def __init__(self, root: Path, limit: int) -> None:
        self.root = root
        self.limit = limit
        self.accounted = 0
        self.reconcile()

    def charge(self, size: int) -> None:
        if size < 0 or self.accounted + size > self.limit:
            _fail("staging byte budget exceeded")
        self.accounted += size
        if shutil.disk_usage(self.root).free < _HEADROOM:
            _fail("staging disk headroom exhausted")

    def release(self, size: int) -> None:
        if size < 0 or size > self.accounted:
            _fail("staging byte accounting underflow")
        self.accounted -= size

    def check_unaccounted(self, size: int) -> None:
        if size < 0 or self.accounted + size > self.limit:
            _fail("staging byte budget exceeded")
        if shutil.disk_usage(self.root).free < _HEADROOM:
            _fail("staging disk headroom exhausted")

    def reconcile(self) -> None:
        value = _inventory(self.root, limit=self.limit, max_entries=_MAX_AGGREGATE_ENTRIES)
        metadata = value["entries"] * _METADATA
        if value["bytes"] + metadata > self.limit:
            _fail("staging byte budget exceeded")
        self.accounted = cast("int", value["bytes"]) + metadata


def _gitlinks(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    return [
        {"path": row["path"], "commit": row["commit"], "contents_omitted": True} for row in rows
    ]


def _snapshot(
    runner: ProductionGitRunner,
    cache: Path,
    tree: str,
    destination: Path,
    budget: AggregateBudget,
) -> dict[str, Any]:
    destination.mkdir()
    listing = destination.parent / f".{destination.name}.ls-tree"
    try:
        runner.run_to_path(
            cache,
            ("ls-tree", "-rz", "--full-tree", "-r", tree),
            listing,
            limit=_TREE_SPOOL,
            staging_budget=cast("Any", budget),
        )
        blobs, raw_gitlinks = packet_primitives._parse_tree(
            packet_primitives._read_bounded(listing, _TREE_SPOOL)
        )
        if len(blobs) + len(raw_gitlinks) > _MAX_FILES_PACKET:
            _fail("snapshot file count exceeded before blob materialization")
        files, symlinks = packet_primitives._materialize_blobs(
            runner,
            cache,
            destination,
            blobs,
            cast("Any", budget),
        )
    finally:
        listing.unlink(missing_ok=True)
        budget.reconcile()
    gitlinks = raw_gitlinks
    if len(files) + len(symlinks) + len(gitlinks) > _MAX_FILES_PACKET:
        _fail("snapshot file count exceeded")
    logical = sum(cast("int", row["bytes"]) for row in [*files, *symlinks])
    if logical > _MAX_SNAPSHOT or any(cast("int", row["bytes"]) > _MAX_BLOB for row in files):
        _fail("snapshot byte bound exceeded")
    return {"tree": tree, "files": files, "symlinks": symlinks, "gitlinks": _gitlinks(gitlinks)}


def _payload_files(packet: Path) -> list[dict[str, Any]]:
    inventory = _inventory(packet, limit=_MAX_PACKET, max_entries=2 * _MAX_FILES_PACKET + 100)
    rows = [
        {"path": row["path"], "sha256": row["sha256"], "bytes": row["bytes"]}
        for row in inventory["rows"]
        if row["type"] == "file" and row["path"] != "packet-manifest.json"
    ]
    return sorted(rows, key=lambda row: cast("str", row["path"]))


def _packet_root(manifest: dict[str, Any]) -> str:
    payload = {key: value for key, value in manifest.items() if key != "packet_root_sha256"}
    return _sha(b"ground-truth-production-review-packet-v1\0" + canonical_json(payload))


def _aggregate_root(manifest: dict[str, Any]) -> str:
    payload = {key: value for key, value in manifest.items() if key != "aggregate_root_sha256"}
    return _sha(b"ground-truth-production-packet-aggregate-v1\0" + canonical_json(payload))


def _diff_template() -> list[str]:
    return [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "filter.lfs.smudge=",
        "-c",
        "core.useReplaceRefs=false",
        "-c",
        "maintenance.auto=false",
        "-c",
        "gc.auto=0",
        "-C",
        "{authenticated_exact_cache}",
        *_DIFF_ARGS,
        "{baseline_commit}",
        "{target_commit}",
    ]


def _structure(record: dict[str, Any], snapshots: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "id": "ground-truth-production-source-structure-v1",
        "repository": record["repository"],
        "pr": record["pr"],
        "baseline": snapshots["baseline"],
        "target": snapshots["target"],
    }


def _build_packet(
    cache: Path,
    packet: Path,
    record: dict[str, Any],
    bindings_hash: str,
    deadline: float,
    budget: AggregateBudget,
    control_bytes: dict[str, bytes],
    aggregate_counter: list[int],
) -> tuple[dict[str, Any], int]:
    packet.mkdir()
    policies = packet / "policies"
    policies.mkdir()
    for name in _PACKET_POLICY_FILES:
        relative = f"{_PROFILE_DIR}/{name}"
        raw = control_bytes.get(relative)
        if raw is None:
            _fail("captured packet policy bytes are absent")
        (policies / name).write_bytes(raw)
    runner = ProductionGitRunner(
        aggregate_deadline=deadline,
        aggregate_counter=aggregate_counter,
    )
    snapshots = {
        side: _snapshot(
            runner,
            cache,
            str(record[f"{side}_tree"]),
            packet / side,
            budget,
        )
        for side in ("baseline", "target")
    }
    total_entries = sum(
        len(cast("list[object]", snapshots[side][kind]))
        for side in ("baseline", "target")
        for kind in ("files", "symlinks", "gitlinks")
    )
    if total_entries > _MAX_FILES_PACKET:
        _fail("packet source entry count exceeded")
    structure = _structure(record, snapshots)
    structure_raw = canonical_json(structure)
    (packet / "source-structure.json").write_bytes(structure_raw)
    diff = packet / "snapshot.diff"
    runner.run_to_path(
        cache,
        (*_DIFF_ARGS, str(record["baseline_commit"]), str(record["target_commit"])),
        diff,
        limit=_MAX_DIFF,
        staging_budget=cast("Any", budget),
    )
    diff_hash, diff_bytes = packet_primitives._hash_file(diff, _MAX_DIFF)
    payload = _payload_files(packet)
    payload_bytes = sum(int(item["bytes"]) for item in payload)
    if payload_bytes > _MAX_PACKET:
        _fail("packet payload bound exceeded")
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "id": _PACKET_ID,
        "repository": record["repository"],
        "pr": record["pr"],
        "source_bindings_sha256": bindings_hash,
        "baseline_commit": record["baseline_commit"],
        "baseline_tree": record["baseline_tree"],
        "target_commit": record["target_commit"],
        "target_tree": record["target_tree"],
        "remote_diff": {
            "payload_present": False,
            "sha256": record["diff_sha256"],
            "bytes": record["diff_bytes"],
            "content_type": record["diff_content_type"],
            "final_url": record["diff_final_url"],
        },
        "local_snapshot": {
            "path": "snapshot.diff",
            "sha256": diff_hash,
            "bytes": diff_bytes,
            "relation_to_remote": "not_compared",
            "git_version": _GIT_VERSION,
            "diff_argv_template": _diff_template(),
        },
        "source_structure_sha256": _sha(structure_raw),
        "payload_files": payload,
        "payload_bytes": payload_bytes,
        "packet_root_sha256": "",
    }
    manifest["packet_root_sha256"] = _packet_root(manifest)
    (packet / "packet-manifest.json").write_bytes(canonical_json(manifest))
    budget.reconcile()
    if runner.commands != 5:
        _fail("packet Git command cardinality is not exactly five")
    return manifest, runner.commands


def _freeze(root: Path) -> None:
    directories: list[Path] = []
    for directory, names, filenames in os.walk(root, topdown=False, followlinks=False):
        base = Path(directory)
        for name in filenames:
            path = base / name
            if path.is_symlink() or not path.is_file():
                _fail("packet contains a special file")
            path.chmod(0o400, follow_symlinks=False)
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        for name in names:
            path = base / name
            if path.is_symlink() or not path.is_dir():
                _fail("packet contains a special directory")
            directories.append(path)
    for path in directories:
        path.chmod(0o500, follow_symlinks=False)
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    root.chmod(0o500, follow_symlinks=False)


def _thaw_remove(path: Path) -> None:
    if not path.exists() or path.is_symlink():
        return
    for directory, names, filenames in os.walk(path):
        Path(directory).chmod(0o700)
        for name in names:
            Path(directory, name).chmod(0o700)
        for name in filenames:
            Path(directory, name).chmod(0o600)
    shutil.rmtree(path, ignore_errors=True)


def _rename_noreplace(source: Path, target: Path) -> None:
    if source.parent != target.parent:
        _fail("packet publication requires same-parent staging")
    descriptor = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = libc.renameat2
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        if (
            renameat2(descriptor, os.fsencode(source.name), descriptor, os.fsencode(target.name), 1)
            == 0
        ):
            os.fsync(descriptor)
            return
        error = ctypes.get_errno()
        if error in {errno.EEXIST, errno.ENOTEMPTY}:
            _fail("packet output already exists at atomic publication")
        _fail(f"packet atomic publication failed: errno {error}")
    finally:
        os.close(descriptor)


def _forbidden_scan(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key.casefold() in _FORBIDDEN_PACKET_KEYS:
                _fail("reviewer packet contains a forbidden key")
            _forbidden_scan(item)
    elif isinstance(value, list):
        for item in value:
            _forbidden_scan(item)
    elif isinstance(value, str):
        lowered = value.casefold()
        if value.startswith("/") or "\\" in value or "/.cache/" in lowered:
            _fail("reviewer packet contains a host path")


def _aggregate_manifest(
    campaign: dict[str, Any],
    campaign_raw: bytes,
    bindings_raw: bytes,
    receipt: dict[str, Any],
    packet_rows: list[dict[str, Any]],
    published: str,
    inventory: dict[str, Any],
) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "id": _AGGREGATE_ID,
        "campaign_id": campaign["id"],
        "campaign_manifest_sha256": _sha(campaign_raw),
        "source_bindings_sha256": _sha(bindings_raw),
        "authorization_entry_hash": receipt["entry_hash"],
        "publication_timestamp": published,
        "packet_count": 50,
        "packets": packet_rows,
        "payload_bytes": inventory["bytes"],
        "payload_entries": inventory["entries"],
        "aggregate_root_sha256": "",
    }
    manifest["aggregate_root_sha256"] = _aggregate_root(manifest)
    return manifest


def _publication_hash(base: dict[str, Any]) -> str:
    return _sha(b"packet-materialization-publication-v1\0" + canonical_json(base))


def _publication_transition(
    campaign: dict[str, Any],
    campaign_raw: bytes,
    bindings_raw: bytes,
    receipt: dict[str, Any],
    output: Path,
    aggregate: dict[str, Any],
    aggregate_raw: bytes,
    inventory: dict[str, Any],
) -> dict[str, Any]:
    status = output.stat(follow_symlinks=False)
    base = {
        "schema_version": 1,
        "protocol": _PUBLICATION_PROTOCOL,
        "campaign_id": campaign["id"],
        "campaign_manifest_sha256": _sha(campaign_raw),
        "authorization_entry_hash": receipt["entry_hash"],
        "source_bindings_sha256": _sha(bindings_raw),
        "output_path": str(output),
        "output_device": status.st_dev,
        "output_inode": status.st_ino,
        "aggregate_manifest_sha256": _sha(aggregate_raw),
        "aggregate_root_sha256": aggregate["aggregate_root_sha256"],
        "inventory_sha256": inventory["sha256"],
        "payload_entries": aggregate["payload_entries"],
        "payload_bytes": aggregate["payload_bytes"],
        "publication_timestamp": aggregate["publication_timestamp"],
        "previous_hash": receipt["entry_hash"],
    }
    return {**base, "entry_hash": _publication_hash(base)}


def _append_publication(
    root: Path,
    ledger_root: Path,
    campaign: dict[str, Any],
    campaign_raw: bytes,
    bindings_raw: bytes,
    receipt: dict[str, Any],
    output: Path,
) -> dict[str, Any]:
    aggregate, aggregate_raw, _ = _json(output / "aggregate-manifest.json", modes={0o400})
    inventory = _inventory(output, limit=_MAX_AGGREGATE_PAYLOAD, max_entries=_MAX_AGGREGATE_ENTRIES)
    transition = _publication_transition(
        campaign,
        campaign_raw,
        bindings_raw,
        receipt,
        output,
        aggregate,
        aggregate_raw,
        inventory,
    )
    private = campaign_v1._private_root(ledger_root)
    with campaign_v1._ledger_lock(private):
        ledger = campaign_v1._validate_ledger_unlocked(private, root)
        if ledger["packet_publication_present"]:
            _fail("packet authorization has already been consumed")
        if ledger["entry_hash"] != receipt["entry_hash"]:
            _fail("packet authorization is not the current unused ledger head")
        current_aggregate, current_raw, _ = _json(output / "aggregate-manifest.json", modes={0o400})
        current_inventory = _inventory(
            output, limit=_MAX_AGGREGATE_PAYLOAD, max_entries=_MAX_AGGREGATE_ENTRIES
        )
        current_transition = _publication_transition(
            campaign,
            campaign_raw,
            bindings_raw,
            receipt,
            output,
            current_aggregate,
            current_raw,
            current_inventory,
        )
        if current_transition != transition:
            _fail("packet output drifted before publication ledger append")
        campaign_v1._publish(private / _PUBLICATION_FILE, transition)
    return transition


def _reauthenticate_boundary(
    root: Path,
    campaign_path: Path,
    bindings_path: Path,
    cache: Path,
    expected_profile: ProfileSnapshot,
    expected_bindings: dict[str, Any],
    expected_bindings_raw: bytes,
    expected_cache: dict[str, Any],
    expected_inventory: dict[str, Any],
) -> None:
    profile = _profile(root)
    bindings, bindings_raw, cache_summary = _bindings(root, campaign_path, cache, bindings_path)
    inventory = source_v1._inventory(cache)
    if (
        profile != expected_profile
        or bindings != expected_bindings
        or bindings_raw != expected_bindings_raw
        or cache_summary != expected_cache
        or inventory != expected_inventory
    ):
        _fail("profile, source binding, or cache drifted at publication boundary")


def _rewrite_aggregate(staging: Path, aggregate: dict[str, Any]) -> None:
    manifest = staging / "aggregate-manifest.json"
    staging.chmod(0o700)
    manifest.chmod(0o600)
    manifest.write_bytes(canonical_json(aggregate))
    manifest.chmod(0o400)
    _freeze(staging)


def build_packets(  # noqa: PLR0915 - explicit fail-closed publication boundary
    root: Path,
    campaign_path: Path,
    bindings_path: Path,
    cache: Path,
    ledger_root: Path,
    output: Path,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    if output.exists() or output.is_symlink():
        _fail("packet output already exists; run finalize-packets for recovery")
    (
        receipt,
        campaign,
        campaign_raw,
        bindings,
        bindings_raw,
        cache_summary,
        profile,
        _ledger,
    ) = _receipt(
        root,
        campaign_path,
        bindings_path,
        cache,
        ledger_root,
        output,
        require_unused=True,
        allow_expired=False,
        now=now,
    )
    parent, parent_status = _private_parent(output, absent=True)
    required = _STAGING_LIMIT + _HEADROOM
    if shutil.disk_usage(parent).free < required:
        _fail("insufficient disk for aggregate packet staging bound")
    cache_before = source_v1._inventory(cache)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=parent))
    staging.chmod(0o700)
    deadline = time.monotonic() + _DEADLINE_SECONDS
    budget = AggregateBudget(staging, _STAGING_LIMIT)
    rows: list[dict[str, Any]] = []
    commands = 0
    aggregate_counter = [0]
    try:
        by_pr = {row["pr"]: row for row in bindings["records"]}
        for record in campaign["records"]:
            bound = by_pr.get(record["pr"])
            if not isinstance(bound, dict):
                _fail("source binding record is missing")
            name = _packet_name(record)
            manifest, used = _build_packet(
                cache,
                staging / name,
                bound,
                _sha(bindings_raw),
                deadline,
                budget,
                profile.files,
                aggregate_counter,
            )
            commands += used
            rows.append(
                {
                    "rank": record["rank"],
                    "repository": record["repository"],
                    "pr": record["pr"],
                    "directory": name,
                    "packet_root_sha256": manifest["packet_root_sha256"],
                }
            )
        if commands != _MAX_COMMANDS or aggregate_counter[0] != _MAX_COMMANDS:
            _fail("aggregate build did not use exactly 250 Git commands")
        semantic_inventory = _inventory(
            staging, limit=_MAX_AGGREGATE_PAYLOAD, max_entries=_MAX_AGGREGATE_ENTRIES
        )
        preliminary_timestamp = cast("str", receipt["issued_at"])
        aggregate = _aggregate_manifest(
            campaign,
            campaign_raw,
            bindings_raw,
            receipt,
            rows,
            preliminary_timestamp,
            semantic_inventory,
        )
        (staging / "aggregate-manifest.json").write_bytes(canonical_json(aggregate))
        _freeze(staging)
        _validate_published(
            campaign,
            campaign_raw,
            bindings,
            bindings_raw,
            cache,
            staging,
            receipt,
            profile,
            regenerate=True,
            expected_publication=preliminary_timestamp,
        )
        _reauthenticate_boundary(
            root,
            campaign_path,
            bindings_path,
            cache,
            profile,
            bindings,
            bindings_raw,
            cache_summary,
            cache_before,
        )
        final_now = datetime.now(timezone.utc) if now is None else now.astimezone(timezone.utc)
        final_timestamp = _timestamp(final_now)
        # Revalidate current time and the exact still-unused authorization at the
        # final publication boundary.
        current = _receipt(
            root,
            campaign_path,
            bindings_path,
            cache,
            ledger_root,
            output,
            require_unused=True,
            allow_expired=False,
            now=final_now,
        )
        if current[:7] != (
            receipt,
            campaign,
            campaign_raw,
            bindings,
            bindings_raw,
            cache_summary,
            profile,
        ):
            _fail("authorization bindings drifted before packet publication")
        aggregate = _aggregate_manifest(
            campaign,
            campaign_raw,
            bindings_raw,
            receipt,
            rows,
            final_timestamp,
            semantic_inventory,
        )
        _rewrite_aggregate(staging, aggregate)
        _validate_published(
            campaign,
            campaign_raw,
            bindings,
            bindings_raw,
            cache,
            staging,
            receipt,
            profile,
            regenerate=False,
            expected_publication=final_timestamp,
        )
        _reauthenticate_boundary(
            root,
            campaign_path,
            bindings_path,
            cache,
            profile,
            bindings,
            bindings_raw,
            cache_summary,
            cache_before,
        )
        current_parent = parent.stat(follow_symlinks=False)
        if (current_parent.st_dev, current_parent.st_ino) != (
            parent_status.st_dev,
            parent_status.st_ino,
        ):
            _fail("packet output parent identity drifted")
        # In production, let _receipt sample the clock only after its expensive
        # reauthentication work, immediately before the atomic rename.
        rename_boundary_now = None if now is None else now.astimezone(timezone.utc)
        rename_boundary = _receipt(
            root,
            campaign_path,
            bindings_path,
            cache,
            ledger_root,
            output,
            require_unused=True,
            allow_expired=False,
            now=rename_boundary_now,
        )
        if rename_boundary[:7] != current[:7]:
            _fail("authorization bindings drifted at atomic packet publication")
        _rename_noreplace(staging, output)
    except BaseException:
        _thaw_remove(staging)
        raise
    transition = _append_publication(
        root, ledger_root, campaign, campaign_raw, bindings_raw, receipt, output
    )
    return {
        "output": str(output),
        "packets": 50,
        "commands": commands,
        "aggregate_root_sha256": aggregate["aggregate_root_sha256"],
        "publication_entry_hash": transition["entry_hash"],
        "live_launch_authorized": False,
        "canonical_import_authorized": False,
    }


def _bounded_int(value: object, *, maximum: int, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > maximum:
        _fail(f"{label} is invalid")
    return value


def _relative_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        _fail(f"{label} path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        _fail(f"{label} path is invalid")
    return value


def _validate_aggregate_header(aggregate: dict[str, Any]) -> None:
    rows = aggregate.get("packets")
    if (
        aggregate.get("packet_count") != _MAX_PACKETS
        or not isinstance(rows, list)
        or len(rows) != _MAX_PACKETS
        or _bounded_int(
            aggregate.get("payload_bytes"),
            maximum=_MAX_AGGREGATE_PAYLOAD,
            label="aggregate payload bytes",
        )
        < 0
        or _bounded_int(
            aggregate.get("payload_entries"),
            maximum=_MAX_AGGREGATE_ENTRIES,
            label="aggregate payload entries",
        )
        < 1
    ):
        _fail("aggregate manifest cardinality is invalid")
    ranks: set[int] = set()
    identities: set[tuple[str, int]] = set()
    directories: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            _fail("aggregate packet row is invalid")
        _strict(
            row,
            {"rank", "repository", "pr", "directory", "packet_root_sha256"},
            "aggregate packet row",
        )
        rank = _bounded_int(row["rank"], maximum=_MAX_PACKETS, label="packet rank")
        pr = _bounded_int(row["pr"], maximum=2**63 - 1, label="packet PR")
        repository = row["repository"]
        directory = _relative_path(row["directory"], "packet directory")
        root_hash = row["packet_root_sha256"]
        if (
            rank < 1
            or pr < 1
            or not isinstance(repository, str)
            or not _REPOSITORY.fullmatch(repository)
            or "/" in directory
            or not isinstance(root_hash, str)
            or not _DIGEST.fullmatch(root_hash)
            or rank in ranks
            or (repository, pr) in identities
            or directory in directories
        ):
            _fail("aggregate packet row value is invalid")
        ranks.add(rank)
        identities.add((repository, pr))
        directories.add(directory)
    if ranks != set(range(1, _MAX_PACKETS + 1)):
        _fail("aggregate packet ranks are invalid")


def _expected_paths(manifest: dict[str, Any]) -> tuple[set[str], set[str]]:
    files = {"packet-manifest.json"}
    payload = manifest.get("payload_files")
    if not isinstance(payload, list):
        _fail("packet payload inventory is invalid")
    for row in payload:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            _fail("packet payload row is invalid")
        files.add(row["path"])
    directories = {"baseline", "target", "policies"}
    for filename in files:
        for parent in PurePosixPath(filename).parents:
            if parent.as_posix() != ".":
                directories.add(parent.as_posix())
    return directories, files


def _validate_one_packet(  # noqa: PLR0912,PLR0915 - fail-closed reconciliation
    packet: Path,
    record: dict[str, Any],
    bindings_hash: str,
    control_bytes: dict[str, bytes],
) -> dict[str, Any]:
    manifest, raw, _ = _json(packet / "packet-manifest.json", modes={0o400})
    required = {
        "schema_version",
        "id",
        "repository",
        "pr",
        "source_bindings_sha256",
        "baseline_commit",
        "baseline_tree",
        "target_commit",
        "target_tree",
        "remote_diff",
        "local_snapshot",
        "source_structure_sha256",
        "payload_files",
        "payload_bytes",
        "packet_root_sha256",
    }
    _strict(manifest, required, "packet manifest")
    if (
        canonical_json(manifest) != raw
        or manifest["schema_version"] != 1
        or manifest["id"] != _PACKET_ID
        or manifest["repository"] != record["repository"]
        or manifest["pr"] != record["pr"]
        or manifest["source_bindings_sha256"] != bindings_hash
        or any(
            manifest[f"{side}_{field}"] != record[f"{side}_{field}"]
            for side in ("baseline", "target")
            for field in ("commit", "tree")
        )
        or manifest["packet_root_sha256"] != _packet_root(manifest)
    ):
        _fail("packet semantic binding is invalid")
    remote = manifest["remote_diff"]
    local = manifest["local_snapshot"]
    if not isinstance(remote, dict) or not isinstance(local, dict):
        _fail("diff metadata sections are invalid")
    _strict(
        remote, {"payload_present", "sha256", "bytes", "content_type", "final_url"}, "remote diff"
    )
    _strict(
        local,
        {"path", "sha256", "bytes", "relation_to_remote", "git_version", "diff_argv_template"},
        "local snapshot",
    )
    if remote != {
        "payload_present": False,
        "sha256": record["diff_sha256"],
        "bytes": record["diff_bytes"],
        "content_type": record["diff_content_type"],
        "final_url": record["diff_final_url"],
    }:
        _fail("remote diff metadata is invalid")
    if (
        not isinstance(local, dict)
        or local.get("path") != "snapshot.diff"
        or local.get("relation_to_remote") != "not_compared"
        or local.get("git_version") != _GIT_VERSION
        or local.get("diff_argv_template") != _diff_template()
    ):
        _fail("local snapshot metadata is invalid")
    diff_hash, diff_bytes = packet_primitives._hash_file(packet / "snapshot.diff", _MAX_DIFF)
    if local.get("sha256") != diff_hash or local.get("bytes") != diff_bytes:
        _fail("local snapshot file identity is invalid")
    structure_raw, _ = _read(packet / "source-structure.json", modes={0o400})
    if _sha(structure_raw) != manifest["source_structure_sha256"]:
        _fail("source structure hash mismatch")
    try:
        structure = json.loads(structure_raw, object_pairs_hook=_unique, parse_constant=_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise PacketV1Error("source structure JSON is invalid") from exc
    if not isinstance(structure, dict):
        _fail("source structure root is invalid")
    _strict(
        structure,
        {"schema_version", "id", "repository", "pr", "baseline", "target"},
        "source structure",
    )
    if (
        structure["schema_version"] != 1
        or structure["id"] != "ground-truth-production-source-structure-v1"
        or structure["repository"] != record["repository"]
        or structure["pr"] != record["pr"]
    ):
        _fail("source structure identity is invalid")
    _forbidden_scan(manifest)
    _forbidden_scan(structure)
    for side in ("baseline", "target"):
        snapshot = structure[side]
        if not isinstance(snapshot, dict):
            _fail("source structure snapshot is invalid")
        _strict(snapshot, {"tree", "files", "symlinks", "gitlinks"}, "source snapshot")
        if snapshot["tree"] != record[f"{side}_tree"]:
            _fail("source structure tree is invalid")
        files = snapshot["files"]
        symlinks = snapshot["symlinks"]
        gitlinks = snapshot["gitlinks"]
        if not all(isinstance(rows, list) for rows in (files, symlinks, gitlinks)):
            _fail("source structure entry lists are invalid")
        for file_row in files:
            if not isinstance(file_row, dict):
                _fail("file metadata is invalid")
            _strict(file_row, {"path", "mode", "oid", "sha256", "bytes"}, "file metadata")
            if (
                file_row["mode"] not in {"100644", "100755"}
                or not isinstance(file_row["oid"], str)
                or not _SHA.fullmatch(file_row["oid"])
                or not isinstance(file_row["sha256"], str)
                or not _DIGEST.fullmatch(file_row["sha256"])
            ):
                _fail("file metadata value is invalid")
            _relative_path(file_row["path"], "file")
            _bounded_int(file_row["bytes"], maximum=_MAX_BLOB, label="file bytes")
        for symlink in symlinks:
            if not isinstance(symlink, dict):
                _fail("symlink metadata is invalid")
            _strict(
                symlink,
                {"path", "oid", "target_hex", "sha256", "bytes"},
                "symlink metadata",
            )
            raw_bytes = _bounded_int(symlink["bytes"], maximum=_MAX_BLOB, label="symlink bytes")
            if (
                not isinstance(symlink["oid"], str)
                or not _SHA.fullmatch(symlink["oid"])
                or not isinstance(symlink["sha256"], str)
                or not _DIGEST.fullmatch(symlink["sha256"])
                or not isinstance(symlink["target_hex"], str)
                or len(symlink["target_hex"]) != 2 * raw_bytes
            ):
                _fail("symlink metadata value is invalid")
            try:
                bytes.fromhex(symlink["target_hex"])
            except ValueError as exc:
                raise PacketV1Error("symlink target hex is invalid") from exc
            _relative_path(symlink["path"], "symlink")
        for link in gitlinks:
            if not isinstance(link, dict):
                _fail("gitlink metadata is invalid")
            _strict(link, {"path", "commit", "contents_omitted"}, "gitlink")
            if (
                link.get("contents_omitted") is not True
                or not isinstance(link.get("commit"), str)
                or not _SHA.fullmatch(link["commit"])
            ):
                _fail("gitlink omission marker or commit is invalid")
            _relative_path(link["path"], "gitlink")
        if len(files) + len(symlinks) + len(gitlinks) > _MAX_FILES_PACKET:
            _fail("source snapshot entry cardinality is invalid")
    payload = _payload_files(packet)
    manifest_payload = manifest["payload_files"]
    if not isinstance(manifest_payload, list):
        _fail("manifest payload inventory is invalid")
    for row in manifest_payload:
        if not isinstance(row, dict):
            _fail("manifest payload row is invalid")
        _strict(row, {"path", "sha256", "bytes"}, "manifest payload row")
        if (
            not isinstance(row["path"], str)
            or not isinstance(row["sha256"], str)
            or not _DIGEST.fullmatch(row["sha256"])
            or not isinstance(row["bytes"], int)
            or isinstance(row["bytes"], bool)
            or row["bytes"] < 0
        ):
            _fail("manifest payload row value is invalid")
        _relative_path(row["path"], "manifest payload")
        _bounded_int(row["bytes"], maximum=_MAX_BLOB, label="manifest payload bytes")
    _bounded_int(manifest["payload_bytes"], maximum=_MAX_PACKET, label="packet payload bytes")
    if (
        payload != manifest_payload
        or sum(int(row["bytes"]) for row in payload) != manifest["payload_bytes"]
    ):
        _fail("packet payload inventory mismatch")
    dirs, files = _expected_paths(manifest)
    inventory = _inventory(packet, limit=_MAX_PACKET, max_entries=2 * _MAX_FILES_PACKET + 100)
    actual_dirs = {row["path"] for row in inventory["rows"] if row["type"] == "directory"}
    actual_files = {row["path"] for row in inventory["rows"] if row["type"] == "file"}
    if dirs != actual_dirs or files != actual_files:
        _fail("packet contains missing or extra paths")
    for row in inventory["rows"]:
        if row["mode"] not in {"0400", "0500"}:
            _fail("packet contains writable or executable output")
    for name in _PACKET_POLICY_FILES:
        expected = control_bytes.get(f"{_PROFILE_DIR}/{name}")
        actual, _ = _read(packet / "policies" / name, modes={0o400})
        if expected is None or actual != expected:
            _fail("packet policy bytes mismatch")
    return manifest


def _validate_published(
    campaign: dict[str, Any],
    campaign_raw: bytes,
    bindings: dict[str, Any],
    bindings_raw: bytes,
    cache: Path,
    output: Path,
    receipt: dict[str, Any],
    profile: ProfileSnapshot,
    *,
    regenerate: bool,
    expected_publication: str | None = None,
) -> dict[str, Any]:
    before = _inventory(output, limit=_MAX_AGGREGATE_PAYLOAD, max_entries=_MAX_AGGREGATE_ENTRIES)
    aggregate, aggregate_raw, _ = _json(output / "aggregate-manifest.json", modes={0o400})
    required = {
        "schema_version",
        "id",
        "campaign_id",
        "campaign_manifest_sha256",
        "source_bindings_sha256",
        "authorization_entry_hash",
        "publication_timestamp",
        "packet_count",
        "packets",
        "payload_bytes",
        "payload_entries",
        "aggregate_root_sha256",
    }
    _strict(aggregate, required, "aggregate manifest")
    _validate_aggregate_header(aggregate)
    if (
        canonical_json(aggregate) != aggregate_raw
        or aggregate["schema_version"] != 1
        or aggregate["id"] != _AGGREGATE_ID
        or aggregate["campaign_id"] != campaign["id"]
        or aggregate["campaign_manifest_sha256"] != _sha(campaign_raw)
        or aggregate["source_bindings_sha256"] != _sha(bindings_raw)
        or aggregate["authorization_entry_hash"] != receipt["entry_hash"]
        or aggregate["packet_count"] != 50
        or aggregate["aggregate_root_sha256"] != _aggregate_root(aggregate)
        or (
            expected_publication is not None
            and aggregate["publication_timestamp"] != expected_publication
        )
    ):
        _fail("aggregate manifest binding is invalid")
    expected_names = [_packet_name(row) for row in campaign["records"]]
    actual_top = sorted(
        entry.name for entry in os.scandir(output) if entry.is_dir(follow_symlinks=False)
    )
    top_files = sorted(
        entry.name for entry in os.scandir(output) if entry.is_file(follow_symlinks=False)
    )
    if sorted(expected_names) != actual_top or top_files != ["aggregate-manifest.json"]:
        _fail("aggregate contains missing or extra top-level entries")
    semantic_rows = [row for row in before["rows"] if row.get("path") != "aggregate-manifest.json"]
    semantic_bytes = sum(int(row["bytes"]) for row in semantic_rows if row.get("type") == "file")
    semantic_entries = 1 + len(semantic_rows)
    if (
        aggregate["payload_bytes"] != semantic_bytes
        or aggregate["payload_entries"] != semantic_entries
        or aggregate["payload_bytes"] > _MAX_AGGREGATE_PAYLOAD
        or aggregate["payload_entries"] > _MAX_AGGREGATE_ENTRIES
    ):
        _fail("aggregate payload inventory summary is invalid")
    if stat.S_IMODE(output.stat(follow_symlinks=False).st_mode) != 0o500:
        _fail("aggregate root mode is invalid")
    if any(row["mode"] not in {"0400", "0500"} for row in before["rows"]):
        _fail("aggregate contains writable or executable entries")
    by_pr = {row["pr"]: row for row in bindings["records"]}
    rows: list[dict[str, Any]] = []
    manifests: list[dict[str, Any]] = []
    for campaign_record, name in zip(campaign["records"], expected_names, strict=True):
        bound = by_pr[campaign_record["pr"]]
        manifest = _validate_one_packet(output / name, bound, _sha(bindings_raw), profile.files)
        manifests.append(manifest)
        rows.append(
            {
                "rank": campaign_record["rank"],
                "repository": campaign_record["repository"],
                "pr": campaign_record["pr"],
                "directory": name,
                "packet_root_sha256": manifest["packet_root_sha256"],
            }
        )
    if aggregate["packets"] != rows:
        _fail("aggregate packet ordering or identities are invalid")
    if regenerate:
        deadline = time.monotonic() + _DEADLINE_SECONDS
        with tempfile.TemporaryDirectory(
            prefix="production-packet-regenerate-", dir=output.parent
        ) as name:
            regeneration = Path(name)
            budget = AggregateBudget(regeneration, _STAGING_LIMIT)
            commands = 0
            aggregate_counter = [0]
            regenerated: list[dict[str, Any]] = []
            for bound, expected in zip(bindings["records"], manifests, strict=True):
                packet = regeneration / _packet_name(bound)
                value, used = _build_packet(
                    cache,
                    packet,
                    bound,
                    _sha(bindings_raw),
                    deadline,
                    budget,
                    profile.files,
                    aggregate_counter,
                )
                commands += used
                regenerated.append(value)
                if value != expected:
                    _fail("packet differs from exact Git regeneration")
            if commands != _MAX_COMMANDS or aggregate_counter[0] != _MAX_COMMANDS:
                _fail("packet regeneration command cardinality is invalid")
    after = _inventory(output, limit=_MAX_AGGREGATE_PAYLOAD, max_entries=_MAX_AGGREGATE_ENTRIES)
    if before != after:
        _fail("complete packet aggregate inventory drifted during validation")
    return aggregate


def _validate_publication_transition(
    root: Path,
    ledger_root: Path,
    campaign: dict[str, Any],
    campaign_raw: bytes,
    bindings_raw: bytes,
    receipt: dict[str, Any],
    output: Path,
) -> dict[str, Any]:
    ledger = campaign_v1.validate_ledger(ledger_root, root)
    if not ledger["packet_publication_present"]:
        _fail("packet publication transition is absent")
    stored, stored_raw, _ = _json(ledger_root / _PUBLICATION_FILE, modes={0o400})
    aggregate, aggregate_raw, _ = _json(output / "aggregate-manifest.json", modes={0o400})
    inventory = _inventory(output, limit=_MAX_AGGREGATE_PAYLOAD, max_entries=_MAX_AGGREGATE_ENTRIES)
    expected = _publication_transition(
        campaign,
        campaign_raw,
        bindings_raw,
        receipt,
        output,
        aggregate,
        aggregate_raw,
        inventory,
    )
    if (
        stored != expected
        or canonical_json(stored) != stored_raw
        or ledger["entry_hash"] != stored["entry_hash"]
        or ledger["packet_publication_entry_hash"] != stored["entry_hash"]
    ):
        _fail("packet publication transition does not bind the exact output")
    return stored


def finalize_packets(
    root: Path,
    campaign_path: Path,
    bindings_path: Path,
    cache: Path,
    ledger_root: Path,
    output: Path,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    aggregate, _, _ = _json(output / "aggregate-manifest.json", modes={0o400})
    publication = aggregate.get("publication_timestamp")
    if not isinstance(publication, str):
        _fail("aggregate publication timestamp is invalid")
    (
        receipt,
        campaign,
        campaign_raw,
        bindings,
        bindings_raw,
        cache_summary,
        profile,
        _ledger,
    ) = _receipt(
        root,
        campaign_path,
        bindings_path,
        cache,
        ledger_root,
        output,
        require_unused=True,
        allow_expired=True,
        publication_timestamp=publication,
        now=now,
    )
    cache_before = source_v1._inventory(cache)
    result = _validate_published(
        campaign,
        campaign_raw,
        bindings,
        bindings_raw,
        cache,
        output,
        receipt,
        profile,
        regenerate=True,
        expected_publication=publication,
    )
    _reauthenticate_boundary(
        root,
        campaign_path,
        bindings_path,
        cache,
        profile,
        bindings,
        bindings_raw,
        cache_summary,
        cache_before,
    )
    transition = _append_publication(
        root, ledger_root, campaign, campaign_raw, bindings_raw, receipt, output
    )
    return {
        "finalized": True,
        "packets": 50,
        "aggregate_root_sha256": result["aggregate_root_sha256"],
        "publication_entry_hash": transition["entry_hash"],
        "live_launch_authorized": False,
        "canonical_import_authorized": False,
    }


def validate_packets(
    root: Path,
    campaign_path: Path,
    bindings_path: Path,
    cache: Path,
    ledger_root: Path,
    output: Path,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    aggregate, _, _ = _json(output / "aggregate-manifest.json", modes={0o400})
    publication = aggregate.get("publication_timestamp")
    if not isinstance(publication, str):
        _fail("aggregate publication timestamp is invalid")
    (
        receipt,
        campaign,
        campaign_raw,
        bindings,
        bindings_raw,
        cache_summary,
        profile,
        _ledger,
    ) = _receipt(
        root,
        campaign_path,
        bindings_path,
        cache,
        ledger_root,
        output,
        require_unused=False,
        allow_expired=True,
        publication_timestamp=publication,
        now=now,
    )
    cache_before = source_v1._inventory(cache)
    result = _validate_published(
        campaign,
        campaign_raw,
        bindings,
        bindings_raw,
        cache,
        output,
        receipt,
        profile,
        regenerate=True,
    )
    _reauthenticate_boundary(
        root,
        campaign_path,
        bindings_path,
        cache,
        profile,
        bindings,
        bindings_raw,
        cache_summary,
        cache_before,
    )
    transition = _validate_publication_transition(
        root, ledger_root, campaign, campaign_raw, bindings_raw, receipt, output
    )
    return {
        "valid": True,
        "packets": 50,
        "aggregate_root_sha256": result["aggregate_root_sha256"],
        "publication_timestamp": result["publication_timestamp"],
        "publication_entry_hash": transition["entry_hash"],
        "live_launch_authorized": False,
        "canonical_import_authorized": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    sub = parser.add_subparsers(dest="command", required=True)
    for name in (
        "authorize-packets",
        "build-packets",
        "finalize-packets",
        "validate-packets",
    ):
        command = sub.add_parser(name)
        command.add_argument("--campaign", type=Path, required=True)
        command.add_argument("--bindings", type=Path, required=True)
        command.add_argument("--cache", type=Path, required=True)
        command.add_argument("--ledger-root", type=Path, required=True)
        if name == "authorize-packets":
            command.add_argument("--output-root", type=Path, required=True)
        else:
            command.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = args.root.resolve(strict=True)
    if args.command == "authorize-packets":
        result = authorize_packets(
            root, args.campaign, args.bindings, args.cache, args.ledger_root, args.output_root
        )
    elif args.command == "build-packets":
        result = build_packets(
            root, args.campaign, args.bindings, args.cache, args.ledger_root, args.output
        )
    elif args.command == "finalize-packets":
        result = finalize_packets(
            root, args.campaign, args.bindings, args.cache, args.ledger_root, args.output
        )
    else:
        result = validate_packets(
            root, args.campaign, args.bindings, args.cache, args.ledger_root, args.output
        )
    print(canonical_json(result).decode(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
