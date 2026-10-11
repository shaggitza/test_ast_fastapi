"""Isolated v1 pre-readiness recovery grant format and append-only writer.

This extension does not alter the production-v1 ledger reader or prepare path.
It is safe to exercise only against synthetic directories until its profile is
published and integrated with those official paths.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from benchmarks.real_world.ground_truth_v2.schema import canonical_json

_PROTOCOL = "ground-truth-review-canary-pre-readiness-recovery-v1"
_DOMAIN = (_PROTOCOL + "\0").encode()
_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_ATTEMPT = re.compile(r"^prod-v1-i[0-9]{3}-rank[0-9]{3}-pr[0-9]+-[AB]$")
_ENTRY = re.compile(r"^[0-9]{6}-[A-Za-z0-9_-]+\.json$")
_ARCHIVE = re.compile(r"^evidence/(?!\.\.?(/|$))(?:[A-Za-z0-9_-]+/)*(?!\.\.?(/|$))[A-Za-z0-9._-]+$")
_ZERO = "sha256:" + "0" * 64
_REQUIRED = {
    "schema_version",
    "protocol",
    "sequence",
    "campaign_id",
    "campaign_manifest_sha256",
    "canonical_campaign_path",
    "corpus_sha256",
    "attempt_id",
    "lane",
    "reviewer_id",
    "source_bindings_sha256",
    "packet_publication_entry_hash",
    "runtime_attestation_entry_hash",
    "production_profile_sha256",
    "prior_authorization_entry_hash",
    "prior_authorization_expires_at",
    "failed_event_entry_hash",
    "failed_event_kind",
    "failure_phase",
    "failure_reason",
    "evidence",
    "no_launch_proof",
    "custody_inventory_sha256",
    "issued_at",
    "expires_at",
    "previous_hash",
    "entry_hash",
}
_PROOF_KEYS = {
    "authoritative",
    "prepared_absent",
    "launch_claim_absent",
    "model_invocation_absent",
    "native_result_absent",
    "pending_absent",
    "submission_absent",
    "reviewer_interaction_absent",
    "broker_dead",
    "socket_registry_slot_cleanup_verified",
}


class RecoveryError(ValueError):
    """Invalid recovery grant or chain."""


def _hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise RecoveryError(f"{label} must be a sha256 digest")
    return value


def _time(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise RecoveryError(f"{label} must be a timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RecoveryError(f"{label} must be an ISO timestamp") from exc
    if result.tzinfo is None:
        raise RecoveryError(f"{label} must include a timezone")
    return result.astimezone(timezone.utc)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RecoveryError("recovery JSON contains duplicate keys")
        result[key] = value
    return result


def _entry_hash(record: dict[str, Any]) -> str:
    body = {key: value for key, value in record.items() if key != "entry_hash"}
    return "sha256:" + hashlib.sha256(_DOMAIN + canonical_json(body)).hexdigest()


def validate_prepare_preflight(
    caller_paths: dict[str, Path],
    caller_hashes: dict[str, str],
    authenticated_paths: dict[str, str],
    authenticated_hashes: dict[str, str],
) -> None:
    """Reject caller input drift before a future v2 prepare path claims a lane.

    Callers must run this after authenticating runtime custody and before creating
    a slot, attempt claim, or ledger event. Paths are canonical identities; equal
    bytes at a different path do not satisfy custody.
    """
    required = {"campaign", "source", "cache", "ledger", "packet"}
    if set(caller_paths) != required or set(caller_hashes) != required:
        raise RecoveryError("prepare preflight inputs are incomplete")
    if set(authenticated_paths) != required or set(authenticated_hashes) != required:
        raise RecoveryError("authenticated custody inputs are incomplete")
    for name in sorted(required):
        try:
            supplied_path = str(caller_paths[name].resolve(strict=True))
        except (OSError, RuntimeError) as exc:
            raise RecoveryError(f"caller {name} path is unavailable") from exc
        if supplied_path != authenticated_paths[name]:
            raise RecoveryError(f"caller {name} path differs from authenticated custody")
        if _hash(caller_hashes[name], f"caller {name} hash") != _hash(
            authenticated_hashes[name], f"authenticated {name} hash"
        ):
            raise RecoveryError(f"caller {name} hash differs from authenticated custody")


def validate_grant(  # noqa: PLR0912, PLR0915
    record: dict[str, Any],
    *,
    expected: dict[str, Any],
    previous_hash: str,
    sequence: int,
    now: datetime,
) -> None:
    """Validate strict grant structure, incident bindings, one-shot scope and expiry."""
    if set(record) != _REQUIRED:
        raise RecoveryError("grant fields do not match the strict schema")
    if record["schema_version"] != 1 or record["protocol"] != _PROTOCOL:
        raise RecoveryError("unsupported recovery protocol")
    expected_keys = _REQUIRED - {
        "schema_version",
        "protocol",
        "sequence",
        "evidence",
        "no_launch_proof",
        "custody_inventory_sha256",
        "issued_at",
        "expires_at",
        "previous_hash",
        "entry_hash",
    }
    if set(expected) != expected_keys:
        raise RecoveryError("expected recovery binding fields are incomplete")
    if (
        not isinstance(record["sequence"], int)
        or isinstance(record["sequence"], bool)
        or record["sequence"] < 1
    ):
        raise RecoveryError("recovery sequence is invalid")
    for key in ("campaign_id", "canonical_campaign_path", "reviewer_id"):
        if not isinstance(record[key], str) or not record[key]:
            raise RecoveryError(f"{key} must be a nonempty string")
    attempt_id = record.get("attempt_id")
    if not isinstance(attempt_id, str) or not _ATTEMPT.fullmatch(attempt_id):
        raise RecoveryError("attempt id is invalid")
    lane = record.get("lane")
    if not isinstance(lane, str) or lane not in {"A", "B"} or not attempt_id.endswith("-" + lane):
        raise RecoveryError("attempt id and lane do not match")
    if record["sequence"] != sequence or record["previous_hash"] != previous_hash:
        raise RecoveryError("recovery chain sequence or head mismatch")
    _hash(record["previous_hash"], "previous_hash")
    for key in (
        "campaign_manifest_sha256",
        "corpus_sha256",
        "source_bindings_sha256",
        "packet_publication_entry_hash",
        "runtime_attestation_entry_hash",
        "production_profile_sha256",
        "prior_authorization_entry_hash",
        "failed_event_entry_hash",
        "custody_inventory_sha256",
    ):
        _hash(record[key], key)
    if record["failed_event_kind"] != "operational_failed":
        raise RecoveryError("recovery must reference an operational_failed event")
    phases = {
        "prebinding": (
            "runtime custody paths or profile changed",
            {"failed_event", "no_launch_census", "cleanup_inventory"},
        ),
        "binding_created_broker_not_ready": (
            "broker failed before readiness",
            {"failed_event", "binding", "broker_log", "no_launch_census", "cleanup_inventory"},
        ),
    }
    phase = record["failure_phase"]
    if not isinstance(phase, str) or phase not in phases:
        raise RecoveryError("failure phase and reason are not an allowed pair")
    if record["failure_reason"] != phases[phase][0]:
        raise RecoveryError("failure phase and reason are not an allowed pair")
    if any(record.get(key) != value for key, value in expected.items()):
        raise RecoveryError("grant identity or custody binding mismatch")
    evidence = record["evidence"]
    if not isinstance(evidence, list) or any(
        not isinstance(item, dict) or set(item) != {"kind", "sha256", "archive_path"}
        for item in evidence
    ):
        raise RecoveryError("evidence inventory is malformed")
    if any(not isinstance(item["kind"], str) for item in evidence):
        raise RecoveryError("evidence kind is malformed")
    kinds = [item["kind"] for item in evidence]
    if len(kinds) != len(set(kinds)) or set(kinds) != phases[phase][1]:
        raise RecoveryError("evidence cardinality does not match the failure phase")
    for item in evidence:
        _hash(item["sha256"], "evidence sha256")
        if not isinstance(item["archive_path"], str) or not _ARCHIVE.fullmatch(
            item["archive_path"]
        ):
            raise RecoveryError("evidence archive path is unsafe")
    # Evidence sha256 hashes archived bytes; the ledger entry hash uses a
    # domain-separated canonical record hash. The official adapter verifies the
    # archived event body against failed_event_entry_hash after reading it.
    proof = record["no_launch_proof"]
    if (
        not isinstance(proof, dict)
        or set(proof) != _PROOF_KEYS
        or any(value is not True for value in proof.values())
    ):
        raise RecoveryError("authoritative no-launch and cleanup proof is incomplete")
    issued, expires = (
        _time(record["issued_at"], "issued_at"),
        _time(record["expires_at"], "expires_at"),
    )
    auth_expiry = _time(record["prior_authorization_expires_at"], "prior_authorization_expires_at")
    if expires <= now.astimezone(timezone.utc) or issued > now.astimezone(timezone.utc):
        raise RecoveryError("recovery grant is expired or issued in the future")
    if expires <= issued or expires - issued > timedelta(hours=24) or expires > auth_expiry:
        raise RecoveryError("recovery grant exceeds its bounded authorization window")
    if record["entry_hash"] != _entry_hash(record):
        raise RecoveryError("recovery grant entry hash is invalid")


def _open_chain_root(root: Path, *, create: bool) -> int:
    """Open every directory component with O_NOFOLLOW; return the final dir fd."""
    absolute = Path(os.path.abspath(root))  # noqa: PTH100
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(absolute.anchor, flags)
    try:
        for component in absolute.parts[1:]:
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise RecoveryError("recovery ledger root is unavailable") from None
                with contextlib.suppress(FileExistsError):
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        status = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(status.st_mode)
            or status.st_uid != os.getuid()
            or stat.S_IMODE(status.st_mode) != 0o700
        ):
            raise RecoveryError("recovery ledger root must be an owned private directory")
        return descriptor
    except OSError as exc:
        os.close(descriptor)
        raise RecoveryError("recovery ledger path contains an unsafe or missing component") from exc
    except BaseException:
        os.close(descriptor)
        raise


def _load_chain_fd(root_fd: int) -> list[dict[str, Any]]:  # noqa: PLR0912
    names = sorted(os.listdir(root_fd))
    if any(not _ENTRY.fullmatch(name) for name in names):
        raise RecoveryError("recovery ledger contains an unexpected entry")
    rows: list[dict[str, Any]] = []
    for index, name in enumerate(names, 1):
        expected_name = re.compile(rf"^{index:06d}-.+\.json$")
        if not expected_name.fullmatch(name):
            raise RecoveryError("recovery ledger sequence is invalid")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(name, flags, dir_fd=root_fd)
        except OSError as exc:
            raise RecoveryError("recovery ledger contains an unsafe entry") from exc
        try:
            status = os.fstat(descriptor)
            if (
                not stat.S_ISREG(status.st_mode)
                or status.st_uid != os.getuid()
                or stat.S_IMODE(status.st_mode) != 0o400
            ):
                raise RecoveryError("recovery ledger contains an unsafe entry")
            chunks = []
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                chunks.append(block)
            raw = b"".join(chunks)
            row = json.loads(raw, object_pairs_hook=_unique_pairs)
            if canonical_json(row) != raw:
                raise RecoveryError("recovery ledger entry is not canonical JSON")
            if not isinstance(row, dict):
                raise RecoveryError("recovery ledger entry is not an object")
        except (ValueError, UnicodeDecodeError) as exc:
            raise RecoveryError("recovery ledger entry is malformed") from exc
        finally:
            os.close(descriptor)
        previous = rows[-1]["entry_hash"] if rows else _ZERO
        if (
            row.get("sequence") != index
            or row.get("previous_hash") != previous
            or row.get("protocol") != _PROTOCOL
            or row.get("entry_hash") != _entry_hash(row)
            or not isinstance(row.get("attempt_id"), str)
            or not _ATTEMPT.fullmatch(row["attempt_id"])
        ):
            raise RecoveryError("recovery ledger chain integrity is invalid")
        rows.append(row)
    if len({row["attempt_id"] for row in rows}) != len(rows):
        raise RecoveryError("recovery ledger contains a replayed attempt")
    return rows


def _load_chain(root: Path) -> list[dict[str, Any]]:
    root_fd = _open_chain_root(root, create=False)
    try:
        return _load_chain_fd(root_fd)
    finally:
        os.close(root_fd)


def append_grant(
    root: Path, record: dict[str, Any], *, expected: dict[str, Any], now: datetime
) -> dict[str, Any]:
    """Append one grant through a no-follow directory descriptor; refuse replay/clobber."""
    attempt_id = record.get("attempt_id")
    if not isinstance(attempt_id, str) or not _ATTEMPT.fullmatch(attempt_id):
        raise RecoveryError("attempt id is invalid")
    root_fd = _open_chain_root(root, create=True)
    try:
        rows = _load_chain_fd(root_fd)
        if any(row.get("attempt_id") == attempt_id for row in rows):
            raise RecoveryError("this attempt already has its one permitted recovery grant")
        prior = rows[-1]["entry_hash"] if rows else _ZERO
        candidate = dict(record)
        candidate["sequence"] = len(rows) + 1
        candidate["previous_hash"] = prior
        candidate["protocol"] = _PROTOCOL
        candidate["schema_version"] = 1
        candidate["entry_hash"] = _entry_hash(candidate)
        validate_grant(
            candidate, expected=expected, previous_hash=prior, sequence=len(rows) + 1, now=now
        )
        name = f"{len(rows) + 1:06d}-{attempt_id}.json"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(name, flags, 0o400, dir_fd=root_fd)
        except OSError as exc:
            raise RecoveryError("recovery grant path already exists or is unsafe") from exc
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(canonical_json(candidate))
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(root_fd)
        except BaseException:
            os.unlink(name, dir_fd=root_fd)
            raise
        return candidate
    finally:
        os.close(root_fd)


def validate_chain(
    root: Path, *, expected_by_attempt: dict[str, dict[str, Any]], now: datetime
) -> list[dict[str, Any]]:
    """Validate every grant and reject duplicate attempts or chain replay."""
    rows = _load_chain(root)
    previous = _ZERO
    seen: set[str] = set()
    for index, row in enumerate(rows, 1):
        attempt = row.get("attempt_id")
        if attempt in seen or attempt not in expected_by_attempt:
            raise RecoveryError("replayed or out-of-scope recovery grant")
        validate_grant(
            row,
            expected=expected_by_attempt[attempt],
            previous_hash=previous,
            sequence=index,
            now=now,
        )
        seen.add(attempt)
        previous = row["entry_hash"]
    return rows
