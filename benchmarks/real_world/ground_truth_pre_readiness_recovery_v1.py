"""Isolated v1 pre-readiness recovery grant format and append-only writer.

This extension does not alter the production-v1 ledger reader or prepare path.
It is safe to exercise only against synthetic directories until its profile is
published and integrated with those official paths.
"""

from __future__ import annotations

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


def validate_grant(  # noqa: PLR0912
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
    if record["sequence"] != sequence or record["previous_hash"] != previous_hash:
        raise RecoveryError("recovery chain sequence or head mismatch")
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
            "canonical campaign path mismatch",
            {"failed_event", "no_launch_census", "cleanup_inventory"},
        ),
        "binding_created_broker_not_ready": (
            "broker failed before readiness",
            {"failed_event", "binding", "broker_log", "no_launch_census", "cleanup_inventory"},
        ),
    }
    phase = record["failure_phase"]
    if phase not in phases or record["failure_reason"] != phases[phase][0]:
        raise RecoveryError("failure phase and reason are not an allowed pair")
    if any(record.get(key) != value for key, value in expected.items()):
        raise RecoveryError("grant identity or custody binding mismatch")
    evidence = record["evidence"]
    if not isinstance(evidence, list) or any(
        not isinstance(item, dict) or set(item) != {"kind", "sha256", "archive_path"}
        for item in evidence
    ):
        raise RecoveryError("evidence inventory is malformed")
    kinds = [item["kind"] for item in evidence]
    if len(kinds) != len(set(kinds)) or set(kinds) != phases[phase][1]:
        raise RecoveryError("evidence cardinality does not match the failure phase")
    for item in evidence:
        _hash(item["sha256"], "evidence sha256")
        if (
            not isinstance(item["archive_path"], str)
            or not item["archive_path"].startswith("evidence/")
            or ".." in Path(item["archive_path"]).parts
        ):
            raise RecoveryError("evidence archive path is unsafe")
    failed_evidence = next(item for item in evidence if item["kind"] == "failed_event")
    if failed_evidence["sha256"] != record["failed_event_entry_hash"]:
        raise RecoveryError("failed event evidence hash does not match its ledger binding")
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


def _load_chain(root: Path) -> list[dict[str, Any]]:
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink() or not root.is_dir() or stat.S_IMODE(root.stat().st_mode) != 0o700:
        raise RecoveryError("recovery ledger root must be a private directory")
    rows: list[dict[str, Any]] = []
    for index, path in enumerate(sorted(root.glob("[0-9][0-9][0-9][0-9][0-9][0-9]-*.json")), 1):
        if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o400:
            raise RecoveryError("recovery ledger contains an unsafe entry")
        row = json.loads(path.read_bytes())
        previous = rows[-1]["entry_hash"] if rows else _ZERO
        if (
            row.get("sequence") != index
            or row.get("previous_hash") != previous
            or row.get("protocol") != _PROTOCOL
            or row.get("entry_hash") != _entry_hash(row)
            or not isinstance(row.get("attempt_id"), str)
        ):
            raise RecoveryError("recovery ledger chain integrity is invalid")
        rows.append(row)
    if len({row["attempt_id"] for row in rows}) != len(rows):
        raise RecoveryError("recovery ledger contains a replayed attempt")
    return rows


def append_grant(
    root: Path, record: dict[str, Any], *, expected: dict[str, Any], now: datetime
) -> dict[str, Any]:
    """Append one grant to an isolated recovery ledger, refusing replay and clobber."""
    root = root.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    rows = _load_chain(root)
    if any(row.get("attempt_id") == record.get("attempt_id") for row in rows):
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
    target = root / f"{len(rows) + 1:06d}-{candidate['attempt_id']}.json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(target, flags, 0o400)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(canonical_json(candidate))
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    return candidate


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
