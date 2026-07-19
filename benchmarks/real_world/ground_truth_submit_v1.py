"""Typed supervisor validation and escrow broker for production review protocol v1.

The child submits only semantic review fields. Supervisor bindings inject canonical
corpus, lane-qualified reviewer identity, provenance, commits, immutable blob
identities, IDs, and evidence ordinals. The broker never imports or executes analyzed
source and does not authorize native launch or canonical import.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import socket
import stat
import struct
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Annotated, Any, Literal, NoReturn, cast

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

from benchmarks.real_world import (
    ground_truth_campaign_v1,
    ground_truth_packet_v1,
    ground_truth_source_v1,
)
from benchmarks.real_world.ground_truth_v2 import GroundTruthError
from benchmarks.real_world.ground_truth_v2.evidence import (
    EvidenceBudget,
    EvidenceValidator,
    GitEvidenceValidator,
)
from benchmarks.real_world.ground_truth_v2.schema import (
    Actor,
    ChangedSymbol,
    Entrypoint,
    EvidenceEdge,
    EvidenceLocation,
    NegativeAssessment,
    ResourceLimits,
    ReviewArtifactV1,
    ReviewClaim,
    RunProvenance,
    SnapshotBinding,
    UnknownFinding,
    artifact_sha256,
    canonical_json,
    parse_artifact,
)
from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

_MAX_BINDING_BYTES = 256 * 1024
_MAX_PACKET_MANIFEST_BYTES = 8 * 1024 * 1024
_MAX_AUTHENTICATED_FILE_BYTES = 8 * 1024 * 1024
_MAX_PACKET_FILE_BYTES = 64 * 1024 * 1024
_MAX_PACKET_PAYLOAD_BYTES = 512 * 1024 * 1024
_MAX_PACKET_FILES = 100_000
_MAX_REQUEST_BYTES = 2_200_000
_MAX_RESPONSE_BYTES = 16 * 1024
_MAX_DIAGNOSTIC = 500
_MAX_ATTEMPTS = 3
_MAX_TRANSPORT_FAILURES = 3
_CAPABILITY = re.compile(r"^[0-9a-f]{64}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_PROFILE_CHECKSUMS = "benchmarks/real_world/production_v1/checksums-v1.json"
_INPUT_NAMES = {
    "packet_manifest",
    "source_structure",
    "review_prompt",
    "model_policy",
    "tool_policy",
    "source_policy",
}


@dataclass(frozen=True)
class ProfileSnapshot:
    checksum_raw: bytes
    checksum_sha256: str
    files: dict[str, bytes]
    digests: dict[str, str]
    files_sha256: str


class GroundTruthSubmitError(RuntimeError):
    """Fail-closed submission broker error."""


class SubmissionRejected(GroundTruthSubmitError):
    """One bounded child-visible validation rejection."""

    def __init__(self, code: str, diagnostic: str = "") -> None:
        super().__init__(code)
        self.code = code
        self.diagnostic = diagnostic


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _safe_relative(value: str) -> str:
    if "\\" in value or "\x00" in value or value.startswith("/"):
        raise ValueError("path must be safe repository-relative POSIX")
    parts = PurePosixPath(value).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("path contains an unsafe segment")
    return value


class BoundRun(_StrictModel):
    prompt_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    model_policy_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    tool_policy_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    source_policy_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    started_at: datetime
    limits: ResourceLimits

    @field_validator("started_at", mode="before")
    @classmethod
    def canonical_start(cls, value: object) -> datetime:
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, str) and value.endswith("Z"):
            try:
                parsed = datetime.fromisoformat(value[:-1] + "+00:00")
            except ValueError as exc:
                raise ValueError("invalid run start") from exc
        else:
            raise ValueError("run start must be a canonical UTC timestamp")
        if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
            raise ValueError("run start must be UTC")
        return parsed


class AuthenticatedInput(_StrictModel):
    name: Literal[
        "packet_manifest",
        "source_structure",
        "review_prompt",
        "model_policy",
        "tool_policy",
        "source_policy",
    ]
    path: str
    sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    bytes: StrictInt = Field(ge=1, le=_MAX_AUTHENTICATED_FILE_BYTES)
    mode: Literal[0o400, 0o444]

    @field_validator("path")
    @classmethod
    def normalized_absolute(cls, value: str) -> str:
        if not Path(value).is_absolute() or os.path.normpath(value) != value:
            raise ValueError("authenticated input path must be normalized absolute")
        return value


class FalseAuthority(_StrictModel):
    review_launch: Literal[False]
    adjudication: Literal[False]
    canonical_import: Literal[False]


class SelectionCustodyReceipt(_StrictModel):
    schema_version: Literal[1]
    protocol: Literal["ground-truth-packet-selection-receipt-v1"]
    runtime_attestation_entry_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    runtime_custody_receipt_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    rank: StrictInt = Field(ge=1, le=50)
    repository: str = Field(pattern=r"^[^/\s]+/[^/\s]+$", max_length=300)
    pr: StrictInt = Field(gt=0)
    packet_root_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    aggregate_root_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    publication_entry_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    cache_inventory_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    packet_inventory_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    commands: Literal[5]
    authorizations: FalseAuthority


class SubmissionBinding(_StrictModel):
    schema_version: Literal[1]
    generation: Literal[1, 2, 3, 4] = 1
    attempt_id: str
    capability: str
    packet_path: str
    packet_device: StrictInt = Field(ge=0)
    packet_inode: StrictInt = Field(gt=0)
    packet_manifest_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    packet_root_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    blob_inventory_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    source_structure_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    packet_inventory_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    original_packet_path: str
    campaign_path: str
    source_bindings_path: str
    ledger_root: str
    packets_root: str
    runtime_attestation_entry_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    runtime_custody_receipt_path: str
    runtime_custody_receipt_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    selection_custody: SelectionCustodyReceipt
    original_packet_root_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    aggregate_root_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    publication_entry_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    source_bindings_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    cache_device: StrictInt = Field(ge=0)
    cache_inode: StrictInt = Field(gt=0)
    cache_inventory_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    authenticated_inputs: tuple[AuthenticatedInput, ...] = Field(min_length=6, max_length=6)
    profile_checksum_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    profile_files_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    escrow_path: str
    cache_root: str
    corpus_id: str = Field(min_length=1, max_length=300)
    repository: str = Field(pattern=r"^[^/\s]+/[^/\s]+$", max_length=300)
    pr: StrictInt = Field(gt=0)
    rank: StrictInt = Field(ge=1, le=50)
    lane: Literal["A", "B"]
    snapshots: SnapshotBinding
    baseline_tree: str = Field(pattern=r"^[0-9a-f]{40}$")
    target_tree: str = Field(pattern=r"^[0-9a-f]{40}$")
    reviewer: Actor
    run: BoundRun
    max_validation_attempts: StrictInt = Field(ge=1, le=_MAX_ATTEMPTS)

    @field_validator("attempt_id")
    @classmethod
    def valid_attempt(cls, value: str) -> str:
        if not _IDENTIFIER.fullmatch(value):
            raise ValueError("attempt_id is invalid")
        return value

    @field_validator("capability")
    @classmethod
    def valid_capability(cls, value: str) -> str:
        if not _CAPABILITY.fullmatch(value):
            raise ValueError("capability must be 64 lowercase hex characters")
        return value

    @field_validator(
        "packet_path",
        "original_packet_path",
        "campaign_path",
        "source_bindings_path",
        "ledger_root",
        "packets_root",
        "runtime_custody_receipt_path",
        "escrow_path",
        "cache_root",
    )
    @classmethod
    def absolute_paths(cls, value: str) -> str:
        if not Path(value).is_absolute() or os.path.normpath(value) != value:
            raise ValueError("binding paths must be normalized absolute")
        return value

    @model_validator(mode="after")
    def coherent(self) -> SubmissionBinding:
        names = [item.name for item in self.authenticated_inputs]
        if set(names) != _INPUT_NAMES or len(names) != len(set(names)):
            raise ValueError("authenticated input names are incomplete or duplicate")
        if self.escrow_path in {self.packet_path, self.cache_root}:
            raise ValueError("escrow path must be distinct")
        if (
            self.selection_custody.runtime_attestation_entry_hash
            != self.runtime_attestation_entry_hash
            or self.selection_custody.runtime_custody_receipt_sha256
            != self.runtime_custody_receipt_sha256
            or self.selection_custody.rank != self.rank
            or self.selection_custody.repository != self.repository
            or self.selection_custody.pr != self.pr
        ):
            raise ValueError("selection custody differs from submission binding")
        return self


class SubmissionBindings(_StrictModel):
    schema_version: Literal[1]
    protocol: Literal["ground-truth-review-submit-v1"]
    records: tuple[SubmissionBinding, ...] = Field(min_length=1, max_length=1)


class DraftLocation(_StrictModel):
    side: Literal["baseline", "target"]
    path: Annotated[str, Field(min_length=1, max_length=1000)]
    start_line: StrictInt = Field(gt=0, le=10_000_000)
    end_line: StrictInt = Field(gt=0, le=10_000_000)
    symbol: str = Field(min_length=1, max_length=500)

    @field_validator("path")
    @classmethod
    def safe_path(cls, value: str) -> str:
        return _safe_relative(value)

    @model_validator(mode="after")
    def ordered(self) -> DraftLocation:
        if self.end_line < self.start_line:
            raise ValueError("location range is reversed")
        return self


class DraftChangedSymbol(_StrictModel):
    canonical_name: str = Field(min_length=1, max_length=2000)
    location: DraftLocation


class DraftEdge(_StrictModel):
    relation: Literal["direct", "calls", "imports", "registers", "dispatches", "depends_on"]
    from_location: DraftLocation
    to_location: DraftLocation


class DraftClaim(_StrictModel):
    recommendation: Literal["include", "exclude", "unknown"]
    summary: str = Field(min_length=1, max_length=2000)
    entrypoint: Entrypoint
    evidence: tuple[DraftEdge, ...] = Field(min_length=1, max_length=1000)


class DraftUnknown(_StrictModel):
    category: str = Field(min_length=1, max_length=2000)
    description: str = Field(min_length=1, max_length=2000)
    evidence_limit: str = Field(min_length=1, max_length=2000)


class ReviewDraft(_StrictModel):
    terminal_recommendation: Literal["positive", "negative_control", "unknown", "not_evaluable"]
    changed_symbols: tuple[DraftChangedSymbol, ...] = Field(max_length=1000)
    claims: tuple[DraftClaim, ...] = Field(max_length=1000)
    unknowns: tuple[DraftUnknown, ...] = Field(max_length=1000)
    negative_assessment: NegativeAssessment | None
    notes: str = Field(max_length=20_000)

    @model_validator(mode="after")
    def terminal_shape(self) -> ReviewDraft:
        if self.terminal_recommendation == "positive" and (
            not self.claims or any(item.recommendation != "include" for item in self.claims)
        ):
            raise ValueError("positive draft requires include claims")
        if self.terminal_recommendation == "negative_control":
            if self.claims or self.negative_assessment is None or not self.changed_symbols:
                raise ValueError("negative draft requires census and changed symbols, no claims")
        elif self.negative_assessment is not None:
            raise ValueError("negative_assessment is allowed only for negative_control")
        if self.terminal_recommendation in {"unknown", "not_evaluable"} and not self.unknowns:
            raise ValueError("unknown/not_evaluable draft requires structured unknowns")
        return self


class SubmissionReceipt(_StrictModel):
    schema_version: Literal[1]
    attempt_id: str
    lane: Literal["A", "B"]
    repository: str
    pr: StrictInt
    recommendation: Literal["positive", "negative_control", "unknown", "not_evaluable"]
    changed_symbols: StrictInt
    claims: StrictInt
    unknowns: StrictInt
    bytes: StrictInt
    sha256: str
    summary: str


class EscrowReceipt(_StrictModel):
    schema_version: Literal[1]
    attempt_id: str
    binding_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    artifact_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    artifact_bytes: StrictInt = Field(gt=0, le=2_097_152)
    summary: str


def _fail(message: str) -> NoReturn:
    raise GroundTruthSubmitError(message)


def _sha(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _reject_symlink_ancestors(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:-1]:
        current /= part
        try:
            status = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(status.st_mode):
            _fail("path has a symlink ancestor")


def _owned_file(path: Path, *, max_bytes: int, allowed_modes: set[int]) -> bytes:
    _reject_symlink_ancestors(path)
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise GroundTruthSubmitError("private file cannot be opened") from exc
    try:
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_uid != os.getuid()
            or stat.S_IMODE(status.st_mode) not in allowed_modes
        ):
            _fail("private file owner, type, or mode is invalid")
        chunks: list[bytes] = []
        total = 0
        while total <= max_bytes:
            chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(raw) > max_bytes:
        _fail("private file exceeds byte limit")
    return raw


def _profile_snapshot(root: Path) -> ProfileSnapshot:
    checksum_path = root / _PROFILE_CHECKSUMS
    checksum_before = _owned_file(
        checksum_path, max_bytes=_MAX_AUTHENTICATED_FILE_BYTES, allowed_modes={0o644}
    )
    try:
        ground_truth_campaign_v1._authenticate_profile(root)
    except ground_truth_campaign_v1.CampaignV1Error as exc:
        raise GroundTruthSubmitError("production profile authentication failed") from exc
    checksum_after = _owned_file(
        checksum_path, max_bytes=_MAX_AUTHENTICATED_FILE_BYTES, allowed_modes={0o644}
    )
    if checksum_before != checksum_after:
        _fail("production checksum profile drifted during authentication")
    value = _strict_json(checksum_before, "production checksum profile")
    files = value.get("files")
    if not isinstance(files, dict) or not files:
        _fail("production checksum profile files are invalid")
    captured: dict[str, bytes] = {}
    digests: dict[str, str] = {}
    for relative, expected in sorted(files.items()):
        if (
            not isinstance(relative, str)
            or not isinstance(expected, str)
            or not _DIGEST.fullmatch(expected)
        ):
            _fail("production checksum profile entry is invalid")
        raw = _owned_file(
            root / relative,
            max_bytes=_MAX_AUTHENTICATED_FILE_BYTES,
            allowed_modes={0o644},
        )
        if _sha(raw) != expected:
            _fail("production profile file checksum mismatch")
        captured[relative] = raw
        digests[relative] = expected
    if (
        _owned_file(checksum_path, max_bytes=_MAX_AUTHENTICATED_FILE_BYTES, allowed_modes={0o644})
        != checksum_before
    ):
        _fail("production checksum profile drifted while capturing files")
    return ProfileSnapshot(
        checksum_raw=checksum_before,
        checksum_sha256=_sha(checksum_before),
        files=captured,
        digests=digests,
        files_sha256=_sha(canonical_json(digests)),
    )


def _same_profile(left: ProfileSnapshot, right: ProfileSnapshot) -> bool:
    return (
        left.checksum_raw == right.checksum_raw
        and left.checksum_sha256 == right.checksum_sha256
        and left.digests == right.digests
        and left.files == right.files
        and left.files_sha256 == right.files_sha256
    )


def _reject_nesting(raw: bytes, *, maximum: int = 100) -> None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GroundTruthSubmitError("JSON is not UTF-8") from exc
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > maximum:
                _fail("JSON nesting exceeds limit")
        elif char in "]}":
            depth -= 1
            if depth < 0:
                _fail("JSON structure is invalid")


def _strict_json(raw: bytes, label: str) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise GroundTruthSubmitError(f"duplicate key in {label}")
            result[key] = value
        return result

    def reject_constant(value: str) -> NoReturn:
        raise GroundTruthSubmitError(f"non-finite value in {label}: {value}")

    _reject_nesting(raw)
    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_constant=reject_constant)
    except (
        json.JSONDecodeError,
        UnicodeDecodeError,
        ValueError,
        OverflowError,
        RecursionError,
        MemoryError,
    ) as exc:
        raise GroundTruthSubmitError(f"invalid JSON: {label}") from exc
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    try:
        canonical_json(value)
    except (UnicodeEncodeError, ValueError, OverflowError, RecursionError, MemoryError) as exc:
        raise GroundTruthSubmitError(f"invalid JSON: {label}") from exc
    return value


def _within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def _manifest_root(manifest: dict[str, Any]) -> str:
    return ground_truth_packet_v1._packet_root(manifest)


def _inventory(
    source_structure: dict[str, Any],
) -> tuple[dict[tuple[str, str], str], str]:
    snapshots = source_structure
    if (
        not isinstance(snapshots, dict)
        or set(snapshots) != {"schema_version", "id", "repository", "pr", "baseline", "target"}
        or snapshots.get("schema_version") != 1
        or snapshots.get("id") != "ground-truth-production-source-structure-v1"
        or not isinstance(snapshots.get("repository"), str)
        or not isinstance(snapshots.get("pr"), int)
    ):
        _fail("packet snapshot inventory is invalid")
    lookup: dict[tuple[str, str], str] = {}
    rows: list[dict[str, str]] = []
    for side in ("baseline", "target"):
        snapshot = snapshots[side]
        if (
            not isinstance(snapshot, dict)
            or set(snapshot) != {"tree", "files", "symlinks", "gitlinks"}
            or not isinstance(snapshot.get("tree"), str)
            or not _GIT_SHA.fullmatch(snapshot["tree"])
            or not isinstance(snapshot.get("files"), list)
            or not isinstance(snapshot.get("symlinks"), list)
            or not isinstance(snapshot.get("gitlinks"), list)
        ):
            _fail("packet snapshot file inventory is invalid")
        for item in snapshot["files"]:
            if not isinstance(item, dict):
                _fail("packet snapshot file entry is invalid")
            path = item.get("path")
            oid = item.get("oid")
            mode = item.get("mode")
            if (
                not isinstance(path, str)
                or not isinstance(oid, str)
                or not isinstance(mode, str)
                or not _GIT_SHA.fullmatch(oid)
            ):
                _fail("packet snapshot file identity is invalid")
            _safe_relative(path)
            if mode not in {"100644", "100755"}:
                continue
            key = (side, path)
            if key in lookup:
                _fail("packet snapshot inventory contains a duplicate path")
            lookup[key] = oid
            rows.append({"side": side, "path": path, "blob_sha": oid})
    rows.sort(key=lambda item: (item["side"], item["path"]))
    return lookup, _sha(b"blind-review-blob-inventory-v1\0" + canonical_json(rows))


def _verify_payload(  # noqa: PLR0912
    packet: Path, manifest: dict[str, Any], authenticated_paths: set[str]
) -> None:
    files = manifest.get("payload_files")
    if not isinstance(files, list) or len(files) > _MAX_PACKET_FILES:
        _fail("packet payload inventory is invalid")
    seen: set[str] = set()
    total = 0
    for item in files:
        if not isinstance(item, dict):
            _fail("packet payload entry is invalid")
        path_value, size, digest = item.get("path"), item.get("bytes"), item.get("sha256")
        if (
            not isinstance(path_value, str)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or size > _MAX_PACKET_FILE_BYTES
            or not isinstance(digest, str)
            or not _DIGEST.fullmatch(digest)
        ):
            _fail("packet payload identity is invalid")
        total += size
        if total > _MAX_PACKET_PAYLOAD_BYTES:
            _fail("packet payload byte budget exceeded")
        path_value = _safe_relative(path_value)
        if path_value in seen:
            _fail("packet payload inventory contains duplicate path")
        seen.add(path_value)
        path = packet / path_value
        raw = _owned_file(path, max_bytes=size, allowed_modes={0o400})
        if len(raw) != size or _sha(raw) != digest:
            _fail("packet payload bytes changed")

    actual: set[str] = set()
    for directory, names, filenames in os.walk(packet, followlinks=False):
        root = Path(directory)
        root_status = root.lstat()
        if (
            not stat.S_ISDIR(root_status.st_mode)
            or stat.S_IMODE(root_status.st_mode) != 0o500
            or root_status.st_uid != os.getuid()
        ):
            _fail("packet directory custody is invalid")
        for name in names:
            child = root / name
            status = child.lstat()
            if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
                _fail("packet contains a non-directory or symlink traversal component")
        for name in filenames:
            child = root / name
            status = child.lstat()
            if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
                _fail("packet contains an unmanifested special file")
            actual.add(child.relative_to(packet).as_posix())
            if len(actual) > _MAX_PACKET_FILES + 1:
                _fail("packet filesystem census exceeds file budget")
    if actual != seen | {"packet-manifest.json"} | authenticated_paths:
        _fail("packet filesystem census does not match manifest")


def _packet_inventory(packet: Path) -> str:
    rows: list[dict[str, object]] = []
    for directory, names, filenames in os.walk(packet, followlinks=False):
        root = Path(directory)
        for name in sorted(names):
            child = root / name
            status = child.lstat()
            if not stat.S_ISDIR(status.st_mode) or stat.S_ISLNK(status.st_mode):
                _fail("attempt packet inventory contains a special directory entry")
            rows.append(
                {
                    "path": child.relative_to(packet).as_posix() + "/",
                    "mode": stat.S_IMODE(status.st_mode),
                    "bytes": 0,
                    "sha256": None,
                }
            )
        for name in sorted(filenames):
            child = root / name
            status = child.lstat()
            if not stat.S_ISREG(status.st_mode) or stat.S_ISLNK(status.st_mode):
                _fail("attempt packet inventory contains a special file")
            raw = _owned_file(
                child,
                max_bytes=_MAX_PACKET_FILE_BYTES,
                allowed_modes={stat.S_IMODE(status.st_mode)},
            )
            rows.append(
                {
                    "path": child.relative_to(packet).as_posix(),
                    "mode": stat.S_IMODE(status.st_mode),
                    "bytes": len(raw),
                    "sha256": _sha(raw),
                }
            )
            if len(rows) > _MAX_PACKET_FILES:
                _fail("attempt packet inventory exceeded file bound")
    rows.sort(key=lambda item: str(item["path"]))
    return _sha(b"ground-truth-review-attempt-packet-v1\0" + canonical_json(rows))


def _authenticate_record(  # noqa: PLR0912,PLR0915 - fail-closed authentication is linear
    record: SubmissionBinding,
) -> dict[tuple[str, str], str]:
    packet = Path(record.packet_path)
    _reject_symlink_ancestors(packet / "sentinel")
    try:
        packet_status = packet.stat()
    except OSError as exc:
        raise GroundTruthSubmitError("bound packet is unavailable") from exc
    if (
        not stat.S_ISDIR(packet_status.st_mode)
        or packet_status.st_uid != os.getuid()
        or packet_status.st_dev != record.packet_device
        or packet_status.st_ino != record.packet_inode
        or stat.S_IMODE(packet_status.st_mode) & 0o022
        or str(packet.resolve(strict=True)) != record.packet_path
    ):
        _fail("bound packet identity changed")

    project_root = Path(__file__).resolve().parents[2]
    profile = _profile_snapshot(project_root)
    if (
        profile.checksum_sha256 != record.profile_checksum_sha256
        or profile.files_sha256 != record.profile_files_sha256
    ):
        _fail("production profile binding changed")
    try:
        published = ground_truth_packet_v1.validate_packet_selection_receipt(
            project_root,
            Path(record.campaign_path),
            Path(record.source_bindings_path),
            Path(record.cache_root),
            Path(record.ledger_root),
            Path(record.packets_root),
            Path(record.runtime_custody_receipt_path),
            record.selection_custody.model_dump(mode="json"),
            runtime_attestation_entry_hash=record.runtime_attestation_entry_hash,
        )
    except (ground_truth_packet_v1.PacketV1Error, ground_truth_source_v1.SourceV1Error) as exc:
        raise GroundTruthSubmitError(
            "production source or packet publication authentication failed"
        ) from exc
    custody_raw = _owned_file(
        Path(record.runtime_custody_receipt_path),
        max_bytes=_MAX_BINDING_BYTES,
        allowed_modes={0o400},
    )
    if (
        published.get("commands") != 0
        or published.get("rank") != record.rank
        or published.get("repository") != record.repository
        or published.get("pr") != record.pr
        or published.get("aggregate_root_sha256") != record.aggregate_root_sha256
        or published.get("publication_entry_hash") != record.publication_entry_hash
        or _sha(custody_raw) != record.runtime_custody_receipt_sha256
        or published.get("runtime_attestation_entry_hash") != record.runtime_attestation_entry_hash
        or published.get("cache_inventory_sha256") != record.cache_inventory_sha256
    ):
        _fail("production source or publication binding changed")
    original = Path(record.original_packet_path)
    if original.parent != Path(record.packets_root) or not original.is_dir():
        _fail("original production packet path is invalid")
    original_manifest_raw = _owned_file(
        original / "packet-manifest.json",
        max_bytes=_MAX_PACKET_MANIFEST_BYTES,
        allowed_modes={0o400},
    )
    original_manifest = _strict_json(original_manifest_raw, "original packet manifest")
    if (
        original_manifest.get("packet_root_sha256") != record.original_packet_root_sha256
        or original_manifest.get("repository") != record.repository
        or original_manifest.get("pr") != record.pr
        or _manifest_root(original_manifest) != record.original_packet_root_sha256
    ):
        _fail("original production packet binding changed")

    raws: dict[str, bytes] = {}
    for item in record.authenticated_inputs:
        path = Path(item.path)
        resolved_parent = path.parent.resolve(strict=True)
        if not _within(resolved_parent, packet):
            _fail("authenticated input escaped packet")
        raw = _owned_file(path, max_bytes=item.bytes, allowed_modes={item.mode})
        if len(raw) != item.bytes or _sha(raw) != item.sha256:
            _fail("authenticated packet or policy input changed")
        raws[item.name] = raw
    if _sha(raws["packet_manifest"]) != record.packet_manifest_sha256:
        _fail("packet manifest binding mismatch")
    manifest = _strict_json(raws["packet_manifest"], "packet manifest")
    expected = {
        "repository": record.repository,
        "pr": record.pr,
        "baseline_commit": record.snapshots.baseline_commit,
        "target_commit": record.snapshots.target_commit,
        "baseline_tree": record.baseline_tree,
        "target_tree": record.target_tree,
        "packet_root_sha256": record.packet_root_sha256,
    }
    if any(manifest.get(key) != value for key, value in expected.items()):
        _fail("packet semantic binding mismatch")
    if _manifest_root(manifest) != record.packet_root_sha256:
        _fail("packet semantic root hash mismatch")
    if _sha(raws["source_structure"]) != record.source_structure_sha256:
        _fail("source structure binding mismatch")
    source_structure = _strict_json(raws["source_structure"], "source structure")
    lookup, inventory_digest = _inventory(source_structure)
    if inventory_digest != record.blob_inventory_sha256:
        _fail("packet blob inventory binding mismatch")
    authenticated_paths = {
        Path(item.path).relative_to(packet).as_posix()
        for item in record.authenticated_inputs
        if item.name not in {"packet_manifest", "source_structure"}
    }
    _verify_payload(packet, manifest, authenticated_paths)
    if _packet_inventory(packet) != record.packet_inventory_sha256:
        _fail("attempt packet inventory changed")
    hashes = {
        "review_prompt": record.run.prompt_sha256,
        "model_policy": record.run.model_policy_sha256,
        "tool_policy": record.run.tool_policy_sha256,
        "source_policy": record.run.source_policy_sha256,
    }
    for name, digest in hashes.items():
        if _sha(raws[name]) != digest:
            _fail("run policy hash binding mismatch")

    escrow = Path(record.escrow_path)
    _reject_symlink_ancestors(escrow)
    parent = escrow.parent
    try:
        parent_status = parent.stat()
    except OSError as exc:
        raise GroundTruthSubmitError("escrow parent is unavailable") from exc
    if (
        not stat.S_ISDIR(parent_status.st_mode)
        or parent_status.st_uid != os.getuid()
        or stat.S_IMODE(parent_status.st_mode) & 0o077
    ):
        _fail("escrow parent is not private")
    cache = Path(record.cache_root)
    _reject_symlink_ancestors(cache / "sentinel")
    try:
        cache_status = cache.stat()
    except OSError as exc:
        raise GroundTruthSubmitError("cache root is unavailable") from exc
    if (
        not stat.S_ISDIR(cache_status.st_mode)
        or cache_status.st_uid != os.getuid()
        or cache.is_symlink()
        or str(cache.resolve(strict=True)) != record.cache_root
        or cache_status.st_dev != record.cache_device
        or cache_status.st_ino != record.cache_inode
        or stat.S_IMODE(cache_status.st_mode) & 0o022
    ):
        _fail("cache root is unavailable")
    return lookup


def load_bindings(path: Path) -> SubmissionBindings:
    """Load and authenticate one private supervisor binding."""
    payload = _strict_json(
        _owned_file(path, max_bytes=_MAX_BINDING_BYTES, allowed_modes={0o400}), "bindings"
    )
    try:
        bindings = SubmissionBindings.model_validate(payload)
    except (ValueError, RecursionError, MemoryError) as exc:
        raise GroundTruthSubmitError("submission bindings are invalid") from exc
    record = bindings.records[0]
    _authenticate_record(record)
    artifact = Path(record.escrow_path)
    receipt = _receipt_path(artifact)
    if artifact.exists() != receipt.exists():
        _fail("escrow recovery state is incomplete")
    return bindings


def _diagnostic(exc: BaseException, record: SubmissionBinding) -> str:
    text = " ".join(str(exc).split())
    for secret in (record.packet_path, record.escrow_path, record.cache_root, record.capability):
        text = text.replace(secret, "<redacted>")
    text = "".join(char for char in text if 32 <= ord(char) < 127)
    return text[:_MAX_DIAGNOSTIC]


def _parse_draft(value: object, record: SubmissionBinding) -> ReviewDraft:
    try:
        raw = canonical_json(value)
        draft = ReviewDraft.model_validate(_strict_json(raw, "review draft"))
    except (
        GroundTruthSubmitError,
        GroundTruthError,
        ValueError,
        RecursionError,
        MemoryError,
    ) as exc:
        raise SubmissionRejected("DRAFT_INVALID", _diagnostic(exc, record)) from exc
    return draft


def _materialize_location(
    location: DraftLocation,
    record: SubmissionBinding,
    lookup: dict[tuple[str, str], str],
) -> EvidenceLocation:
    try:
        blob = lookup[(location.side, location.path)]
    except KeyError as exc:
        raise SubmissionRejected(
            "EVIDENCE_INVALID", f"{location.side}:{location.path}"[:_MAX_DIAGNOSTIC]
        ) from exc
    commit = (
        record.snapshots.baseline_commit
        if location.side == "baseline"
        else record.snapshots.target_commit
    )
    return EvidenceLocation(
        side=location.side,
        commit_sha=commit,
        blob_sha=blob,
        path=location.path,
        start_line=location.start_line,
        end_line=location.end_line,
        symbol=location.symbol,
    )


def materialize_review(
    draft: ReviewDraft,
    record: SubmissionBinding,
    lookup: dict[tuple[str, str], str],
    *,
    completed_at: datetime,
) -> ReviewArtifactV1:
    """Inject all supervisor-owned and deterministic artifact fields."""
    if completed_at.tzinfo is None or completed_at.utcoffset() is None:
        raise SubmissionRejected("COMPLETION_TIME_INVALID")
    completed_at = completed_at.astimezone(timezone.utc)
    if completed_at < record.run.started_at or completed_at > record.run.started_at + timedelta(
        seconds=record.run.limits.max_seconds
    ):
        raise SubmissionRejected("COMPLETION_TIME_INVALID")

    def location(value: DraftLocation) -> EvidenceLocation:
        return _materialize_location(value, record, lookup)

    changed = tuple(
        ChangedSymbol(
            symbol_id=f"symbol-{index:04d}",
            canonical_name=item.canonical_name,
            location=location(item.location),
        )
        for index, item in enumerate(draft.changed_symbols)
    )
    claims = tuple(
        ReviewClaim(
            claim_id=f"claim-{index:04d}",
            claim_kind="entrypoint",
            recommendation=item.recommendation,
            summary=item.summary,
            entrypoint=item.entrypoint,
            evidence=tuple(
                EvidenceEdge(
                    ordinal=edge_index,
                    relation=edge.relation,
                    from_location=location(edge.from_location),
                    to_location=location(edge.to_location),
                )
                for edge_index, edge in enumerate(item.evidence)
            ),
        )
        for index, item in enumerate(draft.claims)
    )
    unknowns = tuple(
        UnknownFinding(
            unknown_id=f"unknown-{index:04d}",
            category=item.category,
            description=item.description,
            evidence_limit=item.evidence_limit,
        )
        for index, item in enumerate(draft.unknowns)
    )
    run = RunProvenance(
        prompt_sha256=record.run.prompt_sha256,
        model_policy_sha256=record.run.model_policy_sha256,
        tool_policy_sha256=record.run.tool_policy_sha256,
        source_policy_sha256=record.run.source_policy_sha256,
        started_at=record.run.started_at,
        completed_at=completed_at,
        limits=record.run.limits,
    )
    return ReviewArtifactV1(
        schema_version=1,
        artifact_type="ground_truth_review",
        corpus_id=record.corpus_id,
        repository=record.repository,
        pr=record.pr,
        lane=record.lane,
        snapshots=record.snapshots,
        reviewer=record.reviewer,
        run=run,
        terminal_recommendation=draft.terminal_recommendation,
        changed_symbols=changed,
        claims=claims,
        unknowns=unknowns,
        negative_assessment=draft.negative_assessment,
        notes=draft.notes,
    )


def _validate_identity(review: ReviewArtifactV1, record: SubmissionBinding) -> None:
    run = review.run
    if (
        review.corpus_id != record.corpus_id
        or review.repository != record.repository
        or review.pr != record.pr
        or review.lane != record.lane
        or review.snapshots != record.snapshots
        or review.reviewer != record.reviewer
        or run.prompt_sha256 != record.run.prompt_sha256
        or run.model_policy_sha256 != record.run.model_policy_sha256
        or run.tool_policy_sha256 != record.run.tool_policy_sha256
        or run.source_policy_sha256 != record.run.source_policy_sha256
        or run.started_at != record.run.started_at
        or run.limits != record.run.limits
    ):
        raise SubmissionRejected("BINDING_MISMATCH")


def _evidence_validator(record: SubmissionBinding) -> GitEvidenceValidator:
    cache = Path(record.cache_root)
    validator = GitEvidenceValidator(
        cache.parent,
        record.repository,
        record.snapshots.baseline_commit,
        record.snapshots.target_commit,
        record.baseline_tree,
        record.target_tree,
        budget=EvidenceBudget(max_wall_seconds=240),
    )
    # Production custody binds one exact bare cache, not a repository-name-derived
    # cache root. Preserve the validator's evidence semantics while replacing only
    # its deterministic cache location.
    validator.cache = cache
    return validator


def _validate_review_evidence(
    review: ReviewArtifactV1, record: SubmissionBinding, validator: EvidenceValidator | None
) -> None:
    evidence = validator or _evidence_validator(record)
    try:
        for symbol in review.changed_symbols:
            evidence.validate_changed_location(symbol.location)
        for claim in review.claims:
            evidence.validate_edges(claim.evidence)
    except (GroundTruthError, OSError, ValueError) as exc:
        raise SubmissionRejected("EVIDENCE_INVALID", _diagnostic(exc, record)) from exc


def validate_submission(
    draft_value: object,
    record: SubmissionBinding,
    *,
    validator: EvidenceValidator | None = None,
    completed_at: datetime | None = None,
) -> tuple[ReviewArtifactV1, bytes]:
    """Reauthenticate, materialize, and validate one semantic review draft."""
    lookup = _authenticate_record(record)
    draft = _parse_draft(draft_value, record)
    review = materialize_review(
        draft,
        record,
        lookup,
        completed_at=completed_at or datetime.now(timezone.utc),
    )
    _validate_identity(review, record)
    _validate_review_evidence(review, record, validator)
    raw = canonical_json(review.model_dump(mode="json"))
    if len(raw) > record.run.limits.max_output_bytes:
        raise SubmissionRejected("OUTPUT_LIMIT_EXCEEDED")
    return review, raw


def deterministic_summary(review: ReviewArtifactV1, raw: bytes) -> str:
    """Return the exact child-visible success summary."""
    return (
        f"SUBMITTED schema=1 lane={review.lane} repository={review.repository} pr={review.pr} "
        f"recommendation={review.terminal_recommendation} "
        f"changed_symbols={len(review.changed_symbols)} claims={len(review.claims)} "
        f"unknowns={len(review.unknowns)} bytes={len(raw)} sha256={artifact_sha256(raw)}"
    )


def _atomic_no_clobber(path: Path, raw: bytes, *, mode: int) -> tuple[int, int]:
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    linked = False
    identity: tuple[int, int] | None = None
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        temporary_status = temporary.stat(follow_symlinks=False)
        identity = (temporary_status.st_dev, temporary_status.st_ino)
        try:
            os.link(temporary, path)
            linked = True
        except FileExistsError as exc:
            raise SubmissionRejected("ALREADY_SUBMITTED") from exc
        published_status = path.stat(follow_symlinks=False)
        if (published_status.st_dev, published_status.st_ino) != identity:
            _fail("no-clobber publication identity changed")
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return identity
    except BaseException:
        if linked and identity is not None:
            _unlink_if_identity(path, identity)
        raise
    finally:
        temporary.unlink(missing_ok=True)


def _unlink_if_identity(path: Path, identity: tuple[int, int]) -> None:
    try:
        status = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return
    if (status.st_dev, status.st_ino) == identity:
        path.unlink()


def _receipt_path(artifact: Path) -> Path:
    return artifact.with_name(artifact.name + ".receipt.json")


def _lock_path(artifact: Path) -> Path:
    return artifact.with_name(artifact.name + ".lock")


@contextlib.contextmanager
def _escrow_lock(artifact: Path) -> Iterator[None]:
    path = _lock_path(artifact)
    _reject_symlink_ancestors(path)
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_uid != os.getuid()
            or stat.S_IMODE(status.st_mode) != 0o600
        ):
            _fail("escrow lock identity is invalid")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _binding_sha(record: SubmissionBinding) -> str:
    excluded = {"generation"} if "generation" not in record.model_fields_set else set()
    return _sha(canonical_json(record.model_dump(mode="json", exclude=excluded)))


def _make_receipt(
    record: SubmissionBinding, review: ReviewArtifactV1, raw: bytes
) -> SubmissionReceipt:
    summary = deterministic_summary(review, raw)
    return SubmissionReceipt(
        schema_version=1,
        attempt_id=record.attempt_id,
        lane=review.lane,
        repository=review.repository,
        pr=review.pr,
        recommendation=review.terminal_recommendation,
        changed_symbols=len(review.changed_symbols),
        claims=len(review.claims),
        unknowns=len(review.unknowns),
        bytes=len(raw),
        sha256=artifact_sha256(raw),
        summary=summary,
    )


def _recover_locked(record: SubmissionBinding) -> SubmissionReceipt:
    before = _authenticate_record(record)
    validator = _evidence_validator(record)
    artifact_path = Path(record.escrow_path)
    sidecar_path = _receipt_path(artifact_path)
    if artifact_path.exists() != sidecar_path.exists():
        _fail("escrow recovery state is incomplete")
    if not artifact_path.exists():
        raise SubmissionRejected("NOT_SUBMITTED")
    raw = _owned_file(
        artifact_path,
        max_bytes=record.run.limits.max_output_bytes,
        allowed_modes={0o400},
    )
    sidecar_raw = _owned_file(sidecar_path, max_bytes=16 * 1024, allowed_modes={0o400})
    try:
        sidecar = EscrowReceipt.model_validate(_strict_json(sidecar_raw, "escrow receipt"))
        review = parse_artifact(raw, ReviewArtifactV1)
    except (GroundTruthError, ValueError, RecursionError, MemoryError) as exc:
        raise GroundTruthSubmitError("escrow recovery artifacts are invalid") from exc
    assert isinstance(review, ReviewArtifactV1)
    canonical = canonical_json(review.model_dump(mode="json"))
    if canonical != raw:
        _fail("escrow artifact is not canonical")
    _validate_identity(review, record)
    _validate_review_evidence(review, record, validator)
    after = _authenticate_record(record)
    if after != before:
        _fail("source, cache, packet, or profile drifted around escrow recovery")
    receipt = _make_receipt(record, review, raw)
    if (
        sidecar.attempt_id != record.attempt_id
        or sidecar.binding_sha256 != _binding_sha(record)
        or sidecar.artifact_sha256 != receipt.sha256
        or sidecar.artifact_bytes != receipt.bytes
        or sidecar.summary != receipt.summary
    ):
        _fail("escrow receipt binding mismatch")
    return receipt


def recover_submission(record: SubmissionBinding) -> SubmissionReceipt:
    """Fully revalidate and recover an exact prior successful submission."""
    with _escrow_lock(Path(record.escrow_path)):
        return _recover_locked(record)


def escrow_submission(
    draft_value: object,
    record: SubmissionBinding,
    *,
    validator: EvidenceValidator | None = None,
    clock: Callable[[], datetime] | None = None,
    deadline: datetime | None = None,
) -> SubmissionReceipt:
    """Publish or idempotently recover one fully validated review."""
    artifact_path = Path(record.escrow_path)
    evidence = validator or _evidence_validator(record)
    now = clock or (lambda: datetime.now(timezone.utc))

    def checked_now() -> datetime:
        value = now().astimezone(timezone.utc)
        if deadline is not None and value >= deadline.astimezone(timezone.utc):
            raise SubmissionRejected("DEADLINE_EXPIRED")
        return value

    with _escrow_lock(artifact_path):
        if artifact_path.exists() or _receipt_path(artifact_path).exists():
            return _recover_locked(record)
        review, raw = validate_submission(
            draft_value,
            record,
            validator=evidence,
            completed_at=checked_now(),
        )
        checked_now()
        receipt = _make_receipt(record, review, raw)
        sidecar = EscrowReceipt(
            schema_version=1,
            attempt_id=record.attempt_id,
            binding_sha256=_binding_sha(record),
            artifact_sha256=receipt.sha256,
            artifact_bytes=receipt.bytes,
            summary=receipt.summary,
        )
        sidecar_path = _receipt_path(artifact_path)
        created: list[tuple[Path, tuple[int, int]]] = []
        try:
            artifact_identity = _atomic_no_clobber(artifact_path, raw, mode=0o400)
            created.append((artifact_path, artifact_identity))
            sidecar_identity = _atomic_no_clobber(
                sidecar_path, canonical_json(sidecar.model_dump(mode="json")), mode=0o400
            )
            created.append((sidecar_path, sidecar_identity))
            return _recover_locked(record)
        except BaseException:
            for created_path, identity in reversed(created):
                _unlink_if_identity(created_path, identity)
            raise


def _read_exact(connection: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise SubmissionRejected("TRUNCATED_REQUEST")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _recv_frame(connection: socket.socket) -> bytes:
    header = _read_exact(connection, 4)
    (size,) = struct.unpack("!I", header)
    if size <= 0 or size > _MAX_REQUEST_BYTES:
        raise SubmissionRejected("REQUEST_SIZE_INVALID")
    return _read_exact(connection, size)


def _send_frame(connection: socket.socket, value: dict[str, object]) -> None:
    raw = canonical_json(value)
    if len(raw) > _MAX_RESPONSE_BYTES:
        _fail("broker response exceeds bound")
    connection.sendall(struct.pack("!I", len(raw)) + raw)


def _peer_credentials(connection: socket.socket) -> tuple[int, int]:
    if not hasattr(socket, "SO_PEERCRED"):
        _fail("peer credentials are unavailable")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, _gid = struct.unpack("3i", raw)
    if pid <= 0 or uid < 0:
        _fail("peer credentials are invalid")
    return cast("tuple[int, int]", (pid, uid))


def _verify_peer_cwd(pid: int, record: SubmissionBinding) -> None:
    """Bind the live Unix peer process to the exact authenticated packet cwd."""
    proc_cwd = Path(f"/proc/{pid}/cwd")
    try:
        peer_path = proc_cwd.resolve(strict=True)
        peer_status = proc_cwd.stat()
        packet_path = Path(record.packet_path).resolve(strict=True)
    except OSError as exc:
        raise SubmissionRejected("PEER_CWD_UNAVAILABLE") from exc
    if (
        peer_path != packet_path
        or peer_status.st_dev != record.packet_device
        or peer_status.st_ino != record.packet_inode
    ):
        raise SubmissionRejected("PEER_CWD_INVALID")


def _request(raw: bytes, record: SubmissionBinding) -> object:
    try:
        payload = _strict_json(raw, "submission request")
    except GroundTruthSubmitError as exc:
        raise SubmissionRejected("REQUEST_INVALID") from exc
    if set(payload) != {"protocol_version", "capability", "cwd", "draft"}:
        raise SubmissionRejected("REQUEST_FIELDS_INVALID")
    if payload["protocol_version"] != 1:
        raise SubmissionRejected("PROTOCOL_VERSION_INVALID")
    capability = payload["capability"]
    if not isinstance(capability, str) or not hmac.compare_digest(capability, record.capability):
        raise SubmissionRejected("CAPABILITY_INVALID")
    cwd = payload["cwd"]
    if not isinstance(cwd, str):
        raise SubmissionRejected("CWD_INVALID")
    try:
        resolved = Path(cwd).resolve(strict=True)
        status = resolved.stat()
    except OSError as exc:
        raise SubmissionRejected("CWD_INVALID") from exc
    if (
        str(resolved) != record.packet_path
        or status.st_dev != record.packet_device
        or status.st_ino != record.packet_inode
    ):
        raise SubmissionRejected("CWD_BINDING_MISMATCH")
    return payload["draft"]


def _failure(exc: SubmissionRejected) -> dict[str, object]:
    result: dict[str, object] = {"protocol_version": 1, "ok": False, "code": exc.code}
    if exc.diagnostic:
        result["diagnostic"] = exc.diagnostic[:_MAX_DIAGNOSTIC]
    return result


def _success(receipt: SubmissionReceipt) -> dict[str, object]:
    return {
        "protocol_version": 1,
        "ok": True,
        "code": "SUBMITTED",
        "summary": receipt.summary,
        "receipt": receipt.model_dump(mode="json"),
    }


def serve(  # noqa: PLR0912,PLR0915
    socket_path: Path,
    bindings_path: Path,
    *,
    timeout_seconds: int = 300,
    deadline_unix_ms: int | None = None,
) -> int:
    """Serve one bound attempt until success or the single absolute deadline."""
    record = load_bindings(bindings_path).records[0]
    binding_deadline = record.run.started_at + timedelta(seconds=record.run.limits.max_seconds)
    requested_deadline = (
        datetime.fromtimestamp(deadline_unix_ms / 1000, timezone.utc)
        if deadline_unix_ms is not None
        else datetime.now(timezone.utc) + timedelta(seconds=timeout_seconds)
    )
    deadline = min(binding_deadline, requested_deadline)

    def remaining_timeout() -> float:
        remaining = (deadline - datetime.now(timezone.utc)).total_seconds()
        if remaining <= 0:
            raise GroundTruthSubmitError("broker absolute deadline expired")
        return remaining

    if not socket_path.is_absolute():
        _fail("socket path must be absolute")
    _reject_symlink_ancestors(socket_path)
    if socket_path.exists() or socket_path.is_symlink():
        _fail("socket path already exists")
    parent = socket_path.parent
    status = parent.stat()
    if (
        not stat.S_ISDIR(status.st_mode)
        or status.st_uid != os.getuid()
        or stat.S_IMODE(status.st_mode) & 0o077
    ):
        _fail("socket parent is not private")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    rejected = 0
    transport_failures = 0
    try:
        server.bind(str(socket_path))
        socket_path.chmod(0o600)
        server.listen(1)
        while rejected < record.max_validation_attempts:
            server.settimeout(remaining_timeout())
            try:
                connection, _ = server.accept()
            except TimeoutError as exc:
                raise GroundTruthSubmitError("broker accept timeout") from exc
            with connection:
                connection.settimeout(remaining_timeout())
                try:
                    peer_pid, peer_uid = _peer_credentials(connection)
                    if peer_uid != os.getuid():
                        raise SubmissionRejected("PEER_UID_INVALID")
                    _verify_peer_cwd(peer_pid, record)
                    draft = _request(_recv_frame(connection), record)
                    remaining_timeout()
                    receipt = escrow_submission(draft, record, deadline=deadline)
                    try:
                        _send_frame(connection, _success(receipt))
                    except OSError:
                        transport_failures += 1
                        if transport_failures >= _MAX_TRANSPORT_FAILURES:
                            _fail("broker transport failure budget exhausted")
                        continue
                    return 0
                except SubmissionRejected as exc:
                    with contextlib.suppress(OSError):
                        _send_frame(connection, _failure(exc))
                    if exc.code not in {"DRAFT_INVALID", "EVIDENCE_INVALID"}:
                        raise GroundTruthSubmitError(
                            f"terminal submission rejection: {exc.code}"
                        ) from exc
                    rejected += 1
                except (OSError, TimeoutError) as exc:
                    rejected += 1
                    with contextlib.suppress(OSError):
                        _send_frame(connection, _failure(SubmissionRejected("IO_ERROR")))
                    if rejected >= record.max_validation_attempts:
                        raise GroundTruthSubmitError("submission attempt budget exhausted") from exc
        raise GroundTruthSubmitError("submission attempt budget exhausted")
    finally:
        server.close()
        socket_path.unlink(missing_ok=True)
        directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


_PRODUCTION_POLICY_FILES = {
    "review_prompt": "review-prompt-v1.md",
    "model_policy": "model-policy-review-v1.json",
    "tool_policy": "tool-policy-review-v1.json",
    "source_policy": "review-source-policy-v1.json",
}
_PROFILE_DIR = "benchmarks/real_world/production_v1"


def _freeze_packet(path: Path) -> None:
    for directory, names, filenames in os.walk(path, topdown=False, followlinks=False):
        root = Path(directory)
        for name in filenames:
            child = root / name
            if child.is_symlink() or not child.is_file():
                _fail("attempt packet contains a special file")
            child.chmod(0o400)
        for name in names:
            child = root / name
            if child.is_symlink() or not child.is_dir():
                _fail("attempt packet contains a special directory entry")
            child.chmod(0o500)
        root.chmod(0o500)


def prepare_binding(  # noqa: PLR0912,PLR0915 - linear fail-closed preparation
    root: Path,
    campaign_path: Path,
    source_bindings_path: Path,
    cache: Path,
    ledger_root: Path,
    packets_root: Path,
    rank: int,
    lane: Literal["A", "B"],
    attempt_id: str,
    attempt_root: Path,
    *,
    runtime_attestation_entry_hash: str,
    runtime_custody_receipt_path: Path,
    runtime_custody_receipt_sha256: str,
    generation: Literal[1, 2, 3, 4] = 1,
    started_at: datetime | None = None,
) -> dict[str, object]:
    """Prepare one no-clobber reviewer-visible packet and private binding."""
    if not _IDENTIFIER.fullmatch(attempt_id) or rank < 1 or rank > 50:
        _fail("attempt identity is invalid")
    if not attempt_root.is_absolute() or attempt_root.exists() or attempt_root.is_symlink():
        _fail("attempt root must be an absent absolute path")
    parent = attempt_root.parent
    parent_status = parent.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(parent_status.st_mode)
        or parent_status.st_uid != os.getuid()
        or stat.S_IMODE(parent_status.st_mode) != 0o700
    ):
        _fail("attempt parent must be private")
    profile = _profile_snapshot(root)
    try:
        campaign_value, _ = ground_truth_campaign_v1._json(campaign_path, modes={0o400})
        ground_truth_campaign_v1.validate_manifest(root, campaign_value)
    except ground_truth_campaign_v1.CampaignV1Error as exc:
        raise GroundTruthSubmitError("campaign lane authentication failed") from exc
    campaign_lanes = campaign_value.get("lanes")
    if not isinstance(campaign_lanes, list):
        _fail("campaign lanes are invalid")
    selected_lanes = [
        item
        for item in campaign_lanes
        if isinstance(item, dict) and item.get("rank") == rank and item.get("lane") == lane
    ]
    if len(selected_lanes) != 1:
        _fail("campaign lane is not unique")
    campaign_lane = selected_lanes[0]
    if campaign_lane.get("attempt_id") != attempt_id:
        _fail("attempt identity differs from authenticated campaign lane")
    lane_reviewer = campaign_lane.get("reviewer")
    if (
        not isinstance(lane_reviewer, dict)
        or set(lane_reviewer) != {"name", "version"}
        or not isinstance(lane_reviewer.get("name"), str)
        or not isinstance(lane_reviewer.get("version"), str)
    ):
        _fail("campaign lane reviewer is invalid")
    custody_raw = _owned_file(
        runtime_custody_receipt_path,
        max_bytes=_MAX_BINDING_BYTES,
        allowed_modes={0o400},
    )
    if _sha(custody_raw) != runtime_custody_receipt_sha256:
        _fail("runtime custody receipt differs from attestation")
    published = ground_truth_packet_v1.attest_packet_selection(
        root,
        campaign_path,
        source_bindings_path,
        cache,
        ledger_root,
        packets_root,
        runtime_custody_receipt_path,
        runtime_attestation_entry_hash,
        rank,
    )
    aggregate_raw = _owned_file(
        packets_root / "aggregate-manifest.json",
        max_bytes=_MAX_PACKET_MANIFEST_BYTES,
        allowed_modes={0o400},
    )
    aggregate = _strict_json(aggregate_raw, "aggregate manifest")
    rows = aggregate.get("packets")
    if not isinstance(rows, list):
        _fail("aggregate packet rows are invalid")
    selected = [item for item in rows if isinstance(item, dict) and item.get("rank") == rank]
    if len(selected) != 1:
        _fail("rank is not unique in aggregate")
    row = selected[0]
    original = packets_root / str(row.get("directory"))
    original_manifest_raw = _owned_file(
        original / "packet-manifest.json",
        max_bytes=_MAX_PACKET_MANIFEST_BYTES,
        allowed_modes={0o400},
    )
    original_manifest = _strict_json(original_manifest_raw, "original packet manifest")
    source_value, source_raw, _ = ground_truth_source_v1._read_json(
        source_bindings_path, modes={0o400}
    )
    if published.get("runtime_custody_receipt_sha256") != _sha(custody_raw):
        _fail("source bindings changed after attested validation")
    source_rows = source_value.get("records")
    if not isinstance(source_rows, list):
        _fail("source binding records are invalid")
    matching_source = [
        item for item in source_rows if isinstance(item, dict) and item.get("rank") == rank
    ]
    if len(matching_source) != 1:
        _fail("source binding rank is not unique")
    source_record = matching_source[0]
    expected = {
        "repository": source_record.get("repository"),
        "pr": source_record.get("pr"),
        "baseline_commit": source_record.get("baseline_commit"),
        "target_commit": source_record.get("target_commit"),
        "baseline_tree": source_record.get("baseline_tree"),
        "target_tree": source_record.get("target_tree"),
        "packet_root_sha256": row.get("packet_root_sha256"),
    }
    if any(original_manifest.get(key) != value for key, value in expected.items()):
        _fail("aggregate, source binding, and packet disagree")
    if _manifest_root(original_manifest) != row.get("packet_root_sha256"):
        _fail("original packet root changed")
    staging = Path(tempfile.mkdtemp(prefix=f".{attempt_root.name}.", dir=parent))
    staging.chmod(0o700)
    try:
        packet = staging / "packet"
        shutil.copytree(original, packet, symlinks=True, copy_function=shutil.copy2)
        packet.chmod(0o700)
        policies = packet / "policies"
        if policies.exists() or policies.is_symlink():
            policy_status = policies.lstat()
            if policies.is_symlink() or not stat.S_ISDIR(policy_status.st_mode):
                _fail("packet policies path is not a directory")
            policies.chmod(0o700)
        else:
            policies.mkdir(mode=0o700)
        for name, filename in _PRODUCTION_POLICY_FILES.items():
            del name
            relative = f"{_PROFILE_DIR}/{filename}"
            try:
                raw = profile.files[relative]
            except KeyError as exc:
                raise GroundTruthSubmitError("review policy is absent from profile") from exc
            target = policies / filename
            target.write_bytes(raw)
            target.chmod(0o400)
        if not _same_profile(profile, _profile_snapshot(root)):
            _fail("production profile drifted after policy copy")
        escrow = staging / "escrow"
        escrow.mkdir(mode=0o700)
        _freeze_packet(packet)
        manifest_path = packet / "packet-manifest.json"
        source_structure_path = packet / "source-structure.json"
        manifest_raw = _owned_file(
            manifest_path, max_bytes=_MAX_PACKET_MANIFEST_BYTES, allowed_modes={0o400}
        )
        structure_raw = _owned_file(
            source_structure_path,
            max_bytes=_MAX_PACKET_MANIFEST_BYTES,
            allowed_modes={0o400},
        )
        structure = _strict_json(structure_raw, "source structure")
        _, blob_inventory = _inventory(structure)
        policy_paths = {
            name: packet / "policies" / filename
            for name, filename in _PRODUCTION_POLICY_FILES.items()
        }
        policy_raw = {
            name: _owned_file(path, max_bytes=_MAX_AUTHENTICATED_FILE_BYTES, allowed_modes={0o400})
            for name, path in policy_paths.items()
        }
        final_packet = attempt_root / "packet"
        inputs = [
            AuthenticatedInput(
                name="packet_manifest",
                path=str(final_packet / "packet-manifest.json"),
                sha256=_sha(manifest_raw),
                bytes=len(manifest_raw),
                mode=0o400,
            ),
            AuthenticatedInput(
                name="source_structure",
                path=str(final_packet / "source-structure.json"),
                sha256=_sha(structure_raw),
                bytes=len(structure_raw),
                mode=0o400,
            ),
        ]
        inputs.extend(
            AuthenticatedInput(
                name=cast("Any", name),
                path=str(final_packet / "policies" / _PRODUCTION_POLICY_FILES[name]),
                sha256=_sha(raw),
                bytes=len(raw),
                mode=0o400,
            )
            for name, raw in policy_raw.items()
        )
        custody_value = _strict_json(custody_raw, "runtime custody receipt")
        cache_summary = custody_value.get("cache")
        if not isinstance(cache_summary, dict):
            _fail("runtime custody cache summary is invalid")
        start = (started_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
        packet_status = packet.stat(follow_symlinks=False)
        reviewer = Actor(
            kind="agent",
            name=cast("str", lane_reviewer["name"]),
            version=cast("str", lane_reviewer["version"]),
        )
        record = SubmissionBinding(
            schema_version=1,
            generation=generation,
            attempt_id=attempt_id,
            capability=secrets.token_hex(32),
            packet_path=str(final_packet),
            packet_device=packet_status.st_dev,
            packet_inode=packet_status.st_ino,
            packet_manifest_sha256=_sha(manifest_raw),
            packet_root_sha256=cast("str", row["packet_root_sha256"]),
            blob_inventory_sha256=blob_inventory,
            source_structure_sha256=_sha(structure_raw),
            packet_inventory_sha256=_packet_inventory(packet),
            original_packet_path=str(original),
            campaign_path=str(campaign_path),
            source_bindings_path=str(source_bindings_path),
            ledger_root=str(ledger_root),
            packets_root=str(packets_root),
            runtime_attestation_entry_hash=runtime_attestation_entry_hash,
            runtime_custody_receipt_path=str(runtime_custody_receipt_path),
            runtime_custody_receipt_sha256=runtime_custody_receipt_sha256,
            selection_custody=SelectionCustodyReceipt.model_validate(published),
            original_packet_root_sha256=cast("str", row["packet_root_sha256"]),
            aggregate_root_sha256=cast("str", published["aggregate_root_sha256"]),
            publication_entry_hash=cast("str", published["publication_entry_hash"]),
            source_bindings_sha256=_sha(source_raw),
            cache_device=cast("int", cache_summary["cache_device"]),
            cache_inode=cast("int", cache_summary["cache_inode"]),
            cache_inventory_sha256=cast("str", cache_summary["inventory_sha256"]),
            authenticated_inputs=tuple(inputs),
            profile_checksum_sha256=profile.checksum_sha256,
            profile_files_sha256=profile.files_sha256,
            escrow_path=str(attempt_root / "escrow" / "review.json"),
            cache_root=str(cache),
            corpus_id="oss-expansion-50x50-lock-v2",
            repository=cast("str", source_record["repository"]),
            pr=cast("int", source_record["pr"]),
            rank=rank,
            lane=lane,
            snapshots=SnapshotBinding(
                baseline_commit=cast("str", source_record["baseline_commit"]),
                target_commit=cast("str", source_record["target_commit"]),
            ),
            baseline_tree=cast("str", source_record["baseline_tree"]),
            target_tree=cast("str", source_record["target_tree"]),
            reviewer=reviewer,
            run=BoundRun(
                prompt_sha256=_sha(policy_raw["review_prompt"]),
                model_policy_sha256=_sha(policy_raw["model_policy"]),
                tool_policy_sha256=_sha(policy_raw["tool_policy"]),
                source_policy_sha256=_sha(policy_raw["source_policy"]),
                started_at=start,
                limits=ResourceLimits(
                    max_tokens=100_000,
                    max_tool_calls=203,
                    max_seconds=1800,
                    max_output_bytes=2_097_152,
                ),
            ),
            max_validation_attempts=3,
        )
        bindings = SubmissionBindings(
            schema_version=1,
            protocol="ground-truth-review-submit-v1",
            records=(record,),
        )
        binding_raw = canonical_json(bindings.model_dump(mode="json"))
        boundary_profile = _profile_snapshot(root)
        boundary_published = ground_truth_packet_v1.validate_packet_selection_receipt(
            root,
            campaign_path,
            source_bindings_path,
            cache,
            ledger_root,
            packets_root,
            runtime_custody_receipt_path,
            published,
            runtime_attestation_entry_hash=runtime_attestation_entry_hash,
        )
        if (
            not _same_profile(profile, boundary_profile)
            or boundary_published.get("commands") != 0
            or boundary_published.get("rank") != published.get("rank")
            or boundary_published.get("runtime_attestation_entry_hash")
            != runtime_attestation_entry_hash
            or _sha(source_raw) != record.source_bindings_sha256
            or _packet_inventory(packet) != record.packet_inventory_sha256
        ):
            _fail("production profile, source, cache, or packet drifted before binding publication")
        binding = staging / "binding.json"
        binding.write_bytes(binding_raw)
        binding.chmod(0o400)
        ground_truth_packet_v1._rename_noreplace(staging, attempt_root)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        raise
    return {
        "attempt_root": str(attempt_root),
        "attempt_id": attempt_id,
        "rank": rank,
        "lane": lane,
        "binding_sha256": _sha(binding_raw),
        "packet_inventory_sha256": record.packet_inventory_sha256,
        "live_launch_authorized": False,
        "canonical_import_authorized": False,
    }


def main(argv: list[str] | None = None) -> NoReturn:
    del argv
    _fail("direct submission CLI is disabled; use the attested runtime broker")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
