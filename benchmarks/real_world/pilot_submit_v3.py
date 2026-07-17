"""Typed supervisor validation and escrow broker for blind review protocol v3.

The child submits only semantic review fields. Supervisor bindings inject identity,
provenance, commits, immutable blob identities, IDs, and evidence ordinals. The
broker never imports or executes analyzed source.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import re
import socket
import stat
import struct
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Annotated, Any, Literal, NoReturn, cast

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

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
_INPUT_NAMES = {
    "packet_manifest",
    "review_prompt",
    "model_policy",
    "tool_policy",
    "source_policy",
}


class PilotSubmitError(RuntimeError):
    """Fail-closed submission broker error."""


class SubmissionRejected(PilotSubmitError):
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
        "packet_manifest", "review_prompt", "model_policy", "tool_policy", "source_policy"
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


class SubmissionBinding(_StrictModel):
    schema_version: Literal[1]
    attempt_id: str
    capability: str
    packet_path: str
    packet_device: StrictInt = Field(ge=0)
    packet_inode: StrictInt = Field(gt=0)
    packet_manifest_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    packet_root_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    blob_inventory_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    authenticated_inputs: tuple[AuthenticatedInput, ...] = Field(min_length=5, max_length=5)
    escrow_path: str
    cache_root: str
    corpus_id: str = Field(min_length=1, max_length=300)
    repository: str = Field(pattern=r"^[^/\s]+/[^/\s]+$", max_length=300)
    pr: StrictInt = Field(gt=0)
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

    @field_validator("packet_path", "escrow_path", "cache_root")
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
        return self


class SubmissionBindings(_StrictModel):
    schema_version: Literal[1]
    protocol: Literal["blind-review-submit-v3"]
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
    raise PilotSubmitError(message)


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
        raise PilotSubmitError("private file cannot be opened") from exc
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


def _reject_nesting(raw: bytes, *, maximum: int = 100) -> None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PilotSubmitError("JSON is not UTF-8") from exc
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
                raise PilotSubmitError(f"duplicate key in {label}")
            result[key] = value
        return result

    def reject_constant(value: str) -> NoReturn:
        raise PilotSubmitError(f"non-finite value in {label}: {value}")

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
        raise PilotSubmitError(f"invalid JSON: {label}") from exc
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    try:
        canonical_json(value)
    except (UnicodeEncodeError, ValueError, OverflowError, RecursionError, MemoryError) as exc:
        raise PilotSubmitError(f"invalid JSON: {label}") from exc
    return value


def _within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def _manifest_root(manifest: dict[str, Any]) -> str:
    payload = {key: value for key, value in manifest.items() if key != "packet_root_sha256"}
    return _sha(b"blind-review-pilot-packet-root-v1\0" + canonical_json(payload))


def _inventory(
    manifest: dict[str, Any],
) -> tuple[dict[tuple[str, str], str], str]:
    snapshots = manifest.get("snapshots")
    if not isinstance(snapshots, dict) or set(snapshots) != {"baseline", "target"}:
        _fail("packet snapshot inventory is invalid")
    lookup: dict[tuple[str, str], str] = {}
    rows: list[dict[str, str]] = []
    for side in ("baseline", "target"):
        snapshot = snapshots[side]
        if not isinstance(snapshot, dict) or not isinstance(snapshot.get("files"), list):
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


def _verify_payload(packet: Path, manifest: dict[str, Any]) -> None:  # noqa: PLR0912
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
        raw = _owned_file(path, max_bytes=size, allowed_modes={0o444})
        if len(raw) != size or _sha(raw) != digest:
            _fail("packet payload bytes changed")

    actual: set[str] = set()
    for directory, names, filenames in os.walk(packet, followlinks=False):
        root = Path(directory)
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
    if actual != seen | {"packet-manifest.json"}:
        _fail("packet filesystem census does not match manifest")


def _authenticate_record(  # noqa: PLR0912 - fail-closed authentication is linear
    record: SubmissionBinding,
) -> dict[tuple[str, str], str]:
    packet = Path(record.packet_path)
    _reject_symlink_ancestors(packet / "sentinel")
    try:
        packet_status = packet.stat()
    except OSError as exc:
        raise PilotSubmitError("bound packet is unavailable") from exc
    if (
        not stat.S_ISDIR(packet_status.st_mode)
        or packet_status.st_uid != os.getuid()
        or packet_status.st_dev != record.packet_device
        or packet_status.st_ino != record.packet_inode
        or stat.S_IMODE(packet_status.st_mode) & 0o022
        or str(packet.resolve(strict=True)) != record.packet_path
    ):
        _fail("bound packet identity changed")

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
    lookup, inventory_digest = _inventory(manifest)
    if inventory_digest != record.blob_inventory_sha256:
        _fail("packet blob inventory binding mismatch")
    _verify_payload(packet, manifest)
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
        raise PilotSubmitError("escrow parent is unavailable") from exc
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
        raise PilotSubmitError("cache root is unavailable") from exc
    if (
        not stat.S_ISDIR(cache_status.st_mode)
        or cache_status.st_uid != os.getuid()
        or cache.is_symlink()
        or str(cache.resolve(strict=True)) != record.cache_root
        or stat.S_IMODE(cache_status.st_mode) & 0o022
    ):
        _fail("cache root is unavailable")
    return lookup


def load_bindings(path: Path) -> SubmissionBindings:
    """Load and authenticate one private supervisor binding."""
    payload = _strict_json(
        _owned_file(path, max_bytes=_MAX_BINDING_BYTES, allowed_modes={0o600}), "bindings"
    )
    try:
        bindings = SubmissionBindings.model_validate(payload)
    except (ValueError, RecursionError, MemoryError) as exc:
        raise PilotSubmitError("submission bindings are invalid") from exc
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
    except (PilotSubmitError, GroundTruthError, ValueError, RecursionError, MemoryError) as exc:
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
            "LOCATION_NOT_IN_BOUND_INVENTORY", f"{location.side}:{location.path}"[:_MAX_DIAGNOSTIC]
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
    if (
        completed_at < record.run.started_at
        or completed_at
        > record.run.started_at + timedelta(seconds=record.run.limits.max_seconds)
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
    return GitEvidenceValidator(
        Path(record.cache_root),
        record.repository,
        record.snapshots.baseline_commit,
        record.snapshots.target_commit,
        record.baseline_tree,
        record.target_tree,
        budget=EvidenceBudget(max_wall_seconds=240),
    )


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


def _atomic_no_clobber(path: Path, raw: bytes, *, mode: int) -> None:
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise SubmissionRejected("ALREADY_SUBMITTED") from exc
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


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
    return _sha(canonical_json(record.model_dump(mode="json")))


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


def _recover_locked(
    record: SubmissionBinding, *, validator: EvidenceValidator | None = None
) -> SubmissionReceipt:
    _authenticate_record(record)
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
        raise PilotSubmitError("escrow recovery artifacts are invalid") from exc
    assert isinstance(review, ReviewArtifactV1)
    canonical = canonical_json(review.model_dump(mode="json"))
    if canonical != raw:
        _fail("escrow artifact is not canonical")
    _validate_identity(review, record)
    _validate_review_evidence(review, record, validator)
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


def recover_submission(
    record: SubmissionBinding, *, validator: EvidenceValidator | None = None
) -> SubmissionReceipt:
    """Fully revalidate and recover an exact prior successful submission."""
    with _escrow_lock(Path(record.escrow_path)):
        return _recover_locked(record, validator=validator)


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
            return _recover_locked(record, validator=evidence)
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
        try:
            _atomic_no_clobber(artifact_path, raw, mode=0o400)
            _atomic_no_clobber(
                sidecar_path, canonical_json(sidecar.model_dump(mode="json")), mode=0o400
            )
            return _recover_locked(record, validator=evidence)
        except BaseException:
            artifact_path.unlink(missing_ok=True)
            sidecar_path.unlink(missing_ok=True)
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
    except PilotSubmitError as exc:
        raise SubmissionRejected("REQUEST_INVALID") from exc
    if set(payload) != {"protocol_version", "capability", "cwd", "draft"}:
        raise SubmissionRejected("REQUEST_FIELDS_INVALID")
    if payload["protocol_version"] != 3:
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
    result: dict[str, object] = {"protocol_version": 3, "ok": False, "code": exc.code}
    if exc.diagnostic:
        result["diagnostic"] = exc.diagnostic[:_MAX_DIAGNOSTIC]
    return result


def _success(receipt: SubmissionReceipt) -> dict[str, object]:
    return {
        "protocol_version": 3,
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
            raise PilotSubmitError("broker absolute deadline expired")
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
                raise PilotSubmitError("broker accept timeout") from exc
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
                    rejected += 1
                    with contextlib.suppress(OSError):
                        _send_frame(connection, _failure(exc))
                except (OSError, TimeoutError) as exc:
                    rejected += 1
                    with contextlib.suppress(OSError):
                        _send_frame(connection, _failure(SubmissionRejected("IO_ERROR")))
                    if rejected >= record.max_validation_attempts:
                        raise PilotSubmitError("submission attempt budget exhausted") from exc
        raise PilotSubmitError("submission attempt budget exhausted")
    finally:
        server.close()
        socket_path.unlink(missing_ok=True)
        directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--socket", type=Path)
    parser.add_argument("--bindings", type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument("--deadline-unix-ms", type=int)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.serve or args.socket is None or args.bindings is None:
        _fail("--serve, --socket, and --bindings are required")
    if args.timeout_seconds <= 0 or args.timeout_seconds > 1800:
        _fail("timeout is out of range")
    if args.deadline_unix_ms is not None and args.deadline_unix_ms <= 0:
        _fail("deadline is out of range")
    return serve(
        args.socket,
        args.bindings,
        timeout_seconds=args.timeout_seconds,
        deadline_unix_ms=args.deadline_unix_ms,
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
