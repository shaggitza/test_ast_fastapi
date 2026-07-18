#!/usr/bin/env python3
"""One-shot typed Luna-xhigh adjudication for frozen v3 review pairs."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal, NoReturn, cast

from benchmarks.real_world import pilot_submit_v3
from benchmarks.real_world import pilot_typed_run_v3 as review_run
from benchmarks.real_world.ground_truth_v2 import GroundTruthError
from benchmarks.real_world.ground_truth_v2.schema import (
    EvidenceLocation,
    ReviewArtifactV1,
    StrictModel,
    artifact_sha256,
    canonical_json,
)
from pydantic import (
    ConfigDict,
    Field,
    StrictInt,
    ValidationError,
    field_validator,
    model_validator,
)

_MAX_JSON = 4 * 1024 * 1024
_MAX_SESSION = 64 * 1024 * 1024
_MAX_SECONDS = 1800
_ATTEMPT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_AGENT_NAME = "pilot-semantic-adjudicator-luna-xhigh-v3"
_MODEL = "openai-codex/gpt-5.6-luna"
_THINKING = "xhigh"
_CONFIG_MODES = {0o600, 0o644}


class PilotAdjudicationError(RuntimeError):
    """Fail-closed adjudication orchestration error."""


def _fail(message: str) -> NoReturn:
    raise PilotAdjudicationError(message)


def _sha(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate JSON key")
        result[key] = value
    return result


def _constant(value: str) -> NoReturn:
    _fail(f"non-finite JSON value: {value}")


def _read(path: Path, limit: int, *, modes: set[int] | None = None) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise PilotAdjudicationError(f"cannot open {path.name}") from exc
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_uid != os.getuid():
            _fail("file owner or type is invalid")
        if modes is not None and stat.S_IMODE(status.st_mode) not in modes:
            _fail("file mode is invalid")
        if status.st_size > limit:
            _fail("file exceeds byte limit")
        raw = bytearray()
        while len(raw) <= limit:
            chunk = os.read(descriptor, min(64 * 1024, limit + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
    finally:
        os.close(descriptor)
    if len(raw) > limit:
        _fail("file exceeds byte limit")
    return bytes(raw)


def _json_bytes(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=_unique, parse_constant=_constant)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise PilotAdjudicationError(f"invalid JSON: {label}") from exc
    if not isinstance(value, dict):
        _fail(f"{label} root must be an object")
    return cast("dict[str, Any]", value)


def _json(path: Path, limit: int, *, modes: set[int] | None = None) -> dict[str, Any]:
    return _json_bytes(_read(path, limit, modes=modes), path.name)


def _atomic(path: Path, raw: bytes, *, mode: int) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise PilotAdjudicationError(f"refusing to overwrite {path}") from exc
        _fsync(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _replace(path: Path, raw: bytes, *, mode: int = 0o600) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
        _fsync(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _fsync(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _safe_path(value: str) -> str:
    if "\\" in value or "\x00" in value or value.startswith("/"):
        _fail("unsafe repository path")
    parts = PurePosixPath(value).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        _fail("unsafe repository path")
    return value


class OutputEvidence(StrictModel):
    side: Literal["baseline", "target"]
    path: Annotated[str, Field(min_length=1, max_length=1000)]
    start_line: Annotated[StrictInt, Field(ge=1, le=10_000_000)]
    end_line: Annotated[StrictInt, Field(ge=1, le=10_000_000)]

    @model_validator(mode="after")
    def range_and_path(self) -> OutputEvidence:
        _safe_path(self.path)
        if self.end_line < self.start_line:
            raise ValueError("evidence range is reversed")
        return self


class OutputEntrypoint(StrictModel):
    kind: Literal["http", "graphql", "task", "event", "cli", "cron", "sdk", "other"]
    public_id: Annotated[str, Field(min_length=1, max_length=2000)]
    confidence: Literal["confirmed", "probable", "possible"]

    @field_validator("public_id")
    @classmethod
    def nonblank_public_id(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("public_id must not be blank")
        return value


class OutputClaim(StrictModel):
    claim_kind: Literal["entrypoint"]
    recommendation: Literal["include", "exclude", "unknown"]
    entrypoint: OutputEntrypoint
    summary: Annotated[str, Field(min_length=1, max_length=20_000)]
    evidence: Annotated[tuple[OutputEvidence, ...], Field(min_length=1, max_length=1000)]

    @field_validator("summary")
    @classmethod
    def nonblank_summary(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("summary must not be blank")
        return value


class OutputUnknown(StrictModel):
    category: Annotated[str, Field(min_length=1, max_length=1000)]
    description: Annotated[str, Field(min_length=1, max_length=20_000)]
    evidence_limit: Annotated[str, Field(min_length=1, max_length=20_000)]

    @field_validator("category", "description", "evidence_limit")
    @classmethod
    def nonblank_unknown_field(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("unknown fields must not be blank")
        return value


class AdjudicationOutput(StrictModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    terminal_recommendation: Literal["positive", "negative_control", "unknown", "not_evaluable"]
    decision: Annotated[str, Field(min_length=1, max_length=20_000)]
    claims: Annotated[tuple[OutputClaim, ...], Field(max_length=1000)]
    unknowns: Annotated[tuple[OutputUnknown, ...], Field(max_length=1000)]

    @field_validator("decision")
    @classmethod
    def nonblank_decision(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("decision must not be blank")
        return value

    @model_validator(mode="after")
    def terminal_shape(self) -> AdjudicationOutput:
        _claim_atoms(self.claims)
        if self.terminal_recommendation == "positive" and not self.claims:
            raise ValueError("positive adjudication requires claims")
        if self.terminal_recommendation == "negative_control" and self.claims:
            raise ValueError("negative_control adjudication cannot have claims")
        if self.terminal_recommendation in {"unknown", "not_evaluable"} and not self.unknowns:
            raise ValueError("unknown/not_evaluable adjudication requires unknowns")
        return self


def _claim_atoms(claims: Any) -> tuple[tuple[str, str, str, str, str], ...]:
    atoms: set[tuple[str, str, str, str, str]] = set()
    identities: dict[tuple[str, str, str], tuple[str, str]] = {}
    for claim in claims:
        atom = (
            str(claim.claim_kind),
            str(claim.recommendation),
            str(claim.entrypoint.kind),
            str(claim.entrypoint.public_id),
            str(claim.entrypoint.confidence),
        )
        identity = (atom[0], atom[2], atom[3])
        outcome = (atom[1], atom[4])
        previous = identities.setdefault(identity, outcome)
        if previous != outcome:
            _fail("one lane contains internally conflicting claims")
        atoms.add(atom)
    return tuple(sorted(atoms))


def _review_atom_rows(review: ReviewArtifactV1) -> tuple[tuple[str, str, str, str, str], ...]:
    return _claim_atoms(review.claims)


def _pair_hash(review_a_sha: str, review_b_sha: str) -> str:
    payload = {
        "domain": "blind-review-adjudication-pair-v3",
        "review_a_sha256": review_a_sha,
        "review_b_sha256": review_b_sha,
    }
    return _sha(canonical_json(payload))


def _authenticated_review_record(
    execution_root: Path, attempt_id: str
) -> tuple[ReviewArtifactV1, bytes, pilot_submit_v3.SubmissionBinding]:
    attempt, state = review_run._load_native_state(execution_root, attempt_id)
    binding = pilot_submit_v3.load_bindings(Path(str(state["binding"]))).records[0]
    review_run._authenticated_result(attempt / "native-result.json", binding)
    raw = _read(Path(binding.escrow_path), binding.run.limits.max_output_bytes, modes={0o400})
    try:
        artifact = ReviewArtifactV1.model_validate_json(raw, strict=True)
    except ValidationError as exc:
        raise PilotAdjudicationError("review artifact schema validation failed") from exc
    if (
        artifact.repository != binding.repository
        or artifact.pr != binding.pr
        or artifact.lane != binding.lane
    ):
        _fail("review artifact identity mismatch")
    return artifact, raw, binding


def _authenticated_review(execution_root: Path, attempt_id: str) -> tuple[ReviewArtifactV1, bytes]:
    artifact, raw, _binding = _authenticated_review_record(execution_root, attempt_id)
    return artifact, raw


def _consumed_pairs(source_root: Path) -> set[str]:
    profile_root = source_root / "benchmarks/real_world/pilot_v3"
    report_path = profile_root / "native-pilot-report-v1.json"
    checksums = _json(profile_root / "checksums-v1.json", _MAX_JSON)
    files = checksums.get("files")
    relative = "benchmarks/real_world/pilot_v3/native-pilot-report-v1.json"
    report_raw = _read(report_path, _MAX_JSON)
    if not isinstance(files, dict) or files.get(relative) != _sha(report_raw):
        _fail("historical native pilot report checksum is invalid")
    report = _json_bytes(report_raw, "historical native pilot report")
    fallback = report.get("xhigh_terminal_fallback")
    medium = report.get("medium_review")
    if not isinstance(fallback, dict) or not isinstance(medium, dict):
        _fail("historical native pilot report is invalid")
    if fallback.get("attempts_launched") != 1:
        return set()
    attempts = medium.get("attempts")
    if not isinstance(attempts, list):
        _fail("historical native pilot attempts are invalid")
    matches = [
        row
        for row in attempts
        if isinstance(row, dict)
        and row.get("repository") == "PrefectHQ/prefect"
        and row.get("pr") == 22189
    ]
    lanes = {row.get("lane"): row.get("artifact_sha256") for row in matches}
    if set(lanes) != {"A", "B"} or not all(isinstance(value, str) for value in lanes.values()):
        _fail("historical consumed pair binding is invalid")
    return {_pair_hash(cast("str", lanes["A"]), cast("str", lanes["B"]))}


def compare_execution(execution_root: Path) -> dict[str, object]:
    if not execution_root.is_absolute():
        _fail("execution root must be absolute")
    root = execution_root.resolve(strict=True)
    identity = review_run._reauthenticate_execution(root)
    groups: dict[tuple[str, int], dict[str, tuple[str, ReviewArtifactV1, bytes]]] = {}
    invalid_groups: set[tuple[str, int]] = set()
    operational: list[dict[str, object]] = []
    for attempt in sorted((root / "attempts").iterdir(), key=lambda path: path.name):
        result = attempt / "native-result.json"
        if not result.exists():
            continue
        try:
            review, raw = _authenticated_review(root, attempt.name)
            group = (review.repository, review.pr)
            lane_rows = groups.setdefault(group, {})
            if review.lane in lane_rows:
                invalid_groups.add(group)
                operational.append(
                    {
                        "repository": review.repository,
                        "pr": review.pr,
                        "error": "DuplicateFinalizedLane",
                    }
                )
                continue
            lane_rows[review.lane] = (attempt.name, review, raw)
        except (
            PilotAdjudicationError,
            pilot_submit_v3.PilotSubmitError,
            GroundTruthError,
        ) as exc:
            operational.append({"attempt_id": attempt.name, "error": type(exc).__name__})
    pairs: list[dict[str, object]] = []
    consumed = _consumed_pairs(Path(cast("str", identity["source_root"])))
    for (repository, pr), lanes in sorted(groups.items()):
        if (repository, pr) in invalid_groups or set(lanes) != {"A", "B"}:
            continue
        attempt_a, review_a, raw_a = lanes["A"]
        attempt_b, review_b, raw_b = lanes["B"]
        if review_a.snapshots != review_b.snapshots or review_a.corpus_id != review_b.corpus_id:
            _fail("lane snapshot or corpus mismatch")
        sha_a, sha_b = artifact_sha256(raw_a), artifact_sha256(raw_b)
        pair_sha = _pair_hash(sha_a, sha_b)
        atoms_a, atoms_b = _review_atom_rows(review_a), _review_atom_rows(review_b)
        reasons: list[str] = []
        if review_a.terminal_recommendation != review_b.terminal_recommendation:
            reasons.append("terminal_recommendation_disagreement")
        if atoms_a != atoms_b:
            reasons.append("normalized_claim_atom_disagreement")
        if review_a.terminal_recommendation in {
            "unknown",
            "not_evaluable",
        } or review_b.terminal_recommendation in {"unknown", "not_evaluable"}:
            reasons.append("terminal_unknown_or_not_evaluable")
        if any(atom[1] == "unknown" for atom in (*atoms_a, *atoms_b)):
            reasons.append("claim_recommendation_unknown")
        required = bool(reasons)
        pairs.append(
            {
                "repository": repository,
                "pr": pr,
                "attempt_a": attempt_a,
                "attempt_b": attempt_b,
                "review_a_sha256": sha_a,
                "review_b_sha256": sha_b,
                "pair_sha256": pair_sha,
                "terminal_a": review_a.terminal_recommendation,
                "terminal_b": review_b.terminal_recommendation,
                "claim_atoms_a": [list(atom) for atom in atoms_a],
                "claim_atoms_b": [list(atom) for atom in atoms_b],
                "xhigh_required": required,
                "trigger_reasons": sorted(set(reasons)),
                "fallback_consumed": pair_sha in consumed,
                "status": "xhigh_required" if required else "agreement",
            }
        )
    return {
        "schema_version": 1,
        "protocol": "blind-review-comparison-v3",
        "pairs": pairs,
        "operational_failures": operational,
        "totals": {
            "pairs": len(pairs),
            "agreements": sum(row["status"] == "agreement" for row in pairs),
            "xhigh_required": sum(row["status"] == "xhigh_required" for row in pairs),
        },
    }


def _select_pair(execution_root: Path, repository: str, pr: int) -> dict[str, Any]:
    comparison = compare_execution(execution_root)
    matches = [
        row
        for row in cast("list[dict[str, Any]]", comparison["pairs"])
        if row["repository"] == repository and row["pr"] == pr
    ]
    if len(matches) != 1:
        _fail("review pair is not unique")
    return matches[0]


def _agent_bytes(source_root: Path) -> bytes:
    prompt = _read(
        source_root / "benchmarks/real_world/pilot_v3/adjudication-prompt-v1.md", _MAX_JSON
    )
    text = prompt.decode("utf-8")
    body = f"""---
name: {_AGENT_NAME}
description: One-shot typed terminal semantic adjudicator
model: {_MODEL}
thinking: {_THINKING}
tools: read, grep, find, ls, structured_output
extensions:
systemPromptMode: replace
inheritProjectContext: false
inheritSkills: false
completionGuard: false
---

{text}
"""
    return body.encode()


def _policy_digest(source_root: Path) -> str:
    return _sha(
        _read(
            source_root / "benchmarks/real_world/pilot_v3/comparison-policy-v1.json",
            _MAX_JSON,
        )
    )


def _root_identity(root: Path) -> dict[str, object]:
    status = root.stat()
    return {
        "schema_version": 1,
        "protocol": "blind-review-adjudication-root-v3",
        "path": str(root),
        "device": str(status.st_dev),
        "inode": str(status.st_ino),
        "policy_sha256": _policy_digest(Path(__file__).resolve().parents[2]),
    }


def _claim_directory() -> Path:
    return Path.home() / ".cache/fastapi-endpoint-detector/pilot-v3-adjudication-claims"


def _private_claim_directory() -> Path:
    path = _claim_directory()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent_status = path.parent.stat()
    if parent_status.st_uid != os.getuid() or stat.S_IMODE(parent_status.st_mode) & 0o077:
        _fail("adjudication claim parent is not private")
    path.mkdir(mode=0o700, exist_ok=True)
    status = path.lstat()
    if (
        stat.S_ISLNK(status.st_mode)
        or not stat.S_ISDIR(status.st_mode)
        or status.st_uid != os.getuid()
        or stat.S_IMODE(status.st_mode) != 0o700
    ):
        _fail("adjudication claim directory is unsafe")
    return path


def _claim_pair(root: Path, pair_sha: str) -> None:
    claim_root = _private_claim_directory()
    claim_path = claim_root / f"{pair_sha.removeprefix('sha256:')}.json"
    identity = _root_identity(root)
    claim = {
        **identity,
        "pair_sha256": pair_sha,
        "claim_scope": "one_preserved_host_canonical_root",
    }
    raw = canonical_json(claim)
    if claim_path.exists():
        existing = _read(claim_path, _MAX_JSON, modes={0o400})
        if existing != raw:
            _fail("fallback pair is claimed by another adjudication root")
        return
    _atomic(claim_path, raw, mode=0o400)


def _private_root(root: Path) -> Path:
    if not root.is_absolute():
        _fail("adjudication root must be absolute")
    resolved = root.resolve(strict=False)
    parent = resolved.parent.resolve(strict=True)
    status = parent.stat()
    if (
        status.st_uid != os.getuid()
        or not stat.S_ISDIR(status.st_mode)
        or stat.S_IMODE(status.st_mode) & 0o077
    ):
        _fail("adjudication parent is not private")
    expected_agent = _agent_bytes(Path(__file__).resolve().parents[2])
    if not resolved.exists():
        resolved.mkdir(mode=0o700)
        (resolved / "pairs").mkdir(mode=0o700)
        (resolved / "runtime").mkdir(mode=0o700)
        _atomic(resolved / "agent.md", expected_agent, mode=0o400)
    for directory in (resolved, resolved / "pairs", resolved / "runtime"):
        status = directory.lstat()
        if (
            stat.S_ISLNK(status.st_mode)
            or not stat.S_ISDIR(status.st_mode)
            or status.st_uid != os.getuid()
            or stat.S_IMODE(status.st_mode) != 0o700
        ):
            _fail("adjudication root is unsafe")
    if _read(resolved / "agent.md", _MAX_JSON, modes={0o400}) != expected_agent:
        _fail("adjudication agent source changed")
    identity_path = resolved / "root-identity.json"
    identity = canonical_json(_root_identity(resolved))
    if identity_path.exists():
        if _read(identity_path, _MAX_JSON, modes={0o400}) != identity:
            _fail("adjudication root identity changed")
    else:
        _atomic(identity_path, identity, mode=0o400)
    return resolved


def _write_state(pair_dir: Path, state: dict[str, object]) -> None:
    _replace(pair_dir / "state.json", canonical_json(state), mode=0o600)


def _load_state(root: Path, pair_sha: str) -> tuple[Path, dict[str, Any]]:
    if not _SHA.fullmatch(pair_sha):
        _fail("pair hash is invalid")
    pair_dir = root / "pairs" / pair_sha.removeprefix("sha256:")
    if not pair_dir.is_dir() or pair_dir.is_symlink():
        _fail("adjudication pair is missing")
    state = _json(pair_dir / "state.json", 512 * 1024, modes={0o600})
    required = {
        "schema_version",
        "protocol",
        "pair_sha256",
        "pair_dir",
        "attempt_id",
        "packet",
        "packet_sha256",
        "source_packet_root_sha256",
        "source_packet_manifest_sha256",
        "review_policy_hashes",
        "execution_root",
        "packet_root",
        "repository",
        "pr",
        "review_a_sha256",
        "review_b_sha256",
        "attempt_a",
        "attempt_b",
        "status",
        "deadline_unix_ms",
    }
    if (
        not required.issubset(state)
        or state.get("schema_version") != 1
        or state.get("protocol") != "blind-review-adjudication-state-v3"
        or state.get("pair_sha256") != pair_sha
        or state.get("pair_dir") != str(pair_dir)
        or state.get("status") not in {"prepared", "launched", "completed", "terminal_unknown"}
        or not isinstance(state.get("deadline_unix_ms"), int)
    ):
        _fail("adjudication state binding mismatch")
    return pair_dir, state


def _inventory_hash(root: Path) -> tuple[list[dict[str, object]], str]:
    files, _ = review_run._inventory(root)
    rows = []
    for path in files:
        relative = path.relative_to(root).as_posix()
        if relative == "adjudication-manifest.json":
            continue
        raw = _read(path, 64 * 1024 * 1024)
        rows.append({"path": relative, "bytes": len(raw), "sha256": _sha(raw)})
    return rows, _sha(canonical_json({"domain": "adjudication-packet-v3", "files": rows}))


def _authenticate_packet(state: dict[str, Any]) -> None:
    packet = Path(cast("str", state["packet"]))
    if packet.resolve(strict=True) != packet or packet.parent != Path(
        cast("str", state["pair_dir"])
    ):
        _fail("adjudication packet path is invalid")
    rows, digest = _inventory_hash(packet)
    manifest = _json(packet / "adjudication-manifest.json", _MAX_JSON, modes={0o444})
    if (
        manifest.get("protocol") != "blind-review-adjudication-packet-v3"
        or manifest.get("pair_sha256") != state["pair_sha256"]
        or manifest.get("files") != rows
        or manifest.get("packet_sha256") != digest
        or manifest.get("source_packet_root_sha256") != state["source_packet_root_sha256"]
        or state.get("packet_sha256") != digest
    ):
        _fail("adjudication packet authentication failed")
    source_manifest_raw = _read(
        packet / "source/packet-manifest.json", 16 * 1024 * 1024, modes={0o444}
    )
    source_manifest = _json_bytes(source_manifest_raw, "copied source packet manifest")
    if (
        _sha(source_manifest_raw) != state["source_packet_manifest_sha256"]
        or source_manifest.get("packet_root_sha256") != state["source_packet_root_sha256"]
        or source_manifest.get("packet_root_sha256")
        != pilot_submit_v3._manifest_root(source_manifest)
    ):
        _fail("copied source packet manifest authentication failed")
    pilot_submit_v3._verify_payload(packet / "source", source_manifest)
    policy_names = {
        "review_prompt": "review-prompt-v1.md",
        "model_policy": "model-policy-v1.json",
        "tool_policy": "tool-policy-v1.json",
        "source_policy": "source-policy-v1.json",
    }
    policy_hashes = state.get("review_policy_hashes")
    if not isinstance(policy_hashes, dict):
        _fail("review policy binding is invalid")
    for name, filename in policy_names.items():
        if policy_hashes.get(name) != _sha(
            _read(packet / "source/policies-v3" / filename, _MAX_JSON, modes={0o444})
        ):
            _fail("copied source packet policy authentication failed")
    freeze = _json(packet / "pair-freeze.json", _MAX_JSON, modes={0o444})
    if (
        freeze.get("pair_sha256") != state["pair_sha256"]
        or freeze.get("review_a_sha256") != state["review_a_sha256"]
        or freeze.get("review_b_sha256") != state["review_b_sha256"]
    ):
        _fail("adjudication pair freeze changed")
    review_a = _read(packet / "reviews/review-a.json", _MAX_JSON, modes={0o444})
    review_b = _read(packet / "reviews/review-b.json", _MAX_JSON, modes={0o444})
    if artifact_sha256(review_a) != state["review_a_sha256"]:
        _fail("adjudication Review A changed")
    if artifact_sha256(review_b) != state["review_b_sha256"]:
        _fail("adjudication Review B changed")


def _input_hashes(binding: pilot_submit_v3.SubmissionBinding) -> dict[str, str]:
    return {item.name: item.sha256 for item in binding.authenticated_inputs}


def _authenticate_source_packet_for_pair(
    source_packet: Path,
    repository: str,
    pr: int,
    binding_a: pilot_submit_v3.SubmissionBinding,
    binding_b: pilot_submit_v3.SubmissionBinding,
) -> tuple[dict[str, Any], str]:
    manifest_path = source_packet / "packet-manifest.json"
    manifest_raw = _read(manifest_path, 16 * 1024 * 1024, modes={0o444})
    manifest = _json_bytes(manifest_raw, "source packet manifest")
    if manifest.get("packet_root_sha256") != pilot_submit_v3._manifest_root(manifest):
        _fail("source packet manifest root is invalid")
    pilot_submit_v3._verify_payload(source_packet, manifest)
    manifest_sha = _sha(manifest_raw)
    expected = {
        "repository": repository,
        "pr": pr,
        "baseline_commit": binding_a.snapshots.baseline_commit,
        "target_commit": binding_a.snapshots.target_commit,
        "baseline_tree": binding_a.baseline_tree,
        "target_tree": binding_a.target_tree,
    }
    if any(manifest.get(key) != value for key, value in expected.items()):
        _fail("source packet does not match recovered review snapshots")
    for binding in (binding_a, binding_b):
        if (
            binding.repository != repository
            or binding.pr != pr
            or binding.snapshots != binding_a.snapshots
            or binding.baseline_tree != binding_a.baseline_tree
            or binding.target_tree != binding_a.target_tree
            or binding.packet_manifest_sha256 != manifest_sha
            or binding.packet_root_sha256 != manifest.get("packet_root_sha256")
        ):
            _fail("review binding and source packet disagree")
    hashes_a, hashes_b = _input_hashes(binding_a), _input_hashes(binding_b)
    if hashes_a != hashes_b or hashes_a.get("packet_manifest") != manifest_sha:
        _fail("review authenticated policy inputs disagree")
    policy_names = {
        "review_prompt": "review-prompt-v1.md",
        "model_policy": "model-policy-v1.json",
        "tool_policy": "tool-policy-v1.json",
        "source_policy": "source-policy-v1.json",
    }
    for name, filename in policy_names.items():
        raw = _read(source_packet / "policies-v3" / filename, _MAX_JSON, modes={0o444})
        if hashes_a.get(name) != _sha(raw):
            _fail("source packet policy hash does not match review binding")
    return manifest, manifest_sha


def prepare_adjudication(
    *,
    execution_root: Path,
    packet_root: Path,
    adjudication_root: Path,
    repository: str,
    pr: int,
    attempt_id: str,
    timeout_seconds: int = _MAX_SECONDS,
) -> dict[str, object]:
    if not _ATTEMPT.fullmatch(attempt_id) or timeout_seconds <= 0 or timeout_seconds > _MAX_SECONDS:
        _fail("attempt or timeout is invalid")
    execution = execution_root.resolve(strict=True)
    pair = _select_pair(execution, repository, pr)
    if not pair["xhigh_required"]:
        _fail("operational agreement must not launch xhigh")
    if pair["fallback_consumed"]:
        _fail("fallback was already consumed for this exact pair")
    root = _private_root(adjudication_root)
    _claim_pair(root, cast("str", pair["pair_sha256"]))
    pair_dir = root / "pairs" / cast("str", pair["pair_sha256"]).removeprefix("sha256:")
    try:
        pair_dir.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise PilotAdjudicationError("fallback pair already exists") from exc
    try:
        packet = pair_dir / "packet"
        source_packet = review_run._find_packet(packet_root.resolve(strict=True), repository, pr)
        review_a, raw_a, binding_a = _authenticated_review_record(
            execution, cast("str", pair["attempt_a"])
        )
        _review_b, raw_b, binding_b = _authenticated_review_record(
            execution, cast("str", pair["attempt_b"])
        )
        source_manifest, source_manifest_sha = _authenticate_source_packet_for_pair(
            source_packet, repository, pr, binding_a, binding_b
        )
        source_packet_sha = source_manifest.get("packet_root_sha256")
        if not isinstance(source_packet_sha, str) or not _SHA.fullmatch(source_packet_sha):
            _fail("source packet root binding is invalid")
        packet.mkdir(mode=0o700)
        review_run._copy_exact(source_packet, packet / "source")
        reviews = packet / "reviews"
        reviews.mkdir(mode=0o700)
        for path, raw in ((reviews / "review-a.json", raw_a), (reviews / "review-b.json", raw_b)):
            path.write_bytes(raw)
            path.chmod(0o600)
        freeze = {
            "schema_version": 1,
            "protocol": "blind-review-adjudication-pair-v3",
            "repository": repository,
            "pr": pr,
            "corpus_id": review_a.corpus_id,
            "snapshots": review_a.snapshots.model_dump(mode="json"),
            "review_a_sha256": pair["review_a_sha256"],
            "review_b_sha256": pair["review_b_sha256"],
            "pair_sha256": pair["pair_sha256"],
            "trigger_reasons": pair["trigger_reasons"],
        }
        (packet / "pair-freeze.json").write_bytes(canonical_json(freeze))
        rows, packet_sha = _inventory_hash(packet)
        manifest = {
            "schema_version": 1,
            "protocol": "blind-review-adjudication-packet-v3",
            "pair_sha256": pair["pair_sha256"],
            "source_packet_root_sha256": source_packet_sha,
            "files": rows,
            "packet_sha256": packet_sha,
        }
        (packet / "adjudication-manifest.json").write_bytes(canonical_json(manifest))
        review_run._freeze_tree(packet)
        started = _utc_now()
        deadline = int(started.timestamp() * 1000) + timeout_seconds * 1000
        state: dict[str, object] = {
            "schema_version": 1,
            "protocol": "blind-review-adjudication-state-v3",
            "attempt_id": attempt_id,
            "pair_sha256": pair["pair_sha256"],
            "pair_dir": str(pair_dir),
            "packet": str(packet),
            "packet_sha256": packet_sha,
            "source_packet_root_sha256": source_packet_sha,
            "source_packet_manifest_sha256": source_manifest_sha,
            "review_policy_hashes": _input_hashes(binding_a),
            "execution_root": str(execution),
            "packet_root": str(packet_root.resolve(strict=True)),
            "repository": repository,
            "pr": pr,
            "review_a_sha256": pair["review_a_sha256"],
            "review_b_sha256": pair["review_b_sha256"],
            "attempt_a": pair["attempt_a"],
            "attempt_b": pair["attempt_b"],
            "status": "prepared",
            "prepared_at": _utc_text(started),
            "deadline_unix_ms": deadline,
        }
        _atomic(pair_dir / "state.json", canonical_json(state), mode=0o600)
        return {
            "pair_sha256": pair["pair_sha256"],
            "attempt_id": attempt_id,
            "packet": str(packet),
            "deadline_unix_ms": deadline,
        }
    except BaseException:
        if not (pair_dir / "state.json").exists():
            shutil.rmtree(pair_dir, ignore_errors=True)
        raise


def _agent_discovery(source_root: Path) -> dict[str, Any]:
    runtime = review_run._runtime_agent_discovery({"source_root": str(source_root)})
    definitions = runtime.get("definitions")
    effective = runtime.get("effective")
    if not isinstance(definitions, dict) or not isinstance(effective, list):
        _fail("agent resolver output is invalid")
    candidates: list[str] = []
    for source in ("builtin", "package", "user", "project"):
        rows = definitions.get(source)
        if not isinstance(rows, list):
            _fail("agent resolver definitions are invalid")
        for row in rows:
            if isinstance(row, dict) and row.get("name") == _AGENT_NAME:
                value = row.get("filePath")
                if not isinstance(value, str):
                    _fail("agent resolver path is invalid")
                candidates.append(str(Path(value).resolve(strict=True)))
    effective_paths = [
        str(Path(cast("str", row["filePath"])).resolve(strict=True))
        for row in effective
        if isinstance(row, dict)
        and row.get("name") == _AGENT_NAME
        and isinstance(row.get("filePath"), str)
    ]
    return {
        "resolver_sha256": _sha(canonical_json(runtime)),
        "candidates": sorted(candidates),
        "effective": sorted(effective_paths),
    }


def _effective_agent_config(source_root: Path) -> dict[str, Any]:
    module = review_run._pi_subagents_agents_module()
    jiti = module.parents[3] / "jiti/lib/jiti.mjs"
    script = """
import { pathToFileURL } from 'node:url';
const { createJiti } = await import(pathToFileURL(process.argv[1]).href);
const api = await createJiti(import.meta.url).import(process.argv[2]);
const matches = api.discoverAgents(process.argv[3], 'both').agents
  .filter((a) => a.name === process.argv[4]);
if (matches.length !== 1) process.exit(7);
const a = matches[0];
process.stdout.write(JSON.stringify({
  name: a.name, filePath: a.filePath, model: a.model, thinking: a.thinking,
  tools: a.tools, extensions: a.extensions,
  subagentOnlyExtensions: a.subagentOnlyExtensions,
  inheritProjectContext: a.inheritProjectContext,
  inheritSkills: a.inheritSkills,
  completionGuard: a.completionGuard,
}));
"""
    node = shutil.which("node")
    if node is None:
        _fail("Node is unavailable for adjudicator config attestation")
    result = subprocess.run(
        [
            node,
            "--input-type=module",
            "-e",
            script,
            str(jiti),
            str(module),
            str(source_root),
            _AGENT_NAME,
        ],
        cwd=source_root,
        env=dict(os.environ),
        check=False,
        capture_output=True,
        timeout=15,
    )
    if result.returncode != 0 or result.stderr or len(result.stdout) > _MAX_JSON:
        _fail("effective adjudicator config resolution failed")
    config = _json_bytes(result.stdout, "effective adjudicator config")
    tools = config.get("tools")
    if (
        config.get("model") != _MODEL
        or config.get("thinking") != _THINKING
        or not isinstance(tools, list)
        or sorted(tools) != ["find", "grep", "ls", "read", "structured_output"]
        or any(tool in {"contact_supervisor", "intercom", "subagent"} for tool in tools)
        or config.get("inheritProjectContext") is not False
        or config.get("inheritSkills") is not False
        or config.get("completionGuard") is not False
        or config.get("extensions") not in (None, [])
        or config.get("subagentOnlyExtensions") not in (None, [])
    ):
        _fail("effective adjudicator config violates pinned policy")
    return config


def _subagent_config_path() -> Path:
    return review_run._pi_agent_dir() / "extensions/subagent/config.json"


def _intercom_config() -> dict[str, object]:
    path = _subagent_config_path().resolve(strict=True)
    raw = _read(path, _MAX_JSON, modes=_CONFIG_MODES)
    config = _json_bytes(raw, "pi-subagents config")
    bridge = config.get("intercomBridge")
    mode = "always"
    if isinstance(bridge, dict) and isinstance(bridge.get("mode"), str):
        mode = cast("str", bridge["mode"])
    if mode not in {"off", "fork-only"}:
        _fail("fresh adjudication requires intercom bridge off or fork-only")
    return {
        "schema_version": 1,
        "path": str(path),
        "sha256": _sha(raw),
        "mode": mode,
        "fresh_bridge_active": False,
    }


def _structured_output_activation_probe(agent: dict[str, Any]) -> dict[str, object]:
    module = review_run._pi_subagents_agents_module()
    pi_args = module.parent.parent / "runs/shared/pi-args.ts"
    jiti = module.parents[3] / "jiti/lib/jiti.mjs"
    script = """
import { pathToFileURL } from 'node:url';
const { createJiti } = await import(pathToFileURL(process.argv[1]).href);
const jiti = createJiti(import.meta.url);
const api = await jiti.import(process.argv[2]);
const tools = JSON.parse(process.argv[3]);
const result = api.buildPiArgs({
  baseArgs: [], task: 'typed-adjudication-probe', sessionEnabled: false,
  model: 'openai-codex/gpt-5.6-luna', thinking: 'xhigh',
  inheritProjectContext: false, inheritSkills: false, tools, extensions: [],
  structuredOutput: {
    schema: {type: 'object'}, schemaPath: '/probe/schema.json',
    outputPath: '/probe/output.json'
  }
});
const index = result.args.indexOf('--tools');
const expected = 'read,grep,find,ls,structured_output';
if (index < 0 || result.args[index + 1] !== expected) process.exit(11);
const schemaEnv = Boolean(result.env.PI_SUBAGENT_STRUCTURED_OUTPUT_SCHEMA);
const captureEnv = Boolean(result.env.PI_SUBAGENT_STRUCTURED_OUTPUT_CAPTURE);
if (!schemaEnv || !captureEnv) process.exit(12);
process.stdout.write(JSON.stringify({toolsArg: result.args[index + 1], schemaEnv, captureEnv}));
"""
    node = shutil.which("node")
    tools = agent.get("tools")
    if node is None or not isinstance(tools, list):
        _fail("Node or adjudicator tools unavailable for activation probe")
    result = subprocess.run(
        [
            node,
            "--input-type=module",
            "-e",
            script,
            str(jiti),
            str(pi_args),
            canonical_json(tools).decode(),
        ],
        cwd=module.parents[2],
        env=dict(os.environ),
        check=False,
        capture_output=True,
        timeout=15,
    )
    if result.returncode != 0 or result.stderr or len(result.stdout) > _MAX_JSON:
        _fail("structured_output activation probe failed")
    return _json_bytes(result.stdout, "structured_output activation probe")


def attest_native_environment(adjudication_root: Path) -> dict[str, object]:
    root = _private_root(adjudication_root)
    config = _intercom_config()
    agent = _effective_agent_config(Path(__file__).resolve().parents[2])
    activation = _structured_output_activation_probe(agent)
    receipt = {
        "schema_version": 1,
        "protocol": "blind-review-adjudication-environment-v3",
        "intercom": config,
        "agent_config_sha256": _sha(canonical_json(agent)),
        "agent_config": agent,
        "structured_output_activation": activation,
    }
    path = root / "environment-attestation.json"
    raw = canonical_json(receipt)
    if path.exists():
        if _read(path, _MAX_JSON, modes={0o400}) != raw:
            _fail("adjudication environment attestation changed")
        return receipt
    _atomic(path, raw, mode=0o400)
    return receipt


def _environment_attestation(root: Path) -> dict[str, Any]:
    receipt = _json(root / "environment-attestation.json", _MAX_JSON, modes={0o400})
    current_intercom = _intercom_config()
    current_agent = _effective_agent_config(Path(__file__).resolve().parents[2])
    current_activation = _structured_output_activation_probe(current_agent)
    if (
        receipt.get("protocol") != "blind-review-adjudication-environment-v3"
        or receipt.get("intercom") != current_intercom
        or receipt.get("agent_config") != current_agent
        or receipt.get("agent_config_sha256") != _sha(canonical_json(current_agent))
        or receipt.get("structured_output_activation") != current_activation
    ):
        _fail("adjudication environment attestation no longer matches")
    return receipt


def create_native_adjudicator(adjudication_root: Path, output: Path) -> dict[str, object]:
    root = _private_root(adjudication_root)
    source = root / "agent.md"
    raw = _read(source, _MAX_JSON, modes={0o400})
    if output.exists() or output.is_symlink():
        _fail("native adjudicator output already exists")
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    status = output.parent.stat()
    if status.st_uid != os.getuid() or stat.S_IMODE(status.st_mode) & 0o077:
        _fail("native adjudicator parent is not private")
    _atomic(output, raw, mode=0o400)
    source_root = Path(__file__).resolve().parents[2]
    discovery = _agent_discovery(source_root)
    installed = str(output.resolve(strict=True))
    if discovery["candidates"] != [installed] or discovery["effective"] != [installed]:
        output.unlink(missing_ok=True)
        _fail("native adjudicator is not the unique effective agent")
    effective_config = _effective_agent_config(source_root)
    if str(Path(cast("str", effective_config.get("filePath"))).resolve(strict=True)) != installed:
        output.unlink(missing_ok=True)
        _fail("effective adjudicator config path is not installed agent")
    receipt = {
        "schema_version": 1,
        "runtime_name": _AGENT_NAME,
        "path": installed,
        "bytes": len(raw),
        "sha256": _sha(raw),
        "discovery": discovery,
        "effective_config_sha256": _sha(canonical_json(effective_config)),
    }
    _atomic(root / "agent-installation.json", canonical_json(receipt), mode=0o400)
    return receipt


def _installed_agent(root: Path) -> dict[str, Any]:
    receipt = _json(root / "agent-installation.json", 512 * 1024, modes={0o400})
    path = Path(cast("str", receipt.get("path")))
    raw = _read(path, _MAX_JSON, modes={0o400})
    if receipt.get("runtime_name") != _AGENT_NAME or receipt.get("sha256") != _sha(raw):
        _fail("native adjudicator receipt is invalid")
    source_root = Path(__file__).resolve().parents[2]
    discovery = _agent_discovery(source_root)
    effective = _effective_agent_config(source_root)
    if (
        receipt.get("discovery") != discovery
        or discovery["candidates"] != [str(path)]
        or receipt.get("effective_config_sha256") != _sha(canonical_json(effective))
        or str(Path(cast("str", effective.get("filePath"))).resolve(strict=True)) != str(path)
    ):
        _fail("native adjudicator resolver binding changed")
    return receipt


def _validate_native_call(call: dict[str, object]) -> str:
    module = review_run._pi_subagents_agents_module()
    schemas = module.parent.parent / "extension/schemas.ts"
    jiti = module.parents[3] / "jiti/lib/jiti.mjs"
    script = """
import { pathToFileURL } from 'node:url';
const { createJiti } = await import(pathToFileURL(process.argv[1]).href);
const jiti = createJiti(import.meta.url);
const api = await jiti.import(process.argv[2]);
const valueApi = await jiti.import('typebox/value');
const value = JSON.parse(process.argv[3]);
if (!valueApi.Value.Check(api.SubagentParams, value)) process.exit(9);
process.stdout.write('VALID');
"""
    node = shutil.which("node")
    if node is None:
        _fail("Node is unavailable for native call validation")
    result = subprocess.run(
        [
            node,
            "--input-type=module",
            "-e",
            script,
            str(jiti),
            str(schemas),
            canonical_json(call).decode(),
        ],
        cwd=module.parents[2],
        env=dict(os.environ),
        check=False,
        capture_output=True,
        timeout=15,
    )
    if result.returncode != 0 or result.stdout != b"VALID" or result.stderr:
        _fail("native adjudication call fails pinned SubagentParams Value.Check")
    return _sha(canonical_json(call))


def native_adjudication_launch_plan(adjudication_root: Path, pair_sha: str) -> dict[str, object]:
    root = _private_root(adjudication_root)
    pair_dir, state = _load_state(root, pair_sha)
    lock = os.open(
        pair_dir / "state.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = _json(pair_dir / "state.json", 512 * 1024, modes={0o600})
        _reconcile_terminal_marker(pair_dir, state)
        if state.get("status") == "launched" and not (pair_dir / "launch-plan.json").exists():
            _terminal_unknown(pair_dir, state, "partial_launch_publication")
            _fail("partial adjudication launch publication")
        if state.get("status") != "prepared":
            _fail("fallback process was already claimed")
        deadline = cast("int", state["deadline_unix_ms"])
        remaining = deadline - int(time.time() * 1000)
        if remaining <= 0:
            _terminal_unknown(pair_dir, state, "prepared_deadline_expired")
            _fail("adjudication deadline expired")
        _authenticate_packet(state)
        installation = _installed_agent(root)
        environment = _environment_attestation(root)
        schema = _json(
            Path(__file__).resolve().parent / "pilot_v3/adjudication-output-schema-v1.json",
            _MAX_JSON,
        )
        call: dict[str, object] = {
            "chain": [
                {
                    "agent": _AGENT_NAME,
                    "task": (
                        "Adjudicate the exact frozen A/B semantic disagreement. "
                        "Follow the system policy and terminate with structured_output."
                    ),
                    "cwd": state["packet"],
                    "output": False,
                    "progress": False,
                    "acceptance": False,
                    "outputSchema": schema,
                }
            ],
            "context": "fresh",
            "artifacts": False,
            "async": False,
            "includeProgress": False,
            "timeoutMs": remaining,
        }
        call_sha = _validate_native_call(call)
        state["status"] = "launched"
        state["launched_at"] = _utc_text(_utc_now())
        state["agent_sha256"] = installation["sha256"]
        state["environment_attestation_sha256"] = _sha(canonical_json(environment))
        state["native_call_sha256"] = call_sha
        _write_state(pair_dir, state)
        plan: dict[str, object] = {
            "authentication": {
                "pair_sha256": pair_sha,
                "agent_sha256": installation["sha256"],
                "packet_sha256": state["packet_sha256"],
                "deadline_unix_ms": deadline,
                "environment_attestation_sha256": _sha(canonical_json(environment)),
                "native_call_sha256": call_sha,
            },
            "subagent_call": call,
        }
        _atomic(pair_dir / "launch-plan.json", canonical_json(plan), mode=0o400)
        return plan
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)


def _blob_map(packet: Path) -> dict[tuple[str, str], str]:
    manifest = _json(packet / "source/packet-manifest.json", 16 * 1024 * 1024, modes={0o444})
    snapshots = manifest.get("snapshots")
    if not isinstance(snapshots, dict):
        _fail("packet snapshot manifest is invalid")
    result: dict[tuple[str, str], str] = {}
    for side in ("baseline", "target"):
        value = snapshots.get(side)
        if not isinstance(value, dict) or not isinstance(value.get("files"), list):
            _fail("packet snapshot files are invalid")
        for row in value["files"]:
            if (
                not isinstance(row, dict)
                or not isinstance(row.get("path"), str)
                or not isinstance(row.get("oid"), str)
            ):
                _fail("packet snapshot file is invalid")
            result[(side, row["path"])] = row["oid"]
    return result


def _validate_output(state: dict[str, Any], output: AdjudicationOutput) -> None:
    execution = Path(cast("str", state["execution_root"]))
    _review_a, _ = _authenticated_review(execution, cast("str", state["attempt_a"]))
    _review_b, _ = _authenticated_review(execution, cast("str", state["attempt_b"]))
    _attempt, native_state = review_run._load_native_state(
        execution, cast("str", state["attempt_a"])
    )
    binding = pilot_submit_v3.load_bindings(Path(str(native_state["binding"]))).records[0]
    validator = review_run._validator_for(binding)
    blobs = _blob_map(Path(cast("str", state["packet"])))
    for claim in output.claims:
        locations: list[EvidenceLocation] = []
        for evidence in claim.evidence:
            oid = blobs.get((evidence.side, evidence.path))
            if oid is None:
                _fail("adjudication evidence path is not in packet inventory")
            locations.append(
                EvidenceLocation(
                    side=evidence.side,
                    commit_sha=getattr(binding.snapshots, f"{evidence.side}_commit"),
                    blob_sha=oid,
                    path=evidence.path,
                    start_line=evidence.start_line,
                    end_line=evidence.end_line,
                    symbol=claim.entrypoint.public_id,
                )
            )
        validator.validate_changed_location(locations[0])
        for location in locations[1:]:
            validator.validate_location(location)


def _completion(
    state: dict[str, Any], output: AdjudicationOutput, output_sha: str
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "artifact_type": "blind_review_pilot_completion_v3",
        "attempt_id": state["attempt_id"],
        "pair_sha256": state["pair_sha256"],
        "repository": state["repository"],
        "pr": state["pr"],
        "review_a_sha256": state["review_a_sha256"],
        "review_b_sha256": state["review_b_sha256"],
        "model": _MODEL,
        "thinking": _THINKING,
        "output_sha256": output_sha,
        "completed_at": _utc_text(_utc_now()),
        "terminal_recommendation": output.terminal_recommendation,
        "decision": output.decision,
        "claims": [claim.model_dump(mode="json") for claim in output.claims],
        "unknowns": [unknown.model_dump(mode="json") for unknown in output.unknowns],
        "canonical_database_imported": False,
    }


def _reconcile_completion(
    pair_dir: Path, state: dict[str, Any], output_sha: str
) -> dict[str, Any] | None:
    completion_path = pair_dir / "pilot-completion.json"
    receipt_path = pair_dir / "receipt.json"
    present = (completion_path.exists(), receipt_path.exists())
    marker_path = pair_dir / "terminal-unknown.json"
    if marker_path.exists() or state.get("status") == "terminal_unknown":
        _reconcile_terminal_marker(pair_dir, state)
        if any(present):
            _record_terminal_contradiction(pair_dir, state)
        _fail("terminal unknown adjudication cannot recover completion")
    if present == (False, False):
        return None
    if present != (True, True):
        _terminal_unknown(pair_dir, state, "partial_completion_publication")
        _fail("partial adjudication completion publication")
    completion_raw = _read(completion_path, _MAX_JSON, modes={0o400})
    completion = _json_bytes(completion_raw, "pilot completion")
    receipt = _json(receipt_path, _MAX_JSON, modes={0o400})
    if (
        completion.get("pair_sha256") != state["pair_sha256"]
        or completion.get("output_sha256") != output_sha
        or receipt.get("pair_sha256") != state["pair_sha256"]
        or receipt.get("completion_sha256") != _sha(completion_raw)
        or receipt.get("output_sha256") != output_sha
    ):
        if state.get("status") != "completed":
            _terminal_unknown(pair_dir, state, "completion_recovery_binding_mismatch")
        _fail("adjudication completion recovery binding mismatch")
    state["status"] = "completed"
    state["completion_sha256"] = receipt["completion_sha256"]
    _write_state(pair_dir, state)
    return completion


def finalize_adjudication(
    adjudication_root: Path, pair_sha: str, output_path: Path
) -> dict[str, object]:
    root = _private_root(adjudication_root)
    pair_dir, _ = _load_state(root, pair_sha)
    lock = os.open(
        pair_dir / "state.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = _json(pair_dir / "state.json", 512 * 1024, modes={0o600})
        _reconcile_terminal_marker(pair_dir, state)
        completion_path = pair_dir / "pilot-completion.json"
        receipt_path = pair_dir / "receipt.json"
        try:
            raw = _read(output_path.resolve(strict=True), _MAX_JSON, modes={0o400, 0o600})
            output_sha = _sha(raw)
            output_value = _json_bytes(raw, "supervisor structured output")
            structured_sha = _sha(canonical_json(output_value))
        except (OSError, PilotAdjudicationError) as exc:
            if state.get("status") == "launched":
                _terminal_unknown(pair_dir, state, type(exc).__name__)
            raise PilotAdjudicationError("adjudication output is terminal invalid") from exc
        recovered = _reconcile_completion(pair_dir, state, output_sha)
        if recovered is not None:
            return recovered
        if state.get("status") != "launched":
            _fail("adjudication was not launched exactly once")
        if int(state["deadline_unix_ms"]) < int(time.time() * 1000):
            _terminal_unknown(pair_dir, state, "deadline_expired")
            _fail("adjudication deadline expired")
        try:
            audit = _json(pair_dir / "session-audit.json", _MAX_JSON, modes={0o400})
            if (
                audit.get("pair_sha256") != state["pair_sha256"]
                or audit.get("structured_output_sha256") != structured_sha
                or audit.get("environment_attestation_sha256")
                != state.get("environment_attestation_sha256")
            ):
                _fail("adjudication session audit binding mismatch")
            _authenticate_packet(state)
            parsed = AdjudicationOutput.model_validate_json(raw, strict=True)
            _validate_output(state, parsed)
        except (
            OSError,
            ValidationError,
            PilotAdjudicationError,
            GroundTruthError,
        ) as exc:
            # Validation failure is intentionally terminal; there is never a retry.
            _terminal_unknown(pair_dir, state, type(exc).__name__)
            raise PilotAdjudicationError("adjudication output is terminal invalid") from exc
        completion = _completion(state, parsed, output_sha)
        completion_raw = canonical_json(completion)
        _atomic(completion_path, completion_raw, mode=0o400)
        receipt = {
            "schema_version": 1,
            "pair_sha256": pair_sha,
            "completion_sha256": _sha(completion_raw),
            "output_sha256": output_sha,
            "terminal_recommendation": parsed.terminal_recommendation,
        }
        _atomic(receipt_path, canonical_json(receipt), mode=0o400)
        state["status"] = "completed"
        state["completion_sha256"] = receipt["completion_sha256"]
        _write_state(pair_dir, state)
        return completion
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)


def _record_terminal_contradiction(pair_dir: Path, state: dict[str, Any]) -> None:
    state["status"] = "terminal_unknown"
    state["terminal_contradiction"] = "completion_artifacts_present_with_terminal_unknown"
    _write_state(pair_dir, state)


def _terminal_unknown(pair_dir: Path, state: dict[str, Any], diagnostic: str) -> None:
    if state.get("status") == "completed" and not (pair_dir / "terminal-unknown.json").exists():
        _fail("completed adjudication cannot transition to terminal unknown")
    marker_path = pair_dir / "terminal-unknown.json"
    if marker_path.exists():
        marker = _json(marker_path, _MAX_JSON, modes={0o400})
        if marker.get("pair_sha256") != state["pair_sha256"]:
            _fail("terminal unknown marker binding mismatch")
    else:
        marker = {
            "schema_version": 1,
            "pair_sha256": state["pair_sha256"],
            "terminal_disposition": "unknown",
            "diagnostic": diagnostic[:200],
            "failed_at": _utc_text(_utc_now()),
        }
        _atomic(marker_path, canonical_json(marker), mode=0o400)
    state["status"] = "terminal_unknown"
    state["terminal_unknown_sha256"] = _sha(_read(marker_path, _MAX_JSON, modes={0o400}))
    if (pair_dir / "pilot-completion.json").exists() or (pair_dir / "receipt.json").exists():
        state["terminal_contradiction"] = "completion_artifacts_present_with_terminal_unknown"
    _write_state(pair_dir, state)


def _reconcile_terminal_marker(pair_dir: Path, state: dict[str, Any]) -> None:
    marker_path = pair_dir / "terminal-unknown.json"
    if not marker_path.exists():
        return
    marker = _json(marker_path, _MAX_JSON, modes={0o400})
    if marker.get("pair_sha256") != state.get("pair_sha256"):
        _fail("terminal unknown marker binding mismatch")
    state["status"] = "terminal_unknown"
    state["terminal_unknown_sha256"] = _sha(_read(marker_path, _MAX_JSON, modes={0o400}))
    if (pair_dir / "pilot-completion.json").exists() or (pair_dir / "receipt.json").exists():
        state["terminal_contradiction"] = "completion_artifacts_present_with_terminal_unknown"
    _write_state(pair_dir, state)


def _parse_adjudication_session(state: dict[str, Any], raw: bytes) -> dict[str, object]:  # noqa: PLR0912,PLR0915
    cwd: str | None = None
    model: str | None = None
    thinking: str | None = None
    session_count = model_count = thinking_count = session_info_count = user_count = 0
    activity_started = False
    calls: list[dict[str, Any]] = []
    results: dict[str, bool] = {}
    terminal_call_id: str | None = None
    terminal_assistant_event: int | None = None
    last_assistant_event: int | None = None
    seen_call_ids: set[str] = set()
    seen_result_ids: set[str] = set()
    allowed_events = {"session", "model_change", "thinking_level_change", "session_info", "message"}
    lines = raw.splitlines()
    if not lines:
        _fail("adjudicator session is empty")
    for event_index, line in enumerate(lines):
        event = _json_bytes(line, "session event")
        kind = event.get("type")
        if kind not in allowed_events:
            _fail("adjudicator session contains unknown event type")
        if kind == "session":
            session_count += 1
            if event_index != 0 or session_count != 1 or activity_started:
                _fail("adjudicator session header cardinality is invalid")
            cwd = cast("str | None", event.get("cwd"))
            continue
        if kind == "model_change":
            model_count += 1
            if activity_started or model_count != 1:
                _fail("adjudicator model event cardinality or order is invalid")
            model = cast("str | None", event.get("modelId"))
            continue
        if kind == "thinking_level_change":
            thinking_count += 1
            if activity_started or thinking_count != 1:
                _fail("adjudicator thinking event cardinality or order is invalid")
            thinking = cast("str | None", event.get("thinkingLevel"))
            continue
        if kind == "session_info":
            session_info_count += 1
            if activity_started or session_info_count != 1:
                _fail("adjudicator session info cardinality or order is invalid")
            continue
        message = event.get("message")
        if not isinstance(message, dict):
            _fail("adjudicator message event is malformed")
        activity_started = True
        if model_count != 1 or thinking_count != 1 or session_count != 1 or session_info_count != 1:
            _fail("adjudicator identity events must precede activity")
        role = message.get("role")
        content = message.get("content")
        if not isinstance(content, list):
            _fail("adjudicator message content is invalid")
        if role == "user":
            user_count += 1
            if user_count != 1 or any(
                not isinstance(part, dict) or part.get("type") != "text" for part in content
            ):
                _fail("adjudicator user message cardinality is invalid")
            text = " ".join(str(part.get("text", "")) for part in content)
            if any(value in text for value in ("contact_supervisor", "intercom", "subagent(")):
                _fail("adjudicator user message references forbidden coordination")
            continue
        if role == "assistant":
            if user_count != 1:
                _fail("adjudicator assistant activity preceded task")
            last_assistant_event = event_index
            for part in content:
                if not isinstance(part, dict):
                    _fail("session assistant content is invalid")
                if part.get("type") == "thinking":
                    continue
                if part.get("type") != "toolCall":
                    _fail("adjudicator emitted forbidden prose or content")
                name, call_id, arguments = part.get("name"), part.get("id"), part.get("arguments")
                if name in {"contact_supervisor", "intercom", "subagent"}:
                    _fail("adjudicator used forbidden coordination")
                if name not in {"read", "grep", "find", "ls", "structured_output"}:
                    _fail("adjudicator used forbidden tool")
                if not isinstance(call_id, str) or not call_id or not isinstance(arguments, dict):
                    _fail("adjudicator tool call is invalid")
                if call_id in seen_call_ids:
                    _fail("adjudicator tool call id is duplicated")
                seen_call_ids.add(call_id)
                if name in {"read", "grep", "find", "ls"}:
                    path_value = arguments.get("path", ".")
                    if not isinstance(path_value, str):
                        _fail("adjudicator source path is invalid")
                    path = Path(path_value)
                    resolved = (
                        path.resolve(strict=False)
                        if path.is_absolute()
                        else (Path(cast("str", state["packet"])) / path).resolve(strict=False)
                    )
                    try:
                        resolved.relative_to(Path(cast("str", state["packet"])))
                    except ValueError as exc:
                        raise PilotAdjudicationError(
                            "adjudicator source tool escaped packet"
                        ) from exc
                else:
                    if (
                        terminal_call_id is not None
                        or set(arguments) != {"value"}
                        or not isinstance(arguments["value"], dict)
                    ):
                        _fail("structured_output wrapper is invalid or repeated")
                    terminal_call_id = call_id
                    terminal_assistant_event = event_index
                calls.append({"id": call_id, "name": name, "arguments": arguments})
            continue
        if role == "toolResult":
            call_id = message.get("toolCallId")
            if not isinstance(call_id, str) or call_id not in seen_call_ids:
                _fail("adjudicator tool result does not match a prior call")
            if call_id in seen_result_ids:
                _fail("adjudicator tool result id is duplicated")
            seen_result_ids.add(call_id)
            results[call_id] = message.get("isError") is False
            continue
        _fail("adjudicator message role is unknown")
    if cwd != state["packet"] or model != "gpt-5.6-luna" or thinking != _THINKING:
        _fail("adjudicator session identity mismatch")
    if user_count != 1 or terminal_call_id is None or not results.get(terminal_call_id):
        _fail("structured_output did not terminate successfully")
    if set(results) != seen_call_ids or terminal_assistant_event != last_assistant_event:
        _fail("adjudicator call/result cardinality or terminal order is invalid")
    terminal_index = next(
        index for index, call in enumerate(calls) if call["id"] == terminal_call_id
    )
    if terminal_index != len(calls) - 1:
        _fail("structured_output was not the final tool call")
    wrapper = calls[terminal_index]["arguments"]
    value = cast("dict[str, Any]", wrapper["value"])
    AdjudicationOutput.model_validate_json(canonical_json(value), strict=True)
    return {
        "schema_version": 1,
        "pair_sha256": state["pair_sha256"],
        "session_sha256": _sha(raw),
        "tool_calls": len(calls),
        "structured_output_calls": 1,
        "structured_output_sha256": _sha(canonical_json(value)),
        "environment_attestation_sha256": state.get("environment_attestation_sha256"),
    }


def audit_adjudication_session(
    adjudication_root: Path, pair_sha: str, session_path: Path
) -> dict[str, object]:
    root = _private_root(adjudication_root)
    pair_dir, _state = _load_state(root, pair_sha)
    lock = os.open(
        pair_dir / "state.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = _json(pair_dir / "state.json", 512 * 1024, modes={0o600})
        _reconcile_terminal_marker(pair_dir, state)
        try:
            if state.get("status") != "launched":
                _fail("adjudication session audit requires launched state")
            if int(state["deadline_unix_ms"]) < int(time.time() * 1000):
                _fail("launched adjudication deadline expired")
            environment = _environment_attestation(root)
            if state.get("environment_attestation_sha256") != _sha(canonical_json(environment)):
                _fail("adjudication environment binding changed")
            _authenticate_packet(state)
            raw = _read(session_path.resolve(strict=True), _MAX_SESSION)
            audit = _parse_adjudication_session(state, raw)
            audit_path = pair_dir / "session-audit.json"
            if audit_path.exists():
                existing = _json(audit_path, _MAX_JSON, modes={0o400})
                if existing != audit:
                    _fail("lost-response session audit changed")
                return existing
            _atomic(audit_path, canonical_json(audit), mode=0o400)
            return audit
        except (OSError, ValidationError, PilotAdjudicationError, GroundTruthError) as exc:
            _terminal_unknown(pair_dir, state, type(exc).__name__)
            raise PilotAdjudicationError("adjudication session audit is terminal invalid") from exc
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)


def summarize(adjudication_root: Path) -> dict[str, object]:
    root = _private_root(adjudication_root)
    rows: list[dict[str, object]] = []
    for pair_dir in sorted((root / "pairs").iterdir(), key=lambda path: path.name):
        lock = os.open(
            pair_dir / "state.lock",
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            state = _json(pair_dir / "state.json", 512 * 1024, modes={0o600})
            _reconcile_terminal_marker(pair_dir, state)
            if state.get("status") in {"prepared", "launched"} and int(
                state["deadline_unix_ms"]
            ) < int(time.time() * 1000):
                _terminal_unknown(pair_dir, state, f"{state['status']}_deadline_expired")
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
            os.close(lock)
        row: dict[str, object] = {
            "pair_sha256": state["pair_sha256"],
            "repository": state["repository"],
            "pr": state["pr"],
            "status": state["status"],
        }
        if isinstance(state.get("terminal_contradiction"), str):
            row["terminal_contradiction"] = state["terminal_contradiction"]
        rows.append(row)
    return {"schema_version": 1, "protocol": "blind-review-adjudication-summary-v3", "pairs": rows}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    compare = sub.add_parser("compare")
    compare.add_argument("--execution-root", required=True, type=Path)
    prepare = sub.add_parser("prepare-adjudication")
    prepare.add_argument("--execution-root", required=True, type=Path)
    prepare.add_argument("--packet-root", required=True, type=Path)
    prepare.add_argument("--adjudication-root", required=True, type=Path)
    prepare.add_argument("--repository", required=True)
    prepare.add_argument("--pr", required=True, type=int)
    prepare.add_argument("--attempt-id", required=True)
    prepare.add_argument("--timeout-seconds", type=int, default=_MAX_SECONDS)
    agent = sub.add_parser("create-native-adjudicator")
    agent.add_argument("--adjudication-root", required=True, type=Path)
    agent.add_argument("--output", required=True, type=Path)
    environment = sub.add_parser("attest-native-environment")
    environment.add_argument("--adjudication-root", required=True, type=Path)
    launch = sub.add_parser("native-adjudication-launch-plan")
    launch.add_argument("--adjudication-root", required=True, type=Path)
    launch.add_argument("--pair-sha256", required=True)
    finalize = sub.add_parser("finalize-adjudication")
    finalize.add_argument("--adjudication-root", required=True, type=Path)
    finalize.add_argument("--pair-sha256", required=True)
    finalize.add_argument("--output", required=True, type=Path)
    audit = sub.add_parser("audit-adjudication-session")
    audit.add_argument("--adjudication-root", required=True, type=Path)
    audit.add_argument("--pair-sha256", required=True)
    audit.add_argument("--session", required=True, type=Path)
    summary = sub.add_parser("summarize")
    summary.add_argument("--adjudication-root", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "compare":
        result = compare_execution(args.execution_root)
    elif args.command == "prepare-adjudication":
        result = prepare_adjudication(
            execution_root=args.execution_root,
            packet_root=args.packet_root,
            adjudication_root=args.adjudication_root,
            repository=args.repository,
            pr=args.pr,
            attempt_id=args.attempt_id,
            timeout_seconds=args.timeout_seconds,
        )
    elif args.command == "create-native-adjudicator":
        result = create_native_adjudicator(args.adjudication_root, args.output)
    elif args.command == "attest-native-environment":
        result = attest_native_environment(args.adjudication_root)
    elif args.command == "native-adjudication-launch-plan":
        result = native_adjudication_launch_plan(args.adjudication_root, args.pair_sha256)
    elif args.command == "finalize-adjudication":
        result = finalize_adjudication(args.adjudication_root, args.pair_sha256, args.output)
    elif args.command == "audit-adjudication-session":
        result = audit_adjudication_session(args.adjudication_root, args.pair_sha256, args.session)
    else:
        result = summarize(args.adjudication_root)
    print(canonical_json(result).decode(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
