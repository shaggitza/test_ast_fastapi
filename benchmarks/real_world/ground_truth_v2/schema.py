"""Strict, bounded contracts for prediction-blind review and adjudication artifacts."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from itertools import pairwise
from pathlib import PurePosixPath
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    field_validator,
    model_validator,
)

from . import GroundTruthError

SHA256 = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
GIT_SHA = Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
NONEMPTY = Annotated[str, Field(min_length=1, max_length=2000)]
IDENTIFIER = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")]
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_ITEMS = 1000


class StrictModel(BaseModel):
    """Common immutable no-coercion model configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class SnapshotBinding(StrictModel):
    baseline_commit: GIT_SHA
    target_commit: GIT_SHA


class CorpusSnapshot(StrictModel):
    commit_sha: GIT_SHA
    tree_sha: GIT_SHA
    rule: NONEMPTY


class CorpusDiff(StrictModel):
    sha256: SHA256
    byte_count: Annotated[StrictInt, Field(ge=0)]
    final_url: NONEMPTY
    content_type: NONEMPTY


class CorpusPullRequest(StrictModel):
    number: Annotated[StrictInt, Field(gt=0)]
    rank: Annotated[StrictInt, Field(gt=0)]
    merged_at: datetime
    base_sha: GIT_SHA
    head_sha: GIT_SHA
    merge_commit_sha: GIT_SHA
    baseline: CorpusSnapshot
    target: CorpusSnapshot
    remote_diff: CorpusDiff

    @field_validator("merged_at", mode="before")
    @classmethod
    def parse_merged_at(cls, value: object) -> datetime:
        return _parse_utc(value, "merged_at")


class CorpusRepository(StrictModel):
    full_name: Annotated[str, Field(pattern=r"^[^/\s]+/[^/\s]+$", max_length=300)]
    partition: NONEMPTY
    terminal_status: Literal["complete", "underfilled", "unavailable"]
    pull_requests: tuple[CorpusPullRequest, ...]

    @model_validator(mode="after")
    def unique_prs(self) -> CorpusRepository:
        _unique([str(item.number) for item in self.pull_requests], "PR number")
        _unique([str(item.rank) for item in self.pull_requests], "PR rank")
        return self


class CorpusDefinition(StrictModel):
    schema_version: Literal[2]
    corpus_id: NONEMPTY
    lock_sha256: SHA256
    source: Literal["authenticated_v2_lock", "strict_synthetic_fixture"]
    repositories: Annotated[tuple[CorpusRepository, ...], Field(min_length=1, max_length=100)]

    @model_validator(mode="after")
    def corpus_consistency(self) -> CorpusDefinition:
        _unique([item.full_name.casefold() for item in self.repositories], "repository")
        return self


class Actor(StrictModel):
    kind: Literal["human", "agent"]
    name: NONEMPTY
    version: NONEMPTY


class ResourceLimits(StrictModel):
    max_tokens: Annotated[StrictInt, Field(ge=0, le=10_000_000)]
    max_tool_calls: Annotated[StrictInt, Field(ge=0, le=100_000)]
    max_seconds: Annotated[StrictInt, Field(gt=0, le=604_800)]
    max_output_bytes: Annotated[StrictInt, Field(gt=0, le=MAX_ARTIFACT_BYTES)]


class RunProvenance(StrictModel):
    prompt_sha256: SHA256
    model_policy_sha256: SHA256
    tool_policy_sha256: SHA256
    source_policy_sha256: SHA256
    started_at: datetime
    completed_at: datetime
    limits: ResourceLimits

    @field_validator("started_at", "completed_at", mode="before")
    @classmethod
    def canonical_utc(cls, value: object) -> datetime:
        return _parse_utc(value, "run timestamp")

    @model_validator(mode="after")
    def chronological(self) -> RunProvenance:
        if self.completed_at < self.started_at:
            raise ValueError("completed_at precedes started_at")
        return self


class EvidenceLocation(StrictModel):
    side: Literal["baseline", "target"]
    commit_sha: GIT_SHA
    blob_sha: GIT_SHA
    path: Annotated[str, Field(min_length=1, max_length=1000)]
    start_line: Annotated[StrictInt, Field(gt=0, le=10_000_000)]
    end_line: Annotated[StrictInt, Field(gt=0, le=10_000_000)]
    symbol: Annotated[str, Field(min_length=1, max_length=500)]

    @field_validator("path")
    @classmethod
    def safe_relative_path(cls, value: str) -> str:
        if "\\" in value or "\x00" in value or value.startswith("/"):
            raise ValueError("path must be a safe repository-relative POSIX path")
        parts = PurePosixPath(value).parts
        if not parts or any(part in {"", ".", ".."} for part in parts):
            raise ValueError("path must not contain empty, dot, or parent segments")
        return value

    @model_validator(mode="after")
    def ordered_range(self) -> EvidenceLocation:
        if self.end_line < self.start_line:
            raise ValueError("evidence line range is reversed")
        return self


class EvidenceEdge(StrictModel):
    ordinal: Annotated[StrictInt, Field(ge=0, le=MAX_ITEMS)]
    relation: Literal["direct", "calls", "imports", "registers", "dispatches", "depends_on"]
    from_location: EvidenceLocation
    to_location: EvidenceLocation


class Entrypoint(StrictModel):
    public_id: NONEMPTY
    kind: Literal["http", "graphql", "task", "event", "cli", "cron", "sdk", "other"]
    confidence: Literal["confirmed", "probable", "possible"]


class ChangedSymbol(StrictModel):
    symbol_id: IDENTIFIER
    canonical_name: NONEMPTY
    location: EvidenceLocation


class ReviewClaim(StrictModel):
    claim_id: IDENTIFIER
    claim_kind: Literal["entrypoint"]
    recommendation: Literal["include", "exclude", "unknown"]
    summary: NONEMPTY
    entrypoint: Entrypoint
    evidence: Annotated[tuple[EvidenceEdge, ...], Field(min_length=1, max_length=MAX_ITEMS)]

    @model_validator(mode="after")
    def chain(self) -> ReviewClaim:
        _validate_chain(self.evidence)
        return self


class UnknownFinding(StrictModel):
    unknown_id: IDENTIFIER
    category: NONEMPTY
    description: NONEMPTY
    evidence_limit: NONEMPTY


class NegativeAssessment(StrictModel):
    changed_symbol_census_complete: Literal[True]
    searched_entrypoint_families: Annotated[
        tuple[NONEMPTY, ...], Field(min_length=1, max_length=100)
    ]
    limitations: Annotated[tuple[NONEMPTY, ...], Field(min_length=1, max_length=100)]


class ReviewArtifactV1(StrictModel):
    schema_version: Literal[1]
    artifact_type: Literal["ground_truth_review"]
    corpus_id: NONEMPTY
    repository: Annotated[str, Field(pattern=r"^[^/\s]+/[^/\s]+$", max_length=300)]
    pr: Annotated[StrictInt, Field(gt=0)]
    lane: Literal["A", "B"]
    snapshots: SnapshotBinding
    reviewer: Actor
    run: RunProvenance
    terminal_recommendation: Literal["positive", "negative_control", "unknown", "not_evaluable"]
    changed_symbols: Annotated[tuple[ChangedSymbol, ...], Field(max_length=MAX_ITEMS)]
    claims: Annotated[tuple[ReviewClaim, ...], Field(max_length=MAX_ITEMS)]
    unknowns: Annotated[tuple[UnknownFinding, ...], Field(max_length=MAX_ITEMS)]
    negative_assessment: NegativeAssessment | None
    notes: Annotated[str, Field(max_length=20_000)]

    @model_validator(mode="after")
    def terminal_shape(self) -> ReviewArtifactV1:
        _unique([item.symbol_id for item in self.changed_symbols], "changed symbol id")
        _unique([item.claim_id for item in self.claims], "claim id")
        _unique([item.unknown_id for item in self.unknowns], "unknown id")
        if self.terminal_recommendation == "positive" and not self.claims:
            raise ValueError("positive review requires an entrypoint claim")
        if self.terminal_recommendation == "negative_control":
            if self.claims or self.negative_assessment is None or not self.changed_symbols:
                raise ValueError(
                    "negative review requires census and changed symbols, with no claims"
                )
        elif self.negative_assessment is not None:
            raise ValueError("negative_assessment is allowed only for negative_control")
        if self.terminal_recommendation in {"unknown", "not_evaluable"} and not self.unknowns:
            raise ValueError("unknown/not_evaluable review requires a structured unknown")
        return self


class DecisionSource(StrictModel):
    """One typed, lane-qualified immutable Review A/B conclusion."""

    lane: Literal["A", "B"]
    source_kind: Literal["claim", "terminal", "unknown", "negative_assessment"]
    source_id: IDENTIFIER | None

    @model_validator(mode="after")
    def source_shape(self) -> DecisionSource:
        if self.source_kind in {"claim", "unknown"} and self.source_id is None:
            raise ValueError("claim/unknown decision sources require source_id")
        if self.source_kind in {"terminal", "negative_assessment"} and self.source_id is not None:
            raise ValueError("terminal/negative decision sources do not have source_id")
        return self


class Decision(StrictModel):
    decision_id: IDENTIFIER
    decision_kind: Literal["entrypoint", "terminal", "unknown"]
    outcome: Literal["include", "exclude"]
    attribution: Literal["A", "B", "both", "newly_inspected"]
    sources: Annotated[tuple[DecisionSource, ...], Field(max_length=4 * MAX_ITEMS)]
    canonical_entrypoint: Entrypoint | None
    rationale: NONEMPTY
    evidence: Annotated[tuple[EvidenceEdge, ...], Field(max_length=MAX_ITEMS)]

    @model_validator(mode="after")
    def provenance_shape(self) -> Decision:
        source_keys = [
            f"{source.lane}:{source.source_kind}:{source.source_id or ''}"
            for source in self.sources
        ]
        _unique(source_keys, "decision source")
        lanes = {source.lane for source in self.sources}
        if self.attribution == "newly_inspected":
            if self.sources or not self.evidence:
                raise ValueError("new inspection requires fresh evidence and no review sources")
        elif not self.sources:
            raise ValueError("review-attributed decision requires typed review sources")
        elif self.attribution in {"A", "B"} and lanes != {self.attribution}:
            raise ValueError("decision attribution does not match source lanes")
        elif self.attribution == "both" and lanes != {"A", "B"}:
            raise ValueError("both attribution requires sources from both lanes")
        if self.outcome == "include" and self.decision_kind == "entrypoint":
            if self.canonical_entrypoint is None:
                raise ValueError("included entrypoint decision requires canonical_entrypoint")
        elif self.canonical_entrypoint is not None:
            raise ValueError(
                "canonical_entrypoint is allowed only for included entrypoint decisions"
            )
        if self.evidence:
            _validate_chain(self.evidence)
        return self


class ScopeMembership(StrictModel):
    """Versioned product-scope classification for one canonical decision."""

    scope_id: IDENTIFIER
    scope_version: Annotated[StrictInt, Field(gt=0, le=1_000_000)]
    product: NONEMPTY
    definition_sha256: SHA256
    decision_id: IDENTIFIER
    status: Literal["in_scope", "out_of_scope"]
    rationale: NONEMPTY


class AdjudicationArtifactV1(StrictModel):
    schema_version: Literal[1]
    artifact_type: Literal["ground_truth_adjudication"]
    corpus_id: NONEMPTY
    repository: Annotated[str, Field(pattern=r"^[^/\s]+/[^/\s]+$", max_length=300)]
    pr: Annotated[StrictInt, Field(gt=0)]
    snapshots: SnapshotBinding
    review_a_sha256: SHA256
    review_b_sha256: SHA256
    adjudicator: Actor
    run: RunProvenance
    version: Annotated[StrictInt, Field(gt=0, le=1_000_000)]
    supersedes_sha256: SHA256 | None
    terminal_status: Literal["positive", "negative_control", "unknown", "not_evaluable"]
    reason: NONEMPTY
    decisions: Annotated[tuple[Decision, ...], Field(min_length=1, max_length=2 * MAX_ITEMS)]
    scope_memberships: Annotated[tuple[ScopeMembership, ...], Field(max_length=4 * MAX_ITEMS)]
    unknowns: Annotated[tuple[UnknownFinding, ...], Field(max_length=MAX_ITEMS)]
    negative_assessment: NegativeAssessment | None

    @model_validator(mode="after")
    def terminal_shape(self) -> AdjudicationArtifactV1:
        decision_ids = [item.decision_id for item in self.decisions]
        _unique(decision_ids, "decision id")
        _unique([item.unknown_id for item in self.unknowns], "unknown id")
        membership_keys = [
            f"{item.decision_id}:{item.scope_id}:{item.scope_version}"
            for item in self.scope_memberships
        ]
        _unique(membership_keys, "scope membership")
        if any(item.decision_id not in decision_ids for item in self.scope_memberships):
            raise ValueError("scope membership references an unknown decision")
        included = [
            item
            for item in self.decisions
            if item.decision_kind == "entrypoint" and item.outcome == "include"
        ]
        included_ids = {item.decision_id for item in included}
        membership_ids = {item.decision_id for item in self.scope_memberships}
        if self.terminal_status == "positive" and not included:
            raise ValueError("positive adjudication requires an included entrypoint")
        if membership_ids != included_ids:
            raise ValueError(
                "every included entrypoint requires product-scope membership, "
                "and only those decisions may have it"
            )
        if self.terminal_status != "positive" and included:
            raise ValueError("non-positive adjudication cannot include entrypoints")
        if self.terminal_status == "negative_control":
            if self.negative_assessment is None:
                raise ValueError("negative-control adjudication requires negative assessment")
        elif self.negative_assessment is not None:
            raise ValueError("negative_assessment is allowed only for negative_control")
        if self.terminal_status in {"unknown", "not_evaluable"} and not self.unknowns:
            raise ValueError("unknown/not_evaluable adjudication requires structured unknown")
        return self


class PublicationReviewV1(StrictModel):
    schema_version: Literal[1]
    artifact_type: Literal["ground_truth_publication_review"]
    release_id: IDENTIFIER
    reviewer: Actor
    reviewed_at: datetime
    secrets_reviewed: StrictBool
    pii_reviewed: StrictBool
    security_findings_reviewed: StrictBool
    scanner_findings_disposition: NONEMPTY

    @field_validator("reviewed_at", mode="before")
    @classmethod
    def review_utc(cls, value: object) -> datetime:
        return _parse_utc(value, "reviewed_at")

    @model_validator(mode="after")
    def all_affirmed(self) -> PublicationReviewV1:
        if not (self.secrets_reviewed and self.pii_reviewed and self.security_findings_reviewed):
            raise ValueError("all publication attestations must be affirmative")
        return self


def _parse_utc(value: object, label: str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.endswith("Z"):
        try:
            parsed = datetime.fromisoformat(value[:-1] + "+00:00")
        except ValueError as exc:
            raise ValueError(f"invalid {label}") from exc
    else:
        raise ValueError(f"{label} must be a canonical UTC timestamp")
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError(f"{label} must be UTC")
    return parsed


def _unique(values: list[str], label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"duplicate {label}")


def _validate_chain(edges: tuple[EvidenceEdge, ...]) -> None:
    if [edge.ordinal for edge in edges] != list(range(len(edges))):
        raise ValueError("evidence edge ordinals must be dense from zero")
    for previous, current in pairwise(edges):
        if previous.to_location != current.from_location:
            raise ValueError("evidence chain is disconnected")


def canonical_json(value: object) -> bytes:
    """Encode canonical JSON with LF, without floats or non-finite values."""
    if isinstance(value, float):
        raise GroundTruthError("floats are not permitted in canonical ground truth")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise GroundTruthError("canonical JSON keys must be strings")
            canonical_json(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            canonical_json(item)
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode()


def parse_artifact(
    raw: bytes, model: type[StrictModel], *, limit: int = MAX_ARTIFACT_BYTES
) -> StrictModel:
    """Bound, duplicate-key parse, and strictly validate one exact artifact."""
    if len(raw) > limit:
        raise GroundTruthError("artifact exceeds byte limit")
    try:
        text = raw.decode("utf-8")
        _reject_excessive_nesting(text)
        payload = json.loads(text, object_pairs_hook=_unique_object)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        GroundTruthError,
        RecursionError,
        MemoryError,
    ) as exc:
        raise GroundTruthError(f"invalid artifact JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise GroundTruthError("artifact root must be an object")
    try:
        return model.model_validate(payload)
    except (ValueError, RecursionError, MemoryError) as exc:
        raise GroundTruthError(f"invalid artifact: {exc}") from exc


def artifact_sha256(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _reject_excessive_nesting(text: str, *, maximum: int = 100) -> None:
    """Reject pathological JSON depth before the recursive decoder/model sees it."""
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
        elif character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > maximum:
                raise GroundTruthError("artifact JSON nesting exceeds limit")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                break


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise GroundTruthError(f"duplicate JSON key: {key}")
        result[key] = value
    return result
