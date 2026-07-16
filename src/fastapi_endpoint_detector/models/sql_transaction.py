"""Conservative endpoint-reachable SQL transaction boundary evidence."""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from fastapi_endpoint_detector.models.effect_contract import EffectTiming, TransactionScope


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _semantic_hash(payload: object) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]


class SQLTransactionOutcome(str, Enum):
    """Strongest outcome justified by endpoint-reachable boundary evidence."""

    PENDING_PERSISTENCE = "pending_persistence"
    COMMIT_REACHABLE = "commit_reachable"
    ROLLBACK_REACHABLE = "rollback_reachable"
    OUTCOME_UNRESOLVED = "outcome_unresolved"


class SQLTransactionBeginScopeEvidence(_StrictModel):
    """Declared transaction/savepoint scope for one exact reachable begin occurrence."""

    schema_version: Literal[1] = 1
    occurrence_id: Digest
    scope: TransactionScope
    timing: EffectTiming


class SQLTransactionEndpointEvidence(_StrictModel):
    """SQL staging and boundaries reachable from one endpoint, without path claims."""

    schema_version: Literal[2] = 2
    endpoint_id: Digest
    stage_occurrence_ids: tuple[Digest, ...] = Field(min_length=1)
    flush_occurrence_ids: tuple[Digest, ...] = ()
    begin_occurrence_ids: tuple[Digest, ...] = ()
    begin_scopes: tuple[SQLTransactionBeginScopeEvidence, ...] = ()
    commit_occurrence_ids: tuple[Digest, ...] = ()
    rollback_occurrence_ids: tuple[Digest, ...] = ()
    outcome: SQLTransactionOutcome
    persistence_status: Literal["not_established"] = "not_established"
    limitations: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_evidence(self) -> SQLTransactionEndpointEvidence:
        collections = (
            self.stage_occurrence_ids,
            self.flush_occurrence_ids,
            self.begin_occurrence_ids,
            self.commit_occurrence_ids,
            self.rollback_occurrence_ids,
        )
        if any(items != tuple(sorted(set(items))) for items in collections):
            raise ValueError("transaction occurrence ids must be sorted and unique")
        all_ids = [item for items in collections for item in items]
        if len(all_ids) != len(set(all_ids)):
            raise ValueError("transaction occurrence roles must be disjoint")
        scoped_ids = tuple(item.occurrence_id for item in self.begin_scopes)
        if scoped_ids != self.begin_occurrence_ids:
            raise ValueError("every begin occurrence requires one sorted scope record")
        if any(
            item.scope != TransactionScope.NONE and item.timing != EffectTiming.CONTEXT_ENTER
            for item in self.begin_scopes
        ):
            raise ValueError("classified begin scopes require context_enter timing")
        expected = (
            SQLTransactionOutcome.OUTCOME_UNRESOLVED
            if self.commit_occurrence_ids and self.rollback_occurrence_ids
            else SQLTransactionOutcome.COMMIT_REACHABLE
            if self.commit_occurrence_ids
            else SQLTransactionOutcome.ROLLBACK_REACHABLE
            if self.rollback_occurrence_ids
            else SQLTransactionOutcome.PENDING_PERSISTENCE
        )
        if self.outcome != expected:
            raise ValueError("transaction outcome does not match reachable boundaries")
        if any(not item.strip() for item in self.limitations):
            raise ValueError("transaction limitations must not be blank")
        return self


class SQLTransactionSummary(_StrictModel):
    endpoints_with_staging: int = Field(ge=0)
    transaction_begins: int = Field(ge=0)
    savepoint_begins: int = Field(ge=0)
    unclassified_begins: int = Field(ge=0)
    pending_persistence: int = Field(ge=0)
    commit_reachable: int = Field(ge=0)
    rollback_reachable: int = Field(ge=0)
    outcome_unresolved: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_counts(self) -> SQLTransactionSummary:
        if (
            self.pending_persistence
            + self.commit_reachable
            + self.rollback_reachable
            + self.outcome_unresolved
            != self.endpoints_with_staging
        ):
            raise ValueError("transaction summary counts are inconsistent")
        return self


class SQLTransactionReport(_StrictModel):
    """Versioned report-only SQL staging/transaction evidence."""

    schema_version: Literal[2] = 2
    status: Literal["diagnostic_only"] = "diagnostic_only"
    effect_audit_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    endpoint_evidence: tuple[SQLTransactionEndpointEvidence, ...]
    summary: SQLTransactionSummary
    report_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    def report_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"report_hash"})

    @model_validator(mode="after")
    def validate_report(self) -> SQLTransactionReport:
        endpoint_ids = [item.endpoint_id for item in self.endpoint_evidence]
        if endpoint_ids != sorted(set(endpoint_ids)):
            raise ValueError("transaction endpoint evidence must be sorted and unique")
        begin_scopes = [
            scope for evidence in self.endpoint_evidence for scope in evidence.begin_scopes
        ]
        expected = SQLTransactionSummary(
            endpoints_with_staging=len(self.endpoint_evidence),
            transaction_begins=sum(
                item.scope == TransactionScope.TRANSACTION for item in begin_scopes
            ),
            savepoint_begins=sum(item.scope == TransactionScope.SAVEPOINT for item in begin_scopes),
            unclassified_begins=sum(item.scope == TransactionScope.NONE for item in begin_scopes),
            pending_persistence=sum(
                item.outcome == SQLTransactionOutcome.PENDING_PERSISTENCE
                for item in self.endpoint_evidence
            ),
            commit_reachable=sum(
                item.outcome == SQLTransactionOutcome.COMMIT_REACHABLE
                for item in self.endpoint_evidence
            ),
            rollback_reachable=sum(
                item.outcome == SQLTransactionOutcome.ROLLBACK_REACHABLE
                for item in self.endpoint_evidence
            ),
            outcome_unresolved=sum(
                item.outcome == SQLTransactionOutcome.OUTCOME_UNRESOLVED
                for item in self.endpoint_evidence
            ),
        )
        if self.summary != expected:
            raise ValueError("transaction summary does not match endpoint evidence")
        if self.report_hash != _semantic_hash(self.report_payload()):
            raise ValueError("transaction report hash does not match report contents")
        return self


def build_sql_transaction_report(
    effect_audit_hash: str,
    endpoint_evidence: tuple[SQLTransactionEndpointEvidence, ...],
) -> SQLTransactionReport:
    """Construct a validated content-addressed transaction report."""
    sorted_evidence = tuple(sorted(endpoint_evidence, key=lambda item: item.endpoint_id))
    begin_scopes = [scope for evidence in sorted_evidence for scope in evidence.begin_scopes]
    summary = SQLTransactionSummary(
        endpoints_with_staging=len(sorted_evidence),
        transaction_begins=sum(item.scope == TransactionScope.TRANSACTION for item in begin_scopes),
        savepoint_begins=sum(item.scope == TransactionScope.SAVEPOINT for item in begin_scopes),
        unclassified_begins=sum(item.scope == TransactionScope.NONE for item in begin_scopes),
        pending_persistence=sum(
            item.outcome == SQLTransactionOutcome.PENDING_PERSISTENCE for item in sorted_evidence
        ),
        commit_reachable=sum(
            item.outcome == SQLTransactionOutcome.COMMIT_REACHABLE for item in sorted_evidence
        ),
        rollback_reachable=sum(
            item.outcome == SQLTransactionOutcome.ROLLBACK_REACHABLE for item in sorted_evidence
        ),
        outcome_unresolved=sum(
            item.outcome == SQLTransactionOutcome.OUTCOME_UNRESOLVED for item in sorted_evidence
        ),
    )
    provisional = SQLTransactionReport.model_construct(
        effect_audit_hash=effect_audit_hash,
        endpoint_evidence=sorted_evidence,
        summary=summary,
        report_hash=f"sha256:{'0' * 64}",
    )
    return SQLTransactionReport(
        effect_audit_hash=effect_audit_hash,
        endpoint_evidence=sorted_evidence,
        summary=summary,
        report_hash=_semantic_hash(provisional.report_payload()),
    )


class SQLTransactionPathError(ValueError):
    """Raised when bounded ordered-path analysis cannot complete safely."""


class SQLTransactionOrderedPath(_StrictModel):
    """One same-scope, same-receiver straight-line stage-to-boundary relation."""

    schema_version: Literal[2] = 2
    id: Digest
    endpoint_id: Digest
    file_path: str = Field(min_length=1)
    function_name: str = Field(min_length=1)
    receiver_hash: Digest
    begin_occurrence_id: Digest | None = None
    begin_scope: TransactionScope | None = None
    stage_occurrence_id: Digest
    boundary_occurrence_id: Digest
    boundary: Literal["commit", "rollback"]
    ordering: Literal["same_scope_straight_line"] = "same_scope_straight_line"
    status: Literal["ordered_boundary_reachable"] = "ordered_boundary_reachable"
    persistence_status: Literal["not_established"] = "not_established"
    limitations: tuple[str, ...] = Field(min_length=1)

    def identity_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"id", "limitations"})

    @model_validator(mode="after")
    def validate_path(self) -> SQLTransactionOrderedPath:
        role_ids = tuple(
            item
            for item in (
                self.begin_occurrence_id,
                self.stage_occurrence_id,
                self.boundary_occurrence_id,
            )
            if item is not None
        )
        if len(role_ids) != len(set(role_ids)):
            raise ValueError("ordered transaction path occurrence roles must be disjoint")
        if (self.begin_occurrence_id is None) != (self.begin_scope is None):
            raise ValueError("ordered begin occurrence and scope must be provided together")
        if not self.file_path.strip() or not self.function_name.strip():
            raise ValueError("ordered transaction source identity must not be blank")
        if any(not item.strip() for item in self.limitations):
            raise ValueError("ordered transaction limitations must not be blank")
        if self.id != _semantic_hash(self.identity_payload()):
            raise ValueError("ordered transaction path id does not match path identity")
        return self


class SQLTransactionPathDiagnostic(_StrictModel):
    endpoint_id: Digest
    stage_occurrence_id: Digest
    boundary_occurrence_id: Digest
    reason_code: Literal[
        "different_source_scope",
        "source_call_unavailable",
        "receiver_unavailable",
        "receiver_mismatch",
        "receiver_reassigned",
        "control_flow_unavailable",
        "boundary_precedes_stage",
    ]


class SQLTransactionPathSummary(_StrictModel):
    ordered_paths: int = Field(ge=0)
    ordered_commits: int = Field(ge=0)
    ordered_rollbacks: int = Field(ge=0)
    unresolved_pairs: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_counts(self) -> SQLTransactionPathSummary:
        if self.ordered_commits + self.ordered_rollbacks != self.ordered_paths:
            raise ValueError("ordered SQL path counts are inconsistent")
        return self


class SQLTransactionPathReport(_StrictModel):
    """Content-addressed bounded straight-line ordering evidence."""

    schema_version: Literal[2] = 2
    status: Literal["diagnostic_only"] = "diagnostic_only"
    effect_audit_hash: Digest
    transaction_report_hash: Digest
    max_pairs: int = Field(ge=1, le=10_000)
    ordered_paths: tuple[SQLTransactionOrderedPath, ...]
    diagnostics: tuple[SQLTransactionPathDiagnostic, ...]
    summary: SQLTransactionPathSummary
    report_hash: Digest

    def report_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"report_hash"})

    @model_validator(mode="after")
    def validate_report(self) -> SQLTransactionPathReport:
        path_ids = [item.id for item in self.ordered_paths]
        if path_ids != sorted(set(path_ids)):
            raise ValueError("ordered SQL paths must be sorted and unique")
        diagnostic_keys = [
            (
                item.endpoint_id,
                item.stage_occurrence_id,
                item.boundary_occurrence_id,
            )
            for item in self.diagnostics
        ]
        if diagnostic_keys != sorted(set(diagnostic_keys)):
            raise ValueError("SQL path diagnostics must be sorted and unique")
        expected = SQLTransactionPathSummary(
            ordered_paths=len(self.ordered_paths),
            ordered_commits=sum(item.boundary == "commit" for item in self.ordered_paths),
            ordered_rollbacks=sum(item.boundary == "rollback" for item in self.ordered_paths),
            unresolved_pairs=len(self.diagnostics),
        )
        if self.summary != expected:
            raise ValueError("SQL path summary does not match report contents")
        if len(self.ordered_paths) + len(self.diagnostics) > self.max_pairs:
            raise ValueError("SQL path report exceeds its atomic pair limit")
        if self.report_hash != _semantic_hash(self.report_payload()):
            raise ValueError("SQL path report hash does not match report contents")
        return self


def build_sql_transaction_ordered_path(
    *,
    endpoint_id: str,
    file_path: str,
    function_name: str,
    receiver_hash: str,
    stage_occurrence_id: str,
    boundary_occurrence_id: str,
    boundary: Literal["commit", "rollback"],
    begin_occurrence_id: str | None = None,
    begin_scope: TransactionScope | None = None,
    limitations: tuple[str, ...],
) -> SQLTransactionOrderedPath:
    """Construct one content-addressed ordered-path record."""
    provisional = SQLTransactionOrderedPath.model_construct(
        id=f"sha256:{'0' * 64}",
        endpoint_id=endpoint_id,
        file_path=file_path,
        function_name=function_name,
        receiver_hash=receiver_hash,
        begin_occurrence_id=begin_occurrence_id,
        begin_scope=begin_scope,
        stage_occurrence_id=stage_occurrence_id,
        boundary_occurrence_id=boundary_occurrence_id,
        boundary=boundary,
        limitations=limitations,
    )
    return SQLTransactionOrderedPath(
        id=_semantic_hash(provisional.identity_payload()),
        endpoint_id=endpoint_id,
        file_path=file_path,
        function_name=function_name,
        receiver_hash=receiver_hash,
        begin_occurrence_id=begin_occurrence_id,
        begin_scope=begin_scope,
        stage_occurrence_id=stage_occurrence_id,
        boundary_occurrence_id=boundary_occurrence_id,
        boundary=boundary,
        limitations=limitations,
    )


def build_sql_transaction_path_report(
    effect_audit_hash: str,
    transaction_report_hash: str,
    ordered_paths: tuple[SQLTransactionOrderedPath, ...],
    diagnostics: tuple[SQLTransactionPathDiagnostic, ...],
    *,
    max_pairs: int,
) -> SQLTransactionPathReport:
    """Construct one validated deterministic path report."""
    sorted_paths = tuple(sorted(ordered_paths, key=lambda item: item.id))
    sorted_diagnostics = tuple(
        sorted(
            diagnostics,
            key=lambda item: (
                item.endpoint_id,
                item.stage_occurrence_id,
                item.boundary_occurrence_id,
            ),
        )
    )
    summary = SQLTransactionPathSummary(
        ordered_paths=len(sorted_paths),
        ordered_commits=sum(item.boundary == "commit" for item in sorted_paths),
        ordered_rollbacks=sum(item.boundary == "rollback" for item in sorted_paths),
        unresolved_pairs=len(sorted_diagnostics),
    )
    provisional = SQLTransactionPathReport.model_construct(
        effect_audit_hash=effect_audit_hash,
        transaction_report_hash=transaction_report_hash,
        max_pairs=max_pairs,
        ordered_paths=sorted_paths,
        diagnostics=sorted_diagnostics,
        summary=summary,
        report_hash=f"sha256:{'0' * 64}",
    )
    return SQLTransactionPathReport(
        effect_audit_hash=effect_audit_hash,
        transaction_report_hash=transaction_report_hash,
        max_pairs=max_pairs,
        ordered_paths=sorted_paths,
        diagnostics=sorted_diagnostics,
        summary=summary,
        report_hash=_semantic_hash(provisional.report_payload()),
    )
