"""Conservative endpoint-reachable SQL transaction boundary evidence."""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


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


class SQLTransactionEndpointEvidence(_StrictModel):
    """SQL staging and boundaries reachable from one endpoint, without path claims."""

    schema_version: Literal[1] = 1
    endpoint_id: Digest
    stage_occurrence_ids: tuple[Digest, ...] = Field(min_length=1)
    flush_occurrence_ids: tuple[Digest, ...] = ()
    begin_occurrence_ids: tuple[Digest, ...] = ()
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

    schema_version: Literal[1] = 1
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
        expected = SQLTransactionSummary(
            endpoints_with_staging=len(self.endpoint_evidence),
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
    summary = SQLTransactionSummary(
        endpoints_with_staging=len(sorted_evidence),
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
