"""Deterministic dry-run audit models for exact effect contracts."""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from fastapi_endpoint_detector.models.effect_contract import (
    CallResolutionStatus,
    InvocationKind,
)


def _semantic_hash(payload: object) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


class EffectContractAuditError(ValueError):
    """Raised when a complete, deterministic contract audit cannot be produced."""


class _StrictAuditModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AuditCallStatus(str, Enum):
    """Dry-run classification of one physical source call."""

    MATCHED = "matched"
    UNMATCHED = "unmatched"
    AMBIGUOUS = "ambiguous"
    UNRESOLVED = "unresolved"


class AuditLimitation(_StrictAuditModel):
    """Normalized source-backed limitation on endpoint inventory."""

    file_path: str = Field(min_length=1)
    line: int = Field(ge=1)
    reason: str = Field(min_length=1)


class AuditEndpoint(_StrictAuditModel):
    """Handler-aware endpoint identity attached to a reachable call."""

    id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    methods: tuple[str, ...] = Field(min_length=1)
    path: str
    handler_module: str
    handler_name: str
    handler_file: str = Field(min_length=1)
    handler_line: int = Field(ge=1)
    discovery_status: Literal["established", "conditional"]
    conditions: tuple[AuditLimitation, ...] = ()

    @model_validator(mode="after")
    def validate_identity(self) -> AuditEndpoint:
        if tuple(sorted(set(self.methods))) != self.methods:
            raise ValueError("endpoint methods must be sorted and unique")
        if (self.discovery_status == "conditional") != bool(self.conditions):
            raise ValueError("endpoint discovery status and conditions are inconsistent")
        identity = {
            "methods": self.methods,
            "path": self.path,
            "handler_module": self.handler_module,
            "handler_name": self.handler_name,
            "handler_file": self.handler_file,
            "handler_line": self.handler_line,
            "discovery_status": self.discovery_status,
            "conditions": [item.model_dump(mode="json") for item in self.conditions],
        }
        if self.id != _semantic_hash(identity):
            raise ValueError("endpoint id does not match endpoint identity")
        return self


class EffectContractAuditOccurrence(_StrictAuditModel):
    """One globally deduplicated physical call reachable from audited endpoints."""

    id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    file_path: str = Field(min_length=1)
    line: int = Field(ge=1)
    column: int = Field(ge=0)
    end_line: int | None = Field(default=None, ge=1)
    end_column: int | None = Field(default=None, ge=0)
    source_spelling: str = Field(min_length=1)
    resolver_status: CallResolutionStatus
    audit_status: AuditCallStatus
    canonical_symbol: str | None = None
    invocation: InvocationKind | None = None
    resolver: str = Field(min_length=1)
    resolver_version: str = Field(min_length=1)
    receiver_candidates: tuple[str, ...] = ()
    reason_code: str | None = None
    contract_id: str | None = None
    contract_hash: str | None = None
    endpoints: tuple[AuditEndpoint, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_classification(  # noqa: PLR0912
        self,
    ) -> EffectContractAuditOccurrence:
        expected_id = _semantic_hash(
            {
                "file_path": self.file_path,
                "line": self.line,
                "column": self.column,
                "end_line": self.end_line,
                "end_column": self.end_column,
            }
        )
        if self.id != expected_id:
            raise ValueError("occurrence id does not match physical source identity")
        endpoint_ids = [item.id for item in self.endpoints]
        if endpoint_ids != sorted(set(endpoint_ids)):
            raise ValueError("occurrence endpoints must have sorted unique identities")
        if self.receiver_candidates != tuple(sorted(set(self.receiver_candidates))):
            raise ValueError("receiver candidates must be sorted and unique")
        paired = (self.contract_id is None) == (self.contract_hash is None)
        if not paired:
            raise ValueError("contract id and hash must be provided together")
        if self.resolver_status == CallResolutionStatus.EXACT:
            if self.canonical_symbol is None or self.invocation is None:
                raise ValueError("exact audit calls require canonical symbol and invocation")
        elif self.canonical_symbol is not None or self.invocation is not None:
            raise ValueError("non-exact audit calls forbid canonical symbol and invocation")
        if self.audit_status == AuditCallStatus.MATCHED:
            if self.resolver_status != CallResolutionStatus.EXACT or self.contract_id is None:
                raise ValueError("matched calls require an exact resolver result and contract")
        elif self.contract_id is not None:
            raise ValueError("only matched calls may reference a contract")
        if (
            self.audit_status == AuditCallStatus.UNMATCHED
            and self.resolver_status != CallResolutionStatus.EXACT
        ):
            raise ValueError("unmatched calls require an exact resolver result")
        if (
            self.audit_status == AuditCallStatus.AMBIGUOUS
            and self.resolver_status != CallResolutionStatus.AMBIGUOUS
        ):
            raise ValueError("ambiguous audit calls require an ambiguous resolver result")
        if (
            self.audit_status == AuditCallStatus.UNRESOLVED
            and self.resolver_status != CallResolutionStatus.UNRESOLVED
        ):
            raise ValueError("unresolved audit calls require an unresolved resolver result")
        return self


class EffectContractCoverage(_StrictAuditModel):
    """Reachable physical-call coverage for one configured contract."""

    contract_id: str
    contract_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    symbol: str
    invocation: InvocationKind
    matched: bool
    occurrence_ids: tuple[str, ...] = ()
    endpoint_ids: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_coverage(self) -> EffectContractCoverage:
        if self.matched != bool(self.occurrence_ids):
            raise ValueError("contract matched status must agree with occurrence ids")
        return self


class EffectContractAuditSummary(_StrictAuditModel):
    """Exhaustive counts over globally deduplicated physical calls."""

    contracts: int = Field(ge=0)
    matched_contracts: int = Field(ge=0)
    unmatched_contracts: int = Field(ge=0)
    physical_occurrences: int = Field(ge=0)
    matched_calls: int = Field(ge=0)
    unmatched_calls: int = Field(ge=0)
    ambiguous_calls: int = Field(ge=0)
    unresolved_calls: int = Field(ge=0)
    endpoint_links: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_totals(self) -> EffectContractAuditSummary:
        if self.matched_contracts + self.unmatched_contracts != self.contracts:
            raise ValueError("contract coverage totals are inconsistent")
        if (
            self.matched_calls + self.unmatched_calls + self.ambiguous_calls + self.unresolved_calls
            != self.physical_occurrences
        ):
            raise ValueError("call classification totals are inconsistent")
        return self


class EffectContractAuditScope(_StrictAuditModel):
    """Completeness and traversal boundaries of the endpoint-reachable corpus."""

    kind: Literal["endpoint_reachable_calls"] = "endpoint_reachable_calls"
    source_root: Literal["."] = "."
    inventory_status: Literal["established", "conditional", "unavailable"]
    inventory_limitations: tuple[AuditLimitation, ...] = ()
    endpoint_inventory: tuple[AuditEndpoint, ...] = ()
    endpoints: int = Field(ge=0)
    established_endpoints: int = Field(ge=0)
    conditional_endpoints: int = Field(ge=0)
    track_transitive: bool
    max_depth: int = Field(ge=1)
    cache_enabled: bool
    package_applicability: Literal["not_evaluated"] = "not_evaluated"

    @model_validator(mode="after")
    def validate_endpoint_totals(self) -> EffectContractAuditScope:
        if len(self.endpoint_inventory) != self.endpoints:
            raise ValueError("endpoint inventory count is inconsistent")
        endpoint_ids = [item.id for item in self.endpoint_inventory]
        if endpoint_ids != sorted(set(endpoint_ids)):
            raise ValueError("endpoint inventory must have sorted unique identities")
        if self.established_endpoints != sum(
            item.discovery_status == "established" for item in self.endpoint_inventory
        ) or self.conditional_endpoints != sum(
            item.discovery_status == "conditional" for item in self.endpoint_inventory
        ):
            raise ValueError("endpoint strength totals are inconsistent")
        if self.established_endpoints + self.conditional_endpoints != self.endpoints:
            raise ValueError("endpoint discovery totals are inconsistent")
        if self.inventory_status == "established" and self.inventory_limitations:
            raise ValueError("established audit inventory forbids limitations")
        if self.inventory_status == "established" and self.conditional_endpoints:
            raise ValueError("established audit inventory forbids conditional endpoints")
        if self.inventory_status != "established" and not self.inventory_limitations:
            raise ValueError("incomplete audit inventory requires limitations")
        return self


class EffectContractAuditProvenance(_StrictAuditModel):
    """Contract and resolver provenance for a reproducible audit."""

    matcher_schema_version: Literal[1] = 1
    matcher: Literal["exact_symbol_invocation_v1"] = "exact_symbol_invocation_v1"
    contract_source_path: str = Field(min_length=1)
    raw_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    config_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    preset_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    contract_hashes: dict[str, str]
    resolver_versions: tuple[str, ...] = Field(min_length=1)
    occurrence_corpus_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    audit_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class EffectContractAudit(_StrictAuditModel):
    """Complete dry-run report, isolated from impact candidates and confidence."""

    schema_version: Literal[1] = 1
    matching_status: Literal["complete"] = "complete"
    scope: EffectContractAuditScope
    provenance: EffectContractAuditProvenance
    summary: EffectContractAuditSummary
    contract_coverage: tuple[EffectContractCoverage, ...]
    occurrences: tuple[EffectContractAuditOccurrence, ...]

    @model_validator(mode="after")
    def validate_report_integrity(self) -> EffectContractAudit:  # noqa: PLR0912
        if self.scope.inventory_status != "established":
            raise ValueError("complete audits require an established endpoint inventory")
        occurrence_by_id = {item.id: item for item in self.occurrences}
        if len(occurrence_by_id) != len(self.occurrences):
            raise ValueError("audit occurrence ids must be unique")
        coverage_by_id = {item.contract_id: item for item in self.contract_coverage}
        if len(coverage_by_id) != len(self.contract_coverage):
            raise ValueError("contract coverage ids must be unique")
        expected_summary = {
            "contracts": len(self.contract_coverage),
            "matched_contracts": sum(item.matched for item in self.contract_coverage),
            "unmatched_contracts": sum(not item.matched for item in self.contract_coverage),
            "physical_occurrences": len(self.occurrences),
            "matched_calls": sum(
                item.audit_status == AuditCallStatus.MATCHED for item in self.occurrences
            ),
            "unmatched_calls": sum(
                item.audit_status == AuditCallStatus.UNMATCHED for item in self.occurrences
            ),
            "ambiguous_calls": sum(
                item.audit_status == AuditCallStatus.AMBIGUOUS for item in self.occurrences
            ),
            "unresolved_calls": sum(
                item.audit_status == AuditCallStatus.UNRESOLVED for item in self.occurrences
            ),
            "endpoint_links": sum(len(item.endpoints) for item in self.occurrences),
        }
        if self.summary.model_dump() != expected_summary:
            raise ValueError("audit summary does not match report contents")
        occurrence_ids_by_contract: dict[str, list[str]] = {
            item.contract_id: [] for item in self.contract_coverage
        }
        endpoint_ids_by_contract: dict[str, set[str]] = {
            item.contract_id: set() for item in self.contract_coverage
        }
        for occurrence in self.occurrences:
            if occurrence.contract_id is None:
                continue
            coverage = coverage_by_id.get(occurrence.contract_id)
            if coverage is None:
                raise ValueError("matched occurrence references unknown contract coverage")
            if occurrence.contract_hash != coverage.contract_hash:
                raise ValueError("matched occurrence contract hash is inconsistent")
            occurrence_ids_by_contract[occurrence.contract_id].append(occurrence.id)
            endpoint_ids_by_contract[occurrence.contract_id].update(
                endpoint.id for endpoint in occurrence.endpoints
            )
        for coverage in self.contract_coverage:
            if coverage.occurrence_ids != tuple(occurrence_ids_by_contract[coverage.contract_id]):
                raise ValueError("contract coverage occurrence ids are inconsistent")
            if coverage.endpoint_ids != tuple(
                sorted(endpoint_ids_by_contract[coverage.contract_id])
            ):
                raise ValueError("contract coverage endpoint ids are inconsistent")
            if self.provenance.contract_hashes.get(coverage.contract_id) != coverage.contract_hash:
                raise ValueError("contract coverage hash is inconsistent with provenance")
        if set(self.provenance.contract_hashes) != set(coverage_by_id):
            raise ValueError("contract provenance keys do not match contract coverage")
        if self.provenance.resolver_versions != tuple(
            sorted(set(self.provenance.resolver_versions))
        ):
            raise ValueError("resolver provenance must be sorted and unique")
        declared_resolvers = set(self.provenance.resolver_versions)
        if any(
            f"{item.resolver}@{item.resolver_version}" not in declared_resolvers
            for item in self.occurrences
        ):
            raise ValueError("occurrence resolver is absent from audit provenance")
        inventory_by_id = {item.id: item for item in self.scope.endpoint_inventory}
        for occurrence in self.occurrences:
            if any(
                inventory_by_id.get(endpoint.id) != endpoint for endpoint in occurrence.endpoints
            ):
                raise ValueError("occurrence endpoint is absent from scope inventory")
        corpus_payload = {
            "endpoints": [item.model_dump(mode="json") for item in self.scope.endpoint_inventory],
            "occurrences": [
                {
                    "file_path": item.file_path,
                    "line": item.line,
                    "column": item.column,
                    "end_line": item.end_line,
                    "end_column": item.end_column,
                    "source_spelling": item.source_spelling,
                    "resolver_status": item.resolver_status.value,
                    "canonical_symbol": item.canonical_symbol,
                    "invocation": (item.invocation.value if item.invocation is not None else None),
                    "resolver": item.resolver,
                    "resolver_version": item.resolver_version,
                    "receiver_candidates": list(item.receiver_candidates),
                    "reason_code": item.reason_code,
                    "id": item.id,
                    "endpoint_ids": [endpoint.id for endpoint in item.endpoints],
                }
                for item in self.occurrences
            ],
        }
        if self.provenance.occurrence_corpus_hash != _semantic_hash(corpus_payload):
            raise ValueError("occurrence corpus hash does not match report contents")
        audit_payload = {
            "matcher_schema_version": self.provenance.matcher_schema_version,
            "contract_source_path": self.provenance.contract_source_path,
            "raw_hash": self.provenance.raw_hash,
            "config_hash": self.provenance.config_hash,
            "preset_hash": self.provenance.preset_hash,
            "contract_hashes": self.provenance.contract_hashes,
            "occurrence_corpus_hash": self.provenance.occurrence_corpus_hash,
            "resolver_versions": self.provenance.resolver_versions,
            "scope": self.scope.model_dump(mode="json"),
            "summary": self.summary.model_dump(mode="json"),
            "contract_coverage": [item.model_dump(mode="json") for item in self.contract_coverage],
            "call_classification": [
                {
                    "id": item.id,
                    "audit_status": item.audit_status.value,
                    "contract_id": item.contract_id,
                    "contract_hash": item.contract_hash,
                }
                for item in self.occurrences
            ],
        }
        if self.provenance.audit_hash != _semantic_hash(audit_payload):
            raise ValueError("audit hash does not match report contents")
        return self
