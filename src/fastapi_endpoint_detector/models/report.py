"""
Report data models.

Models representing analysis reports and results.
"""

import hashlib
import json
import re
from datetime import datetime
from enum import Enum
from pathlib import PurePosixPath
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from fastapi_endpoint_detector.models.effect_contract import (
    EffectContract,
    FiniteValueStatus,
    ResourceIdentityEvidence,
)
from fastapi_endpoint_detector.models.effect_contract_audit import EffectContractAudit
from fastapi_endpoint_detector.models.endpoint import (
    Endpoint,
    EndpointDiscoveryCondition,
    InventoryStatus,
)
from fastapi_endpoint_detector.models.resource_coupling import (
    ResourceCouplingCandidateEvidence,
    ResourceCouplingGraph,
)
from fastapi_endpoint_detector.models.sql_transaction import (
    SQLTransactionPathReport,
    SQLTransactionReport,
)


def _contract_hash(contract: EffectContract) -> str:
    payload = json.dumps(
        contract.model_dump(mode="json", exclude_none=True),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


class ConfidenceLevel(str, Enum):
    """Legacy prioritization level for endpoint impact."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class EvidenceProducer(str, Enum):
    """Analyzer that produced an evidence record."""

    DIRECT = "direct"
    STRUCTURAL = "structural"
    MYPY = "mypy"
    SCIP = "scip"
    DATA_FLOW = "data_flow"
    EFFECT_CONTRACT = "effect_contract"


class EvidenceStatus(str, Enum):
    """How strongly source establishes the described effect."""

    ESTABLISHED = "established"
    CONDITIONAL = "conditional"
    REACHABILITY_ONLY = "reachability_only"
    UNRESOLVED = "unresolved"


class ChangeEffectKind(str, Enum):
    """Semantic shape of a source change."""

    HANDLER_IMPLEMENTATION = "handler_implementation"
    ROUTE_ASSEMBLY = "route_assembly"
    DEFENSIVE_COPY_ADDED = "defensive_copy_added"
    ARGUMENT_MUTATION_ISOLATED = "argument_mutation_isolated"
    RETURN_VALUE_CHANGED = "return_value_changed"
    CONTROL_FLOW_CHANGED = "control_flow_changed"
    PERSISTENCE_CHANGED = "persistence_changed"
    OUTBOUND_IO_CHANGED = "outbound_io_changed"
    EVENT_CHANGED = "event_changed"
    LOGGING_CHANGED = "logging_changed"
    UNKNOWN = "unknown"


class DataObservationKind(str, Enum):
    """How changed data is observed after a call."""

    RETURNED = "returned"
    READ = "read"
    BRANCH = "branch"
    LOGGED = "logged"
    PERSISTED = "persisted"
    SENT_OUTBOUND = "sent_outbound"
    EMITTED = "emitted"
    FORWARDED = "forwarded"
    DYNAMIC_ESCAPE = "dynamic_escape"
    NOT_OBSERVED_AFTER_CALL = "not_observed_after_call"
    UNKNOWN = "unknown"


class ImpactChannel(str, Enum):
    """Externally meaningful channel, if one is established."""

    HTTP_RESPONSE = "http_response"
    PERSISTENT_STATE = "persistent_state"
    OUTBOUND_REQUEST = "outbound_request"
    EVENT_OR_MESSAGE = "event_or_message"
    LOG_OR_TELEMETRY = "log_or_telemetry"
    CONTROL_FLOW = "control_flow"
    IN_MEMORY_ALIASING = "in_memory_aliasing"
    DYNAMIC_EXTENSION = "dynamic_extension"
    UNKNOWN = "unknown"


class EffectDisposition(str, Enum):
    """Interpretation of an effect without discarding reachability."""

    OBSERVABLE_BEHAVIOR = "observable_behavior"
    OPERATIONAL_ONLY = "operational_only"
    INTERNAL_EFFECT = "internal_effect"
    NOT_OBSERVED_BY_CALLER = "not_observed_by_caller"
    DYNAMIC_OR_UNRESOLVED = "dynamic_or_unresolved"
    REACHABILITY_ONLY = "reachability_only"


class CodeReference(BaseModel):
    """Stable source reference used by structured evidence."""

    file_path: str
    line_number: int = Field(ge=1)
    end_line_number: int | None = None
    symbol: str | None = None

    class Config:
        frozen = True


class EffectEvidence(BaseModel):
    """Auditable effect and data-observation evidence for one impact path."""

    schema_version: int = 1
    producer: EvidenceProducer
    status: EvidenceStatus
    effect: ChangeEffectKind
    observations: list[DataObservationKind] = Field(default_factory=list)
    channel: ImpactChannel = ImpactChannel.UNKNOWN
    disposition: EffectDisposition
    summary: str
    subject: str | None = None
    changed_location: CodeReference
    observation_location: CodeReference | None = None
    conditions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    class Config:
        frozen = True


class ContractEffectEvidence(BaseModel):
    """Declared contract semantics at an exact endpoint-reachable call occurrence."""

    schema_version: Literal[1] = 1
    producer: Literal[EvidenceProducer.EFFECT_CONTRACT] = EvidenceProducer.EFFECT_CONTRACT
    status: Literal["declared_reachable"] = "declared_reachable"
    contract: EffectContract
    contract_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    config_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    preset_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    raw_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    audit_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    occurrence_corpus_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    contract_source_path: str
    occurrence_id: str
    endpoint_audit_id: str
    call_location: CodeReference
    resolver: str
    resolver_version: str
    matcher: str
    package_applicability: Literal["not_evaluated"] = "not_evaluated"
    resource_identity_status: FiniteValueStatus = FiniteValueStatus.UNAVAILABLE
    resource_identity: ResourceIdentityEvidence = Field(
        default_factory=lambda: ResourceIdentityEvidence(
            status=FiniteValueStatus.UNAVAILABLE,
            reason_code="resource_analysis_unavailable",
        )
    )
    change_to_call_flow: Literal["not_established"] = "not_established"
    limitations: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_resource_identity(self) -> "ContractEffectEvidence":
        if self.resource_identity_status != self.resource_identity.status:
            raise ValueError("resource identity status and evidence are inconsistent")
        return self

    class Config:
        frozen = True


class CallStackFrame(BaseModel):
    """A single frame in a call stack trace."""

    file_path: str = Field(description="Absolute path to the file")
    line_number: int = Field(description="Line number in the file")
    function_name: str = Field(description="Name of the function/method")
    code_context: str | None = Field(default=None, description="The line of code at this location")
    caller_file_path: str | None = Field(
        default=None, description="File containing the call into this frame"
    )
    caller_line_number: int | None = Field(
        default=None, description="Line containing the call into this frame"
    )

    class Config:
        frozen = True

    def format_traceback(self) -> str:
        """Format this frame like a Python traceback."""
        # Check if code_context contains line range notation
        line_display = f"line {self.line_number}"
        if self.code_context and self.code_context.startswith("[lines "):
            # Parse "[lines X-Y]" format
            match = re.match(r"\[lines (\d+)-(\d+)\]", self.code_context)
            if match:
                start_line = match.group(1)
                end_line = match.group(2)
                line_display = f"lines {start_line}-{end_line}"

        result = f'  File "{self.file_path}", {line_display}, in {self.function_name}'
        if self.code_context:
            # Handle multi-line code context (when showing multiple lines in a range)
            context_str = self.code_context.strip()
            if "\n" in context_str:
                # Multi-line context - indent each line
                lines = context_str.split("\n")
                for line in lines:
                    result += f"\n    {line}"
            else:
                # Single line context
                result += f"\n    {context_str}"
        return result


class AffectedEndpoint(BaseModel):
    """An endpoint affected by code changes."""

    endpoint: Endpoint = Field(description="The affected endpoint")
    confidence: ConfidenceLevel = Field(description="Confidence level")
    reason: str = Field(description="Why this endpoint is considered affected")
    dependency_chain: list[str] = Field(
        default_factory=list,
        description="Primary dependency chain from change to endpoint",
    )
    dependency_chains: list[list[str]] = Field(
        default_factory=list,
        description="All distinct dependency chains supporting this result",
    )
    changed_files: list[str] = Field(
        default_factory=list,
        description="Files that changed affecting this endpoint",
    )
    call_stacks: list[list[CallStackFrame]] = Field(
        default_factory=list,
        description=(
            "All traceback-style call stacks showing different dependency paths. "
            "Each inner list represents one path from the endpoint handler to the changed file."
        ),
    )
    effect_evidence: list[EffectEvidence] = Field(
        default_factory=list,
        description="Structured reachability, effect, and data-observation evidence.",
    )
    contract_evidence: tuple[ContractEffectEvidence, ...] = Field(
        default_factory=tuple,
        description=(
            "Exact declared call semantics, separate from changed-code causality and observation."
        ),
    )
    resource_coupling_evidence: tuple[ResourceCouplingCandidateEvidence, ...] = Field(
        default_factory=tuple,
        description="LOW-only potential cross-request resource coupling evidence.",
    )

    class Config:
        frozen = True

    @property
    def all_dependency_chains(self) -> list[list[str]]:
        """Return the primary chain followed by distinct additional chains."""
        chains: list[list[str]] = []
        for chain in [self.dependency_chain, *self.dependency_chains]:
            if chain and chain not in chains:
                chains.append(chain)
        return chains

    def format_traceback(self) -> str:
        """Format all call stacks like Python tracebacks.

        If there are multiple call stacks (multiple paths to reach the same dependency),
        each one is shown separately with a header indicating which path it is.
        """
        if not self.call_stacks:
            return ""

        results = []
        for i, call_stack in enumerate(self.call_stacks, 1):
            if len(self.call_stacks) > 1:
                # Multiple paths - label each one
                results.append(
                    f"Traceback (dependency chain, path {i} of {len(self.call_stacks)}):"
                )
            else:
                # Single path
                results.append("Traceback (dependency chain):")

            for frame in call_stack:
                results.append(frame.format_traceback())

            # Add spacing between multiple tracebacks
            if i < len(self.call_stacks):
                results.append("")

        return "\n".join(results)


class OrphanChange(BaseModel):
    """Represents code changes that are not related to any endpoint."""

    file_path: str = Field(description="Path to the file with orphan changes")
    added_lines: list[int] = Field(
        default_factory=list,
        description="Line numbers of added lines that are orphan",
    )
    removed_lines: list[int] = Field(
        default_factory=list,
        description="Line numbers of removed lines that are orphan",
    )
    reason: str = Field(
        default="Code changes not related to any endpoint",
        description="Why these changes are considered orphan",
    )

    class Config:
        frozen = True

    @property
    def total_lines(self) -> int:
        """Total number of orphan lines."""
        return len(self.added_lines) + len(self.removed_lines)

    def format_lines(self) -> str:
        """Format the orphan lines for display."""
        parts = []
        if self.added_lines:
            lines_str = ", ".join(str(ln) for ln in sorted(self.added_lines)[:10])
            if len(self.added_lines) > 10:
                lines_str += f", ... ({len(self.added_lines)} total)"
            parts.append(f"Added: lines {lines_str}")
        if self.removed_lines:
            lines_str = ", ".join(str(ln) for ln in sorted(self.removed_lines)[:10])
            if len(self.removed_lines) > 10:
                lines_str += f", ... ({len(self.removed_lines)} total)"
            parts.append(f"Removed: lines {lines_str}")
        return "; ".join(parts) if parts else "No lines"


class AnalysisReport(BaseModel):
    """Complete analysis report."""

    timestamp: datetime = Field(
        default_factory=datetime.now,
        description="When the analysis was performed",
    )
    app_path: str = Field(description="Path to the analyzed FastAPI application")
    diff_source: str = Field(description="Source of the diff (file path or 'stdin')")
    total_endpoints: int = Field(description="Total endpoints in the application")
    inventory_status: InventoryStatus | None = Field(
        default=None,
        description=(
            "Completeness of the target execution-free inventory; unset for runtime analysis"
        ),
    )
    inventory_limitations: tuple[EndpointDiscoveryCondition, ...] = Field(
        default_factory=tuple,
        description="Source-backed limitations on the target execution-free inventory",
    )
    affected_endpoints: list[AffectedEndpoint] = Field(
        default_factory=list,
        description="Endpoints selected by the legacy confidence threshold",
    )
    candidate_endpoints: list[AffectedEndpoint] = Field(
        default_factory=list,
        description="All reachable candidates before presentation filtering",
    )
    orphan_changes: list[OrphanChange] = Field(
        default_factory=list,
        description="Code changes not related to any endpoint",
    )
    total_files_changed: int = Field(
        default=0,
        description="Total files in the diff",
    )
    python_files_changed: int = Field(
        default=0,
        description="Python files changed in the diff",
    )
    analysis_duration_ms: float | None = Field(
        default=None,
        description="How long the analysis took in milliseconds",
    )
    errors: list[str] = Field(
        default_factory=list,
        description="Any errors encountered during analysis",
    )
    warnings: list[str] = Field(
        default_factory=list,
        description="Any warnings from the analysis",
    )
    effect_contract_audit: EffectContractAudit | None = Field(
        default=None,
        description="Complete exact contract audit when configured.",
    )
    resource_coupling_graph: ResourceCouplingGraph | None = Field(
        default=None,
        description="Finite cross-endpoint resource graph and optional LOW evidence.",
    )
    sql_transaction_report: SQLTransactionReport | None = Field(
        default=None,
        description="Report-only endpoint-reachable SQL staging and boundary evidence.",
    )
    sql_transaction_path_report: SQLTransactionPathReport | None = Field(
        default=None,
        description="Bounded source-backed same-scope SQL ordering diagnostics.",
    )

    @model_validator(mode="after")
    def validate_inventory_strength(self) -> "AnalysisReport":
        has_limitations = bool(self.inventory_limitations)
        if self.inventory_status is None:
            if has_limitations:
                raise ValueError("unset inventory status forbids inventory limitations")
            return self
        if (self.inventory_status == InventoryStatus.ESTABLISHED) == has_limitations:
            raise ValueError(
                "established inventory forbids limitations; conditional/unavailable require them"
            )
        return self

    @model_validator(mode="after")
    def populate_candidates_from_legacy_results(self) -> "AnalysisReport":
        """Keep manually constructed legacy reports internally consistent."""
        if not self.candidate_endpoints and self.affected_endpoints:
            self.candidate_endpoints = list(self.affected_endpoints)
        return self

    @model_validator(mode="after")
    def validate_sql_transaction_report(self) -> "AnalysisReport":
        transaction_report = self.sql_transaction_report
        if transaction_report is None:
            return self
        audit = self.effect_contract_audit
        if audit is None or transaction_report.effect_audit_hash != audit.provenance.audit_hash:
            raise ValueError("SQL transaction report requires its exact effect audit")
        occurrence_by_id = {item.id: item for item in audit.occurrences}
        endpoint_ids = {item.id for item in audit.scope.endpoint_inventory}
        for evidence in transaction_report.endpoint_evidence:
            if evidence.endpoint_id not in endpoint_ids:
                raise ValueError("SQL transaction evidence references an unknown endpoint")
            occurrence_ids = (
                *evidence.stage_occurrence_ids,
                *evidence.flush_occurrence_ids,
                *evidence.begin_occurrence_ids,
                *evidence.commit_occurrence_ids,
                *evidence.rollback_occurrence_ids,
            )
            for occurrence_id in occurrence_ids:
                occurrence = occurrence_by_id.get(occurrence_id)
                if (
                    occurrence is None
                    or occurrence.contract_id is None
                    or not any(item.id == evidence.endpoint_id for item in occurrence.endpoints)
                ):
                    raise ValueError("SQL transaction occurrence is absent from its endpoint audit")
        return self

    @model_validator(mode="after")
    def validate_sql_transaction_path_report(self) -> "AnalysisReport":  # noqa: PLR0912
        path_report = self.sql_transaction_path_report
        if path_report is None:
            return self
        transaction_report = self.sql_transaction_report
        audit = self.effect_contract_audit
        if (
            transaction_report is None
            or audit is None
            or path_report.transaction_report_hash != transaction_report.report_hash
            or path_report.effect_audit_hash != audit.provenance.audit_hash
        ):
            raise ValueError("SQL transaction paths require their exact reports")
        occurrence_by_id = {item.id: item for item in audit.occurrences}
        evidence_by_endpoint = {
            item.endpoint_id: item for item in transaction_report.endpoint_evidence
        }
        expected_pairs = {
            (evidence.endpoint_id, stage_id, boundary_id)
            for evidence in transaction_report.endpoint_evidence
            for stage_id in evidence.stage_occurrence_ids
            for boundary_id in (
                *evidence.commit_occurrence_ids,
                *evidence.rollback_occurrence_ids,
            )
        }
        path_pairs: list[tuple[str, str, str]] = []
        for path in path_report.ordered_paths:
            evidence = evidence_by_endpoint.get(path.endpoint_id)
            if evidence is None:
                raise ValueError("SQL ordered path references unknown endpoint evidence")
            begin_scope_by_id = {item.occurrence_id: item.scope for item in evidence.begin_scopes}
            expected_boundaries = (
                evidence.commit_occurrence_ids
                if path.boundary == "commit"
                else evidence.rollback_occurrence_ids
            )
            if (
                path.stage_occurrence_id not in evidence.stage_occurrence_ids
                or path.boundary_occurrence_id not in expected_boundaries
                or (
                    path.begin_occurrence_id is not None
                    and (
                        path.begin_occurrence_id not in evidence.begin_occurrence_ids
                        or path.begin_scope != begin_scope_by_id[path.begin_occurrence_id]
                    )
                )
            ):
                raise ValueError("SQL ordered path roles contradict transaction evidence")
            occurrence_ids = [path.stage_occurrence_id, path.boundary_occurrence_id]
            if path.begin_occurrence_id is not None:
                occurrence_ids.append(path.begin_occurrence_id)
            if any(
                occurrence_by_id.get(item) is None
                or occurrence_by_id[item].file_path != path.file_path
                or not any(
                    endpoint.id == path.endpoint_id for endpoint in occurrence_by_id[item].endpoints
                )
                for item in occurrence_ids
            ):
                raise ValueError("SQL ordered path is absent from its source audit")
            path_pairs.append(
                (path.endpoint_id, path.stage_occurrence_id, path.boundary_occurrence_id)
            )
        for context_path in path_report.context_paths:
            evidence = evidence_by_endpoint.get(context_path.endpoint_id)
            if evidence is None:
                raise ValueError("SQL context path references unknown endpoint evidence")
            begin_by_id = {item.occurrence_id: item for item in evidence.begin_scopes}
            begin = begin_by_id.get(context_path.begin_occurrence_id)
            if (
                context_path.stage_occurrence_id not in evidence.stage_occurrence_ids
                or begin is None
                or begin.scope != context_path.begin_scope
                or begin.context_exit != context_path.context_exit
            ):
                raise ValueError("SQL context path roles contradict transaction evidence")
            if any(
                occurrence_by_id.get(item) is None
                or occurrence_by_id[item].file_path != context_path.file_path
                or not any(
                    endpoint.id == context_path.endpoint_id
                    for endpoint in occurrence_by_id[item].endpoints
                )
                for item in (
                    context_path.begin_occurrence_id,
                    context_path.stage_occurrence_id,
                )
            ):
                raise ValueError("SQL context path is absent from its source audit")
        diagnostic_pairs = [
            (item.endpoint_id, item.stage_occurrence_id, item.boundary_occurrence_id)
            for item in path_report.diagnostics
        ]
        all_pairs = [*path_pairs, *diagnostic_pairs]
        if len(all_pairs) != len(set(all_pairs)) or set(all_pairs) != expected_pairs:
            raise ValueError("SQL transaction paths must account for every bounded pair once")
        if len(expected_pairs) > path_report.max_pairs:
            raise ValueError("SQL transaction path report exceeds its atomic pair limit")
        return self

    @model_validator(mode="after")
    def validate_resource_coupling_graph(self) -> "AnalysisReport":  # noqa: PLR0912
        graph = self.resource_coupling_graph
        candidate_evidence = [
            evidence
            for candidate in self.candidate_endpoints
            for evidence in candidate.resource_coupling_evidence
        ]
        if graph is None:
            if candidate_evidence:
                raise ValueError("resource coupling candidate evidence requires its graph")
            return self
        audit = self.effect_contract_audit
        if audit is None or graph.effect_audit_hash != audit.provenance.audit_hash:
            raise ValueError("resource coupling graph requires its exact effect audit")
        occurrence_by_id = {item.id: item for item in audit.occurrences}
        group_by_id = {item.id: item for item in graph.groups}
        edge_by_id = {edge.id: edge for edge in graph.edges}
        endpoint_by_id = {item.id: item for item in audit.scope.endpoint_inventory}
        for edge in graph.edges:
            producer = occurrence_by_id.get(edge.producer_occurrence_id)
            consumer = occurrence_by_id.get(edge.consumer_occurrence_id)
            group = group_by_id.get(edge.group_id)
            if producer is None or consumer is None or group is None:
                raise ValueError("resource coupling edge references unknown audit evidence")
            if (
                producer.contract_id != edge.producer_contract_id
                or consumer.contract_id != edge.consumer_contract_id
                or edge.producer_contract_id not in group.producer_contract_ids
                or edge.consumer_contract_id not in group.consumer_contract_ids
                or edge.group_hash != group.group_hash
                or edge.resource_space_hash != group.resource_space_hash
                or edge.channel != group.channel
            ):
                raise ValueError("resource coupling edge contract/group evidence is inconsistent")
            producer_linked = any(
                item.id == edge.producer_endpoint_id for item in producer.endpoints
            )
            consumer_linked = any(
                item.id == edge.consumer_endpoint_id for item in consumer.endpoints
            )
            if not producer_linked or not consumer_linked:
                raise ValueError("resource coupling edge endpoint is absent from audit occurrence")
            if (
                producer.resource_identity is None
                or consumer.resource_identity is None
                or edge.resource_value_hash not in producer.resource_identity.value_hashes
                or edge.resource_value_hash not in consumer.resource_identity.value_hashes
            ):
                raise ValueError("resource coupling edge has no exact finite resource overlap")
        evidence_keys: set[tuple[str, str]] = set()
        for candidate in self.candidate_endpoints:
            for evidence in candidate.resource_coupling_evidence:
                evidence_edge = edge_by_id.get(evidence.edge_id)
                target = endpoint_by_id.get(evidence.consumer_endpoint_id)
                producer = occurrence_by_id.get(evidence.producer_occurrence_id)
                if evidence_edge is None or target is None or producer is None:
                    raise ValueError("coupling candidate evidence is absent from its graph/audit")
                if (
                    graph.mode != "changed_callsite_candidates"
                    or evidence.graph_hash != graph.graph_hash
                    or evidence.producer_occurrence_id != evidence_edge.producer_occurrence_id
                    or evidence.producer_endpoint_id != evidence_edge.producer_endpoint_id
                    or evidence.consumer_endpoint_id != evidence_edge.consumer_endpoint_id
                    or evidence.resource_value_hash != evidence_edge.resource_value_hash
                    or evidence.strength != evidence_edge.strength
                    or evidence.changed_file != producer.file_path
                    or not (
                        producer.line
                        <= evidence.changed_line
                        <= (producer.end_line or producer.line)
                    )
                ):
                    raise ValueError("coupling candidate evidence differs from graph edge")
                endpoint = candidate.endpoint
                handler_path = PurePosixPath(str(endpoint.handler.file_path).replace("\\", "/"))
                target_path = PurePosixPath(target.handler_file)
                handler_matches = handler_path == target_path or (
                    len(handler_path.parts) >= len(target_path.parts)
                    and handler_path.parts[-len(target_path.parts) :] == target_path.parts
                )
                if (
                    endpoint.path != target.path
                    or tuple(sorted(item.value for item in endpoint.methods)) != target.methods
                    or endpoint.handler.module != target.handler_module
                    or endpoint.handler.name != target.handler_name
                    or endpoint.handler.line_number != target.handler_line
                    or not handler_matches
                ):
                    raise ValueError("coupling evidence is attached to a different target")
                key = (evidence.edge_id, evidence.consumer_endpoint_id)
                if key in evidence_keys:
                    raise ValueError("duplicate resource coupling candidate evidence")
                evidence_keys.add(key)
        return self

    @model_validator(mode="after")
    def validate_contract_evidence(self) -> "AnalysisReport":
        if any(affected not in self.candidate_endpoints for affected in self.affected_endpoints):
            raise ValueError("affected endpoint must equal an enriched candidate record")
        evidence_items = [
            (candidate, evidence)
            for candidate in self.candidate_endpoints
            for evidence in candidate.contract_evidence
        ]
        if not evidence_items:
            return self
        audit = self.effect_contract_audit
        if audit is None:
            raise ValueError("contract evidence requires an attached effect contract audit")
        occurrence_by_id = {item.id: item for item in audit.occurrences}
        coverage_by_id = {item.contract_id: item for item in audit.contract_coverage}
        for candidate, evidence in evidence_items:
            occurrence = occurrence_by_id.get(evidence.occurrence_id)
            coverage = coverage_by_id.get(evidence.contract.id)
            if occurrence is None or occurrence.contract_id != evidence.contract.id:
                raise ValueError("contract evidence occurrence is absent from the audit")
            if (
                coverage is None
                or evidence.contract_hash != coverage.contract_hash
                or evidence.contract.symbol != coverage.symbol
                or evidence.contract.invocation != coverage.invocation
                or _contract_hash(evidence.contract) != evidence.contract_hash
            ):
                raise ValueError("contract evidence is inconsistent with audit coverage")
            endpoint_record = next(
                (
                    endpoint
                    for endpoint in occurrence.endpoints
                    if endpoint.id == evidence.endpoint_audit_id
                ),
                None,
            )
            if endpoint_record is None:
                raise ValueError("contract evidence endpoint is absent from audit occurrence")
            endpoint = candidate.endpoint
            handler_path = PurePosixPath(str(endpoint.handler.file_path).replace("\\", "/"))
            expected_handler_path = PurePosixPath(endpoint_record.handler_file)
            handler_matches = handler_path == expected_handler_path or (
                len(handler_path.parts) >= len(expected_handler_path.parts)
                and handler_path.parts[-len(expected_handler_path.parts) :]
                == expected_handler_path.parts
            )
            if (
                tuple(sorted(method.value for method in endpoint.methods))
                != endpoint_record.methods
                or endpoint.path != endpoint_record.path
                or endpoint.handler.module != endpoint_record.handler_module
                or endpoint.handler.name != endpoint_record.handler_name
                or endpoint.handler.line_number != endpoint_record.handler_line
                or not handler_matches
                or endpoint.discovery_status.value != endpoint_record.discovery_status
                or tuple(
                    (
                        condition.source_line,
                        condition.reason,
                    )
                    for condition in endpoint.discovery_conditions
                )
                != tuple(
                    (condition.line, condition.reason) for condition in endpoint_record.conditions
                )
            ):
                raise ValueError("contract evidence is attached to a different endpoint")
            if (
                evidence.call_location.file_path != occurrence.file_path
                or evidence.call_location.line_number != occurrence.line
                or evidence.call_location.end_line_number != occurrence.end_line
                or evidence.call_location.symbol != occurrence.canonical_symbol
                or evidence.resolver != occurrence.resolver
                or evidence.resolver_version != occurrence.resolver_version
            ):
                raise ValueError("contract evidence call occurrence is inconsistent with audit")
            provenance = audit.provenance
            if (
                evidence.config_hash != provenance.config_hash
                or evidence.preset_hash != provenance.preset_hash
                or evidence.raw_hash != provenance.raw_hash
                or evidence.audit_hash != provenance.audit_hash
                or evidence.occurrence_corpus_hash != provenance.occurrence_corpus_hash
                or evidence.contract_source_path != provenance.contract_source_path
                or evidence.matcher != provenance.matcher
            ):
                raise ValueError("contract evidence provenance is inconsistent with audit")
        for candidate in self.candidate_endpoints:
            keys = [
                (item.occurrence_id, item.contract.id, item.endpoint_audit_id)
                for item in candidate.contract_evidence
            ]
            if len(keys) != len(set(keys)):
                raise ValueError("candidate contains duplicate contract evidence")
        return self

    @property
    def affected_count(self) -> int:
        """Number of affected endpoints."""
        return len(self.affected_endpoints)

    @property
    def candidate_count(self) -> int:
        """Number of reachable candidates before presentation filtering."""
        return len(self.candidate_endpoints)

    @property
    def high_confidence_count(self) -> int:
        """Number of high confidence affected endpoints."""
        return sum(1 for ae in self.affected_endpoints if ae.confidence == ConfidenceLevel.HIGH)

    @property
    def orphan_count(self) -> int:
        """Number of files with orphan changes."""
        return len(self.orphan_changes)

    @property
    def total_orphan_lines(self) -> int:
        """Total number of orphan lines across all files."""
        return sum(oc.total_lines for oc in self.orphan_changes)

    @property
    def has_errors(self) -> bool:
        """Check if there were any errors."""
        return len(self.errors) > 0

    def get_endpoints_by_confidence(
        self,
        confidence: ConfidenceLevel,
    ) -> list[AffectedEndpoint]:
        """Get affected endpoints filtered by confidence level."""
        return [ae for ae in self.affected_endpoints if ae.confidence == confidence]
