"""
Report data models.

Models representing analysis reports and results.
"""

import re
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field, model_validator

from fastapi_endpoint_detector.models.endpoint import Endpoint


class ConfidenceLevel(str, Enum):
    """Legacy prioritization level for endpoint impact."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class EvidenceProducer(str, Enum):
    """Analyzer that produced an evidence record."""

    DIRECT = "direct"
    MYPY = "mypy"
    SCIP = "scip"
    DATA_FLOW = "data_flow"


class EvidenceStatus(str, Enum):
    """How strongly source establishes the described effect."""

    ESTABLISHED = "established"
    CONDITIONAL = "conditional"
    REACHABILITY_ONLY = "reachability_only"
    UNRESOLVED = "unresolved"


class ChangeEffectKind(str, Enum):
    """Semantic shape of a source change."""

    HANDLER_IMPLEMENTATION = "handler_implementation"
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

    @model_validator(mode="after")
    def populate_candidates_from_legacy_results(self) -> "AnalysisReport":
        """Keep manually constructed legacy reports internally consistent."""
        if not self.candidate_endpoints and self.affected_endpoints:
            self.candidate_endpoints = list(self.affected_endpoints)
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
