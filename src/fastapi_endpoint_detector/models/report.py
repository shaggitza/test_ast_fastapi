"""
Report data models.

Models representing analysis reports and results.
"""

import re
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from fastapi_endpoint_detector.models.endpoint import Endpoint


class ConfidenceLevel(str, Enum):
    """Confidence level for endpoint being affected."""

    HIGH = "high"       # Direct change to endpoint handler
    MEDIUM = "medium"   # Change to direct dependency
    LOW = "low"         # Change to transitive dependency


class CallStackFrame(BaseModel):
    """A single frame in a call stack trace."""

    file_path: str = Field(description="Absolute path to the file")
    line_number: int = Field(description="Line number in the file")
    function_name: str = Field(description="Name of the function/method")
    code_context: str | None = Field(
        default=None,
        description="The line of code at this location"
    )

    class Config:
        frozen = True

    def format_traceback(self) -> str:
        """Format this frame like a Python traceback."""
        # Check if code_context contains line range notation
        line_display = f"line {self.line_number}"
        if self.code_context and self.code_context.startswith("[lines "):
            # Parse "[lines X-Y]" format
            match = re.match(r'\[lines (\d+)-(\d+)\]', self.code_context)
            if match:
                start_line = match.group(1)
                end_line = match.group(2)
                line_display = f"lines {start_line}-{end_line}"

        result = f'  File "{self.file_path}", {line_display}, in {self.function_name}'
        if self.code_context:
            # Handle multi-line code context (when showing multiple lines in a range)
            context_str = self.code_context.strip()
            if '\n' in context_str:
                # Multi-line context - indent each line
                lines = context_str.split('\n')
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
        description="Chain of dependencies from change to endpoint",
    )
    changed_files: list[str] = Field(
        default_factory=list,
        description="Files that changed affecting this endpoint",
    )
    call_stacks: list[list[CallStackFrame]] = Field(
        default_factory=list,
        description="All traceback-style call stacks showing different dependency paths. Each inner list represents one path from the endpoint handler to the changed file.",
    )

    class Config:
        frozen = True

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
                results.append(f"Traceback (dependency chain, path {i} of {len(self.call_stacks)}):")
            else:
                # Single path
                results.append("Traceback (dependency chain):")
            
            for frame in call_stack:
                results.append(frame.format_traceback())
            
            # Add spacing between multiple tracebacks
            if i < len(self.call_stacks):
                results.append("")
        
        return "\n".join(results)


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
        description="Endpoints affected by changes",
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

    @property
    def affected_count(self) -> int:
        """Number of affected endpoints."""
        return len(self.affected_endpoints)

    @property
    def high_confidence_count(self) -> int:
        """Number of high confidence affected endpoints."""
        return sum(
            1 for ae in self.affected_endpoints
            if ae.confidence == ConfidenceLevel.HIGH
        )

    @property
    def has_errors(self) -> bool:
        """Check if there were any errors."""
        return len(self.errors) > 0

    def get_endpoints_by_confidence(
        self,
        confidence: ConfidenceLevel,
    ) -> list[AffectedEndpoint]:
        """Get affected endpoints filtered by confidence level."""
        return [
            ae for ae in self.affected_endpoints
            if ae.confidence == confidence
        ]
