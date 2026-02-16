"""
Report data models.

Models representing analysis reports and results.
"""

import re
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

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
    code_context: Optional[str] = Field(
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
    call_stack: list[CallStackFrame] = Field(
        default_factory=list,
        description="Traceback-style call stack showing the dependency path",
    )
    
    class Config:
        frozen = True
    
    def format_traceback(self) -> str:
        """Format the call stack like a Python traceback."""
        if not self.call_stack:
            return ""
        lines = ["Traceback (dependency chain):"]
        for frame in self.call_stack:
            lines.append(frame.format_traceback())
        return "\n".join(lines)


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
        description="Endpoints affected by changes",
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
    analysis_duration_ms: Optional[float] = Field(
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
        return [
            ae for ae in self.affected_endpoints 
            if ae.confidence == confidence
        ]
