"""
JSON output formatter.
"""

import json
from typing import Any

from fastapi_endpoint_detector.models.endpoint import Endpoint
from fastapi_endpoint_detector.models.report import AnalysisReport
from fastapi_endpoint_detector.output.formatters import BaseFormatter, register_formatter


@register_formatter("json")
class JsonFormatter(BaseFormatter):
    """
    Format output as JSON.
    """
    
    def __init__(self, indent: int = 2) -> None:
        """
        Initialize the JSON formatter.
        
        Args:
            indent: JSON indentation level.
        """
        self.indent = indent
    
    def _endpoint_to_dict(self, endpoint: Endpoint) -> dict[str, Any]:
        """Convert an endpoint to a dictionary."""
        return {
            "path": endpoint.path,
            "methods": [m.value for m in endpoint.methods],
            "handler": {
                "name": endpoint.handler.name,
                "module": endpoint.handler.module,
                "file": str(endpoint.handler.file_path),
                "line": endpoint.handler.line_number,
                "end_line": endpoint.handler.end_line_number,
            },
            "name": endpoint.name,
            "tags": endpoint.tags,
            "dependencies": endpoint.dependencies,
        }
    
    def format(self, report: AnalysisReport) -> str:
        """Format an analysis report as JSON."""
        data = {
            "timestamp": report.timestamp.isoformat(),
            "app_path": report.app_path,
            "diff_source": report.diff_source,
            "summary": {
                "total_endpoints": report.total_endpoints,
                "affected_endpoints": report.affected_count,
                "high_confidence": report.high_confidence_count,
                "files_changed": report.total_files_changed,
                "python_files_changed": report.python_files_changed,
                "analysis_duration_ms": report.analysis_duration_ms,
            },
            "affected_endpoints": [
                {
                    "endpoint": self._endpoint_to_dict(ae.endpoint),
                    "confidence": ae.confidence.value,
                    "reason": ae.reason,
                    "dependency_chain": ae.dependency_chain,
                    "changed_files": ae.changed_files,
                }
                for ae in report.affected_endpoints
            ],
            "errors": report.errors,
            "warnings": report.warnings,
        }
        
        return json.dumps(data, indent=self.indent, default=str)
    
    def format_endpoints(self, endpoints: list[Endpoint]) -> str:
        """Format a list of endpoints as JSON."""
        data = {
            "total": len(endpoints),
            "endpoints": [self._endpoint_to_dict(ep) for ep in endpoints],
        }
        
        return json.dumps(data, indent=self.indent, default=str)
