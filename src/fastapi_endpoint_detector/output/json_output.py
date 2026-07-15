"""
JSON output formatter.
"""

import json
from typing import Any

from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointInventory
from fastapi_endpoint_detector.models.report import AffectedEndpoint, AnalysisReport
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
            "discovery_status": endpoint.discovery_status.value,
            "discovery_conditions": [
                condition.model_dump(mode="json") for condition in endpoint.discovery_conditions
            ],
            "surface": (
                endpoint.surface.model_dump(mode="json") if endpoint.surface is not None else None
            ),
        }

    def _affected_to_dict(self, affected: AffectedEndpoint) -> dict[str, Any]:
        return {
            "endpoint": self._endpoint_to_dict(affected.endpoint),
            "confidence": affected.confidence.value,
            "reason": affected.reason,
            "dependency_chain": affected.dependency_chain,
            "dependency_chains": affected.all_dependency_chains,
            "changed_files": affected.changed_files,
            "call_stacks": [
                [frame.model_dump(mode="json", exclude_none=True) for frame in stack]
                for stack in affected.call_stacks
            ],
            "effect_evidence": [
                evidence.model_dump(mode="json", exclude_none=True)
                for evidence in affected.effect_evidence
            ],
            "contract_evidence": [
                evidence.model_dump(mode="json", exclude_none=True)
                for evidence in affected.contract_evidence
            ],
            "resource_coupling_evidence": [
                evidence.model_dump(mode="json", exclude_none=True)
                for evidence in affected.resource_coupling_evidence
            ],
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
                "candidate_endpoints": len(report.candidate_endpoints),
                "high_confidence": report.high_confidence_count,
                "orphan_files": report.orphan_count,
                "orphan_lines": report.total_orphan_lines,
                "files_changed": report.total_files_changed,
                "python_files_changed": report.python_files_changed,
                "analysis_duration_ms": report.analysis_duration_ms,
            },
            "affected_endpoints": [
                self._affected_to_dict(affected) for affected in report.affected_endpoints
            ],
            "candidate_endpoints": [
                self._affected_to_dict(affected) for affected in report.candidate_endpoints
            ],
            "orphan_changes": [
                {
                    "file_path": oc.file_path,
                    "added_lines": oc.added_lines,
                    "removed_lines": oc.removed_lines,
                    "total_lines": oc.total_lines,
                    "reason": oc.reason,
                }
                for oc in report.orphan_changes
            ],
            "errors": report.errors,
            "warnings": report.warnings,
            "effect_contract_audit": (
                report.effect_contract_audit.model_dump(mode="json", exclude_none=True)
                if report.effect_contract_audit is not None
                else None
            ),
            "resource_coupling_graph": (
                report.resource_coupling_graph.model_dump(mode="json", exclude_none=True)
                if report.resource_coupling_graph is not None
                else None
            ),
            "sql_transaction_report": (
                report.sql_transaction_report.model_dump(mode="json", exclude_none=True)
                if report.sql_transaction_report is not None
                else None
            ),
            "sql_transaction_path_report": (
                report.sql_transaction_path_report.model_dump(mode="json", exclude_none=True)
                if report.sql_transaction_path_report is not None
                else None
            ),
        }

        return json.dumps(data, indent=self.indent, default=str)

    def format_inventory(self, inventory: EndpointInventory) -> str:
        """Format endpoints with whole-inventory strength metadata."""
        data = {
            "schema_version": 2,
            "inventory_status": inventory.status.value,
            "inventory_limitations": [
                limitation.model_dump(mode="json") for limitation in inventory.limitations
            ],
            "total": len(inventory.endpoints),
            "endpoints": [self._endpoint_to_dict(ep) for ep in inventory.endpoints],
        }
        return json.dumps(data, indent=self.indent, default=str)

    def format_endpoints(self, endpoints: list[Endpoint]) -> str:
        """Format a legacy endpoint list as JSON."""
        data = {
            "total": len(endpoints),
            "endpoints": [self._endpoint_to_dict(ep) for ep in endpoints],
        }
        return json.dumps(data, indent=self.indent, default=str)
