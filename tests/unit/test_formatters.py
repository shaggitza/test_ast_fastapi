"""
Unit tests for output formatters.
"""

import json
from pathlib import Path

import pytest

from fastapi_endpoint_detector.models.endpoint import (
    Endpoint,
    EndpointDiscoveryCondition,
    EndpointDiscoveryStatus,
    EndpointMethod,
    HandlerInfo,
)
from fastapi_endpoint_detector.models.report import (
    AffectedEndpoint,
    AnalysisReport,
    ChangeEffectKind,
    CodeReference,
    ConfidenceLevel,
    DataObservationKind,
    EffectDisposition,
    EffectEvidence,
    EvidenceProducer,
    EvidenceStatus,
    ImpactChannel,
)
from fastapi_endpoint_detector.output.formatters import get_formatter
from fastapi_endpoint_detector.output.html_output import HtmlFormatter
from fastapi_endpoint_detector.output.json_output import JsonFormatter
from fastapi_endpoint_detector.output.markdown_output import MarkdownFormatter
from fastapi_endpoint_detector.output.text_output import TextFormatter
from fastapi_endpoint_detector.output.yaml_output import YamlFormatter


def test_conditional_discovery_is_structured_and_visible() -> None:
    endpoint = Endpoint(
        path="/items",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="route", module="main", file_path=Path("/app/main.py"), line_number=3
        ),
        discovery_status=EndpointDiscoveryStatus.CONDITIONAL,
        discovery_conditions=(
            EndpointDiscoveryCondition(
                source_path=Path("/app/main.py"),
                source_line=9,
                reason="unknown helper may mutate app",
            ),
        ),
    )
    candidate = AffectedEndpoint(
        endpoint=endpoint,
        confidence=ConfidenceLevel.LOW,
        reason="conditional route",
    )
    report = AnalysisReport(
        app_path="/app",
        diff_source="change.diff",
        total_endpoints=1,
        candidate_endpoints=[candidate],
    )

    for formatted in (JsonFormatter().format(report), YamlFormatter().format(report)):
        assert "discovery_status" in formatted
        assert "conditional" in formatted
        assert "unknown helper may mutate app" in formatted
    for formatted in (
        TextFormatter().format(report),
        MarkdownFormatter().format(report),
        HtmlFormatter().format(report),
    ):
        assert "CONDITIONAL" in formatted
        assert "unknown helper may mutate app" in formatted


def test_json_preserves_candidates_and_structured_effect_evidence() -> None:
    handler = HandlerInfo(
        name="route",
        module="main",
        file_path=Path("/app/main.py"),
        line_number=3,
    )
    candidate = AffectedEndpoint(
        endpoint=Endpoint(path="/items", methods=[EndpointMethod.GET], handler=handler),
        confidence=ConfidenceLevel.LOW,
        reason="Reachable defensive-copy change",
        effect_evidence=[
            EffectEvidence(
                producer=EvidenceProducer.DATA_FLOW,
                status=EvidenceStatus.CONDITIONAL,
                effect=ChangeEffectKind.ARGUMENT_MUTATION_ISOLATED,
                observations=[DataObservationKind.NOT_OBSERVED_AFTER_CALL],
                channel=ImpactChannel.IN_MEMORY_ALIASING,
                disposition=EffectDisposition.NOT_OBSERVED_BY_CALLER,
                summary="Caller does not read the original argument after the call.",
                changed_location=CodeReference(file_path="service.py", line_number=2),
            )
        ],
    )
    report = AnalysisReport(
        app_path="/app",
        diff_source="change.diff",
        total_endpoints=1,
        affected_endpoints=[],
        candidate_endpoints=[candidate],
    )

    result = json.loads(JsonFormatter().format(report))

    assert result["affected_endpoints"] == []
    evidence = result["candidate_endpoints"][0]["effect_evidence"][0]
    assert evidence["effect"] == "argument_mutation_isolated"
    assert evidence["observations"] == ["not_observed_after_call"]
    assert evidence["disposition"] == "not_observed_by_caller"

    html_output = HtmlFormatter().format(report)
    assert "Reachable Candidates:</span> 1" in html_output
    assert "Additional Reachable Candidates" in html_output
    assert "/items" in html_output
    assert "No endpoints selected by the confidence threshold." in html_output


class TestMarkdownFormatter:
    """Tests for MarkdownFormatter."""

    def test_format_empty_report(self) -> None:
        """Test formatting a report with no affected endpoints."""
        report = AnalysisReport(
            app_path="/app",
            diff_source="test.diff",
            total_endpoints=10,
            affected_endpoints=[],
        )

        formatter = MarkdownFormatter()
        output = formatter.format(report)

        assert "# FastAPI Endpoint Change Detector" in output
        assert "## Summary" in output
        assert "**Total Endpoints:** 10" in output
        assert "**Affected Endpoints:** 0" in output
        assert "✅ No Affected Endpoints" in output

    def test_format_with_affected_endpoints(self) -> None:
        """Test formatting a report with affected endpoints."""
        handler = HandlerInfo(
            name="get_users",
            module="routers.users",
            file_path=Path("/app/routers/users.py"),
            line_number=10,
        )
        endpoint = Endpoint(
            path="/api/users",
            methods=[EndpointMethod.GET],
            handler=handler,
        )
        affected = AffectedEndpoint(
            endpoint=endpoint,
            confidence=ConfidenceLevel.HIGH,
            reason="Direct change",
            dependency_chain=["users.py", "get_users"],
            changed_files=["users.py"],
        )

        report = AnalysisReport(
            app_path="/app",
            diff_source="test.diff",
            total_endpoints=10,
            affected_endpoints=[affected],
        )

        formatter = MarkdownFormatter()
        output = formatter.format(report)

        assert "## Affected Endpoints" in output
        assert "🔴" in output  # High confidence emoji
        assert "GET `/api/users`" in output
        assert "**Handler:** `get_users`" in output
        assert "**Reason:** Direct change" in output

    def test_format_endpoints_empty(self) -> None:
        """Test formatting an empty list of endpoints."""
        formatter = MarkdownFormatter()
        output = formatter.format_endpoints([])

        assert "_No endpoints found._" in output

    def test_format_endpoints_table(self) -> None:
        """Test formatting endpoints as a markdown table."""
        handler = HandlerInfo(
            name="get_users",
            module="routers.users",
            file_path=Path("/app/routers/users.py"),
            line_number=10,
        )
        endpoint = Endpoint(
            path="/api/users",
            methods=[EndpointMethod.GET],
            handler=handler,
        )

        formatter = MarkdownFormatter()
        output = formatter.format_endpoints([endpoint])

        assert "# FastAPI Endpoints" in output
        assert "| Method(s) | Path | Handler | File | Line |" in output
        assert "| GET | `/api/users`" in output
        assert "| `get_users`" in output
        assert "| `users.py`" in output


class TestHtmlFormatter:
    """Tests for HtmlFormatter."""

    def test_format_empty_report(self) -> None:
        """Test formatting a report with no affected endpoints."""
        report = AnalysisReport(
            app_path="/app",
            diff_source="test.diff",
            total_endpoints=10,
            affected_endpoints=[],
        )

        formatter = HtmlFormatter()
        output = formatter.format(report)

        assert "<!DOCTYPE html>" in output
        assert "<title>FastAPI Endpoint Change Detector" in output
        assert "Total Endpoints" in output
        assert "10" in output
        assert "No endpoints selected by the confidence threshold." in output

    def test_format_with_affected_endpoints(self) -> None:
        """Test formatting a report with affected endpoints."""
        handler = HandlerInfo(
            name="get_users",
            module="routers.users",
            file_path=Path("/app/routers/users.py"),
            line_number=10,
        )
        endpoint = Endpoint(
            path="/api/users",
            methods=[EndpointMethod.GET],
            handler=handler,
        )
        affected = AffectedEndpoint(
            endpoint=endpoint,
            confidence=ConfidenceLevel.HIGH,
            reason="Direct change",
            dependency_chain=["users.py", "get_users"],
            changed_files=["users.py"],
        )

        report = AnalysisReport(
            app_path="/app",
            diff_source="test.diff",
            total_endpoints=10,
            affected_endpoints=[affected],
        )

        formatter = HtmlFormatter()
        output = formatter.format(report)

        assert "<h2>Affected Endpoints</h2>" in output
        assert "🔴" in output  # High confidence emoji
        assert "method-GET" in output  # CSS class for GET method
        assert "/api/users" in output
        assert "get_users" in output
        assert "Direct change" in output

    def test_html_has_css_styling(self) -> None:
        """Test that HTML output includes CSS styling."""
        report = AnalysisReport(
            app_path="/app",
            diff_source="test.diff",
            total_endpoints=10,
            affected_endpoints=[],
        )

        formatter = HtmlFormatter()
        output = formatter.format(report)

        assert "<style>" in output
        assert ".endpoint-card" in output
        assert ".method-badge" in output
        assert ".hover-tooltip" in output  # Hover functionality CSS

    def test_html_has_hover_tooltip(self) -> None:
        """Test that HTML output includes hover tooltip structure."""
        handler = HandlerInfo(
            name="get_users",
            module="routers.users",
            file_path=Path("/app/routers/users.py"),
            line_number=10,
        )
        endpoint = Endpoint(
            path="/api/users",
            methods=[EndpointMethod.GET],
            handler=handler,
        )
        affected = AffectedEndpoint(
            endpoint=endpoint,
            confidence=ConfidenceLevel.HIGH,
            reason="Direct change",
            dependency_chain=[],
            changed_files=[],
        )

        report = AnalysisReport(
            app_path="/app",
            diff_source="test.diff",
            total_endpoints=10,
            affected_endpoints=[affected],
        )

        formatter = HtmlFormatter()
        output = formatter.format(report)

        # Should contain code-ref class for hover functionality
        assert "code-ref" in output
        # Should contain hover-tooltip class
        assert "hover-tooltip" in output

    def test_format_endpoints_table(self) -> None:
        """Test formatting endpoints as an HTML table."""
        handler = HandlerInfo(
            name="get_users",
            module="routers.users",
            file_path=Path("/app/routers/users.py"),
            line_number=10,
        )
        endpoint = Endpoint(
            path="/api/users",
            methods=[EndpointMethod.GET],
            handler=handler,
        )

        formatter = HtmlFormatter()
        output = formatter.format_endpoints([endpoint])

        assert "<table>" in output
        assert "<th>Method(s)</th>" in output
        assert "<th>Path</th>" in output
        assert "method-GET" in output
        assert "/api/users" in output


class TestFormatterRegistry:
    """Tests for formatter registry."""

    def test_get_markdown_formatter(self) -> None:
        """Test getting markdown formatter from registry."""
        formatter = get_formatter("markdown")
        assert isinstance(formatter, MarkdownFormatter)

    def test_get_html_formatter(self) -> None:
        """Test getting HTML formatter from registry."""
        formatter = get_formatter("html")
        assert isinstance(formatter, HtmlFormatter)

    def test_get_json_formatter(self) -> None:
        """Test getting JSON formatter from registry."""
        formatter = get_formatter("json")
        assert isinstance(formatter, JsonFormatter)

    def test_get_unknown_formatter_raises(self) -> None:
        """Test that getting an unknown formatter raises an error."""
        with pytest.raises(ValueError, match="Unknown formatter"):
            get_formatter("unknown_format")
