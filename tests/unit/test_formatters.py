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
    EndpointInventory,
    EndpointMethod,
    HandlerInfo,
    InventoryStatus,
)
from fastapi_endpoint_detector.models.report import (
    AffectedEndpoint,
    AnalysisReport,
    CallStackFrame,
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


def test_inventory_strength_is_structured_and_visible() -> None:
    limitation = EndpointDiscoveryCondition(
        source_path=Path("/app/main.py"),
        source_line=9,
        reason="unknown plugin may register routes",
    )
    inventory = EndpointInventory(status=InventoryStatus.CONDITIONAL, limitations=(limitation,))

    json_result = json.loads(JsonFormatter().format_inventory(inventory))
    assert json_result["schema_version"] == 2
    assert json_result["inventory_status"] == "conditional"
    assert json_result["inventory_limitations"][0]["reason"] == limitation.reason
    assert json_result["endpoints"] == []
    for formatter in (
        YamlFormatter(),
        TextFormatter(),
        MarkdownFormatter(),
        HtmlFormatter(),
    ):
        rendered = formatter.format_inventory(inventory)
        assert "conditional" in rendered
        assert limitation.reason in rendered


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

    def test_html_renders_static_call_path_graph_and_text_fallback(self) -> None:
        """Render path topology without implying runtime execution."""
        handler = HandlerInfo(
            name="get_items",
            module="routers.items",
            file_path=Path("/app/routers/items.py"),
            line_number=10,
        )
        endpoint = Endpoint(path="/items", methods=[EndpointMethod.GET], handler=handler)
        affected = AffectedEndpoint(
            endpoint=endpoint,
            confidence=ConfidenceLevel.HIGH,
            reason="Typed dependency path",
            call_stacks=[
                [
                    CallStackFrame(
                        file_path="/app/routers/items.py",
                        line_number=10,
                        function_name="[ENDPOINT] GET /items",
                        code_context="def get_items():",
                    ),
                    # The mapper can include the handler again in mypy's raw stack.
                    CallStackFrame(
                        file_path="/app/routers/items.py",
                        line_number=10,
                        function_name="routers.items.get_items",
                    ),
                    CallStackFrame(
                        file_path="/app/services/items.py",
                        line_number=22,
                        function_name="services.items.load_items",
                        code_context="return repository.fetch()",
                    ),
                    CallStackFrame(
                        file_path="/app/repository.py",
                        line_number=42,
                        function_name="repository.fetch",
                        code_context="return rows",
                    ),
                ]
            ],
        )
        report = AnalysisReport(
            app_path="/app",
            diff_source="test.diff",
            total_endpoints=1,
            affected_endpoints=[affected],
        )

        output = HtmlFormatter().format(report)

        assert 'class="call-path-view"' in output
        assert 'class="call-path-svg"' in output
        assert "1 static paths" in output
        assert "3 shared nodes" in output
        assert "endpoint handler → shared/intermediate logic" in output
        assert "services.items.load_items" in output
        assert "repository.fetch" in output
        assert 'class="call-path-text"' in output
        assert 'data-call-path-detail="affected-call-path-1-n2"' in output
        # The duplicate raw handler is normalized in the graph view.
        assert output.count("routers.items.get_items") == 1

    def test_html_keeps_multiple_call_paths_separate(self) -> None:
        """Do not merge contextual paths that share a function or file."""
        handler = HandlerInfo(
            name="route",
            module="main",
            file_path=Path("/app/main.py"),
            line_number=3,
        )
        endpoint = Endpoint(path="/items", methods=[EndpointMethod.GET], handler=handler)
        def stack(file_path: str, line_number: int, function_name: str) -> CallStackFrame:
            return CallStackFrame(
                file_path=file_path,
                line_number=line_number,
                function_name=function_name,
            )
        affected = AffectedEndpoint(
            endpoint=endpoint,
            confidence=ConfidenceLevel.MEDIUM,
            reason="Two static paths",
            call_stacks=[
                [
                    stack("/app/main.py", 3, "route"),
                    stack("/app/shared.py", 8, "shared.load"),
                ],
                [
                    stack("/app/main.py", 3, "route"),
                    stack("/app/shared.py", 19, "shared.load"),
                ],
            ],
        )
        report = AnalysisReport(
            app_path="/app",
            diff_source="test.diff",
            total_endpoints=1,
            affected_endpoints=[affected],
        )

        output = HtmlFormatter().format(report)

        assert "2 static paths" in output
        assert "3 shared nodes" in output
        assert "shared by all 2 paths" in output
        assert "call-path-node-fork" in output
        assert "Path 1 of 2" not in output
        assert "shared.py:8" in output
        assert "shared.py:19" in output

    def test_html_renders_no_path_evidence_fallback(self) -> None:
        """Explain missing paths rather than inventing intermediate frames."""
        handler = HandlerInfo(
            name="route",
            module="main",
            file_path=Path("/app/main.py"),
            line_number=3,
        )
        candidate = AffectedEndpoint(
            endpoint=Endpoint(path="/items", methods=[EndpointMethod.GET], handler=handler),
            confidence=ConfidenceLevel.LOW,
            reason="Direct source evidence",
            effect_evidence=[
                EffectEvidence(
                    producer=EvidenceProducer.DATA_FLOW,
                    status=EvidenceStatus.CONDITIONAL,
                    effect=ChangeEffectKind.ARGUMENT_MUTATION_ISOLATED,
                    disposition=EffectDisposition.NOT_OBSERVED_BY_CALLER,
                    summary="The changed handler is not read by its caller.",
                    changed_location=CodeReference(
                        file_path="/app/main.py",
                        line_number=3,
                    ),
                )
            ],
        )
        report = AnalysisReport(
            app_path="/app",
            diff_source="test.diff",
            total_endpoints=1,
            candidate_endpoints=[candidate],
        )

        output = HtmlFormatter().format(report)

        assert "No static call path available." in output
        assert "Evidence location" in output
        assert "Direct handler change." in output
        assert "call-path-direct-edge" in output
        assert "No intermediate static path is inferred." in output
        assert 'class="call-path-node-intermediate"' not in output

    def test_html_escapes_call_path_source_and_is_deterministic(self) -> None:
        """Source-derived graph values cannot escape the standalone report."""
        handler = HandlerInfo(
            name="<handler>",
            module="main",
            file_path=Path("/app/main.py"),
            line_number=3,
        )
        endpoint = Endpoint(path="/items", methods=[EndpointMethod.GET], handler=handler)
        affected = AffectedEndpoint(
            endpoint=endpoint,
            confidence=ConfidenceLevel.HIGH,
            reason="<reason>",
            call_stacks=[
                [
                    CallStackFrame(
                        file_path="/app/main.py",
                        line_number=3,
                        function_name="</script><script>alert(1)</script>",
                        code_context="</script><img src=x onerror=alert(1)>",
                    ),
                    CallStackFrame(
                        file_path="/app/service.py",
                        line_number=9,
                        function_name="changed",
                        code_context="return '<unsafe>'",
                    ),
                ]
            ],
        )
        report = AnalysisReport(
            app_path="/app",
            diff_source="test.diff",
            total_endpoints=1,
            affected_endpoints=[affected],
        )

        formatter = HtmlFormatter()
        output = formatter.format(report)

        assert "&lt;/script&gt;&lt;script&gt;alert(1)&lt;/script&gt;" in output
        assert "&lt;img src=x onerror=alert(1)&gt;" in output
        assert "</script><script>alert(1)</script>" not in output
        assert output == formatter.format(report)

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
