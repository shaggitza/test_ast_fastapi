"""
Unit tests for output formatters.
"""

import json
import re
from pathlib import Path

import pytest
import yaml

from fastapi_endpoint_detector.models.endpoint import (
    Endpoint,
    EndpointDiscoveryCondition,
    EndpointDiscoveryStatus,
    EndpointInventory,
    EndpointMethod,
    HandlerInfo,
    InventoryStatus,
    RouteActivationEvidence,
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


def test_unavailable_report_inventory_is_visible_in_all_formats() -> None:
    limitation = EndpointDiscoveryCondition(
        source_path=Path("/app/broken.py"),
        source_line=17,
        reason="target module could not be parsed",
    )
    report = AnalysisReport(
        app_path="/app/broken.py",
        diff_source="change.diff",
        total_endpoints=0,
        inventory_status=InventoryStatus.UNAVAILABLE,
        inventory_limitations=(limitation,),
    )

    json_result = json.loads(JsonFormatter().format(report))
    yaml_result = yaml.safe_load(YamlFormatter().format(report))
    for result in (json_result, yaml_result):
        assert result["inventory_status"] == "unavailable"
        assert result["inventory_limitations"] == [
            {
                "source_path": "/app/broken.py",
                "source_line": 17,
                "reason": "target module could not be parsed",
            }
        ]
    for formatter in (TextFormatter(), MarkdownFormatter(), HtmlFormatter()):
        rendered = re.sub(r"\x1b\[[0-9;]*m", "", formatter.format(report))
        assert "UNAVAILABLE" in rendered
        assert "/app/broken.py" in rendered
        assert "17" in rendered
        assert limitation.reason in rendered


def test_json_and_yaml_preserve_startup_activation_evidence() -> None:
    condition = EndpointDiscoveryCondition(
        source_path=Path("/app/main.py"),
        source_line=8,
        reason="route is installed only if framework startup executes",
    )
    digest = "sha256:" + "a" * 64
    endpoint = Endpoint(
        path="/late",
        methods=[EndpointMethod.POST],
        handler=HandlerInfo(
            name="late", module="main", file_path=Path("/app/main.py"), line_number=5
        ),
        discovery_status=EndpointDiscoveryStatus.CONDITIONAL,
        discovery_conditions=(condition,),
        activation=RouteActivationEvidence(
            lifecycle_surface_id="event:startup",
            contract_id="fastapi-on-event",
            registration_file=Path("/app/main.py"),
            registration_line=7,
            activation_file=Path("/app/main.py"),
            activation_line=9,
            activation_source_hash=digest,
            contract_source_path="preset:framework-v1",
            raw_hash=digest,
            config_hash=digest,
            preset_hash=digest,
            contract_hash=digest,
        ),
    )
    candidate = AffectedEndpoint(
        endpoint=endpoint,
        confidence=ConfidenceLevel.LOW,
        reason="startup route",
    )
    report = AnalysisReport(
        app_path="/app",
        diff_source="change.diff",
        total_endpoints=1,
        candidate_endpoints=[candidate],
    )

    for result in (
        json.loads(JsonFormatter().format(report)),
        yaml.safe_load(YamlFormatter().format(report)),
    ):
        serialized = result["candidate_endpoints"][0]["endpoint"]
        assert serialized["surface"] is None
        assert serialized["activation"]["phase"] == "startup"
        assert serialized["activation"]["activation_line"] == 9
        assert serialized["activation"]["contract_id"] == "fastapi-on-event"


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
        assert "data-call-path-layout" in output
        assert '<option value="flow-lr">Flow</option>' in output
        assert '<option value="flow-tb">Top-down</option>' in output
        assert '<option value="radial">Radial</option>' in output
        assert '<option value="files">File groups</option>' in output
        assert "data-call-path-layer=" in output
        assert "data-call-path-file-label=" in output
        assert ">get_items</text>" in output
        assert ">load_items</text>" in output
        assert ">fetch</text>" in output
        assert "<strong>load_items</strong>" in output
        assert "<strong>fetch</strong>" in output
        assert "<h4>Static reachable frame: load_items</h4>" in output
        assert ">services.items.load_items</text>" not in output
        assert "<strong>services.items.load_items</strong>" not in output
        assert ">repository.fetch</text>" not in output
        assert 'class="call-tree-panel"' in output
        assert '<details class="call-tree-panel">' in output  # collapsed by default
        assert "data-call-tree-expand" in output
        assert "data-call-tree-collapse" in output
        assert "data-call-path-stage" in output
        assert "data-call-path-zoom-in" in output
        assert "data-call-path-zoom-out" in output
        assert "data-call-path-fit" in output
        assert "Show linear tracebacks (1 paths)" in output
        assert 'data-call-path-detail="affected-call-path-1-n2"' in output
        assert output.count("<text ") == output.count("</text>")
        # The synthetic endpoint marker is replaced by the compact handler symbol.
        assert ">[ENDPOINT] GET /items</text>" not in output
        assert "function applyLayout(layoutId)" in output
        assert "function radialLayout()" in output
        assert "function fileGroupLayout()" in output

    def test_html_deep_graph_is_scrollable_without_javascript_and_fully_fittable(self) -> None:
        """Keep a 20-node chain available before enhancement and below legacy fit limits."""
        handler = HandlerInfo(
            name="route",
            module="main",
            file_path=Path("/app/main.py"),
            line_number=3,
        )
        endpoint = Endpoint(path="/items", methods=[EndpointMethod.GET], handler=handler)
        frames = [
            CallStackFrame(
                file_path="/app/main.py",
                line_number=3,
                function_name="main.route",
            )
        ]
        frames.extend(
            CallStackFrame(
                file_path=f"/app/services/group_{index % 4}.py",
                line_number=index + 10,
                function_name=f"services.group_{index % 4}.step_{index}",
            )
            for index in range(1, 20)
        )
        affected = AffectedEndpoint(
            endpoint=endpoint,
            confidence=ConfidenceLevel.HIGH,
            reason="Deep static chain",
            call_stacks=[frames],
        )
        report = AnalysisReport(
            app_path="/app",
            diff_source="test.diff",
            total_endpoints=1,
            affected_endpoints=[affected],
        )

        output = HtmlFormatter().format(report)

        assert 'width="5700" height="300" viewBox="0 0 5700 300"' in output
        assert "var nextScale = Math.max(0.01" in output
        assert "data-call-path-touch-pan" in output
        assert "new ResizeObserver" in output

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
        assert "call-path-topology-key-fork" in output
        assert "call-path-topology-key-merge" in output
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

    def test_html_has_ten_persistent_offline_themes(self) -> None:
        """Emit one data view with ten allow-listed standalone visual themes."""
        report = AnalysisReport(
            app_path="/app",
            diff_source="test.diff",
            total_endpoints=0,
            affected_endpoints=[],
        )

        output = HtmlFormatter().format(report)
        theme_ids = re.findall(r'<option value="([a-z-]+)"(?: selected)?>', output)

        assert theme_ids == [
            "harbor",
            "obsidian",
            "terminal",
            "parchment",
            "blueprint",
            "forest",
            "ember",
            "lavender",
            "monochrome",
            "rose-quartz",
        ]
        assert '<html lang="en" data-theme="ember">' in output
        assert '<option value="ember" selected>Ember</option>' in output
        assert 'getAttribute("data-theme") || "ember"' in output
        assert "data-theme-select" in output
        assert "fastapi-endpoint-detector.theme.v1" in output
        assert output.count('html[data-theme="') == 10
        assert "@media (prefers-reduced-motion: reduce)" in output
        assert "@media print" in output
        assert "html[data-theme] { color-scheme: light;" in output
        assert "[data-call-path-reset]" in output
        assert "reference.blur()" not in output
        assert "<link" not in output
        assert "<script src=" not in output

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
        # Should contain a keyboard-reachable tooltip.
        assert "hover-tooltip" in output
        assert 'class="code-ref" tabindex="0" aria-describedby="code-preview-1"' in output
        assert 'role="tooltip"' in output

    def test_format_endpoints_table(self) -> None:
        """Test formatting endpoints as an HTML table."""
        handler = HandlerInfo(
            name="get_users",
            module="routers.users",
            file_path=Path("/app/routers/users.py"),
            line_number=10,
        )
        endpoints = [
            Endpoint(path="/api/users", methods=[EndpointMethod.GET], handler=handler),
            Endpoint(path="/trace", methods=[EndpointMethod.TRACE], handler=handler),
            Endpoint(path="/ws", methods=[EndpointMethod.WEBSOCKET], handler=handler),
        ]

        formatter = HtmlFormatter()
        output = formatter.format_endpoints(endpoints)

        assert "<table>" in output
        assert '<th scope="col">Method(s)</th>' in output
        assert '<th scope="col">Path</th>' in output
        assert '<caption class="sr-only">Discovered FastAPI endpoints</caption>' in output
        assert "method-GET" in output
        assert "method-TRACE" in output
        assert "method-WEBSOCKET" in output
        assert ".method-CUSTOM { background:" in output
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
