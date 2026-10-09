"""Machine reports retain snapshot-qualified endpoint lifecycle evidence."""

import json
from pathlib import Path

import pytest
import yaml

from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo
from fastapi_endpoint_detector.models.report import (
    AnalysisReport,
    EndpointLifecycle,
    EndpointLifecycleKind,
)
from fastapi_endpoint_detector.output.formatters import get_formatter


def _endpoint(name: str, snapshot: str) -> Endpoint:
    return Endpoint(
        path="/items",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name=name,
            module="routes",
            file_path=Path(snapshot) / "routes.py",
            line_number=5,
            end_line_number=7,
        ),
    )


@pytest.mark.parametrize("output_format", ["json", "yaml"])
@pytest.mark.parametrize("lifecycle", list(EndpointLifecycleKind))
def test_snapshot_qualified_endpoint_lifecycle_is_exposed(
    output_format: str,
    lifecycle: EndpointLifecycleKind,
) -> None:
    baseline = (
        _endpoint("old_items", "baseline")
        if lifecycle not in {EndpointLifecycleKind.TARGET, EndpointLifecycleKind.AMBIGUOUS}
        else None
    )
    target = (
        _endpoint("new_items", "target")
        if lifecycle not in {EndpointLifecycleKind.REMOVED, EndpointLifecycleKind.AMBIGUOUS}
        else None
    )
    report = AnalysisReport(
        app_path="target/app.py",
        diff_source="change.diff",
        total_endpoints=0,
        endpoint_lifecycle=[
            EndpointLifecycle(
                identity="GET /items",
                lifecycle=lifecycle,
                baseline_endpoint=baseline,
                target_endpoint=target,
            )
        ],
    )
    rendered = get_formatter(output_format).format(report)
    payload = json.loads(rendered) if output_format == "json" else yaml.safe_load(rendered)

    assert payload["schema_version"] == 4
    assert payload["analysis_completeness"] == "complete"
    assert len(payload["endpoint_lifecycle"]) == 1
    record = payload["endpoint_lifecycle"][0]
    assert record["identity"] == "GET /items"
    assert record["lifecycle"] == lifecycle.value
    if baseline is None:
        assert "baseline_endpoint" not in record
    else:
        assert record["baseline_endpoint"]["handler"]["name"] == "old_items"
        assert record["baseline_endpoint"]["handler"]["file_path"] == "baseline/routes.py"
    if target is None:
        assert "target_endpoint" not in record
    else:
        assert record["target_endpoint"]["handler"]["name"] == "new_items"
        assert record["target_endpoint"]["handler"]["file_path"] == "target/routes.py"
    assert payload["affected_endpoints"] == []
    assert payload["candidate_endpoints"] == []


@pytest.mark.parametrize("output_format", ["json", "yaml"])
def test_unreconciled_report_keeps_empty_lifecycle_and_partial_status(output_format: str) -> None:
    rendered = get_formatter(output_format).format(
        AnalysisReport(
            app_path="target/app.py",
            diff_source="change.diff",
            total_endpoints=0,
            analysis_completeness="partial",
        )
    )
    payload = json.loads(rendered) if output_format == "json" else yaml.safe_load(rendered)

    assert payload["schema_version"] == 4
    assert payload["analysis_completeness"] == "partial"
    assert payload["endpoint_lifecycle"] == []
