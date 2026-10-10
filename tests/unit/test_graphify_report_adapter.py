"""Offline end-to-end tests for the Graphify input and report adapters."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import BaseModel

from fastapi_endpoint_detector.analyzer.graphify_report_adapter import (
    GraphifyOverlayHookError,
    GraphifyOverlayReport,
    analyze_graphify_overlay_from_inputs,
    attach_graphify_overlay,
)
from fastapi_endpoint_detector.analyzer.source_inventory import build_source_inventory
from fastapi_endpoint_detector.models.diff import ChangeType, DiffFile, DiffHunk
from fastapi_endpoint_detector.models.endpoint import (
    DependencyCallableKind,
    DependencyDeclarationKind,
    DependencyDeclarationScope,
    DependencyGraphStatus,
    DependencyResolutionStatus,
    DependencySourceSpan,
    Endpoint,
    EndpointDependencyGraph,
    EndpointDependencyOccurrence,
    EndpointMethod,
    HandlerInfo,
)


def _write_side(root: Path) -> tuple[Path, Endpoint]:
    root.mkdir()
    (root / "routes.py").write_text("def endpoint():\n    return 1\n", encoding="utf-8")
    (root / "deps.py").write_text("def db_provider():\n    return 1\n", encoding="utf-8")
    (root / "service.py").write_text("def changed_helper():\n    return 1\n", encoding="utf-8")
    endpoint = Endpoint(
        path="/items",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="endpoint",
            module="routes",
            file_path=root / "routes.py",
            line_number=1,
            end_line_number=2,
        ),
        dependency_graph=EndpointDependencyGraph(
            status=DependencyGraphStatus.ESTABLISHED,
            occurrences=(
                EndpointDependencyOccurrence(
                    index_path=(0,),
                    parent_path=(),
                    depth=1,
                    order=0,
                    declaration_scope=DependencyDeclarationScope.PARAMETER,
                    declaration_kind=DependencyDeclarationKind.DEPENDS,
                    callable_kind=DependencyCallableKind.FUNCTION,
                    resolution_status=DependencyResolutionStatus.ESTABLISHED,
                    display_name="db_provider",
                    module="deps",
                    qualname="db_provider",
                    source_span=DependencySourceSpan(
                        file_path=Path("deps.py"), start_line=1, end_line=2
                    ),
                ),
            ),
        ),
    )
    return root, endpoint


def _write_raw_graph(path: Path) -> None:
    payload = {
        "input_tokens": 0,
        "output_tokens": 0,
        "hyperedges": [],
        "nodes": [
            {
                "id": "endpoint",
                "label": "endpoint",
                "file_type": "code",
                "source_file": "routes.py",
                "source_location": "L1",
            },
            {
                "id": "db_provider",
                "label": "db_provider",
                "file_type": "code",
                "source_file": "deps.py",
                "source_location": "L1",
            },
            {
                "id": "changed_helper",
                "label": "changed_helper",
                "file_type": "code",
                "source_file": "service.py",
                "source_location": "L1",
            },
        ],
        "edges": [
            {
                "source": "db_provider",
                "target": "changed_helper",
                "relation": "calls",
                "confidence": "EXTRACTED",
                "source_file": "deps.py",
                "source_location": "L2",
                "context": "declared dependency body",
            }
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


@pytest.mark.integration
def test_raw_snapshots_diff_route_di_and_report_hook_compose(tmp_path: Path) -> None:
    baseline_root, baseline_endpoint = _write_side(tmp_path / "baseline")
    target_root, target_endpoint = _write_side(tmp_path / "target")
    baseline_inventory = build_source_inventory(baseline_root)
    target_inventory = build_source_inventory(target_root)
    baseline_graph = tmp_path / "baseline-raw.json"
    target_graph = tmp_path / "target-raw.json"
    _write_raw_graph(baseline_graph)
    _write_raw_graph(target_graph)
    diff = DiffFile(
        path=Path("service.py"),
        change_type=ChangeType.MODIFIED,
        hunks=[
            DiffHunk(
                source_start=1,
                source_length=1,
                target_start=1,
                target_length=1,
                removed_lines=[1],
                added_lines=[1],
            )
        ],
    )

    overlay = analyze_graphify_overlay_from_inputs(
        baseline_graph_path=baseline_graph,
        target_graph_path=target_graph,
        baseline_project_root=baseline_root,
        target_project_root=target_root,
        schema="graphify-raw-0.9.30-v1",
        diff_files=(diff,),
        baseline_endpoints=(baseline_endpoint,),
        target_endpoints=(target_endpoint,),
        baseline_inventory=baseline_inventory,
        target_inventory=target_inventory,
    )

    assert isinstance(overlay, GraphifyOverlayReport)
    assert overlay.evidence_scope == "validated_offline_snapshots"
    assert len(overlay.evidence) == 2
    assert {item.side for item in overlay.evidence} == {"baseline", "target"}
    assert {item.binding_kind for item in overlay.evidence} == {"dependency"}
    assert {item.binding_identity for item in overlay.evidence} == {"dependency:0"}
    assert {item.confidence for item in overlay.evidence} == {"LOW"}
    assert all(item.incomplete is False for item in overlay.evidence)
    assert all(
        item.relations_source_to_target[0].source_node_id == "db_provider"
        and item.relations_source_to_target[0].target_node_id == "changed_helper"
        for item in overlay.evidence
    )
    assert all(
        item.relations_source_to_target[0].source_span is not None
        and item.relations_source_to_target[0].source_span.module_name == "deps"
        for item in overlay.evidence
    )

    class ReportWithOverlay(BaseModel):
        affected_endpoints: tuple[str, ...]
        graphify_overlay: GraphifyOverlayReport | None = None

    report = ReportWithOverlay(affected_endpoints=("GET /unchanged",))
    attached = attach_graphify_overlay(report, overlay)
    assert report.graphify_overlay is None
    assert attached.graphify_overlay == overlay
    assert attached.affected_endpoints == report.affected_endpoints
    assert attached.model_dump(mode="json")["graphify_overlay"]["schema_version"] == 1


def test_report_adapter_fails_if_cli_report_has_no_declared_overlay_field() -> None:
    class ReportWithoutOverlay(BaseModel):
        affected_endpoints: tuple[str, ...] = ()

    with pytest.raises(GraphifyOverlayHookError, match="must expose the graphify_overlay field"):
        attach_graphify_overlay(
            ReportWithoutOverlay(),
            GraphifyOverlayReport.model_construct(
                baseline_snapshot={},
                target_snapshot={},
                evidence=(),
                baseline_limitations=(),
                target_limitations=(),
            ),
        )
