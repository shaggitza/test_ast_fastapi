"""Offline integration tests for Graphify evidence overlay traversal."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.graphify_adapter import (
    GraphifySourceSpan,
    GraphSide,
    load_graphify_snapshot,
)
from fastapi_endpoint_detector.analyzer.graphify_analyzer import (
    ChangedSourceRange,
    GraphEndpointSeed,
    traverse_graphify_sides,
    traverse_graphify_snapshot,
)
from fastapi_endpoint_detector.models.endpoint import EndpointDiscoveryStatus


def _write_project(root: Path, *, deleted_file: bool = False) -> Path:
    root.mkdir()
    (root / "routes.py").write_text("def endpoint():\n    return alias()\n", encoding="utf-8")
    if not deleted_file:
        (root / "legacy.py").write_text("def alias():\n    return helper()\n", encoding="utf-8")
    (root / "service.py").write_text(
        "def helper():\n    return 1\n\ndef helper_method():\n    return 2\n",
        encoding="utf-8",
    )
    return root


def _graph(
    path: Path,
    *,
    legacy: bool = True,
    duplicate_endpoint: bool = False,
    edge_strength: str = "EXTRACTED",
) -> None:
    nodes = [
        {
            "id": "route_file",
            "label": "routes.py",
            "file_type": "code",
            "source_file": "routes.py",
        },
        {
            "id": "endpoint",
            "label": "endpoint",
            "file_type": "code",
            "source_file": "routes.py",
            "source_location": "L1-L2",
        },
        {
            "id": "helper",
            "label": "helper",
            "file_type": "code",
            "source_file": "service.py",
            "source_location": "L1-L2",
        },
        {
            "id": "helper_method",
            "label": "helper_method",
            "file_type": "code",
            "source_file": "service.py",
            "source_location": "L4-L5",
        },
    ]
    links = [
        {
            "source": "endpoint",
            "target": "alias",
            "relation": "calls",
            "confidence": edge_strength,
            "source_file": "routes.py",
            "source_location": "L2",
        },
        {
            "source": "alias",
            "target": "helper",
            "relation": "calls",
            "confidence": edge_strength,
            "source_file": "legacy.py",
            "source_location": "L2",
        },
    ]
    if legacy:
        nodes.append(
            {
                "id": "alias",
                "label": "alias",
                "file_type": "code",
                "source_file": "legacy.py",
                "source_location": "L1-L2",
            }
        )
    if duplicate_endpoint:
        nodes.append(
            {
                "id": "endpoint_duplicate",
                "label": "endpoint",
                "file_type": "code",
                "source_file": "routes.py",
                "source_location": "L1-L2",
            }
        )
    payload = {
        "directed": True,
        "multigraph": True,
        "graph": {},
        "hyperedges": [],
        "built_at_commit": "1" * 40,
        "nodes": nodes,
        "links": links if legacy else [],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def _load(root: Path, graph: Path, side: GraphSide = "target"):
    return load_graphify_snapshot(graph, project_root=root, side=side)


def _line_only_snapshot(snapshot):
    def line_span(span: GraphifySourceSpan | None) -> GraphifySourceSpan | None:
        if span is None:
            return None
        return replace(span, end_line=span.start_line)

    return replace(
        snapshot,
        graph_schema_version=2,
        nodes=tuple(replace(node, span=line_span(node.span)) for node in snapshot.nodes),
        edges=tuple(replace(edge, span=line_span(edge.span)) for edge in snapshot.edges),
    )


def _seed() -> GraphEndpointSeed:
    return GraphEndpointSeed(
        "GET /items", "endpoint", Path("routes.py"), 1, 2, EndpointDiscoveryStatus.ESTABLISHED
    )


@pytest.mark.integration
def test_reverse_traversal_tracks_cross_file_alias_and_exact_method_range(tmp_path: Path) -> None:
    root = _write_project(tmp_path / "target")
    graph = tmp_path / "graph.json"
    _graph(graph)
    snapshot = _load(root, graph)

    result = traverse_graphify_snapshot(
        snapshot,
        project_root=root,
        changed_ranges=(ChangedSourceRange(Path("service.py"), 1, 2),),
        endpoints=(_seed(),),
    )
    assert len(result.evidence) == 1
    assert result.evidence[0].node_path == ("helper", "alias", "endpoint")
    assert result.evidence[0].relations == ("calls", "calls")
    assert result.evidence[0].extractor_strengths == ("EXTRACTED", "EXTRACTED")
    assert result.evidence[0].confidence == "HIGH"

    method_result = traverse_graphify_snapshot(
        snapshot,
        project_root=root,
        changed_ranges=(ChangedSourceRange(Path("service.py"), 4, 5),),
        endpoints=(_seed(),),
    )
    assert method_result.evidence == ()


@pytest.mark.integration
def test_deleted_cross_file_alias_is_evaluated_in_baseline_snapshot(tmp_path: Path) -> None:
    baseline_root = _write_project(tmp_path / "baseline")
    target_root = _write_project(tmp_path / "target", deleted_file=True)
    baseline_graph = tmp_path / "baseline.json"
    target_graph = tmp_path / "target.json"
    _graph(baseline_graph)
    _graph(target_graph, legacy=False)
    baseline = _load(baseline_root, baseline_graph, "baseline")
    target = _load(target_root, target_graph, "target")
    change = (ChangedSourceRange(Path("legacy.py"), 1, 2),)

    pair = traverse_graphify_sides(
        baseline,
        target,
        baseline_project_root=baseline_root,
        target_project_root=target_root,
        baseline_changed_ranges=change,
        target_changed_ranges=(),
        baseline_endpoints=(_seed(),),
        target_endpoints=(_seed(),),
    )
    assert [item.endpoint_id for item in pair.baseline.evidence] == ["GET /items"]
    assert pair.target.evidence == ()


def test_ambiguous_binding_is_not_guessed_and_conditional_seed_is_low(tmp_path: Path) -> None:
    root = _write_project(tmp_path / "target")
    graph = tmp_path / "graph.json"
    _graph(graph, duplicate_endpoint=True)
    snapshot = _load(root, graph)
    result = traverse_graphify_snapshot(
        snapshot,
        project_root=root,
        changed_ranges=(ChangedSourceRange(Path("service.py"), 1, 2),),
        endpoints=(_seed(),),
    )
    assert result.evidence == ()
    assert any(
        "ambiguous endpoint binding (LOW, not guessed)" in item for item in result.limitations
    )

    conditional = GraphEndpointSeed(
        "GET /items", "endpoint", Path("routes.py"), 1, 2, EndpointDiscoveryStatus.CONDITIONAL
    )
    clean_graph = tmp_path / "graph-clean.json"
    _graph(clean_graph)
    conditional_result = traverse_graphify_snapshot(
        _load(root, clean_graph),
        project_root=root,
        changed_ranges=(ChangedSourceRange(Path("service.py"), 1, 2),),
        endpoints=(conditional,),
    )
    assert len(conditional_result.evidence) == 1
    assert conditional_result.evidence[0].confidence == "LOW"
    assert conditional_result.evidence[0].discovery_status == EndpointDiscoveryStatus.CONDITIONAL


def test_raw_line_only_binding_preserves_location_and_stays_low(tmp_path: Path) -> None:
    root = _write_project(tmp_path / "target")
    graph = tmp_path / "graph.json"
    _graph(graph)
    snapshot = _line_only_snapshot(_load(root, graph))

    result = traverse_graphify_snapshot(
        snapshot,
        project_root=root,
        changed_ranges=(ChangedSourceRange(Path("service.py"), 1, 2),),
        endpoints=(_seed(),),
    )

    assert len(result.evidence) == 1
    evidence = result.evidence[0]
    assert evidence.node_path == ("helper", "alias", "endpoint")
    assert [
        (span.file_path, span.start_line, span.end_line)
        for span in evidence.node_source_spans
        if span is not None
    ] == [
        (Path("service.py"), 1, 1),
        (Path("legacy.py"), 1, 1),
        (Path("routes.py"), 1, 1),
    ]
    assert all(
        span is not None and span.start_line == span.end_line for span in evidence.edge_source_spans
    )
    assert evidence.confidence == "LOW"
    assert evidence.limitations
    assert all("without widening or confidence promotion" in item for item in evidence.limitations)
    assert set(evidence.limitations).issubset(result.limitations)


def test_ambiguous_raw_line_only_binding_is_not_guessed(tmp_path: Path) -> None:
    root = _write_project(tmp_path / "target")
    graph = tmp_path / "graph.json"
    _graph(graph, duplicate_endpoint=True)
    snapshot = _line_only_snapshot(_load(root, graph))

    result = traverse_graphify_snapshot(
        snapshot,
        project_root=root,
        changed_ranges=(ChangedSourceRange(Path("service.py"), 1, 2),),
        endpoints=(_seed(),),
    )

    assert result.evidence == ()
    assert any("ambiguous endpoint binding" in item for item in result.limitations)


@pytest.mark.parametrize(
    ("strength", "expected_confidence"),
    [("INFERRED", "MEDIUM"), ("AMBIGUOUS", "LOW")],
)
def test_extractor_strength_stays_distinct_from_overlay_confidence(
    tmp_path: Path, strength: str, expected_confidence: str
) -> None:
    root = _write_project(tmp_path / "target")
    graph = tmp_path / "graph.json"
    _graph(graph, edge_strength=strength)
    result = traverse_graphify_snapshot(
        _load(root, graph),
        project_root=root,
        changed_ranges=(ChangedSourceRange(Path("service.py"), 1, 2),),
        endpoints=(_seed(),),
    )
    assert result.evidence[0].extractor_strengths == (strength, strength)
    assert result.evidence[0].confidence == expected_confidence


def test_capped_traversal_returns_explicit_limitation(tmp_path: Path) -> None:
    root = _write_project(tmp_path / "target")
    graph = tmp_path / "graph.json"
    _graph(graph)
    result = traverse_graphify_snapshot(
        _load(root, graph),
        project_root=root,
        changed_ranges=(ChangedSourceRange(Path("service.py"), 1, 2),),
        endpoints=(_seed(),),
        max_visited_nodes=1,
    )
    assert result.evidence == ()
    assert result.visited_nodes == 1
    assert result.limitations == ("maximum visited-node cap reached (1)",)


def test_rejects_invalid_ranges_and_traversal_bounds() -> None:
    with pytest.raises(ValueError, match="positive and ordered"):
        ChangedSourceRange(Path("x.py"), 3, 2)
