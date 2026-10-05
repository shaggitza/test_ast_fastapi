"""Evidence-only reverse traversal over validated, offline Graphify snapshots.

This module is an opt-in overlay primitive. It never invokes Graphify and does
not participate in default endpoint analysis.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from fastapi_endpoint_detector.models.endpoint import EndpointDiscoveryStatus

if TYPE_CHECKING:
    from fastapi_endpoint_detector.analyzer.graphify_adapter import (
        GraphifyEdge,
        GraphifyNode,
        GraphifySnapshot,
        GraphifySourceSpan,
        GraphifyStrength,
        GraphSide,
    )
    from fastapi_endpoint_detector.models.endpoint import Endpoint

GraphConfidence = Literal["HIGH", "MEDIUM", "LOW"]
_EVIDENCE_RELATIONS = frozenset({"calls", "imports", "imports_from", "inherits", "references"})


@dataclass(frozen=True)
class ChangedSourceRange:
    """One changed source range in the baseline or target tree."""

    file_path: Path
    start_line: int
    end_line: int

    def __post_init__(self) -> None:
        if self.start_line < 1 or self.end_line < self.start_line:
            raise ValueError("changed source range must be positive and ordered")


@dataclass(frozen=True)
class GraphEndpointSeed:
    """Securely discovered endpoint identity supplied by the caller."""

    endpoint_id: str
    handler_name: str
    file_path: Path
    start_line: int
    end_line: int
    discovery_status: EndpointDiscoveryStatus

    @classmethod
    def from_endpoint(cls, endpoint: Endpoint) -> GraphEndpointSeed:
        """Adapt an existing secure endpoint without re-discovering its identity."""
        handler = endpoint.handler
        return cls(
            endpoint.identifier,
            handler.name,
            handler.file_path,
            handler.line_number,
            handler.end_line_number or handler.line_number,
            endpoint.discovery_status,
        )


@dataclass(frozen=True)
class GraphPathEvidence:
    """One auditable path from a changed node to a secure endpoint handler."""

    side: GraphSide
    endpoint_id: str
    discovery_status: EndpointDiscoveryStatus
    changed_node_id: str
    endpoint_node_id: str
    node_path: tuple[str, ...]
    node_source_spans: tuple[GraphifySourceSpan | None, ...]
    edge_source_spans: tuple[GraphifySourceSpan | None, ...]
    relations: tuple[str, ...]
    extractor_strengths: tuple[GraphifyStrength, ...]
    confidence: GraphConfidence
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class GraphTraversalResult:
    """Evidence and explicit limits for one bounded snapshot traversal."""

    side: GraphSide
    evidence: tuple[GraphPathEvidence, ...]
    limitations: tuple[str, ...]
    visited_nodes: int


@dataclass(frozen=True)
class GraphTraversalPair:
    """Independent baseline and target evidence results for one change."""

    baseline: GraphTraversalResult
    target: GraphTraversalResult


@dataclass(frozen=True)
class _Walk:
    node_id: str
    node_path: tuple[str, ...]
    edges: tuple[GraphifyEdge, ...]


@dataclass(frozen=True)
class _EndpointBinding:
    seed: GraphEndpointSeed
    line_only: bool


def _overlaps(left_start: int, left_end: int, right_start: int, right_end: int) -> bool:
    return left_start <= right_end and right_start <= left_end


def _confidence(
    strengths: tuple[GraphifyStrength, ...], discovery: EndpointDiscoveryStatus
) -> GraphConfidence:
    if discovery == EndpointDiscoveryStatus.CONDITIONAL or "AMBIGUOUS" in strengths:
        return "LOW"
    if "INFERRED" in strengths:
        return "MEDIUM"
    return "HIGH"


def _endpoint_bindings(
    nodes: tuple[GraphifyNode, ...],
    seeds: tuple[GraphEndpointSeed, ...],
    project_root: Path,
    *,
    graph_schema_version: int,
) -> tuple[dict[str, _EndpointBinding], set[str]]:
    bindings: dict[str, _EndpointBinding] = {}
    ambiguous: set[str] = set()
    for seed in seeds:
        path = _relative_path(seed.file_path, project_root)
        exact_matches = [
            node
            for node in nodes
            if node.source_file == path
            and node.label == seed.handler_name
            and node.span is not None
            and node.span.file_path == path
            and node.span.start_line == seed.start_line
            and node.span.end_line == seed.end_line
        ]
        if graph_schema_version == 2:
            # The explicit raw Graphify schema only carries line markers. Keep
            # the marker intact and use containment solely to associate it
            # with a secure range; never widen it into a function span.
            matches = [
                node
                for node in nodes
                if node.source_file == path
                and node.label == seed.handler_name
                and node.span is not None
                and node.span.file_path == path
                and node.span.start_line == node.span.end_line
                and seed.start_line <= node.span.start_line <= seed.end_line
            ]
            line_only = True
        else:
            matches = exact_matches
            line_only = False
        if len(matches) == 1:
            bindings[matches[0].node_id] = _EndpointBinding(seed, line_only)
        elif len(matches) > 1:
            ambiguous.add(seed.endpoint_id)
    return bindings, ambiguous


def _relative_path(path_value: Path, project_root: Path) -> Path:
    path = Path(path_value)
    if path.is_absolute():
        try:
            return path.resolve(strict=False).relative_to(project_root.resolve(strict=False))
        except ValueError:
            return path
    return path


def traverse_graphify_snapshot(  # noqa: PLR0912
    snapshot: GraphifySnapshot,
    *,
    project_root: Path,
    changed_ranges: tuple[ChangedSourceRange, ...],
    endpoints: tuple[GraphEndpointSeed, ...],
    max_depth: int = 64,
    max_visited_nodes: int = 50_000,
) -> GraphTraversalResult:
    """Find securely identified endpoints reachable by reverse evidence paths.

    The graph is walked from changed source occurrences against incoming,
    source-backed calls/imports/inheritance/references. Community,
    similarity, containment, labels alone, and unlocated links never fan out.
    """
    if max_depth < 0 or max_visited_nodes < 1:
        raise ValueError("traversal bounds must be non-negative depth and positive node cap")
    starts = {
        node.node_id
        for node in snapshot.nodes
        if node.span is not None
        and any(
            node.source_file == _relative_path(changed.file_path, project_root)
            and _overlaps(
                node.span.start_line,
                node.span.end_line,
                changed.start_line,
                changed.end_line,
            )
            for changed in changed_ranges
        )
    }
    reverse: dict[str, list[GraphifyEdge]] = {}
    for edge in snapshot.edges:
        if edge.traversable and edge.relation in _EVIDENCE_RELATIONS:
            reverse.setdefault(edge.target_id, []).append(edge)
    endpoint_by_node, ambiguous_endpoints = _endpoint_bindings(
        snapshot.nodes,
        endpoints,
        project_root,
        graph_schema_version=snapshot.graph_schema_version,
    )
    limitations: list[str] = []
    for endpoint in endpoints:
        if endpoint.endpoint_id not in ambiguous_endpoints and not any(
            item.seed.endpoint_id == endpoint.endpoint_id for item in endpoint_by_node.values()
        ):
            limitations.append(
                f"LOW; endpoint did not bind uniquely and was not traversed: {endpoint.endpoint_id}"
            )
    for endpoint_id in sorted(ambiguous_endpoints):
        limitations.append(f"ambiguous endpoint binding (LOW, not guessed): {endpoint_id}")

    queue = deque(_Walk(node_id, (node_id,), ()) for node_id in sorted(starts))
    nodes_by_id = {node.node_id: node for node in snapshot.nodes}
    visited_depth: dict[str, int] = {}
    evidence: dict[tuple[str, str, tuple[str, ...]], GraphPathEvidence] = {}
    capped = False
    while queue:
        walk = queue.popleft()
        depth = len(walk.edges)
        previous_depth = visited_depth.get(walk.node_id)
        if previous_depth is not None and previous_depth <= depth:
            continue
        if len(visited_depth) >= max_visited_nodes:
            capped = True
            break
        visited_depth[walk.node_id] = depth
        binding = endpoint_by_node.get(walk.node_id)
        if binding is not None:
            endpoint_seed = binding.seed
            strengths = tuple(edge.extractor_strength for edge in walk.edges)
            node_spans = tuple(nodes_by_id[node_id].span for node_id in walk.node_path)
            edge_spans = tuple(edge.span for edge in walk.edges)
            line_only_spans = (
                tuple(
                    span
                    for span in (*node_spans, *edge_spans)
                    if span is not None and span.start_line == span.end_line
                )
                if snapshot.graph_schema_version == 2
                else ()
            )
            path_limitations = tuple(
                dict.fromkeys(
                    "line-only Graphify location retained without widening or confidence "
                    "promotion: "
                    f"{span.file_path}:L{span.start_line}"
                    for span in line_only_spans
                )
            )
            item = GraphPathEvidence(
                snapshot.side,
                endpoint_seed.endpoint_id,
                endpoint_seed.discovery_status,
                walk.node_path[0],
                walk.node_id,
                walk.node_path,
                node_spans,
                edge_spans,
                tuple(edge.relation for edge in walk.edges),
                strengths,
                (
                    "LOW"
                    if binding.line_only or line_only_spans
                    else _confidence(strengths, endpoint_seed.discovery_status)
                ),
                path_limitations,
            )
            evidence[(endpoint_seed.endpoint_id, item.changed_node_id, item.node_path)] = item
            limitations.extend(path_limitations)
        if depth >= max_depth:
            if reverse.get(walk.node_id):
                limitations.append(f"maximum traversal depth reached at {walk.node_id}")
            continue
        for edge in sorted(
            reverse.get(walk.node_id, ()), key=lambda item: (item.source_id, item.relation)
        ):
            queue.append(
                _Walk(
                    edge.source_id,
                    (*walk.node_path, edge.source_id),
                    (*walk.edges, edge),
                )
            )
    if capped:
        limitations.append(f"maximum visited-node cap reached ({max_visited_nodes})")
    return GraphTraversalResult(
        snapshot.side,
        tuple(evidence[key] for key in sorted(evidence)),
        tuple(dict.fromkeys(limitations)),
        len(visited_depth),
    )


def traverse_graphify_sides(
    baseline_snapshot: GraphifySnapshot,
    target_snapshot: GraphifySnapshot,
    *,
    baseline_project_root: Path,
    target_project_root: Path,
    baseline_changed_ranges: tuple[ChangedSourceRange, ...],
    target_changed_ranges: tuple[ChangedSourceRange, ...],
    baseline_endpoints: tuple[GraphEndpointSeed, ...],
    target_endpoints: tuple[GraphEndpointSeed, ...],
    max_depth: int = 64,
    max_visited_nodes: int = 50_000,
) -> GraphTraversalPair:
    """Traverse baseline and target snapshots with side-specific source inputs."""
    if baseline_snapshot.side != "baseline" or target_snapshot.side != "target":
        raise ValueError("snapshots must be supplied in baseline, target order")
    return GraphTraversalPair(
        baseline=traverse_graphify_snapshot(
            baseline_snapshot,
            project_root=baseline_project_root,
            changed_ranges=baseline_changed_ranges,
            endpoints=baseline_endpoints,
            max_depth=max_depth,
            max_visited_nodes=max_visited_nodes,
        ),
        target=traverse_graphify_snapshot(
            target_snapshot,
            project_root=target_project_root,
            changed_ranges=target_changed_ranges,
            endpoints=target_endpoints,
            max_depth=max_depth,
            max_visited_nodes=max_visited_nodes,
        ),
    )
