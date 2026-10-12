"""Evidence-only reverse traversal over validated, offline Graphify snapshots.

This module is an opt-in overlay primitive. It never invokes Graphify and does
not participate in default endpoint analysis.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, replace
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
_MAX_PATH_WITNESS_STATES = 100_000
_DEFAULT_MAX_QUEUED_WITNESSES = 10_000
_EdgeWitnessKey = tuple[str, str, str, str, int, int, str, str, str, str, str, str]
_PathWitnessKey = tuple[str, tuple[str, ...], tuple[_EdgeWitnessKey, ...]]


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
    binding_identity: str = "handler"
    binding_kind: Literal["handler", "dependency"] = "handler"
    confidence_ceiling: Literal["MEDIUM", "LOW"] | None = None

    def __post_init__(self) -> None:
        if not self.endpoint_id or not self.binding_identity:
            raise ValueError("endpoint and binding identities must be non-empty")
        if self.binding_kind not in {"handler", "dependency"}:
            raise ValueError("unsupported endpoint binding kind")

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
    edge_keys: tuple[int | str | None, ...] = ()
    edge_context_identities: tuple[str | None, ...] = ()
    incomplete: bool = False
    binding_identity: str = "handler"
    binding_kind: Literal["handler", "dependency"] = "handler"


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


def _apply_confidence_ceiling(
    confidence: GraphConfidence,
    ceiling: Literal["MEDIUM", "LOW"] | None,
) -> GraphConfidence:
    if ceiling == "LOW":
        return "LOW"
    if ceiling == "MEDIUM" and confidence == "HIGH":
        return "MEDIUM"
    return confidence


def _endpoint_bindings(
    nodes: tuple[GraphifyNode, ...],
    seeds: tuple[GraphEndpointSeed, ...],
    project_root: Path,
    *,
    graph_schema_version: int,
) -> tuple[dict[str, tuple[_EndpointBinding, ...]], set[str]]:
    bindings: dict[str, list[_EndpointBinding]] = {}
    ambiguous: set[str] = set()
    seeds_by_id: dict[tuple[str, str], GraphEndpointSeed] = {}
    statuses_by_endpoint: dict[str, EndpointDiscoveryStatus] = {}
    for seed in seeds:
        prior_status = statuses_by_endpoint.setdefault(seed.endpoint_id, seed.discovery_status)
        if prior_status != seed.discovery_status:
            raise ValueError(f"conflicting endpoint seeds share endpoint_id: {seed.endpoint_id}")
        seed_key = (seed.endpoint_id, seed.binding_identity)
        prior_seed = seeds_by_id.get(seed_key)
        if prior_seed is not None:
            if prior_seed != seed:
                raise ValueError(
                    "conflicting endpoint seeds share endpoint and binding identities: "
                    f"{seed.endpoint_id}/{seed.binding_identity}"
                )
            continue
        seeds_by_id[seed_key] = seed
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
            bindings.setdefault(matches[0].node_id, []).append(_EndpointBinding(seed, line_only))
        elif len(matches) > 1:
            ambiguous.add(seed.endpoint_id)
    return {
        node_id: tuple(
            sorted(
                node_bindings,
                key=lambda item: (
                    item.seed.endpoint_id,
                    item.seed.binding_identity,
                    item.seed.discovery_status.value,
                ),
            )
        )
        for node_id, node_bindings in bindings.items()
    }, ambiguous


def _edge_key(edge: GraphifyEdge) -> int | str | None:
    value = getattr(edge, "edge_key", None)
    if isinstance(value, bool) or not isinstance(value, (int, str, type(None))):
        return None
    return value


def _edge_context_identity(edge: GraphifyEdge) -> str | None:
    value = getattr(edge, "context_identity", None)
    if value is not None and not isinstance(value, str):
        raise ValueError("Graphify edge context_identity must be a string or null")
    return value


def _edge_witness_key(edge: GraphifyEdge) -> _EdgeWitnessKey:
    span = edge.span
    if span is None:
        source_file, start_line, end_line, source_sha256 = "", -1, -1, ""
    else:
        source_file = span.file_path.as_posix()
        start_line, end_line = span.start_line, span.end_line
        source_sha256 = span.source_sha256
    key = _edge_key(edge)
    context_identity = _edge_context_identity(edge)
    return (
        edge.source_id,
        edge.target_id,
        edge.relation,
        source_file,
        start_line,
        end_line,
        source_sha256,
        type(key).__name__,
        "" if key is None else str(key),
        edge.extractor_strength,
        type(context_identity).__name__,
        "" if context_identity is None else context_identity,
    )


def _relative_path(path_value: Path, project_root: Path) -> Path:
    path = Path(path_value)
    if path.is_absolute():
        try:
            return path.resolve(strict=False).relative_to(project_root.resolve(strict=False))
        except ValueError:
            return path
    return path


def traverse_graphify_snapshot(  # noqa: PLR0912, PLR0915
    snapshot: GraphifySnapshot,
    *,
    project_root: Path,
    changed_ranges: tuple[ChangedSourceRange, ...],
    endpoints: tuple[GraphEndpointSeed, ...],
    max_depth: int = 64,
    max_visited_nodes: int = 50_000,
    max_queued_witnesses: int = _DEFAULT_MAX_QUEUED_WITNESSES,
) -> GraphTraversalResult:
    """Find securely identified endpoints reachable by reverse evidence paths.

    The graph is walked from changed source occurrences against incoming,
    source-backed calls/imports/inheritance/references. Community,
    similarity, containment, labels alone, and unlocated links never fan out.
    """
    if max_depth < 0 or max_visited_nodes < 1 or max_queued_witnesses < 1:
        raise ValueError(
            "traversal bounds must be non-negative depth and positive node and queue caps"
        )
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
            binding.seed.endpoint_id == endpoint.endpoint_id
            for node_bindings in endpoint_by_node.values()
            for binding in node_bindings
        ):
            limitations.append(
                f"LOW; endpoint did not bind uniquely and was not traversed: {endpoint.endpoint_id}"
            )
    for endpoint_id in sorted(ambiguous_endpoints):
        limitations.append(f"ambiguous endpoint binding (LOW, not guessed): {endpoint_id}")

    queue: deque[_Walk] = deque()
    scheduled_witnesses: set[_PathWitnessKey] = set()

    def enqueue(walk: _Walk) -> bool:
        key = (walk.node_id, walk.node_path, tuple(_edge_witness_key(edge) for edge in walk.edges))
        if key in scheduled_witnesses:
            return True
        if len(queue) >= max_queued_witnesses:
            return False
        scheduled_witnesses.add(key)
        queue.append(walk)
        return True

    frontier_capped = False
    for node_id in sorted(starts):
        if not enqueue(_Walk(node_id, (node_id,), ())):
            frontier_capped = True
            break
    nodes_by_id = {node.node_id: node for node in snapshot.nodes}
    visited_depth: dict[str, int] = {}
    visited_witnesses: set[_PathWitnessKey] = set()
    evidence: dict[
        tuple[str, str, str, tuple[str, ...], tuple[_EdgeWitnessKey, ...]], GraphPathEvidence
    ] = {}
    node_capped = False
    witness_capped = False
    depth_truncated = False
    while queue:
        walk = queue.popleft()
        depth = len(walk.edges)
        edge_witness = tuple(_edge_witness_key(edge) for edge in walk.edges)
        witness_key = (walk.node_id, walk.node_path, edge_witness)
        if witness_key in visited_witnesses:
            continue
        if len(visited_witnesses) >= _MAX_PATH_WITNESS_STATES:
            witness_capped = True
            break
        if walk.node_id not in visited_depth and len(visited_depth) >= max_visited_nodes:
            node_capped = True
            break
        visited_witnesses.add(witness_key)
        previous_depth = visited_depth.get(walk.node_id)
        if previous_depth is None or depth < previous_depth:
            visited_depth[walk.node_id] = depth
        bindings = endpoint_by_node.get(walk.node_id, ())
        for binding in bindings:
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
            confidence = (
                "LOW"
                if binding.line_only or line_only_spans
                else _confidence(strengths, endpoint_seed.discovery_status)
            )
            confidence = _apply_confidence_ceiling(confidence, endpoint_seed.confidence_ceiling)
            item = GraphPathEvidence(
                side=snapshot.side,
                endpoint_id=endpoint_seed.endpoint_id,
                discovery_status=endpoint_seed.discovery_status,
                changed_node_id=walk.node_path[0],
                endpoint_node_id=walk.node_id,
                node_path=walk.node_path,
                node_source_spans=node_spans,
                edge_source_spans=edge_spans,
                relations=tuple(edge.relation for edge in walk.edges),
                extractor_strengths=strengths,
                confidence=confidence,
                limitations=path_limitations,
                edge_keys=tuple(_edge_key(edge) for edge in walk.edges),
                edge_context_identities=tuple(_edge_context_identity(edge) for edge in walk.edges),
                binding_identity=endpoint_seed.binding_identity,
                binding_kind=endpoint_seed.binding_kind,
            )
            evidence[
                (
                    endpoint_seed.endpoint_id,
                    endpoint_seed.binding_identity,
                    item.changed_node_id,
                    item.node_path,
                    edge_witness,
                )
            ] = item
            limitations.extend(path_limitations)
        available_edges: list[GraphifyEdge] = []
        for edge in reverse.get(walk.node_id, ()):
            if edge.source_id in walk.node_path:
                limitations.append(
                    f"cycle edge skipped: {edge.source_id}->{edge.target_id} ({edge.relation})"
                )
            else:
                available_edges.append(edge)
        if depth >= max_depth:
            if available_edges:
                depth_truncated = True
                limitations.append(f"maximum traversal depth reached at {walk.node_id}")
            continue
        for edge in sorted(available_edges, key=_edge_witness_key):
            if not enqueue(
                _Walk(
                    edge.source_id,
                    (*walk.node_path, edge.source_id),
                    (*walk.edges, edge),
                )
            ):
                frontier_capped = True
    if node_capped:
        limitations.append(f"maximum visited-node cap reached ({max_visited_nodes})")
    if witness_capped:
        limitations.append(f"maximum path-witness state cap reached ({_MAX_PATH_WITNESS_STATES})")
    if frontier_capped:
        limitations.append(
            "maximum queued path-witness cap reached "
            f"({max_queued_witnesses}); some witnesses were not scheduled"
        )
    incomplete = node_capped or witness_capped or frontier_capped or depth_truncated
    evidence_items = tuple(evidence[key] for key in sorted(evidence))
    if incomplete:
        evidence_items = tuple(
            replace(
                item,
                confidence="LOW",
                incomplete=True,
                limitations=(
                    *item.limitations,
                    "traversal incomplete; evidence confidence capped LOW",
                ),
            )
            for item in evidence_items
        )
    return GraphTraversalResult(
        snapshot.side,
        evidence_items,
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
    max_queued_witnesses: int = _DEFAULT_MAX_QUEUED_WITNESSES,
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
            max_queued_witnesses=max_queued_witnesses,
        ),
        target=traverse_graphify_snapshot(
            target_snapshot,
            project_root=target_project_root,
            changed_ranges=target_changed_ranges,
            endpoints=target_endpoints,
            max_depth=max_depth,
            max_visited_nodes=max_visited_nodes,
            max_queued_witnesses=max_queued_witnesses,
        ),
    )
