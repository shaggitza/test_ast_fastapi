"""Adapt secure endpoint, route, and dependency evidence into Graphify seeds.

This adapter reads already-discovered endpoint identities. It does not import
application code, execute Graphify, or infer route/dependency registrations.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi_endpoint_detector.analyzer.graphify_analyzer import (
    ChangedSourceRange,
    GraphEndpointSeed,
)
from fastapi_endpoint_detector.models.endpoint import (
    DependencyGraphStatus,
    DependencyResolutionStatus,
    Endpoint,
    EndpointDiscoveryStatus,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from fastapi_endpoint_detector.analyzer.graphify_adapter import GraphifySnapshot
    from fastapi_endpoint_detector.analyzer.source_inventory import SourceInventory
    from fastapi_endpoint_detector.models.diff import DiffFile


@dataclass(frozen=True)
class GraphifyEndpointInputs:
    """Secure route/DI seeds and explicit omissions for one source snapshot."""

    seeds: tuple[GraphEndpointSeed, ...]
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class GraphifyChangedRanges:
    """Side-qualified changed lines translated from parsed Git diff records."""

    baseline: tuple[ChangedSourceRange, ...]
    target: tuple[ChangedSourceRange, ...]
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class GraphifyScopedSnapshot:
    """Snapshot view restricted to one canonical side-specific inventory."""

    snapshot: GraphifySnapshot
    module_names: tuple[tuple[Path, str | None], ...]
    limitations: tuple[str, ...]


def _line_ranges(file_path: Path, lines: Iterable[int]) -> tuple[ChangedSourceRange, ...]:
    ordered = sorted(set(lines))
    if not ordered:
        return ()
    ranges: list[ChangedSourceRange] = []
    start = previous = ordered[0]
    for line in ordered[1:]:
        if line != previous + 1:
            ranges.append(ChangedSourceRange(file_path, start, previous))
            start = line
        previous = line
    ranges.append(ChangedSourceRange(file_path, start, previous))
    return tuple(ranges)


def build_graphify_changed_ranges(diff_files: Iterable[DiffFile]) -> GraphifyChangedRanges:
    """Keep removed coordinates on baseline and additions on target only."""
    baseline: list[ChangedSourceRange] = []
    target: list[ChangedSourceRange] = []
    limitations: list[str] = []
    for diff_file in diff_files:
        removed, added = diff_file.get_side_qualified_lines()
        source_path = diff_file.source_path or diff_file.path
        baseline.extend(_line_ranges(source_path, removed))
        target.extend(_line_ranges(diff_file.path, added))
        if not removed and not added:
            limitations.append(
                "file-level change has no line coordinates for Graphify traversal: "
                f"{source_path} -> {diff_file.path}"
            )
    return GraphifyChangedRanges(tuple(baseline), tuple(target), tuple(limitations))


def scope_graphify_snapshot_to_inventory(
    snapshot: GraphifySnapshot,
    inventory: SourceInventory,
) -> GraphifyScopedSnapshot:
    """Restrict graph traversal to the inventory's exact path/hash allowlist."""
    inventory_by_path = {Path(item.relative_path): item for item in inventory.files}
    ambiguous_modules = {module for module, _paths in inventory.module_collisions}
    module_names = tuple(
        (
            Path(item.relative_path),
            None if item.module in ambiguous_modules else item.module,
        )
        for item in inventory.files
    )
    limitations: list[str] = []
    admitted_nodes = {}
    for node in snapshot.nodes:
        source = inventory_by_path.get(node.source_file)
        if source is None:
            limitations.append(
                f"Graphify node outside canonical source inventory excluded: {node.source_file}"
            )
        elif source.sha256 != node.source_sha256:
            limitations.append(
                f"Graphify node source hash differs from canonical inventory; excluded: "
                f"{node.source_file}"
            )
        else:
            admitted_nodes[node.node_id] = node
    admitted_edges = []
    for edge in snapshot.edges:
        if edge.source_id not in admitted_nodes or edge.target_id not in admitted_nodes:
            limitations.append(
                f"Graphify edge touching an excluded inventory node omitted: "
                f"{edge.source_id}->{edge.target_id}"
            )
            continue
        if edge.span is not None:
            source = inventory_by_path.get(edge.span.file_path)
            if source is None:
                limitations.append(
                    "Graphify edge outside canonical source inventory excluded: "
                    f"{edge.span.file_path}"
                )
                continue
            if source.sha256 != edge.span.source_sha256:
                limitations.append(
                    "Graphify edge source hash differs from canonical inventory; excluded: "
                    f"{edge.span.file_path}"
                )
                continue
        admitted_edges.append(edge)
    for module, paths in inventory.module_collisions:
        limitations.append(
            f"canonical module identity {module!r} is ambiguous across: {', '.join(paths)}"
        )
    return GraphifyScopedSnapshot(
        snapshot=replace(
            snapshot,
            nodes=tuple(admitted_nodes.values()),
            edges=tuple(admitted_edges),
        ),
        module_names=module_names,
        limitations=tuple(dict.fromkeys(limitations)),
    )


def build_graphify_endpoint_inputs(endpoints: Iterable[Endpoint]) -> GraphifyEndpointInputs:
    """Create handler and exact declared-DI seeds from secure endpoint records.

    Dependency occurrences retain their endpoint identity and occurrence path.
    Conditional dependency inventories lower only their own seed confidence;
    unresolved or spanless dependencies are reported without guessed bindings.
    """
    seeds: list[GraphEndpointSeed] = []
    limitations: list[str] = []
    for endpoint in endpoints:
        seeds.append(GraphEndpointSeed.from_endpoint(endpoint))
        graph = endpoint.dependency_graph
        if graph is None:
            limitations.append(
                f"DI graph unavailable; no dependency seeds added for {endpoint.identifier}"
            )
            continue
        if graph.status == DependencyGraphStatus.UNAVAILABLE:
            limitations.append(
                f"DI graph unavailable; no dependency seeds added for {endpoint.identifier}"
            )
            continue
        if graph.status == DependencyGraphStatus.CONDITIONAL:
            limitations.extend(
                f"conditional DI graph for {endpoint.identifier}: {item.code}: {item.reason}"
                for item in graph.limitations
            )
        for occurrence in graph.occurrences:
            identity = "dependency:" + ".".join(map(str, occurrence.index_path))
            if (
                occurrence.resolution_status == DependencyResolutionStatus.UNAVAILABLE
                or occurrence.source_span is None
                or occurrence.qualname is None
            ):
                limitations.append(
                    "LOW; dependency occurrence has no exact callable source identity and was "
                    f"not seeded: {endpoint.identifier}/{identity}"
                )
                continue
            is_conditional = (
                graph.status == DependencyGraphStatus.CONDITIONAL
                or occurrence.resolution_status == DependencyResolutionStatus.CONDITIONAL
                or endpoint.discovery_status == EndpointDiscoveryStatus.CONDITIONAL
            )
            seeds.append(
                GraphEndpointSeed(
                    endpoint_id=endpoint.identifier,
                    handler_name=occurrence.qualname,
                    file_path=occurrence.source_span.file_path,
                    start_line=occurrence.source_span.start_line,
                    end_line=occurrence.source_span.end_line,
                    discovery_status=endpoint.discovery_status,
                    binding_identity=identity,
                    binding_kind="dependency",
                    confidence_ceiling="LOW" if is_conditional else None,
                )
            )
    return GraphifyEndpointInputs(tuple(seeds), tuple(dict.fromkeys(limitations)))
