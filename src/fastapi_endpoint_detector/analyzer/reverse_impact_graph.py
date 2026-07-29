"""Bounded snapshot-local graph primitives for reverse impact analysis.

This module is intentionally not wired into the default mypy backend yet.  It
provides a deterministic, occurrence-sensitive IR and a fail-closed reverse
traversal that can be populated by the existing analyzer during parity work.
"""

from __future__ import annotations

import hashlib
import heapq
import json
from dataclasses import dataclass
from enum import Enum
from itertools import islice
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

_GRAPH_SCHEMA_VERSION = 1


class ReverseImpactGraphError(ValueError):
    """Raised when graph construction would be ambiguous or exceed a bound."""


class GraphSide(str, Enum):
    """Source snapshot represented by a graph occurrence."""

    BASELINE = "baseline"
    TARGET = "target"


@dataclass(frozen=True, slots=True, order=True)
class GraphOccurrence:
    """One source occurrence; paths are normalized for stable identities."""

    file_path: str
    line: int
    column: int = 0
    end_line: int | None = None
    end_column: int | None = None

    def __post_init__(self) -> None:
        if self.line < 1 or self.column < 0:
            raise ReverseImpactGraphError("occurrence line/column must be non-negative")
        if self.end_line is not None and self.end_line < self.line:
            raise ReverseImpactGraphError("occurrence end line precedes its start")
        if self.end_column is not None and self.end_column < 0:
            raise ReverseImpactGraphError("occurrence end column must be non-negative")
        if (
            self.end_line == self.line
            and self.end_column is not None
            and self.end_column < self.column
        ):
            raise ReverseImpactGraphError("occurrence end column precedes its start")
        normalized_path = PurePosixPath(self.file_path.replace("\\", "/"))
        normalized = str(normalized_path)
        if normalized in {"", "."} or normalized.startswith("/") or ".." in normalized_path.parts:
            raise ReverseImpactGraphError("occurrence path must be repository-relative")
        object.__setattr__(self, "file_path", normalized)

    def as_tuple(self) -> tuple[str, int, int, int | None, int | None]:
        """Return a canonical occurrence key."""
        return self.file_path, self.line, self.column, self.end_line, self.end_column


@dataclass(frozen=True, slots=True, order=True)
class ReverseImpactNode:
    """A typed symbol occurrence in one source snapshot."""

    node_id: str
    side: GraphSide
    kind: str
    qualified_name: str
    occurrence: GraphOccurrence

    @classmethod
    def create(
        cls,
        *,
        side: GraphSide,
        kind: str,
        qualified_name: str,
        occurrence: GraphOccurrence,
    ) -> ReverseImpactNode:
        """Create a node whose stable ID preserves its physical occurrence."""
        if not kind or not qualified_name:
            raise ReverseImpactGraphError("node kind and qualified name are required")
        identity = json.dumps(
            [side.value, kind, qualified_name, *occurrence.as_tuple()],
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode()
        node_id = hashlib.sha256(identity).hexdigest()
        return cls(
            node_id=node_id,
            side=side,
            kind=kind,
            qualified_name=qualified_name,
            occurrence=occurrence,
        )


@dataclass(frozen=True, slots=True, order=True)
class ReverseImpactEdge:
    """A directed evidence edge from caller/owner to referenced target."""

    source_id: str
    target_id: str
    kind: str
    occurrence: GraphOccurrence

    def __post_init__(self) -> None:
        if not self.source_id or not self.target_id or not self.kind:
            raise ReverseImpactGraphError("edge source, target, and kind are required")

    @property
    def edge_id(self) -> str:
        """Return an occurrence-sensitive deterministic edge identity."""
        identity = json.dumps(
            [self.source_id, self.target_id, self.kind, *self.occurrence.as_tuple()],
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode()
        return hashlib.sha256(identity).hexdigest()


@dataclass(frozen=True, slots=True)
class ReverseImpactProvenance:
    """Inputs that must match before a persisted graph can be reused."""

    provider: str
    provider_version: str
    snapshot_sha256: str
    configuration_sha256: str
    schema_version: int = _GRAPH_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != _GRAPH_SCHEMA_VERSION:
            raise ReverseImpactGraphError(
                f"unsupported reverse-impact graph schema: {self.schema_version}"
            )
        for name, value in (
            ("provider", self.provider),
            ("provider_version", self.provider_version),
            ("snapshot_sha256", self.snapshot_sha256),
            ("configuration_sha256", self.configuration_sha256),
        ):
            if not value:
                raise ReverseImpactGraphError(f"graph provenance {name} is required")


@dataclass(frozen=True, slots=True)
class ReverseImpactCaps:
    """Private deterministic resource limits for construction and traversal."""

    max_nodes: int = 50_000
    max_edges: int = 200_000
    max_paths_per_seed: int = 64
    max_path_length: int = 64
    max_traversal_steps: int = 100_000

    def __post_init__(self) -> None:
        for name, value in (
            ("max_nodes", self.max_nodes),
            ("max_edges", self.max_edges),
            ("max_paths_per_seed", self.max_paths_per_seed),
            ("max_path_length", self.max_path_length),
            ("max_traversal_steps", self.max_traversal_steps),
        ):
            if type(value) is not int or value < 1:
                raise ReverseImpactGraphError(f"{name} must be a positive integer")


@dataclass(frozen=True, slots=True, order=True)
class ReverseImpactPath:
    """One seed-to-handler path, stored in reverse traversal order."""

    seed_id: str
    handler_id: str
    node_ids: tuple[str, ...]
    edge_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReverseImpactResult:
    """Bounded paths and explicit limitations for one changed-symbol seed."""

    seed_id: str
    paths: tuple[ReverseImpactPath, ...]
    truncated: bool = False
    limitations: tuple[str, ...] = ()


class ReverseImpactGraph:
    """Immutable occurrence graph supporting deterministic reverse traversal."""

    def __init__(
        self,
        *,
        nodes: Iterable[ReverseImpactNode],
        edges: Iterable[ReverseImpactEdge],
        handler_node_ids: Iterable[str],
        provenance: ReverseImpactProvenance,
        caps: ReverseImpactCaps | None = None,
    ) -> None:
        self.provenance = provenance
        self.caps = caps or ReverseImpactCaps()
        materialized_nodes = tuple(islice(nodes, self.caps.max_nodes + 1))
        materialized_edges = tuple(islice(edges, self.caps.max_edges + 1))
        if len(materialized_nodes) > self.caps.max_nodes:
            raise ReverseImpactGraphError("reverse-impact node limit exceeded")
        if len(materialized_edges) > self.caps.max_edges:
            raise ReverseImpactGraphError("reverse-impact edge limit exceeded")

        ordered_nodes = tuple(sorted(materialized_nodes, key=lambda item: item.node_id))
        node_by_id = {node.node_id: node for node in ordered_nodes}
        if len(node_by_id) != len(ordered_nodes):
            raise ReverseImpactGraphError("duplicate reverse-impact node identity")

        ordered_edges = tuple(sorted(materialized_edges, key=lambda item: item.edge_id))
        edge_ids = {edge.edge_id for edge in ordered_edges}
        if len(edge_ids) != len(ordered_edges):
            raise ReverseImpactGraphError("duplicate reverse-impact edge identity")
        incoming: dict[str, list[ReverseImpactEdge]] = {}
        for edge in ordered_edges:
            source = node_by_id.get(edge.source_id)
            target = node_by_id.get(edge.target_id)
            if source is None or target is None:
                raise ReverseImpactGraphError("reverse-impact edge references an unknown node")
            if source.side != target.side:
                raise ReverseImpactGraphError("reverse-impact edges cannot cross snapshot sides")
            incoming.setdefault(edge.target_id, []).append(edge)

        materialized_handlers = tuple(islice(handler_node_ids, self.caps.max_nodes + 1))
        if len(materialized_handlers) > self.caps.max_nodes:
            raise ReverseImpactGraphError("handler mapping limit exceeded")
        handlers = frozenset(materialized_handlers)
        if not handlers <= node_by_id.keys():
            raise ReverseImpactGraphError("handler mapping references an unknown node")

        self.nodes = ordered_nodes
        self.edges = ordered_edges
        self.handler_node_ids = handlers
        self._node_by_id = node_by_id
        self._incoming = {
            node_id: tuple(sorted(items, key=lambda item: item.edge_id))
            for node_id, items in incoming.items()
        }

    def _query_handlers(self, handler_node_ids: Iterable[str] | None) -> frozenset[str]:
        if handler_node_ids is None:
            return self.handler_node_ids
        materialized = tuple(islice(handler_node_ids, self.caps.max_nodes + 1))
        if len(materialized) > self.caps.max_nodes:
            raise ReverseImpactGraphError("query handler mapping limit exceeded")
        handlers = frozenset(materialized)
        if not handlers <= self._node_by_id.keys():
            raise ReverseImpactGraphError("query handler mapping references an unknown node")
        return handlers

    def reverse_paths(
        self,
        seed_id: str,
        *,
        handler_node_ids: Iterable[str] | None = None,
    ) -> ReverseImpactResult:
        """Return bounded simple paths from a changed seed to mapped handlers."""
        if seed_id not in self._node_by_id:
            raise ReverseImpactGraphError(f"unknown reverse-impact seed: {seed_id}")
        handlers = self._query_handlers(handler_node_ids)

        # Heap ordering makes results independent of insertion and hash order.
        work: list[tuple[int, tuple[str, ...], tuple[str, ...]]] = [(0, (seed_id,), ())]
        paths: list[ReverseImpactPath] = []
        limitations: set[str] = set()
        steps = 0
        truncated = False
        while work:
            _length, node_path, edge_path = heapq.heappop(work)
            current = node_path[-1]
            if current in handlers:
                paths.append(
                    ReverseImpactPath(
                        seed_id=seed_id,
                        handler_id=current,
                        node_ids=node_path,
                        edge_ids=edge_path,
                    )
                )
                if len(paths) >= self.caps.max_paths_per_seed:
                    if work:
                        limitations.add("reverse-impact path count limit reached")
                        truncated = True
                    break
                continue
            incoming = self._incoming.get(current, ())
            for edge in incoming:
                steps += 1
                if steps > self.caps.max_traversal_steps:
                    limitations.add("reverse-impact traversal work limit reached")
                    truncated = True
                    work.clear()
                    break
                predecessor = edge.source_id
                if predecessor in node_path:
                    # SCC/cycle edge: simple paths terminate rather than looping.
                    continue
                if len(node_path) >= self.caps.max_path_length:
                    limitations.add("reverse-impact path length limit reached")
                    truncated = True
                    continue
                next_nodes = (*node_path, predecessor)
                next_edges = (*edge_path, edge.edge_id)
                heapq.heappush(work, (len(next_nodes), next_nodes, next_edges))

        return ReverseImpactResult(
            seed_id=seed_id,
            paths=tuple(sorted(set(paths))),
            truncated=truncated,
            limitations=tuple(sorted(limitations)),
        )

    def cache_fingerprint(self) -> str:
        """Return a deterministic cache key over provenance and graph contents."""
        payload = {
            "schema_version": self.provenance.schema_version,
            "provider": self.provenance.provider,
            "provider_version": self.provenance.provider_version,
            "snapshot_sha256": self.provenance.snapshot_sha256,
            "configuration_sha256": self.provenance.configuration_sha256,
            "nodes": [
                [
                    node.node_id,
                    node.side.value,
                    node.kind,
                    node.qualified_name,
                    *node.occurrence.as_tuple(),
                ]
                for node in self.nodes
            ],
            "edges": [
                [
                    edge.edge_id,
                    edge.source_id,
                    edge.target_id,
                    edge.kind,
                    *edge.occurrence.as_tuple(),
                ]
                for edge in self.edges
            ],
            "handlers": sorted(self.handler_node_ids),
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()
