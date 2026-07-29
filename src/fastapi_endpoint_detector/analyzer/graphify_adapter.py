"""Strict, offline-only adapter for pinned Graphify code-graph snapshots.

This module is deliberately not wired into the default analyzer. It never
installs or executes Graphify. It only imports an operator-supplied ``graph.json``
whose expected producer metadata and schema are pinned below. Execution remains
deferred to the trusted sandbox gate tracked by issue #101.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from fastapi_endpoint_detector.strict_data import load_json_unique

GRAPHIFY_PACKAGE_NAME = "graphifyy"
GRAPHIFY_PACKAGE_VERSION = "0.9.30"
GRAPHIFY_COMMAND_NAME = "graphify"
GRAPHIFY_EXPECTED_VERSION_OUTPUT = "graphify 0.9.30"
GRAPHIFY_GRAPH_SCHEMA_VERSION = 1
GRAPHIFY_EXPECTED_DIRECTED = True
GRAPHIFY_EXPECTED_MULTIGRAPH = True
MAX_GRAPH_BYTES = 64 * 1024 * 1024
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_GRAPH_NODES = 250_000
MAX_GRAPH_EDGES = 1_000_000
MAX_TEXT_LENGTH = 16_384

GraphSide = Literal["baseline", "target"]
GraphifyStrength = Literal["EXTRACTED", "INFERRED", "AMBIGUOUS"]
GraphifyRelationOrientation = Literal[
    "caller-to-callee",
    "importer-to-imported",
    "subclass-to-base",
    "referencer-to-referenced",
    "exporter-to-exported",
    "container-to-contained",
    "symmetric",
]

_RELATION_ORIENTATIONS: dict[str, GraphifyRelationOrientation] = {
    "calls": "caller-to-callee",
    "imports": "importer-to-imported",
    "imports_from": "importer-to-imported",
    "inherits": "subclass-to-base",
    "references": "referencer-to-referenced",
    "re_exports": "exporter-to-exported",
    "contains": "container-to-contained",
    "related_to": "symmetric",
}
_TRAVERSABLE_RELATIONS = frozenset(
    {"calls", "imports", "imports_from", "inherits", "references", "re_exports"}
)
_TOP_LEVEL_KEYS = frozenset(
    {"directed", "multigraph", "graph", "nodes", "links", "hyperedges", "built_at_commit"}
)
_NODE_REQUIRED_KEYS = frozenset({"id", "label", "file_type", "source_file"})
_NODE_KEYS = _NODE_REQUIRED_KEYS | {
    "source_location",
    "confidence",
    "confidence_score",
    "community",
    "community_name",
    "norm_label",
    "type",
    "kind",
}
_EDGE_REQUIRED_KEYS = frozenset({"source", "target", "relation", "confidence"})
_EDGE_KEYS = _EDGE_REQUIRED_KEYS | {
    "confidence_score",
    "source_file",
    "source_location",
    "weight",
    "context",
    "key",
}
_LOCATION = re.compile(r"^(?:L)?(?P<start>[1-9][0-9]*)(?:-(?:L)?(?P<end>[1-9][0-9]*))?$")
_GIT_OID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class GraphifyAdapterError(RuntimeError):
    """Raised when an offline Graphify snapshot cannot be trusted."""


@dataclass(frozen=True)
class GraphifySourceSpan:
    """One source occurrence tied to the exact bounded source bytes checked."""

    file_path: Path
    start_line: int
    end_line: int
    source_sha256: str


@dataclass(frozen=True)
class GraphifyNode:
    """A normalized code node from the pinned Graphify schema."""

    node_id: str
    label: str
    source_file: Path
    source_sha256: str
    span: GraphifySourceSpan | None
    extractor_strength: GraphifyStrength | None


@dataclass(frozen=True)
class GraphifyEdge:
    """A relation with its pinned source-to-target orientation."""

    source_id: str
    target_id: str
    relation: str
    orientation: GraphifyRelationOrientation
    extractor_strength: GraphifyStrength
    span: GraphifySourceSpan | None

    @property
    def traversable(self) -> bool:
        """Whether this source-backed relation may support future traversal."""
        return self.relation in _TRAVERSABLE_RELATIONS and self.span is not None


@dataclass(frozen=True)
class GraphifySnapshot:
    """One immutable graph byte snapshot adapted without executing its producer."""

    side: GraphSide
    graph_sha256: str
    graph_schema_version: int
    expected_graphify_package: str
    expected_graphify_version: str
    expected_graphify_command: str
    expected_version_output: str
    directed: bool
    multigraph: bool
    built_at_commit: str | None
    nodes: tuple[GraphifyNode, ...]
    edges: tuple[GraphifyEdge, ...]


@dataclass(frozen=True)
class GraphifySnapshotReceipt:
    """Durable receipt for a successfully validated offline import."""

    side: GraphSide
    graph_sha256: str
    graph_schema_version: int
    expected_graphify_package: str
    expected_graphify_version: str
    expected_graphify_command: str
    expected_version_output: str
    directed: bool
    multigraph: bool
    node_count: int
    edge_count: int

    def as_json(self) -> str:
        """Return deterministic strict JSON for exclusive publication."""
        return (
            json.dumps(
                {
                    "directed": self.directed,
                    "edge_count": self.edge_count,
                    "expected_graphify_command": self.expected_graphify_command,
                    "expected_graphify_package": self.expected_graphify_package,
                    "expected_graphify_version": self.expected_graphify_version,
                    "expected_version_output": self.expected_version_output,
                    "graph_schema_version": self.graph_schema_version,
                    "graph_sha256": self.graph_sha256,
                    "import_mode": "offline-only",
                    "multigraph": self.multigraph,
                    "node_count": self.node_count,
                    "side": self.side,
                },
                allow_nan=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )


@dataclass(frozen=True)
class _FileSnapshot:
    path: Path
    relative_path: Path | None
    sha256: str
    line_count: int
    signature: tuple[int, int, int, int, int]


def _bounded_string(value: object, location: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise GraphifyAdapterError(f"{location} must be a non-empty string")
    if len(value) > MAX_TEXT_LENGTH or "\x00" in value:
        raise GraphifyAdapterError(f"{location} is invalid or too large")
    return value


def _finite_number(value: object, location: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise GraphifyAdapterError(f"{location} must be a finite number")
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError) as error:
        raise GraphifyAdapterError(f"{location} must be a finite number") from error
    if not math.isfinite(result):
        raise GraphifyAdapterError(f"{location} must be finite")
    return result


def _signature(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _read_regular_file(path: Path, limit: int, description: str) -> tuple[bytes, _FileSnapshot]:
    """Read at most limit+1 bytes through one descriptor and detect path mutation."""
    flags = os.O_RDONLY
    for supported_flag in ("O_BINARY", "O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK"):
        flags |= getattr(os, supported_flag, 0)

    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise GraphifyAdapterError(f"{description} is not a regular file: {path}")
        handle = os.fdopen(descriptor, "rb")
        descriptor = None
        with handle:
            raw = handle.read(limit + 1)
            after = os.fstat(handle.fileno())
        current = path.stat(follow_symlinks=False)
    except GraphifyAdapterError:
        raise
    except (OSError, RuntimeError) as error:
        raise GraphifyAdapterError(f"cannot read {description} {path}: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)

    before_signature = _signature(before)
    if _signature(after) != before_signature or _signature(current) != before_signature:
        raise GraphifyAdapterError(f"{description} changed while it was being read")
    if len(raw) > limit:
        raise GraphifyAdapterError(f"{description} exceeds {limit} bytes")
    if len(raw) != before.st_size:
        raise GraphifyAdapterError(f"{description} changed while it was being read")
    line_count = raw.count(b"\n") + (1 if raw and not raw.endswith(b"\n") else 0)
    snapshot = _FileSnapshot(
        path=path,
        relative_path=None,
        sha256=hashlib.sha256(raw).hexdigest(),
        line_count=line_count,
        signature=before_signature,
    )
    return raw, snapshot


def _validate_json_numbers(value: object) -> None:
    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, float) and not math.isfinite(current):
            raise GraphifyAdapterError("graph.json contains a non-finite number")
        if isinstance(current, dict):
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)


def _strict_json(raw: bytes, source: Path) -> dict[str, object]:
    try:
        text = raw.decode("utf-8")
        value = load_json_unique(text)
    except (UnicodeError, TypeError, ValueError, OverflowError) as error:
        raise GraphifyAdapterError(f"invalid strict JSON in {source}: {error}") from error
    _validate_json_numbers(value)
    if not isinstance(value, dict):
        raise GraphifyAdapterError("graph.json must contain an object")
    required = _TOP_LEVEL_KEYS - {"built_at_commit"}
    if not required.issubset(value) or not set(value).issubset(_TOP_LEVEL_KEYS):
        extra = sorted(set(value) - _TOP_LEVEL_KEYS)
        missing = sorted(required - set(value))
        raise GraphifyAdapterError(
            f"unsupported graph.json top-level schema; extra={extra}, missing={missing}"
        )
    return cast("dict[str, object]", value)


class _SourceRegistry:
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self._snapshots: dict[Path, _FileSnapshot] = {}

    def read(self, value: object, location: str) -> _FileSnapshot:
        source = _bounded_string(value, location)
        supplied = Path(source)
        try:
            absolute = (
                supplied.resolve(strict=True)
                if supplied.is_absolute()
                else (self.project_root / supplied).resolve(strict=True)
            )
            relative = absolute.relative_to(self.project_root)
        except (OSError, RuntimeError, ValueError) as error:
            raise GraphifyAdapterError(
                f"{location} does not identify a confined project file: {source!r}"
            ) from error
        if not relative.parts or ".." in relative.parts:
            raise GraphifyAdapterError(f"{location} is not project relative: {source!r}")
        cached = self._snapshots.get(relative)
        if cached is not None:
            return cached
        _raw, snapshot = _read_regular_file(absolute, MAX_SOURCE_BYTES, "source file")
        snapshot = _FileSnapshot(
            path=absolute,
            relative_path=relative,
            sha256=snapshot.sha256,
            line_count=snapshot.line_count,
            signature=snapshot.signature,
        )
        self._snapshots[relative] = snapshot
        return snapshot

    def verify_unchanged(self) -> None:
        for snapshot in self._snapshots.values():
            try:
                current_path = snapshot.path.resolve(strict=True)
                current = snapshot.path.stat()
                current_path.relative_to(self.project_root)
            except (OSError, RuntimeError, ValueError) as error:
                raise GraphifyAdapterError(
                    f"source file changed during import: {snapshot.relative_path}"
                ) from error
            if current_path != snapshot.path or _signature(current) != snapshot.signature:
                raise GraphifyAdapterError(
                    f"source file changed during import: {snapshot.relative_path}"
                )


def _source_span(
    registry: _SourceRegistry,
    source_value: object,
    location_value: object,
    location: str,
) -> tuple[_FileSnapshot, GraphifySourceSpan | None]:
    source = registry.read(source_value, f"{location}.source_file")
    if location_value is None:
        return source, None
    raw_location = _bounded_string(location_value, f"{location}.source_location")
    match = _LOCATION.fullmatch(raw_location)
    if match is None:
        raise GraphifyAdapterError(f"{location}.source_location is unsupported: {raw_location!r}")
    try:
        start_line = int(match.group("start"))
        end_line = int(match.group("end") or start_line)
    except (TypeError, ValueError, OverflowError) as error:
        raise GraphifyAdapterError(
            f"{location}.source_location is unsupported: {raw_location!r}"
        ) from error
    if end_line < start_line:
        raise GraphifyAdapterError(f"{location}.source_location has a reversed range")
    if end_line > source.line_count:
        raise GraphifyAdapterError(
            f"{location}.source_location exceeds the exact source bytes ({source.line_count} lines)"
        )
    assert source.relative_path is not None
    return source, GraphifySourceSpan(
        source.relative_path,
        start_line,
        end_line,
        source.sha256,
    )


def _optional_edge_span(
    registry: _SourceRegistry, edge: dict[str, object], location: str
) -> GraphifySourceSpan | None:
    has_source = "source_file" in edge
    location_value = edge.get("source_location")
    if not has_source:
        if location_value is not None:
            raise GraphifyAdapterError(f"{location} has a source location without a source file")
        return None
    _source, span = _source_span(registry, edge["source_file"], location_value, location)
    return span


def _strength(value: object, location: str, *, optional: bool = False) -> GraphifyStrength | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or value not in {"EXTRACTED", "INFERRED", "AMBIGUOUS"}:
        raise GraphifyAdapterError(f"{location} has unsupported extractor confidence {value!r}")
    return cast("GraphifyStrength", value)


def _validate_optional_fields(item: dict[str, object], location: str) -> None:
    if "confidence_score" in item:
        score = _finite_number(item["confidence_score"], f"{location}.confidence_score")
        if not 0.0 <= score <= 1.0:
            raise GraphifyAdapterError(f"{location}.confidence_score must be between 0 and 1")
    if "weight" in item:
        weight = _finite_number(item["weight"], f"{location}.weight")
        if weight < 0.0:
            raise GraphifyAdapterError(f"{location}.weight must be non-negative")
    for field in ("context", "community_name", "norm_label", "type", "kind"):
        if field in item:
            _bounded_string(item[field], f"{location}.{field}", allow_empty=True)
    if "community" in item:
        community = item["community"]
        if community is not None and (type(community) is not int or community < 0):
            raise GraphifyAdapterError(
                f"{location}.community must be a non-negative integer or null"
            )
    if "key" in item:
        key = item["key"]
        if isinstance(key, bool) or not isinstance(key, (int, str)):
            raise GraphifyAdapterError(f"{location}.key must be an integer or string")
        if isinstance(key, str):
            _bounded_string(key, f"{location}.key", allow_empty=True)


def _read_graph_payload(
    graph_path: Path, expected_sha256: str | None
) -> tuple[str, dict[str, object]]:
    if expected_sha256 is not None and _SHA256.fullmatch(expected_sha256) is None:
        raise GraphifyAdapterError("expected_sha256 must be a lowercase SHA-256 digest")
    raw, snapshot = _read_regular_file(graph_path, MAX_GRAPH_BYTES, "Graphify snapshot")
    if expected_sha256 is not None and snapshot.sha256 != expected_sha256:
        raise GraphifyAdapterError(
            f"Graphify snapshot hash mismatch: expected {expected_sha256}, got {snapshot.sha256}"
        )
    return snapshot.sha256, _strict_json(raw, graph_path)


def _payload_collections(
    payload: dict[str, object],
) -> tuple[list[object], list[object], str | None]:
    if payload["directed"] is not GRAPHIFY_EXPECTED_DIRECTED:
        raise GraphifyAdapterError(
            f"graph.json directed must be attested value {GRAPHIFY_EXPECTED_DIRECTED}"
        )
    if payload["multigraph"] is not GRAPHIFY_EXPECTED_MULTIGRAPH:
        raise GraphifyAdapterError(
            f"graph.json multigraph must be attested value {GRAPHIFY_EXPECTED_MULTIGRAPH}"
        )
    if payload["graph"] != {}:
        raise GraphifyAdapterError("graph.json graph field must be an empty object")
    hyperedges = payload["hyperedges"]
    if not isinstance(hyperedges, list) or hyperedges:
        raise GraphifyAdapterError("code-only Graphify snapshots must have no semantic hyperedges")
    raw_nodes = payload["nodes"]
    raw_edges = payload["links"]
    if not isinstance(raw_nodes, list) or not isinstance(raw_edges, list):
        raise GraphifyAdapterError("graph.json nodes and links must be lists")
    if len(raw_nodes) > MAX_GRAPH_NODES or len(raw_edges) > MAX_GRAPH_EDGES:
        raise GraphifyAdapterError("graph.json exceeds the bounded node or edge limit")
    built_at_commit = payload.get("built_at_commit")
    if built_at_commit is not None:
        built_at_commit = _bounded_string(built_at_commit, "built_at_commit")
        if _GIT_OID.fullmatch(built_at_commit) is None:
            raise GraphifyAdapterError("built_at_commit must be a lowercase full Git OID")
    return raw_nodes, raw_edges, built_at_commit


def _adapt_nodes(
    raw_nodes: list[object], registry: _SourceRegistry
) -> tuple[tuple[GraphifyNode, ...], set[str]]:
    nodes: list[GraphifyNode] = []
    node_ids: set[str] = set()
    for index, raw_node in enumerate(raw_nodes):
        location = f"nodes[{index}]"
        if not isinstance(raw_node, dict):
            raise GraphifyAdapterError(f"{location} must be an object")
        node = cast("dict[str, object]", raw_node)
        extra = set(node) - _NODE_KEYS
        missing = _NODE_REQUIRED_KEYS - set(node)
        if extra or missing:
            raise GraphifyAdapterError(
                f"{location} has unsupported schema; "
                f"extra={sorted(extra)}, missing={sorted(missing)}"
            )
        node_id = _bounded_string(node["id"], f"{location}.id")
        if node_id in node_ids:
            raise GraphifyAdapterError(f"duplicate Graphify node id: {node_id}")
        node_ids.add(node_id)
        if node["file_type"] != "code":
            raise GraphifyAdapterError(f"{location} is not a code-only node")
        label = _bounded_string(node["label"], f"{location}.label")
        source, span = _source_span(
            registry,
            node["source_file"],
            node.get("source_location"),
            location,
        )
        strength = _strength(node.get("confidence"), f"{location}.confidence", optional=True)
        _validate_optional_fields(node, location)
        assert source.relative_path is not None
        nodes.append(
            GraphifyNode(
                node_id,
                label,
                source.relative_path,
                source.sha256,
                span,
                strength,
            )
        )
    return tuple(nodes), node_ids


def _adapt_edges(
    raw_edges: list[object], registry: _SourceRegistry, node_ids: set[str]
) -> tuple[GraphifyEdge, ...]:
    edges: list[GraphifyEdge] = []
    for index, raw_edge in enumerate(raw_edges):
        location = f"links[{index}]"
        if not isinstance(raw_edge, dict):
            raise GraphifyAdapterError(f"{location} must be an object")
        edge = cast("dict[str, object]", raw_edge)
        extra = set(edge) - _EDGE_KEYS
        missing = _EDGE_REQUIRED_KEYS - set(edge)
        if extra or missing:
            raise GraphifyAdapterError(
                f"{location} has unsupported schema; "
                f"extra={sorted(extra)}, missing={sorted(missing)}"
            )
        source_id = _bounded_string(edge["source"], f"{location}.source")
        target_id = _bounded_string(edge["target"], f"{location}.target")
        if source_id not in node_ids or target_id not in node_ids:
            raise GraphifyAdapterError(f"{location} references an unknown node")
        relation = _bounded_string(edge["relation"], f"{location}.relation")
        orientation = _RELATION_ORIENTATIONS.get(relation)
        if orientation is None:
            raise GraphifyAdapterError(
                f"{location}.relation has no attested source-to-target orientation: {relation!r}"
            )
        strength = _strength(edge["confidence"], f"{location}.confidence")
        assert strength is not None
        span = _optional_edge_span(registry, edge, location)
        _validate_optional_fields(edge, location)
        edges.append(GraphifyEdge(source_id, target_id, relation, orientation, strength, span))
    return tuple(edges)


def _resolve_project_root(project_root: Path) -> Path:
    try:
        root = project_root.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise GraphifyAdapterError(
            f"Graphify project root does not exist: {project_root}"
        ) from error
    if not root.is_dir():
        raise GraphifyAdapterError(f"Graphify project root is not a directory: {project_root}")
    return root


def load_graphify_snapshot(
    graph_path: Path,
    *,
    project_root: Path,
    side: GraphSide,
    expected_sha256: str | None = None,
) -> GraphifySnapshot:
    """Read and validate one offline graph snapshot; never execute Graphify."""
    if side not in {"baseline", "target"}:
        raise GraphifyAdapterError(f"unsupported snapshot side: {side!r}")
    root = _resolve_project_root(project_root)
    graph_sha256, payload = _read_graph_payload(graph_path, expected_sha256)
    raw_nodes, raw_edges, built_at_commit = _payload_collections(payload)
    registry = _SourceRegistry(root)
    nodes, node_ids = _adapt_nodes(raw_nodes, registry)
    edges = _adapt_edges(raw_edges, registry, node_ids)
    registry.verify_unchanged()
    return GraphifySnapshot(
        side=side,
        graph_sha256=graph_sha256,
        graph_schema_version=GRAPHIFY_GRAPH_SCHEMA_VERSION,
        expected_graphify_package=GRAPHIFY_PACKAGE_NAME,
        expected_graphify_version=GRAPHIFY_PACKAGE_VERSION,
        expected_graphify_command=GRAPHIFY_COMMAND_NAME,
        expected_version_output=GRAPHIFY_EXPECTED_VERSION_OUTPUT,
        directed=GRAPHIFY_EXPECTED_DIRECTED,
        multigraph=GRAPHIFY_EXPECTED_MULTIGRAPH,
        built_at_commit=built_at_commit,
        nodes=nodes,
        edges=edges,
    )


def _receipt_for(snapshot: GraphifySnapshot) -> GraphifySnapshotReceipt:
    return GraphifySnapshotReceipt(
        side=snapshot.side,
        graph_sha256=snapshot.graph_sha256,
        graph_schema_version=snapshot.graph_schema_version,
        expected_graphify_package=snapshot.expected_graphify_package,
        expected_graphify_version=snapshot.expected_graphify_version,
        expected_graphify_command=snapshot.expected_graphify_command,
        expected_version_output=snapshot.expected_version_output,
        directed=snapshot.directed,
        multigraph=snapshot.multigraph,
        node_count=len(snapshot.nodes),
        edge_count=len(snapshot.edges),
    )


def import_graphify_snapshot(
    graph_path: Path,
    *,
    project_root: Path,
    side: GraphSide,
    receipt_path: Path,
    expected_sha256: str | None = None,
) -> GraphifySnapshot:
    """Validate an offline snapshot and exclusively publish its import receipt."""
    snapshot = load_graphify_snapshot(
        graph_path,
        project_root=project_root,
        side=side,
        expected_sha256=expected_sha256,
    )
    try:
        with receipt_path.open("x", encoding="utf-8") as handle:
            handle.write(_receipt_for(snapshot).as_json())
            handle.flush()
            os.fsync(handle.fileno())
    except (OSError, RuntimeError) as error:
        raise GraphifyAdapterError(
            f"cannot publish Graphify snapshot receipt {receipt_path}: {error}"
        ) from error
    return snapshot
