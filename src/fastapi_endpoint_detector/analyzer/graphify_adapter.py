"""Strict, opt-in adapter for pinned Graphify code-only snapshots.

This module is deliberately not wired into the default analyzer.  It provides a
bounded POC boundary that can invoke a separately installed, pinned Graphify
binary in code-only mode and adapt its immutable ``graph.json`` bytes into a
small source/provenance IR.  It never installs tools, starts servers, queries a
semantic backend, or treats Graphify confidence as detector confidence.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from fastapi_endpoint_detector.strict_data import DuplicateKeyError, load_json_unique

GRAPHIFY_PACKAGE_VERSION = "0.9.30"
GRAPHIFY_GRAPH_SCHEMA_VERSION = 1
GRAPHIFY_OUTPUT_DIRECTORY = "graphify-out"
MAX_GRAPH_BYTES = 64 * 1024 * 1024
MAX_GRAPH_NODES = 250_000
MAX_GRAPH_EDGES = 1_000_000
MAX_TEXT_LENGTH = 16_384

GraphSide = Literal["baseline", "target"]
GraphifyStrength = Literal["EXTRACTED", "INFERRED", "AMBIGUOUS"]

_TRAVERSABLE_RELATIONS = frozenset(
    {"calls", "imports", "imports_from", "inherits", "references", "re_exports"}
)
_TOP_LEVEL_KEYS = frozenset(
    {"directed", "multigraph", "graph", "nodes", "links", "hyperedges", "built_at_commit"}
)
_NODE_KEYS = frozenset(
    {
        "id",
        "label",
        "file_type",
        "source_file",
        "source_location",
        "confidence",
        "confidence_score",
        "community",
        "community_name",
        "norm_label",
        "type",
        "kind",
        "metadata",
        "origin_file",
        "scope_id",
        "scope_kind",
        "target_file",
        "target_fqn",
        "package",
        "namespace",
    }
)
_EDGE_KEYS = frozenset(
    {
        "source",
        "target",
        "relation",
        "confidence",
        "confidence_score",
        "source_file",
        "source_location",
        "weight",
        "context",
        "metadata",
        "key",
        "target_file",
        "target_fqn",
        "origin_file",
    }
)
_LOCATION = re.compile(r"^(?:L)?(?P<start>[1-9][0-9]*)(?:-(?:L)?(?P<end>[1-9][0-9]*))?$")
_GIT_OID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


class GraphifyAdapterError(RuntimeError):
    """Raised when the explicit Graphify POC cannot produce trustworthy evidence."""


@dataclass(frozen=True)
class GraphifySourceSpan:
    """One project-relative, one-based inclusive source span."""

    file_path: Path
    start_line: int
    end_line: int


@dataclass(frozen=True)
class GraphifyNode:
    """A normalized code node from the pinned Graphify schema."""

    node_id: str
    label: str
    span: GraphifySourceSpan | None
    extractor_strength: GraphifyStrength | None


@dataclass(frozen=True)
class GraphifyEdge:
    """A directed Graphify edge with extractor provenance kept separate."""

    source_id: str
    target_id: str
    relation: str
    extractor_strength: GraphifyStrength
    span: GraphifySourceSpan | None

    @property
    def traversable(self) -> bool:
        """Whether the relation is eligible for later evidence-bearing traversal."""
        return self.relation in _TRAVERSABLE_RELATIONS and self.span is not None


@dataclass(frozen=True)
class GraphifySnapshot:
    """One immutable byte snapshot adapted from a pinned Graphify graph."""

    side: GraphSide
    graph_sha256: str
    graph_schema_version: int
    graphify_version: str
    built_at_commit: str | None
    nodes: tuple[GraphifyNode, ...]
    edges: tuple[GraphifyEdge, ...]


@dataclass(frozen=True)
class GraphifySnapshotReceipt:
    """Durable receipt written beside a successfully validated graph snapshot."""

    side: GraphSide
    graph_sha256: str
    graph_schema_version: int
    graphify_version: str
    node_count: int
    edge_count: int

    def as_json(self) -> str:
        """Return deterministic strict JSON for exclusive publication."""
        return (
            json.dumps(
                {
                    "edge_count": self.edge_count,
                    "graph_schema_version": self.graph_schema_version,
                    "graph_sha256": self.graph_sha256,
                    "graphify_version": self.graphify_version,
                    "node_count": self.node_count,
                    "side": self.side,
                },
                allow_nan=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )


def _bounded_string(value: object, location: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise GraphifyAdapterError(f"{location} must be a non-empty string")
    if len(value) > MAX_TEXT_LENGTH or "\x00" in value:
        raise GraphifyAdapterError(f"{location} is invalid or too large")
    return value


def _finite_number(value: object, location: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise GraphifyAdapterError(f"{location} must be a finite number")
    result = float(value)
    if not math.isfinite(result):
        raise GraphifyAdapterError(f"{location} must be finite")
    return result


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
    except (UnicodeError, json.JSONDecodeError, DuplicateKeyError) as error:
        raise GraphifyAdapterError(f"invalid strict JSON in {source}: {error}") from error
    _validate_json_numbers(value)
    if not isinstance(value, dict):
        raise GraphifyAdapterError("graph.json must contain an object")
    if set(value) != _TOP_LEVEL_KEYS and set(value) != _TOP_LEVEL_KEYS - {"built_at_commit"}:
        extra = sorted(set(value) - _TOP_LEVEL_KEYS)
        missing = sorted((_TOP_LEVEL_KEYS - {"built_at_commit"}) - set(value))
        raise GraphifyAdapterError(
            f"unsupported graph.json top-level schema; extra={extra}, missing={missing}"
        )
    return cast("dict[str, object]", value)


def _relative_source(project_root: Path, value: object, location: str) -> Path | None:
    source = _bounded_string(value, location, allow_empty=True)
    if not source:
        return None
    supplied = Path(source)
    try:
        absolute = (
            supplied.resolve(strict=False)
            if supplied.is_absolute()
            else (project_root / supplied).resolve(strict=False)
        )
        relative = absolute.relative_to(project_root)
    except ValueError as error:
        raise GraphifyAdapterError(f"{location} escapes the project root: {source!r}") from error
    if not relative.parts or ".." in relative.parts:
        raise GraphifyAdapterError(f"{location} is not project relative: {source!r}")
    if not absolute.is_file():
        raise GraphifyAdapterError(f"{location} does not identify a project file: {source!r}")
    return relative


def _source_span(
    project_root: Path,
    source_value: object,
    location_value: object,
    location: str,
) -> GraphifySourceSpan | None:
    file_path = _relative_source(project_root, source_value, f"{location}.source_file")
    if location_value in {None, ""}:
        return None
    if file_path is None:
        raise GraphifyAdapterError(f"{location} has a source location without a source file")
    raw_location = _bounded_string(location_value, f"{location}.source_location")
    match = _LOCATION.fullmatch(raw_location)
    if match is None:
        raise GraphifyAdapterError(f"{location}.source_location is unsupported: {raw_location!r}")
    start_line = int(match.group("start"))
    end_line = int(match.group("end") or start_line)
    if end_line < start_line:
        raise GraphifyAdapterError(f"{location}.source_location has a reversed range")
    return GraphifySourceSpan(file_path, start_line, end_line)


def _strength(value: object, location: str, *, optional: bool = False) -> GraphifyStrength | None:
    if value is None and optional:
        return None
    if value not in {"EXTRACTED", "INFERRED", "AMBIGUOUS"}:
        raise GraphifyAdapterError(f"{location} has unsupported extractor confidence {value!r}")
    return cast("GraphifyStrength", value)


def _validate_common_optional_fields(item: dict[str, object], location: str) -> None:
    if "confidence_score" in item:
        score = _finite_number(item["confidence_score"], f"{location}.confidence_score")
        if not 0.0 <= score <= 1.0:
            raise GraphifyAdapterError(f"{location}.confidence_score must be between 0 and 1")
    if "weight" in item:
        weight = _finite_number(item["weight"], f"{location}.weight")
        if weight < 0.0:
            raise GraphifyAdapterError(f"{location}.weight must be non-negative")
    for field in ("context", "community_name", "norm_label", "type", "kind"):
        if field in item and item[field] is not None:
            _bounded_string(item[field], f"{location}.{field}", allow_empty=True)
    community = item.get("community")
    if community is not None and (type(community) is not int or community < 0):
        raise GraphifyAdapterError(f"{location}.community must be a non-negative integer or null")
    key = item.get("key")
    if key is not None and (isinstance(key, bool) or not isinstance(key, (int, str))):
        raise GraphifyAdapterError(f"{location}.key must be an integer or string")
    if "metadata" in item and not isinstance(item["metadata"], dict):
        raise GraphifyAdapterError(f"{location}.metadata must be an object")


def _read_graph_payload(
    graph_path: Path, expected_sha256: str | None
) -> tuple[str, dict[str, object]]:
    try:
        size = graph_path.stat().st_size
        if size > MAX_GRAPH_BYTES:
            raise GraphifyAdapterError(f"graph.json exceeds {MAX_GRAPH_BYTES} bytes")
        raw = graph_path.read_bytes()
    except OSError as error:
        raise GraphifyAdapterError(
            f"cannot read Graphify snapshot {graph_path}: {error}"
        ) from error
    if len(raw) != size:
        raise GraphifyAdapterError("graph.json changed while it was being read")
    graph_sha256 = hashlib.sha256(raw).hexdigest()
    if expected_sha256 is not None and graph_sha256 != expected_sha256:
        raise GraphifyAdapterError(
            f"Graphify snapshot hash mismatch: expected {expected_sha256}, got {graph_sha256}"
        )
    return graph_sha256, _strict_json(raw, graph_path)


def _payload_collections(
    payload: dict[str, object],
) -> tuple[list[object], list[object], str | None]:
    if type(payload["directed"]) is not bool or type(payload["multigraph"]) is not bool:
        raise GraphifyAdapterError("graph.json directed and multigraph fields must be booleans")
    if not isinstance(payload["graph"], dict):
        raise GraphifyAdapterError("graph.json graph field must be an object")
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
    raw_nodes: list[object], project_root: Path
) -> tuple[tuple[GraphifyNode, ...], set[str]]:
    nodes: list[GraphifyNode] = []
    node_ids: set[str] = set()
    for index, raw_node in enumerate(raw_nodes):
        location = f"nodes[{index}]"
        if not isinstance(raw_node, dict):
            raise GraphifyAdapterError(f"{location} must be an object")
        node = cast("dict[str, object]", raw_node)
        extra = set(node) - _NODE_KEYS
        if extra:
            raise GraphifyAdapterError(f"{location} has unsupported fields: {sorted(extra)}")
        node_id = _bounded_string(node.get("id"), f"{location}.id")
        if node_id in node_ids:
            raise GraphifyAdapterError(f"duplicate Graphify node id: {node_id}")
        node_ids.add(node_id)
        if node.get("file_type") != "code":
            raise GraphifyAdapterError(f"{location} is not a code-only node")
        label = _bounded_string(node.get("label"), f"{location}.label")
        span = _source_span(
            project_root,
            node.get("source_file", ""),
            node.get("source_location"),
            location,
        )
        strength = _strength(node.get("confidence"), f"{location}.confidence", optional=True)
        _validate_common_optional_fields(node, location)
        nodes.append(GraphifyNode(node_id, label, span, strength))
    return tuple(nodes), node_ids


def _adapt_edges(
    raw_edges: list[object], project_root: Path, node_ids: set[str]
) -> tuple[GraphifyEdge, ...]:
    edges: list[GraphifyEdge] = []
    for index, raw_edge in enumerate(raw_edges):
        location = f"links[{index}]"
        if not isinstance(raw_edge, dict):
            raise GraphifyAdapterError(f"{location} must be an object")
        edge = cast("dict[str, object]", raw_edge)
        extra = set(edge) - _EDGE_KEYS
        if extra:
            raise GraphifyAdapterError(f"{location} has unsupported fields: {sorted(extra)}")
        source_id = _bounded_string(edge.get("source"), f"{location}.source")
        target_id = _bounded_string(edge.get("target"), f"{location}.target")
        if source_id not in node_ids or target_id not in node_ids:
            raise GraphifyAdapterError(f"{location} references an unknown node")
        relation = _bounded_string(edge.get("relation"), f"{location}.relation")
        strength = _strength(edge.get("confidence"), f"{location}.confidence")
        assert strength is not None
        span = _source_span(
            project_root,
            edge.get("source_file", ""),
            edge.get("source_location"),
            location,
        )
        _validate_common_optional_fields(edge, location)
        edges.append(GraphifyEdge(source_id, target_id, relation, strength, span))
    return tuple(edges)


def load_graphify_snapshot(
    graph_path: Path,
    *,
    project_root: Path,
    side: GraphSide,
    graphify_version: str = GRAPHIFY_PACKAGE_VERSION,
    expected_sha256: str | None = None,
) -> GraphifySnapshot:
    """Read one immutable graph.json byte snapshot and strictly adapt its evidence."""
    if side not in {"baseline", "target"}:
        raise GraphifyAdapterError(f"unsupported snapshot side: {side!r}")
    if graphify_version != GRAPHIFY_PACKAGE_VERSION:
        raise GraphifyAdapterError(
            f"unsupported Graphify version {graphify_version!r}; "
            f"expected {GRAPHIFY_PACKAGE_VERSION}"
        )
    graph_sha256, payload = _read_graph_payload(graph_path, expected_sha256)
    raw_nodes, raw_edges, built_at_commit = _payload_collections(payload)
    root = project_root.resolve(strict=True)
    nodes, node_ids = _adapt_nodes(raw_nodes, root)
    edges = _adapt_edges(raw_edges, root, node_ids)
    return GraphifySnapshot(
        side=side,
        graph_sha256=graph_sha256,
        graph_schema_version=GRAPHIFY_GRAPH_SCHEMA_VERSION,
        graphify_version=graphify_version,
        built_at_commit=built_at_commit,
        nodes=nodes,
        edges=edges,
    )


class GraphifyRunner:
    """Explicit pinned Graphify runner; construction never occurs in default analysis."""

    def __init__(self, project_root: Path, executable: Path, *, timeout: float = 300.0):
        self.project_root = project_root.resolve(strict=True)
        self.executable = executable.resolve(strict=True)
        if not self.project_root.is_dir():
            raise GraphifyAdapterError(f"Graphify project root is not a directory: {project_root}")
        if not self.executable.is_file():
            raise GraphifyAdapterError(f"Graphify executable is not a file: {executable}")
        if timeout <= 0:
            raise GraphifyAdapterError("Graphify timeout must be positive")
        self.timeout = timeout

    @staticmethod
    def _environment(home: Path) -> dict[str, str]:
        allowed = ("PATH", "SYSTEMROOT", "WINDIR", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL")
        environment = {name: os.environ[name] for name in allowed if name in os.environ}
        environment.update(
            {
                "GRAPHIFY_OUT": GRAPHIFY_OUTPUT_DIRECTORY,
                "HOME": str(home),
                "XDG_CONFIG_HOME": str(home / ".config"),
            }
        )
        return environment

    def _run(self, args: list[str], *, cwd: Path, home: Path) -> subprocess.CompletedProcess[str]:
        try:
            result = subprocess.run(
                args,
                cwd=cwd,
                env=self._environment(home),
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="strict",
                timeout=self.timeout,
            )
        except (OSError, subprocess.TimeoutExpired, UnicodeError) as error:
            raise GraphifyAdapterError(f"Graphify command failed to execute: {error}") from error
        if result.returncode:
            detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic output"
            raise GraphifyAdapterError(f"Graphify command failed ({result.returncode}): {detail}")
        return result

    def validate_tool(self, *, cwd: Path, home: Path) -> None:
        """Require the exact separately installed POC version before extraction."""
        result = self._run([str(self.executable), "--version"], cwd=cwd, home=home)
        if result.stdout.strip() != f"graphify {GRAPHIFY_PACKAGE_VERSION}":
            raise GraphifyAdapterError(
                f"unsupported Graphify version {result.stdout.strip()!r}; "
                f"expected graphify {GRAPHIFY_PACKAGE_VERSION}"
            )

    def extract_snapshot(self, side: GraphSide, output_root: Path) -> GraphifySnapshot:
        """Run one explicit code-only extraction into a fresh side-qualified directory."""
        if side not in {"baseline", "target"}:
            raise GraphifyAdapterError(f"unsupported snapshot side: {side!r}")
        root = output_root.expanduser().resolve(strict=False)
        if root == self.project_root or root.is_relative_to(self.project_root):
            raise GraphifyAdapterError("Graphify output must be outside the analyzed project")
        side_directory = root / side
        if side_directory.exists() or side_directory.is_symlink():
            raise GraphifyAdapterError(
                f"Graphify snapshot directory already exists: {side_directory}"
            )
        root.mkdir(parents=True, exist_ok=True)
        side_directory.mkdir(mode=0o700)
        home = side_directory / "home"
        home.mkdir(mode=0o700)
        self.validate_tool(cwd=side_directory, home=home)
        command = [
            str(self.executable),
            "extract",
            str(self.project_root),
            "--code-only",
            "--no-cluster",
            "--force",
            "--out",
            str(side_directory),
        ]
        self._run(command, cwd=side_directory, home=home)
        graph_path = side_directory / GRAPHIFY_OUTPUT_DIRECTORY / "graph.json"
        try:
            graph_path.resolve(strict=True).relative_to(side_directory.resolve(strict=True))
        except (OSError, ValueError) as error:
            raise GraphifyAdapterError("Graphify did not produce a confined graph.json") from error
        snapshot = load_graphify_snapshot(
            graph_path,
            project_root=self.project_root,
            side=side,
            graphify_version=GRAPHIFY_PACKAGE_VERSION,
        )
        receipt = GraphifySnapshotReceipt(
            side=snapshot.side,
            graph_sha256=snapshot.graph_sha256,
            graph_schema_version=snapshot.graph_schema_version,
            graphify_version=snapshot.graphify_version,
            node_count=len(snapshot.nodes),
            edge_count=len(snapshot.edges),
        )
        receipt_path = side_directory / "snapshot-receipt.json"
        try:
            with receipt_path.open("x", encoding="utf-8") as handle:
                handle.write(receipt.as_json())
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as error:
            raise GraphifyAdapterError(
                f"cannot publish Graphify snapshot receipt: {error}"
            ) from error
        return snapshot
