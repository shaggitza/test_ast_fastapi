"""Versioned source and import evidence graph.

Edges here document source relationships only and cannot assert runtime execution.
"""

from __future__ import annotations

import hashlib
import platform
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict

if TYPE_CHECKING:
    from fastapi_endpoint_detector.analyzer.source_inventory import SourceInventory


def _ast_engine_version() -> str:
    """Identify the interpreter implementation and version supplying the AST parser."""
    return f"{platform.python_implementation()} {platform.python_version()}"


class EvidenceProvenance(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    side: Literal["baseline", "target"]
    source_path: str
    start_line: int | None = None
    end_line: int | None = None
    engine: str
    engine_version: str
    strength: Literal["inventory", "reference", "registration", "execution"]
    confidence: Literal["low", "medium", "high"]
    limitations: tuple[str, ...] = ()


class EvidenceNode(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    id: str
    kind: Literal["source_file", "symbol", "registration", "endpoint", "resource", "observation"]
    attributes: dict[str, str | int | bool]
    provenance: EvidenceProvenance


class EvidenceEdge(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    source: str
    target: str
    kind: Literal["imports", "calls", "references", "includes", "mounts", "invokes", "observes"]
    provenance: EvidenceProvenance


class EvidenceGraph(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    schema_version: Literal[1] = 1
    nodes: tuple[EvidenceNode, ...]
    edges: tuple[EvidenceEdge, ...]


def source_evidence_graph(  # noqa: PLR0912
    inventory: SourceInventory, *, side: Literal["baseline", "target"] = "target"
) -> EvidenceGraph:
    nodes: list[EvidenceNode] = []
    edges: list[EvidenceEdge] = []
    by_module: dict[str, str] = {}
    ambiguous_modules = {module for module, _paths in inventory.module_collisions}
    seen_edges: set[tuple[str, str]] = set()
    for item in inventory.files:
        node_id = f"{side}:file:{item.relative_path}"
        if item.module not in ambiguous_modules:
            by_module[item.module] = node_id
        provenance = EvidenceProvenance(
            side=side,
            source_path=item.relative_path,
            engine="source-inventory",
            engine_version="1",
            strength="inventory",
            confidence="low",
            limitations=(
                "Import reachability does not establish execution",
                *inventory.limitations,
            ),
        )
        nodes.append(
            EvidenceNode(
                id=node_id,
                kind="source_file",
                attributes={
                    "module": item.module,
                    "sha256": item.sha256,
                },
                provenance=provenance,
            )
        )
    for item in inventory.files:
        for imported in item.imports:
            target = None
            parts = imported.split(".")
            for stop in range(len(parts), 0, -1):
                module = ".".join(parts[:stop])
                if module in ambiguous_modules:
                    break
                target = by_module.get(module)
                if target is not None:
                    break
            if target is None:
                continue
            edge_key = (f"{side}:file:{item.relative_path}", target)
            if edge_key in seen_edges:
                continue
            seen_edges.add(edge_key)
            edges.append(
                EvidenceEdge(
                    source=edge_key[0],
                    target=target,
                    kind="imports",
                    provenance=EvidenceProvenance(
                        side=side,
                        source_path=item.relative_path,
                        engine="python-ast",
                        engine_version=_ast_engine_version(),
                        strength="reference",
                        confidence="low",
                        limitations=(
                            "Import statements may be conditional or dynamically bypassed",
                            "Import reachability does not establish execution",
                            *inventory.limitations,
                        ),
                    ),
                )
            )
    node_ids = {node.id for node in nodes}
    source_nodes = {f"{side}:file:{item.relative_path}" for item in inventory.files}
    for source_path, imported in inventory.unresolved_imports:
        source_id = f"{side}:file:{source_path}"
        if source_id not in source_nodes:
            continue
        digest = hashlib.sha256(f"{source_path}\0{imported}".encode()).hexdigest()
        unresolved_id = f"{side}:unresolved-import:{digest}"
        matching_limitations = tuple(
            limitation
            for limitation in inventory.limitations
            if source_path in limitation and imported in limitation
        )
        reason = matching_limitations or (
            f"Import {imported!r} from {source_path} was not resolved inside the inventory",
        )
        provenance = EvidenceProvenance(
            side=side,
            source_path=source_path,
            engine="python-ast",
            engine_version=_ast_engine_version(),
            strength="reference",
            confidence="low",
            limitations=(
                *reason,
                "Unresolved import references do not establish execution",
            ),
        )
        if unresolved_id not in node_ids:
            nodes.append(
                EvidenceNode(
                    id=unresolved_id,
                    kind="resource",
                    attributes={"module": imported, "resolution": "unresolved"},
                    provenance=provenance,
                )
            )
            node_ids.add(unresolved_id)
        edge_key = (source_id, unresolved_id)
        if edge_key not in seen_edges:
            seen_edges.add(edge_key)
            edges.append(
                EvidenceEdge(
                    source=source_id,
                    target=unresolved_id,
                    kind="imports",
                    provenance=provenance,
                )
            )
    return EvidenceGraph(nodes=tuple(nodes), edges=tuple(edges))
