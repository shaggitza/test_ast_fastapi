"""Versioned source and import evidence graph.

Edges here document source relationships only and cannot assert runtime execution.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict

if TYPE_CHECKING:
    from fastapi_endpoint_detector.analyzer.source_inventory import SourceInventory


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


def source_evidence_graph(
    inventory: SourceInventory, *, side: Literal["baseline", "target"] = "target"
) -> EvidenceGraph:
    nodes: list[EvidenceNode] = []
    edges: list[EvidenceEdge] = []
    by_module: dict[str, str] = {}
    seen_edges: set[tuple[str, str]] = set()
    for item in inventory.files:
        node_id = f"{side}:file:{item.relative_path}"
        by_module[item.module] = node_id
        provenance = EvidenceProvenance(
            side=side,
            source_path=item.relative_path,
            engine="source-inventory",
            engine_version="1",
            strength="inventory",
            confidence="low",
            limitations=("Import reachability does not establish execution",),
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
            target = by_module.get(imported)
            if target is None and imported.rpartition(".")[0]:
                target = by_module.get(imported.rpartition(".")[0])
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
                        engine="cpython-ast",
                        engine_version="stdlib",
                        strength="reference",
                        confidence="low",
                        limitations=(
                            "Import statements may be conditional or dynamically bypassed",
                            "Import reachability does not establish execution",
                        ),
                    ),
                )
            )
    return EvidenceGraph(nodes=tuple(nodes), edges=tuple(edges))
