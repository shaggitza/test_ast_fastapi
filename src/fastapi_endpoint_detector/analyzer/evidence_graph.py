"""Versioned source and import evidence graph.

Edges here document source relationships only and cannot assert runtime execution.
"""

from __future__ import annotations

import hashlib
import platform
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, model_validator

from fastapi_endpoint_detector.analyzer.source_inventory import (
    ImportOccurrence,
    UnresolvedImportOccurrence,
)

if TYPE_CHECKING:
    from fastapi_endpoint_detector.analyzer.source_inventory import SourceInventory


def _ast_engine_version() -> str:
    """Identify the interpreter implementation and version supplying the AST parser."""
    return f"{platform.python_implementation()} {platform.python_version()}"


class EvidenceProvenance(BaseModel):
    """Source positions use inclusive lines and Python AST UTF-8 byte columns."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    side: Literal["baseline", "target"]
    source_path: str
    start_line: int | None = None
    end_line: int | None = None
    start_column: int | None = None
    end_column: int | None = None
    engine: str
    engine_version: str
    strength: Literal["inventory", "reference", "registration", "execution"]
    confidence: Literal["low", "medium", "high"]
    limitations: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_column_span(self) -> EvidenceProvenance:
        if (self.start_column is None) != (self.end_column is None):
            raise ValueError("source span columns must be paired")
        if self.start_column is None or self.end_column is None:
            return self
        if self.start_line is None or self.end_line is None:
            raise ValueError("source span columns require both line endpoints")
        if self.start_line < 1 or self.end_line < 1 or self.start_column < 0 or self.end_column < 0:
            raise ValueError("source span positions must be nonnegative with positive lines")
        if (self.end_line, self.end_column) < (self.start_line, self.start_column):
            raise ValueError("source span end must not precede its start")
        return self


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
    schema_version: Literal[1, 2] = 2
    nodes: tuple[EvidenceNode, ...]
    edges: tuple[EvidenceEdge, ...]

    @model_validator(mode="after")
    def validate_column_schema(self) -> EvidenceGraph:
        records: tuple[EvidenceNode | EvidenceEdge, ...] = (*self.nodes, *self.edges)
        if self.schema_version == 1 and any(
            item.provenance.start_column is not None or item.provenance.end_column is not None
            for item in records
        ):
            raise ValueError("source graph column spans require schema version 2")
        return self


def source_evidence_graph(  # noqa: PLR0912
    inventory: SourceInventory, *, side: Literal["baseline", "target"] = "target"
) -> EvidenceGraph:
    nodes: list[EvidenceNode] = []
    edges: list[EvidenceEdge] = []
    by_module: dict[str, str] = {}
    ambiguous_modules = {module for module, _paths in inventory.module_collisions}
    seen_edges: set[tuple[str, str, int | None, int | None, int | None, int | None]] = set()
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
                attributes={"module": item.module, "sha256": item.sha256},
                provenance=provenance,
            )
        )
    for item in inventory.files:
        occurrences = item.import_occurrences or tuple(
            ImportOccurrence(imported) for imported in item.imports
        )
        for occurrence in occurrences:
            imported = occurrence.module
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
            source_id = f"{side}:file:{item.relative_path}"
            edge_key = (
                source_id,
                target,
                occurrence.start_line,
                occurrence.end_line,
                occurrence.start_column,
                occurrence.end_column,
            )
            if edge_key in seen_edges:
                continue
            seen_edges.add(edge_key)
            edges.append(
                EvidenceEdge(
                    source=source_id,
                    target=target,
                    kind="imports",
                    provenance=EvidenceProvenance(
                        side=side,
                        source_path=item.relative_path,
                        start_line=occurrence.start_line,
                        end_line=occurrence.end_line,
                        start_column=occurrence.start_column,
                        end_column=occurrence.end_column,
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
    unresolved_occurrences = list(inventory.unresolved_import_occurrences)
    recorded_pairs = {(item.source_path, item.module) for item in unresolved_occurrences}
    unresolved_occurrences.extend(
        UnresolvedImportOccurrence(source_path, imported)
        for source_path, imported in inventory.unresolved_imports
        if (source_path, imported) not in recorded_pairs
    )
    for unresolved_occurrence in sorted(
        unresolved_occurrences,
        key=lambda item: (
            item.source_path,
            item.module,
            item.start_line or 0,
            item.end_line or 0,
            item.start_column or 0,
            item.end_column or 0,
        ),
    ):
        source_path, imported = unresolved_occurrence.source_path, unresolved_occurrence.module
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
            start_line=unresolved_occurrence.start_line,
            end_line=unresolved_occurrence.end_line,
            start_column=unresolved_occurrence.start_column,
            end_column=unresolved_occurrence.end_column,
            engine="python-ast",
            engine_version=_ast_engine_version(),
            strength="reference",
            confidence="low",
            limitations=(*reason, "Unresolved import references do not establish execution"),
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
        edge_key = (
            source_id,
            unresolved_id,
            unresolved_occurrence.start_line,
            unresolved_occurrence.end_line,
            unresolved_occurrence.start_column,
            unresolved_occurrence.end_column,
        )
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
