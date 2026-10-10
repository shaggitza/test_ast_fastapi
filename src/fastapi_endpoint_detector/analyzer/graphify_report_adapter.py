"""Serialize Graphify overlay evidence for an additive report integration hook.

The payload remains separate from affected-endpoint selection and confidence.
It describes evidence from validated offline snapshots only.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from fastapi_endpoint_detector.analyzer.graphify_adapter import load_graphify_snapshot
from fastapi_endpoint_detector.analyzer.graphify_analyzer import (
    GraphPathEvidence,
    GraphTraversalPair,
    traverse_graphify_sides,
)
from fastapi_endpoint_detector.analyzer.graphify_input_adapter import (
    build_graphify_changed_ranges,
    build_graphify_endpoint_inputs,
    scope_graphify_snapshot_to_inventory,
)

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

    from fastapi_endpoint_detector.analyzer.graphify_adapter import (
        GraphifySnapshot,
        GraphifySourceSpan,
    )
    from fastapi_endpoint_detector.analyzer.source_inventory import SourceInventory
    from fastapi_endpoint_detector.models.diff import DiffFile
    from fastapi_endpoint_detector.models.endpoint import Endpoint


ReportT = TypeVar("ReportT", bound=BaseModel)


class GraphifyOverlayHookError(RuntimeError):
    """Raised when a report model does not expose the agreed additive field."""


class GraphifySourceLocationRecord(BaseModel):
    """One source coordinate without widening a line-only Graphify marker."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    file_path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    source_sha256: str
    module_name: str | None = None


class GraphifyOverlaySnapshotRecord(BaseModel):
    """Metadata for one validated Graphify snapshot; not a runtime receipt."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    side: Literal["baseline", "target"]
    graph_sha256: str
    graph_schema_version: int = Field(ge=1)
    expected_graphify_package: str
    expected_graphify_version: str
    node_count: int = Field(ge=0)
    edge_count: int = Field(ge=0)


class GraphifyRelationRecord(BaseModel):
    """One oriented source relation supporting an endpoint path."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    source_node_id: str
    target_node_id: str
    relation: str
    source_span: GraphifySourceLocationRecord | None = None
    extractor_strength: Literal["EXTRACTED", "INFERRED", "AMBIGUOUS"]
    edge_key: int | str | None = None
    context_identity: str | None = None


class GraphifyOverlayPathRecord(BaseModel):
    """Evidence kept independent from legacy endpoint impact scoring."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    side: Literal["baseline", "target"]
    endpoint_id: str
    binding_identity: str
    binding_kind: Literal["handler", "dependency"]
    endpoint_discovery_status: Literal["established", "conditional"]
    changed_node_id: str
    endpoint_node_id: str
    node_path_changed_to_endpoint: tuple[str, ...]
    node_source_spans: tuple[GraphifySourceLocationRecord | None, ...]
    relations_source_to_target: tuple[GraphifyRelationRecord, ...]
    confidence: Literal["HIGH", "MEDIUM", "LOW"]
    incomplete: bool
    limitations: tuple[str, ...]


class GraphifyOverlayReport(BaseModel):
    """Versioned, additive Graphify overlay for JSON and later text rendering."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    schema_version: Literal[1] = 1
    evidence_scope: Literal["validated_offline_snapshots"] = "validated_offline_snapshots"
    baseline_snapshot: GraphifyOverlaySnapshotRecord
    target_snapshot: GraphifyOverlaySnapshotRecord
    evidence: tuple[GraphifyOverlayPathRecord, ...]
    baseline_limitations: tuple[str, ...]
    target_limitations: tuple[str, ...]
    input_limitations: tuple[str, ...] = ()


def _location_record(
    span: GraphifySourceSpan | None,
    *,
    module_names: dict[Path, str | None],
) -> GraphifySourceLocationRecord | None:
    if span is None:
        return None
    return GraphifySourceLocationRecord(
        file_path=span.file_path.as_posix(),
        start_line=span.start_line,
        end_line=span.end_line,
        source_sha256=span.source_sha256,
        module_name=module_names.get(span.file_path),
    )


def _snapshot_record(snapshot: GraphifySnapshot) -> GraphifyOverlaySnapshotRecord:
    return GraphifyOverlaySnapshotRecord(
        side=snapshot.side,
        graph_sha256=snapshot.graph_sha256,
        graph_schema_version=snapshot.graph_schema_version,
        expected_graphify_package=snapshot.expected_graphify_package,
        expected_graphify_version=snapshot.expected_graphify_version,
        node_count=len(snapshot.nodes),
        edge_count=len(snapshot.edges),
    )


def _path_record(
    item: GraphPathEvidence,
    module_names: dict[Path, str | None],
) -> GraphifyOverlayPathRecord:
    relations: list[GraphifyRelationRecord] = []
    for index, relation in enumerate(item.relations):
        # Reverse traversal visits callee/target to caller/source; serialize the
        # original directed source-to-target orientation explicitly.
        relations.append(
            GraphifyRelationRecord(
                source_node_id=item.node_path[index + 1],
                target_node_id=item.node_path[index],
                relation=relation,
                source_span=_location_record(
                    item.edge_source_spans[index], module_names=module_names
                ),
                extractor_strength=item.extractor_strengths[index],
                edge_key=item.edge_keys[index],
                context_identity=item.edge_context_identities[index],
            )
        )
    return GraphifyOverlayPathRecord(
        side=item.side,
        endpoint_id=item.endpoint_id,
        binding_identity=item.binding_identity,
        binding_kind=item.binding_kind,
        endpoint_discovery_status=item.discovery_status.value,
        changed_node_id=item.changed_node_id,
        endpoint_node_id=item.endpoint_node_id,
        node_path_changed_to_endpoint=item.node_path,
        node_source_spans=tuple(
            _location_record(span, module_names=module_names) for span in item.node_source_spans
        ),
        relations_source_to_target=tuple(relations),
        # Graphify records are lexical provenance, not proof of runtime calls.
        confidence="LOW",
        incomplete=item.incomplete,
        limitations=tuple(
            dict.fromkeys(
                (
                    *item.limitations,
                    "Graphify records are lexical evidence only; execution is not established",
                )
            )
        ),
    )


def build_graphify_overlay_report(
    baseline_snapshot: GraphifySnapshot,
    target_snapshot: GraphifySnapshot,
    traversal: GraphTraversalPair,
    *,
    input_limitations: tuple[str, ...] = (),
    baseline_module_names: tuple[tuple[Path, str | None], ...] = (),
    target_module_names: tuple[tuple[Path, str | None], ...] = (),
) -> GraphifyOverlayReport:
    """Create an additive report payload from side-matched snapshots/results."""
    if baseline_snapshot.side != "baseline" or target_snapshot.side != "target":
        raise ValueError("snapshots must be supplied in baseline, target order")
    if traversal.baseline.side != baseline_snapshot.side:
        raise ValueError("baseline traversal does not match its snapshot")
    if traversal.target.side != target_snapshot.side:
        raise ValueError("target traversal does not match its snapshot")
    modules_by_side = {
        "baseline": dict(baseline_module_names),
        "target": dict(target_module_names),
    }
    evidence = tuple(
        _path_record(item, modules_by_side[item.side])
        for item in (*traversal.baseline.evidence, *traversal.target.evidence)
    )
    return GraphifyOverlayReport(
        baseline_snapshot=_snapshot_record(baseline_snapshot),
        target_snapshot=_snapshot_record(target_snapshot),
        evidence=evidence,
        baseline_limitations=traversal.baseline.limitations,
        target_limitations=traversal.target.limitations,
        input_limitations=input_limitations,
    )


def analyze_graphify_overlay_from_inputs(
    *,
    baseline_graph_path: Path,
    target_graph_path: Path,
    baseline_project_root: Path,
    target_project_root: Path,
    schema: str,
    diff_files: Iterable[DiffFile],
    baseline_endpoints: Iterable[Endpoint],
    target_endpoints: Iterable[Endpoint],
    baseline_inventory: SourceInventory,
    target_inventory: SourceInventory,
    baseline_expected_sha256: str | None = None,
    target_expected_sha256: str | None = None,
    max_depth: int = 64,
    max_visited_nodes: int = 50_000,
    max_queued_witnesses: int = 10_000,
) -> GraphifyOverlayReport:
    """Run the explicit offline overlay from parsed diff and secure mapper inputs.

    This is the integration seam for the CLI owner: callers supply already
    selected snapshots, source inventories, parsed diff files, and independently
    discovered baseline/target endpoints. Snapshot or schema errors propagate;
    the overlay never falls back to heuristic findings.
    """
    _assert_inventory_root(baseline_inventory, baseline_project_root, "baseline")
    _assert_inventory_root(target_inventory, target_project_root, "target")
    baseline_snapshot = load_graphify_snapshot(
        baseline_graph_path,
        project_root=baseline_project_root,
        side="baseline",
        expected_sha256=baseline_expected_sha256,
        schema=schema,
    )
    target_snapshot = load_graphify_snapshot(
        target_graph_path,
        project_root=target_project_root,
        side="target",
        expected_sha256=target_expected_sha256,
        schema=schema,
    )
    baseline_scoped = scope_graphify_snapshot_to_inventory(baseline_snapshot, baseline_inventory)
    target_scoped = scope_graphify_snapshot_to_inventory(target_snapshot, target_inventory)
    changed = build_graphify_changed_ranges(diff_files)
    baseline_inputs = build_graphify_endpoint_inputs(baseline_endpoints)
    target_inputs = build_graphify_endpoint_inputs(target_endpoints)
    traversal = traverse_graphify_sides(
        baseline_scoped.snapshot,
        target_scoped.snapshot,
        baseline_project_root=baseline_project_root,
        target_project_root=target_project_root,
        baseline_changed_ranges=changed.baseline,
        target_changed_ranges=changed.target,
        baseline_endpoints=baseline_inputs.seeds,
        target_endpoints=target_inputs.seeds,
        max_depth=max_depth,
        max_visited_nodes=max_visited_nodes,
        max_queued_witnesses=max_queued_witnesses,
    )
    input_limitations = [
        *(f"diff: {item}" for item in changed.limitations),
        *(f"baseline: {item}" for item in baseline_inputs.limitations),
        *(f"target: {item}" for item in target_inputs.limitations),
        *(f"baseline source inventory: {item}" for item in baseline_inventory.limitations),
        *(f"target source inventory: {item}" for item in target_inventory.limitations),
        *(f"baseline: {item}" for item in baseline_scoped.limitations),
        *(f"target: {item}" for item in target_scoped.limitations),
    ]
    input_limitations.extend(
        f"baseline unresolved source import: {path} -> {module}"
        for path, module in baseline_inventory.unresolved_imports
    )
    input_limitations.extend(
        f"target unresolved source import: {path} -> {module}"
        for path, module in target_inventory.unresolved_imports
    )
    return build_graphify_overlay_report(
        baseline_snapshot,
        target_snapshot,
        traversal,
        input_limitations=tuple(dict.fromkeys(input_limitations)),
        baseline_module_names=baseline_scoped.module_names,
        target_module_names=target_scoped.module_names,
    )


def _assert_inventory_root(inventory: SourceInventory, project_root: Path, side: str) -> None:
    try:
        inventory_root = inventory.root.resolve(strict=True)
        expected_root = project_root.resolve(strict=True)
    except OSError as error:
        raise ValueError(f"{side} Graphify and source inventory roots must exist") from error
    if inventory_root != expected_root:
        raise ValueError(f"{side} source inventory root must match its Graphify project root")


def attach_graphify_overlay(report: ReportT, overlay: GraphifyOverlayReport) -> ReportT:
    """Return a report copy with the versioned overlay in the agreed field.

    Call this only when the explicit Graphify option is enabled. Reports without
    the declared field fail clearly rather than silently dropping the overlay.
    """
    fields = getattr(type(report), "model_fields", {})
    if "graphify_overlay" not in fields:
        raise GraphifyOverlayHookError(
            "AnalysisReport must expose the graphify_overlay field before attachment"
        )
    return report.model_copy(update={"graphify_overlay": overlay})
