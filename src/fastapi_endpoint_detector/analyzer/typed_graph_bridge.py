"""Fail-closed bridge from an existing ordinary mypy build to the typed graph."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from mypy.server.update import FineGrainedBuildManager

from fastapi_endpoint_detector.analyzer.mypy_incremental import BuildReport, TypedBuild
from fastapi_endpoint_detector.analyzer.typed_reverse_graph import (
    ChangedSeed,
    EndpointOccurrenceBinding,
    GraphSide,
    SourceSpan,
    TypedReverseGraph,
    build_typed_reverse_graph,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
    from fastapi_endpoint_detector.models.endpoint import Endpoint


class TypedGraphBridgeError(RuntimeError):
    """The retained mypy result cannot be authenticated as this inventory."""


def retained_typed_build(  # noqa: PLR0912, PLR0915
    analyzer: MypyAnalyzer,
    inventory: Any,
) -> tuple[TypedBuild, dict[str, bytes], str]:
    """Wrap the exact retained ordinary build after bounded source verification."""
    if (
        getattr(inventory, "limitations", ())
        or inventory.unresolved_imports
        or getattr(inventory, "module_collisions", ())
    ):
        raise TypedGraphBridgeError("source inventory is limited or ambiguous")
    if len(inventory.files) > 4096:
        raise TypedGraphBridgeError("source inventory exceeds the file budget")
    retained = analyzer.framework_phase_build_snapshot()
    if retained is None:
        raise TypedGraphBridgeError("mypy build is not retained")
    result, retained_map = retained

    retained_sources: dict[str, bytes] = {}
    module_paths: dict[str, str] = {}
    total_bytes = 0
    source_digests: list[tuple[str, str]] = []
    for record in sorted(inventory.files, key=lambda item: item.module):
        if record.module in module_paths:
            raise TypedGraphBridgeError("source inventory contains duplicate module identities")
        path = Path(record.path)
        if path.is_symlink() or not path.is_file():
            raise TypedGraphBridgeError(f"symlink or unavailable source: {record.module}")
        resolved = path.resolve(strict=True)
        if str(resolved) in module_paths.values():
            raise TypedGraphBridgeError("source inventory aliases one file under multiple modules")
        if not resolved.is_relative_to(Path(inventory.root).resolve(strict=True)):
            raise TypedGraphBridgeError(f"source escapes inventory root: {record.module}")
        source = retained_map.get(str(resolved))
        if source is None or len(source) > analyzer.MAX_LAMBDA_SOURCE_FILE_BYTES:
            raise TypedGraphBridgeError(f"retained source bytes unavailable: {record.module}")
        total_bytes += len(source)
        if total_bytes > analyzer.MAX_LAMBDA_SOURCE_SNAPSHOT_BYTES:
            raise TypedGraphBridgeError("retained source snapshot exceeds byte budget")
        digest = hashlib.sha256(source).hexdigest()
        current = analyzer.framework_phase_source_bytes(
            resolved, max_bytes=analyzer.MAX_LAMBDA_SOURCE_FILE_BYTES
        )
        state = result.graph.get(record.module)
        if (
            digest != record.sha256
            or current != source
            or hashlib.sha1(source).hexdigest() != getattr(state, "source_hash", None)
            or state is None
            or state.tree is None
            or state.tree.fullname != record.module
            or not state.path
            or Path(state.path).resolve() != resolved
        ):
            raise TypedGraphBridgeError(f"retained typed source differs: {record.module}")
        retained_sources[record.module] = source
        module_paths[record.module] = str(resolved)
        source_digests.append((record.module, digest))

    if not source_digests:
        raise TypedGraphBridgeError("empty source inventory")
    options = result.manager.options
    option_fields = {
        field for cls in type(options).__mro__ for field in getattr(cls, "__mypyc_attrs__", ())
    }
    if not option_fields:
        raise TypedGraphBridgeError("effective mypy options are unavailable")
    effective_options = tuple((key, repr(getattr(options, key))) for key in sorted(option_fields))
    if analyzer.framework_phase_build_options() != effective_options:
        raise TypedGraphBridgeError("retained mypy options changed after the build")
    config_fingerprint = hashlib.sha256(
        json.dumps(
            {
                "engine": "fastapi-endpoint-detector:ordinary-mypy-build-v1",
                "mypy": analyzer.resolver_version,
                "module_root": str(analyzer.module_root.resolve()),
                "options": effective_options,
                "analysis_fingerprint": analyzer._built_source_fingerprint,
            },
            sort_keys=True,
        ).encode()
    ).hexdigest()
    inventory_fingerprint = hashlib.sha256(
        json.dumps(
            sorted(
                (record.module, record.relative_path, record.sha256) for record in inventory.files
            ),
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    cache_fingerprint = hashlib.sha256(
        json.dumps(
            {
                "config": config_fingerprint,
                "inventory": inventory_fingerprint,
                "sources": source_digests,
            },
            sort_keys=True,
        ).encode()
    ).hexdigest()
    rows = tuple(source_digests)
    report = BuildReport(
        "same_ordinary_build_result",
        None,
        0.0,
        tuple(module_paths),
        (),
        tuple(result.errors),
        inventory_fingerprint,
        cache_fingerprint,
        rows,
        rows,
    )
    typed = TypedBuild(result, FineGrainedBuildManager(result), report, module_paths)
    return typed, retained_sources, config_fingerprint


def exact_handler_bindings(
    typed: TypedBuild,
    inventory: Any,
    endpoints: Iterable[Endpoint],
) -> tuple[EndpointOccurrenceBinding, ...]:
    """Bind only handlers with exact module/name/path/line identity."""
    records = {record.module: record for record in inventory.files}
    bindings: list[EndpointOccurrenceBinding] = []
    occurrence_ids: set[str] = set()
    for endpoint in endpoints:
        handler = endpoint.handler
        record = records.get(handler.module)
        state = typed.modules.get(handler.module)
        if record is None or state is None or state.tree is None:
            raise TypedGraphBridgeError("handler module is outside the typed inventory")
        if Path(handler.file_path).resolve() != Path(record.path).resolve():
            raise TypedGraphBridgeError("handler path does not match canonical module")
        table = state.tree.names.get(handler.name)
        node: Any = getattr(table, "node", None)
        if getattr(node, "func", None) is not None:
            node = node.func
        expected_fullname = f"{handler.module}.{handler.name}"
        if (
            not node
            or getattr(node, "fullname", None) != expected_fullname
            or getattr(node, "name", None) != handler.name
            or int(getattr(node, "line", 0) or 0) != handler.line_number
        ):
            raise TypedGraphBridgeError("handler fullname or source line is not exact")
        span = SourceSpan(
            handler.module,
            str(Path(record.path).resolve()),
            record.sha256,
            int(node.line),
            int(node.column),
            int(node.end_line),
            int(node.end_column),
        )
        conditional = endpoint.discovery_status.value == "conditional"
        provenance = endpoint.native_provenance
        if provenance is not None:
            registration = provenance.registration
            occurrence_id = (
                f"{endpoint.identifier}@{registration.source_span.file_path.resolve()}"
                f":{registration.source_span.start_line}:{registration.source_span.start_column}"
                f"#{registration.occurrence_order}"
            )
        else:
            occurrence_id = (
                f"{endpoint.identifier}@{Path(handler.file_path).resolve()}:{handler.line_number}"
            )
        if occurrence_id in occurrence_ids:
            raise TypedGraphBridgeError("duplicate physical route occurrence identity")
        occurrence_ids.add(occurrence_id)
        bindings.append(
            EndpointOccurrenceBinding(
                occurrence_id=occurrence_id,
                endpoint_id=endpoint.identifier,
                symbol=expected_fullname,
                span=span,
                confidence="LOW" if conditional else "HIGH",
                conditional=conditional,
            )
        )
    return tuple(bindings)


def build_shadow_graph(
    analyzer: MypyAnalyzer,
    inventory: Any,
    endpoints: Iterable[Endpoint],
) -> TypedReverseGraph:
    """Build a diagnostic graph from one authenticated retained ordinary build."""
    typed, snapshots, config = retained_typed_build(analyzer, inventory)
    bindings = exact_handler_bindings(typed, inventory, endpoints)
    return build_typed_reverse_graph(
        inventory,
        typed,
        bindings,
        config_fingerprint=config,
        source_snapshots=snapshots,
    )


def query_changed_lines(
    graph: TypedReverseGraph,
    inventory: Any,
    changed_lines: Iterable[tuple[str, int]],
    *,
    side: GraphSide,
) -> Any:
    """Reverse-query exact graph symbols whose source spans contain changed lines."""
    paths = {record.relative_path: str(Path(record.path).resolve()) for record in inventory.files}
    seeds: set[ChangedSeed] = set()
    for relative, line in changed_lines:
        path = paths.get(Path(relative).as_posix())
        if path is None:
            continue
        for symbol in graph.symbols:
            span = symbol.span
            if span is not None and span.path == path and span.start_line <= line <= span.end_line:
                seeds.add(ChangedSeed(side, symbol.fullname, span))
    ordered_seeds = tuple(
        sorted(
            seeds,
            key=lambda seed: (
                seed.side,
                seed.symbol,
                seed.span.path if seed.span is not None else "",
                seed.span.start_line if seed.span is not None else 0,
                seed.span.start_column if seed.span is not None else 0,
            ),
        )
    )
    return graph.query(ordered_seeds, side=side)
