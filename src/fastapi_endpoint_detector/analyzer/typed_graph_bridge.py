"""Fail-closed bridge from an existing ordinary mypy build to the typed graph."""

from __future__ import annotations

import hashlib
import json
import os
import stat
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
    from fastapi_endpoint_detector.analyzer.source_inventory import SourceInventory
    from fastapi_endpoint_detector.models.endpoint import Endpoint


class TypedGraphBridgeError(RuntimeError):
    """The retained mypy result cannot be authenticated as this inventory."""


def _read_current_source(path: Path, max_bytes: int) -> bytes:
    """Read one regular source file without following a final symlink."""
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or path.is_symlink() or before.st_size > max_bytes:
        raise TypedGraphBridgeError("source is not a bounded regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or opened.st_size > max_bytes
        ):
            raise TypedGraphBridgeError("source identity changed during bounded open")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(max_bytes + 1)
        after = path.lstat()
        if (
            len(data) > max_bytes
            or (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
            or path.is_symlink()
        ):
            raise TypedGraphBridgeError("source identity changed during bounded read")
        return data
    finally:
        os.close(descriptor)


def retained_typed_build(
    analyzer: MypyAnalyzer,
    inventory: SourceInventory,
) -> tuple[TypedBuild, dict[str, bytes], str]:
    """Wrap the exact retained ordinary build after bounded source verification."""
    if inventory.limitations or inventory.unresolved_imports or inventory.module_collisions:
        raise TypedGraphBridgeError("source inventory is limited or ambiguous")
    if len(inventory.files) > 4096:
        raise TypedGraphBridgeError("source inventory exceeds the file budget")
    result = analyzer._build_result
    if result is None:
        raise TypedGraphBridgeError("mypy build is not retained")
    if (
        analyzer._built_source_fingerprint is not None
        and analyzer._built_source_fingerprint != analyzer._cache_fingerprint()[0]
    ):
        raise TypedGraphBridgeError("retained build no longer matches analyzer inputs")

    retained_sources: dict[str, bytes] = {}
    module_paths: dict[str, str] = {}
    total_bytes = 0
    source_digests: list[tuple[str, str]] = []
    for record in sorted(inventory.files, key=lambda item: item.module):
        path = Path(record.path)
        if path.is_symlink() or not path.is_file():
            raise TypedGraphBridgeError(f"symlink or unavailable source: {record.module}")
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(Path(inventory.root).resolve(strict=True)):
            raise TypedGraphBridgeError(f"source escapes inventory root: {record.module}")
        retained = analyzer._analysis_source_snapshots.get(str(resolved))
        if retained is None or len(retained) > analyzer.MAX_LAMBDA_SOURCE_FILE_BYTES:
            raise TypedGraphBridgeError(f"retained source bytes unavailable: {record.module}")
        total_bytes += len(retained)
        if total_bytes > analyzer.MAX_LAMBDA_SOURCE_SNAPSHOT_BYTES:
            raise TypedGraphBridgeError("retained source snapshot exceeds byte budget")
        digest = hashlib.sha256(retained).hexdigest()
        current = _read_current_source(path, analyzer.MAX_LAMBDA_SOURCE_FILE_BYTES)
        state = result.graph.get(record.module)
        if (
            digest != record.sha256
            or current != retained
            or hashlib.sha1(retained).hexdigest() != getattr(state, "source_hash", None)
            or state is None
            or state.tree is None
            or state.tree.fullname != record.module
            or not state.path
            or Path(state.path).resolve() != resolved
        ):
            raise TypedGraphBridgeError(f"retained typed source differs: {record.module}")
        retained_sources[record.module] = retained
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
    effective_options = {key: repr(getattr(options, key)) for key in sorted(option_fields)}
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
    inventory: SourceInventory,
    endpoints: Iterable[Endpoint],
) -> tuple[EndpointOccurrenceBinding, ...]:
    """Bind only handlers with exact module/name/path/line identity."""
    records = {record.module: record for record in inventory.files}
    bindings: list[EndpointOccurrenceBinding] = []
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
        bindings.append(
            EndpointOccurrenceBinding(
                occurrence_id=endpoint.identifier,
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
    inventory: SourceInventory,
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
    inventory: SourceInventory,
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
    return graph.query(tuple(sorted(seeds)), side=side)
