"""Fail-closed bridge from an existing ordinary mypy build to the typed graph."""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

from mypy.nodes import ARG_NAMED, ARG_POS, CallExpr, Decorator, FuncDef
from mypy.server.update import FineGrainedBuildManager

from fastapi_endpoint_detector.analyzer.mypy_incremental import BuildReport, TypedBuild
from fastapi_endpoint_detector.analyzer.typed_reverse_graph import (
    ChangedSeed,
    EndpointOccurrenceBinding,
    GraphSide,
    SourceDependencyUncertainty,
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


@dataclass(frozen=True)
class DirectEdgeDiagnostic:
    """One exact direct call from a physical handler occurrence to a changed symbol."""

    occurrence_id: str
    witness_id: str
    caller_span: SourceSpan
    changed_symbol: str
    changed_span: SourceSpan | None


@dataclass(frozen=True)
class ShadowSideComparison:
    """Side-bound graph evidence compared descriptively with combined legacy IDs."""

    side: GraphSide
    graph_occurrence_ids: tuple[str, ...]
    graph_endpoint_ids: tuple[str, ...]
    direct_evidence: tuple[DirectEdgeDiagnostic, ...]
    legacy_candidate_ids: tuple[str, ...]
    shared_endpoint_ids: tuple[str, ...]
    graph_only_endpoint_ids: tuple[str, ...]
    comparison_scope: str = "legacy candidates are combined across snapshots; not a parity oracle"


def compare_shadow_side(
    side: GraphSide, graph: TypedReverseGraph, result: Any, legacy_candidates: Iterable[Any]
) -> ShadowSideComparison:
    """Describe exact side evidence against the unsplit legacy candidate set.

    `direct_evidence` records only proven direct physical edge witnesses, with their
    source spans. Uncertain/deferred evidence stays in the graph query unchanged.
    """
    rows: list[DirectEdgeDiagnostic] = []
    occurrence_ids: set[str] = set()
    endpoint_ids: set[str] = set()
    graph_witness_ids = {witness.witness_id for witness in graph.edges}
    for evidence in (*result.evidence, *result.uncertain_evidence):
        if evidence.side != side:
            continue
        occurrence_ids.add(evidence.occurrence.occurrence_id)
        endpoint_ids.add(evidence.occurrence.endpoint_id)
        witnesses = getattr(evidence, "witnesses", getattr(evidence, "supporting_witnesses", ()))
        for witness in witnesses:
            if (
                witness.witness_id not in graph_witness_ids
                or witness.caller != evidence.occurrence.symbol
                or witness.callee != evidence.seed.symbol
            ):
                continue
            span = witness.span
            if span is not None:
                rows.append(
                    DirectEdgeDiagnostic(
                        evidence.occurrence.occurrence_id,
                        witness.witness_id,
                        span,
                        evidence.seed.symbol,
                        evidence.seed.span,
                    )
                )
    legacy = {candidate.endpoint.identifier for candidate in legacy_candidates}
    graph_ids = set(endpoint_ids)
    return ShadowSideComparison(
        side=side,
        graph_occurrence_ids=tuple(sorted(occurrence_ids)),
        graph_endpoint_ids=tuple(sorted(graph_ids)),
        direct_evidence=tuple(
            sorted(set(rows), key=lambda item: (item.occurrence_id, item.witness_id))
        ),
        legacy_candidate_ids=tuple(sorted(legacy)),
        shared_endpoint_ids=tuple(sorted(graph_ids & legacy)),
        graph_only_endpoint_ids=tuple(sorted(graph_ids - legacy)),
    )


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


_DEPENDENCY_SELECTORS = frozenset(
    {
        "fastapi.params.Depends",
        "fastapi.params.Security",
        "fastapi.param_functions.Depends",
        "fastapi.param_functions.Security",
    }
)
_DEPENDENCY_SPELLINGS = frozenset({"Depends", "Security"})
_MAX_DEPENDENCY_AST_NODES = 32768
_MAX_DEPENDENCY_CALLS_PER_HANDLER = 64
_MAX_DEPENDENCY_TYPED_NODES = 32768
_MAX_DEPENDENCY_METADATA = 8192
_DEPENDENCY_SCOPE_LIMITATION = (
    "Only handler signature dependency candidates are inspected. String annotations "
    "are not expanded. Route decorators and module-level dependency declarations "
    "are not scanned; FastAPI selector source ownership is not authenticated, so "
    "no positive dependency binding is emitted."
)


def _bridge_occurrence_id(endpoint: Endpoint) -> str:
    provenance = endpoint.native_provenance
    if provenance is not None:
        registration = provenance.registration
        span = registration.source_span
        return (
            f"{endpoint.identifier}@{span.file_path.resolve()}"
            f":{span.start_line}:{span.start_column}#{registration.occurrence_order}"
        )
    handler = endpoint.handler
    return f"{endpoint.identifier}@{Path(handler.file_path).resolve()}:{handler.line_number}"


def _bridge_func(node: Any) -> FuncDef | None:
    if isinstance(node, Decorator):
        node = node.func
    return node if isinstance(node, FuncDef) else None


def _bridge_fullname(node: Any) -> str | None:
    if isinstance(node, Decorator):
        node = node.func
    fullname = getattr(node, "fullname", None)
    return fullname if isinstance(fullname, str) and fullname else None


def _bridge_children(node: Any) -> tuple[Any, ...]:
    ignored = {
        "node",
        "info",
        "type",
        "unanalyzed_type",
        "original_def",
        "original_first_arg",
        "def_var",
        "expanded",
        "analyzed",
    }
    children: list[Any] = []
    attributes: set[str] = set()
    for cls in type(node).__mro__:
        for name in getattr(cls, "__mypyc_attrs__", ()):
            if name in attributes or name.startswith("_") or name in ignored:
                continue
            attributes.add(name)
            try:
                value = getattr(node, name)
            except (AttributeError, RuntimeError):
                continue
            if isinstance(value, (tuple, list)):
                children.extend(item for item in value if hasattr(type(item), "__mypyc_attrs__"))
            elif hasattr(type(value), "__mypyc_attrs__"):
                children.append(value)
    return tuple(children)


def _dependency_spelling(expression: ast.expr, imports: dict[str, str]) -> str | None:
    if isinstance(expression, ast.Name):
        resolved = imports.get(expression.id, expression.id)
        leaf = resolved.rsplit(".", 1)[-1]
        return leaf if leaf in _DEPENDENCY_SPELLINGS else None
    if isinstance(expression, ast.Attribute) and expression.attr in _DEPENDENCY_SPELLINGS:
        return expression.attr
    return None


def _source_module_imports(parsed: ast.Module) -> dict[str, str]:
    imports: dict[str, str] = {}
    for statement in parsed.body:
        if isinstance(statement, ast.ImportFrom):
            for item in statement.names:
                imports[item.asname or item.name] = f"{statement.module or ''}.{item.name}"
        elif isinstance(statement, ast.Import):
            for item in statement.names:
                imports[item.asname or item.name.split(".", 1)[0]] = item.name
    return imports


def _signature_dependency_calls(
    function: ast.FunctionDef | ast.AsyncFunctionDef, imports: dict[str, str]
) -> tuple[ast.Call, ...]:
    arguments = function.args
    roots: list[ast.AST] = [
        argument.annotation
        for argument in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs)
        if argument.annotation is not None
    ]
    roots.extend(arguments.defaults)
    roots.extend(value for value in arguments.kw_defaults if value is not None)
    for argument in (arguments.vararg, arguments.kwarg):
        if argument is not None and argument.annotation is not None:
            roots.append(argument.annotation)
    calls: list[ast.Call] = []
    seen: set[int] = set()
    stack = list(roots)
    while stack:
        node = stack.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if len(seen) > _MAX_DEPENDENCY_AST_NODES:
            raise TypedGraphBridgeError("dependency signature AST exceeds node budget")
        if isinstance(node, ast.Call) and _dependency_spelling(node.func, imports):
            calls.append(node)
            if len(calls) > _MAX_DEPENDENCY_CALLS_PER_HANDLER:
                raise TypedGraphBridgeError("dependency signature exceeds call budget")
        stack.extend(ast.iter_child_nodes(node))
    return tuple(calls)


def _typed_signature_calls(function: FuncDef) -> dict[tuple[int, int], list[CallExpr]]:
    calls: dict[tuple[int, int], list[CallExpr]] = {}
    seen: set[int] = set()
    stack: list[Any] = [
        value
        for argument in function.arguments
        for value in (argument.type_annotation, argument.initializer)
        if value is not None
    ]
    while stack:
        node = stack.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if len(seen) > _MAX_DEPENDENCY_TYPED_NODES:
            raise TypedGraphBridgeError("typed dependency signature exceeds node budget")
        if isinstance(node, CallExpr):
            calls.setdefault((int(node.line), int(node.column)), []).append(node)
        stack.extend(_bridge_children(node))
    return calls


def _dependency_argument_index(call: CallExpr) -> int | None:
    if (
        len(call.args) != len(call.arg_kinds)
        or len(call.args) != len(call.arg_names)
        or any(kind not in {ARG_POS, ARG_NAMED} for kind in call.arg_kinds)
    ):
        return None
    positional = [
        index
        for index, (kind, name) in enumerate(zip(call.arg_kinds, call.arg_names, strict=True))
        if kind == ARG_POS and name is None
    ]
    named = [
        index
        for index, (kind, name) in enumerate(zip(call.arg_kinds, call.arg_names, strict=True))
        if kind == ARG_NAMED and name == "dependency"
    ]
    # Only the unambiguous first argument or explicit dependency keyword is inspected.
    if len(positional) > 1 or len(named) > 1 or bool(positional) == bool(named):
        return None
    return positional[0] if positional else named[0]


def _is_exact_project_provider(node: Any, typed: TypedBuild, records: dict[str, Any]) -> bool:
    provider = _bridge_func(node)
    fullname = _bridge_fullname(provider)
    if provider is None or fullname is None or "." not in fullname:
        return False
    module, leaf = fullname.rsplit(".", 1)
    state = typed.modules.get(module)
    if module not in records or state is None or state.tree is None:
        return False
    table_node = getattr(state.tree.names.get(leaf), "node", None)
    return _bridge_func(table_node) is provider and provider.name == leaf


def _signature_dependency_reason(
    candidates: list[CallExpr], typed: TypedBuild, records: dict[str, Any]
) -> str:
    if len(candidates) != 1:
        return (
            "dependency_selector_typed_call_ambiguous"
            if candidates
            else "dependency_selector_typed_call_unavailable"
        )
    call = candidates[0]
    selector = _bridge_fullname(getattr(call.callee, "node", None))
    if selector not in _DEPENDENCY_SELECTORS:
        if selector is not None and any(selector.startswith(module + ".") for module in records):
            return "dependency_selector_project_shadow"
        return "dependency_selector_identity_unverified"
    index = _dependency_argument_index(call)
    if index is None:
        return "dependency_argument_binding_unsupported"
    if not _is_exact_project_provider(getattr(call.args[index], "node", None), typed, records):
        return "dependency_provider_not_top_level_project_function"
    # Neither this fullname nor adjacent package hashes authenticate the selector implementation.
    return "fastapi_selector_origin_unverified"


def _append_dependency_uncertainty(
    output: list[SourceDependencyUncertainty],
    owner: EndpointOccurrenceBinding,
    span: SourceSpan,
    reason: str,
    spelling: str,
) -> None:
    output.append(
        SourceDependencyUncertainty(
            occurrence_id=owner.occurrence_id,
            owner_symbol=owner.symbol,
            span=span,
            reason_code=reason,
            source_spelling=spelling[:256],
        )
    )
    if len(output) > _MAX_DEPENDENCY_METADATA:
        raise TypedGraphBridgeError("dependency metadata exceeds row budget")


def _dependency_uncertainty_key(item: SourceDependencyUncertainty) -> tuple[Any, ...]:
    return (
        item.occurrence_id,
        item.owner_symbol,
        item.span.module,
        item.span.path,
        item.span.source_sha256,
        item.span.start_line,
        item.span.start_column,
        item.span.end_line,
        item.span.end_column,
        item.reason_code,
        item.source_spelling,
    )


def _dependency_source_uncertainties(
    typed: TypedBuild,
    inventory: Any,
    endpoints: tuple[Endpoint, ...],
    bindings: tuple[EndpointOccurrenceBinding, ...],
    source_snapshots: dict[str, bytes],
) -> tuple[SourceDependencyUncertainty, ...]:
    """Record bounded signature candidates without asserting selector origin."""
    records = {record.module: record for record in inventory.files}
    by_occurrence = {binding.occurrence_id: binding for binding in bindings}
    if len(by_occurrence) != len(bindings) or len(endpoints) != len(bindings):
        raise TypedGraphBridgeError("endpoint occurrence bindings are incomplete or duplicated")
    output: list[SourceDependencyUncertainty] = []
    for endpoint in endpoints:
        owner = by_occurrence.get(_bridge_occurrence_id(endpoint))
        module = endpoint.handler.module
        record, state, raw = (
            records.get(module),
            typed.modules.get(module),
            source_snapshots.get(module),
        )
        if owner is None or record is None or state is None or state.tree is None or raw is None:
            raise TypedGraphBridgeError("dependency owner lacks authenticated typed source")
        typed_node = _bridge_func(
            getattr(state.tree.names.get(endpoint.handler.name), "node", None)
        )
        if typed_node is None or _bridge_fullname(typed_node) != owner.symbol:
            raise TypedGraphBridgeError("dependency handler is not an exact typed function")
        try:
            parsed = ast.parse(raw.decode("utf-8"), filename=str(record.path))
        except (UnicodeDecodeError, SyntaxError):
            _append_dependency_uncertainty(
                output,
                owner,
                owner.span,
                "dependency_signature_source_parse_unavailable",
                "<handler signature>",
            )
            continue
        functions = [
            node
            for node in parsed.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == endpoint.handler.name
            and node.lineno == endpoint.handler.line_number
        ]
        if len(functions) != 1:
            raise TypedGraphBridgeError("dependency handler source is not unique")
        syntax_calls = _signature_dependency_calls(functions[0], _source_module_imports(parsed))
        typed_calls = _typed_signature_calls(typed_node)
        for call in syntax_calls:
            span = SourceSpan(
                module,
                str(Path(record.path).resolve()),
                record.sha256,
                int(call.lineno),
                int(call.col_offset),
                int(call.end_lineno or call.lineno),
                int(call.end_col_offset or call.col_offset),
            )
            reason = _signature_dependency_reason(
                typed_calls.get((int(call.lineno), int(call.col_offset)), []), typed, records
            )
            _append_dependency_uncertainty(output, owner, span, reason, ast.unparse(call.func))
    return tuple(sorted(output, key=_dependency_uncertainty_key))


def build_shadow_graph(
    analyzer: MypyAnalyzer,
    inventory: Any,
    endpoints: Iterable[Endpoint],
) -> TypedReverseGraph:
    """Build a diagnostic graph from one authenticated retained ordinary build."""
    typed, snapshots, config = retained_typed_build(analyzer, inventory)
    selected = tuple(endpoints)
    bindings = exact_handler_bindings(typed, inventory, selected)
    uncertainties = _dependency_source_uncertainties(
        typed, inventory, selected, bindings, snapshots
    )
    graph = build_typed_reverse_graph(
        inventory,
        typed,
        bindings,
        config_fingerprint=config,
        source_snapshots=snapshots,
        source_dependency_uncertainties=uncertainties,
    )
    return replace(
        graph,
        limitations=tuple(sorted({*graph.limitations, _DEPENDENCY_SCOPE_LIMITATION})),
    )


def query_changed_lines(
    graph: TypedReverseGraph,
    inventory: Any,
    changed_lines: Iterable[tuple[str, int]],
    *,
    side: GraphSide,
) -> Any:
    """Reverse-query exact graph symbols whose source spans contain changed lines."""
    return graph.query(
        seeds_for_changed_lines(graph, inventory, changed_lines, side=side), side=side
    )


def seeds_for_changed_lines(
    graph: TypedReverseGraph,
    inventory: Any,
    changed_lines: Iterable[tuple[str, int]],
    *,
    side: GraphSide,
) -> tuple[ChangedSeed, ...]:
    """Seed only the narrowest AST symbol definition containing each changed line."""
    paths = {record.relative_path: str(Path(record.path).resolve()) for record in inventory.files}
    seeds: set[ChangedSeed] = set()
    for relative, line in changed_lines:
        path = paths.get(Path(relative).as_posix())
        if path is None:
            continue
        containing = [
            symbol
            for symbol in graph.symbols
            if symbol.span is not None
            and symbol.span.path == path
            and symbol.span.start_line <= line <= symbol.span.end_line
        ]
        if not containing:
            continue
        narrowest = min(
            (
                symbol.span.end_line - symbol.span.start_line,
                symbol.span.end_column - symbol.span.start_column,
            )
            for symbol in containing
            if symbol.span is not None
        )
        for symbol in containing:
            span = symbol.span
            if (
                span is not None
                and (
                    span.end_line - span.start_line,
                    span.end_column - span.start_column,
                )
                == narrowest
            ):
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
    return ordered_seeds
