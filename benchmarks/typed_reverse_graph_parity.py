"""Generated evidence parity and phase benchmark for the opt-in reverse graph.

The oracle is current full-depth MypyAnalyzer call stacks, resolved call sites,
argument evidence, and referenced symbol/file evidence. Candidate, occurrence,
terminal, exact callee-coordinate, target, and invocation mismatches fail.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import tempfile
import time
from dataclasses import dataclass
from importlib.metadata import version
from itertools import pairwise
from pathlib import Path
from typing import Any, Literal

from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.analyzer.mypy_incremental import (
    BuildConfig,
    MypyIncrementalProvider,
    TypedBuild,
)
from fastapi_endpoint_detector.analyzer.typed_reverse_graph import (
    ChangedSeed,
    EndpointOccurrenceBinding,
    SourceSpan,
    build_typed_reverse_graph,
)
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo


@dataclass(frozen=True)
class SourceRecord:
    module: str
    path: Path
    relative_path: str
    sha256: str


@dataclass(frozen=True)
class Inventory:
    root: Path
    files: tuple[SourceRecord, ...]


def _write_fixture(root: Path, modules: int, leaf_increment: int = 0) -> dict[str, str]:
    sources: dict[str, str] = {}
    for index in range(modules):
        following = index + 1
        if following < modules:
            imported = f"from {root.name}.m{following} import f{following}\n"
            increment = leaf_increment if following == modules - 1 else 0
            body = f"    return f{following}(value) + {increment}\n"
        else:
            imported = ""
            body = f"    return value + {leaf_increment}\n"
        sources[f"m{index}"] = (
            imported
            + f"def f{index}(value: int) -> int:\n{body}"
            + "\ndef unused(value: int) -> int:\n    return value\n"
        )
    sources["app"] = (
        f"from {root.name}.m0 import f0\n"
        "def handler(value: int) -> int:\n    return f0(value)\n"
    )
    for module, source in sources.items():
        (root / f"{module}.py").write_text(source, encoding="utf-8")
    return sources


def _retained_snapshot(
    root: Path, *, max_depth: int
) -> tuple[
    Inventory,
    TypedBuild,
    MypyAnalyzer,
    MypyIncrementalProvider,
    dict[str, Path],
    float,
    float,
]:
    module_paths = {f"{root.name}.{path.stem}": path for path in sorted(root.glob("*.py"))}
    provider = MypyIncrementalProvider(BuildConfig(source_root=root))
    typed = provider.build(module_paths)
    records = tuple(
        SourceRecord(
            module,
            path,
            path.relative_to(root).as_posix(),
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )
        for module, path in sorted(module_paths.items())
    )
    provider_elapsed = typed.report.elapsed_seconds
    analyzer = MypyAnalyzer(root, max_depth=max_depth)
    oracle_start = time.perf_counter()
    analyzer._ensure_mypy_built()
    oracle_elapsed = time.perf_counter() - oracle_start
    return (
        Inventory(root, records),
        typed,
        analyzer,
        provider,
        module_paths,
        provider_elapsed,
        oracle_elapsed,
    )


def _physical_oracle_paths(
    analyzer: MypyAnalyzer, endpoint: Endpoint, terminal_symbol: str, root: Path
) -> list[tuple[tuple[str, int, int, int, int, str], ...]]:
    dependencies = analyzer.analyze_endpoint(endpoint)
    sites = dependencies.get_resolved_call_sites()
    paths: list[tuple[tuple[str, int, int, int, int, str], ...]] = []
    for stacks in dependencies.call_stacks.values():
        for stack in stacks:
            terminal_indexes = [
                index for index, frame in enumerate(stack) if frame.function_name == terminal_symbol
            ]
            if not terminal_indexes:
                continue
            terminal = terminal_indexes[-1]
            physical: list[tuple[str, int, int, int, int, str]] = []
            for caller, callee in pairwise(stack[: terminal + 1]):
                if callee.caller_line_number is None:
                    raise AssertionError("full-depth oracle path lacks caller line coordinate")
                caller_path = Path(caller.file_path).resolve()
                matching = [
                    site
                    for site in sites
                    if Path(site.file_path).resolve() == caller_path
                    and site.line == callee.caller_line_number
                    and site.canonical_symbol == callee.function_name
                    and site.status.value == "exact"
                ]
                if len(matching) != 1:
                    raise AssertionError(
                        "oracle physical path does not map to one exact full-name site: "
                        f"{caller!r} -> {callee!r}, matches={matching!r}"
                    )
                site = matching[0]
                if site.end_line is None or site.end_column is None:
                    raise AssertionError(f"oracle call site lacks end coordinates: {site!r}")
                physical.append(
                    (
                        caller_path.relative_to(root.resolve()).as_posix(),
                        callee.caller_line_number,
                        site.column,
                        site.end_line,
                        site.end_column,
                        callee.function_name,
                    )
                )
            paths.append(tuple(physical))
    return sorted(set(paths))


def _graph_physical_paths(
    graph: Any, seed: str, *, side: Literal["baseline", "target"] = "target"
) -> list[tuple[tuple[str, int, int, int, int, str], ...]]:
    result = graph.query([ChangedSeed(side, seed)], side=side)
    return sorted(
        {
            tuple(
                (
                    Path(edge.span.path).resolve().relative_to(Path(graph.root)).as_posix(),
                    edge.span.start_line,
                    edge.target_span.start_column if edge.target_span else -1,
                    edge.target_span.end_line if edge.target_span else -1,
                    edge.target_span.end_column if edge.target_span else -1,
                    edge.callee,
                )
                for edge in evidence.witnesses
                if edge.kind in {"call", "constructor"}
            )
            for evidence in result.evidence
        }
    )


def _inventory_module(snapshot: Any, module: str) -> str:
    state = snapshot.modules.get(module)
    if state is None or getattr(state, "tree", None) is None:
        raise AssertionError(f"snapshot does not contain exact fixture module {module!r}")
    return module


def _fullname(snapshot: Any, module: str, name: str) -> str:
    fullname = snapshot.modules[module].tree.names[name].node.fullname
    if not isinstance(fullname, str):
        raise AssertionError(f"fixture symbol has no canonical fullname: {module}.{name}")
    return fullname


def _endpoint(root: Path, snapshot: Any) -> tuple[Endpoint, EndpointOccurrenceBinding]:
    module = _inventory_module(snapshot, f"{root.name}.app")
    path = root / "app.py"
    fullname = _fullname(snapshot, module, "handler")
    endpoint = Endpoint(
        path="/generated",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="handler", module=module, file_path=path, line_number=2, end_line_number=3
        ),
    )
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    binding = EndpointOccurrenceBinding(
        endpoint.identifier,
        endpoint.identifier,
        fullname,
        SourceSpan(module, str(path.resolve()), digest, 2, 0, 3, 0),
    )
    return endpoint, binding


def _oracle_endpoint(root: Path, analyzer: MypyAnalyzer) -> Endpoint:
    path = (root / "app.py").resolve()
    module = next(
        name
        for name, candidate in analyzer._module_to_path.items()
        if Path(candidate).resolve() == path
    )
    return Endpoint(
        path="/generated",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="handler", module=module, file_path=path, line_number=2, end_line_number=3
        ),
    )


def _seed_path(root: Path, seed: str) -> Path:
    module = seed.rsplit(".", maxsplit=1)[0]
    package = f"{root.name}."
    if module.startswith(package):
        module = module.removeprefix(package)
    return root.joinpath(*module.split(".")).with_suffix(".py").resolve()


def _compare_full_depth_evidence(  # noqa: PLR0912, PLR0915
    analyzer: MypyAnalyzer,
    endpoint: Endpoint,
    graph: Any,
    seed: str,
    *,
    side: Literal["baseline", "target"],
    root: Path,
) -> dict[str, Any]:
    """Compare route terminals and each physical call edge to full-depth stacks."""
    dependencies = analyzer.analyze_endpoint(endpoint)
    oracle_paths: list[tuple[tuple[Any, ...], ...]] = []
    oracle_sites = dependencies.get_resolved_call_sites()
    for stacks in dependencies.call_stacks.values():
        for stack in stacks:
            if not any(
                Path(frame.file_path).resolve() == _seed_path(root, seed)
                and frame.function_name.rsplit(".", maxsplit=1)[-1]
                == seed.rsplit(".", maxsplit=1)[-1]
                for frame in stack
            ):
                continue
            terminal = max(
                index
                for index, frame in enumerate(stack)
                if Path(frame.file_path).resolve() == _seed_path(root, seed)
                and frame.function_name.rsplit(".", maxsplit=1)[-1]
                == seed.rsplit(".", maxsplit=1)[-1]
            )
            rows: list[tuple[Any, ...]] = []
            for caller, callee in pairwise(stack[: terminal + 1]):
                # CallFrame stores the physical call line on the callee frame.
                line = callee.caller_line_number
                if line is None:
                    raise AssertionError(
                        f"oracle path lacks call coordinate: {caller!r} -> {callee!r}"
                    )
                caller_path = Path(caller.file_path).resolve()
                matching_sites = [
                        site
                        for site in oracle_sites
                        if Path(site.file_path).resolve() == caller_path
                        and site.line == line
                        and site.status.value == "exact"
                        and site.canonical_symbol == callee.function_name
                    ]
                if len(matching_sites) != 1:
                    raise AssertionError(
                        "full-depth stack edge does not map to one exact ResolvedCallSite: "
                        f"{caller!r} -> {callee!r}, matches={matching_sites!r}"
                    )
                target_site = matching_sites[0]
                if target_site.end_line is None or target_site.end_column is None:
                    raise AssertionError(f"exact call site lacks end coordinates: {target_site!r}")
                source_line = caller_path.read_bytes().splitlines()[line - 1]
                source_spelling = source_line[target_site.column : target_site.end_column].decode(
                    "utf-8"
                )
                if source_spelling != target_site.source_spelling:
                    raise AssertionError(
                        "oracle call-site spelling does not match its byte coordinates: "
                        f"site={target_site!r}, source={source_spelling!r}"
                    )
                rows.append(
                    (
                        caller_path.relative_to(root.resolve()).as_posix(),
                        line,
                        target_site.column,
                        target_site.end_line,
                        target_site.end_column,
                        target_site.canonical_symbol,
                        target_site.status.value,
                        target_site.invocation.value if target_site.invocation else None,
                    )
                )
            oracle_paths.append(tuple(rows))

    query = graph.query([ChangedSeed(side, seed)], side=side)
    graph_paths: list[tuple[tuple[Any, ...], ...]] = []
    expected_candidates = {endpoint.identifier} if oracle_paths else set()
    for item in query.evidence:
        rows_list: list[tuple[Any, ...]] = []
        for edge in item.witnesses:
            if edge.kind not in {"call", "constructor"}:
                continue
            target_span = edge.target_span
            if target_span is None:
                raise AssertionError(f"graph call edge has no exact target span: {edge!r}")
            matching_sites = [
                site
                for site in oracle_sites
                if Path(site.file_path).resolve() == Path(edge.span.path).resolve()
                and site.line == target_span.start_line
                and site.column == target_span.start_column
                and site.end_line == target_span.end_line
                and site.end_column == target_span.end_column
                and site.canonical_symbol == edge.callee
            ]
            if len(matching_sites) != 1:
                raise AssertionError(
                    "graph physical target does not map to one oracle call site: "
                    f"{edge!r}, matches={matching_sites!r}"
                )
            site = matching_sites[0]
            if edge.confidence != "HIGH":
                raise AssertionError(
                    f"exact oracle call site has lowered direct graph confidence: {edge!r}"
                )
            if edge.execution_state != "executed" or edge.reference_state != "invocation":
                raise AssertionError(
                    "call-stack oracle edge is not represented as an executed invocation: "
                    f"{edge!r}"
                )
            graph_argument_bindings = {
                (argument.source_index, argument.positional_index, argument.keyword)
                for argument in edge.arguments
                if argument.source_index >= 0
            }
            for argument in site.arguments:
                if (
                    argument.source_index,
                    argument.positional_index,
                    argument.keyword,
                ) not in graph_argument_bindings:
                    raise AssertionError(
                        "oracle finite argument binding is missing from graph edge: "
                        f"site={site!r}, argument={argument!r}, edge={edge!r}"
                    )
            rows_list.append(
                (
                Path(edge.span.path).resolve().relative_to(root.resolve()).as_posix(),
                target_span.start_line,
                target_span.start_column,
                target_span.end_line,
                target_span.end_column,
                edge.callee,
                "exact",
                edge.invocation,
            )
            )
        graph_rows = tuple(rows_list)
        if not graph_rows or graph_rows[-1][5] != seed:
            raise AssertionError(f"graph evidence does not terminate at changed symbol {seed!r}")
        graph_paths.append(graph_rows)
    # Full-depth forward stacks may include an intermediate prefix ending at
    # each helper. Compare the terminal-reaching complete physical paths only.
    oracle_terminal_paths = [path for path in oracle_paths if path]
    oracle_norm = sorted(oracle_terminal_paths)
    graph_norm = sorted(graph_paths)
    exact_sites = sum(1 for site in oracle_sites if site.status.value == "exact")
    graph_route_symbols = {
        fullname
        for item in query.evidence
        for fullname in (
            item.occurrence.symbol,
            item.seed.symbol,
            *(edge.caller for edge in item.witnesses),
        )
    }
    graph_symbol_ranges = {
        (
            Path(symbol.span.path).resolve().relative_to(root.resolve()).as_posix(),
            symbol.span.start_line,
            symbol.span.end_line,
        )
        for symbol in graph.symbols
        if symbol.fullname in graph_route_symbols and symbol.span is not None
    }
    oracle_symbol_ranges = {
        (
            Path(reference.file_path).resolve().relative_to(root.resolve()).as_posix(),
            reference.start_line,
            reference.end_line,
        )
        for reference in dependencies.referenced_symbols
        if Path(reference.file_path).resolve().is_relative_to(root.resolve())
    }
    result = {
        "candidate_ids": sorted({item.occurrence.endpoint_id for item in query.evidence}),
        "oracle_candidate_ids": sorted(expected_candidates),
        "physical_route_occurrences": sorted(
            item.occurrence.occurrence_id for item in query.evidence
        ),
        "terminal_count": len(query.evidence),
        "terminal_symbols": sorted({path[-1][5] for path in graph_paths if path}),
        "oracle_terminal_paths": [list(path) for path in oracle_norm],
        "graph_terminal_paths": [list(path) for path in graph_norm],
        "resolved_call_site_count": len(oracle_sites),
        "resolved_exact_call_site_count": exact_sites,
        "oracle_call_site_evidence": [
            {
                "path": Path(site.file_path).resolve().relative_to(root.resolve()).as_posix(),
                "line": site.line,
                "column": site.column,
                "end_line": site.end_line,
                "end_column": site.end_column,
                "canonical_symbol": site.canonical_symbol,
                "status": site.status.value,
                "invocation": site.invocation.value if site.invocation else None,
                "arguments": [
                    {
                        "source_index": argument.source_index,
                        "positional_index": argument.positional_index,
                        "keyword": argument.keyword,
                        "status": argument.status.value,
                        "value_hashes": list(argument.value_hashes),
                        "reason_code": argument.reason_code,
                    }
                    for argument in site.arguments
                ],
            }
            for site in oracle_sites
        ],
        "oracle_reference_evidence": {
            "referenced_files": {
                Path(path).resolve().relative_to(root.resolve()).as_posix(): sorted(lines)
                for path, lines in sorted(dependencies.referenced_files.items())
                if Path(path).resolve().is_relative_to(root.resolve())
            },
            "referenced_symbols": [
                {
                    "path": Path(reference.file_path)
                    .resolve()
                    .relative_to(root.resolve())
                    .as_posix(),
                    "symbol": reference.symbol_name,
                    "start_line": reference.start_line,
                    "end_line": reference.end_line,
                    "low_confidence": reference.low_confidence,
                }
                for reference in dependencies.referenced_symbols
                if Path(reference.file_path).resolve().is_relative_to(root.resolve())
            ],
        },
        "graph_route_symbol_ranges": sorted(graph_symbol_ranges),
        "oracle_referenced_symbol_ranges": sorted(oracle_symbol_ranges),
        "reference_range_comparability": bool(oracle_paths),
        "graph_route_evidence": [
            {
                "occurrence_id": item.occurrence.occurrence_id,
                "terminal_symbol": item.seed.symbol,
                "confidence": item.confidence,
                "execution_state": item.execution_state,
                "reference_state": item.reference_state,
                "witness_ids": [edge.witness_id for edge in item.witnesses],
                "incomplete": {
                    "capped": item.incomplete.capped,
                    "reasons": list(item.incomplete.reasons),
                    "affected_seeds": list(item.incomplete.affected_seeds),
                },
                "uncertainties": [
                    {
                        "category": uncertainty.category,
                        "reason_code": uncertainty.reason_code,
                    }
                    for uncertainty in item.uncertainties
                ],
            }
            for item in query.evidence
        ],
        "confidence_comparability": (
            "direct exact-call confidence is asserted HIGH; endpoint route-level confidence "
            "and graph effect/cap semantics have no one-to-one EndpointDependencies fields"
        ),
        "graph_confidences": sorted({item.confidence for item in query.evidence}),
        "graph_witnesses": [
            [
                {
                    "witness_id": edge.witness_id,
                    "kind": edge.kind,
                    "caller": edge.caller,
                    "callee": edge.callee,
                    "path": Path(edge.span.path).resolve().relative_to(root.resolve()).as_posix(),
                    "line": edge.span.start_line,
                    "column": edge.span.start_column,
                    "confidence": edge.confidence,
                    "execution_state": edge.execution_state,
                    "reference_state": edge.reference_state,
                    "relation": edge.relation,
                    "arguments": [
                        {
                            "source_index": argument.source_index,
                            "formal_name": argument.formal_name,
                            "positional_index": argument.positional_index,
                            "keyword": argument.keyword,
                            "expression_fullname": argument.expression_fullname,
                            "actual_type": argument.actual_type,
                            "formal_type": argument.formal_type,
                        }
                        for argument in edge.arguments
                    ],
                    "receiver_fullname": edge.receiver_fullname,
                    "environment": list(edge.environment),
                }
                for edge in item.witnesses
            ]
            for item in query.evidence
        ],
        "graph_execution_states": sorted({item.execution_state for item in query.evidence}),
        "graph_reference_states": sorted({item.reference_state for item in query.evidence}),
        "graph_uncertainties": [
            {
                "category": uncertainty.category,
                "reason_code": uncertainty.reason_code,
                "owner": uncertainty.owner,
                "path": Path(uncertainty.span.path)
                .resolve()
                .relative_to(root.resolve())
                .as_posix(),
                "line": uncertainty.span.start_line,
                "column": uncertainty.span.start_column,
                "source_spelling": uncertainty.source_spelling,
            }
            for item in query.evidence
            for uncertainty in item.uncertainties
        ],
        "uncertain_candidate_ids": sorted(
            {item.occurrence.endpoint_id for item in query.uncertain_evidence}
        ),
        "uncertain_evidence": [
            {
                "occurrence_id": item.occurrence.occurrence_id,
                "endpoint_id": item.occurrence.endpoint_id,
                "seed": item.seed.symbol,
                "confidence": item.confidence,
                "uncertainty_category": item.uncertainty.category,
                "reason_code": item.uncertainty.reason_code,
                "source_spelling": item.uncertainty.source_spelling,
                "supporting_witness_ids": [
                    edge.witness_id for edge in item.supporting_witnesses
                ],
                "incomplete": {
                    "capped": item.incomplete.capped,
                    "reasons": list(item.incomplete.reasons),
                    "affected_seeds": list(item.incomplete.affected_seeds),
                },
            }
            for item in query.uncertain_evidence
        ],
        "graph_incompleteness": {
            "capped": query.incomplete.capped,
            "reasons": list(query.incomplete.reasons),
            "affected_seeds": list(query.incomplete.affected_seeds),
        },
        "limitations": [
            "endpoint oracle call stacks and exact call sites do not encode graph cap state",
            "endpoint oracle does not expose the reverse graph effect-summary transfer",
            "DI transfer, unknown target, deferred callable, and route-conditional parity "
            "need paired fixtures and current change-mapper output comparison",
            "confidence is compared at exact direct call edges; oracle route-level confidence "
            "does not have a one-to-one field on EndpointDependencies",
        ],
    }
    actual_candidate_ids = sorted({item.occurrence.endpoint_id for item in query.evidence})
    if actual_candidate_ids != sorted(expected_candidates):
        raise AssertionError(f"full-depth candidate parity mismatch: {result!r}")
    if graph_norm != oracle_norm:
        raise AssertionError(f"full-depth physical witness parity mismatch: {result!r}")
    if oracle_paths and graph_symbol_ranges != oracle_symbol_ranges:
        raise AssertionError(f"full-depth referenced-symbol range parity mismatch: {result!r}")
    if query.incomplete.capped:
        raise AssertionError(f"uncapped generated parity fixture unexpectedly capped: {result!r}")
    return result


def _p95(samples: list[float]) -> float:
    ordered = sorted(samples)
    return ordered[max(0, int(0.95 * len(ordered) + 0.999999) - 1)]


def _measure(modules: int, samples: int) -> dict[str, Any]:  # noqa: PLR0915
    phases: dict[str, list[float]] = {
        name: []
        for name in (
            "typed_provider_cold_build_seconds",
            "oracle_full_depth_cold_build_seconds",
            "graph_cold_build_seconds",
            "warm_query_seconds",
            "one_file_provider_cold_rebuild_seconds",
            "one_file_oracle_full_depth_rebuild_seconds",
            "one_file_cold_graph_rebuild_seconds",
            "one_file_provider_incremental_update_seconds",
            "one_file_provider_graph_rebuild_seconds",
        )
    }
    oracle_checks = 0
    evidence_comparisons: list[dict[str, Any]] = []
    for _sample in range(samples):
        with tempfile.TemporaryDirectory(prefix="typed_reverse_graph_") as directory:
            root = Path(directory)
            sources = _write_fixture(root, modules)
            start = time.perf_counter()
            (
                inventory,
                snapshot,
                analyzer,
                provider,
                provider_paths,
                provider_elapsed,
                oracle_elapsed,
            ) = _retained_snapshot(root, max_depth=modules + 2)
            phases["typed_provider_cold_build_seconds"].append(provider_elapsed)
            phases["oracle_full_depth_cold_build_seconds"].append(oracle_elapsed)
            _endpoint_value, binding = _endpoint(root, snapshot)
            oracle_endpoint = _oracle_endpoint(root, analyzer)
            changed_module = _inventory_module(snapshot, f"{root.name}.m{modules - 1}")
            positive_seed = _fullname(snapshot, changed_module, f"f{modules - 1}")
            start = time.perf_counter()
            graph = build_typed_reverse_graph(
                inventory, snapshot, [binding], config_fingerprint="generated-v1"
            )
            phases["graph_cold_build_seconds"].append(time.perf_counter() - start)
            initial_oracle_paths = _physical_oracle_paths(
                analyzer, oracle_endpoint, positive_seed, root
            )
            initial_provider_paths = _graph_physical_paths(graph, positive_seed, side="baseline")
            if initial_provider_paths != initial_oracle_paths:
                raise AssertionError(
                    "retained provider cold graph physical parity mismatch: "
                    f"provider={initial_provider_paths!r}, oracle={initial_oracle_paths!r}"
                )
            oracle_checks += 1
            evidence_comparisons.append(
                {
                    "phase": "provider_cold",
                    "oracle_terminal_paths": initial_oracle_paths,
                    "provider_terminal_paths": initial_provider_paths,
                    "provider_report_mode": snapshot.report.mode,
                    "provider_cache_fingerprint": snapshot.report.cache_fingerprint,
                }
            )
            positive_evidence = _compare_full_depth_evidence(
                analyzer, oracle_endpoint, graph, positive_seed, side="baseline", root=root
            )
            oracle_checks += 1
            evidence_comparisons.append(positive_evidence)
            negative_module = _inventory_module(snapshot, f"{root.name}.m0")
            negative_seed = _fullname(snapshot, negative_module, "unused")
            negative_evidence = _compare_full_depth_evidence(
                analyzer, oracle_endpoint, graph, negative_seed, side="baseline", root=root
            )
            oracle_checks += 1
            evidence_comparisons.append(negative_evidence)
            start = time.perf_counter()
            for _ in range(5):
                graph.query([ChangedSeed("baseline", positive_seed)], side="baseline")
            phases["warm_query_seconds"].append((time.perf_counter() - start) / 5)

            updated_sources = dict(sources)
            updated_sources[f"m{modules - 1}"] = updated_sources[f"m{modules - 1}"].replace(
                "return value + 0", "return value + 1"
            )
            (root / f"m{modules - 1}.py").write_text(
                updated_sources[f"m{modules - 1}"], encoding="utf-8"
            )
            start = time.perf_counter()
            provider_typed = provider.build(provider_paths)
            phases["one_file_provider_incremental_update_seconds"].append(
                time.perf_counter() - start
            )
            provider_inventory = Inventory(
                root,
                tuple(
                    SourceRecord(
                        module,
                        path,
                        path.relative_to(root).as_posix(),
                        hashlib.sha256(path.read_bytes()).hexdigest(),
                    )
                    for module, path in sorted(provider_paths.items())
                ),
            )
            _provider_endpoint, provider_binding = _endpoint(root, provider_typed)
            start = time.perf_counter()
            provider_graph = build_typed_reverse_graph(
                provider_inventory,
                provider_typed,
                [provider_binding],
                config_fingerprint="generated-v1",
            )
            phases["one_file_provider_graph_rebuild_seconds"].append(
                time.perf_counter() - start
            )
            start = time.perf_counter()
            (
                updated_inventory,
                updated_snapshot,
                updated_analyzer,
                _updated_provider,
                _updated_paths,
                updated_provider_elapsed,
                updated_oracle_elapsed,
            ) = _retained_snapshot(root, max_depth=modules + 2)
            phases["one_file_provider_cold_rebuild_seconds"].append(
                updated_provider_elapsed
            )
            phases["one_file_oracle_full_depth_rebuild_seconds"].append(updated_oracle_elapsed)
            _updated_endpoint, updated_binding = _endpoint(root, updated_snapshot)
            start = time.perf_counter()
            updated_graph = build_typed_reverse_graph(
                updated_inventory,
                updated_snapshot,
                [updated_binding],
                config_fingerprint="generated-v1",
            )
            phases["one_file_cold_graph_rebuild_seconds"].append(time.perf_counter() - start)
            updated_oracle_endpoint = _oracle_endpoint(root, updated_analyzer)
            updated_seed = _fullname(
                updated_snapshot,
                _inventory_module(updated_snapshot, f"{root.name}.m{modules - 1}"),
                f"f{modules - 1}",
            )
            provider_seed = _fullname(
                provider_typed,
                _inventory_module(provider_typed, f"{root.name}.m{modules - 1}"),
                f"f{modules - 1}",
            )
            provider_update_evidence = _compare_full_depth_evidence(
                updated_analyzer,
                updated_oracle_endpoint,
                provider_graph,
                provider_seed,
                side="target",
                root=root,
            )
            oracle_checks += 1
            evidence_comparisons.append(
                {
                    **provider_update_evidence,
                    "phase": "provider_incremental_update_full_evidence",
                    "provider_report_mode": provider_typed.report.mode,
                    "provider_updated_modules": list(provider_typed.report.updated_modules),
                }
            )
            updated_evidence = _compare_full_depth_evidence(
                updated_analyzer,
                updated_oracle_endpoint,
                updated_graph,
                updated_seed,
                side="target",
                root=root,
            )
            oracle_checks += 1
            evidence_comparisons.append(updated_evidence)
            updated_oracle_paths = _physical_oracle_paths(
                updated_analyzer, updated_oracle_endpoint, updated_seed, root
            )
            updated_provider_paths = _graph_physical_paths(
                provider_graph,
                _fullname(
                    provider_typed,
                    _inventory_module(provider_typed, f"{root.name}.m{modules - 1}"),
                    f"f{modules - 1}",
                ),
            )
            if updated_provider_paths != updated_oracle_paths:
                raise AssertionError(
                    "retained provider incremental graph physical parity mismatch: "
                    f"provider={updated_provider_paths!r}, oracle={updated_oracle_paths!r}"
                )
            if provider_typed.report.mode != "incremental_update":
                raise AssertionError(
                    "one-file provider phase fell back instead of testing retained update: "
                    f"{provider_typed.report.mode!r}"
                )
            expected_updated_module = f"{root.name}.m{modules - 1}"
            if provider_typed.report.updated_modules != (expected_updated_module,):
                raise AssertionError(
                    "retained provider updated an unexpected module set: "
                    f"expected={(expected_updated_module,)!r}, "
                    f"actual={provider_typed.report.updated_modules!r}"
                )
            oracle_checks += 1
            evidence_comparisons.append(
                {
                    "phase": "provider_incremental_update",
                    "oracle_terminal_paths": updated_oracle_paths,
                    "provider_terminal_paths": updated_provider_paths,
                    "provider_report_mode": provider_typed.report.mode,
                    "provider_updated_modules": list(provider_typed.report.updated_modules),
                    "provider_cache_fingerprint": provider_typed.report.cache_fingerprint,
                }
            )

    return {
        "schema_version": 3,
        "fixture": (
            "generated typed call DAG with one endpoint, a positive path, "
            "and an uncalled negative function"
        ),
        "modules": modules,
        "samples": samples,
        "oracle": (
            "full-depth call_stacks plus exact ResolvedCallSite byte coordinates, "
            "canonical targets, invocation/resolution status, argument bindings, "
            "referenced symbols/files, and terminal occurrence evidence"
        ),
        "oracle_checks": oracle_checks,
        "evidence_comparisons": evidence_comparisons,
        "python_version": platform.python_version(),
        "mypy_version": version("mypy"),
        "raw_samples": phases,
        "p95_seconds": {name: _p95(values) for name, values in phases.items()},
        "notes": [
            "baseline and target graphs use separate retained provider snapshots",
            "one-file phases separate PR #326 incremental update from fresh typed rebuild",
            "fixture parity does not establish corpus, DI, dispatch, or effect parity",
            "direct exact-call confidence and execution/invocation state are checked",
            "endpoint oracle has no matching route confidence, effect-summary, "
            "graph-cap, or deferred-callable output; those dimensions remain unproven",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--modules", type=int, default=24)
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.modules < 4:
        parser.error("--modules must be at least 4")
    if args.samples < 1:
        parser.error("--samples must be positive")
    result = _measure(args.modules, args.samples)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
