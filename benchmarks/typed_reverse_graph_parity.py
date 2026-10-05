"""Generated evidence parity and phase benchmark for the opt-in reverse graph.

The oracle is current full-depth MypyAnalyzer call stacks and resolved call sites.
Candidate, physical path, and edge-coordinate mismatches fail without filtering.
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
from typing import Any

from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.analyzer.mypy_incremental import BuildConfig, MypyIncrementalProvider
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
            imported = f"from m{following} import f{following}\n"
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
    sources["app"] = "from m0 import f0\ndef handler(value: int) -> int:\n    return f0(value)\n"
    for module, source in sources.items():
        (root / f"{module}.py").write_text(source, encoding="utf-8")
    return sources


def _retained_snapshot(root: Path, *, max_depth: int):
    module_paths = {path.stem: path for path in sorted(root.glob("*.py"))}
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
    analyzer: MypyAnalyzer, endpoint: Endpoint, terminal_name: str, root: Path
) -> list[tuple[tuple[str, int], ...]]:
    dependencies = analyzer.analyze_endpoint(endpoint)
    paths: list[tuple[tuple[str, int], ...]] = []
    for stacks in dependencies.call_stacks.values():
        for stack in stacks:
            terminal_indexes = [
                index
                for index, frame in enumerate(stack)
                if frame.function_name.rsplit(".", maxsplit=1)[-1] == terminal_name
            ]
            if not terminal_indexes:
                continue
            terminal = terminal_indexes[-1]
            physical = []
            for caller, callee in pairwise(stack[: terminal + 1]):
                if callee.caller_line_number is None:
                    raise AssertionError("full-depth oracle path lacks caller line coordinate")
                physical.append(
                    (
                        Path(caller.file_path).resolve().relative_to(root.resolve()).as_posix(),
                        callee.caller_line_number,
                    )
                )
            paths.append(tuple(physical))
    return sorted(set(paths))


def _graph_physical_paths(
    graph: Any, seed: str, *, side: str = "target"
) -> list[tuple[tuple[str, int], ...]]:
    result = graph.query([ChangedSeed(side, seed)], side=side)
    return sorted(
        {
            tuple(
                (
                    Path(edge.span.path).resolve().relative_to(Path(graph.root)).as_posix(),
                    edge.span.start_line,
                )
                for edge in evidence.witnesses
                if edge.kind in {"call", "constructor"}
            )
            for evidence in result.evidence
        }
    )


def _inventory_module(snapshot: Any, short: str) -> str:
    return next(
        module
        for module, state in snapshot.modules.items()
        if module.rsplit(".", maxsplit=1)[-1] == short and getattr(state, "tree", None) is not None
    )


def _fullname(snapshot: Any, module: str, name: str) -> str:
    return snapshot.modules[module].tree.names[name].node.fullname


def _endpoint(root: Path, snapshot: Any) -> tuple[Endpoint, EndpointOccurrenceBinding]:
    module = _inventory_module(snapshot, "app")
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
    return root.joinpath(*module.split(".")).with_suffix(".py").resolve()


def _oracle_set(
    analyzer: MypyAnalyzer, endpoint: Endpoint, changed_symbol: str, root: Path
) -> set[str]:
    dependencies = analyzer.analyze_endpoint(endpoint)
    expected_path = _seed_path(root, changed_symbol)
    expected_name = changed_symbol.rsplit(".", maxsplit=1)[-1]
    found = any(
        Path(frame.file_path).resolve() == expected_path
        and frame.function_name.rsplit(".", maxsplit=1)[-1] == expected_name
        for call_stacks in dependencies.call_stacks.values()
        for stack in call_stacks
        for frame in stack
    )
    return {endpoint.identifier} if found else set()


def _compare_full_depth_evidence(
    analyzer: MypyAnalyzer,
    endpoint: Endpoint,
    graph: Any,
    seed: str,
    *,
    side: str,
    root: Path,
) -> dict[str, Any]:
    """Compare route terminals and each physical call edge to full-depth stacks."""
    dependencies = analyzer.analyze_endpoint(endpoint)
    oracle_paths: list[tuple[tuple[str, int, str], ...]] = []
    oracle_sites = {
        (Path(site.file_path).resolve(), site.line, site.canonical_symbol, site.status.value)
        for site in dependencies.get_resolved_call_sites()
    }
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
            rows: list[tuple[str, int, str]] = []
            for caller, callee in pairwise(stack[: terminal + 1]):
                # CallFrame stores the physical call line on the callee frame.
                line = callee.caller_line_number
                if line is None:
                    raise AssertionError(
                        f"oracle path lacks call coordinate: {caller!r} -> {callee!r}"
                    )
                caller_path = Path(caller.file_path).resolve()
                target_site = next(
                    (
                        site
                        for site in dependencies.get_resolved_call_sites()
                        if Path(site.file_path).resolve() == caller_path
                        and site.line == line
                        and site.status.value == "exact"
                        and site.canonical_symbol is not None
                        and site.canonical_symbol.rsplit(".", maxsplit=1)[-1]
                        == callee.function_name.rsplit(".", maxsplit=1)[-1]
                    ),
                    None,
                )
                if target_site is None:
                    raise AssertionError(
                        "full-depth stack edge lacks exact ResolvedCallSite: "
                        f"{caller!r} -> {callee!r}"
                    )
                rows.append(
                    (
                        caller_path.relative_to(root.resolve()).as_posix(),
                        line,
                        (
                            Path(callee.file_path)
                            .resolve()
                            .relative_to(root.resolve())
                            .with_suffix("")
                            .as_posix()
                            .replace("/", ".")
                            + "."
                            + callee.function_name.rsplit(".", maxsplit=1)[-1]
                        ),
                    )
                )
            oracle_paths.append(tuple(rows))

    query = graph.query([ChangedSeed(side, seed)], side=side)
    graph_paths: list[tuple[tuple[str, int, str], ...]] = []
    for item in query.evidence:
        rows = tuple(
            (
                Path(edge.span.path).resolve().relative_to(root.resolve()).as_posix(),
                edge.span.start_line,
                edge.callee,
            )
            for edge in item.witnesses
            if edge.kind in {"call", "constructor"}
        )
        graph_paths.append(rows)
    # Full-depth forward stacks may include an intermediate prefix ending at
    # each helper. Compare the terminal-reaching complete physical paths only.
    oracle_terminal_paths = [path for path in oracle_paths if path]
    oracle_norm = sorted(oracle_terminal_paths)
    graph_norm = sorted(graph_paths)
    exact_sites = sum(1 for site in oracle_sites if site[3] == "exact")
    result = {
        "candidate_ids": sorted({item.occurrence.endpoint_id for item in query.evidence}),
        "physical_route_occurrences": sorted(
            item.occurrence.occurrence_id for item in query.evidence
        ),
        "terminal_count": len(query.evidence),
        "oracle_terminal_paths": [list(path) for path in oracle_norm],
        "graph_terminal_paths": [list(path) for path in graph_norm],
        "resolved_call_site_count": len(oracle_sites),
        "resolved_exact_call_site_count": exact_sites,
        "confidence_comparability": (
            "not represented by the current full-depth endpoint oracle; graph confidence "
            "is shown with uncertainty witnesses and is not inferred from exact call resolution"
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
        "limitation": (
            "existing endpoint output has no graph-level cap/effect-summary field; effect, DI, "
            "and conditional-route parity remain explicitly unproven"
        ),
    }
    if graph_norm != oracle_norm:
        raise AssertionError(f"full-depth physical witness parity mismatch: {result!r}")
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
            changed_module = _inventory_module(snapshot, f"m{modules - 1}")
            positive_seed = _fullname(snapshot, changed_module, f"f{modules - 1}")
            start = time.perf_counter()
            graph = build_typed_reverse_graph(
                inventory, snapshot, [binding], config_fingerprint="generated-v1"
            )
            phases["graph_cold_build_seconds"].append(time.perf_counter() - start)
            initial_oracle_paths = _physical_oracle_paths(
                analyzer, oracle_endpoint, f"f{modules - 1}", root
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
                    "provider_report_mode": provider._typed.report.mode,
                    "provider_cache_fingerprint": provider._typed.report.cache_fingerprint,
                }
            )
            positive_evidence = _compare_full_depth_evidence(
                analyzer, oracle_endpoint, graph, positive_seed, side="baseline", root=root
            )
            expected = _oracle_set(analyzer, oracle_endpoint, positive_seed, root)
            actual = set(positive_evidence["candidate_ids"])
            if actual != expected:
                dependencies = analyzer.analyze_endpoint(oracle_endpoint)
                frame_names = [
                    frame.function_name
                    for stacks in dependencies.call_stacks.values()
                    for stack in stacks
                    for frame in stack
                ]
                raise AssertionError(
                    f"positive parity mismatch: graph={actual!r}, oracle={expected!r}, "
                    f"seed={positive_seed!r}, frames={frame_names!r}"
                )
            oracle_checks += 1
            evidence_comparisons.append(positive_evidence)
            negative_module = _inventory_module(snapshot, "m0")
            negative_seed = _fullname(snapshot, negative_module, "unused")
            expected_negative = _oracle_set(analyzer, oracle_endpoint, negative_seed, root)
            actual_negative = {
                item.occurrence.endpoint_id
                for item in graph.query(
                    [ChangedSeed("baseline", negative_seed)], side="baseline"
                ).evidence
            }
            negative_evidence = _compare_full_depth_evidence(
                analyzer, oracle_endpoint, graph, negative_seed, side="baseline", root=root
            )
            actual_negative = set(negative_evidence["candidate_ids"])
            if actual_negative != expected_negative:
                raise AssertionError(
                    "negative parity mismatch: "
                    f"graph={actual_negative!r}, oracle={expected_negative!r}"
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
                _inventory_module(updated_snapshot, f"m{modules - 1}"),
                f"f{modules - 1}",
            )
            updated_evidence = _compare_full_depth_evidence(
                updated_analyzer,
                updated_oracle_endpoint,
                updated_graph,
                updated_seed,
                side="target",
                root=root,
            )
            updated_actual = set(updated_evidence["candidate_ids"])
            updated_expected = _oracle_set(
                updated_analyzer, updated_oracle_endpoint, updated_seed, root
            )
            if updated_actual != updated_expected:
                raise AssertionError(
                    "one-file parity mismatch: "
                    f"graph={updated_actual!r}, oracle={updated_expected!r}"
                )
            oracle_checks += 1
            evidence_comparisons.append(updated_evidence)
            updated_oracle_paths = _physical_oracle_paths(
                updated_analyzer, updated_oracle_endpoint, f"f{modules - 1}", root
            )
            updated_provider_paths = _graph_physical_paths(
                provider_graph,
                f"m{modules - 1}.f{modules - 1}",
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
        "schema_version": 2,
        "fixture": (
            "generated typed call DAG with one endpoint, a positive path, "
            "and an uncalled negative function"
        ),
        "modules": modules,
        "samples": samples,
        "oracle": (
            "full-depth call_stacks plus resolved_call_sites physical edge paths "
            "and terminal occurrence evidence"
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
            "oracle does not expose effect summaries or route confidence caps; "
            "those remain unproven",
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
