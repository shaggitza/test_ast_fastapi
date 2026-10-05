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
from types import SimpleNamespace
from typing import Any

from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
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


def _retained_snapshot(root: Path, *, max_depth: int) -> tuple[Inventory, Any, MypyAnalyzer]:
    analyzer = MypyAnalyzer(root, max_depth=max_depth)
    analyzer._ensure_mypy_built()
    module_paths = {
        module: Path(path)
        for module, path in analyzer._module_to_path.items()
        if Path(path).suffix == ".py" and Path(path).is_relative_to(root)
    }
    records = tuple(
        SourceRecord(
            module,
            path,
            path.relative_to(root).as_posix(),
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )
        for module, path in sorted(module_paths.items())
    )
    modules = {name: SimpleNamespace(tree=tree) for name, tree in analyzer._trees.items()}
    typed = SimpleNamespace(
        modules=modules,
        module_paths={module: str(path) for module, path in module_paths.items()},
        type_maps=analyzer._types_map,
        report=SimpleNamespace(
            cache_fingerprint=f"mypy:{version('mypy')}:{root.resolve()}",
            engine="mypy-build-api",
            mypy_version=version("mypy"),
        ),
    )
    return Inventory(root, records), typed, analyzer


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


def _oracle_set(analyzer: MypyAnalyzer, endpoint: Endpoint, changed_symbol: str) -> set[str]:
    dependencies = analyzer.analyze_endpoint(endpoint)
    found = any(
        frame.function_name == changed_symbol
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
            names = [frame.function_name for frame in stack]
            if seed not in names:
                continue
            terminal = names.index(seed)
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
                        target_site.canonical_symbol,
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
            "typed_cold_build_seconds",
            "graph_cold_build_seconds",
            "warm_query_seconds",
            "one_file_typed_full_rebuild_seconds",
            "one_file_graph_rebuild_seconds",
        )
    }
    oracle_checks = 0
    evidence_comparisons: list[dict[str, Any]] = []
    for _sample in range(samples):
        with tempfile.TemporaryDirectory(prefix="typed_reverse_graph_") as directory:
            root = Path(directory)
            sources = _write_fixture(root, modules)
            start = time.perf_counter()
            inventory, snapshot, analyzer = _retained_snapshot(root, max_depth=modules + 2)
            phases["typed_cold_build_seconds"].append(time.perf_counter() - start)
            endpoint, binding = _endpoint(root, snapshot)
            changed_module = _inventory_module(snapshot, f"m{modules - 1}")
            positive_seed = _fullname(snapshot, changed_module, f"f{modules - 1}")
            start = time.perf_counter()
            graph = build_typed_reverse_graph(
                inventory, snapshot, [binding], config_fingerprint="generated-v1"
            )
            phases["graph_cold_build_seconds"].append(time.perf_counter() - start)
            positive_evidence = _compare_full_depth_evidence(
                analyzer, endpoint, graph, positive_seed, side="target", root=root
            )
            expected = _oracle_set(analyzer, endpoint, positive_seed)
            actual = set(positive_evidence["candidate_ids"])
            if actual != expected:
                dependencies = analyzer.analyze_endpoint(endpoint)
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
            expected_negative = _oracle_set(analyzer, endpoint, negative_seed)
            actual_negative = {
                item.occurrence.endpoint_id
                for item in graph.query(
                    [ChangedSeed("target", negative_seed)], side="target"
                ).evidence
            }
            negative_evidence = _compare_full_depth_evidence(
                analyzer, endpoint, graph, negative_seed, side="target", root=root
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
                graph.query([ChangedSeed("target", positive_seed)], side="target")
            phases["warm_query_seconds"].append((time.perf_counter() - start) / 5)

            updated_sources = dict(sources)
            updated_sources[f"m{modules - 1}"] = updated_sources[f"m{modules - 1}"].replace(
                "return value + 0", "return value + 1"
            )
            (root / f"m{modules - 1}.py").write_text(
                updated_sources[f"m{modules - 1}"], encoding="utf-8"
            )
            start = time.perf_counter()
            updated_inventory, updated_snapshot, updated_analyzer = _retained_snapshot(
                root, max_depth=modules + 2
            )
            phases["one_file_typed_full_rebuild_seconds"].append(time.perf_counter() - start)
            _endpoint_value, updated_binding = _endpoint(root, updated_snapshot)
            start = time.perf_counter()
            updated_graph = build_typed_reverse_graph(
                updated_inventory,
                updated_snapshot,
                [updated_binding],
                config_fingerprint="generated-v1",
            )
            phases["one_file_graph_rebuild_seconds"].append(time.perf_counter() - start)
            updated_endpoint, _ = _endpoint(root, updated_snapshot)
            updated_seed = _fullname(
                updated_snapshot,
                _inventory_module(updated_snapshot, f"m{modules - 1}"),
                f"f{modules - 1}",
            )
            updated_evidence = _compare_full_depth_evidence(
                updated_analyzer,
                updated_endpoint,
                updated_graph,
                updated_seed,
                side="target",
                root=root,
            )
            updated_actual = set(updated_evidence["candidate_ids"])
            updated_expected = _oracle_set(updated_analyzer, updated_endpoint, updated_seed)
            if updated_actual != updated_expected:
                raise AssertionError(
                    "one-file parity mismatch: "
                    f"graph={updated_actual!r}, oracle={updated_expected!r}"
                )
            oracle_checks += 1
            evidence_comparisons.append(updated_evidence)

    return {
        "schema_version": 1,
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
            "one-file phase is a fresh full typed rebuild here, not a fine-grained provider update",
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
