from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from itertools import pairwise
from pathlib import Path
from types import SimpleNamespace

from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.analyzer.mypy_incremental import BuildConfig, MypyIncrementalProvider
from fastapi_endpoint_detector.analyzer.typed_reverse_graph import (
    ChangedSeed,
    EndpointOccurrenceBinding,
    SourceSpan,
    TraversalBudgets,
    TypedGraphCache,
    build_typed_reverse_graph,
    seeds_for_changed_coordinates,
)
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo


@dataclass(frozen=True)
class _Record:
    module: str
    path: Path
    relative_path: str
    sha256: str


@dataclass(frozen=True)
class _Inventory:
    root: Path
    files: tuple[_Record, ...]


def _snapshot(root: Path, sources: dict[str, str]):
    for module, source in sources.items():
        path = root / f"{module}.py"
        path.write_text(source, encoding="utf-8")
    analyzer = MypyAnalyzer(root)
    analyzer._ensure_mypy_built()
    provider = MypyIncrementalProvider(BuildConfig(source_root=root))
    typed = provider.build({module: root / f"{module}.py" for module in sources})
    records = tuple(
        _Record(
            module,
            root / f"{module}.py",
            Path(f"{module}.py").as_posix(),
            hashlib.sha256((root / f"{module}.py").read_bytes()).hexdigest(),
        )
        for module in sorted(sources)
    )
    return _Inventory(root, records), typed, analyzer


def _binding(root: Path, module: str, symbol: str, occurrence: str) -> EndpointOccurrenceBinding:
    path = root / f"{module.rsplit('.', maxsplit=1)[-1]}.py"
    raw = path.read_bytes()
    lines = raw.splitlines(keepends=True)
    start_line = 2 if len(lines) > 1 else 1
    end_line = len(lines)
    digest = hashlib.sha256(raw).hexdigest()
    return EndpointOccurrenceBinding(
        occurrence,
        "GET /items",
        symbol,
        SourceSpan(module, str(path.resolve()), digest, start_line, 0, end_line, 0),
    )


def _fullname(snapshot: object, module: str, name: str) -> str:
    return snapshot.modules[module].tree.names[name].node.fullname


def _module(snapshot: object, name: str) -> str:
    return next(module for module in snapshot.modules if module.rsplit(".", maxsplit=1)[-1] == name)


def test_snapshot_graph_preserves_reconvergent_physical_paths_and_occurrences(
    tmp_path: Path,
) -> None:
    inventory, snapshot, _ = _snapshot(
        tmp_path,
        {
            "app": "from service import left, right\ndef handler():\n    left()\n    right()\n",
            "service": (
                "from leaf import changed\n"
                "def left():\n    changed()\n"
                "def right():\n    changed()\n"
            ),
            "leaf": "def changed():\n    return None\n",
        },
    )
    app_module = _module(snapshot, "app")
    leaf_module = _module(snapshot, "leaf")
    handler_symbol = _fullname(snapshot, app_module, "handler")
    bindings = [
        _binding(tmp_path, app_module, handler_symbol, "route-a"),
        _binding(tmp_path, app_module, handler_symbol, "route-b"),
    ]
    graph = build_typed_reverse_graph(inventory, snapshot, bindings, config_fingerprint="cfg")
    result = graph.query(
        [ChangedSeed("target", _fullname(snapshot, leaf_module, "changed"))], side="target"
    )

    assert len(result.evidence) == 4  # two paths x two physical route occurrences
    assert {item.occurrence.occurrence_id for item in result.evidence} == {"route-a", "route-b"}
    assert {len(item.witnesses) for item in result.evidence} == {2}
    assert not result.incomplete.capped


def test_global_relations_and_lambda_execution_state_are_distinct(tmp_path: Path) -> None:
    inventory, snapshot, _ = _snapshot(
        tmp_path,
        {
            "app": (
                "from service import changed\n"
                "VALUE = 1\n"
                "def handler():\n"
                "    cb = lambda: changed()\n"
                "    (lambda: changed())()\n"
                "    return VALUE\n"
            ),
            "service": "def changed():\n    return None\n",
        },
    )
    app_module = _module(snapshot, "app")
    binding = _binding(
        tmp_path,
        app_module,
        _fullname(snapshot, app_module, "handler"),
        "route",
    )
    graph = build_typed_reverse_graph(inventory, snapshot, [binding], config_fingerprint="cfg")
    service_module = _module(snapshot, "service")
    changed = _fullname(snapshot, service_module, "changed")
    lambda_edges = [edge for edge in graph.edges if edge.callee == changed]

    assert {edge.execution_state for edge in lambda_edges} == {"deferred", "executed"}
    assert any(edge.kind == "global_read" and edge.callee.endswith("VALUE") for edge in graph.edges)
    assert any(
        edge.kind == "global_write" and edge.callee.endswith("VALUE") for edge in graph.edges
    )
    result = graph.query([ChangedSeed("target", changed)], side="target")
    assert result.evidence
    assert all(item.confidence == "LOW" for item in result.evidence)
    assert all(
        any(uncertainty.category == "deferred_callable" for uncertainty in item.uncertainties)
        for item in result.evidence
    )


def test_caps_are_explicit_and_fail_closed_even_when_evidence_was_found(tmp_path: Path) -> None:
    inventory, snapshot, _ = _snapshot(
        tmp_path,
        {
            "app": "def handler():\n    return None\ndef dispatcher():\n    handler()\n",
        },
    )
    app_module = _module(snapshot, "app")
    binding = _binding(tmp_path, app_module, _fullname(snapshot, app_module, "handler"), "route")
    graph = build_typed_reverse_graph(inventory, snapshot, [binding], config_fingerprint="cfg")
    result = graph.query(
        [ChangedSeed("target", _fullname(snapshot, app_module, "handler"))],
        side="target",
        budgets=TraversalBudgets(nodes=1),
    )

    assert result.incomplete.capped
    assert "node_budget" in result.incomplete.reasons
    assert result.evidence
    assert all(item.confidence == "LOW" for item in result.evidence)
    assert all(item.incomplete.capped for item in result.evidence)


def test_cache_rejects_changed_bytes_symlinks_and_root_mismatch(tmp_path: Path) -> None:
    inventory, snapshot, _ = _snapshot(tmp_path, {"app": "def handler():\n    return 1\n"})
    app_module = _module(snapshot, "app")
    binding = _binding(tmp_path, app_module, _fullname(snapshot, app_module, "handler"), "route")
    graph = build_typed_reverse_graph(inventory, snapshot, [binding], config_fingerprint="cfg")

    assert TypedGraphCache.validate(
        graph, inventory, snapshot, config_fingerprint="cfg"
    )
    assert TypedGraphCache.cache_key(graph) != TypedGraphCache.cache_key(
        replace(graph, engine_version="different")
    )
    assert not TypedGraphCache.validate(
        graph, inventory, snapshot, config_fingerprint="other"
    )
    assert not TypedGraphCache.validate(
        graph,
        replace(inventory, root=tmp_path / "other"),
        snapshot,
        config_fingerprint="cfg",
    )
    assert not TypedGraphCache.validate(
        replace(graph, schema_version=99),
        inventory,
        snapshot,
        config_fingerprint="cfg",
    )
    assert not TypedGraphCache.validate(
        replace(graph, graph_provenance="different-provider-build"),
        inventory,
        snapshot,
        config_fingerprint="cfg",
    )
    assert not TypedGraphCache.validate(
        replace(graph, engine="different-engine"),
        inventory,
        snapshot,
        config_fingerprint="cfg",
    )
    assert not TypedGraphCache.validate(
        graph,
        inventory,
        replace(
            snapshot,
            report=replace(snapshot.report, cache_fingerprint="other-build"),
        ),
        config_fingerprint="cfg",
    )
    assert not TypedGraphCache.validate(
        graph,
        inventory,
        replace(
            snapshot,
            report=replace(
                snapshot.report,
                source_digests_after=(("app", "0" * 64),),
            ),
        ),
        config_fingerprint="cfg",
    )
    inventory.files[0].path.write_text("def handler():\n    return 2\n", encoding="utf-8")
    assert not TypedGraphCache.validate(
        graph, inventory, snapshot, config_fingerprint="cfg"
    )

    alias = tmp_path / "alias.py"
    alias.symlink_to(inventory.files[0].path)
    bad = _Inventory(tmp_path, (_Record("app", alias, "alias.py", graph.source_hashes[0][1]),))
    assert not TypedGraphCache.validate(
        graph, bad, snapshot, config_fingerprint="cfg"
    )


def test_constructor_seed_uses_typed_constructor_target(tmp_path: Path) -> None:
    inventory, snapshot, _ = _snapshot(
        tmp_path,
        {
            "app": "from model import Item\ndef handler():\n    return Item(1)\n",
            "model": "class Item:\n    def __init__(self, key: int):\n        self.key = key\n",
        },
    )
    app_module = _module(snapshot, "app")
    binding = _binding(tmp_path, app_module, _fullname(snapshot, app_module, "handler"), "route")
    graph = build_typed_reverse_graph(inventory, snapshot, [binding], config_fingerprint="cfg")

    constructor = next(edge for edge in graph.edges if edge.relation == "typed_constructor")
    assert constructor.arguments[0].formal_name == "self"
    assert constructor.arguments[1].formal_name == "key"
    assert constructor.arguments[1].formal_type == "builtins.int"
    result = graph.query([ChangedSeed("target", constructor.callee)], side="target")
    assert result.evidence and result.evidence[0].occurrence.occurrence_id == "route"


def test_typed_arguments_and_utf8_end_columns_use_provider_findings(tmp_path: Path) -> None:
    inventory, snapshot, _ = _snapshot(
        tmp_path,
        {
            "app": (
                "from service import changed\n"
                "def handler() -> str:\n"
                '    return changed("café")\n'
            ),
            "service": "def changed(value: str) -> str:\n    return value\n",
        },
    )
    edge = next(item for item in build_typed_reverse_graph(
        inventory, snapshot, [], config_fingerprint="cfg"
    ).edges if item.callee.endswith("service.changed"))
    raw_line = (tmp_path / "app.py").read_bytes().splitlines()[edge.span.start_line - 1]

    assert edge.arguments[0].actual_type is not None
    assert "café" in edge.arguments[0].actual_type
    assert edge.arguments[0].formal_type == "builtins.str"
    source_slice = raw_line[edge.span.start_column : edge.span.end_column].decode("utf-8")
    assert source_slice == 'changed("café")'


def test_keyword_formals_resolve_exactly_and_starred_formals_abstain(tmp_path: Path) -> None:
    inventory, snapshot, _ = _snapshot(
        tmp_path,
        {
            "app": (
                "from service import combine as join\n"
                "def handler(first: str, second: str, values: tuple[str, ...]):\n"
                "    join(second=second, first=first)\n"
                "    join(*values)\n"
            ),
            "service": (
                "def combine(first: str, second: str) -> None:\n"
                "    return None\n"
            ),
        },
    )
    graph = build_typed_reverse_graph(inventory, snapshot, [], config_fingerprint="cfg")
    calls = [edge for edge in graph.edges if edge.callee.endswith("service.combine")]
    keyword_call = next(edge for edge in calls if len(edge.arguments) == 2)
    starred_call = next(edge for edge in calls if len(edge.arguments) == 1)

    assert [argument.formal_name for argument in keyword_call.arguments] == [
        "second",
        "first",
    ]
    assert all(argument.formal_type == "builtins.str" for argument in keyword_call.arguments)
    assert [argument.expression_fullname for argument in keyword_call.arguments] == [
        "app.handler.second",
        "app.handler.first",
    ]
    assert starred_call.arguments[0].formal_name is None
    assert any(
        item.owner == starred_call.caller
        and item.reason_code == "starred_actual_formal_binding_unresolved"
        for item in graph.uncertainties
    )


def test_unmodeled_binding_effect_and_virtual_dispatch_are_per_evidence(
    tmp_path: Path,
) -> None:
    inventory, snapshot, _ = _snapshot(
        tmp_path,
        {
            "app": (
                "from service import changed\n"
                "def handler(obj, callback):\n"
                "    obj.run()\n"
                "    callback()\n"
                "    return changed()\n"
            ),
            "service": "def changed():\n    return None\ndef other():\n    return None\n",
        },
    )
    app_module = _module(snapshot, "app")
    binding = _binding(
        tmp_path,
        app_module,
        _fullname(snapshot, app_module, "handler"),
        "route",
    )
    graph = build_typed_reverse_graph(inventory, snapshot, [binding], config_fingerprint="cfg")
    result = graph.query(
        [ChangedSeed("target", _fullname(snapshot, _module(snapshot, "service"), "changed"))],
        side="target",
    )

    assert len(result.evidence) == 1
    evidence = result.evidence[0]
    assert evidence.confidence == "LOW"
    categories = {item.category for item in evidence.uncertainties}
    assert "effect_summary" in categories
    assert "unknown_binding" in categories
    assert "virtual_dispatch" in categories
    assert "effect_transfer_not_imported" in evidence.incomplete.reasons
    unknown = graph.query(
        [ChangedSeed("target", _fullname(snapshot, _module(snapshot, "service"), "other"))],
        side="target",
    )
    assert unknown.evidence == ()
    assert unknown.uncertain_evidence
    assert all(item.confidence == "LOW" for item in unknown.uncertain_evidence)
    assert all(
        item.uncertainty.category in {"unknown_binding", "virtual_dispatch"}
        for item in unknown.uncertain_evidence
    )


def test_dependency_occurrence_binding_creates_uncertain_typed_edge(tmp_path: Path) -> None:
    inventory, snapshot, _ = _snapshot(
        tmp_path,
        {
            "app": "def handler(value):\n    return value\n",
            "service": "def dependency():\n    return 1\n",
        },
    )
    app_module = _module(snapshot, "app")
    service_module = _module(snapshot, "service")
    handler = _fullname(snapshot, app_module, "handler")
    dependency = _fullname(snapshot, service_module, "dependency")
    binding = replace(
        _binding(tmp_path, app_module, handler, "route"),
        dependency_symbols=(dependency,),
    )
    graph = build_typed_reverse_graph(inventory, snapshot, [binding], config_fingerprint="cfg")
    result = graph.query([ChangedSeed("target", dependency)], side="target")

    assert len(result.evidence) == 1
    assert result.evidence[0].confidence == "LOW"
    assert result.evidence[0].witnesses[0].kind == "dependency"
    assert result.evidence[0].uncertainties[0].category == "dependency_injection"
    assert "dependency_parameter_transfer_not_proven" in result.incomplete.reasons


def test_conditional_route_binding_forces_low_confidence() -> None:
    binding = EndpointOccurrenceBinding(
        "conditional-route",
        "GET /conditional",
        "app.handler",
        SourceSpan("app", "/project/app.py", "0" * 64, 1, 0, 1, 12),
        conditional=True,
    )
    assert binding.confidence == "LOW"


def test_removed_baseline_and_added_target_use_separate_typed_snapshots(
    tmp_path: Path,
) -> None:
    baseline_inventory, baseline_snapshot, _ = _snapshot(
        tmp_path,
        {
            "app": "from service import old\ndef handler():\n    return old()\n",
            "service": "def old():\n    return 1\n",
        },
    )
    app_module = _module(baseline_snapshot, "app")
    baseline_binding = _binding(
        tmp_path,
        app_module,
        _fullname(baseline_snapshot, app_module, "handler"),
        "same-route",
    )
    baseline_graph = build_typed_reverse_graph(
        baseline_inventory,
        baseline_snapshot,
        [baseline_binding],
        config_fingerprint="paired-cfg",
    )
    service_module = _module(baseline_snapshot, "service")
    removed_seed = seeds_for_changed_coordinates(
        "baseline", [(str(tmp_path / "service.py"), 1, 4)], baseline_graph
    )

    target_inventory, target_snapshot, _ = _snapshot(
        tmp_path,
        {
            "app": "from service import new\ndef handler():\n    return new()\n",
            "service": "def new():\n    return 2\n",
        },
    )
    target_app_module = _module(target_snapshot, "app")
    target_binding = _binding(
        tmp_path,
        target_app_module,
        _fullname(target_snapshot, target_app_module, "handler"),
        "same-route",
    )
    target_graph = build_typed_reverse_graph(
        target_inventory,
        target_snapshot,
        [target_binding],
        config_fingerprint="paired-cfg",
    )
    added_seed = seeds_for_changed_coordinates(
        "target", [(str(tmp_path / "service.py"), 1, 4)], target_graph
    )

    baseline_result = baseline_graph.query(removed_seed, side="baseline")
    target_result = target_graph.query(added_seed, side="target")
    wrong_side = target_graph.query(
        [ChangedSeed("target", _fullname(baseline_snapshot, service_module, "old"))],
        side="target",
    )
    assert removed_seed and added_seed
    assert baseline_result.evidence and baseline_result.evidence[0].side == "baseline"
    assert target_result.evidence and target_result.evidence[0].side == "target"
    assert wrong_side.evidence == ()


def test_pr326_retained_update_graph_matches_independent_cold_call_path(
    tmp_path: Path,
) -> None:
    paths = {
        "app": tmp_path / "app.py",
        "m0": tmp_path / "m0.py",
        "m1": tmp_path / "m1.py",
        "leaf": tmp_path / "leaf.py",
    }
    paths["app"].write_text(
        "from m0 import first\ndef handler(value: int) -> int:\n    return first(value)\n",
        encoding="utf-8",
    )
    paths["m0"].write_text(
        "from m1 import second\ndef first(value: int) -> int:\n    return second(value)\n",
        encoding="utf-8",
    )
    paths["m1"].write_text(
        "from leaf import changed\ndef second(value: int) -> int:\n    return changed(value)\n",
        encoding="utf-8",
    )
    paths["leaf"].write_text(
        "def changed(value: int) -> int:\n    return value\n", encoding="utf-8"
    )
    provider = MypyIncrementalProvider(BuildConfig(source_root=tmp_path))
    source_inventory = dict(paths)
    provider.build(source_inventory)
    paths["leaf"].write_text(
        "def changed(value: int) -> int:\n    return value + 1\n", encoding="utf-8"
    )
    typed = provider.build(source_inventory)
    assert typed.report.mode == "incremental_update"
    assert "leaf" in typed.report.updated_modules

    records = tuple(
        _Record(
            module,
            path,
            path.relative_to(tmp_path).as_posix(),
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )
        for module, path in sorted(paths.items())
    )
    inventory = _Inventory(tmp_path, records)
    handler_symbol = typed.modules["app"].tree.names["handler"].node.fullname
    app_digest = hashlib.sha256(paths["app"].read_bytes()).hexdigest()
    binding = EndpointOccurrenceBinding(
        "provider-route",
        "GET /provider",
        handler_symbol,
        SourceSpan("app", str(paths["app"].resolve()), app_digest, 2, 0, 3, 0),
    )
    graph = build_typed_reverse_graph(
        inventory, typed, [binding], config_fingerprint="provider-integration-test"
    )
    result = graph.query([ChangedSeed("target", "leaf.changed")], side="target")

    analyzer = MypyAnalyzer(tmp_path, max_depth=16)
    analyzer._ensure_mypy_built()
    analyzer_app = _module(
        SimpleNamespace(modules={
            module: SimpleNamespace(tree=tree)
            for module, tree in analyzer._trees.items()
        }),
        "app",
    )
    endpoint = Endpoint(
        path="/provider",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="handler",
            module=analyzer_app,
            file_path=paths["app"],
            line_number=2,
            end_line_number=3,
        ),
    )
    oracle = analyzer.analyze_endpoint(endpoint)
    oracle_paths = [
        stack
        for stacks in oracle.call_stacks.values()
        for stack in stacks
        if any(frame.function_name.endswith(".changed") for frame in stack)
    ]
    oracle_edges = sorted(
        (
            Path(caller.file_path).relative_to(tmp_path).as_posix(),
            callee.caller_line_number,
        )
        for stack in oracle_paths
        for caller, callee in pairwise(stack)
    )
    graph_edges = sorted(
        (Path(edge.span.path).relative_to(tmp_path).as_posix(), edge.span.start_line)
        for evidence in result.evidence
        for edge in evidence.witnesses
        if edge.kind in {"call", "constructor"}
    )
    assert result.evidence and result.evidence[0].confidence == "LOW"
    assert oracle_paths
    assert graph_edges == oracle_edges


def test_generated_fixture_matches_current_full_depth_candidate_oracle(tmp_path: Path) -> None:
    inventory, snapshot, analyzer = _snapshot(
        tmp_path,
        {
            "app": "from service import left\ndef handler():\n    left()\n",
            "service": "from leaf import changed\ndef left():\n    changed()\n",
            "leaf": "def changed():\n    return None\n",
        },
    )
    app_module = _module(snapshot, "app")
    leaf_module = _module(snapshot, "leaf")
    endpoint = Endpoint(
        path="/fixture",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="handler",
            module=app_module,
            file_path=tmp_path / "app.py",
            line_number=2,
        ),
    )
    oracle = analyzer.analyze_endpoint(endpoint)
    occurrence = _binding(
        tmp_path, app_module, _fullname(snapshot, app_module, "handler"), endpoint.identifier
    )
    graph = build_typed_reverse_graph(inventory, snapshot, [occurrence], config_fingerprint="cfg")
    result = graph.query(
        [ChangedSeed("target", _fullname(snapshot, leaf_module, "changed"))], side="target"
    )

    oracle_affected = str((tmp_path / "leaf.py").resolve()) in oracle.call_stacks
    reverse_affected = any(
        evidence.occurrence.occurrence_id == endpoint.identifier for evidence in result.evidence
    )
    assert oracle_affected is True
    assert reverse_affected == oracle_affected


def test_recursive_scc_and_input_order_are_deterministic(tmp_path: Path) -> None:
    inventory, snapshot, _ = _snapshot(
        tmp_path,
        {
            "app": "from graph import first\ndef handler():\n    first()\n",
            "graph": ("def first():\n    second()\ndef second():\n    first()\n    return None\n"),
        },
    )
    app_module = _module(snapshot, "app")
    graph_module = _module(snapshot, "graph")
    binding = _binding(tmp_path, app_module, _fullname(snapshot, app_module, "handler"), "route")
    reverse = build_typed_reverse_graph(inventory, snapshot, [binding], config_fingerprint="cfg")
    seed = ChangedSeed("baseline", _fullname(snapshot, graph_module, "second"))
    forward_result = reverse.query([seed], side="baseline")
    reordered = replace(reverse, edges=tuple(reversed(reverse.edges)))
    reverse_result = reordered.query([seed], side="baseline")

    assert forward_result == reverse_result
    assert len(forward_result.evidence) == 1
    assert forward_result.evidence[0].side == "baseline"
    assert len(forward_result.evidence[0].witnesses) <= 3
    assert reverse.query([seed], side="target").evidence == ()


def test_exact_changed_coordinate_seeds_and_conditional_low_cap(tmp_path: Path) -> None:
    inventory, snapshot, _ = _snapshot(
        tmp_path,
        {
            "app": "from service import changed\ndef handler():\n    changed()\n",
            "service": "def changed():\n    return None\n",
        },
    )
    app_module = _module(snapshot, "app")
    service_module = _module(snapshot, "service")
    handler = _fullname(snapshot, app_module, "handler")
    changed = _fullname(snapshot, service_module, "changed")
    changed_path = tmp_path / "service.py"
    binding = replace(
        _binding(tmp_path, app_module, handler, "conditional-route"), confidence="LOW"
    )
    graph = build_typed_reverse_graph(inventory, snapshot, [binding], config_fingerprint="cfg")
    seeds = seeds_for_changed_coordinates("baseline", [(str(changed_path), 1, 4)], graph)
    result = graph.query(seeds, side="baseline")

    assert [seed.symbol for seed in seeds] == [changed]
    assert result.evidence
    assert all(item.confidence == "LOW" for item in result.evidence)
