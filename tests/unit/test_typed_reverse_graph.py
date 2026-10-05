from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace

from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
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
    modules = {name: SimpleNamespace(tree=tree) for name, tree in analyzer._trees.items()}
    records = [
        _Record(
            module,
            Path(path),
            Path(path).name,
            hashlib.sha256(Path(path).read_bytes()).hexdigest(),
        )
        for module, path in analyzer._module_to_path.items()
        if Path(path).suffix == ".py" and Path(path).is_relative_to(root)
    ]
    typed = SimpleNamespace(
        modules=modules,
        module_paths=analyzer._module_to_path,
        type_maps=analyzer._types_map,
        report=SimpleNamespace(
            cache_fingerprint="test-provider-fingerprint",
            engine="mypy-fine-grained",
            mypy_version="1.19.1",
        ),
    )
    return _Inventory(root, tuple(records)), typed, analyzer


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
