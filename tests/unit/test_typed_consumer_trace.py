"""Realized typed-node consumer tracing through analyzer and phase APIs."""

from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from mypy.build import BuildSource, build
from mypy.nodes import (
    Block,
    ClassDef,
    Decorator,
    FuncDef,
    NameExpr,
    SymbolTable,
    TypeInfo,
)
from mypy.options import Options

from fastapi_endpoint_detector.analyzer.framework_phase_integration import (
    collect_framework_phase_evidence,
)
from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.analyzer.mypy_incremental import (
    BuildConfig,
    MypyIncrementalProvider,
    TypedBuild,
)
from fastapi_endpoint_detector.analyzer.typed_cache_admission import CacheRunPlan
from fastapi_endpoint_detector.analyzer.typed_consumer_trace import (
    ConsumerTraceRejected,
    ConsumerTraceSnapshot,
    TypedConsumerTrace,
    audited_typeinfo_get,
    collect_typed_consumer_trace,
)
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo
from fastapi_endpoint_detector.models.surface_contract import load_surface_preset
from fastapi_endpoint_detector.parser.custom_surface_extractor import CustomSurfaceExtractor


def _source_snapshot(typed_build: TypedBuild, paths: tuple[Path, ...]) -> ConsumerTraceSnapshot:
    project_sources = {str(path.resolve()): path.read_bytes() for path in paths}
    external_sources: dict[str, bytes] = {}
    for module, state in typed_build.modules.items():
        if module == "fastapi.applications" and state.path:
            path = Path(state.path).resolve()
            external_sources[str(path)] = path.read_bytes()
            break
    return ConsumerTraceSnapshot.from_owner_snapshots(
        typed_build,
        source_root=paths[0].parent,
        project_sources=project_sources,
        external_sources=external_sources,
    )


def _assert_unknown_decorator_child_rejected(
    trace: TypedConsumerTrace, typed_build: TypedBuild
) -> None:
    app_tree = typed_build.modules["app"].tree
    registration = next(
        statement for statement in app_tree.defs if isinstance(statement, Decorator)
    )
    original_func = registration.func
    registration.func = FuncDef("injected_unknown", [], Block([]))
    try:
        _ = registration.fullname
    finally:
        registration.func = original_func
    assert any(
        "unknown typed node: mypy.nodes.FuncDef.fullname" in blocker
        for blocker in trace.result().blockers
    )
    with pytest.raises(ConsumerTraceRejected):
        trace.require_complete()


def _assert_independent_reader_failures(
    trace: TypedConsumerTrace,
    typed_build: TypedBuild,
    snapshot: ConsumerTraceSnapshot,
    source_root: Path,
) -> None:
    info_node = typed_build.modules["fastapi.applications"].tree.names["FastAPI"].node
    assert isinstance(info_node, TypeInfo)
    _assert_unknown_decorator_child_rejected(trace, typed_build)
    original_mro = info_node.mro
    unknown_def = ClassDef("InjectedUnknown", Block([]))
    unknown_base = TypeInfo(SymbolTable(), unknown_def, "injected_unknown")
    info_node.mro = [*original_mro, unknown_base]
    try:
        assert audited_typeinfo_get(info_node, "__r31_missing_member__") is None
    finally:
        info_node.mro = original_mro
    assert any(
        "unknown typed node: mypy.nodes.TypeInfo.names" in blocker
        for blocker in trace.result().blockers
    )
    original_reader = TypeInfo.__getattribute__
    had_local_reader = "__getattribute__" in TypeInfo.__dict__
    TypeInfo.__getattribute__ = object.__getattribute__
    try:
        _ = info_node.fullname
        with pytest.raises(ConsumerTraceRejected):
            trace.require_complete()
        assert any(
            "retained graph node reader changed" in blocker for blocker in trace.result().blockers
        )
    finally:
        if had_local_reader:
            TypeInfo.__getattribute__ = original_reader
        else:
            del TypeInfo.__getattribute__
    with (
        pytest.raises(ConsumerTraceRejected, match="nested typed consumer traces"),
        collect_typed_consumer_trace(snapshot, typed_build, source_root=source_root),
    ):
        pass


def _assert_invalid_cache_plan_rejected(
    snapshot: ConsumerTraceSnapshot, typed_build: TypedBuild, source_root: Path
) -> None:
    invalid_plan = CacheRunPlan(
        run_root=source_root / "unrelated-run",
        cache_map={"/fake/source.pyi": ("/tmp/nonexistent.meta", "/tmp/nonexistent.data")},
        expected_graph={},
        expected_roots=frozenset(),
        admitted_modules=frozenset({"foreignpkg.bridge"}),
        manifest_sha256="invalid",
        trust_id="invalid",
        artifact_hashes={"/tmp/nonexistent.meta": "0" * 64},
    )
    invalid_trace = TypedConsumerTrace(
        snapshot, typed_build, source_root=source_root, cache_plan=invalid_plan
    )
    blockers = invalid_trace.result().blockers
    assert any("typed build did not consume the exact planned cache map" in b for b in blockers)
    assert any(
        "cache artifact digest keys do not exactly match staged members" in blocker
        for blocker in blockers
    )


def test_public_analyzer_and_phase_trace_uses_one_retained_typed_graph(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.on_event('startup')\n"
        "def start() -> None:\n"
        "    print('started')\n",
        encoding="utf-8",
    )
    contracts = load_surface_preset("framework-v1")
    inventory = CustomSurfaceExtractor(tmp_path, contracts).extract_inventory()
    provider = MypyIncrementalProvider(BuildConfig(tmp_path))
    typed_build = provider.build({"app": source})
    snapshot = _source_snapshot(typed_build, (source,))
    analyzer = MypyAnalyzer(source, module_root=tmp_path)
    analyzer.attach_typed_build(
        typed_build,
        source_bytes={path: item.data for path, item in snapshot.sources.items()},
    )

    with collect_typed_consumer_trace(snapshot, typed_build, source_root=tmp_path) as trace:
        report = collect_framework_phase_evidence(inventory, contracts, analyzer, typed_build)
        result = trace.require_complete()
        assert TypeInfo in trace.node_types
        _assert_independent_reader_failures(trace, typed_build, snapshot, tmp_path)
        with pytest.raises(ConsumerTraceRejected):
            trace.require_complete()

    assert report.records and report.records[0].typed_framework_symbol == (
        "fastapi.applications.FastAPI.on_event"
    )
    assert any(access.consumer.endswith(".walk_node") for access in result.accesses)
    assert any(
        access.consumer.endswith("._resolved_call_site_uncached") for access in result.accesses
    )
    audited_fields = {field for access in result.accesses for field in access.fields}
    assert {"rvalue", "lvalues", "expr", "body", "args"} <= audited_fields
    assert result.canonical_registration_pins
    assert (
        result.canonical_registration_pins[0][1]
        == hashlib.sha256(
            snapshot.sources[result.canonical_registration_pins[0][0]].data
        ).hexdigest()
    )
    assert result.complete, result.blockers
    assert all(access.node_identity > 0 for access in result.accesses)
    assert any("nested typed consumer traces" in blocker for blocker in trace.result().blockers)
    assert any(
        "actual Mypy node field read belongs to an unknown typed node" in blocker
        for blocker in trace.result().blockers
    )

    with collect_typed_consumer_trace(snapshot, typed_build, source_root=tmp_path) as unknown_trace:
        unknown_node = NameExpr("outside_graph")
        assert unknown_node.name == "outside_graph"
    assert any("unknown typed node" in blocker for blocker in unknown_trace.result().blockers)


def _assert_missing_attribute_reads_are_recorded(trace: TypedConsumerTrace, node: object) -> None:
    assert not hasattr(node, "r35_absent_field")
    with pytest.raises(AttributeError):
        getattr(node, "r37_absent_getattr_field")  # noqa: B009
    for field in ("r35_absent_field", "r37_absent_getattr_field"):
        assert any(
            access.node_identity == id(node)
            and access.fields == (field,)
            and not access.value_present
            for access in trace.result().accesses
        )


def test_real_cached_foreign_forward_consumer_is_rejected(tmp_path: Path) -> None:
    package = tmp_path / "foreignpkg"
    package.mkdir()
    init = package / "__init__.py"
    init.write_text("", encoding="utf-8")
    bridge = package / "bridge.pyi"
    bridge.write_text(
        "class Foreign:\n    def forward(self, value: int) -> int: ...\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from foreignpkg.bridge import Foreign\n"
        "def nested(value: int) -> int:\n"
        "    return Foreign().forward(value)\n"
        "def endpoint(value: int) -> int:\n"
        "    return nested(value)\n",
        encoding="utf-8",
    )
    cache_dir = tmp_path / "mypy-cache"
    options = Options()
    options.mypy_path = [str(tmp_path)]
    options.incremental = True
    options.cache_dir = str(cache_dir)
    options.export_types = True
    options.preserve_asts = True
    options.ignore_missing_imports = True
    options.check_untyped_defs = True
    options.follow_imports = "normal"
    cold = build([BuildSource(str(main), "main", text=main.read_text())], options)
    warm = build([BuildSource(str(main), "main", text=main.read_text())], options)
    assert "foreignpkg.bridge" not in warm.manager.rechecked_modules
    foreign_type = warm.graph["foreignpkg.bridge"].tree.names["Foreign"].node
    forward_node = foreign_type.names["forward"].node
    if type(forward_node).__name__ == "Decorator":
        forward_node = forward_node.func
    assert forward_node.line == -1
    assert forward_node.body.body == [], "the control must exercise an empty cached body block"
    typed_build = SimpleNamespace(
        result=warm,
        manager=warm.manager,
        modules=warm.graph,
        module_paths={name: str(state.path) for name, state in warm.graph.items() if state.path},
    )
    del cold
    source_paths = (main, init, bridge)
    sources = {str(path.resolve()): path.read_bytes() for path in source_paths}
    snapshot = ConsumerTraceSnapshot.from_owner_snapshots(
        typed_build,
        source_root=tmp_path,
        project_sources=sources,
        external_sources={},
    )
    endpoint = Endpoint(
        path="/forward",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="endpoint",
            module="main",
            file_path=main,
            line_number=4,
        ),
    )
    analyzer = MypyAnalyzer(main, module_root=tmp_path)
    analyzer.attach_typed_build(typed_build, source_bytes=sources)

    with collect_typed_consumer_trace(snapshot, typed_build, source_root=tmp_path) as trace:
        analyzer.analyze_endpoint(endpoint)
        _assert_missing_attribute_reads_are_recorded(trace, forward_node)
        endpoint_result = trace.result()
        assert any(
            "cached typed node field read" in blocker and "foreignpkg.bridge" in blocker
            for blocker in endpoint_result.blockers
        ), endpoint_result.blockers
        assert any(
            access.module == "foreignpkg.bridge"
            and access.fullname == "foreignpkg.bridge.Foreign.forward"
            and access.fields
            for access in endpoint_result.accesses
        ), "the public endpoint path itself must read the cached callable"
        assert analyzer._callable_declaration(forward_node) is not None
    result = trace.result()

    assert any(
        "cached typed node field read" in blocker and "foreignpkg.bridge" in blocker
        for blocker in result.blockers
    ), result.blockers
    assert any(
        access.module == "foreignpkg.bridge"
        and access.fullname == "foreignpkg.bridge.Foreign.forward"
        and access.shape.line == -1
        and access.shape.body_child_count == 0
        for access in result.accesses
    )
    _assert_invalid_cache_plan_rejected(snapshot, typed_build, tmp_path)
    assert any(
        access.consumer.endswith("._callable_declaration") and access.module == "foreignpkg.bridge"
        for access in result.accesses
    ), "cached declaration must be rejected when a helper binds the returned callable"


def test_real_dynamic_or_untyped_call_consumer_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "main.py"
    source.write_text(
        "from typing import Any\ndef endpoint(handler: Any) -> Any:\n    return handler()\n",
        encoding="utf-8",
    )
    typed_build = MypyIncrementalProvider(BuildConfig(tmp_path)).build({"main": source})
    source_bytes = {str(source.resolve()): source.read_bytes()}
    snapshot = ConsumerTraceSnapshot.from_owner_snapshots(
        typed_build,
        source_root=tmp_path,
        project_sources=source_bytes,
        external_sources={},
    )
    endpoint = Endpoint(
        path="/dynamic",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="endpoint",
            module="main",
            file_path=source,
            line_number=2,
        ),
    )
    analyzer = MypyAnalyzer(source, module_root=tmp_path)
    analyzer.attach_typed_build(typed_build, source_bytes=source_bytes)

    with collect_typed_consumer_trace(snapshot, typed_build, source_root=tmp_path) as trace:
        analyzer.analyze_endpoint(endpoint)
    result = trace.result()

    assert any("nonexact typed consumer" in blocker for blocker in result.blockers)


def test_real_cached_on_event_declaration_is_source_pinned(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "from fastapi import FastAPI\n"
        "app: FastAPI\n"
        "@app.on_event('startup')\n"
        "def start() -> None: pass\n",
        encoding="utf-8",
    )
    cache_dir = tmp_path / "mypy-cache"
    options = Options()
    options.mypy_path = [str(tmp_path)]
    options.incremental = True
    options.cache_dir = str(cache_dir)
    options.export_types = True
    options.preserve_asts = True
    options.ignore_missing_imports = True
    options.check_untyped_defs = True
    cold = build([BuildSource(str(source), "app", text=source.read_text())], options)
    warm = build([BuildSource(str(source), "app", text=source.read_text())], options)
    assert "app" in warm.manager.rechecked_modules
    assert "fastapi.applications" not in warm.manager.rechecked_modules
    typed_build = SimpleNamespace(
        result=warm,
        manager=warm.manager,
        modules=warm.graph,
        module_paths={name: str(state.path) for name, state in warm.graph.items() if state.path},
    )
    del cold
    app_module = warm.graph["fastapi.applications"]
    app_source = Path(app_module.path).resolve()
    project_sources = {str(source.resolve()): source.read_bytes()}
    external_sources = {str(app_source): app_source.read_bytes()}
    snapshot = ConsumerTraceSnapshot.from_owner_snapshots(
        typed_build,
        source_root=tmp_path,
        project_sources=project_sources,
        external_sources=external_sources,
    )
    analyzer = MypyAnalyzer(source, module_root=tmp_path)
    analyzer.attach_typed_build(
        typed_build,
        source_bytes={**project_sources, **external_sources},
    )
    endpoint = Endpoint(
        path="/startup",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="start",
            module="app",
            file_path=source,
            line_number=4,
        ),
    )

    with collect_typed_consumer_trace(snapshot, typed_build, source_root=tmp_path) as trace:
        analyzer.analyze_endpoint(endpoint)
    result = trace.result()

    canonical_accesses = [
        access
        for access in result.accesses
        if access.fullname == "fastapi.applications.FastAPI.on_event"
    ]
    assert canonical_accesses
    assert all(access.cached for access in canonical_accesses)
    assert all(access.shape.line == -1 for access in canonical_accesses)
    assert all(
        access.shape.body_present is False or access.shape.body_child_count == 0
        for access in canonical_accesses
    )
    assert result.canonical_registration_pins == (
        (str(app_source), hashlib.sha256(external_sources[str(app_source)]).hexdigest()),
    )
    assert any("no matching admitted artifact binding" in blocker for blocker in result.blockers)
