"""Version-independent declaration controls; no application or provider code is run."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest
from mypy.nodes import (
    GDEF,
    MDEF,
    Block,
    ClassDef,
    Decorator,
    ExpressionStmt,
    FuncDef,
    MypyFile,
    NameExpr,
    SymbolTable,
    SymbolTableNode,
    TypeInfo,
    Var,
)
from mypy.types import Instance

from fastapi_endpoint_detector.analyzer import typed_consumer_trace as reader
from fastapi_endpoint_detector.models.effect_contract import (
    CallResolutionStatus,
    InvocationKind,
    ResolvedCallSite,
)


@dataclass
class _OwnedGraph:
    root: Path
    build: SimpleNamespace
    snapshot: reader.ConsumerTraceSnapshot
    probe: NameExpr
    receiver: TypeInfo
    owner: TypeInfo
    declaration: FuncDef
    wrapper: FuncDef | Decorator
    selector: str
    owner_path: str
    source_hash: str


def _info(module: str, name: str) -> TypeInfo:
    definition = ClassDef(name, Block([]))
    definition.fullname = f"{module}.{name}"
    info = TypeInfo(SymbolTable(), definition, module)
    info._fullname = definition.fullname
    definition.info = info
    info.mro = [info]
    return info


def _method(owner: TypeInfo, name: str, *, decorated: bool) -> tuple[FuncDef, FuncDef | Decorator]:
    function = FuncDef(name, [], Block([]))
    function._fullname = f"{owner.fullname}.{name}"
    function.info = owner
    wrapper: FuncDef | Decorator = function
    if decorated:
        variable = Var(name)
        variable._fullname = function.fullname
        variable.info = owner
        wrapper = Decorator(function, [], variable)
    owner.names[name] = SymbolTableNode(MDEF, wrapper)
    return function, wrapper


def _owned_graph(
    path: Path,
    *,
    method: str = "add_event_handler",
    class_name: str = "APIRouter",
    inherited: bool = False,
    cached: bool = False,
    decorated: bool = True,
) -> _OwnedGraph:
    root = (path / "project").resolve()
    receiver_module = {
        "FastAPI": "fastapi.applications",
        "APIRouter": "fastapi.routing",
        "Starlette": "starlette.applications",
    }[class_name]
    public_module = "fastapi" if class_name != "Starlette" else receiver_module
    receiver = _info(receiver_module, class_name)
    owner = _info("fastapi.synthetic_base", "BaseRouter") if inherited else receiver
    if inherited:
        receiver.mro = [receiver, owner]
    declaration, wrapper = _method(owner, method, decorated=decorated)
    probe = NameExpr("owned_probe")
    probe.line = 1
    probe.column = 0
    modules: dict[str, SimpleNamespace] = {}
    sources: dict[str, reader.TraceSource] = {}
    exports = {
        "app": {},
        public_module: {class_name: receiver},
        receiver_module: {class_name: receiver},
    }
    if inherited:
        exports["fastapi.synthetic_base"] = {"BaseRouter": owner}
    for module, nodes in exports.items():
        module_path = str(
            (root / "app.py") if module == "app" else (path / "provider" / f"{module}.py")
        )
        tree = MypyFile([ExpressionStmt(probe)] if module == "app" else [], [], False)
        tree._fullname = module
        tree.names = SymbolTable()
        tree.path = module_path
        for name, node in nodes.items():
            tree.names[name] = SymbolTableNode(GDEF, node)
        raw = f"# owned inert source snapshot for {module}\n".encode()
        modules[module] = SimpleNamespace(
            path=module_path,
            tree=tree,
            source_hash=hashlib.sha1(raw).hexdigest(),
        )
        sources[module_path] = reader.TraceSource(
            module_path,
            raw,
            "project_snapshot" if module == "app" else "admitted_external_source",
        )
    owner_path = modules[owner.module_name].path
    build = SimpleNamespace(
        modules=modules,
        manager=SimpleNamespace(rechecked_modules={"app"} if cached else set(modules)),
    )
    return _OwnedGraph(
        root,
        build,
        reader.ConsumerTraceSnapshot(sources),
        probe,
        receiver,
        owner,
        declaration,
        wrapper,
        f"{public_module}.{class_name}.{method}",
        owner_path,
        sources[owner_path].sha256,
    )


def _site(graph: _OwnedGraph, **updates: object) -> ResolvedCallSite:
    row: dict[str, object] = {
        "file_path": str(graph.root / "app.py"),
        "line": 1,
        "column": 0,
        "end_line": 1,
        "end_column": 5,
        "source_spelling": "owned_probe",
        "canonical_symbol": graph.declaration.fullname,
        "receiver_candidates": [graph.receiver.fullname],
        "invocation": InvocationKind.INSTANCE_METHOD,
        "status": CallResolutionStatus.EXACT,
        "resolver": "mypy",
        "resolver_version": "owned-node-control",
    }
    row.update(updates)
    return ResolvedCallSite.model_validate(row)


def _trace(graph: _OwnedGraph, symbols: tuple[str, ...] | None = None) -> reader.TypedConsumerTrace:
    return reader.TypedConsumerTrace(
        graph.snapshot,
        graph.build,
        source_root=graph.root,
        registration_symbols=(graph.selector,) if symbols is None else symbols,
    )


def _read_probe(probe: NameExpr) -> None:
    assert probe.name == "owned_probe"


@pytest.mark.parametrize(
    ("class_name", "method"),
    [("FastAPI", "on_event"), ("APIRouter", "on_event"), ("APIRouter", "add_event_handler")],
)
@pytest.mark.parametrize("decorated", [False, True])
def test_selected_public_alias_pins_the_exact_effective_declaration(
    tmp_path: Path, method: str, class_name: str, decorated: bool
) -> None:
    graph = _owned_graph(tmp_path, method=method, class_name=class_name, decorated=decorated)
    site = _site(graph)
    trace = _trace(graph)
    assert trace.node_modules[id(graph.declaration)] == graph.owner.module_name
    with trace:
        _read_probe(graph.probe)
        reader.observe_framework_registration(site, graph.selector)
        result = trace.require_complete()
    assert result.canonical_registration_pins == ((graph.owner_path, graph.source_hash),)
    assert result.complete
    with pytest.raises(RuntimeError, match="entered twice"):
        trace.__enter__()


def test_inherited_registration_pins_declaring_source_and_rejects_changed_mro(
    tmp_path: Path,
) -> None:
    graph = _owned_graph(tmp_path, inherited=True)
    site = _site(graph)
    trace = _trace(graph)
    assert trace.node_modules[id(graph.declaration)] == graph.owner.module_name
    with trace:
        _read_probe(graph.probe)
        reader.observe_framework_registration(site, graph.selector)
        result = trace.require_complete()
    receiver_path = graph.build.modules["fastapi.routing"].path
    assert receiver_path != graph.owner_path
    assert result.canonical_registration_pins == ((graph.owner_path, graph.source_hash),)

    changed = _trace(graph)
    override, _wrapper = _method(graph.receiver, "add_event_handler", decorated=False)
    assert override is not graph.declaration
    with changed:
        _read_probe(graph.probe)
        reader.observe_framework_registration(site, graph.selector)
        with pytest.raises(reader.ConsumerTraceRejected, match="identity differs"):
            changed.require_complete()
    assert not changed.result().framework_registration_observed


@pytest.mark.parametrize(
    "mutation", ["alias_copy", "declaration_copy", "owner_export_copy", "missing_owner"]
)
def test_nominal_copies_and_absent_declaring_owners_cannot_borrow_a_selected_pin(
    tmp_path: Path, mutation: str
) -> None:
    graph = _owned_graph(tmp_path, inherited=True)
    trace = _trace(graph)
    site = _site(graph)
    if mutation == "alias_copy":
        duplicate = _info("fastapi.routing", graph.receiver.name)
        graph.build.modules["fastapi"].tree.names[graph.receiver.name] = SymbolTableNode(
            GDEF, duplicate
        )
    elif mutation == "declaration_copy":
        _method(graph.owner, "add_event_handler", decorated=True)
    elif mutation == "owner_export_copy":
        duplicate = _info(graph.owner.module_name, graph.owner.name)
        graph.build.modules[graph.owner.module_name].tree.names[graph.owner.name] = SymbolTableNode(
            GDEF, duplicate
        )
    else:
        del graph.build.modules[graph.owner.module_name]
    with trace:
        _read_probe(graph.probe)
        reader.observe_framework_registration(site, graph.selector)
        with pytest.raises(reader.ConsumerTraceRejected):
            trace.require_complete()
    assert not trace.result().framework_registration_observed
    assert trace.result().canonical_registration_pins == ()


@pytest.mark.parametrize(
    "symbols", [(), ("fastapi.APIRouter.missing",), ("foreign.APIRouter.add_event_handler",)]
)
def test_absent_or_unselected_registration_cannot_complete(
    tmp_path: Path, symbols: tuple[str, ...]
) -> None:
    graph = _owned_graph(tmp_path)
    site = _site(graph)
    trace = _trace(graph, symbols)
    with trace:
        _read_probe(graph.probe)
        reader.observe_framework_registration(site, graph.selector)
        with pytest.raises(reader.ConsumerTraceRejected, match="unselected"):
            trace.require_complete()
    assert not trace.result().framework_registration_observed


def test_each_selected_contract_identity_must_be_observed(tmp_path: Path) -> None:
    graph = _owned_graph(tmp_path)
    event, _wrapper = _method(graph.receiver, "on_event", decorated=False)
    second = "fastapi.APIRouter.on_event"
    trace = _trace(graph, (graph.selector, second))
    first_site = _site(graph)
    event_site = _site(graph, canonical_symbol=event.fullname)
    with trace:
        _read_probe(graph.probe)
        reader.observe_framework_registration(first_site, graph.selector)
        with pytest.raises(
            reader.ConsumerTraceRejected, match="selected registration was not observed"
        ):
            trace.require_complete()
        reader.observe_framework_registration(event_site, second)
        assert trace.require_complete().complete


def test_type_observer_metadata_is_not_recorded_as_analyzer_reads(tmp_path: Path) -> None:
    graph = _owned_graph(tmp_path, cached=True)
    trace = _trace(graph, ())
    instance = Instance(graph.receiver, [])
    with trace:
        _read_probe(graph.probe)
        reader.observe_type_access(graph.probe, instance)
        result = trace.result()
    assert not result.blockers
    assert len(result.accesses) == 2
    assert result.accesses[-1].type_identity == graph.receiver.fullname
    assert result.accesses[-1].consumer == "MypyAnalyzer._get_type_from_node"
    assert all(
        not access.consumer.endswith((".observe_type_access", "._node_shape"))
        for access in result.accesses
    )
    assert all(access.node_identity != id(graph.receiver) for access in result.accesses)


def test_symbol_only_cached_decorator_child_is_known_without_cache_admission(
    tmp_path: Path,
) -> None:
    graph = _owned_graph(tmp_path, cached=True)
    site = _site(graph)
    trace = _trace(graph)
    assert graph.build.modules[graph.owner.module_name].tree.defs == []
    assert isinstance(graph.wrapper, Decorator)
    assert trace.node_modules[id(graph.declaration)] == graph.owner.module_name
    with trace:
        _read_probe(graph.probe)
        reader.observe_framework_registration(site, graph.selector)
        with pytest.raises(reader.ConsumerTraceRejected, match="no matching admitted artifact"):
            trace.require_complete()
    result = trace.result()
    assert not any("unknown typed node" in blocker for blocker in result.blockers)
    assert result.canonical_registration_pins == ((graph.owner_path, graph.source_hash),)


@pytest.mark.parametrize("reason", ["cached_body", "project_provenance", "missing_source"])
def test_selected_declaration_requires_external_source_and_empty_cached_body(
    tmp_path: Path, reason: str
) -> None:
    graph = _owned_graph(tmp_path, cached=reason == "cached_body")
    if reason == "cached_body":
        graph.declaration.body = Block([ExpressionStmt(NameExpr("not_empty"))])
    else:
        sources = dict(graph.snapshot.sources)
        if reason == "missing_source":
            del sources[graph.owner_path]
        else:
            prior = sources[graph.owner_path]
            sources[graph.owner_path] = reader.TraceSource(
                prior.path, prior.data, "project_snapshot"
            )
        graph.snapshot = reader.ConsumerTraceSnapshot(sources)
    site = _site(graph)
    trace = _trace(graph)
    with trace:
        _read_probe(graph.probe)
        reader.observe_framework_registration(site, graph.selector)
        with pytest.raises(reader.ConsumerTraceRejected):
            trace.require_complete()
    assert trace.result().canonical_registration_pins == ()
    assert not trace.result().framework_registration_observed


def test_selected_lookup_has_no_cross_product_of_receiver_and_member(tmp_path: Path) -> None:
    graph = _owned_graph(tmp_path, cached=True)
    trace = _trace(graph)
    with trace:
        _read_probe(graph.probe)
        assert reader.audited_typeinfo_get(graph.receiver, "missing_member") is None
    assert any(
        "cached typed node field read outside" in blocker for blocker in trace.result().blockers
    )


@pytest.mark.parametrize(
    "fault",
    [
        "different_symbol",
        "different_receiver",
        "multiple_receivers",
        "function_invocation",
        "nonexact",
    ],
)
def test_registration_observation_requires_the_exact_selected_typed_site(
    tmp_path: Path, fault: str
) -> None:
    graph = _owned_graph(tmp_path)
    updates: dict[str, object] = {
        "different_symbol": {"canonical_symbol": "fastapi.routing.Foreign.add_event_handler"},
        "different_receiver": {"receiver_candidates": ("fastapi.routing.Foreign",)},
        "multiple_receivers": {"receiver_candidates": (graph.receiver.fullname, "foreign.Other")},
        "function_invocation": {"invocation": InvocationKind.FUNCTION},
        "nonexact": {"status": CallResolutionStatus.UNRESOLVED},
    }[fault]
    site = _site(graph).model_copy(update=updates)
    trace = _trace(graph)
    with trace:
        _read_probe(graph.probe)
        reader.observe_framework_registration(site, graph.selector)
        with pytest.raises(reader.ConsumerTraceRejected, match="identity differs"):
            trace.require_complete()
    assert trace.result().canonical_registration_pins == ()


def test_lookup_allowance_pairs_each_receiver_with_its_selected_member(tmp_path: Path) -> None:
    graph = _owned_graph(tmp_path)
    other = _info("fastapi.routing", "FastAPI")
    _method(other, "on_event", decorated=True)
    for module in ("fastapi", "fastapi.routing"):
        graph.build.modules[module].tree.names["FastAPI"] = SymbolTableNode(GDEF, other)
    trace = _trace(graph, (graph.selector, "fastapi.FastAPI.on_event"))
    token = reader._TYPEINFO_LOOKUP.set((id(other), "on_event"))
    try:
        assert trace._selected_type_lookup(other, "names")
        assert not trace._selected_type_lookup(graph.receiver, "names")
    finally:
        reader._TYPEINFO_LOOKUP.reset(token)
    token = reader._TYPEINFO_LOOKUP.set((id(other), "add_event_handler"))
    try:
        assert not trace._selected_type_lookup(other, "names")
    finally:
        reader._TYPEINFO_LOOKUP.reset(token)


@pytest.mark.parametrize(
    "fault", ["duplicate", "not_tuple", "malformed", "too_many", "mro_too_many"]
)
def test_selected_registration_bounds_fail_closed(tmp_path: Path, fault: str) -> None:
    graph = _owned_graph(tmp_path)
    symbols: object = (graph.selector,)
    if fault == "duplicate":
        symbols = (graph.selector, graph.selector)
    elif fault == "not_tuple":
        symbols = [graph.selector]
    elif fault == "malformed":
        symbols = ("fastapi..APIRouter.add_event_handler",)
    elif fault == "too_many":
        symbols = tuple(
            f"fastapi.APIRouter.member{i}" for i in range(reader.MAX_TRACE_REGISTRATIONS + 1)
        )
    else:
        graph.receiver.mro = [graph.receiver] * (reader.MAX_TRACE_REGISTRATION_MRO + 1)
    trace = reader.TypedConsumerTrace(
        graph.snapshot, graph.build, source_root=graph.root, registration_symbols=symbols
    )
    assert trace.result().blockers
    assert not trace.result().complete


@pytest.mark.parametrize("direct", [False, True])
@pytest.mark.parametrize("decorated", [False, True])
def test_cached_selected_observer_accepts_the_exact_synthetic_artifact_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, direct: bool, decorated: bool
) -> None:
    """Exercise the plan branch; these are not Mypy-produced cache artifacts."""
    graph = _owned_graph(tmp_path, decorated=decorated)
    module = graph.owner.module_name
    source = graph.snapshot.sources[graph.owner_path]
    source_sha1 = hashlib.sha1(source.data).hexdigest()
    graph.build.manager.rechecked_modules.remove(module)
    graph.build.modules[module].meta_source_hash = source_sha1
    run_root = tmp_path / "cache-run"
    members = (str(run_root / "owned.meta.json"), str(run_root / "owned.data.json"))
    artifacts = {members[0]: b'{"owned":"meta"}', members[1]: b'{"owned":"data"}'}

    def read_artifact(path: Path) -> bytes:
        try:
            return artifacts[str(path)]
        except KeyError as error:
            raise OSError("control has no artifact at this path") from error

    monkeypatch.setattr(Path, "read_bytes", read_artifact)
    plan = reader.CacheRunPlan(
        run_root=run_root,
        cache_map={graph.owner_path: members},
        expected_graph={module: source_sha1},
        expected_roots=frozenset({"app"}),
        admitted_modules=frozenset({module}),
        manifest_sha256="0" * 64,
        trust_id="owned-artifact-binding-control",
        artifact_hashes={
            path: hashlib.sha256(data).hexdigest() for path, data in artifacts.items()
        },
    )
    graph.build.manager.options = SimpleNamespace(
        cache_map=dict(plan.cache_map), cache_dir=str(run_root / "output")
    )
    trace = reader.TypedConsumerTrace(
        graph.snapshot,
        graph.build,
        source_root=graph.root,
        cache_plan=plan,
        registration_symbols=(graph.selector,),
    )
    site = _site(graph)
    with trace:
        _read_probe(graph.probe)
        if direct:
            trace.observe_framework_registration(site, graph.selector)
        else:
            reader.observe_framework_registration(site, graph.selector)
        result = trace.require_complete()
    assert result.complete
    assert result.canonical_registration_pins == ((graph.owner_path, graph.source_hash),)
    assert not any(
        access.consumer.endswith(("._resolve_selected_registration", "._pin_canonical_declaration"))
        for access in result.accesses
    )
