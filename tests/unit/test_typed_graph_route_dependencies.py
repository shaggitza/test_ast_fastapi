"""In-memory native declaration sites, source custody, and occurrence isolation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, replace
from importlib.metadata import version
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from mypy.nodes import (
    ARG_POS,
    GDEF,
    Block,
    CallExpr,
    ExpressionStmt,
    FuncDef,
    MypyFile,
    NameExpr,
    SymbolTable,
    SymbolTableNode,
)

from fastapi_endpoint_detector.analyzer import typed_graph_bridge as bridge
from fastapi_endpoint_detector.analyzer import typed_reverse_graph as graph_module
from fastapi_endpoint_detector.analyzer.typed_reverse_graph import (
    ChangedSeed,
    EndpointOccurrenceBinding,
    SourceDependencyUncertainty,
    SourceSpan,
    Symbol,
    TypedGraphCache,
    TypedReverseGraph,
    UncertaintyWitness,
    dependency_declaration_spelling,
)
from fastapi_endpoint_detector.models.endpoint import (
    Endpoint,
    EndpointMethod,
    HandlerInfo,
    NativeAssemblyMode,
    NativeRegistrationKind,
    NativeRootSelectionKind,
    NativeRouteAssemblyEdgeEvidence,
    NativeRouteDependencyExpressionEvidence,
    NativeRouteObjectEvidence,
    NativeRouteProvenance,
    NativeRouteRegistrationEvidence,
    NativeRouteRootEvidence,
    NativeSourceSpan,
    SnapshotSide,
)

ASSEMBLY = Path("/retained/assembly.py")
HANDLER = Path("/retained/handlers.py")
ASSEMBLY_BYTES = (
    b"Depends(provider)\n"
    b"Depends(provider)\n"
    b"Security(provider)\n"
    b"Depends(provider)\n"
    b"route_registration\n"
)
HANDLER_BYTES = b"def handler():\n    return 1\n"


def _native_span(line: int) -> NativeSourceSpan:
    return NativeSourceSpan(
        file_path=ASSEMBLY,
        start_line=line,
        start_column=0,
        end_line=line,
        end_column=len(ASSEMBLY_BYTES.splitlines()[line - 1]),
    )


def _expression(scope: Any, line: int) -> NativeRouteDependencyExpressionEvidence:
    return NativeRouteDependencyExpressionEvidence(
        side=SnapshotSide.TARGET,
        scope=scope,
        expression="this rendered spelling is not the source authority",
        callable_expressions=("untrusted.provider",),
        kind="ambiguous",
        confidence="conditional",
        source_span=_native_span(line),
    )


def _endpoint(path: str = "/one", order: int = 0) -> Endpoint:
    app = NativeRouteObjectEvidence(
        side=SnapshotSide.TARGET,
        object_kind="app",
        module="assembly",
        symbol="app",
        source_span=_native_span(1),
        dependency_expressions=(_expression("app", 1),),
    )
    router = NativeRouteObjectEvidence(
        side=SnapshotSide.TARGET,
        object_kind="router",
        module="assembly",
        symbol="router",
        source_span=_native_span(2),
        dependency_expressions=(_expression("router", 2),),
    )
    edge = NativeRouteAssemblyEdgeEvidence(
        side=SnapshotSide.TARGET,
        operation="include_router",
        mode=NativeAssemblyMode.COPY,
        parent_module="assembly",
        parent_symbol="app",
        child_module="assembly",
        child_symbol="router",
        occurrence_order=0,
        resolved_prefix="",
        source_span=_native_span(3),
        dependency_expressions=(_expression("include", 3),),
    )
    provenance = NativeRouteProvenance(
        side=SnapshotSide.TARGET,
        root=NativeRouteRootEvidence(
            side=SnapshotSide.TARGET,
            selection_kind=NativeRootSelectionKind.APP_VARIABLE,
            module="assembly",
            symbol="app",
            source_span=_native_span(1),
        ),
        registration=NativeRouteRegistrationEvidence(
            side=SnapshotSide.TARGET,
            kind=NativeRegistrationKind.DECORATOR,
            operation="get",
            owner_module="assembly",
            owner_symbol="router",
            occurrence_order=order,
            source_span=_native_span(5),
            dependency_expressions=(_expression("route", 4),),
        ),
        object_chain=(app, router),
        assembly_chain=(edge,),
    )
    return Endpoint(
        path=path,
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="handler",
            module="handlers",
            file_path=HANDLER,
            line_number=1,
            end_line_number=2,
        ),
        native_provenance=provenance,
    )


def _case(
    endpoints: tuple[Endpoint, ...] | None = None,
) -> tuple[Any, dict[str, bytes], tuple[Endpoint, ...], tuple[EndpointOccurrenceBinding, ...]]:
    selected = endpoints if endpoints is not None else (_endpoint(),)
    snapshots = {"assembly": ASSEMBLY_BYTES, "handlers": HANDLER_BYTES}
    records = tuple(
        SimpleNamespace(
            module=module,
            path=path,
            relative_path=path.name,
            sha256=hashlib.sha256(snapshots[module]).hexdigest(),
        )
        for module, path in (("assembly", ASSEMBLY), ("handlers", HANDLER))
    )
    inventory = SimpleNamespace(files=records)
    handler_span = SourceSpan(
        "handlers", str(HANDLER), records[1].sha256, 1, 0, 2, len(b"    return 1")
    )
    bindings = tuple(
        EndpointOccurrenceBinding(
            bridge._bridge_occurrence_id(endpoint),
            endpoint.identifier,
            "handlers.handler",
            handler_span,
        )
        for endpoint in selected
    )
    return inventory, snapshots, selected, bindings


def _valid_metadata(
    inventory: Any,
    snapshots: dict[str, bytes],
    bindings: tuple[EndpointOccurrenceBinding, ...],
    sites: Any,
    rows: Any,
) -> bool:
    return graph_module._dependency_metadata_valid(
        (),
        rows,
        bindings,
        (Symbol("handlers", "handlers.handler", "function", bindings[0].span),),
        {str(record.path): record.sha256 for record in inventory.files},
        {str(record.path): record.module for record in inventory.files},
        {
            str(record.path): tuple(snapshots[record.module].splitlines(keepends=True))
            for record in inventory.files
        },
        declaration_sites=sites,
    )


def _graph(
    inventory: Any,
    bindings: tuple[EndpointOccurrenceBinding, ...],
    sites: Any,
    rows: Any,
) -> TypedReverseGraph:
    edges, issues = graph_module._source_dependency_projection((), rows)
    assert edges == {}
    return TypedReverseGraph(
        schema_version=7,
        root="/retained",
        inventory_fingerprint="inventory",
        source_hashes=tuple((record.module, record.sha256) for record in inventory.files),
        engine="owned-manual-input",
        engine_version="none",
        config_fingerprint="config",
        graph_provenance="manual-source-custody-control",
        symbols=(Symbol("handlers", "handlers.handler", "function", bindings[0].span),),
        edges=(),
        endpoint_bindings=bindings,
        uncertainties=tuple(sorted(issues.values())),
        source_dependency_uncertainties=rows,
        source_dependency_declaration_sites=sites,
    )


def test_native_scopes_use_exact_retained_bytes_and_emit_no_provider_edge() -> None:
    inventory, snapshots, endpoints, bindings = _case()
    sites, rows = bridge._route_dependency_source_metadata(
        inventory, endpoints, bindings, snapshots
    )
    assert len(sites) == len(rows) == 4
    assert {row.scope for row in rows} == {"app", "router", "include", "route"}
    assert {row.span.module for row in rows} == {"assembly"}
    assert {row.source_spelling for row in rows} == {"Depends(provider)", "Security(provider)"}
    assert all(row.owner_symbol == "handlers.handler" for row in rows)
    assert all(
        row.reason_code == "route_dependency_association_origin_and_transfer_unverified"
        for row in rows
    )
    assert _valid_metadata(inventory, snapshots, bindings, sites, rows)
    graph = _graph(inventory, bindings, sites, rows)
    assert graph.source_dependency_bindings == ()
    assert graph.edges == ()
    assert len(graph.uncertainties) == 4


def test_one_source_site_stays_separate_for_two_route_occurrences() -> None:
    inventory, snapshots, endpoints, bindings = _case((_endpoint("/one", 0), _endpoint("/two", 1)))
    sites, rows = bridge._route_dependency_source_metadata(
        inventory, endpoints, bindings, snapshots
    )
    assert len(sites) == len(rows) == 8
    assert {row.occurrence_id for row in rows} == {binding.occurrence_id for binding in bindings}
    assert _valid_metadata(inventory, snapshots, bindings, sites, rows)
    _, issues = graph_module._source_dependency_projection((), rows)
    assert len(issues) == 8
    assert {issue.occurrence_id for issue in issues.values()} == {
        binding.occurrence_id for binding in bindings
    }


def test_duplicate_native_evidence_is_deduplicated_only_within_one_scope() -> None:
    endpoint = _endpoint()
    assert endpoint.native_provenance is not None
    provenance = endpoint.native_provenance
    route_expression = provenance.registration.dependency_expressions[0]
    registration = provenance.registration.model_copy(
        update={"dependency_expressions": (route_expression, route_expression)}
    )
    endpoint = endpoint.model_copy(
        update={"native_provenance": provenance.model_copy(update={"registration": registration})}
    )
    inventory, snapshots, endpoints, bindings = _case((endpoint,))
    sites, rows = bridge._route_dependency_source_metadata(
        inventory, endpoints, bindings, snapshots
    )
    assert len(sites) == len(rows) == 4
    route = next(row for row in rows if row.scope == "route")
    app = replace(route, scope="app")
    app_site = replace(next(site for site in sites if site.scope == "route"), scope="app")
    assert _valid_metadata(inventory, snapshots, bindings, (app_site,), (app,))
    _, issues = graph_module._source_dependency_projection((), (route, app))
    assert len(issues) == 2


@pytest.mark.parametrize(
    "change",
    [
        lambda row: replace(row, scope="unknown"),
        lambda row: replace(row, scope="signature"),
        lambda row: replace(row, occurrence_id="another-occurrence"),
        lambda row: replace(row, owner_symbol="other.handler"),
        lambda row: replace(row, source_spelling="invented text"),
        lambda row: replace(row, span=replace(row.span, source_sha256="0" * 64)),
        lambda row: replace(row, span=replace(row.span, path="/retained/unselected.py")),
        lambda row: replace(row, span=replace(row.span, start_column=True)),
    ],
)
def test_external_uncertainty_cannot_escape_its_authorized_site(change: Any) -> None:
    inventory, snapshots, endpoints, bindings = _case()
    sites, rows = bridge._route_dependency_source_metadata(
        inventory, endpoints, bindings, snapshots
    )
    route = next(row for row in rows if row.scope == "route")
    site = next(item for item in sites if item.scope == "route")
    assert _valid_metadata(inventory, snapshots, bindings, (site,), (route,))
    assert not _valid_metadata(inventory, snapshots, bindings, (site,), (change(route),))
    assert not _valid_metadata(inventory, snapshots, bindings, (), (route,))


def test_signature_containment_remains_required_and_sites_must_be_used() -> None:
    inventory, snapshots, endpoints, bindings = _case()
    sites, rows = bridge._route_dependency_source_metadata(
        inventory, endpoints, bindings, snapshots
    )
    inside = SourceDependencyUncertainty(
        bindings[0].occurrence_id, bindings[0].symbol, bindings[0].span, "unverified", "handler"
    )
    assert _valid_metadata(inventory, snapshots, bindings, (), (inside,))
    external = replace(inside, span=rows[0].span)
    assert not _valid_metadata(inventory, snapshots, bindings, sites, (external,))
    assert not _valid_metadata(inventory, snapshots, bindings, sites, ())
    assert not _valid_metadata(inventory, snapshots, bindings, (*sites, sites[0]), rows)


def test_scoped_query_uncertainties_do_not_bleed_between_equal_handlers() -> None:
    inventory, snapshots, endpoints, bindings = _case((_endpoint("/one", 0), _endpoint("/two", 1)))
    sites, rows = bridge._route_dependency_source_metadata(
        inventory, endpoints, bindings, snapshots
    )
    selected_sites = tuple(
        site for site in sites if site.occurrence_id == bindings[0].occurrence_id
    )
    selected_rows = tuple(row for row in rows if row.occurrence_id == bindings[0].occurrence_id)
    assert _valid_metadata(inventory, snapshots, bindings, selected_sites, selected_rows)
    graph = _graph(inventory, bindings, selected_sites, selected_rows)
    result = graph.query([ChangedSeed("target", "handlers.handler")], side="target")
    by_occurrence = {row.occurrence.occurrence_id: row for row in result.evidence}
    assert by_occurrence[bindings[0].occurrence_id].uncertainties
    assert by_occurrence[bindings[1].occurrence_id].uncertainties == ()
    assert {row.occurrence.occurrence_id for row in result.uncertain_evidence} == {
        bindings[0].occurrence_id
    }
    assert all(row.confidence == "LOW" for row in result.uncertain_evidence)
    assert graph.edges == ()


def test_manifest_and_projection_bind_scope_sites_and_occurrences() -> None:
    inventory, snapshots, endpoints, bindings = _case()
    sites, rows = bridge._route_dependency_source_metadata(
        inventory, endpoints, bindings, snapshots
    )
    graph = _graph(inventory, bindings, sites, rows)
    manifest = TypedGraphCache.manifest(graph)
    encoded = json.loads(json.dumps(asdict(manifest)))
    assert manifest.schema_version == 7
    assert len(encoded["source_dependency_declaration_sites"]) == 4
    assert {row["scope"] for row in encoded["source_dependency_uncertainties"]} == {
        "app",
        "router",
        "include",
        "route",
    }
    assert TypedGraphCache.cache_key(
        replace(graph, source_dependency_declaration_sites=())
    ) != TypedGraphCache.cache_key(graph)
    assert graph_module._dependency_projection_valid(graph, expected_graph=graph)
    assert not graph_module._dependency_projection_valid(
        replace(
            graph,
            uncertainties=tuple(
                replace(row, occurrence_id="elsewhere") for row in graph.uncertainties
            ),
        ),
        expected_graph=graph,
    )


@pytest.mark.parametrize(
    ("raw", "start_line", "start_column", "end_line", "end_column", "expected"),
    [
        ("é = Depends(provider)\n".encode(), 1, 5, 1, 22, "Depends(provider)"),
        ("é = Depends(provider)\n".encode(), 1, 1, 1, 22, None),
        (b"Depends(\n    provider,\n)\n", 1, 0, 3, 1, "Depends(\n    provider,\n)"),
        (b"Depends(provider)\n", 1, 0, 1, 100, None),
        (b"Depends(provider)\n", 1, 0, 1, 0, None),
        (b"x" * 65537, 1, 0, 1, 65537, None),
        (b"x\n" * 1025, 1, 0, 1025, 1, None),
    ],
)
def test_declaration_spelling_uses_bounded_utf8_byte_spans(
    raw: bytes,
    start_line: int,
    start_column: int,
    end_line: int,
    end_column: int,
    expected: str | None,
) -> None:
    span = SourceSpan(
        "assembly",
        str(ASSEMBLY),
        hashlib.sha256(raw).hexdigest(),
        start_line,
        start_column,
        end_line,
        end_column,
    )
    assert dependency_declaration_spelling(span, tuple(raw.splitlines(keepends=True))) == expected


@pytest.mark.parametrize("mutation", ["missing", "changed", "duplicate", "outside"])
def test_route_declaration_source_custody_fails_closed(mutation: str) -> None:
    inventory, snapshots, endpoints, bindings = _case()
    if mutation == "missing":
        snapshots.pop("assembly")
    elif mutation == "changed":
        snapshots["assembly"] = b"tampered\n"
    elif mutation == "duplicate":
        inventory.files = (*inventory.files, inventory.files[0])
    else:
        inventory.files = (inventory.files[1],)
    with pytest.raises(bridge.TypedGraphBridgeError, match=r"source|identity"):
        bridge._route_dependency_source_metadata(inventory, endpoints, bindings, snapshots)


@pytest.mark.parametrize("budget", ["endpoint", "total"])
def test_route_expression_limits_count_duplicates_before_deduplication(
    monkeypatch: pytest.MonkeyPatch, budget: str
) -> None:
    endpoint = _endpoint()
    assert endpoint.native_provenance is not None
    provenance = endpoint.native_provenance
    expression = provenance.registration.dependency_expressions[0]
    registration = provenance.registration.model_copy(
        update={"dependency_expressions": (expression,) * 3}
    )
    endpoint = endpoint.model_copy(
        update={"native_provenance": provenance.model_copy(update={"registration": registration})}
    )
    inventory, snapshots, endpoints, bindings = _case((endpoint,))
    name = (
        "_MAX_ROUTE_DEPENDENCY_EXPRESSIONS_PER_ENDPOINT"
        if budget == "endpoint"
        else "_MAX_DEPENDENCY_METADATA"
    )
    monkeypatch.setattr(bridge, name, 2)
    with pytest.raises(bridge.TypedGraphBridgeError, match=budget + " budget"):
        bridge._route_dependency_source_metadata(inventory, endpoints, bindings, snapshots)


def test_no_native_provenance_adds_no_declaration_metadata() -> None:
    endpoint = _endpoint().model_copy(update={"native_provenance": None})
    inventory, snapshots, endpoints, bindings = _case((endpoint,))
    assert bridge._route_dependency_source_metadata(inventory, endpoints, bindings, snapshots) == (
        (),
        (),
    )


@pytest.mark.parametrize("field", ["scope", "side"])
def test_native_expression_scope_and_side_must_match_the_attached_group(field: str) -> None:
    endpoint = _endpoint()
    assert endpoint.native_provenance is not None
    provenance = endpoint.native_provenance
    expression = provenance.registration.dependency_expressions[0]
    expression = expression.model_copy(
        update={field: "app" if field == "scope" else SnapshotSide.BASELINE}
    )
    registration = provenance.registration.model_copy(
        update={"dependency_expressions": (expression,)}
    )
    endpoint = endpoint.model_copy(
        update={"native_provenance": provenance.model_copy(update={"registration": registration})}
    )
    inventory, snapshots, endpoints, bindings = _case((endpoint,))
    with pytest.raises(bridge.TypedGraphBridgeError, match="scope or side"):
        bridge._route_dependency_source_metadata(inventory, endpoints, bindings, snapshots)


@pytest.mark.parametrize("mutation", ["extra_global", "duplicate", "missing", "changed"])
def test_dependency_projection_rejects_extra_or_changed_cache_witnesses(mutation: str) -> None:
    inventory, snapshots, endpoints, bindings = _case((_endpoint("/one", 0), _endpoint("/two", 1)))
    sites, rows = bridge._route_dependency_source_metadata(
        inventory, endpoints, bindings, snapshots
    )
    trusted = _graph(inventory, bindings, sites, rows)
    issues = trusted.uncertainties
    if mutation == "extra_global":
        extra = UncertaintyWitness(
            "invented-global-dependency",
            bindings[0].symbol,
            bindings[0].span,
            "dependency_injection",
            "unverified",
            "Depends(unrelated)",
        )
        altered = replace(trusted, uncertainties=(*issues, extra))
    elif mutation == "duplicate":
        altered = replace(trusted, uncertainties=(*issues, issues[0]))
    elif mutation == "missing":
        altered = replace(trusted, uncertainties=issues[1:])
    else:
        altered = replace(
            trusted, uncertainties=(replace(issues[0], source_spelling="forged"), *issues[1:])
        )
    assert not graph_module._dependency_projection_valid(altered, expected_graph=trusted)


def test_reconstructed_projection_preserves_legacy_and_unrelated_uncertainties() -> None:
    inventory, snapshots, endpoints, bindings = _case()
    sites, rows = bridge._route_dependency_source_metadata(
        inventory, endpoints, bindings, snapshots
    )
    trusted = _graph(inventory, bindings, sites, rows)
    # The trusted reference stands for the retained typed-AST reconstruction:
    # old unresolved-Depends and framework witnesses are intentionally unscoped.
    legacy = UncertaintyWitness(
        "retained-legacy-dependency",
        bindings[0].symbol,
        bindings[0].span,
        "dependency_injection",
        "dependency_parameter_transfer_not_proven",
        "Depends",
    )
    trusted = replace(trusted, uncertainties=(*trusted.uncertainties, legacy))
    unrelated = replace(legacy, uncertainty_id="unrelated-coverage", category="source_coverage")
    assert graph_module._dependency_projection_valid(
        replace(trusted, uncertainties=(*trusted.uncertainties, unrelated)),
        expected_graph=trusted,
    )
    assert not graph_module._dependency_projection_valid(
        replace(
            trusted,
            uncertainties=tuple(row for row in trusted.uncertainties if row is not legacy),
        ),
        expected_graph=trusted,
    )


def _located(node: Any, line: int, column: int, end_line: int, end_column: int) -> Any:
    node.line = line
    node.column = column
    node.end_line = end_line
    node.end_column = end_column
    return node


@pytest.mark.parametrize("mutation", ["extra_global", "duplicate", "edge_missing", "none"])
def test_cache_rebuild_authenticates_all_di_producers_from_retained_manual_nodes(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    inventory, snapshots, endpoints, bindings = _case()
    inventory.root = Path("/retained")
    snapshots["handlers"] = b"def handler():\n    Depends(provider)\n"
    handler_hash = hashlib.sha256(snapshots["handlers"]).hexdigest()
    inventory.files = (
        inventory.files[0],
        SimpleNamespace(
            module="handlers", path=HANDLER, relative_path=HANDLER.name, sha256=handler_hash
        ),
    )
    handler_span = SourceSpan("handlers", str(HANDLER), handler_hash, 1, 0, 2, 21)
    bindings = (
        replace(
            bindings[0],
            span=handler_span,
            dependency_symbols=("handlers.handler",),
        ),
    )
    sites, rows = bridge._route_dependency_source_metadata(
        inventory, endpoints, bindings, snapshots
    )
    call = _located(
        CallExpr(NameExpr("Depends"), [NameExpr("provider")], [ARG_POS], [None]),
        2,
        4,
        2,
        21,
    )
    statement = _located(ExpressionStmt(call), 2, 4, 2, 21)
    function = _located(FuncDef("handler", [], Block([statement])), 1, 0, 2, 21)
    function._fullname = "handlers.handler"
    handler_tree = _located(MypyFile([function], []), 1, 0, 2, 21)
    handler_tree._fullname = "handlers"
    handler_tree.names = {"handler": SymbolTableNode(GDEF, function)}
    assembly_tree = MypyFile([], [])
    assembly_tree._fullname = "assembly"
    assembly_tree.names = SymbolTable()
    digests = tuple((record.module, record.sha256) for record in inventory.files)
    snapshot = SimpleNamespace(
        modules={
            "assembly": SimpleNamespace(tree=assembly_tree),
            "handlers": SimpleNamespace(tree=handler_tree),
        },
        module_paths={"assembly": str(ASSEMBLY), "handlers": str(HANDLER)},
        type_maps={},
        report=SimpleNamespace(
            engine="owned-manual-input",
            mypy_version=version("mypy"),
            cache_fingerprint="manual-retained-tree-custody",
            source_digests_after=digests,
        ),
    )
    virtual_bytes = {str(ASSEMBLY): snapshots["assembly"], str(HANDLER): snapshots["handlers"]}

    def resolve(path: Path, strict: bool = False) -> Path:
        assert path.is_absolute()
        return path

    monkeypatch.setattr(Path, "resolve", resolve)
    monkeypatch.setattr(Path, "is_symlink", lambda _path: False)
    monkeypatch.setattr(Path, "read_bytes", lambda path: virtual_bytes[str(path)])
    trusted = graph_module.build_typed_reverse_graph(
        inventory,
        snapshot,
        bindings,
        config_fingerprint="config",
        source_snapshots=snapshots,
        source_dependency_uncertainties=rows,
        source_dependency_declaration_sites=sites,
    )
    di_rows = tuple(row for row in trusted.uncertainties if row.category == "dependency_injection")
    assert len(di_rows) == 6  # four scoped, one framework, one unresolved-Depends witness
    assert len([row for row in di_rows if not row.occurrence_id]) == 2
    assert any(edge.relation == "framework_dependency_binding" for edge in trusted.edges)
    assert TypedGraphCache.validate(trusted, inventory, snapshot, config_fingerprint="config")
    if mutation == "extra_global":
        extra = replace(
            di_rows[0], uncertainty_id="invented-global", occurrence_id="", source_spelling="forged"
        )
        altered = replace(trusted, uncertainties=(*trusted.uncertainties, extra))
    elif mutation == "duplicate":
        altered = replace(trusted, uncertainties=(*trusted.uncertainties, di_rows[0]))
    elif mutation == "edge_missing":
        altered = replace(
            trusted,
            edges=tuple(
                edge for edge in trusted.edges if edge.relation != "framework_dependency_binding"
            ),
        )
    else:
        altered = trusted
    assert TypedGraphCache.validate(altered, inventory, snapshot, config_fingerprint="config") is (
        mutation == "none"
    )
