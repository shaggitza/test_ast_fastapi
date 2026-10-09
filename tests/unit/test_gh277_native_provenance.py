"""Regression coverage for source-only GH277 route provenance additions."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi_endpoint_detector.models.endpoint import SnapshotSide
from fastapi_endpoint_detector.parser.secure_ast_extractor import (
    SecureASTExtractor,
    native_route_structural_owners,
)

if TYPE_CHECKING:
    from pathlib import Path


def test_dependency_expressions_are_side_qualified_and_structurally_owned(
    tmp_path: Path,
) -> None:
    app_file = tmp_path / "main.py"
    app_file.write_text(
        "from fastapi import APIRouter, Depends, FastAPI\n"
        "def app_dep(): pass\n"
        "def router_dep(): pass\n"
        "def route_dep(): pass\n"
        "app = FastAPI(dependencies=[Depends(app_dep)])\n"
        "router = APIRouter(dependencies=[Depends(router_dep)])\n"
        "@router.get('/items')\n"
        "def items(): pass\n"
        "app.include_router(router, dependencies=[Depends(route_dep)])\n"
        "app.add_api_route('/extra', items, dependencies=[Depends(route_dep)])\n",
        encoding="utf-8",
    )

    endpoints = SecureASTExtractor(
        app_file, snapshot_side=SnapshotSide.BASELINE
    ).extract_endpoints()
    included = next(item for item in endpoints if item.identifier == "GET /items")
    evidence = included.native_provenance
    assert evidence is not None
    assert evidence.side == SnapshotSide.BASELINE
    assert evidence.object_chain[0].dependency_expressions[0].scope == "app"
    assert evidence.object_chain[0].dependency_expressions[0].callable_expressions == (
        "main.app_dep",
    )
    assert evidence.object_chain[1].dependency_expressions[0].callable_expressions == (
        "main.router_dep",
    )
    assert evidence.assembly_chain[0].dependency_expressions[0].scope == "include"
    dependency_line = evidence.assembly_chain[0].dependency_expressions[0].source_span.start_line
    owners = native_route_structural_owners(included, app_file, {dependency_line})
    assert {item.role for item in owners} == {"assembly", "dependency"}
    assert {item.endpoint_identifier for item in owners} == {"GET /items"}
    assert {item.side for item in owners} == {SnapshotSide.BASELINE}

    imperative = next(item for item in endpoints if item.identifier == "GET /extra")
    registration = imperative.native_provenance
    assert registration is not None
    dependency = registration.registration.dependency_expressions[0]
    assert dependency.scope == "route"
    assert dependency.kind == "depends"
    assert dependency.confidence == "established"
    assert dependency.callable_expressions == ("main.route_dep",)


def test_dynamic_dependency_expression_is_retained_as_conditional(
    tmp_path: Path,
) -> None:
    app_file = tmp_path / "main.py"
    app_file.write_text(
        "from fastapi import APIRouter, FastAPI\n"
        "router = APIRouter()\n"
        "@router.get('/items')\n"
        "def items(): pass\n"
        "app = FastAPI()\n"
        "app.include_router(router, dependencies=make_dependencies())\n",
        encoding="utf-8",
    )
    endpoint = SecureASTExtractor(app_file).extract_endpoints()[0]
    provenance = endpoint.native_provenance
    assert provenance is not None
    dependency = provenance.assembly_chain[0].dependency_expressions[0]
    assert dependency.kind == "ambiguous"
    assert dependency.confidence == "conditional"
    assert native_route_structural_owners(endpoint, app_file, {1}) == ()


def test_dependency_binding_alias_keyword_and_shadowing_are_conservative(tmp_path: Path) -> None:
    cases = {
        "shadowed.py": (
            "from fastapi import APIRouter, FastAPI, Depends\n"
            "def Depends(value): return value\n"
            "def dep(): pass\n"
            "router = APIRouter(dependencies=[Depends(dep)])\n"
            "@router.get('/shadowed')\n"
            "def shadowed(): pass\n"
            "app = FastAPI()\n"
            "app.include_router(router)\n",
            "ambiguous",
            "conditional",
            (),
        ),
        "alias.py": (
            "from fastapi import APIRouter, FastAPI, Depends as D\n"
            "def dep(): pass\n"
            "router = APIRouter(dependencies=[D(dep)])\n"
            "@router.get('/alias')\n"
            "def alias(): pass\n"
            "app = FastAPI()\n"
            "app.include_router(router)\n",
            "depends",
            "established",
            ("alias.dep",),
        ),
        "keyword.py": (
            "from fastapi import APIRouter, FastAPI, Depends\n"
            "def dep(): pass\n"
            "router = APIRouter(dependencies=[Depends(dependency=dep)])\n"
            "@router.get('/keyword')\n"
            "def keyword(): pass\n"
            "app = FastAPI()\n"
            "app.include_router(router)\n",
            "depends",
            "established",
            ("keyword.dep",),
        ),
        "external.py": (
            "from fastapi import APIRouter, FastAPI, Depends\n"
            "from thirdparty.dependencies import dep\n"
            "router = APIRouter(dependencies=[Depends(dep)])\n"
            "@router.get('/external')\n"
            "def external(): pass\n"
            "app = FastAPI()\n"
            "app.include_router(router)\n",
            "depends",
            "conditional",
            ("thirdparty.dependencies.dep",),
        ),
    }
    for filename, (source, kind, confidence, callables) in cases.items():
        path = tmp_path / filename
        path.write_text(source, encoding="utf-8")
        endpoint = SecureASTExtractor(path).extract_endpoints()[0]
        evidence = endpoint.native_provenance
        assert evidence is not None
        dependency = evidence.object_chain[-1].dependency_expressions[0]
        assert dependency.kind == kind
        assert dependency.confidence == confidence
        assert dependency.callable_expressions == callables


def test_structural_owner_spans_are_exact_to_descendants_and_exclude_unrelated_code(
    tmp_path: Path,
) -> None:
    app_file = tmp_path / "main.py"
    app_file.write_text(
        "from fastapi import APIRouter, FastAPI\n"
        "router = APIRouter()\n"
        "@router.get(\n"
        "    '/items',\n"
        ")\n"
        "def items(\n"
        "    value: int = 1,\n"
        "):\n"
        "    return value\n"
        "@router.get('/other')\n"
        "def other(): pass\n"
        "app = FastAPI()\n"
        "app.include_router(router)\n"
        "unrelated_global = 1\n"
        "class Unrelated: pass\n",
        encoding="utf-8",
    )
    endpoints = SecureASTExtractor(app_file).extract_endpoints()
    item = next(endpoint for endpoint in endpoints if endpoint.identifier == "GET /items")
    other = next(endpoint for endpoint in endpoints if endpoint.identifier == "GET /other")
    provenance = item.native_provenance
    assert provenance is not None
    header = next(
        owner for owner in provenance.source_owners if owner.owner_kind == "decorator_signature"
    )
    assert header.source_span.start_line == 3
    assert header.source_span.end_line == 8
    assert any(
        owner.owner_kind == "decorator_signature"
        for owner in native_route_structural_owners(item, app_file, {4})
    )
    assert native_route_structural_owners(other, app_file, {4}) == ()
    assert native_route_structural_owners(item, app_file, {14, 15}) == ()


def test_import_and_all_export_owners_follow_only_the_imported_router(tmp_path: Path) -> None:
    implementation_file = tmp_path / "implementation.py"
    implementation_file.write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.get('/imported')\n"
        "def imported(): pass\n",
        encoding="utf-8",
    )
    routes_file = tmp_path / "routes.py"
    routes_file.write_text(
        "from implementation import router\n__all__ = ['router']\n",
        encoding="utf-8",
    )
    app_file = tmp_path / "main.py"
    app_file.write_text(
        "from fastapi import APIRouter, FastAPI\n"
        "from routes import router as api\n"
        "local = APIRouter()\n"
        "@local.get('/local')\n"
        "def local_route(): pass\n"
        "app = FastAPI()\n"
        "app.include_router(api)\n"
        "app.include_router(local)\n",
        encoding="utf-8",
    )
    endpoints = SecureASTExtractor(app_file).extract_endpoints()
    imported = next(endpoint for endpoint in endpoints if endpoint.identifier == "GET /imported")
    local = next(endpoint for endpoint in endpoints if endpoint.identifier == "GET /local")
    evidence = imported.native_provenance
    assert evidence is not None
    assert any(owner.owner_kind == "import_binding" for owner in evidence.source_owners)
    assert any(owner.owner_kind == "reexport" for owner in evidence.source_owners)
    assert any(owner.owner_kind == "all_export" for owner in evidence.source_owners)
    assert any(
        owner.owner_kind == "import_binding"
        for owner in native_route_structural_owners(imported, app_file, {2})
    )
    assert native_route_structural_owners(local, app_file, {2}) == ()


def test_factory_return_owner_tracks_only_the_factory_selected_route(tmp_path: Path) -> None:
    app_file = tmp_path / "main.py"
    app_file.write_text(
        "from fastapi import FastAPI\n"
        "def create_app():\n"
        "    app = FastAPI()\n"
        "    @app.get('/factory')\n"
        "    def factory_route(): pass\n"
        "    return app\n",
        encoding="utf-8",
    )
    endpoint = SecureASTExtractor(app_file, app_entry="main:create_app").extract_endpoints()[0]
    provenance = endpoint.native_provenance
    assert provenance is not None
    owner = next(item for item in provenance.source_owners if item.owner_kind == "factory_return")
    assert owner.qualified_binding == "main.create_app"
    assert owner.expression == "app"
    assert any(
        item.owner_kind == "factory_return"
        for item in native_route_structural_owners(
            endpoint, app_file, {owner.source_span.start_line}
        )
    )


def test_bootstrap_registration_owner_is_exact_to_the_bootstrap_route_call(
    tmp_path: Path,
) -> None:
    app_file = tmp_path / "main.py"
    app_file.write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "def handler(): pass\n"
        "def run():\n"
        "    app.add_api_route('/bootstrap', handler)\n",
        encoding="utf-8",
    )
    endpoint = SecureASTExtractor(app_file, bootstrap_entry="main:run").extract_endpoints()[0]
    provenance = endpoint.native_provenance
    assert provenance is not None
    owner = next(
        item for item in provenance.source_owners if item.owner_kind == "bootstrap_registration"
    )
    assert owner.source_span.start_line == 5
    assert any(
        item.owner_kind == "bootstrap_registration"
        for item in native_route_structural_owners(endpoint, app_file, {5})
    )
    assert not any(
        item.owner_kind == "bootstrap_registration"
        for item in native_route_structural_owners(endpoint, app_file, {3})
    )


def test_same_line_keyword_include_calls_keep_exact_import_owners(tmp_path: Path) -> None:
    first_file = tmp_path / "first_routes.py"
    first_file.write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.get('/first')\n"
        "def first(): pass\n",
        encoding="utf-8",
    )
    second_file = tmp_path / "second_routes.py"
    second_file.write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.get('/second')\n"
        "def second(): pass\n",
        encoding="utf-8",
    )
    exports_file = tmp_path / "exports.py"
    exports_file.write_text(
        "from first_routes import router as first\n__all__ = ['first']\n",
        encoding="utf-8",
    )
    app_file = tmp_path / "main.py"
    app_file.write_text(
        "from fastapi import FastAPI\n"
        "from exports import first as alias1; from second_routes import router as alias2\n"
        "app = FastAPI()\n"
        "app.router.include_router(router=alias1); app.include_router(router=alias2)\n",
        encoding="utf-8",
    )

    endpoints = SecureASTExtractor(app_file).extract_endpoints()
    first = next(endpoint for endpoint in endpoints if endpoint.identifier == "GET /first")
    second = next(endpoint for endpoint in endpoints if endpoint.identifier == "GET /second")
    first_evidence = first.native_provenance
    second_evidence = second.native_provenance
    assert first_evidence is not None and second_evidence is not None
    first_imports = {
        owner.qualified_binding: owner.related_binding
        for owner in first_evidence.source_owners
        if owner.owner_kind == "import_binding"
    }
    second_imports = {
        owner.qualified_binding: owner.related_binding
        for owner in second_evidence.source_owners
        if owner.owner_kind == "import_binding"
    }
    assert first_imports == {"main.alias1": "exports.first"}
    assert second_imports == {"main.alias2": "second_routes.router"}
    assert any(owner.owner_kind == "reexport" for owner in first_evidence.source_owners)
    first_edge = first_evidence.assembly_chain[0]
    second_edge = second_evidence.assembly_chain[0]
    assert first_edge.source_span != second_edge.source_span
    assert first_edge.source_span.start_line == second_edge.source_span.start_line == 4
    assert first_edge.occurrence_order < second_edge.occurrence_order


def test_annotated_and_security_handler_dependencies_are_route_scoped(tmp_path: Path) -> None:
    app_file = tmp_path / "main.py"
    app_file.write_text(
        "from typing import Annotated\n"
        "from fastapi import Depends, FastAPI, Security as Guard\n"
        "def nested(): pass\n"
        "def scopes(): pass\n"
        "app = FastAPI()\n"
        "@app.get('/annotated')\n"
        "def annotated(\n"
        "    value: Annotated[int, Depends(nested)],\n"
        "    token=Guard(dependency=scopes, scopes=['x']),\n"
        "): pass\n",
        encoding="utf-8",
    )
    endpoint = SecureASTExtractor(app_file).extract_endpoints()[0]
    provenance = endpoint.native_provenance
    assert provenance is not None
    expressions = provenance.registration.dependency_expressions
    assert [(item.kind, item.callable_expressions) for item in expressions] == [
        ("depends", ("main.nested",)),
        ("security", ("main.scopes",)),
    ]
    assert all(item.scope == "route" and item.confidence == "established" for item in expressions)


def test_same_line_mount_keyword_apps_keep_distinct_import_owners(tmp_path: Path) -> None:
    first_file = tmp_path / "first_apps.py"
    first_file.write_text(
        "from fastapi import FastAPI\nchild = FastAPI()\n@child.get('/first')\ndef first(): pass\n",
        encoding="utf-8",
    )
    second_file = tmp_path / "second_apps.py"
    second_file.write_text(
        "from fastapi import FastAPI\n"
        "child = FastAPI()\n"
        "@child.get('/second')\n"
        "def second(): pass\n",
        encoding="utf-8",
    )
    app_file = tmp_path / "main.py"
    app_file.write_text(
        "from fastapi import FastAPI\n"
        "from first_apps import child as first; from second_apps import child as second\n"
        "app = FastAPI()\n"
        "app.mount('/one', app=first); app.mount('/two', app=second)\n",
        encoding="utf-8",
    )
    endpoints = SecureASTExtractor(app_file).extract_endpoints()
    first = next(endpoint for endpoint in endpoints if endpoint.identifier == "GET /one/first")
    second = next(endpoint for endpoint in endpoints if endpoint.identifier == "GET /two/second")
    first_provenance = first.native_provenance
    second_provenance = second.native_provenance
    assert first_provenance is not None and second_provenance is not None
    assert first_provenance.assembly_chain[0].operation == "mount"
    assert second_provenance.assembly_chain[0].operation == "mount"
    assert (
        first_provenance.assembly_chain[0].source_span
        != second_provenance.assembly_chain[0].source_span
    )
    assert (
        first_provenance.assembly_chain[0].occurrence_order
        < second_provenance.assembly_chain[0].occurrence_order
    )
    first_bindings = [
        owner.qualified_binding
        for owner in first_provenance.source_owners
        if owner.owner_kind == "import_binding"
    ]
    second_bindings = [
        owner.qualified_binding
        for owner in second_provenance.source_owners
        if owner.owner_kind == "import_binding"
    ]
    assert first_bindings == ["main.first"]
    assert second_bindings == ["main.second"]


def test_selected_factory_local_constructor_assignments_are_structural_owners(
    tmp_path: Path,
) -> None:
    app_file = tmp_path / "main.py"
    app_file.write_text(
        "from fastapi import APIRouter, FastAPI\n"
        "def create_app():\n"
        "    router = APIRouter(prefix='/local')\n"
        "    @router.get('/item')\n"
        "    def item(): pass\n"
        "    app = FastAPI()\n"
        "    app.include_router(router)\n"
        "    return app\n",
        encoding="utf-8",
    )
    endpoint = SecureASTExtractor(app_file, app_entry="main:create_app").extract_endpoints()[0]
    provenance = endpoint.native_provenance
    assert provenance is not None
    assignments = {
        owner.qualified_binding: owner
        for owner in provenance.source_owners
        if owner.owner_kind == "assignment_rhs"
    }
    assert set(assignments) == {"main.create_app.router", "main.create_app.app"}
    assert assignments["main.create_app.router"].source_span.start_line == 3
    assert assignments["main.create_app.app"].source_span.start_line == 6
    assert any(
        owner.owner_kind == "assignment_rhs" and owner.qualified_binding == "main.create_app.router"
        for owner in native_route_structural_owners(endpoint, app_file, {3})
    )


def test_factory_router_snapshot_preserves_scoped_dependency_provenance(
    tmp_path: Path,
) -> None:
    app_file = tmp_path / "main.py"
    app_file.write_text(
        "from fastapi import APIRouter, Depends, FastAPI\n"
        "def load_identity(): pass\n"
        "def create_app():\n"
        "    router = APIRouter(dependencies=[Depends(load_identity)])\n"
        "    @router.get('/item')\n"
        "    def item(): pass\n"
        "    app = FastAPI()\n"
        "    app.include_router(router)\n"
        "    return app\n",
        encoding="utf-8",
    )

    endpoint = SecureASTExtractor(app_file, app_entry="main:create_app").extract_endpoints()[0]
    provenance = endpoint.native_provenance
    assert provenance is not None
    assert len(provenance.assembly_chain) == 1
    assert provenance.assembly_chain[0].operation == "include_router"
    assert provenance.assembly_chain[0].source_span.start_line == 8

    router = provenance.object_chain[-1]
    assert router.object_kind == "router"
    assert len(router.dependency_expressions) == 1
    dependency = router.dependency_expressions[0]
    assert dependency.scope == "router"
    assert dependency.kind == "depends"
    assert dependency.confidence == "established"
    assert dependency.callable_expressions == ("main.load_identity",)
    assert dependency.source_span.start_line == 4

    owners = native_route_structural_owners(endpoint, app_file, {4})
    dependency_owners = [item for item in owners if item.role == "dependency"]
    assert len(dependency_owners) == 1
    assert dependency_owners[0].source_span == dependency.source_span


def test_same_line_route_registrations_have_distinct_physical_occurrence_order(
    tmp_path: Path,
) -> None:
    app_file = tmp_path / "main.py"
    app_file.write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "def handler(): pass\n"
        "app.add_api_route('/first', handler); app.add_api_route('/second', handler)\n",
        encoding="utf-8",
    )
    endpoints = SecureASTExtractor(app_file).extract_endpoints()
    first = next(endpoint for endpoint in endpoints if endpoint.identifier == "GET /first")
    second = next(endpoint for endpoint in endpoints if endpoint.identifier == "GET /second")
    first_registration = first.native_provenance.registration if first.native_provenance else None
    second_registration = (
        second.native_provenance.registration if second.native_provenance else None
    )
    assert first_registration is not None and second_registration is not None
    assert first_registration.source_span.start_line == second_registration.source_span.start_line
    assert first_registration.source_span != second_registration.source_span
    assert first_registration.occurrence_order < second_registration.occurrence_order
