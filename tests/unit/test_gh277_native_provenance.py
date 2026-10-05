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
