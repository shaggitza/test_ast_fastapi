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
    assert evidence.object_chain[0].dependency_expressions[0].callable_expressions == ("app_dep",)
    assert evidence.object_chain[1].dependency_expressions[0].callable_expressions == (
        "router_dep",
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
    assert dependency.callable_expressions == ("route_dep",)


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
