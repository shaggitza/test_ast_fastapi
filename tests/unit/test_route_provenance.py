"""Secure-AST native route assembly provenance and ownership tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.analyzer.endpoint_registry import EndpointRegistry
from fastapi_endpoint_detector.models.diff import ChangeType, DiffFile, DiffHunk
from fastapi_endpoint_detector.models.endpoint import (
    NativeRegistrationKind,
    NativeRootSelectionKind,
    NativeRouteProvenance,
    SnapshotSide,
)
from fastapi_endpoint_detector.models.report import (
    ChangeEffectKind,
    EvidenceProducer,
)
from fastapi_endpoint_detector.parser.secure_ast_extractor import SecureASTExtractor


class _EmptySCIP:
    def ensure_index(self, *, force: bool = False) -> None:
        del force

    def definitions_at(self, _file_path: Path, _lines: set[int]) -> list[object]:
        return []


def _write_composed_app(path: Path, *, prefix: str = "/new") -> None:
    path.write_text(
        "from fastapi import APIRouter, FastAPI\n"
        "app = FastAPI()\n"
        "first = APIRouter(prefix='/first')\n"
        "second = APIRouter(prefix='/second')\n"
        "@first.get(\n"
        "    '/items',\n"
        ")\n"
        "def first_items(): pass\n"
        "@second.get('/items')\n"
        "def second_items(): pass\n"
        f"app.include_router(first, prefix={prefix!r})\n"
        "app.include_router(second, prefix='/other')\n",
        encoding="utf-8",
    )


def _nested_provenance_payload(tmp_path: Path) -> dict[str, Any]:
    app_file = tmp_path / "nested.py"
    app_file.write_text(
        "from fastapi import APIRouter, FastAPI\n"
        "app = FastAPI()\n"
        "mounted = FastAPI()\n"
        "router = APIRouter()\n"
        "@router.get('/items')\n"
        "def items(): pass\n"
        "mounted.include_router(router)\n"
        "app.mount('/service', mounted)\n",
        encoding="utf-8",
    )
    endpoint = SecureASTExtractor(app_file).extract_endpoints()[0]
    assert endpoint.native_provenance is not None
    return endpoint.native_provenance.model_dump(mode="python")


def test_secure_provenance_preserves_multiline_registration_and_exact_chain(
    tmp_path: Path,
) -> None:
    app_file = tmp_path / "main.py"
    _write_composed_app(app_file)

    endpoints = SecureASTExtractor(app_file).extract_endpoints()
    endpoint = next(item for item in endpoints if item.identifier == "GET /new/first/items")
    provenance = endpoint.native_provenance

    assert provenance is not None
    assert provenance.side == SnapshotSide.TARGET
    assert provenance.root.selection_kind == NativeRootSelectionKind.APP_VARIABLE
    assert provenance.registration.kind == NativeRegistrationKind.DECORATOR
    assert provenance.registration.operation == "get"
    assert (
        provenance.registration.source_span.start_line,
        provenance.registration.source_span.end_line,
    ) == (5, 7)
    assert [item.operation for item in provenance.assembly_chain] == ["include_router"]
    assert [item.resolved_prefix for item in provenance.assembly_chain] == ["/new"]
    assert provenance.assembly_chain[0].source_span.start_line == 11
    assert [item.object_kind for item in provenance.object_chain] == ["app", "router"]
    assert [item.resolved_prefix for item in provenance.object_chain] == ["", "/first"]


def test_repeated_include_occurrences_remain_distinct(tmp_path: Path) -> None:
    app_file = tmp_path / "main.py"
    app_file.write_text(
        "from fastapi import APIRouter, FastAPI\n"
        "app = FastAPI()\n"
        "router = APIRouter()\n"
        "@router.get('/items')\n"
        "def items(): pass\n"
        "app.include_router(router, prefix='/one')\n"
        "app.include_router(router, prefix='/two')\n",
        encoding="utf-8",
    )

    endpoints = SecureASTExtractor(app_file).extract_endpoints()
    evidence = {
        item.identifier: item.native_provenance.assembly_chain[0]  # type: ignore[union-attr]
        for item in endpoints
    }

    assert set(evidence) == {"GET /one/items", "GET /two/items"}
    assert {item.source_span.start_line for item in evidence.values()} == {6, 7}
    assert len({item.occurrence_order for item in evidence.values()}) == 2


def test_snapshot_side_and_factory_bootstrap_roots_are_explicit(tmp_path: Path) -> None:
    (tmp_path / "factory.py").write_text(
        "from fastapi import FastAPI\n"
        "def create():\n"
        "    app = FastAPI()\n"
        "    @app.get('/factory')\n"
        "    def route(): pass\n"
        "    return app\n",
        encoding="utf-8",
    )
    factory_endpoint = SecureASTExtractor(
        tmp_path,
        app_entry="factory:create",
        snapshot_side=SnapshotSide.BASELINE,
    ).extract_endpoints()[0]

    assert factory_endpoint.native_provenance is not None
    assert factory_endpoint.native_provenance.side == SnapshotSide.BASELINE
    assert (
        factory_endpoint.native_provenance.root.selection_kind
        == NativeRootSelectionKind.APP_ENTRY_FACTORY
    )

    (tmp_path / "bootstrap.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "def route(): pass\n"
        "def run():\n"
        "    app.add_api_route('/bootstrap', route)\n",
        encoding="utf-8",
    )
    bootstrap_endpoint = SecureASTExtractor(
        tmp_path,
        app_entry="bootstrap:app",
        bootstrap_entry="bootstrap:run",
    ).extract_endpoints()[0]

    assert bootstrap_endpoint.native_provenance is not None
    assert bootstrap_endpoint.native_provenance.root.bootstrap_span is not None
    assert (
        bootstrap_endpoint.native_provenance.registration.kind == NativeRegistrationKind.IMPERATIVE
    )
    assert bootstrap_endpoint.native_provenance.registration.source_span.start_line == 5


def test_native_provenance_rejects_root_disconnected_from_object_chain(
    tmp_path: Path,
) -> None:
    payload = _nested_provenance_payload(tmp_path)
    payload["root"]["symbol"] = "not_the_selected_root"

    with pytest.raises(ValidationError, match="root must be the first object"):
        NativeRouteProvenance.model_validate(payload)


@pytest.mark.parametrize(
    ("selection_kind", "incompatible_kind"),
    [
        (NativeRootSelectionKind.APP_VARIABLE, "router"),
        (NativeRootSelectionKind.APP_ENTRY_OBJECT, "router"),
        (NativeRootSelectionKind.APP_ENTRY_FACTORY, "router"),
        (NativeRootSelectionKind.ROUTER_VARIABLE, "app"),
    ],
)
def test_native_provenance_rejects_incompatible_root_object_role(
    tmp_path: Path,
    selection_kind: NativeRootSelectionKind,
    incompatible_kind: str,
) -> None:
    payload = _nested_provenance_payload(tmp_path)
    payload["root"]["selection_kind"] = selection_kind
    payload["object_chain"][0]["object_kind"] = incompatible_kind

    with pytest.raises(ValidationError, match="root selection must match"):
        NativeRouteProvenance.model_validate(payload)


@pytest.mark.parametrize(
    ("edge_index", "incompatible_mode"),
    [(0, "copy"), (1, "live")],
    ids=["mount-copy", "include-router-live"],
)
def test_native_provenance_rejects_incompatible_assembly_mode(
    tmp_path: Path,
    edge_index: int,
    incompatible_mode: str,
) -> None:
    payload = _nested_provenance_payload(tmp_path)
    payload["assembly_chain"][edge_index]["mode"] = incompatible_mode

    with pytest.raises(ValidationError, match="operation must use its declared composition mode"):
        NativeRouteProvenance.model_validate(payload)


@pytest.mark.parametrize(
    ("object_index", "incompatible_kind"),
    [(1, "router"), (2, "app")],
    ids=["mount-router", "include-router-app"],
)
def test_native_provenance_rejects_incompatible_assembly_object_role(
    tmp_path: Path,
    object_index: int,
    incompatible_kind: str,
) -> None:
    payload = _nested_provenance_payload(tmp_path)
    payload["object_chain"][object_index]["object_kind"] = incompatible_kind

    with pytest.raises(ValidationError, match="operation must target a compatible object role"):
        NativeRouteProvenance.model_validate(payload)


def test_registry_maps_include_change_only_to_exact_descendants(tmp_path: Path) -> None:
    app_file = tmp_path / "main.py"
    _write_composed_app(app_file)
    endpoints = SecureASTExtractor(app_file).extract_endpoints()
    registry = EndpointRegistry()
    registry.register_many(endpoints)

    matches = registry.get_structural_overlaps(Path("main.py"), {11})

    assert [(item.identifier, kinds, lines) for item, kinds, lines in matches] == [
        ("GET /new/first/items", ("assembly_include_router",), {11})
    ]
    assert registry.get_structural_overlaps(Path("ambiguous/main.py"), {11}) == []


def test_change_mapper_emits_structural_evidence_for_target_prefix_change(
    tmp_path: Path,
    monkeypatch,
) -> None:
    app_file = tmp_path / "main.py"
    _write_composed_app(app_file)
    mapper = ChangeMapper(app_file, secure_ast=True, use_cache=False)
    monkeypatch.setattr(mapper, "_check_mypy_dependency", lambda *_args, **_kwargs: None)
    diff_file = DiffFile(
        path=Path("main.py"),
        change_type=ChangeType.MODIFIED,
        hunks=[
            DiffHunk(
                source_start=11,
                source_length=1,
                target_start=11,
                target_length=1,
                added_lines=[11],
                removed_lines=[11],
            )
        ],
        added_lines=1,
        removed_lines=1,
    )

    affected, processed_added, processed_removed = mapper._analyze_diff_file(diff_file)

    assert [item.endpoint.identifier for item in affected] == ["GET /new/first/items"]
    assert processed_added == {11}
    assert processed_removed == set()
    assert affected[0].effect_evidence[0].producer == EvidenceProducer.STRUCTURAL
    assert affected[0].effect_evidence[0].effect == ChangeEffectKind.ROUTE_ASSEMBLY


def test_duplicate_public_routes_keep_distinct_assembly_occurrences(
    tmp_path: Path,
    monkeypatch,
) -> None:
    app_file = tmp_path / "main.py"
    app_file.write_text(
        "from fastapi import APIRouter, FastAPI\n"
        "app = FastAPI()\n"
        "router = APIRouter()\n"
        "@router.get('/items')\n"
        "def items(): pass\n"
        "app.include_router(router)\n"
        "app.include_router(router)\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(app_file, secure_ast=True, use_cache=False)
    monkeypatch.setattr(mapper, "_check_mypy_dependency", lambda *_args, **_kwargs: None)
    diff_file = DiffFile(
        path=Path("main.py"),
        change_type=ChangeType.MODIFIED,
        hunks=[
            DiffHunk(
                source_start=6,
                source_length=2,
                target_start=6,
                target_length=2,
                added_lines=[6, 7],
                removed_lines=[],
            )
        ],
        added_lines=2,
    )

    affected, processed_added, _processed_removed = mapper._analyze_diff_file(diff_file)

    assert [item.endpoint.identifier for item in affected] == ["GET /items", "GET /items"]
    assert {
        item.endpoint.native_provenance.assembly_chain[0].source_span.start_line  # type: ignore[union-attr]
        for item in affected
    } == {6, 7}
    assert processed_added == {6, 7}


def test_scip_mode_keeps_target_and_baseline_assembly_sides_distinct(tmp_path: Path) -> None:
    target = tmp_path / "target"
    baseline = tmp_path / "baseline"
    target.mkdir()
    baseline.mkdir()
    _write_composed_app(target / "main.py", prefix="/new")
    _write_composed_app(baseline / "main.py", prefix="/old")
    mapper = ChangeMapper(
        target / "main.py",
        secure_ast=True,
        use_scip=True,
        use_cache=False,
        baseline_app_path=baseline / "main.py",
    )
    mapper._scip_analyzer = _EmptySCIP()  # type: ignore[assignment]
    mapper._baseline_scip_analyzer = _EmptySCIP()  # type: ignore[assignment]
    diff_file = DiffFile(
        path=Path("main.py"),
        source_path=Path("main.py"),
        change_type=ChangeType.MODIFIED,
        hunks=[
            DiffHunk(
                source_start=11,
                source_length=1,
                target_start=11,
                target_length=1,
                added_lines=[11],
                removed_lines=[11],
            )
        ],
        added_lines=1,
        removed_lines=1,
    )

    affected, orphans = mapper._analyze_with_scip([diff_file], [], None)

    assert {item.endpoint.identifier for item in affected} == {
        "GET /new/first/items",
        "GET /old/first/items",
    }
    sides = {
        item.endpoint.identifier: item.endpoint.native_provenance.side  # type: ignore[union-attr]
        for item in affected
    }
    assert sides == {
        "GET /new/first/items": SnapshotSide.TARGET,
        "GET /old/first/items": SnapshotSide.BASELINE,
    }
    assert orphans == []
