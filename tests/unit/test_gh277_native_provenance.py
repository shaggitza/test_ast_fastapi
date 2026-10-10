"""Regression coverage for source-only GH277 route provenance additions."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
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


def test_native_route_dependency_reaches_typed_transitive_helper_without_fanout(
    tmp_path: Path,
) -> None:
    app_file = tmp_path / "main.py"
    app_file.write_text(
        "from fastapi import APIRouter, Depends, FastAPI\n"
        "from helpers import app_helper, include_helper, route_helper, router_helper\n"
        "def app_dep(): return app_helper()\n"
        "def router_dep(): return router_helper()\n"
        "def include_dep(): return include_helper()\n"
        "def route_dep(): return route_helper()\n"
        "app = FastAPI(dependencies=[Depends(app_dep)])\n"
        "router = APIRouter(dependencies=[Depends(router_dep)])\n"
        "@router.get('/items', dependencies=[Depends(route_dep)])\n"
        "def handler(): return 1\n"
        "@router.get('/safe')\n"
        "def safe_handler(): return 2\n"
        "app.include_router(router, dependencies=[Depends(include_dep)])\n",
        encoding="utf-8",
    )
    helper_file = tmp_path / "helpers.py"
    helper_file.write_text(
        "def app_helper(): return 3\n"
        "def router_helper(): return 4\n"
        "def include_helper(): return 5\n"
        "def route_helper(): return 6\n",
        encoding="utf-8",
    )
    endpoints = SecureASTExtractor(app_file).extract_endpoints()
    selected = next(endpoint for endpoint in endpoints if endpoint.identifier == "GET /items")
    unrelated = next(endpoint for endpoint in endpoints if endpoint.identifier == "GET /safe")
    analyzer = MypyAnalyzer(tmp_path, max_depth=4)

    result = analyzer.analyze_endpoint(selected)
    unrelated_result = analyzer.analyze_endpoint(unrelated)
    for line in range(3, 7):
        assert result.references_symbol_at_line("main.py", line) is not None
    for line in range(1, 5):
        assert result.references_symbol_at_line("helpers.py", line) is not None
    for line in range(3, 6):
        assert unrelated_result.references_symbol_at_line("main.py", line) is not None
    assert unrelated_result.references_symbol_at_line("main.py", 6) is None
    for line in range(1, 4):
        assert unrelated_result.references_symbol_at_line("helpers.py", line) is not None
    assert unrelated_result.references_symbol_at_line("helpers.py", 4) is None
    assert analyzer._endpoint_key(selected) != analyzer._endpoint_key(
        selected.model_copy(update={"native_provenance": None})
    )


@pytest.mark.parametrize(
    ("scope", "helper", "expected"),
    [
        ("app", "app_helper", {"GET /items", "GET /safe", "GET /foreign"}),
        ("router", "router_helper", {"GET /items", "GET /safe"}),
        ("include", "include_helper", {"GET /items", "GET /safe"}),
        ("route", "route_helper", {"GET /items"}),
    ],
)
def test_native_dependency_helper_diff_reaches_only_public_descendant_routes(
    tmp_path: Path,
    scope: str,
    helper: str,
    expected: set[str],
) -> None:
    baseline = tmp_path / "baseline"
    target = tmp_path / "target"
    for root in (baseline, target):
        root.mkdir()
        (root / "helpers.py").write_text(
            "def app_helper(): return 1\n"
            "def router_helper(): return 2\n"
            "def include_helper(): return 3\n"
            "def route_helper(): return 4\n"
            "def foreign_helper(): return 5\n",
            encoding="utf-8",
        )
        (root / "foreign.py").write_text("def route_helper(): return 6\n", encoding="utf-8")
        (root / "main.py").write_text(
            "from fastapi import APIRouter, Depends, FastAPI\n"
            "from helpers import app_helper, include_helper, router_helper, route_helper\n"
            "from foreign import route_helper as foreign_route_helper\n"
            "def app_dep(): return app_helper()\n"
            "def router_dep(): return router_helper()\n"
            "def include_dep(): return include_helper()\n"
            "def route_dep(): return route_helper()\n"
            "app = FastAPI(dependencies=[Depends(app_dep)])\n"
            "router = APIRouter(dependencies=[Depends(router_dep)])\n"
            "@router.get('/items', dependencies=[Depends(route_dep)])\n"
            "def items(): return 1\n"
            "@router.get('/safe')\n"
            "def safe(): return 2\n"
            "@app.get('/foreign', dependencies=[Depends(foreign_route_helper)])\n"
            "def foreign(): return 3\n"
            "app.include_router(router, dependencies=[Depends(include_dep)])\n",
            encoding="utf-8",
        )

    # Edit exactly one bound helper in each public dependency scope. The same
    # short route_helper name in foreign.py must never create a candidate.
    helper_lines = (target / "helpers.py").read_text(encoding="utf-8").splitlines()
    helper_index = next(
        index for index, line in enumerate(helper_lines) if line.startswith(f"def {helper}()")
    )
    old_line = helper_lines[helper_index]
    new_line = old_line.replace("return ", "return 40 + ", 1)
    helper_lines[helper_index] = new_line
    (target / "helpers.py").write_text("\n".join(helper_lines) + "\n", encoding="utf-8")
    diff = (
        "diff --git a/helpers.py b/helpers.py\n"
        "--- a/helpers.py\n"
        "+++ b/helpers.py\n"
        f"@@ -{helper_index + 1},1 +{helper_index + 1},1 @@\n"
        f"-{old_line}\n"
        f"+{new_line}\n"
    )

    report = ChangeMapper(
        target / "main.py",
        baseline_app_path=baseline / "main.py",
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)

    candidates = {item.endpoint.identifier: item for item in report.candidate_endpoints}
    assert set(candidates) == expected
    assert {item.endpoint.identifier for item in report.affected_endpoints} == expected
    for candidate in candidates.values():
        assert candidate.endpoint.native_provenance is not None
        assert candidate.endpoint.native_provenance.side == SnapshotSide.TARGET


@pytest.mark.parametrize(
    ("helper", "expected"),
    [
        ("parent_helper", {"GET /parent"}),
        ("child_helper", {"GET /child/item"}),
    ],
)
def test_mounted_child_dependency_diff_respects_mount_ownership_boundary(
    tmp_path: Path,
    helper: str,
    expected: set[str],
) -> None:
    baseline = tmp_path / "baseline"
    target = tmp_path / "target"
    for root in (baseline, target):
        root.mkdir()
        (root / "helpers.py").write_text(
            "def parent_helper(): return 1\ndef child_helper(): return 2\n",
            encoding="utf-8",
        )
        (root / "main.py").write_text(
            "from fastapi import Depends, FastAPI\n"
            "from helpers import child_helper, parent_helper\n"
            "def parent_dep(): return parent_helper()\n"
            "def child_dep(): return child_helper()\n"
            "app = FastAPI(dependencies=[Depends(parent_dep)])\n"
            "child = FastAPI(dependencies=[Depends(child_dep)])\n"
            "@app.get('/parent')\n"
            "def parent_route(): return 1\n"
            "@child.get('/item')\n"
            "def child_route(): return 2\n"
            "app.mount('/child', child)\n",
            encoding="utf-8",
        )

    helper_lines = (target / "helpers.py").read_text(encoding="utf-8").splitlines()
    helper_index = next(
        index for index, line in enumerate(helper_lines) if line.startswith(f"def {helper}()")
    )
    old_line = helper_lines[helper_index]
    new_line = old_line.replace("return ", "return 40 + ", 1)
    helper_lines[helper_index] = new_line
    (target / "helpers.py").write_text("\n".join(helper_lines) + "\n", encoding="utf-8")
    diff = (
        "diff --git a/helpers.py b/helpers.py\n"
        "--- a/helpers.py\n"
        "+++ b/helpers.py\n"
        f"@@ -{helper_index + 1},1 +{helper_index + 1},1 @@\n"
        f"-{old_line}\n"
        f"+{new_line}\n"
    )

    report = ChangeMapper(
        target / "main.py",
        baseline_app_path=baseline / "main.py",
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)
    candidates = {item.endpoint.identifier: item for item in report.candidate_endpoints}
    assert set(candidates) == expected
    assert {item.endpoint.identifier for item in report.affected_endpoints} == expected
    for candidate in candidates.values():
        provenance = candidate.endpoint.native_provenance
        assert provenance is not None
        assert provenance.side == SnapshotSide.TARGET
        if candidate.endpoint.identifier == "GET /child/item":
            assert any(edge.operation == "mount" for edge in provenance.assembly_chain)


def test_global_prefix_ownership_is_limited_to_descendant_routes_and_side(
    tmp_path: Path,
) -> None:
    app_file = tmp_path / "main.py"
    app_file.write_text(
        "from fastapi import APIRouter, FastAPI\n"
        "PREFIX_PART = '/api'\n"
        "PREFIX = (\n"
        "    PREFIX_PART\n"
        ")\n"
        "DECOY = '/decoy'\n"
        "router = APIRouter()\n"
        "@router.get('/items')\n"
        "def items(): pass\n"
        "@router.get('/other')\n"
        "def other(): pass\n"
        "unrelated = APIRouter()\n"
        "@unrelated.get('/unrelated')\n"
        "def unrelated_route(): pass\n"
        "app = FastAPI()\n"
        "app.include_router(router, prefix=PREFIX)\n"
        "app.include_router(unrelated, prefix='/safe')\n",
        encoding="utf-8",
    )
    baseline = SecureASTExtractor(app_file, snapshot_side=SnapshotSide.BASELINE).extract_endpoints()
    target = SecureASTExtractor(app_file, snapshot_side=SnapshotSide.TARGET).extract_endpoints()
    line_prefix = 2
    line_alias = 3
    for endpoints, side in ((baseline, SnapshotSide.BASELINE), (target, SnapshotSide.TARGET)):
        items = next(endpoint for endpoint in endpoints if endpoint.identifier == "GET /api/items")
        other = next(endpoint for endpoint in endpoints if endpoint.identifier == "GET /api/other")
        prefix_owners = [
            owner
            for owner in native_route_structural_owners(
                items, app_file, {line_prefix, line_alias, 4, 5}
            )
            if owner.role == "assembly"
        ]
        assert {owner.source_span.start_line for owner in prefix_owners} == {
            line_prefix,
            line_alias,
        }
        alias_owner = next(
            owner for owner in prefix_owners if owner.source_span.start_line == line_alias
        )
        assert (alias_owner.source_span.start_line, alias_owner.source_span.end_line) == (
            line_alias,
            5,
        )
        assert {owner.endpoint_identifier for owner in prefix_owners} == {items.identifier}
        assert {owner.side for owner in prefix_owners} == {side}
        assert any(
            owner.role == "assembly"
            for owner in native_route_structural_owners(other, app_file, {4})
        )
        safe = next(
            endpoint for endpoint in endpoints if endpoint.identifier == "GET /safe/unrelated"
        )
        assert native_route_structural_owners(safe, app_file, {line_prefix, line_alias}) == ()

    baseline_items = next(
        endpoint for endpoint in baseline if endpoint.identifier == "GET /api/items"
    )
    evidence = baseline_items.native_provenance
    assert evidence is not None
    restored = type(baseline_items).model_validate(baseline_items.model_dump())
    app_file.write_text(
        app_file.read_text(encoding="utf-8").replace(
            "PREFIX_PART = '/api'", "PREFIX_PART = '/changed'"
        ),
        encoding="utf-8",
    )
    after_rewrite = native_route_structural_owners(restored, app_file, {2})
    assert {owner.source_span.start_line for owner in after_rewrite} == {2}
    assert {owner.side for owner in after_rewrite} == {SnapshotSide.BASELINE}


def test_global_prefix_ownership_fails_closed_for_dynamic_or_reassigned_names(
    tmp_path: Path,
) -> None:
    for filename, assignments in (
        ("dynamic.py", "PREFIX = make_prefix()\n"),
        ("reassigned.py", "PREFIX = '/api'\nPREFIX = '/other'\n"),
    ):
        app_file = tmp_path / filename
        app_file.write_text(
            "from fastapi import APIRouter, FastAPI\n"
            + assignments
            + "router = APIRouter()\n"
            + "@router.get('/items')\n"
            + "def items(): pass\n"
            + "app = FastAPI()\n"
            + "app.include_router(router, prefix=PREFIX)\n",
            encoding="utf-8",
        )
        endpoints = SecureASTExtractor(app_file).extract_endpoints()
        for endpoint in endpoints:
            assert not any(
                owner.role == "assembly"
                for owner in native_route_structural_owners(endpoint, app_file, {2, 3})
            )


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


def test_recursive_reexport_owners_cover_each_export_hop_and_only_descendants(
    tmp_path: Path,
) -> None:
    implementation = tmp_path / "implementation.py"
    implementation.write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.get('/deep')\n"
        "def deep(): pass\n",
        encoding="utf-8",
    )
    (tmp_path / "level_one.py").write_text(
        "from implementation import router as first\n__all__ = ['first']\n",
        encoding="utf-8",
    )
    (tmp_path / "level_two.py").write_text(
        "from level_one import first as second\n__all__ = ['second']\n",
        encoding="utf-8",
    )
    (tmp_path / "public.py").write_text(
        "from level_two import second as published\n__all__ = ['published']\n",
        encoding="utf-8",
    )
    app_file = tmp_path / "main.py"
    app_file.write_text(
        "from fastapi import APIRouter, FastAPI\n"
        "from public import published\n"
        "other = APIRouter()\n"
        "@other.get('/other')\n"
        "def other_route(): pass\n"
        "app = FastAPI()\n"
        "app.include_router(published)\n"
        "app.include_router(other)\n",
        encoding="utf-8",
    )

    endpoints = SecureASTExtractor(app_file).extract_endpoints()
    deep = next(item for item in endpoints if item.identifier == "GET /deep")
    other = next(item for item in endpoints if item.identifier == "GET /other")
    owners = deep.native_provenance.source_owners if deep.native_provenance else ()
    assert {owner.qualified_binding for owner in owners if owner.owner_kind == "reexport"} == {
        "public.published",
        "level_two.second",
        "level_one.first",
    }
    assert {owner.qualified_binding for owner in owners if owner.owner_kind == "all_export"} == {
        "public.published",
        "level_two.second",
        "level_one.first",
    }
    for source in (tmp_path / "public.py", tmp_path / "level_two.py", tmp_path / "level_one.py"):
        assert any(
            owner.role == "object" for owner in native_route_structural_owners(deep, source, {1})
        )
        assert any(
            owner.role == "object" for owner in native_route_structural_owners(deep, source, {2})
        )
        assert native_route_structural_owners(other, source, {1, 2}) == ()


def test_reassigned_or_deleted_all_does_not_leave_stale_export_ownership(
    tmp_path: Path,
) -> None:
    cases = {
        "reassigned": (
            "from implementation import router as published\n"
            "__all__ = ['published']\n"
            "__all__ = []\n",
            {2},
        ),
        "deleted": (
            "from implementation import router as published\n"
            "__all__ = ['published']\n"
            "del __all__\n",
            {2},
        ),
        "annotation_without_value": (
            "from implementation import router as published\n"
            "__all__ = ['published']\n"
            "__all__: list[str]\n",
            {2, 3},
        ),
        "annotation_mutation": (
            "from implementation import router as published\n"
            "__all__ = ['published']\n"
            "__all__: (__all__.clear() or list[str])\n",
            {2, 3},
        ),
        "aliased_mutation": (
            "from implementation import router as published\n"
            "__all__ = ['published']\n"
            "exports = __all__\n"
            "exports.clear()\n",
            {2, 3, 4},
        ),
        "alias_then_literal_reset": (
            "from implementation import router as published\n"
            "__all__ = ['published']\n"
            "exports = __all__\n"
            "exports.clear()\n"
            "__all__ = ['published']\n",
            {5},
        ),
        "destructured_all": (
            "from implementation import router as published\n"
            "__all__, untouched = ('published', 'x')\n",
            {2},
        ),
        "chained_alias_mutation": (
            "from implementation import router as published\n"
            "__all__ = exports = ['published']\n"
            "exports.clear()\n",
            {2, 3},
        ),
        "chained_alias_reset": (
            "from implementation import router as published\n"
            "__all__ = exports = ['published']\n"
            "exports.clear()\n"
            "__all__ = ['published']\n",
            {4},
        ),
    }
    (tmp_path / "implementation.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.get('/owned')\n"
        "def owned(): pass\n",
        encoding="utf-8",
    )
    for name, (exports, changed_lines) in cases.items():
        public = tmp_path / f"{name}.py"
        public.write_text(exports, encoding="utf-8")
        app_file = tmp_path / f"main_{name}.py"
        app_file.write_text(
            f"from fastapi import FastAPI\nfrom {name} import published\n"
            "app = FastAPI()\napp.include_router(published)\n",
            encoding="utf-8",
        )
        endpoint = SecureASTExtractor(app_file).extract_endpoints()[0]
        provenance = endpoint.native_provenance
        assert provenance is not None
        all_owners = [
            owner for owner in provenance.source_owners if owner.owner_kind == "all_export"
        ]
        if name == "annotation_without_value":
            assert len(all_owners) == 1
            assert all_owners[0].source_span.start_line == 2
            assert any(
                owner.role == "object"
                for owner in native_route_structural_owners(endpoint, public, {2})
            )
            assert native_route_structural_owners(endpoint, public, {3}) == ()
        elif name in {"alias_then_literal_reset", "chained_alias_reset"}:
            reset_line = 5 if name == "alias_then_literal_reset" else 4
            assert len(all_owners) == 1
            assert all_owners[0].source_span.start_line == reset_line
            assert any(
                owner.role == "object"
                for owner in native_route_structural_owners(endpoint, public, {reset_line})
            )
            assert not any(
                owner.role == "object"
                for owner in native_route_structural_owners(
                    endpoint, public, set(range(2, reset_line))
                )
            )
        else:
            assert all_owners == []
            assert not any(
                owner.role == "object"
                for owner in native_route_structural_owners(endpoint, public, changed_lines)
            )


def test_nested_all_escape_and_mutation_invalidate_stale_ownership(
    tmp_path: Path,
) -> None:
    nested_statements = {
        "if_alias": "if condition:\n    exports = __all__\n    exports.clear()\n",
        "try_alias": (
            "try:\n    exports = __all__\n    exports.clear()\nexcept Exception:\n    pass\n"
        ),
        "loop_alias": "for unused in [0]:\n    exports = __all__\n    exports.clear()\n",
        "if_direct_mutation": "if condition:\n    __all__.clear()\n",
        "if_delete": "if condition:\n    del __all__\n",
        "try_delete": "try:\n    del __all__\nexcept Exception:\n    pass\n",
        "for_delete": "for unused in [0]:\n    del __all__\n",
        "while_delete": "while condition:\n    del __all__\n",
        "with_delete": "with manager:\n    del __all__\n",
        "match_delete": "match value:\n    case _:\n        del __all__\n",
        "if_augassign": "if condition:\n    __all__ *= 0\n",
        "try_augassign": "try:\n    __all__ *= 0\nexcept Exception:\n    pass\n",
        "for_augassign": "for unused in [0]:\n    __all__ *= 0\n",
        "while_augassign": "while condition:\n    __all__ *= 0\n",
        "with_augassign": "with manager:\n    __all__ *= 0\n",
        "match_augassign": "match value:\n    case _:\n        __all__ *= 0\n",
        "if_namedexpr": "if (__all__ := []):\n    pass\n",
        "except_alias": "try:\n    pass\nexcept Exception as __all__:\n    pass\n",
        "match_capture": "match value:\n    case __all__:\n        pass\n",
        "match_star_capture": "match value:\n    case [*__all__]:\n        pass\n",
        "match_rest_capture": "match value:\n    case {**__all__}:\n        pass\n",
        "if_annotation_only": "if condition:\n    __all__: list[str]\n",
        "try_annotation_only": "try:\n    __all__: list[str]\nexcept Exception:\n    pass\n",
        "for_annotation_only": "for unused in [0]:\n    __all__: list[str]\n",
        "while_annotation_only": "while condition:\n    __all__: list[str]\n",
        "with_annotation_only": "with manager:\n    __all__: list[str]\n",
        "match_annotation_only": "match value:\n    case _:\n        __all__: list[str]\n",
        "if_annotation_effect": "if condition:\n    __all__: (__all__.clear() or list[str])\n",
        "annotation_namedexpr_effect": "__all__: (__all__ := [])\n",
        "if_annotation_namedexpr_effect": "if condition:\n    __all__: (__all__ := [])\n",
    }
    (tmp_path / "implementation.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.get('/nested')\n"
        "def nested(): pass\n",
        encoding="utf-8",
    )
    for name, statement in nested_statements.items():
        public = tmp_path / f"nested_{name}.py"
        public.write_text(
            f"from implementation import router as published\n__all__ = ['published']\n{statement}",
            encoding="utf-8",
        )
        app_file = tmp_path / f"nested_main_{name}.py"
        app_file.write_text(
            f"from fastapi import FastAPI\nfrom nested_{name} import published\n"
            "app = FastAPI()\napp.include_router(published)\n",
            encoding="utf-8",
        )
        endpoint = SecureASTExtractor(app_file).extract_endpoints()[0]
        provenance = endpoint.native_provenance
        assert provenance is not None
        if name.endswith("_annotation_only"):
            all_owners = [
                owner for owner in provenance.source_owners if owner.owner_kind == "all_export"
            ]
            assert len(all_owners) == 1
            assert all_owners[0].source_span.start_line == 2
            assert any(
                owner.owner_kind == "all_export"
                for owner in native_route_structural_owners(endpoint, public, {2})
            )
            assert not any(
                owner.role == "object"
                for owner in native_route_structural_owners(endpoint, public, set(range(3, 8)))
            )
        else:
            assert not any(owner.owner_kind == "all_export" for owner in provenance.source_owners)
            assert not any(
                owner.role == "object"
                for owner in native_route_structural_owners(endpoint, public, {2, *range(3, 8)})
            )


def test_later_literal_all_assignment_restores_deleted_export_ownership(tmp_path: Path) -> None:
    (tmp_path / "implementation.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.get('/restored')\n"
        "def restored(): pass\n",
        encoding="utf-8",
    )
    public = tmp_path / "public.py"
    public.write_text(
        "from implementation import router as published\n"
        "__all__ = ['published']\n"
        "if condition:\n    del __all__\n"
        "__all__ = ['published']\n",
        encoding="utf-8",
    )
    app_file = tmp_path / "main.py"
    app_file.write_text(
        "from fastapi import FastAPI\nfrom public import published\n"
        "app = FastAPI()\napp.include_router(published)\n",
        encoding="utf-8",
    )
    endpoint = SecureASTExtractor(app_file).extract_endpoints()[0]
    provenance = endpoint.native_provenance
    assert provenance is not None
    owners = [owner for owner in provenance.source_owners if owner.owner_kind == "all_export"]
    assert len(owners) == 1
    assert owners[0].source_span.start_line == 5
    assert not any(
        owner.role == "object"
        for owner in native_route_structural_owners(endpoint, public, {2, 3, 4})
    )
    assert any(
        owner.owner_kind == "all_export"
        for owner in native_route_structural_owners(endpoint, public, {5})
    )


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
