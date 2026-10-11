"""Construction proof controls use mypy's parsed source; no fixture code executes."""

import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from mypy.build import build
from mypy.modulefinder import BuildSource
from mypy.nodes import ARG_NAMED, ARG_POS, CallExpr, NameExpr, StrExpr, TypeInfo
from mypy.options import Options

from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.models.effect_contract import CallResolutionStatus, ResolvedCallSite

_PROJECT = "/__callable_construction_guard__/project"
_SOURCE = """from typing import Any
from foreign import External
class Direct:
    def __call__(self) -> int: return 1
class Base:
    def __call__(self) -> int: return 2
class Child(Base): pass
class ExternalChild(External): pass
class Proxy:
    def __call__(self) -> int: return 3
class Meta(type):
    def __call__(cls) -> Proxy: return Proxy()
class CustomMeta(metaclass=Meta):
    def __call__(self) -> int: return 4
class CustomNew:
    def __new__(cls) -> Any: return Proxy()
    def __call__(self) -> int: return 5
class CustomInit:
    def __init__(self, value: object) -> None: pass
    def __call__(self) -> int: return 6
class HookBase:
    def __init_subclass__(cls) -> None: pass
class HookChild(HookBase):
    def __call__(self) -> int: return 7
class StaticCall:
    @staticmethod
    def __call__() -> int: return 8
class ClassCall:
    @classmethod
    def __call__(cls) -> int: return 9
class PropertyCall:
    @property
    def __call__(self) -> object: return object()
class ShadowCall(Base):
    __call__: Any = object()
def decorate(cls: Any) -> Any: return cls
@decorate
class Decorated:
    def __call__(self) -> int: return 10
"""


@pytest.fixture(scope="module")
def parsed_construction_guard() -> tuple[MypyAnalyzer, dict[str, TypeInfo]]:
    options = Options()
    options.incremental = False
    options.cache_dir = os.devnull
    options.preserve_asts = True
    options.export_types = True
    result = build(
        sources=[
            BuildSource(f"{_PROJECT}/main.py", "main", _SOURCE),
            BuildSource(
                "/__callable_construction_guard__/dependency/foreign.py",
                "foreign",
                "class External:\n    def __call__(self) -> int: return 0\n",
            ),
        ],
        options=options,
    )
    tree = result.graph["main"].tree
    assert tree is not None
    classes = {
        name: symbol.node
        for name, symbol in tree.names.items()
        if isinstance(symbol.node, TypeInfo) and symbol.node.module_name == "main"
    }
    analyzer = object.__new__(MypyAnalyzer)
    analyzer.source_root = Path(_PROJECT)
    analyzer._project_modules = {"main"}
    analyzer._exact_project_identity_cache = {}
    analyzer._fullname_resolution_cache = {}
    analyzer._module_to_path = {"main": f"{_PROJECT}/main.py"}
    analyzer._trees = {
        module: state.tree for module, state in result.graph.items() if state.tree is not None
    }
    analyzer._build_result = result
    return analyzer, classes


@pytest.mark.parametrize(
    ("class_name", "expected"),
    [
        ("Direct", "main.Direct.__call__"),
        ("Child", "main.Base.__call__"),
        ("ExternalChild", None),
        ("CustomMeta", None),
        ("CustomNew", None),
        ("CustomInit", None),
        ("HookChild", None),
        ("StaticCall", None),
        ("ClassCall", None),
        ("PropertyCall", None),
        ("ShadowCall", None),
        ("Decorated", None),
    ],
)
def test_actual_mro_and_construction_hooks(
    parsed_construction_guard: tuple[MypyAnalyzer, dict[str, TypeInfo]],
    class_name: str,
    expected: str | None,
) -> None:
    analyzer, classes = parsed_construction_guard
    constructor = CallExpr(NameExpr(class_name), [], [], [])
    declaration = analyzer._constructed_project_callable(classes[class_name], constructor)
    assert (declaration[0] if declaration else None) == expected


@pytest.mark.parametrize("kind", [ARG_POS, ARG_NAMED])
def test_constructor_actuals_are_not_default_allocation_proof(
    parsed_construction_guard: tuple[MypyAnalyzer, dict[str, TypeInfo]], kind: object
) -> None:
    analyzer, classes = parsed_construction_guard
    constructor = CallExpr(
        NameExpr("Direct"), [StrExpr("argument")], [kind], [None if kind == ARG_POS else "value"]
    )
    assert analyzer._constructed_project_callable(classes["Direct"], constructor) is None


def test_external_file_cannot_become_project_owned_by_symbol_prefix(
    parsed_construction_guard: tuple[MypyAnalyzer, dict[str, TypeInfo]],
) -> None:
    analyzer, classes = parsed_construction_guard
    old_path = analyzer._module_to_path["main"]
    try:
        analyzer._module_to_path["main"] = "/__callable_construction_guard__/dependency/main.py"
        analyzer._fullname_resolution_cache.clear()
        assert (
            analyzer._constructed_project_callable(
                classes["Direct"], CallExpr(NameExpr("Direct"), [], [], [])
            )
            is None
        )
    finally:
        analyzer._module_to_path["main"] = old_path
        analyzer._fullname_resolution_cache.clear()


def test_cached_abstention_records_each_endpoint_and_keeps_call_span() -> None:
    analyzer = object.__new__(MypyAnalyzer)
    site = ResolvedCallSite(
        file_path=f"{_PROJECT}/main.py",
        line=12,
        column=4,
        end_line=12,
        end_column=16,
        source_spelling="CustomMeta()",
        status=CallResolutionStatus.UNRESOLVED,
        resolver="mypy",
        resolver_version="test",
        reason_code="unproven_callable_construction",
    )
    call = object()
    analyzer._resolved_call_site_cache = {id(call): site}
    for _endpoint in range(2):
        captured = []
        analyzer._active_endpoint_dependencies = SimpleNamespace(
            add_analysis_limitation=captured.append
        )
        assert analyzer._resolved_call_site(call, site.file_path, {}) is site
        assert len(captured) == 1
        assert captured[0].cap == "UNPROVEN_CALLABLE_CONSTRUCTION"
        assert captured[0].file_path == site.file_path
        assert captured[0].call_line == site.line
        assert captured[0].call_column == site.column


def test_cached_missing_site_remains_missing() -> None:
    analyzer = object.__new__(MypyAnalyzer)
    call = object()
    analyzer._resolved_call_site_cache = {id(call): None}
    captured = []
    analyzer._active_endpoint_dependencies = SimpleNamespace(
        add_analysis_limitation=captured.append
    )
    assert analyzer._resolved_call_site(call, f"{_PROJECT}/main.py", {}) is None
    assert captured == []
