from __future__ import annotations

import ast
from typing import TYPE_CHECKING

import pytest
from mypy.nodes import (
    ARG_POS,
    Block,
    CallExpr,
    DictExpr,
    IntExpr,
    LambdaExpr,
    ListExpr,
    MemberExpr,
    NameExpr,
    StrExpr,
    TupleExpr,
)

from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.models.effect_contract import CallResolutionStatus
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo

if TYPE_CHECKING:
    from pathlib import Path


def _endpoint(path: Path, line: int) -> Endpoint:
    return Endpoint(
        path="/test",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(name="handler", module=path.stem, file_path=path, line_number=line),
    )


@pytest.mark.parametrize(
    "exposure",
    [
        "mutate(bound)",
        "mutate(alias)",
        "alias2 = alias\n    mutate(alias2)",
        "mutate([bound])",
        "mutate({'callback': alias})",
        "mutate(((bound,),))",
        "mutate(bound.keywords)",
        "bound.keywords.update({'callback': second})",
    ],
)
def test_exposed_partial_invalidates_all_aliases_and_retains_unrelated_partial(
    tmp_path: Path, exposure: str
) -> None:
    (tmp_path / "effects.py").write_text(
        "from collections.abc import Callable\n"
        "from typing import Any\n"
        "def first() -> None: pass\n"
        "def second() -> None: pass\n"
        "def run(callback: Callable[[], None]) -> None:\n"
        "    callback()\n"
        "def mutate(value: Any) -> None:\n"
        "    while isinstance(value, (list, tuple)): value = value[0]\n"
        "    if isinstance(value, dict):\n"
        "        if hasattr(value.get('callback'), 'keywords'):\n"
        "            value['callback'].keywords['callback'] = second\n"
        "        else:\n"
        "            value['callback'] = second\n"
        "    else:\n"
        "        value.keywords['callback'] = second\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from functools import partial\n"
        "from effects import first, second, run, mutate\n"
        "def handler() -> None:\n"
        "    bound = partial(run, callback=first)\n"
        "    alias = bound\n"
        "    other = partial(run, callback=second)\n"
        f"    {exposure}\n"
        "    alias()\n"
        "    other()\n",
        encoding="utf-8",
    )
    parsed = ast.parse(main.read_text(encoding="utf-8"))
    declaration = next(node for node in parsed.body if isinstance(node, ast.FunctionDef))
    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, declaration.lineno))
    sites = deps.get_resolved_call_sites(str(main))
    alias_line = declaration.body[-2].lineno
    other_line = declaration.body[-1].lineno
    alias_sites = [site for site in sites if site.line == alias_line]
    assert alias_sites and all(site.status != CallResolutionStatus.EXACT for site in alias_sites)
    other_sites = [site for site in sites if site.line == other_line]
    assert any(
        site.status == CallResolutionStatus.EXACT
        and site.canonical_symbol is not None
        and site.canonical_symbol.endswith(".run")
        for site in other_sites
    )


def test_reassigned_name_does_not_expose_old_partial_alias(tmp_path: Path) -> None:
    (tmp_path / "effects.py").write_text(
        "from collections.abc import Callable\n"
        "def first() -> None: pass\n"
        "def run(callback: Callable[[], None]) -> None: callback()\n"
        "def mutate(value: object) -> None: pass\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from functools import partial\n"
        "from typing import Any\n"
        "from effects import first, run, mutate\n"
        "def handler() -> None:\n"
        "    bound: Any = partial(run, callback=first)\n"
        "    alias = bound\n"
        "    bound = object()\n"
        "    mutate(bound)\n"
        "    alias()\n",
        encoding="utf-8",
    )
    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, 4))
    sites = deps.get_resolved_call_sites(str(main))
    assert any(
        site.line == 9
        and site.status == CallResolutionStatus.EXACT
        and site.canonical_symbol is not None
        and site.canonical_symbol.endswith(".run")
        for site in sites
    )


def test_exposure_roots_are_bounded_and_do_not_enter_callable_bodies() -> None:
    root = NameExpr("bound")
    nested = DictExpr([(StrExpr("cb"), ListExpr([TupleExpr([root])]))])
    names, complete = MypyAnalyzer._exposed_partial_names(nested)
    assert complete and names == {"bound"}
    receiver = MemberExpr(MemberExpr(root, "keywords"), "update")
    call = CallExpr(receiver, [IntExpr(1)], [ARG_POS], [None])
    names, complete = MypyAnalyzer._exposed_partial_names(call)
    assert complete and names == {"bound"}
    names, complete = MypyAnalyzer._exposed_partial_names(ListExpr([root] * 20), max_nodes=4)
    assert not complete
    opaque = LambdaExpr([], Block([]))
    _names, complete = MypyAnalyzer._exposed_partial_names(opaque)
    assert not complete
