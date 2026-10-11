from __future__ import annotations

import ast
from typing import TYPE_CHECKING

import pytest
from mypy.nodes import ARG_NAMED, ARG_POS, ARG_STAR, ARG_STAR2

from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.models.effect_contract import CallResolutionStatus
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize(
    ("stored", "holes", "actual", "expected", "fixed", "slots"),
    [
        (
            ("hole", "hole", "first"),
            (0, 1),
            ("second", "third"),
            ("second", "third", "first"),
            (2,),
            (0, 1),
        ),
        (
            ("hole", "fixed", "hole"),
            (0, 2),
            ("x", "y", "z"),
            ("x", "fixed", "y", "z"),
            (1,),
            (0, 2, 3),
        ),
        (
            ("fixed", "hole", "tail"),
            (1,),
            ("fill", "extra"),
            ("fixed", "fill", "tail", "extra"),
            (0, 2),
            (1, 3),
        ),
        (("fixed",), (), ("extra",), ("fixed", "extra"), (0,), (1,)),
    ],
)
def test_partial_merge_fills_holes_before_appending_actuals(
    stored: tuple[str, ...],
    holes: tuple[int, ...],
    actual: tuple[str, ...],
    expected: tuple[str, ...],
    fixed: tuple[int, ...],
    slots: tuple[int, ...],
) -> None:
    result = MypyAnalyzer._merge_partial_invocation(
        stored,
        (ARG_POS,) * len(stored),
        (None,) * len(stored),
        holes,
        actual,
        (ARG_POS,) * len(actual),
        (None,) * len(actual),
        ("a", "b", "c", "d"),
    )
    assert result.reason is None
    assert result.args == expected
    assert result.fixed_positional_slots == fixed
    assert result.invocation_positional_slots == slots


def test_partial_merge_keyword_override_preserves_fixed_positional_slot() -> None:
    result = MypyAnalyzer._merge_partial_invocation(
        ("fixed", "old"),
        (ARG_POS, ARG_NAMED),
        (None, "mode"),
        (),
        ("new",),
        (ARG_NAMED,),
        ("mode",),
        ("first",),
    )
    assert result.reason is None
    assert result.args == ("fixed", "new")
    assert result.arg_names == (None, "mode")
    assert result.fixed_positional_slots == (0,)
    assert result.invocation_positional_slots == ()


@pytest.mark.parametrize(
    (
        "stored",
        "stored_kinds",
        "stored_names",
        "holes",
        "actual",
        "actual_kinds",
        "actual_names",
        "reason",
    ),
    [
        (
            ("hole", "hole"),
            (ARG_POS, ARG_POS),
            (None, None),
            (0, 1),
            ("fill",),
            (ARG_POS,),
            (None,),
            "UNFILLED_PARTIAL_PLACEHOLDERS",
        ),
        (("values",), (ARG_STAR,), (None,), (), (), (), (), "UNRESOLVED_PARTIAL_STAR_ARGUMENTS"),
        ((), (), (), (), ("values",), (ARG_STAR2,), (None,), "UNRESOLVED_PARTIAL_STAR_ARGUMENTS"),
        (
            ("old",),
            (ARG_NAMED,),
            ("a",),
            (),
            ("new",),
            (ARG_POS,),
            (None,),
            "INVALID_PARTIAL_ARGUMENTS",
        ),
        (
            ("fixed",),
            (ARG_POS,),
            (None,),
            (),
            ("new",),
            (ARG_NAMED,),
            ("a",),
            "INVALID_PARTIAL_ARGUMENTS",
        ),
        (
            ("hole",),
            (ARG_POS,),
            (None,),
            (-1,),
            ("fill",),
            (ARG_POS,),
            (None,),
            "INVALID_PARTIAL_PLACEHOLDER_MAP",
        ),
        (
            ("hole",),
            (ARG_POS,),
            (None,),
            (0, 0),
            ("x", "y"),
            (ARG_POS, ARG_POS),
            (None, None),
            "INVALID_PARTIAL_PLACEHOLDER_MAP",
        ),
        (("fixed",), (ARG_POS,), (), (), (), (), (), "PARTIAL_ARGUMENT_SHAPE_MISMATCH"),
        (
            ("fixed",) * 257,
            (ARG_POS,) * 257,
            (None,) * 257,
            (),
            (),
            (),
            (),
            "MAX_PARTIAL_ARGUMENTS",
        ),
    ],
)
def test_invalid_partial_merge_never_produces_effective_execution_args(
    stored: tuple[str, ...],
    stored_kinds: tuple[object, ...],
    stored_names: tuple[str | None, ...],
    holes: tuple[int, ...],
    actual: tuple[str, ...],
    actual_kinds: tuple[object, ...],
    actual_names: tuple[str | None, ...],
    reason: str,
) -> None:
    result = MypyAnalyzer._merge_partial_invocation(
        stored,
        stored_kinds,
        stored_names,
        holes,
        actual,
        actual_kinds,
        actual_names,
        ("a", "b", "c"),
    )
    assert result.reason == reason
    assert result.args == result.arg_kinds == result.arg_names == ()


@pytest.mark.parametrize(
    ("imports", "setup", "hole"),
    [
        ("from functools import partial, Placeholder as Hole\n", "", "Hole"),
        ("from functools import partial\nimport functools as ft\n", "", "ft.Placeholder"),
        ("from functools import partial, Placeholder as Hole\n", "    hole = Hole\n", "hole"),
    ],
)
def test_placeholder_fills_callback_slot_and_retains_creation_time_other_callback(
    tmp_path: Path, imports: str, setup: str, hole: str
) -> None:
    (tmp_path / "effects.py").write_text(
        "from collections.abc import Callable\n"
        "def first() -> None: pass\n"
        "def second() -> None: pass\n"
        "def run(callback: Callable[[], None], other: Callable[[], None]) -> None:\n"
        "    callback()\n"
        "    other()\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        imports + "from effects import first, second, run\n"
        "def handler() -> None:\n"
        "    fixed = first\n" + setup + f"    bound = partial(run, {hole}, fixed)\n"
        "    fixed = second\n"
        "    bound(second)\n",
        encoding="utf-8",
    )
    parsed = ast.parse(main.read_text(encoding="utf-8"))
    declaration = next(node for node in parsed.body if isinstance(node, ast.FunctionDef))
    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(
        Endpoint(
            path="/test",
            methods=[EndpointMethod.GET],
            handler=HandlerInfo(
                name="handler", module="main", file_path=main, line_number=declaration.lineno
            ),
        )
    )
    assert any(
        site.line == declaration.body[-1].lineno
        and site.status == CallResolutionStatus.EXACT
        and site.canonical_symbol is not None
        and site.canonical_symbol.endswith(".run")
        for site in deps.get_resolved_call_sites(str(main))
    )
    callback_sites = [
        site for site in deps.resolved_call_sites if site.source_spelling == "callback"
    ]
    other_sites = [site for site in deps.resolved_call_sites if site.source_spelling == "other"]
    assert any(
        site.canonical_symbol and site.canonical_symbol.endswith(".second")
        for site in callback_sites
    )
    assert any(
        site.canonical_symbol and site.canonical_symbol.endswith(".first") for site in other_sites
    )


@pytest.mark.parametrize(
    ("setup", "reason"),
    [
        (
            "    bound = partial(run, Hole, Hole)\n    bound(first)\n",
            "UNFILLED_PARTIAL_PLACEHOLDERS",
        ),
        (
            "    bound = partial(run, callback=Hole)\n    bound(first)\n",
            "INVALID_PARTIAL_PLACEHOLDER_KEYWORD",
        ),
        (
            "    values = [Hole, first]\n    bound = partial(run, *values)\n    bound(second)\n",
            "UNRESOLVED_PARTIAL_STAR_ARGUMENTS",
        ),
        (
            "    bound = partial(run, Hole, first)\n    values = [second]\n    bound(*values)\n",
            "UNRESOLVED_PARTIAL_STAR_ARGUMENTS",
        ),
        (
            "    hole = Hole\n"
            "    hole = object()\n"
            "    bound = partial(run, hole, first)\n"
            "    bound(second)\n",
            "UNRESOLVED_PARTIAL_PLACEHOLDER_ARGUMENTS",
        ),
        (
            "    Hole = object()\n    bound = partial(run, Hole, first)\n    bound(second)\n",
            "UNRESOLVED_PARTIAL_PLACEHOLDER_ARGUMENTS",
        ),
        (
            "    inner = partial(run, Hole, first)\n"
            "    bound = partial(inner, second)\n"
            "    bound()\n",
            "NESTED_PARTIAL_COMPOSITION_UNSUPPORTED",
        ),
    ],
)
def test_invalid_or_unsupported_placeholder_call_does_not_promote_wrapped_execution(
    tmp_path: Path, setup: str, reason: str
) -> None:
    (tmp_path / "effects.py").write_text(
        "from collections.abc import Callable\n"
        "def first() -> None: pass\n"
        "def second() -> None: pass\n"
        "def run(callback: Callable[[], None], other: Callable[[], None]) -> None:\n"
        "    callback()\n    other()\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from functools import partial, Placeholder as Hole\n"
        "from effects import first, second, run\n"
        "def handler() -> None:\n" + setup,
        encoding="utf-8",
    )
    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(
        Endpoint(
            path="/test",
            methods=[EndpointMethod.GET],
            handler=HandlerInfo(name="handler", module="main", file_path=main, line_number=3),
        )
    )
    final_line = len(main.read_text(encoding="utf-8").splitlines())
    assert any(item.cap == reason for item in deps.analysis_limitations)
    assert not any(
        site.line == final_line
        and site.status == CallResolutionStatus.EXACT
        and site.canonical_symbol is not None
        and site.canonical_symbol.endswith(".run")
        for site in deps.get_resolved_call_sites(str(main))
    )
