"""Structured loop exits preserve continuation aliases and finalizer control."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.mypy_analyzer import EndpointDependencies, MypyAnalyzer
from fastapi_endpoint_detector.models.effect_contract import CallResolutionStatus, ResolvedCallSite
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo


def _analyze(tmp_path: Path, body: str) -> tuple[Path, EndpointDependencies]:
    (tmp_path / "helpers.py").write_text(
        "from collections.abc import Callable\n\n"
        "def first() -> int:\n    return 1\n\n"
        "def second() -> int:\n    return 2\n\n"
        "def third() -> int:\n    return 3\n\n"
        "def invoke(callback: Callable[[], int]) -> int:\n    return callback()\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from functools import partial\n"
        "from helpers import first, second, third, invoke\n\n"
        "def handler(flag: bool = False, stop: bool = False, values: tuple[int, ...] = ()):\n"
        + "\n".join("    " + line if line else "" for line in body.splitlines())
        + "\n",
        encoding="utf-8",
    )
    handler = next(
        node
        for node in ast.parse(main.read_text(encoding="utf-8")).body
        if isinstance(node, ast.FunctionDef) and node.name == "handler"
    )
    endpoint = Endpoint(
        path="/test",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="handler",
            module="main",
            file_path=main,
            line_number=handler.lineno,
            end_line_number=handler.end_lineno,
        ),
    )
    return main, MypyAnalyzer(tmp_path, module_root=tmp_path).analyze_endpoint(endpoint)


def _sites_at_last_call(
    deps: EndpointDependencies,
    main: Path,
    spelling: str = "callback",
) -> list[ResolvedCallSite]:
    calls = [
        node
        for node in ast.walk(ast.parse(main.read_text(encoding="utf-8")))
        if isinstance(node, ast.Call) and ast.unparse(node.func) == spelling
    ]
    assert calls
    line = max(node.lineno for node in calls)
    return [
        site
        for site in deps.resolved_call_sites
        if Path(site.file_path).resolve() == main.resolve()
        and site.line == line
        and site.source_spelling == spelling
    ]


def _exact_targets(sites: list[ResolvedCallSite]) -> set[str | None]:
    return {site.canonical_symbol for site in sites if site.status == CallResolutionStatus.EXACT}


def _assert_possible_targets(
    deps: EndpointDependencies,
    tmp_path: Path,
    *names: str,
) -> None:
    helpers = tmp_path / "helpers.py"
    definitions = {
        node.name: node
        for node in ast.parse(helpers.read_text(encoding="utf-8")).body
        if isinstance(node, ast.FunctionDef)
    }
    for name in names:
        line = definitions[name].body[0].lineno
        assert deps.references_lines(str(helpers), {line}) == {line}
        assert deps.references_lines_low_only(str(helpers), {line})


@pytest.mark.parametrize(
    "loop",
    (
        "for item in values:\n    if flag:\n        callback = second\n        break",
        "for item in values:\n    if flag:\n        callback = second\n        continue",
        "while flag:\n    callback = second\n"
        "    if stop:\n        break\n"
        "    flag = False\n    continue",
    ),
    ids=("for-break", "for-continue", "while-break-and-continue"),
)
def test_conditional_loop_exit_keeps_all_possible_targets(tmp_path: Path, loop: str) -> None:
    main, deps = _analyze(tmp_path, "callback = first\n" + loop + "\ncallback()")
    assert _sites_at_last_call(deps, main)
    assert not _exact_targets(_sites_at_last_call(deps, main))
    _assert_possible_targets(deps, tmp_path, "first", "second")


@pytest.mark.parametrize("header", ("for item in values:", "while flag:"))
def test_break_bypasses_loop_else(tmp_path: Path, header: str) -> None:
    main, deps = _analyze(
        tmp_path,
        "callback = first\n" + header + "\n"
        "    callback = second\n"
        "    break\n"
        "else:\n    callback = third\n"
        "callback()",
    )
    assert not _exact_targets(_sites_at_last_call(deps, main))
    _assert_possible_targets(deps, tmp_path, "second", "third")


@pytest.mark.parametrize("header", ("for item in ():", "while False:"))
def test_proven_zero_trip_runs_only_else(tmp_path: Path, header: str) -> None:
    main, deps = _analyze(
        tmp_path,
        "callback = first\n" + header + "\n"
        "    callback = second\n"
        "else:\n    callback = third\n"
        "callback()",
    )
    assert _exact_targets(_sites_at_last_call(deps, main)) == {"helpers.third"}
    second_line = 7
    assert not deps.references_lines(str(tmp_path / "helpers.py"), {second_line})


def test_return_from_body_does_not_join_into_for_continuation(tmp_path: Path) -> None:
    main, deps = _analyze(
        tmp_path,
        "callback = first\nfor item in values:\n    callback = second\n    return 0\ncallback()",
    )
    assert _exact_targets(_sites_at_last_call(deps, main)) == {"helpers.first"}
    assert not deps.references_lines(str(tmp_path / "helpers.py"), {7})


def test_literal_true_break_establishes_only_break_target(tmp_path: Path) -> None:
    main, deps = _analyze(
        tmp_path,
        "callback = first\n"
        "while True:\n    callback = second\n    break\n"
        "else:\n    callback = third\n"
        "callback()",
    )
    assert _exact_targets(_sites_at_last_call(deps, main)) == {"helpers.second"}
    assert not deps.references_lines(str(tmp_path / "helpers.py"), {10})


def test_inner_break_does_not_exit_outer_body(tmp_path: Path) -> None:
    main, deps = _analyze(
        tmp_path,
        "callback = first\n"
        "while True:\n"
        "    while True:\n        callback = second\n        break\n"
        "    callback = third\n"
        "    break\n"
        "callback()",
    )
    assert _exact_targets(_sites_at_last_call(deps, main)) == {"helpers.third"}


def test_inner_loop_else_break_targets_outer_loop(tmp_path: Path) -> None:
    main, deps = _analyze(
        tmp_path,
        "callback = first\n"
        "while True:\n"
        "    for item in ():\n        pass\n"
        "    else:\n        callback = second\n        break\n"
        "    callback = third\n"
        "callback()",
    )
    assert _exact_targets(_sites_at_last_call(deps, main)) == {"helpers.second"}
    assert not deps.references_lines(str(tmp_path / "helpers.py"), {10})


def test_finally_return_overrides_pending_break(tmp_path: Path) -> None:
    main, deps = _analyze(
        tmp_path,
        "callback = first\n"
        "while True:\n"
        "    try:\n        break\n"
        "    finally:\n        return 0\n"
        "callback()",
    )
    assert not _sites_at_last_call(deps, main)


@pytest.mark.parametrize("exit_statement", ("break", "continue"))
def test_finally_loop_exit_overrides_return(tmp_path: Path, exit_statement: str) -> None:
    main, deps = _analyze(
        tmp_path,
        "callback = first\n"
        "while flag:\n"
        "    try:\n        return 0\n"
        "    finally:\n        " + exit_statement + "\n"
        "callback()",
    )
    assert _exact_targets(_sites_at_last_call(deps, main)) == {"helpers.first"}


def test_finally_preserves_untouched_break_alias(tmp_path: Path) -> None:
    main, deps = _analyze(
        tmp_path,
        "callback = first\n"
        "while True:\n"
        "    try:\n        break\n"
        "    finally:\n        marker = 1\n"
        "callback()",
    )
    assert _exact_targets(_sites_at_last_call(deps, main)) == {"helpers.first"}


def test_finally_rebinding_abstains_on_break_with_limit(tmp_path: Path) -> None:
    main, deps = _analyze(
        tmp_path,
        "callback = first\n"
        "for item in values:\n"
        "    try:\n        callback = second\n        break\n"
        "    finally:\n        callback = third\n"
        "callback()",
    )
    assert _sites_at_last_call(deps, main)
    assert not _exact_targets(_sites_at_last_call(deps, main))
    assert deps.analysis_incomplete
    assert any(item.cap == "UNKNOWN_FINALLY_EXIT_BINDING" for item in deps.analysis_limitations)


def test_exception_binder_deleted_on_handler_break(tmp_path: Path) -> None:
    main, deps = _analyze(
        tmp_path,
        "callback = first\n"
        "while True:\n"
        "    try:\n        raise RuntimeError\n"
        "    except Exception as callback:\n        break\n"
        "callback()",
    )
    assert _sites_at_last_call(deps, main)
    assert not _exact_targets(_sites_at_last_call(deps, main))


@pytest.mark.parametrize("binding", ("partial(invoke, callback=first)", "lambda: first()"))
def test_divergent_partial_or_lambda_loop_exits_are_capped(tmp_path: Path, binding: str) -> None:
    main, deps = _analyze(
        tmp_path,
        "callback = " + binding + "\n"
        "for item in values:\n"
        "    if flag:\n        callback = second\n        break\n"
        "callback()",
    )
    assert not _exact_targets(_sites_at_last_call(deps, main))
    assert deps.analysis_incomplete
    assert any(item.cap == "UNKNOWN_CONTROL_EXIT_BINDING" for item in deps.analysis_limitations)


def test_unmodeled_context_exit_does_not_preserve_exact_captured_alias(tmp_path: Path) -> None:
    main, deps = _analyze(
        tmp_path,
        "class Manager:\n"
        "    def __enter__(self):\n        return self\n"
        "    def __exit__(self, *args):\n"
        "        nonlocal callback\n        callback = second\n"
        "manager = Manager()\n"
        "callback = first\n"
        "with manager:\n    pass\n"
        "callback()",
    )
    assert not _exact_targets(_sites_at_last_call(deps, main))
    assert deps.analysis_incomplete
    assert any(item.cap == "UNKNOWN_CONTEXT_MANAGER_EXIT" for item in deps.analysis_limitations)


def test_finalizer_budget_does_not_resume_after_pending_break(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(MypyAnalyzer, "MAX_FINALLY_BODY_EVALUATIONS", 0)
    main, deps = _analyze(
        tmp_path,
        "callback = first\n"
        "while True:\n"
        "    try:\n        break\n"
        "    finally:\n        return 0\n"
        "    callback()\n"
        "callback()",
    )
    handler = next(
        node
        for node in ast.parse(main.read_text(encoding="utf-8")).body
        if isinstance(node, ast.FunctionDef) and node.name == "handler"
    )
    inside_line = handler.body[1].body[-1].lineno
    assert not any(
        site.source_spelling == "callback" and site.line == inside_line
        for site in deps.resolved_call_sites
    )
    assert not _exact_targets(_sites_at_last_call(deps, main))
    assert any(item.cap == "MAX_FINALLY_FLOW_ITERATIONS" for item in deps.analysis_limitations)


def test_loop_budget_marks_retained_prefix_possible_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(MypyAnalyzer, "MAX_LOOP_BODY_EVALUATIONS", 0)
    main, deps = _analyze(
        tmp_path,
        "callback = first\nfor item in values:\n    callback = second\n    continue\ncallback()",
    )
    assert not _exact_targets(_sites_at_last_call(deps, main))
    assert any(item.cap == "MAX_LOOP_FLOW_ITERATIONS" for item in deps.analysis_limitations)
