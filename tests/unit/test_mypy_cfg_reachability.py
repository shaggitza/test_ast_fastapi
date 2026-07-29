"""Bounded reachability controls for mypy dependency traversal."""

from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.models.endpoint import (
    DependencyGraphStatus,
    Endpoint,
    EndpointMethod,
    HandlerInfo,
)


def _dependencies(
    tmp_path: Path,
    handler_source: str,
    *,
    async_handler: bool = False,
    module_source: str = "",
    max_depth: int = 5,
):
    (tmp_path / "worker.py").write_text(
        "def changed() -> int:\n    return 1\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    prefix = "async " if async_handler else ""
    main.write_text(
        f"from worker import changed\n{module_source}\n{prefix}def handler():\n{handler_source}",
        encoding="utf-8",
    )
    endpoint = Endpoint(
        path="/items",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="handler",
            module="main",
            file_path=main,
            line_number=3 + bool(module_source),
        ),
    )
    return MypyAnalyzer(tmp_path, max_depth=max_depth).analyze_endpoint(endpoint)


@pytest.mark.parametrize(
    "handler_source",
    [
        "    if False:\n        changed()\n    return 1\n",
        "    while False:\n        changed()\n    return 1\n",
        "    False and changed()\n    return 1\n",
        "    changed() if False else None\n    return 1\n",
        "    return 1\n    changed()\n",
        "    raise RuntimeError\n    changed()\n",
    ],
)
def test_literal_dead_and_post_terminal_calls_are_not_reachable(
    tmp_path: Path,
    handler_source: str,
) -> None:
    dependencies = _dependencies(tmp_path, handler_source)

    assert dependencies.references_symbol_at_line("worker.py", 1) is None


@pytest.mark.parametrize(
    "handler_source",
    [
        "    if True:\n        changed()\n    return 1\n",
        "    flag = object()\n    if flag:\n        changed()\n    return 1\n",
        "    True and changed()\n    return 1\n",
        "    changed() if True else None\n    return 1\n",
    ],
)
def test_equivalent_live_and_unknown_paths_remain_reachable(
    tmp_path: Path,
    handler_source: str,
) -> None:
    dependencies = _dependencies(tmp_path, handler_source)

    assert dependencies.references_symbol_at_line("worker.py", 1) is not None
    assert not dependencies.references_lines_low_only("worker.py", {1})


def test_uncalled_nested_function_body_is_deferred(tmp_path: Path) -> None:
    dependencies = _dependencies(
        tmp_path,
        "    def nested():\n        return changed()\n    return 1\n",
    )

    assert dependencies.references_symbol_at_line("worker.py", 1) is None


def test_nested_function_defaults_execute_at_definition(tmp_path: Path) -> None:
    dependencies = _dependencies(
        tmp_path,
        "    def nested(value=changed()):\n        return value\n    return 1\n",
    )

    assert dependencies.references_symbol_at_line("worker.py", 1) is not None


def test_exactly_invoked_nested_function_body_is_reachable(tmp_path: Path) -> None:
    dependencies = _dependencies(
        tmp_path,
        "    def nested():\n        return changed()\n    return nested()\n",
    )

    assert dependencies.references_symbol_at_line("worker.py", 1) is not None
    assert any(
        any("nested" in frame.function_name for frame in stack)
        for stack in dependencies.get_call_stack("worker.py")
    )


def test_uncalled_lambda_body_is_deferred(tmp_path: Path) -> None:
    dependencies = _dependencies(
        tmp_path,
        "    callback = lambda: changed()\n    return 1\n",
    )

    assert dependencies.references_symbol_at_line("worker.py", 1) is None


def test_unawaited_coroutine_body_is_low_only(tmp_path: Path) -> None:
    (tmp_path / "callbacks.py").write_text(
        "from worker import changed\n\nasync def deferred() -> int:\n    return changed()\n",
        encoding="utf-8",
    )
    dependencies = _dependencies(
        tmp_path,
        "    deferred()\n    return 1\n",
        async_handler=True,
        module_source="from callbacks import deferred",
    )

    assert dependencies.references_symbol_at_line("worker.py", 1) is not None
    assert dependencies.references_lines_low_only("worker.py", {1})
    assert any(
        any("deferred_coroutine_creation" in frame.code_context for frame in stack)
        for stack in dependencies.get_call_stack("worker.py")
    )


def test_awaited_coroutine_body_is_established(tmp_path: Path) -> None:
    (tmp_path / "callbacks.py").write_text(
        "from worker import changed\n\nasync def deferred() -> int:\n    return changed()\n",
        encoding="utf-8",
    )
    dependencies = _dependencies(
        tmp_path,
        "    return await deferred()\n",
        async_handler=True,
        module_source="from callbacks import deferred",
    )

    assert dependencies.references_symbol_at_line("worker.py", 1) is not None
    assert not dependencies.references_lines_low_only("worker.py", {1})


def test_unawaited_local_coroutine_body_is_low_only(tmp_path: Path) -> None:
    dependencies = _dependencies(
        tmp_path,
        (
            "    async def deferred() -> int:\n"
            "        return changed()\n"
            "    deferred()\n"
            "    return 1\n"
        ),
        async_handler=True,
    )

    assert dependencies.references_symbol_at_line("worker.py", 1) is not None
    assert dependencies.references_lines_low_only("worker.py", {1})
    assert any(
        any("deferred_coroutine_creation" in frame.code_context for frame in stack)
        for stack in dependencies.get_call_stack("worker.py")
    )


def test_awaited_local_coroutine_body_is_established(tmp_path: Path) -> None:
    dependencies = _dependencies(
        tmp_path,
        (
            "    async def deferred() -> int:\n"
            "        return changed()\n"
            "    return await deferred()\n"
        ),
        async_handler=True,
    )

    assert dependencies.references_symbol_at_line("worker.py", 1) is not None
    assert not dependencies.references_lines_low_only("worker.py", {1})


def test_unawaited_local_coroutine_shares_edge_cap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(MypyAnalyzer, "MAX_POINTS_TO_EDGES", 0)

    dependencies = _dependencies(
        tmp_path,
        (
            "    async def deferred() -> int:\n"
            "        return changed()\n"
            "    deferred()\n"
            "    return 1\n"
        ),
        async_handler=True,
    )

    assert dependencies.references_symbol_at_line("worker.py", 1) is None
    assert dependencies.status == DependencyGraphStatus.CONDITIONAL
    assert [item.code for item in dependencies.limitations] == [
        "points_to_edge_cap_exhausted"
    ]


@pytest.mark.parametrize(
    "handler_source",
    [
        (
            "    flag = object()\n"
            "    if flag:\n"
            "        return 1\n"
            "    else:\n"
            "        raise RuntimeError\n"
            "    changed()\n"
        ),
        "    try:\n        return 1\n    finally:\n        pass\n    changed()\n",
        "    while True:\n        pass\n    changed()\n",
        (
            "    for item in (1,):\n"
            "        continue\n"
            "    else:\n"
            "        return 1\n"
            "    changed()\n"
        ),
    ],
)
def test_compound_terminal_paths_suppress_following_calls(
    tmp_path: Path,
    handler_source: str,
) -> None:
    dependencies = _dependencies(tmp_path, handler_source)

    assert dependencies.references_symbol_at_line("worker.py", 1) is None


@pytest.mark.parametrize(
    "handler_source",
    [
        "    while False:\n        pass\n    else:\n        changed()\n",
        "    for item in ():\n        pass\n    else:\n        changed()\n",
        (
            "    for item in (1,):\n"
            "        break\n"
            "    else:\n"
            "        return 1\n"
            "    changed()\n"
        ),
        (
            "    while True:\n"
            "        if object():\n"
            "            break\n"
            "    changed()\n"
        ),
    ],
)
def test_loop_else_and_reachable_break_paths_remain_live(
    tmp_path: Path,
    handler_source: str,
) -> None:
    dependencies = _dependencies(tmp_path, handler_source)

    assert dependencies.references_symbol_at_line("worker.py", 1) is not None


@pytest.mark.parametrize(
    "handler_source",
    [
        "    callback = lambda: changed()\n    return callback()\n",
        "    return (lambda: changed())()\n",
    ],
)
def test_exactly_invoked_lambda_body_is_reachable(
    tmp_path: Path,
    handler_source: str,
) -> None:
    dependencies = _dependencies(tmp_path, handler_source)

    assert dependencies.references_symbol_at_line("worker.py", 1) is not None


def test_local_lambda_join_retains_every_fallthrough_target(tmp_path: Path) -> None:
    dependencies = _dependencies(
        tmp_path,
        (
            "    callback = lambda: changed()\n"
            "    flag = object()\n"
            "    if flag:\n"
            "        callback = lambda: 0\n"
            "    return callback()\n"
        ),
    )

    assert dependencies.references_symbol_at_line("worker.py", 1) is not None


def test_local_lambda_join_discards_terminal_branch_target(tmp_path: Path) -> None:
    dependencies = _dependencies(
        tmp_path,
        (
            "    callback = lambda: 0\n"
            "    flag = object()\n"
            "    if flag:\n"
            "        callback = lambda: changed()\n"
            "        return 1\n"
            "    return callback()\n"
        ),
    )

    assert dependencies.references_symbol_at_line("worker.py", 1) is None


def test_local_callable_target_cap_is_explicit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(MypyAnalyzer, "MAX_LOCAL_CALLABLE_TARGETS", 1)

    dependencies = _dependencies(
        tmp_path,
        (
            "    callback = lambda: changed()\n"
            "    flag = object()\n"
            "    if flag:\n"
            "        callback = lambda: 0\n"
            "    return callback()\n"
        ),
    )

    assert dependencies.references_symbol_at_line("worker.py", 1) is None
    assert dependencies.status == DependencyGraphStatus.CONDITIONAL
    assert [item.code for item in dependencies.limitations] == [
        "local_callable_target_cap_exhausted"
    ]


def test_match_subject_guard_and_live_arm_are_traversed(tmp_path: Path) -> None:
    dependencies = _dependencies(
        tmp_path,
        (
            "    value = object()\n"
            "    match value:\n"
            "        case _ if False:\n"
            "            changed()\n"
            "        case _:\n"
            "            return changed()\n"
        ),
    )

    assert dependencies.references_symbol_at_line("worker.py", 1) is not None


def test_match_subject_and_guard_expressions_are_reachable(tmp_path: Path) -> None:
    dependencies = _dependencies(
        tmp_path,
        (
            "    match changed():\n"
            "        case _ if changed():\n"
            "            return 1\n"
            "        case _:\n"
            "            return 2\n"
        ),
    )

    assert dependencies.references_symbol_at_line("worker.py", 1) is not None


def test_literal_false_match_guard_keeps_arm_body_dead(tmp_path: Path) -> None:
    dependencies = _dependencies(
        tmp_path,
        (
            "    value = object()\n"
            "    match value:\n"
            "        case _ if False:\n"
            "            changed()\n"
            "        case _:\n"
            "            return 1\n"
        ),
    )

    assert dependencies.references_symbol_at_line("worker.py", 1) is None


def test_depth_cap_emits_one_persisted_limitation(tmp_path: Path) -> None:
    (tmp_path / "chain.py").write_text(
        "from worker import changed\n\ndef first() -> int:\n    return changed()\n",
        encoding="utf-8",
    )
    (tmp_path / "worker.py").write_text(
        "def changed() -> int:\n    return 1\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from chain import first\n\ndef handler():\n    return first()\n",
        encoding="utf-8",
    )
    endpoint = Endpoint(
        path="/items",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="handler",
            module="main",
            file_path=main,
            line_number=3,
        ),
    )

    analyzer = MypyAnalyzer(tmp_path, max_depth=1)
    analyzer.analyze_endpoints([endpoint], use_cache=True)
    dependencies = analyzer.get_endpoint_dependencies(endpoint)
    cached_analyzer = MypyAnalyzer(tmp_path, max_depth=1)
    cached_analyzer.analyze_endpoints([endpoint], use_cache=True)
    loaded = cached_analyzer.get_endpoint_dependencies(endpoint)

    assert dependencies is not None
    assert loaded is not None
    assert dependencies.status == DependencyGraphStatus.CONDITIONAL
    assert [item.code for item in dependencies.limitations] == [
        "analysis_depth_exhausted"
    ]
    assert loaded.status == dependencies.status
    assert loaded.limitations == dependencies.limitations
    assert dependencies.references_symbol_at_line("worker.py", 1) is None


def test_points_to_edge_cap_emits_deduplicated_limitation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "callbacks.py").write_text(
        "from worker import changed\n\nasync def deferred() -> int:\n    return changed()\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(MypyAnalyzer, "MAX_POINTS_TO_EDGES", 0)

    dependencies = _dependencies(
        tmp_path,
        "    deferred()\n    deferred()\n    return 1\n",
        async_handler=True,
        module_source="from callbacks import deferred",
    )

    assert dependencies.status == DependencyGraphStatus.CONDITIONAL
    assert [item.code for item in dependencies.limitations] == [
        "points_to_edge_cap_exhausted"
    ]
    assert dependencies.references_symbol_at_line("worker.py", 1) is None
