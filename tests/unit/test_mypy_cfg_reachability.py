"""Bounded reachability controls for mypy dependency traversal."""

from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo


def _dependencies(
    tmp_path: Path,
    handler_source: str,
    *,
    async_handler: bool = False,
    module_source: str = "",
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
    return MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(endpoint)


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
