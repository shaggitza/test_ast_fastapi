"""Exact framework callback and dependency execution summaries."""

from pathlib import Path

from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo


def _endpoint(main: Path, *, line: int) -> Endpoint:
    return Endpoint(
        path="/framework",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="handler",
            module="main",
            file_path=main,
            line_number=line,
        ),
    )


def test_background_task_binds_finite_arguments_at_low(tmp_path: Path) -> None:
    (tmp_path / "services.py").write_text(
        "class Service:\n"
        "    def changed(self) -> int:\n"
        "        return 1\n\n"
        "class Other:\n"
        "    def changed(self) -> int:\n"
        "        return 2\n",
        encoding="utf-8",
    )
    (tmp_path / "callbacks.py").write_text(
        "def dispatch(service) -> int:\n    return service.changed()\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from fastapi import BackgroundTasks\n"
        "from callbacks import dispatch\n"
        "from services import Service\n\n"
        "def handler(tasks: BackgroundTasks) -> int:\n"
        "    tasks.add_task(dispatch, Service())\n"
        "    return 1\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, line=5))

    assert deps.references_symbol_at_line("services.py", 2) is not None
    assert deps.references_symbol_at_line("services.py", 6) is None
    assert deps.references_lines_low_only("services.py", {2})
    assert any(
        any("background_task_callback:" in frame.code_context for frame in stack)
        for stack in deps.get_call_stack("services.py")
    )


def test_background_task_executes_exact_async_callback(tmp_path: Path) -> None:
    (tmp_path / "worker.py").write_text(
        "def changed() -> int:\n    return 1\n",
        encoding="utf-8",
    )
    (tmp_path / "callbacks.py").write_text(
        "from worker import changed\n\nasync def dispatch() -> int:\n    return changed()\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from fastapi import BackgroundTasks\n"
        "from callbacks import dispatch\n\n"
        "def handler(tasks: BackgroundTasks) -> int:\n"
        "    tasks.add_task(func=dispatch)\n"
        "    return 1\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, line=4))

    assert deps.references_symbol_at_line("worker.py", 1) is not None
    assert deps.references_lines_low_only("worker.py", {1})


def test_background_task_rejects_generator_callback(tmp_path: Path) -> None:
    (tmp_path / "worker.py").write_text(
        "def changed() -> int:\n    return 1\n",
        encoding="utf-8",
    )
    (tmp_path / "callbacks.py").write_text(
        "from worker import changed\n\ndef deferred():\n    yield changed()\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from fastapi import BackgroundTasks\n"
        "from callbacks import deferred\n\n"
        "def handler(tasks: BackgroundTasks) -> int:\n"
        "    tasks.add_task(deferred)\n"
        "    return 1\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, line=4))

    assert deps.references_symbol_at_line("worker.py", 1) is None
    assert deps.references_symbol_at_line("callbacks.py", 3) is None


def test_same_named_user_add_task_never_receives_framework_summary(tmp_path: Path) -> None:
    (tmp_path / "worker.py").write_text(
        "def changed() -> int:\n    return 1\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from worker import changed\n\n"
        "class Tasks:\n"
        "    def add_task(self, callback):\n"
        "        return None\n\n"
        "def handler(tasks: Tasks) -> int:\n"
        "    tasks.add_task(changed)\n"
        "    return 1\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, line=7))

    assert deps.references_symbol_at_line("worker.py", 1) is None


def test_fastapi_dependency_has_exact_boundary_provenance(tmp_path: Path) -> None:
    (tmp_path / "dependency.py").write_text(
        "def changed() -> int:\n    return 1\n\ndef provide() -> int:\n    return changed()\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from fastapi import Depends\n"
        "from dependency import provide\n\n"
        "def handler(value: int = Depends(provide)) -> int:\n"
        "    return value\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, line=4))

    assert deps.references_symbol_at_line("dependency.py", 1) is not None
    assert not deps.references_lines_low_only("dependency.py", {1})
    assert any(
        any("fastapi_dependency:" in frame.code_context for frame in stack)
        for stack in deps.get_call_stack("dependency.py")
    )


def test_same_named_user_depends_does_not_execute_argument(tmp_path: Path) -> None:
    (tmp_path / "worker.py").write_text(
        "def changed() -> int:\n    return 1\n\ndef provide() -> int:\n    return changed()\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from worker import provide\n\n"
        "def Depends(callback):\n"
        "    return 0\n\n"
        "def handler(value=Depends(provide)) -> int:\n"
        "    return value\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, line=6))

    assert deps.references_symbol_at_line("worker.py", 1) is None


def test_background_task_summary_round_trips_cache(tmp_path: Path) -> None:
    (tmp_path / "worker.py").write_text(
        "def changed() -> int:\n    return 1\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from fastapi import BackgroundTasks\n"
        "from worker import changed\n\n"
        "def handler(tasks: BackgroundTasks) -> int:\n"
        "    tasks.add_task(changed)\n"
        "    return 1\n",
        encoding="utf-8",
    )
    endpoint = _endpoint(main, line=4)
    cache = tmp_path / "cache.json"
    writer = MypyAnalyzer(tmp_path, max_depth=5)
    writer.set_cache_path(cache)
    expected = writer.analyze_endpoints([endpoint], use_cache=True)[writer._endpoint_key(endpoint)]

    reader = MypyAnalyzer(tmp_path, max_depth=5)
    reader.set_cache_path(cache)
    actual = reader.analyze_endpoints([endpoint], use_cache=True)[reader._endpoint_key(endpoint)]

    assert expected.references_lines_low_only("worker.py", {1})
    assert actual.references_lines_low_only("worker.py", {1})
    assert actual.call_stacks == expected.call_stacks
