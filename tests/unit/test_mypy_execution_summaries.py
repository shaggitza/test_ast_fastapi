"""Exact LOW-only executor execution summaries."""

from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo


def _endpoint(main: Path, *, line: int = 3) -> Endpoint:
    return Endpoint(
        path="/executor",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="handler",
            module="main",
            file_path=main,
            line_number=line,
        ),
    )


@pytest.mark.parametrize(
    ("import_line", "expression"),
    [
        ("import asyncio", "asyncio.to_thread(changed)"),
        ("from anyio.to_thread import run_sync", "run_sync(changed)"),
        (
            "from starlette.concurrency import run_in_threadpool",
            "run_in_threadpool(changed)",
        ),
    ],
)
def test_awaited_executor_wrapper_reaches_exact_callback_at_low(
    tmp_path: Path,
    import_line: str,
    expression: str,
) -> None:
    worker = tmp_path / "worker.py"
    worker.write_text("def changed() -> int:\n    return 1\n", encoding="utf-8")
    main = tmp_path / "main.py"
    main.write_text(
        f"{import_line}\n"
        "from worker import changed\n\n"
        "async def handler() -> int:\n"
        f"    return await {expression}\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=4).analyze_endpoint(_endpoint(main, line=4))

    assert deps.references_symbol_at_line("worker.py", 1) is not None
    assert deps.references_lines_low_only("worker.py", {1})
    stacks = deps.get_call_stack("worker.py")
    assert any(
        any("executor_callback:" in frame.code_context for frame in stack) for stack in stacks
    )


def test_anyio_keyword_callback_is_not_confused_with_control_kwargs(tmp_path: Path) -> None:
    worker = tmp_path / "worker.py"
    worker.write_text("def changed() -> int:\n    return 1\n", encoding="utf-8")
    controls = tmp_path / "controls.py"
    controls.write_text(
        "def unrelated() -> bool:\n    return True\n\n"
        "def control() -> bool:\n    return unrelated()\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from anyio.to_thread import run_sync\n"
        "from controls import control\n"
        "from worker import changed\n\n"
        "async def handler() -> int:\n"
        "    return await run_sync(abandon_on_cancel=control, func=changed)\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=4).analyze_endpoint(_endpoint(main, line=5))

    assert deps.references_symbol_at_line("worker.py", 1) is not None
    assert deps.references_symbol_at_line("controls.py", 1) is None


def test_coroutine_callback_creation_does_not_execute_its_body(tmp_path: Path) -> None:
    worker = tmp_path / "worker.py"
    worker.write_text("def changed() -> int:\n    return 1\n", encoding="utf-8")
    callbacks = tmp_path / "callbacks.py"
    callbacks.write_text(
        "from worker import changed\n\nasync def deferred() -> int:\n    return changed()\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "import asyncio\n"
        "from callbacks import deferred\n\n"
        "async def handler():\n"
        "    return await asyncio.to_thread(deferred)\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=4).analyze_endpoint(_endpoint(main, line=4))

    assert deps.references_symbol_at_line("worker.py", 1) is None


def test_unawaited_async_wrapper_does_not_execute_callback(tmp_path: Path) -> None:
    worker = tmp_path / "worker.py"
    worker.write_text("def changed() -> int:\n    return 1\n", encoding="utf-8")
    main = tmp_path / "main.py"
    main.write_text(
        "import asyncio\n"
        "from worker import changed\n\n"
        "async def handler():\n"
        "    pending = asyncio.to_thread(changed)\n"
        "    return pending\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=4).analyze_endpoint(_endpoint(main, line=4))

    assert deps.references_symbol_at_line("worker.py", 1) is None


def test_same_named_user_wrapper_never_receives_executor_summary(tmp_path: Path) -> None:
    worker = tmp_path / "worker.py"
    worker.write_text("def changed() -> int:\n    return 1\n", encoding="utf-8")
    main = tmp_path / "main.py"
    main.write_text(
        "from worker import changed\n\n"
        "async def to_thread(callback):\n"
        "    return 0\n\n"
        "async def handler() -> int:\n"
        "    return await to_thread(changed)\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=4).analyze_endpoint(_endpoint(main, line=6))

    assert deps.references_symbol_at_line("worker.py", 1) is None


def test_executor_summary_round_trips_low_boundary_through_cache(tmp_path: Path) -> None:
    worker = tmp_path / "worker.py"
    worker.write_text("def changed() -> int:\n    return 1\n", encoding="utf-8")
    main = tmp_path / "main.py"
    main.write_text(
        "import asyncio\n"
        "from worker import changed\n\n"
        "async def handler() -> int:\n"
        "    return await asyncio.to_thread(changed)\n",
        encoding="utf-8",
    )
    endpoint = _endpoint(main, line=4)
    cache = tmp_path / "cache.json"
    writer = MypyAnalyzer(tmp_path, max_depth=4)
    writer.set_cache_path(cache)
    writer.analyze_endpoints([endpoint], use_cache=True)

    reader = MypyAnalyzer(tmp_path, max_depth=4)
    reader.set_cache_path(cache)
    loaded = reader.analyze_endpoints([endpoint], use_cache=True)[reader._endpoint_key(endpoint)]

    assert loaded.references_lines_low_only("worker.py", {1})
    assert any(
        any("executor_callback:" in frame.code_context for frame in stack)
        for stack in loaded.get_call_stack("worker.py")
    )


@pytest.mark.parametrize(
    ("import_line", "expression"),
    [
        ("import asyncio", "asyncio.to_thread(invoke, Service())"),
        (
            "from anyio.to_thread import run_sync",
            "run_sync(invoke, Service(), abandon_on_cancel=True)",
        ),
        (
            "from starlette.concurrency import run_in_threadpool",
            "run_in_threadpool(invoke, service=Service())",
        ),
    ],
)
def test_executor_arguments_seed_finite_callback_environment(
    tmp_path: Path,
    import_line: str,
    expression: str,
) -> None:
    services = tmp_path / "services.py"
    services.write_text(
        "class Service:\n"
        "    def changed(self) -> int:\n"
        "        return 1\n\n"
        "class Other:\n"
        "    def changed(self) -> int:\n"
        "        return 2\n",
        encoding="utf-8",
    )
    callbacks = tmp_path / "callbacks.py"
    callbacks.write_text(
        "from services import Service\n\n"
        "def invoke(service: Service) -> int:\n"
        "    return service.changed()\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        f"{import_line}\n"
        "from callbacks import invoke\n"
        "from services import Service\n\n"
        "async def handler() -> int:\n"
        f"    return await {expression}\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, line=5))

    assert deps.references_symbol_at_line("services.py", 2) is not None
    assert deps.references_symbol_at_line("services.py", 6) is None
    assert deps.references_lines_low_only("services.py", {2})


def test_bound_method_callback_binds_receiver_and_payload(tmp_path: Path) -> None:
    services = tmp_path / "services.py"
    services.write_text(
        "class Payload:\n"
        "    def changed(self) -> int:\n"
        "        return 1\n\n"
        "class Runner:\n"
        "    def invoke(self, payload: Payload) -> int:\n"
        "        return payload.changed()\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "import asyncio\n"
        "from services import Payload, Runner\n\n"
        "async def handler() -> int:\n"
        "    runner = Runner()\n"
        "    return await asyncio.to_thread(runner.invoke, Payload())\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, line=4))

    assert deps.references_symbol_at_line("services.py", 2) is not None
    assert deps.references_symbol_at_line("services.py", 6) is not None
    assert deps.references_lines_low_only("services.py", {2, 6})


@pytest.mark.parametrize("decorator", ["staticmethod", "classmethod"])
def test_descriptor_callback_binds_only_implicit_receiver(
    tmp_path: Path,
    decorator: str,
) -> None:
    services = tmp_path / "services.py"
    implicit = "" if decorator == "staticmethod" else "cls, "
    services.write_text(
        "class Payload:\n"
        "    def changed(self) -> int:\n"
        "        return 1\n\n"
        "class Runner:\n"
        f"    @{decorator}\n"
        f"    def invoke({implicit}payload: Payload) -> int:\n"
        "        return payload.changed()\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "import asyncio\n"
        "from services import Payload, Runner\n\n"
        "async def handler() -> int:\n"
        "    runner = Runner()\n"
        "    return await asyncio.to_thread(runner.invoke, Payload())\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, line=4))

    assert deps.references_symbol_at_line("services.py", 2) is not None
    assert deps.references_symbol_at_line("services.py", 7) is not None
    assert deps.references_lines_low_only("services.py", {2, 7})


def test_keyword_only_callback_argument_is_bound_exactly(tmp_path: Path) -> None:
    services = tmp_path / "services.py"
    services.write_text(
        "class Service:\n    def changed(self) -> int:\n        return 1\n",
        encoding="utf-8",
    )
    callbacks = tmp_path / "callbacks.py"
    callbacks.write_text(
        "def invoke(*, service) -> int:\n    return service.changed()\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "import asyncio\n"
        "from callbacks import invoke\n"
        "from services import Service\n\n"
        "async def handler() -> int:\n"
        "    return await asyncio.to_thread(invoke, service=Service())\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, line=5))

    assert deps.references_symbol_at_line("services.py", 2) is not None
    assert deps.references_lines_low_only("services.py", {2})


def test_unknown_callback_argument_does_not_create_finite_target(tmp_path: Path) -> None:
    services = tmp_path / "services.py"
    services.write_text(
        "class Service:\n    def changed(self) -> int:\n        return 1\n",
        encoding="utf-8",
    )
    callbacks = tmp_path / "callbacks.py"
    callbacks.write_text(
        "def invoke(service) -> int:\n    return service.changed()\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "import asyncio\n"
        "from callbacks import invoke\n\n"
        "async def handler(service):\n"
        "    return await asyncio.to_thread(invoke, service)\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, line=4))

    assert deps.references_symbol_at_line("services.py", 2) is None


def test_distinct_callback_argument_environments_are_traced_separately(
    tmp_path: Path,
) -> None:
    services = tmp_path / "services.py"
    services.write_text(
        "class First:\n"
        "    def changed(self) -> int:\n"
        "        return 1\n\n"
        "class Second:\n"
        "    def changed(self) -> int:\n"
        "        return 2\n",
        encoding="utf-8",
    )
    callbacks = tmp_path / "callbacks.py"
    callbacks.write_text(
        "def invoke(service) -> int:\n    return service.changed()\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "import asyncio\n"
        "from callbacks import invoke\n"
        "from services import First, Second\n\n"
        "async def handler() -> int:\n"
        "    first = await asyncio.to_thread(invoke, First())\n"
        "    second = await asyncio.to_thread(invoke, Second())\n"
        "    return first + second\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, line=5))

    assert deps.references_symbol_at_line("services.py", 2) is not None
    assert deps.references_symbol_at_line("services.py", 6) is not None
    assert deps.references_lines_low_only("services.py", {2, 6})


@pytest.mark.parametrize(
    "executor_call",
    [
        "asyncio.to_thread(invoke, *services)",
        "asyncio.to_thread(invoke, **values)",
    ],
)
def test_expanded_executor_arguments_do_not_create_finite_targets(
    tmp_path: Path,
    executor_call: str,
) -> None:
    services = tmp_path / "services.py"
    services.write_text(
        "class Service:\n    def changed(self) -> int:\n        return 1\n",
        encoding="utf-8",
    )
    callbacks = tmp_path / "callbacks.py"
    callbacks.write_text(
        "def invoke(service) -> int:\n    return service.changed()\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "import asyncio\n"
        "from callbacks import invoke\n"
        "from services import Service\n\n"
        "async def handler() -> int:\n"
        "    services = (Service(),)\n"
        "    values = {'service': Service()}\n"
        f"    return await {executor_call}\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, line=5))

    assert deps.references_symbol_at_line("services.py", 2) is None
    assert deps.references_symbol_at_line("callbacks.py", 1) is None


def test_executor_argument_environment_round_trips_through_cache(tmp_path: Path) -> None:
    services = tmp_path / "services.py"
    services.write_text(
        "class Service:\n    def changed(self) -> int:\n        return 1\n",
        encoding="utf-8",
    )
    callbacks = tmp_path / "callbacks.py"
    callbacks.write_text(
        "def invoke(service) -> int:\n    return service.changed()\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "import asyncio\n"
        "from callbacks import invoke\n"
        "from services import Service\n\n"
        "async def handler() -> int:\n"
        "    return await asyncio.to_thread(invoke, Service())\n",
        encoding="utf-8",
    )
    endpoint = _endpoint(main, line=5)
    cache = tmp_path / "cache.json"
    writer = MypyAnalyzer(tmp_path, max_depth=5)
    writer.set_cache_path(cache)
    expected = writer.analyze_endpoints([endpoint], use_cache=True)[writer._endpoint_key(endpoint)]

    reader = MypyAnalyzer(tmp_path, max_depth=5)
    reader.set_cache_path(cache)
    actual = reader.analyze_endpoints([endpoint], use_cache=True)[reader._endpoint_key(endpoint)]

    assert expected.references_lines_low_only("services.py", {2})
    assert actual.references_lines_low_only("services.py", {2})
    assert actual.call_stacks == expected.call_stacks


def test_finite_bound_method_callback_uses_exact_mro_target(tmp_path: Path) -> None:
    services = tmp_path / "services.py"
    services.write_text(
        "class First:\n"
        "    def changed(self) -> int:\n"
        "        return 1\n\n"
        "class Other:\n"
        "    def changed(self) -> int:\n"
        "        return 2\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "import asyncio\n"
        "from services import First\n\n"
        "async def handler() -> int:\n"
        "    service = First()\n"
        "    return await asyncio.to_thread(service.changed)\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=4).analyze_endpoint(_endpoint(main, line=4))

    assert deps.references_symbol_at_line("services.py", 2) is not None
    assert deps.references_symbol_at_line("services.py", 6) is None
    assert deps.references_lines_low_only("services.py", {2})
