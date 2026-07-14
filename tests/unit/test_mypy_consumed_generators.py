"""Creation-versus-consumption-correct LOW-only generator summaries."""

from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo


def _endpoint(main: Path, *, line: int) -> Endpoint:
    return Endpoint(
        path="/generators",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="handler",
            module="main",
            file_path=main,
            line_number=line,
        ),
    )


def _write_generator_project(tmp_path: Path) -> None:
    (tmp_path / "worker.py").write_text(
        "def changed() -> int:\n    return 1\n",
        encoding="utf-8",
    )
    (tmp_path / "streams.py").write_text(
        "from worker import changed\n\n"
        "def sync_stream():\n"
        "    yield changed()\n\n"
        "async def async_stream():\n"
        "    yield changed()\n",
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    "body",
    [
        "    pending = sync_stream()\n    return 0\n",
        "    pending = async_stream()\n    return 0\n",
        "    return sync_stream()\n",
        "    return async_stream()\n",
    ],
)
def test_generator_creation_does_not_execute_body(tmp_path: Path, body: str) -> None:
    _write_generator_project(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        f"from streams import async_stream, sync_stream\n\ndef handler():\n{body}",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, line=3))

    assert deps.references_symbol_at_line("worker.py", 1) is None
    assert deps.references_symbol_at_line("streams.py", 3) is None
    assert deps.references_symbol_at_line("streams.py", 6) is None


def test_generator_expression_creation_does_not_execute_element(tmp_path: Path) -> None:
    (tmp_path / "worker.py").write_text(
        "def changed() -> int:\n    return 1\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from worker import changed\n\n"
        "def handler():\n"
        "    pending = (changed() for _ in range(1))\n"
        "    return pending\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, line=3))

    assert deps.references_symbol_at_line("worker.py", 1) is None


@pytest.mark.parametrize(
    ("function_header", "expression"),
    [
        ("def handler():", "[value for value in sync_stream()]"),
        ("async def handler():", "[value async for value in async_stream()]"),
    ],
)
def test_eager_comprehension_consumes_generator(
    tmp_path: Path,
    function_header: str,
    expression: str,
) -> None:
    _write_generator_project(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "from streams import async_stream, sync_stream\n\n"
        f"{function_header}\n"
        f"    return {expression}\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, line=3))

    assert deps.references_symbol_at_line("worker.py", 1) is not None
    assert deps.references_lines_low_only("worker.py", {1})


@pytest.mark.parametrize(
    ("function_header", "loop"),
    [
        ("def handler() -> int:", "    for value in sync_stream():\n        return value"),
        (
            "async def handler() -> int:",
            "    async for value in async_stream():\n        return value",
        ),
    ],
)
def test_direct_loop_consumes_generator_at_low(
    tmp_path: Path,
    function_header: str,
    loop: str,
) -> None:
    _write_generator_project(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "from streams import async_stream, sync_stream\n\n"
        f"{function_header}\n"
        f"{loop}\n"
        "    return 0\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, line=3))

    assert deps.references_symbol_at_line("worker.py", 1) is not None
    assert deps.references_lines_low_only("worker.py", {1})
    assert any(
        any("consumed_" in frame.code_context for frame in stack)
        for stack in deps.get_call_stack("worker.py")
    )


@pytest.mark.parametrize(
    ("function_header", "creation", "consumer"),
    [
        ("def handler() -> int:", "sync_stream()", "next(alias)"),
        ("async def handler() -> int:", "async_stream()", "await anext(alias)"),
    ],
)
def test_exact_local_alias_is_consumed_by_builtin(
    tmp_path: Path,
    function_header: str,
    creation: str,
    consumer: str,
) -> None:
    _write_generator_project(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "from streams import async_stream, sync_stream\n\n"
        f"{function_header}\n"
        f"    original = {creation}\n"
        "    alias = original\n"
        f"    return {consumer}\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, line=3))

    assert deps.references_symbol_at_line("worker.py", 1) is not None
    assert deps.references_lines_low_only("worker.py", {1})


@pytest.mark.parametrize(
    "response_expression",
    ["StreamingResponse(pending)", "StreamingResponse(content=pending)"],
)
def test_streaming_response_consumes_exact_generator_alias(
    tmp_path: Path,
    response_expression: str,
) -> None:
    _write_generator_project(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "from fastapi.responses import StreamingResponse\n"
        "from streams import async_stream\n\n"
        "async def handler():\n"
        "    pending = async_stream()\n"
        f"    return {response_expression}\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, line=4))

    assert deps.references_symbol_at_line("worker.py", 1) is not None
    assert deps.references_lines_low_only("worker.py", {1})


def test_shadowed_anext_does_not_consume_async_generator(tmp_path: Path) -> None:
    _write_generator_project(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "from streams import async_stream\n\n"
        "async def anext(value):\n"
        "    return 0\n\n"
        "async def handler() -> int:\n"
        "    pending = async_stream()\n"
        "    return await anext(pending)\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, line=6))

    assert deps.references_symbol_at_line("worker.py", 1) is None


@pytest.mark.parametrize(
    ("function_header", "creation", "loop"),
    [
        (
            "async def handler() -> int:",
            "sync_stream()",
            "    async for value in pending:\n        return value",
        ),
        (
            "def handler() -> int:",
            "async_stream()",
            "    for value in pending:\n        return value",
        ),
    ],
)
def test_protocol_mismatch_does_not_consume_generator(
    tmp_path: Path,
    function_header: str,
    creation: str,
    loop: str,
) -> None:
    _write_generator_project(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "from streams import async_stream, sync_stream\n\n"
        f"{function_header}\n"
        f"    pending = {creation}\n"
        f"{loop}\n"
        "    return 0\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, line=3))

    assert deps.references_symbol_at_line("worker.py", 1) is None


@pytest.mark.parametrize(
    "intervening",
    [
        "    pending = 0\n",
        "    unknown()\n",
    ],
)
def test_reassignment_or_unknown_call_invalidates_generator_alias(
    tmp_path: Path,
    intervening: str,
) -> None:
    _write_generator_project(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "from streams import sync_stream\n\n"
        "def unknown():\n    return None\n\n"
        "def handler() -> int:\n"
        "    pending = sync_stream()\n"
        f"{intervening}"
        "    return next(pending)\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, line=6))

    assert deps.references_symbol_at_line("worker.py", 1) is None


def test_invalid_builtin_consumer_shape_does_not_execute_generator(tmp_path: Path) -> None:
    _write_generator_project(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "from streams import sync_stream\n\n"
        "def handler() -> int:\n"
        "    pending = sync_stream()\n"
        "    return next(pending, 0, 1)\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, line=3))

    assert deps.references_symbol_at_line("worker.py", 1) is None


def test_yield_from_consumes_nested_sync_generator(tmp_path: Path) -> None:
    _write_generator_project(tmp_path)
    streams = tmp_path / "streams.py"
    streams.write_text(
        streams.read_text(encoding="utf-8") + "\ndef outer():\n    yield from sync_stream()\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from streams import outer\n\ndef handler() -> int:\n    return next(outer())\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=6).analyze_endpoint(_endpoint(main, line=3))

    assert deps.references_symbol_at_line("worker.py", 1) is not None
    assert deps.references_lines_low_only("worker.py", {1})


def test_consumed_generator_arguments_seed_finite_environment(tmp_path: Path) -> None:
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
    streams = tmp_path / "streams.py"
    streams.write_text(
        "def stream(service):\n    yield service.changed()\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from services import Service\n"
        "from streams import stream\n\n"
        "def handler() -> int:\n"
        "    for value in stream(Service()):\n"
        "        return value\n"
        "    return 0\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, line=4))

    assert deps.references_symbol_at_line("services.py", 2) is not None
    assert deps.references_symbol_at_line("services.py", 6) is None
    assert deps.references_lines_low_only("services.py", {2})


def test_typed_parameter_generator_creation_remains_deferred(tmp_path: Path) -> None:
    (tmp_path / "worker.py").write_text(
        "def changed() -> int:\n    return 1\n",
        encoding="utf-8",
    )
    services = tmp_path / "services.py"
    services.write_text(
        "from worker import changed\n\n"
        "class Runner:\n"
        "    def stream(self):\n"
        "        yield changed()\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from services import Runner\n\n"
        "def handler(runner: Runner) -> int:\n"
        "    pending = runner.stream()\n"
        "    return 0\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, line=3))

    assert deps.references_symbol_at_line("worker.py", 1) is None
    assert deps.references_symbol_at_line("services.py", 4) is None


def test_finite_generator_method_receiver_is_preserved(tmp_path: Path) -> None:
    services = tmp_path / "services.py"
    services.write_text(
        "class Service:\n"
        "    def changed(self) -> int:\n"
        "        return 1\n\n"
        "class Runner:\n"
        "    def __init__(self) -> None:\n"
        "        self.service = Service()\n\n"
        "    def stream(self):\n"
        "        yield self.service.changed()\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from services import Runner\n\n"
        "def handler() -> int:\n"
        "    for value in Runner().stream():\n"
        "        return value\n"
        "    return 0\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, line=3))

    assert deps.references_symbol_at_line("services.py", 2) is not None
    assert deps.references_symbol_at_line("services.py", 9) is not None
    assert deps.references_lines_low_only("services.py", {2, 9})


@pytest.mark.parametrize("decorator", ["staticmethod", "classmethod"])
def test_descriptor_generator_method_is_consumed_with_finite_instance(
    tmp_path: Path,
    decorator: str,
) -> None:
    implicit = "" if decorator == "staticmethod" else "cls"
    services = tmp_path / "services.py"
    services.write_text(
        "from worker import changed\n\n"
        "class Runner:\n"
        f"    @{decorator}\n"
        f"    def stream({implicit}):\n"
        "        yield changed()\n",
        encoding="utf-8",
    )
    (tmp_path / "worker.py").write_text(
        "def changed() -> int:\n    return 1\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from services import Runner\n\n"
        "def handler() -> int:\n"
        "    for value in Runner().stream():\n"
        "        return value\n"
        "    return 0\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, line=3))

    assert deps.references_symbol_at_line("worker.py", 1) is not None
    assert deps.references_lines_low_only("worker.py", {1})


def test_identical_branch_alias_survives_join(tmp_path: Path) -> None:
    _write_generator_project(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "from streams import sync_stream\n\n"
        "def handler(condition) -> int:\n"
        "    original = sync_stream()\n"
        "    if condition:\n"
        "        selected = original\n"
        "    else:\n"
        "        selected = original\n"
        "    return next(selected)\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, line=3))

    assert deps.references_symbol_at_line("worker.py", 1) is not None
    assert deps.references_lines_low_only("worker.py", {1})


def test_divergent_branch_alias_is_not_consumed(tmp_path: Path) -> None:
    _write_generator_project(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "from streams import sync_stream\n\n"
        "def handler(condition) -> int:\n"
        "    original = sync_stream()\n"
        "    if condition:\n"
        "        selected = original\n"
        "    else:\n"
        "        selected = 0\n"
        "    return next(selected)\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main, line=3))

    assert deps.references_symbol_at_line("worker.py", 1) is None


def test_consumed_generator_summary_round_trips_through_cache(tmp_path: Path) -> None:
    _write_generator_project(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        "from streams import async_stream\n\n"
        "async def handler() -> int:\n"
        "    pending = async_stream()\n"
        "    return await anext(pending)\n",
        encoding="utf-8",
    )
    endpoint = _endpoint(main, line=3)
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
