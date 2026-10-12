"Public mapper controls for raising expressions and captured callback state."

from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo


def _diff(path: str, line: int) -> str:
    return (
        f"diff --git a/{path} b/{path}\n"
        f"--- a/{path}\n+++ b/{path}\n"
        f"@@ -{line},1 +{line},1 @@\n"
        "-    return 1\n"
        "+    return 2\n"
    )


@pytest.mark.parametrize(
    "raising_expression", ["obj.attr", "obj[key]", "left + right", "missing_name"]
)
def test_handler_keeps_intermediate_callable_at_raising_expression(
    tmp_path: Path, raising_expression: str
) -> None:
    (tmp_path / "helpers.py").write_text(
        "def base(): return 0\ndef second(): return 1\ndef third(): return 2\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\nfrom helpers import base, second, third\n"
        "app=FastAPI()\n@app.get('/try-attribute')\ndef handler(obj):\n"
        "    callback = base\n    try:\n        callback = second\n"
        f"        value = {raising_expression}\n        callback = third\n"
        "    except Exception:\n        callback()\n    return 0\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)

    intermediate = mapper.analyze_diff(_diff("helpers.py", 2))
    assert {item.endpoint.identifier for item in intermediate.candidate_endpoints} == {
        "GET /try-attribute"
    }
    unreachable = mapper.analyze_diff(_diff("helpers.py", 3))
    assert unreachable.candidate_endpoints == []


def test_exposing_partial_invalidates_its_captured_callback(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text(
        "def first(): return 1\ndef second(): return 2\ndef run(callback): return callback()\n"
        "def mutate(value): value.keywords['callback'] = second\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from functools import partial\nfrom fastapi import FastAPI\n"
        "from helpers import first, run, mutate\napp=FastAPI()\n@app.get('/partial-exposed')\n"
        "def handler():\n    bound = partial(run, callback=first)\n"
        "    mutate(bound)\n    return bound()\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)
    report = mapper.analyze_diff(_diff("helpers.py", 2))
    assert report.candidate_endpoints == []


def test_true_loop_rejects_earlier_continue_and_dead_body_calls(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text("def target(): return 1\n", encoding="utf-8")
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\nfrom helpers import target\napp=FastAPI()\n"
        "@app.get('/continue')\ndef handler():\n    while True:\n"
        "        continue\n        target()\n        break\n    return 0\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)
    report = mapper.analyze_diff(_diff("helpers.py", 1))
    assert report.candidate_endpoints == []


def test_comprehension_callback_is_possible_execution(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text("def target(): return 1\n", encoding="utf-8")
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\nfrom helpers import target\napp=FastAPI()\n"
        "@app.get('/comp')\ndef handler():\n    callback = lambda: target()\n"
        "    [callback() for item in ()]\n    return 0\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)
    report = mapper.analyze_diff(
        "diff --git a/main.py b/main.py\n--- a/main.py\n+++ b/main.py\n"
        "@@ -5,1 +5,1 @@\n-    callback = lambda: target()\n+    callback = lambda: target() + 1\n"
    )
    assert {item.endpoint.identifier for item in report.candidate_endpoints} == {"GET /comp"}
    endpoint = mapper.registry.get_all()[0]
    dependencies = mapper.mypy_analyzer.get_endpoint_dependencies(endpoint)
    assert dependencies is not None
    assert dependencies.get_source_evidence_spans(
        str(tmp_path / "main.py"), execution_state="possible_execution"
    )


def test_handler_preserves_pre_try_callable_as_exception_target(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text(
        "def first(): return 1\ndef second(): return 2\ndef risky(): raise RuntimeError\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\nfrom helpers import first, second, risky\n"
        "app=FastAPI()\n@app.get('/try-target')\ndef handler():\n"
        "    callback = first\n    try:\n        risky()\n"
        "        callback = second\n    except Exception:\n"
        "        callback()\n    return 0\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)
    assert {
        item.endpoint.identifier
        for item in mapper.analyze_diff(_diff("helpers.py", 1)).candidate_endpoints
    } == {"GET /try-target"}
    assert mapper.analyze_diff(_diff("helpers.py", 2)).candidate_endpoints == []


def test_handler_keeps_callable_before_resolved_unbound_local_load(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text(
        "def base(): return 0\ndef second(): return 1\ndef third(): return 2\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\nfrom helpers import base, second, third\n"
        "app=FastAPI()\n@app.get('/try-local-load')\ndef handler():\n"
        "    callback = base\n    try:\n        callback = second\n"
        "        value = maybe_local\n        callback = third\n"
        "        callback()\n"
        "    except Exception:\n        callback()\n    maybe_local = 1\n"
        "    return 0\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)

    intermediate = mapper.analyze_diff(_diff("helpers.py", 2))
    assert {item.endpoint.identifier for item in intermediate.candidate_endpoints} == {
        "GET /try-local-load"
    }
    assert mapper.analyze_diff(_diff("helpers.py", 3)).candidate_endpoints == []


@pytest.mark.parametrize(
    ("prefix", "expected_state"),
    [
        ("", "established_execution"),
        ("    if False:\n        return 0\n", "established_execution"),
        ("    if flag:\n        return 0\n", "possible_execution"),
        ("    if flag:\n        raise ValueError()\n", "possible_execution"),
        ("    with Suppressor():\n        raise ValueError()\n", "possible_execution"),
        (
            "    with Suppressor():\n        if flag:\n            raise ValueError()\n",
            "possible_execution",
        ),
    ],
)
def test_lambda_after_abrupt_alternatives_has_conditional_source_evidence(
    tmp_path: Path, prefix: str, expected_state: str
) -> None:
    prelude = (
        "def hit() -> int:\n"
        "    return 1\n"
        "class Suppressor:\n"
        '    def __enter__(self) -> "Suppressor":\n'
        "        return self\n"
        "    def __exit__(\n"
        "        self,\n"
        "        exc_type: type[BaseException] | None,\n"
        "        exc: BaseException | None,\n"
        "        traceback: object,\n"
        "    ) -> bool:\n"
        "        return True\n"
        "def handler(flag: bool) -> int:\n"
    )
    body = "    return (lambda: hit())()"
    source = prelude + prefix + body + "\n"
    app_path = tmp_path / "app.py"
    app_path.write_text(source, encoding="utf-8")
    endpoint = Endpoint(
        path="/block-continuations",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(name="handler", module="app", file_path=app_path, line_number=13),
    )

    dependencies = MypyAnalyzer(tmp_path, max_depth=4).analyze_endpoint(endpoint)

    body_line = len(prelude.splitlines()) + len(prefix.splitlines()) + 1
    body_column = len(body[: body.index("hit()")].encode("utf-8"))
    states = {
        span.execution_state
        for span in dependencies.source_evidence_spans
        if (
            span.start_line,
            span.start_column,
            span.end_line,
            span.end_column,
        )
        == (body_line, body_column, body_line, body_column + len("hit()"))
    }
    assert dependencies.references_symbol_at_line("app.py", 1) is not None
    assert expected_state in states
    if expected_state == "possible_execution":
        assert "established_execution" not in states
    else:
        assert "possible_execution" not in states
        assert "deferred_execution" not in states


@pytest.mark.parametrize(
    ("alias", "initial", "replacement", "invoke"),
    [
        ("callback", "first", "second", "callback()"),
        ("bound", "partial(run, first)", "partial(run, second)", "bound()"),
        ("callback", "lambda: first()", "lambda: second()", "callback()"),
    ],
)
def test_normal_finally_preserves_definite_callable_binding(
    tmp_path: Path, alias: str, initial: str, replacement: str, invoke: str
) -> None:
    (tmp_path / "helpers.py").write_text(
        "def first():\n    return 1\n\ndef second():\n    return 1\n\n"
        "def run(callback):\n    return callback()\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from functools import partial\nfrom fastapi import FastAPI\n"
        "from helpers import first, second, run\napp=FastAPI()\n"
        "@app.get('/finally-write')\ndef handler():\n"
        f"    {alias} = {initial}\n"
        "    try:\n        pass\n    finally:\n"
        f"        {alias} = {replacement}\n"
        f"    return {invoke}\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)
    report = mapper.analyze_diff(_diff("helpers.py", 5))
    assert {item.endpoint.identifier for item in report.candidate_endpoints} == {
        "GET /finally-write"
    }
    assert not any(
        item.cap == "UNKNOWN_FINALLY_EXIT_BINDING" for item in report.analysis_limitations
    )


@pytest.mark.parametrize(
    "finalizer",
    [
        "        if flag:\n            callback = second\n            return 0\n",
        "        callback = second\n        raise RuntimeError()\n",
        "        callback = second\n        return 0\n",
    ],
)
def test_abrupt_finally_write_does_not_supply_post_try_call(tmp_path: Path, finalizer: str) -> None:
    (tmp_path / "helpers.py").write_text(
        "def first():\n    return 1\n\ndef second():\n    return 1\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\nfrom helpers import first, second\n"
        "app=FastAPI()\n@app.get('/finally-abrupt')\ndef handler(flag: bool):\n"
        "    callback = first\n    try:\n        pass\n    finally:\n"
        + finalizer
        + "    return callback()\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)
    assert mapper.analyze_diff(_diff("helpers.py", 5)).candidate_endpoints == []


def test_normal_finally_write_survives_pending_loop_break(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text(
        "def first():\n    return 1\n\ndef second():\n    return 1\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\nfrom helpers import first, second\n"
        "app=FastAPI()\n@app.get('/finally-break')\ndef handler():\n"
        "    callback = first\n    while True:\n        try:\n            break\n"
        "        finally:\n            callback = second\n"
        "    return callback()\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)
    assert {
        item.endpoint.identifier
        for item in mapper.analyze_diff(_diff("helpers.py", 5)).candidate_endpoints
    } == {"GET /finally-break"}


def test_conditional_normal_finally_write_stays_low(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text(
        "def first():\n    return 1\n\ndef second():\n    return 1\n",
        encoding="utf-8",
    )
    main_path = tmp_path / "main.py"
    main_path.write_text(
        "from helpers import first, second\n"
        "def handler(flag: bool):\n"
        "    callback = first\n    try:\n        pass\n    finally:\n"
        "        if flag:\n            callback = second\n"
        "    return callback()\n",
        encoding="utf-8",
    )
    endpoint = Endpoint(
        path="/conditional-finally",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(name="handler", module="main", file_path=main_path, line_number=2),
    )
    dependencies = MypyAnalyzer(tmp_path).analyze_endpoint(endpoint)
    for line in (2, 5):
        reference = dependencies.references_symbol_at_line("helpers.py", line)
        assert reference is not None
        assert reference.low_confidence
