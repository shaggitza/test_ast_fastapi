"Public mapper controls for raising expressions and captured callback state."

from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper


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
