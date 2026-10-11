"Public mapper controls for callable arguments and mandatory loop state."

import json
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


def test_execution_semantics_cache_rejects_previous_policy_and_accepts_warm_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "helpers.py").write_text("def target(): return 1\n", encoding="utf-8")
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\nfrom helpers import target\n"
        "app=FastAPI()\n@app.get('/cache')\ndef handler():\n    return target()\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=True)
    endpoints = mapper.registry.get_all()
    mapper.mypy_analyzer.analyze_endpoints(endpoints, use_cache=False)
    mapper.mypy_analyzer._save_cache()

    mapper.mypy_analyzer._endpoint_deps.clear()
    assert mapper.mypy_analyzer._load_cache()

    current_policy = mapper.mypy_analyzer.EXECUTION_STATE_POLICY
    monkeypatch.setattr(
        mapper.mypy_analyzer,
        "EXECUTION_STATE_POLICY",
        "conditional-elif-try-else-guaranteed-finally-v3",
    )
    old_fingerprint, _ = mapper.mypy_analyzer._cache_fingerprint()
    monkeypatch.setattr(mapper.mypy_analyzer, "EXECUTION_STATE_POLICY", current_policy)

    cache_data = json.loads(mapper.mypy_analyzer.cache_path.read_text(encoding="utf-8"))
    cache_data["fingerprint"] = old_fingerprint
    mapper.mypy_analyzer.cache_path.write_text(json.dumps(cache_data), encoding="utf-8")
    mapper.mypy_analyzer._endpoint_deps.clear()

    assert not mapper.mypy_analyzer._load_cache()
    assert mapper.mypy_analyzer._endpoint_deps == {}


def test_partial_bound_callback_does_not_shift_second_argument_to_first(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text(
        "def first() -> int:\n    return 1\n\n"
        "def second() -> int:\n    return 1\n\n"
        "def run(primary, secondary) -> int:\n    return primary()\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from functools import partial\n"
        "from fastapi import FastAPI\n"
        "from helpers import first, second, run\n\n"
        "app = FastAPI()\n\n"
        "@app.get('/partial')\n"
        "def handler():\n"
        "    bound = partial(run, first)\n"
        "    return bound(second)\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)

    first_change = mapper.analyze_diff(_diff("helpers.py", 2))
    second_change = mapper.analyze_diff(_diff("helpers.py", 5))

    assert {item.endpoint.identifier for item in first_change.candidate_endpoints} == {
        "GET /partial"
    }
    assert second_change.candidate_endpoints == []


def test_partial_invocation_keyword_overrides_creation_capture(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text(
        "def first() -> int: return 1\ndef second() -> int: return 2\n"
        "def run(callback): return callback()\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from functools import partial\nfrom fastapi import FastAPI\n"
        "from helpers import first, second, run\napp=FastAPI()\n"
        "@app.get('/override')\ndef handler():\n"
        "    bound = partial(run, callback=first)\n"
        "    return bound(callback=second)\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)
    assert {
        item.endpoint.identifier
        for item in mapper.analyze_diff(_diff("helpers.py", 2)).candidate_endpoints
    } == {"GET /override"}
    assert mapper.analyze_diff(_diff("helpers.py", 1)).candidate_endpoints == []


def test_invalid_partial_positional_keyword_duplicate_is_not_promoted(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text(
        "def first() -> int: return 1\ndef second() -> int: return 2\n"
        "def run(callback): return callback()\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from functools import partial\nfrom fastapi import FastAPI\n"
        "from helpers import first, second, run\napp=FastAPI()\n"
        "@app.get('/invalid')\ndef handler():\n"
        "    bound = partial(run, first)\n"
        "    return bound(callback=second)\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)
    deps = mapper.mypy_analyzer.analyze_endpoints(mapper.registry.get_all(), use_cache=False)
    endpoint_deps = next(iter(deps.values()))
    assert any(
        item.cap == "INVALID_PARTIAL_ARGUMENTS" for item in endpoint_deps.analysis_limitations
    )
    assert mapper.analyze_diff(_diff("helpers.py", 1)).candidate_endpoints == []
    assert mapper.analyze_diff(_diff("helpers.py", 2)).candidate_endpoints == []


def test_partial_keeps_creation_time_callback_across_rebinding(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text(
        "def first() -> int: return 1\ndef second() -> int: return 2\n"
        "def run(callback): return callback()\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from functools import partial\nfrom fastapi import FastAPI\n"
        "from helpers import first, second, run\napp=FastAPI()\n"
        "@app.get('/capture')\ndef handler():\n"
        "    callback = first\n"
        "    bound = partial(run, callback=callback)\n"
        "    callback = second\n"
        "    return bound()\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)
    assert {
        item.endpoint.identifier
        for item in mapper.analyze_diff(_diff("helpers.py", 1)).candidate_endpoints
    } == {"GET /capture"}
    assert mapper.analyze_diff(_diff("helpers.py", 2)).candidate_endpoints == []


def test_partial_captures_finite_string_argument_at_creation(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text(
        "def old_effect(): return 1\ndef new_effect(): return 2\n"
        "def run(path):\n    if path == '/old': return old_effect()\n"
        "    if path == '/new': return new_effect()\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from functools import partial\nfrom fastapi import FastAPI\n"
        "from helpers import run\napp=FastAPI()\n"
        "@app.get('/partial-string')\ndef handler():\n"
        "    path = '/old'\n    bound = partial(run, path=path)\n"
        "    path = '/new'\n    return bound()\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)
    assert {
        item.endpoint.identifier
        for item in mapper.analyze_diff(_diff("helpers.py", 1)).candidate_endpoints
    } == {"GET /partial-string"}
    assert mapper.analyze_diff(_diff("helpers.py", 2)).candidate_endpoints == []


def test_partial_keyword_positional_collision_is_not_traced(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text(
        "def first(): return 1\ndef second(): return 2\ndef run(callback): return callback()\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from functools import partial\nfrom fastapi import FastAPI\n"
        "from helpers import first, second, run\napp=FastAPI()\n"
        "@app.get('/invalid-reverse')\ndef handler():\n"
        "    bound = partial(run, callback=first)\n    return bound(second)\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)
    endpoint_dependencies = mapper.mypy_analyzer.analyze_endpoints(
        mapper.registry.get_all(), use_cache=False
    )
    endpoint_deps = next(iter(endpoint_dependencies.values()))
    assert any(
        item.cap == "INVALID_PARTIAL_ARGUMENTS" for item in endpoint_deps.analysis_limitations
    )
    assert mapper.analyze_diff(_diff("helpers.py", 1)).candidate_endpoints == []
    assert mapper.analyze_diff(_diff("helpers.py", 2)).candidate_endpoints == []


def test_literal_true_loop_break_uses_mandatory_assignment(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text(
        "def first(): return 1\ndef second(): return 2\n", encoding="utf-8"
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\nfrom helpers import first, second\n"
        "app=FastAPI()\n@app.get('/loop')\ndef handler():\n"
        "    callback = first\n    while True:\n"
        "        callback = second\n        break\n"
        "    return callback()\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)
    assert {
        item.endpoint.identifier
        for item in mapper.analyze_diff(_diff("helpers.py", 2)).candidate_endpoints
    } == {"GET /loop"}
    assert mapper.analyze_diff(_diff("helpers.py", 1)).candidate_endpoints == []


def test_mandatory_loop_lambda_execution_is_established(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\napp=FastAPI()\n"
        "@app.get('/mandatory-lambda')\ndef handler():\n"
        "    callback = lambda: 1\n    while True:\n"
        "        callback()\n        break\n    return 0\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)
    lambda_diff = (
        "diff --git a/main.py b/main.py\n"
        "--- a/main.py\n+++ b/main.py\n"
        "@@ -5,1 +5,1 @@\n"
        "-    callback = lambda: 1\n"
        "+    callback = lambda: 2\n"
    )
    report = mapper.analyze_diff(lambda_diff)
    assert {item.endpoint.identifier for item in report.candidate_endpoints} == {
        "GET /mandatory-lambda"
    }
    assert any(
        evidence.execution_state == "established_execution"
        for candidate in report.candidate_endpoints
        for evidence in candidate.execution_evidence
    )


def test_handler_joins_callable_state_at_each_raising_call(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text(
        "def base(): return 0\ndef first(): return 1\ndef second(): return 2\n"
        "def risky(): raise RuntimeError\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\nfrom helpers import base, first, second, risky\n"
        "app=FastAPI()\n@app.get('/try-each')\ndef handler():\n"
        "    callback = base\n    try:\n        callback = first\n        risky()\n"
        "        callback = second\n        risky()\n    except Exception:\n"
        "        callback()\n    return 0\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)
    for line in (2, 3):
        report = mapper.analyze_diff(_diff("helpers.py", line))
        assert {item.endpoint.identifier for item in report.candidate_endpoints} == {
            "GET /try-each"
        }
