"""Public mapper controls for callable argument and exceptional-path state."""

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
    ("parameter", "prefix", "expected"),
    [
        (True, "", (False, True)),
        (False, "    maybe_local = 0\n", (False, True)),
        (False, "    if condition:\n        maybe_local = 0\n", (True, True)),
    ],
)
def test_exception_snapshots_preserve_local_binding_guards(
    tmp_path: Path,
    parameter: bool,
    prefix: str,
    expected: tuple[bool, bool],
) -> None:
    (tmp_path / "helpers.py").write_text(
        "def base(): return 0\ndef second(): return 1\ndef third(): return 2\n",
        encoding="utf-8",
    )
    argument = "maybe_local" if parameter else "condition"
    lines = [
        "from fastapi import FastAPI",
        "from helpers import base, second, third",
        "app=FastAPI()",
        "@app.get('/try-binding')",
        f"def handler({argument}):",
    ]
    lines.extend(prefix.rstrip("\n").splitlines() if prefix else [])
    lines.extend(
        [
            "    callback = base",
            "    try:",
            "        callback = second",
            "        value = maybe_local",
            "        callback = third",
            "        callback()",
            "    except Exception:",
            "        callback()",
            "    maybe_local = 1",
            "    return 0",
        ]
    )
    (tmp_path / "main.py").write_text("\n".join(lines) + "\n", encoding="utf-8")
    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)

    second = mapper.analyze_diff(_diff("helpers.py", 2)).candidate_endpoints
    third = mapper.analyze_diff(_diff("helpers.py", 3)).candidate_endpoints
    assert bool(second) is expected[0]
    assert bool(third) is expected[1]


def test_conditional_break_loop_remains_conservative(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text(
        "def first(): return 1\ndef second(): return 2\n", encoding="utf-8"
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\nfrom helpers import first, second\n"
        "app=FastAPI()\n@app.get('/loop')\ndef handler(flag: bool):\n"
        "    callback = first\n    while True:\n"
        "        if flag: break\n        callback = second\n"
        "        break\n    return callback()\n",
        encoding="utf-8",
    )
    report = ChangeMapper(tmp_path, secure_ast=True, use_cache=False).analyze_diff(
        _diff("helpers.py", 2)
    )
    assert {item.endpoint.identifier for item in report.candidate_endpoints} == {"GET /loop"}
    assert all(item.confidence.value != "high" for item in report.candidate_endpoints)


def test_unknown_branch_callable_join_keeps_both_possible_targets(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text(
        "def first() -> int:\n    return 1\n\ndef second() -> int:\n    return 1\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\nfrom helpers import first, second\n\n"
        "app = FastAPI()\n\n@app.get('/branch')\n"
        "def handler(flag: bool):\n"
        "    if flag:\n        callback = first\n"
        "    else:\n        callback = second\n"
        "    return callback()\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)

    first = mapper.analyze_diff(_diff("helpers.py", 2))
    second = mapper.analyze_diff(_diff("helpers.py", 5))

    assert {item.endpoint.identifier for item in first.candidate_endpoints} == {"GET /branch"}
    assert {item.endpoint.identifier for item in second.candidate_endpoints} == {"GET /branch"}
    assert all(item.confidence.value != "high" for item in first.candidate_endpoints)
    assert all(item.confidence.value != "high" for item in second.candidate_endpoints)


def test_try_assignment_keeps_normal_and_exception_callable_targets(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text(
        "def first() -> int:\n    return 1\n\n"
        "def second() -> int:\n    return 1\n\n"
        "def risky() -> None:\n    raise RuntimeError\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from helpers import first, second, risky\n\n"
        "app = FastAPI()\n\n"
        "@app.get('/try')\n"
        "def handler():\n"
        "    callback = first\n"
        "    try:\n"
        "        risky()\n"
        "        callback = second\n"
        "    except Exception:\n"
        "        pass\n"
        "    return callback()\n",
        encoding="utf-8",
    )
    report = ChangeMapper(tmp_path, secure_ast=True, use_cache=False).analyze_diff(
        _diff("helpers.py", 5)
    )

    assert {item.endpoint.identifier for item in report.candidate_endpoints} == {"GET /try"}


def test_callable_union_cap_is_endpoint_scoped_and_cached(tmp_path: Path) -> None:
    (tmp_path / "nested.py").write_text("def visit():\n    return 1\n", encoding="utf-8")
    (tmp_path / "helpers.py").write_text(
        "def one(): return 1\ndef two(): return 2\ndef three(): return 3\n"
        "def unrelated(): return 4\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\nfrom helpers import one, two, three, unrelated\n"
        "from nested import visit\n"
        "app = FastAPI()\n@app.get('/limited')\ndef limited(flag: int):\n"
        "    visit()\n"
        "    if flag == 1: callback = one\n"
        "    elif flag == 2: callback = two\n"
        "    else: callback = three\n"
        "    return callback()\n\n@app.get('/plain')\ndef plain():\n    return unrelated()\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=True)
    mapper.mypy_analyzer.MAX_POINTS_TO_TARGETS = 2
    endpoint_list = mapper.registry.get_all()
    dependencies = mapper.mypy_analyzer.analyze_endpoints(endpoint_list, use_cache=False)
    limited = next(value for value in dependencies.values() if value.path == "/limited")
    plain = next(value for value in dependencies.values() if value.path == "/plain")

    assert limited.analysis_incomplete
    assert [(item.cap, item.target_count, item.limit) for item in limited.analysis_limitations] == [
        ("MAX_POINTS_TO_TARGETS", 3, 2)
    ]
    assert limited.analysis_limitations[0].file_path.endswith("main.py")
    assert limited.analysis_limitations[0].call_line == 10
    assert not plain.analysis_incomplete
    assert not plain.analysis_limitations

    mapper.mypy_analyzer._save_cache()
    mapper.mypy_analyzer._endpoint_deps.clear()
    assert mapper.mypy_analyzer._load_cache()
    restored = mapper.mypy_analyzer.get_endpoint_dependencies(endpoint_list[0])
    assert restored is not None
    assert restored.analysis_limitations == limited.analysis_limitations

    report = mapper.analyze_diff(_diff("helpers.py", 1))
    assert report.analysis_completeness == "partial"
    assert report.analysis_limitations[0].cap == "MAX_POINTS_TO_TARGETS"
    assert all(
        item.confidence.value not in {"high", "medium"} for item in report.affected_endpoints
    )


def test_finite_object_union_overflow_is_endpoint_incomplete(tmp_path: Path) -> None:
    (tmp_path / "services.py").write_text(
        "class First:\n    def run(self): return 1\n\n"
        "class Second:\n    def run(self): return 2\n\n"
        "class Third:\n    def run(self): return 3\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from services import First, Second, Third\n"
        "app = FastAPI()\n@app.get('/object')\n"
        "def handler(choice: int):\n"
        "    if choice == 1: service = First()\n"
        "    elif choice == 2: service = Second()\n"
        "    else: service = Third()\n"
        "    return service.run()\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)
    mapper.mypy_analyzer.MAX_POINTS_TO_TARGETS = 2
    endpoint = mapper.registry.get_all()[0]
    dependencies = mapper.mypy_analyzer.analyze_endpoints([endpoint], use_cache=False)
    analyzed = next(iter(dependencies.values()))

    assert analyzed.analysis_incomplete
    assert any(item.cap == "MAX_POINTS_TO_TARGETS" for item in analyzed.analysis_limitations)
    assert all(
        not reference.low_confidence
        for reference in analyzed.referenced_symbols
        if reference.symbol_name.endswith(".run")
    )


def test_depth_limit_counts_only_resolved_project_targets(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text(
        "def inner(): return 1\ndef middle(): return inner()\ndef outer(): return middle()\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\nfrom helpers import outer\n"
        "app = FastAPI()\n@app.get('/external')\ndef external():\n"
        "    return len([])\n\n@app.get('/project')\ndef project():\n"
        "    return outer()\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)
    mapper.mypy_analyzer.max_depth = 1
    endpoints = mapper.registry.get_all()
    dependencies = mapper.mypy_analyzer.analyze_endpoints(endpoints, use_cache=False)
    external = next(value for value in dependencies.values() if value.path == "/external")
    project = next(value for value in dependencies.values() if value.path == "/project")

    assert not external.analysis_incomplete
    assert not external.analysis_limitations
    assert project.analysis_incomplete
    depth_limitations = [item for item in project.analysis_limitations if item.cap == "MAX_DEPTH"]
    assert depth_limitations
    assert depth_limitations[0].file_path.endswith("main.py")
    assert depth_limitations[0].call_line == 10
