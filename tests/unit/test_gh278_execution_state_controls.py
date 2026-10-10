"""Public mapper controls for callable argument and exceptional-path state."""

from pathlib import Path

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper


def _diff(path: str, line: int) -> str:
    return (
        f"diff --git a/{path} b/{path}\n"
        f"--- a/{path}\n+++ b/{path}\n"
        f"@@ -{line},1 +{line},1 @@\n"
        "-    return 1\n"
        "+    return 2\n"
    )


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


def test_try_assignment_is_not_promoted_across_exception_join(tmp_path: Path) -> None:
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

    assert report.candidate_endpoints == []


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
