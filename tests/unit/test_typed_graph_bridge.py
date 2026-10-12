"""Production bridge checks against the analyzer's retained ordinary mypy build."""

import ast
import subprocess
import tarfile
from pathlib import Path
from typing import Any

import pytest

from fastapi_endpoint_detector.analyzer import change_mapper as change_mapper_module
from fastapi_endpoint_detector.analyzer import typed_graph_bridge as graph_bridge
from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.analyzer.source_inventory import (
    SourceInventory,
    build_source_inventory,
)
from fastapi_endpoint_detector.analyzer.typed_graph_bridge import (
    TypedGraphBridgeError,
    build_shadow_graph,
    retained_typed_build,
)
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo


def _endpoint(path: Path, module: str, *, name: str = "handler", line: int = 5) -> Endpoint:
    return Endpoint(
        path="/",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(name=name, module=module, file_path=path, line_number=line),
    )


def _source(tmp_path: Path) -> tuple[Path, SourceInventory, MypyAnalyzer]:
    app = tmp_path / "app.py"
    app.write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "def helper() -> int: return 1\n"
        "@app.get('/')\n"
        "def handler() -> int: return helper()\n",
        encoding="utf-8",
    )
    decoy = tmp_path / "decoy.py"
    decoy.write_text("def handler() -> str: return 'decoy'\n", encoding="utf-8")
    inventory = build_source_inventory(tmp_path)
    analyzer = MypyAnalyzer(app, module_root=tmp_path, source_inventory=inventory)
    analyzer._ensure_mypy_built()
    return app, inventory, analyzer


def test_retained_ordinary_build_is_wrapped_with_exact_provenance(tmp_path: Path) -> None:
    app, inventory, analyzer = _source(tmp_path)
    typed, snapshots, config_fingerprint = retained_typed_build(analyzer, inventory)

    assert typed.result is analyzer._build_result
    assert typed.modules is analyzer._build_result.graph
    assert config_fingerprint
    assert snapshots["app"].decode().startswith("from fastapi")
    assert typed.report.mode == "same_ordinary_build_result"
    assert dict(typed.report.source_digests_after) == {
        record.module: record.sha256 for record in inventory.files
    }
    graph = build_shadow_graph(analyzer, inventory, [_endpoint(app, "app")])
    assert {binding.symbol for binding in graph.endpoint_bindings} == {"app.handler"}
    assert any(edge.caller == "app.handler" and edge.callee == "app.helper" for edge in graph.edges)


def test_handler_module_path_and_line_decoys_fail_closed(tmp_path: Path) -> None:
    app, inventory, analyzer = _source(tmp_path)
    for endpoint in (
        _endpoint(app, "decoy"),
        _endpoint(app, "app", line=3),
        _endpoint(tmp_path / "decoy.py", "app"),
    ):
        with pytest.raises(TypedGraphBridgeError):
            build_shadow_graph(analyzer, inventory, [endpoint])


def test_source_mutation_after_mypy_build_is_rejected(tmp_path: Path) -> None:
    app, inventory, analyzer = _source(tmp_path)
    app.write_text(app.read_text(encoding="utf-8") + "# changed after build\n", encoding="utf-8")

    with pytest.raises(TypedGraphBridgeError):
        retained_typed_build(analyzer, inventory)


def test_mypy_options_changed_after_build_are_rejected(tmp_path: Path) -> None:
    _app, inventory, analyzer = _source(tmp_path)
    options = analyzer._build_result.manager.options
    original = options.follow_imports
    options.follow_imports = "skip" if original != "skip" else "normal"

    with pytest.raises(TypedGraphBridgeError):
        retained_typed_build(analyzer, inventory)


def test_public_mapper_invokes_snapshot_graph_without_replacing_legacy_report(
    tmp_path: Path,
) -> None:
    app = tmp_path / "app.py"
    app.write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "def helper() -> int: return 1\n"
        "@app.get('/other')\n"
        "@app.get('/')\n"
        "def handler() -> int: return helper()\n",
        encoding="utf-8",
    )
    baseline_root = tmp_path / "baseline"
    baseline_root.mkdir()
    baseline_app = baseline_root / "app.py"
    baseline_app.write_text(app.read_text(encoding="utf-8").replace("return 1", "return 0"))
    mapper = ChangeMapper(
        app,
        secure_ast=True,
        use_cache=False,
        baseline_app_path=baseline_app,
        typed_graph_shadow=True,
    )
    diff = (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -3,1 +3,1 @@\n"
        "-def helper() -> int: return 0\n"
        "+def helper() -> int: return 1\n"
    )

    report = mapper.analyze_diff(diff)

    assert [entry[0] for entry in mapper._typed_graph_shadow] == ["target", "baseline"]
    _, target_graph, target_query = mapper._typed_graph_shadow[0]
    assert any(
        edge.caller == "app.handler" and edge.callee == "app.helper" for edge in target_graph.edges
    )
    assert any(item.occurrence.symbol == "app.handler" for item in target_query.evidence)
    target_comparison, baseline_comparison = mapper._typed_graph_shadow_comparison
    assert target_comparison.side == "target"
    assert baseline_comparison.side == "baseline"
    assert len(target_comparison.graph_occurrence_ids) == 2
    assert len(baseline_comparison.graph_occurrence_ids) == 2
    assert target_comparison.direct_evidence
    assert baseline_comparison.direct_evidence
    assert all(
        (
            row.caller_span.module,
            row.caller_span.start_line,
            row.caller_span.start_column,
            row.caller_span.end_line,
            row.caller_span.end_column,
        )
        == ("app", 6, 29, 6, 37)
        for row in target_comparison.direct_evidence
    )
    assert all(
        row.changed_span is not None and row.changed_span.start_line == 3
        for row in target_comparison.direct_evidence
    )
    assert all(
        row.changed_span is not None and row.changed_span.start_line == 3
        for row in baseline_comparison.direct_evidence
    )
    assert "not a parity oracle" in target_comparison.comparison_scope
    assert report.candidate_endpoints == report.affected_endpoints


def test_public_git_rename_keeps_side_bound_direct_occurrences(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app_source = (
        "from fastapi import FastAPI\nfrom routes import shared\napp = FastAPI()\n"
        "@app.get('/second')\n@app.get('/first')\n"
        "def handler() -> int: return shared()\n"
    )
    (repo / "app.py").write_text(app_source, encoding="utf-8")
    helper_source = (
        "def stable_one() -> int: return 1\n"
        "def stable_two() -> int: return 2\n"
        "def shared() -> int: return 1\n"
        "def stable_three() -> int: return 3\n"
        "def stable_four() -> int: return 4\n"
        "def stable_five() -> int: return 5\n"
        "def stable_six() -> int: return 6\n"
        "def stable_seven() -> int: return 7\n"
    )
    (repo / "routes.py").write_text(helper_source, encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "GH107 fixture"], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "app.py", "routes.py"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "baseline"], check=True)
    baseline = tmp_path / "baseline"
    baseline.mkdir()
    archive = subprocess.run(
        ["git", "-C", str(repo), "archive", "HEAD"], check=True, capture_output=True
    )
    archive_path = tmp_path / "baseline.tar"
    archive_path.write_bytes(archive.stdout)
    with tarfile.open(archive_path) as bundle:
        bundle.extractall(baseline, filter="data")
    (repo / "app.py").write_text(
        app_source.replace("from routes", "from handlers"),
        encoding="utf-8",
    )
    (repo / "routes.py").rename(repo / "handlers.py")
    (repo / "handlers.py").write_text(
        helper_source.replace("shared() -> int: return 1", "shared() -> int: return 2"),
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    diff = subprocess.run(
        ["git", "-C", str(repo), "diff", "--cached", "--find-renames", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert "rename from routes.py" in diff and "rename to handlers.py" in diff

    mapper = ChangeMapper(
        repo / "app.py",
        secure_ast=True,
        use_cache=False,
        baseline_app_path=baseline / "app.py",
        typed_graph_shadow=True,
    )
    report = mapper.analyze_diff(diff)
    assert report.candidate_endpoints == report.affected_endpoints
    comparisons = {item.side: item for item in mapper._typed_graph_shadow_comparison}
    assert set(comparisons) == {"target", "baseline"}
    assert len(comparisons["target"].graph_occurrence_ids) == 2
    assert len(comparisons["baseline"].graph_occurrence_ids) == 2
    assert comparisons["target"].direct_evidence
    assert comparisons["baseline"].direct_evidence
    assert {row.changed_span.module for row in comparisons["target"].direct_evidence} == {
        "handlers"
    }
    assert {row.changed_span.module for row in comparisons["baseline"].direct_evidence} == {
        "routes"
    }
    assert all(row.caller_span.module == "app" for row in comparisons["target"].direct_evidence)
    assert all(row.caller_span.module == "app" for row in comparisons["baseline"].direct_evidence)


def _public_mapper_fixture(tmp_path: Path, **kwargs: object) -> tuple[ChangeMapper, str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    app = tmp_path / "app.py"
    app.write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "def helper() -> int: return 1\n"
        "@app.get('/')\n"
        "def handler() -> int: return helper()\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(app, secure_ast=True, use_cache=False, **kwargs)
    diff = (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -3,1 +3,1 @@\n"
        "-def helper() -> int: return 0\n"
        "+def helper() -> int: return 1\n"
    )
    return mapper, diff


def test_shadow_is_opt_in_and_disabled_run_clears_previous_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mapper, diff = _public_mapper_fixture(tmp_path)

    def forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError("default mapper called typed graph diagnostic")

    mapper._typed_graph_shadow = (("stale", object(), object()),)
    monkeypatch.setattr(change_mapper_module, "build_shadow_graph", forbidden)
    report = mapper.analyze_diff(diff)
    assert report.candidate_endpoints == report.affected_endpoints
    assert mapper._typed_graph_shadow == ()


@pytest.mark.parametrize("failure", [KeyError("adapter"), AttributeError("query")])
def test_shadow_ordinary_failures_do_not_abort_authoritative_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: Exception
) -> None:
    mapper, diff = _public_mapper_fixture(tmp_path, typed_graph_shadow=True)

    def broken(*args: object, **kwargs: object) -> object:
        raise failure

    mapper._typed_graph_shadow = (("stale", object(), object()),)
    monkeypatch.setattr(change_mapper_module, "build_shadow_graph", broken)
    report = mapper.analyze_diff(diff)
    mapper.typed_graph_shadow = False
    expected = mapper.analyze_diff(diff)
    assert report.candidate_endpoints == expected.candidate_endpoints
    assert report.affected_endpoints == expected.affected_endpoints
    assert report.endpoint_lifecycle == expected.endpoint_lifecycle
    assert report.errors == expected.errors
    assert report.warnings == expected.warnings
    assert report.analysis_completeness == expected.analysis_completeness
    assert mapper._typed_graph_shadow == ()


def test_shadow_baseline_failure_isolated_and_does_not_retain_target_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target_root = tmp_path / "target"
    baseline_root = tmp_path / "baseline"
    target_root.mkdir()
    baseline_root.mkdir()
    app_text = (
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "def helper() -> int: return 1\n"
        "@app.get('/')\n"
        "def handler() -> int: return helper()\n"
    )
    target_app = target_root / "app.py"
    baseline_app = baseline_root / "app.py"
    target_app.write_text(app_text, encoding="utf-8")
    baseline_app.write_text(app_text.replace("return 1", "return 0"), encoding="utf-8")
    mapper = ChangeMapper(
        target_app,
        secure_ast=True,
        use_cache=False,
        baseline_app_path=baseline_app,
        typed_graph_shadow=True,
    )
    original = change_mapper_module.build_shadow_graph
    calls = 0

    def target_ok_baseline_broken(analyzer: MypyAnalyzer, *args: object, **kwargs: object):
        nonlocal calls
        calls += 1
        if analyzer is mapper.baseline_mypy_analyzer:
            raise KeyError("baseline adapter")
        return original(analyzer, *args, **kwargs)

    monkeypatch.setattr(change_mapper_module, "build_shadow_graph", target_ok_baseline_broken)
    diff = (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -3,1 +3,1 @@\n"
        "-def helper() -> int: return 0\n"
        "+def helper() -> int: return 1\n"
    )
    report = mapper.analyze_diff(diff)
    assert calls == 2
    assert report.candidate_endpoints == report.affected_endpoints
    assert mapper._typed_graph_shadow == ()
    assert mapper._typed_graph_shadow_comparison == ()


@pytest.mark.parametrize("failing_side", ["target", "baseline"])
def test_shadow_query_failures_are_isolated_on_both_sides(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failing_side: str
) -> None:
    target_root = tmp_path / "target"
    baseline_root = tmp_path / "baseline"
    target_root.mkdir()
    baseline_root.mkdir()
    app_text = (
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "def helper() -> int: return 1\n"
        "@app.get('/')\n"
        "def handler() -> int: return helper()\n"
    )
    target_app = target_root / "app.py"
    baseline_app = baseline_root / "app.py"
    target_app.write_text(app_text, encoding="utf-8")
    baseline_app.write_text(app_text.replace("return 1", "return 0"), encoding="utf-8")
    mapper = ChangeMapper(
        target_app,
        secure_ast=True,
        use_cache=False,
        baseline_app_path=baseline_app,
        typed_graph_shadow=True,
    )
    original = change_mapper_module.query_changed_lines

    def query_with_failure(*args: object, **kwargs: object):
        if kwargs.get("side") == failing_side:
            raise AttributeError(f"{failing_side} query")
        return original(*args, **kwargs)

    monkeypatch.setattr(change_mapper_module, "query_changed_lines", query_with_failure)
    mapper._typed_graph_shadow = (("stale", object(), object()),)
    diff = (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -3,1 +3,1 @@\n"
        "-def helper() -> int: return 0\n"
        "+def helper() -> int: return 1\n"
    )
    report = mapper.analyze_diff(diff)
    mapper.typed_graph_shadow = False
    expected = mapper.analyze_diff(diff)
    assert report.candidate_endpoints == expected.candidate_endpoints
    assert report.affected_endpoints == expected.affected_endpoints
    assert report.endpoint_lifecycle == expected.endpoint_lifecycle
    assert report.errors == expected.errors
    assert report.warnings == expected.warnings
    assert report.analysis_completeness == expected.analysis_completeness
    assert mapper._typed_graph_shadow == ()


def test_shadow_does_not_swallow_process_interrupts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mapper, diff = _public_mapper_fixture(tmp_path, typed_graph_shadow=True)

    def interrupted(*args: object, **kwargs: object) -> object:
        raise KeyboardInterrupt

    monkeypatch.setattr(change_mapper_module, "build_shadow_graph", interrupted)
    with pytest.raises(KeyboardInterrupt):
        mapper.analyze_diff(diff)


def test_dependency_candidates_keep_route_occurrences_and_call_spans(
    tmp_path: Path,
) -> None:
    app = tmp_path / "app.py"
    app.write_text(
        "from fastapi import FastAPI\n"
        "from fastapi.params import Depends as Need, Security as Guard\n"
        "app = FastAPI()\n"
        "def first() -> int: return 1\n"
        "def second() -> int: return 2\n"
        "@app.get('/first')\n"
        "@app.get('/second')\n"
        "def handler(a: int = Need(dependency=first), "
        "b: int = Guard(second, scopes=['x'])) -> int: return a + b\n",
        encoding="utf-8",
    )
    inventory = build_source_inventory(tmp_path)
    analyzer = MypyAnalyzer(app, module_root=tmp_path, source_inventory=inventory)
    analyzer._ensure_mypy_built()
    endpoints = [
        Endpoint(
            path=path,
            methods=[EndpointMethod.GET],
            handler=HandlerInfo(name="handler", module="app", file_path=app, line_number=8),
        )
        for path in ("/first", "/second")
    ]

    graph = build_shadow_graph(analyzer, inventory, endpoints)

    assert graph.source_dependency_bindings == ()
    rows = graph.source_dependency_uncertainties
    assert len(rows) == 4
    assert {row.occurrence_id for row in rows} == {
        binding.occurrence_id for binding in graph.endpoint_bindings
    }
    assert {row.reason_code for row in rows} == {"fastapi_selector_origin_unverified"}
    assert {row.source_spelling for row in rows} == {"Need", "Guard"}
    line = app.read_text(encoding="utf-8").splitlines()[7]
    assert {(row.span.start_line, row.span.start_column) for row in rows} == {
        (8, line.index("Need(")),
        (8, line.index("Guard(")),
    }
    excerpts = {line[row.span.start_column : row.span.end_column] for row in rows}
    assert "Need(dependency=first)" in excerpts
    assert "Guard(second, scopes=['x'])" in excerpts
    assert any("selector source ownership" in item for item in graph.limitations)


def test_project_local_depends_spelling_is_reported_as_shadow(tmp_path: Path) -> None:
    app = tmp_path / "app.py"
    app.write_text(
        "def Depends(value: object) -> object: return value\n"
        "def provider() -> int: return 1\n"
        "def handler(value: int = Depends(provider)) -> int: return value\n",
        encoding="utf-8",
    )
    inventory = build_source_inventory(tmp_path)
    analyzer = MypyAnalyzer(app, module_root=tmp_path, source_inventory=inventory)
    analyzer._ensure_mypy_built()
    endpoint = Endpoint(
        path="/",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(name="handler", module="app", file_path=app, line_number=3),
    )

    graph = build_shadow_graph(analyzer, inventory, [endpoint])

    assert graph.source_dependency_bindings == ()
    assert any(
        row.reason_code == "dependency_selector_project_shadow"
        for row in graph.source_dependency_uncertainties
    )


def test_dependency_calls_in_handler_body_are_outside_signature_scan(
    tmp_path: Path,
) -> None:
    app = tmp_path / "app.py"
    app.write_text(
        "from fastapi import FastAPI\n"
        "from fastapi.params import Depends\n"
        "app = FastAPI()\n"
        "def provider() -> int: return 1\n"
        "@app.get('/')\n"
        "def handler() -> object: return Depends(provider)\n",
        encoding="utf-8",
    )
    inventory = build_source_inventory(tmp_path)
    analyzer = MypyAnalyzer(app, module_root=tmp_path, source_inventory=inventory)
    analyzer._ensure_mypy_built()
    endpoint = Endpoint(
        path="/",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(name="handler", module="app", file_path=app, line_number=6),
    )

    graph = build_shadow_graph(analyzer, inventory, [endpoint])

    assert graph.source_dependency_bindings == ()
    assert graph.source_dependency_uncertainties == ()


def test_signature_dependency_call_budget_is_enforced_before_return(monkeypatch: Any) -> None:
    parsed = ast.parse("def handler(value = Depends(Depends(provider))): pass")
    function = parsed.body[0]
    assert isinstance(function, ast.FunctionDef)
    monkeypatch.setattr(graph_bridge, "_MAX_DEPENDENCY_CALLS_PER_HANDLER", 1)
    with pytest.raises(TypedGraphBridgeError, match="call budget"):
        graph_bridge._signature_dependency_calls(function, {})
