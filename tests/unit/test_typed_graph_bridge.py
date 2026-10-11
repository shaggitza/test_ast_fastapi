"""Production bridge checks against the analyzer's retained ordinary mypy build."""

from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer import change_mapper as change_mapper_module
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
        "@app.get('/')\n"
        "def handler() -> int: return helper()\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(app, secure_ast=True, use_cache=False, typed_graph_shadow=True)
    diff = (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -3,1 +3,1 @@\n"
        "-def helper() -> int: return 0\n"
        "+def helper() -> int: return 1\n"
    )

    report = mapper.analyze_diff(diff)

    assert len(mapper._typed_graph_shadow) == 1
    side, graph, query = mapper._typed_graph_shadow[0]
    assert side == "target"
    assert any(edge.caller == "app.handler" and edge.callee == "app.helper" for edge in graph.edges)
    assert any(item.occurrence.symbol == "app.handler" for item in query.evidence)
    assert report.candidate_endpoints == report.affected_endpoints


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
