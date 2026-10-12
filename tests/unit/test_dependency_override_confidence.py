"""Keep declared dependency paths conditional when runtime overrides are visible."""

from pathlib import Path

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.models.diff import ChangeType, DiffFile
from fastapi_endpoint_detector.models.endpoint import (
    DependencyGraphLimitation,
    DependencyGraphStatus,
    Endpoint,
)
from fastapi_endpoint_detector.models.report import ConfidenceLevel
from fastapi_endpoint_detector.parser.fastapi_extractor import FastAPIExtractor

PROVIDERS = """from fastapi import Depends

def leaf() -> int:
    return 1

def nested() -> int:
    return leaf()

def original(value: int = Depends(nested)) -> int:
    return value

def replacement_leaf() -> int:
    return 2

def replacement() -> int:
    return replacement_leaf()

def sibling() -> int:
    return 3
"""
APP = """from fastapi import Depends, FastAPI
from providers import original, replacement, sibling

app = FastAPI()
child = FastAPI()

@app.get('/conditional')
def handler(value: int = Depends(original)) -> int:
    return value

@child.get('/stable')
def stable(value: int = Depends(sibling)) -> int:
    return value

app.dependency_overrides[original] = replacement
app.mount('/child', child)
"""


def _routes(tmp_path: Path, *, direct_call: bool = False) -> dict[str, Endpoint]:
    (tmp_path / "providers.py").write_text(PROVIDERS, encoding="utf-8")
    source = APP
    if direct_call:
        source = source.replace("    return value", "    return original()", 1)
    main = tmp_path / "main.py"
    main.write_text(source, encoding="utf-8")
    return {endpoint.path: endpoint for endpoint in FastAPIExtractor(main).extract_endpoints()}


def _line(source: str, exact: str) -> int:
    return source.splitlines().index(exact) + 1


def test_declared_override_closure_is_low_and_does_not_invent_replacement(
    tmp_path: Path,
) -> None:
    endpoint = _routes(tmp_path)["/conditional"]
    graph = endpoint.dependency_graph
    assert graph is not None and graph.semantics == "declared"
    assert graph.status == DependencyGraphStatus.CONDITIONAL
    assert "dependency_overrides_visible" in {item.code for item in graph.limitations}

    deps = MypyAnalyzer(tmp_path, max_depth=6).analyze_endpoint(endpoint)

    for source_line in (
        "def original(value: int = Depends(nested)) -> int:",
        "    return value",
        "def nested() -> int:",
        "    return leaf()",
        "def leaf() -> int:",
        "    return 1",
    ):
        line = _line(PROVIDERS, source_line)
        assert deps.references_lines("providers.py", {line}) == {line}
        assert deps.references_lines_low_only("providers.py", {line})
    for source_line in (
        "def replacement_leaf() -> int:",
        "    return 2",
        "def replacement() -> int:",
        "    return replacement_leaf()",
        "def sibling() -> int:",
        "    return 3",
    ):
        assert not deps.references_lines("providers.py", {_line(PROVIDERS, source_line)})
    assert deps.analysis_incomplete
    assert {item.cap for item in deps.analysis_limitations} == {"DEPENDENCY_OVERRIDES_UNMODELED"}
    assert endpoint.dependency_graph == graph


def test_override_dependency_change_maps_low(tmp_path: Path) -> None:
    endpoint = _routes(tmp_path)["/conditional"]
    analyzer = MypyAnalyzer(tmp_path, max_depth=6)
    analyzer.analyze_endpoint(endpoint)
    mapper = ChangeMapper(tmp_path)
    mapper._mypy_analyzer = analyzer

    result = mapper._check_mypy_dependency(
        endpoint,
        DiffFile(path=Path("providers.py"), change_type=ChangeType.MODIFIED),
        [_line(PROVIDERS, "    return 1")],
        [],
    )

    assert result is not None
    assert result.confidence == ConfidenceLevel.LOW
    assert result.reason.startswith("LOW conditional reachability")


def test_direct_handler_invocation_retains_independent_strong_evidence(tmp_path: Path) -> None:
    endpoint = _routes(tmp_path, direct_call=True)["/conditional"]
    deps = MypyAnalyzer(tmp_path, max_depth=6).analyze_endpoint(endpoint)

    for source_line in (
        "def original(value: int = Depends(nested)) -> int:",
        "    return value",
    ):
        line = _line(PROVIDERS, source_line)
        assert deps.references_lines("providers.py", {line}) == {line}
        assert not deps.references_lines_low_only("providers.py", {line})
    assert any(
        ref.symbol_name == "providers.original" and ref.low_confidence
        for ref in deps.referenced_symbols
    )
    assert any(
        ref.symbol_name == "providers.original" and not ref.low_confidence
        for ref in deps.referenced_symbols
    )
    assert {item.cap for item in deps.analysis_limitations} == {"DEPENDENCY_OVERRIDES_UNMODELED"}


def test_mounted_child_with_its_own_empty_override_mapping_stays_strong(tmp_path: Path) -> None:
    routes = _routes(tmp_path)
    endpoint = routes["/child/stable"]
    assert endpoint.dependency_graph is not None
    assert endpoint.dependency_graph.status == DependencyGraphStatus.ESTABLISHED
    analyzer = MypyAnalyzer(tmp_path, max_depth=6)
    conditional = analyzer.analyze_endpoint(routes["/conditional"])
    deps = analyzer.analyze_endpoint(endpoint)
    line = _line(PROVIDERS, "    return 3")

    assert conditional.analysis_incomplete
    assert deps.references_lines("providers.py", {line}) == {line}
    assert not deps.references_lines_low_only("providers.py", {line})
    assert "DEPENDENCY_OVERRIDES_UNMODELED" not in {item.cap for item in deps.analysis_limitations}


def test_other_conditional_graph_limit_does_not_relabel_exact_declared_provider(
    tmp_path: Path,
) -> None:
    endpoint = _routes(tmp_path)["/conditional"]
    assert endpoint.dependency_graph is not None
    graph = endpoint.dependency_graph.model_copy(
        update={
            "limitations": (
                DependencyGraphLimitation(
                    code="depth_cap",
                    source_path=tmp_path / "main.py",
                    source_line=8,
                    reason="Collector stopped below its bounded dependency depth",
                ),
            )
        }
    )
    endpoint = endpoint.model_copy(update={"dependency_graph": graph})
    deps = MypyAnalyzer(tmp_path, max_depth=6).analyze_endpoint(endpoint)
    line = _line(PROVIDERS, "    return 1")

    assert deps.references_lines("providers.py", {line}) == {line}
    assert not deps.references_lines_low_only("providers.py", {line})
    assert "DEPENDENCY_OVERRIDES_UNMODELED" not in {item.cap for item in deps.analysis_limitations}
