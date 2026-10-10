"""Bounded traversal does not erase independent or possible source evidence."""

from difflib import unified_diff
from pathlib import Path

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.analyzer.mypy_analyzer import (
    EndpointDependencies,
    SourceEvidenceSpan,
)
from fastapi_endpoint_detector.config import AnalysisConfig, Config, ParserConfig
from fastapi_endpoint_detector.models.diff import ChangedByteSpan
from fastapi_endpoint_detector.models.report import ConfidenceLevel
from fastapi_endpoint_detector.parser.diff_parser import DiffParser


def _diff(before: str, after: str, name: str) -> str:
    return f"diff --git a/{name} b/{name}\n" + "".join(
        unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{name}",
            tofile=f"b/{name}",
            n=0,
        )
    )


def test_possible_lambda_body_edit_is_not_suppressed() -> None:
    before = "def service(flag):\n    callback = lambda: 1\n    if flag: callback()\n"
    after = before.replace("lambda: 1", "lambda: 2")
    diff_file = DiffParser.parse_string(_diff(before, after, "service.py"))[0]
    deps = EndpointDependencies(
        endpoint_id="endpoint", methods=["GET"], path="/one", project_files={"service.py"}
    )
    for state in ("deferred_execution", "possible_execution"):
        deps.source_evidence_spans.append(SourceEvidenceSpan("service.py", 2, 23, 2, 24, state))
    assert not ChangeMapper._change_is_deferred_lambda_only(deps, diff_file, {2}, side="target")
    deps.source_evidence_spans.pop()
    assert ChangeMapper._change_is_deferred_lambda_only(deps, diff_file, {2}, side="target")


def test_same_line_edit_does_not_borrow_other_lambda_execution_state() -> None:
    span = SourceEvidenceSpan("service.py", 4, 20, 4, 30, "deferred_execution")
    assert not ChangeMapper._source_span_overlaps_change(span, ChangedByteSpan(4, 40, 41))
    assert ChangeMapper._source_span_overlaps_change(span, ChangedByteSpan(4, 23, 24))
    assert not ChangeMapper._source_span_overlaps_change(span, ChangedByteSpan(4, 30, 31))


def test_direct_handler_edit_remains_high_when_other_traversal_is_bounded(tmp_path: Path) -> None:
    main = tmp_path / "main.py"
    source = (
        "from fastapi import FastAPI\n"
        "from service import deep\n"
        "app = FastAPI()\n"
        "@app.get('/direct')\n"
        "def handler() -> int:\n"
        "    return deep() + 1\n"
    )
    main.write_text(source)
    (tmp_path / "service.py").write_text(
        "def leaf() -> int: return 1\n"
        "def middle() -> int: return leaf()\n"
        "def deep() -> int: return middle()\n"
    )
    mapper = ChangeMapper(
        tmp_path,
        config=Config(
            parser=ParserConfig(max_depth=1),
            analysis=AnalysisConfig(confidence_threshold=0.5),
        ),
        secure_ast=True,
        use_cache=False,
    )
    report = mapper.analyze_diff(_diff(source.replace("+ 1", "+ 0"), source, "main.py"))
    assert report.analysis_limitations
    assert [item.endpoint.path for item in report.affected_endpoints] == ["/direct"]
    assert report.affected_endpoints[0].confidence == ConfidenceLevel.HIGH


def test_public_mapper_retains_conditional_lambda_body_edit(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline"
    target = tmp_path / "target"
    baseline.mkdir()
    target.mkdir()
    app_source = (
        "from fastapi import FastAPI\n"
        "from service import run\n"
        "app = FastAPI()\n"
        "@app.get('/conditional')\n"
        "def handler() -> int: return run(True)\n"
    )
    before = (
        "def run(flag: bool) -> int:\n"
        "    callback = lambda: 1\n"
        "    if flag:\n"
        "        return callback()\n"
        "    return 0\n"
    )
    after = before.replace("lambda: 1", "lambda: 2")
    for root, service in ((baseline, before), (target, after)):
        (root / "main.py").write_text(app_source)
        (root / "service.py").write_text(service)
    report = ChangeMapper(
        target,
        baseline_app_path=baseline,
        secure_ast=True,
        use_cache=False,
        config=Config(analysis=AnalysisConfig(confidence_threshold=0.0)),
    ).analyze_diff(_diff(before, after, "service.py"))
    assert [item.endpoint.path for item in report.candidate_endpoints] == ["/conditional"]
    assert any(
        evidence.execution_state == "possible_execution"
        for candidate in report.candidate_endpoints
        for evidence in candidate.execution_evidence
    )
