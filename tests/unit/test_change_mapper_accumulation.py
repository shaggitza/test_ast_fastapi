"""Focused tests for deterministic affected/orphan evidence accumulation."""

import json
from pathlib import Path

import yaml

from fastapi_endpoint_detector.analyzer.change_mapper import (
    _CONFIDENCE_SCORE,
    _endpoint_result_key,
    _merge_affected,
    _normalized_diff_path,
    _OrphanAccumulator,
)
from fastapi_endpoint_detector.models.endpoint import (
    Endpoint,
    EndpointMethod,
    HandlerInfo,
)
from fastapi_endpoint_detector.models.report import (
    AffectedEndpoint,
    AnalysisReport,
    CallStackFrame,
    ConfidenceLevel,
)
from fastapi_endpoint_detector.output.json_output import JsonFormatter
from fastapi_endpoint_detector.output.yaml_output import YamlFormatter


def _endpoint(file_path: Path, line: int = 5, *, path: str = "/items") -> Endpoint:
    return Endpoint(
        path=path,
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name=f"handler_{line}",
            module="main",
            file_path=file_path,
            line_number=line,
        ),
    )


def _candidate(
    endpoint: Endpoint,
    confidence: ConfidenceLevel,
    chain: list[str],
    changed_file: str,
    stack_line: int,
) -> AffectedEndpoint:
    return AffectedEndpoint(
        endpoint=endpoint,
        confidence=confidence,
        reason=f"{confidence.value} evidence",
        dependency_chain=chain,
        changed_files=[changed_file],
        call_stacks=[
            [
                CallStackFrame(
                    file_path=changed_file,
                    line_number=stack_line,
                    function_name="changed",
                )
            ]
        ],
    )


def test_merges_confidence_files_chains_and_stacks_before_threshold(tmp_path: Path) -> None:
    endpoint = _endpoint(tmp_path / "main.py")
    accumulated = {}
    medium = _candidate(endpoint, ConfidenceLevel.MEDIUM, ["seed-a", "handler"], "a.py", 2)
    high = _candidate(endpoint, ConfidenceLevel.HIGH, ["seed-b", "handler"], "b.py", 4)

    _merge_affected(accumulated, medium)
    _merge_affected(accumulated, high)
    _merge_affected(accumulated, medium)
    result = next(iter(accumulated.values())).materialize()

    assert result.confidence == ConfidenceLevel.HIGH
    assert result.reason == "high evidence"
    assert result.dependency_chain == ["seed-b", "handler"]
    assert result.all_dependency_chains == [
        ["seed-b", "handler"],
        ["seed-a", "handler"],
    ]
    assert result.changed_files == ["a.py", "b.py"]
    assert len(result.call_stacks) == 2
    assert _CONFIDENCE_SCORE[result.confidence] >= 1.0


def test_result_identity_keeps_same_public_route_with_distinct_handlers(tmp_path: Path) -> None:
    first = _endpoint(tmp_path / "first.py", 5)
    second = _endpoint(tmp_path / "second.py", 5)
    accumulated = {}

    _merge_affected(
        accumulated,
        _candidate(first, ConfidenceLevel.MEDIUM, ["a"], "a.py", 1),
    )
    _merge_affected(
        accumulated,
        _candidate(second, ConfidenceLevel.MEDIUM, ["b"], "b.py", 1),
    )

    assert first.identifier == second.identifier
    assert _endpoint_result_key(first) != _endpoint_result_key(second)
    assert len(accumulated) == 2


def test_orphan_evidence_deduplicates_and_subtracts_all_processed_lines() -> None:
    evidence_by_path: dict[str, _OrphanAccumulator] = {}
    for spelling, added, removed, processed in [
        ("./pkg/service.py", {2, 3}, {8}, {2}),
        ("pkg/service.py", {2, 4}, {8, 9}, {4}),
    ]:
        key = _normalized_diff_path(spelling)
        evidence = evidence_by_path.setdefault(key, _OrphanAccumulator(spelling, "unresolved"))
        evidence.added.update(added)
        evidence.removed.update(removed)
        evidence.processed_added.update(processed)
        evidence.processed_removed.add(8)

    assert len(evidence_by_path) == 1
    orphan = next(iter(evidence_by_path.values())).materialize()
    assert orphan is not None
    assert orphan.added_lines == [3]
    assert orphan.removed_lines == [9]
    assert orphan.total_lines == 2


def test_json_and_yaml_preserve_plural_evidence(tmp_path: Path) -> None:
    endpoint = _endpoint(tmp_path / "main.py")
    candidate = _candidate(endpoint, ConfidenceLevel.HIGH, ["primary"], "change.py", 7).model_copy(
        update={"dependency_chains": [["primary"], ["secondary"]]}
    )
    report = AnalysisReport(
        app_path=str(tmp_path),
        diff_source="stdin",
        total_endpoints=1,
        affected_endpoints=[candidate],
    )

    json_result = json.loads(JsonFormatter().format(report))["affected_endpoints"][0]
    yaml_result = yaml.safe_load(YamlFormatter().format(report))["affected_endpoints"][0]

    for result in (json_result, yaml_result):
        assert result["dependency_chain"] == ["primary"]
        assert result["dependency_chains"] == [["primary"], ["secondary"]]
        assert result["call_stacks"][0][0]["line_number"] == 7
