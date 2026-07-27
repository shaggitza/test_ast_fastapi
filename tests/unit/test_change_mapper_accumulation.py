"""Focused tests for deterministic affected/orphan evidence accumulation."""

import json
from pathlib import Path

import pytest
import yaml

from fastapi_endpoint_detector.analyzer.change_mapper import (
    _CONFIDENCE_SCORE,
    ChangeMapper,
    _endpoint_result_key,
    _merge_affected,
    _normalized_diff_path,
    _OrphanAccumulator,
    _scip_confidence,
)
from fastapi_endpoint_detector.analyzer.scip_analyzer import SCIPDefinition
from fastapi_endpoint_detector.models.endpoint import (
    Endpoint,
    EndpointDiscoveryCondition,
    EndpointDiscoveryStatus,
    EndpointInventory,
    EndpointMethod,
    HandlerInfo,
    InventoryStatus,
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


def test_inventory_strength_requires_source_backed_limitations(tmp_path: Path) -> None:
    condition = EndpointDiscoveryCondition(
        source_path=tmp_path / "main.py", source_line=1, reason="unknown plugin"
    )

    assert EndpointInventory().status == InventoryStatus.ESTABLISHED
    with pytest.raises(ValueError, match="established inventory forbids limitations"):
        EndpointInventory(status=InventoryStatus.CONDITIONAL)
    with pytest.raises(ValueError, match="established inventory forbids limitations"):
        EndpointInventory(limitations=(condition,))
    with pytest.raises(ValueError, match="only conditional endpoints"):
        EndpointInventory(
            endpoints=[_endpoint(tmp_path / "main.py")],
            status=InventoryStatus.UNAVAILABLE,
            limitations=(condition,),
        )


def test_endpoint_discovery_provenance_requires_consistent_status(tmp_path: Path) -> None:
    established = _endpoint(tmp_path / "main.py")
    condition = EndpointDiscoveryCondition(
        source_path=tmp_path / "main.py", source_line=9, reason="unknown helper"
    )

    with pytest.raises(ValueError, match="conditional discovery requires conditions"):
        Endpoint.model_validate({**established.model_dump(), "discovery_status": "conditional"})
    with pytest.raises(ValueError, match="conditional discovery requires conditions"):
        Endpoint.model_validate({**established.model_dump(), "discovery_conditions": [condition]})
    with pytest.raises(ValueError, match="must not be blank"):
        EndpointDiscoveryCondition(source_path=tmp_path / "main.py", source_line=9, reason="  ")


def test_conditional_discovery_caps_confidence_at_low(tmp_path: Path) -> None:
    endpoint = _endpoint(tmp_path / "main.py").model_copy(
        update={
            "discovery_status": EndpointDiscoveryStatus.CONDITIONAL,
            "discovery_conditions": (
                EndpointDiscoveryCondition(
                    source_path=tmp_path / "main.py",
                    source_line=9,
                    reason="unknown helper may mutate app",
                ),
            ),
        }
    )
    accumulated = {}

    _merge_affected(
        accumulated,
        _candidate(endpoint, ConfidenceLevel.HIGH, ["direct"], "change.py", 1),
    )

    result = next(iter(accumulated.values())).materialize()
    assert result.confidence == ConfidenceLevel.LOW
    assert result.endpoint.discovery_status == EndpointDiscoveryStatus.CONDITIONAL


def test_established_discovery_dominates_conditional_in_both_orders(tmp_path: Path) -> None:
    established = _endpoint(tmp_path / "main.py")
    conditional = established.model_copy(
        update={
            "discovery_status": EndpointDiscoveryStatus.CONDITIONAL,
            "discovery_conditions": (
                EndpointDiscoveryCondition(
                    source_path=tmp_path / "main.py",
                    source_line=9,
                    reason="unknown helper may mutate app",
                ),
            ),
        }
    )

    for first, second in [(conditional, established), (established, conditional)]:
        accumulated = {}
        _merge_affected(
            accumulated,
            _candidate(first, ConfidenceLevel.HIGH, ["first"], "a.py", 1),
        )
        _merge_affected(
            accumulated,
            _candidate(second, ConfidenceLevel.HIGH, ["second"], "b.py", 2),
        )
        result = next(iter(accumulated.values())).materialize()
        assert result.endpoint.discovery_status == EndpointDiscoveryStatus.ESTABLISHED
        assert result.confidence == ConfidenceLevel.HIGH


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


def test_transitive_scip_references_are_low_confidence_unless_direct() -> None:
    structural = SCIPDefinition("class", "module:Config", Path("module.py"), 1, 20)
    callable_seed = SCIPDefinition("function", "module:load_config()", Path("module.py"), 2, 5)

    assert _scip_confidence(structural, 0) == ConfidenceLevel.LOW
    assert _scip_confidence(structural, 1) == ConfidenceLevel.LOW
    assert _scip_confidence(callable_seed, 0) == ConfidenceLevel.HIGH
    assert _scip_confidence(callable_seed, 1) == ConfidenceLevel.LOW


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


class _NoopMypyAnalyzer:
    def release_typed_snapshot(self) -> None:
        return


class _NoopSCIPAnalyzer:
    def ensure_index(self, *, force: bool = False) -> None:
        assert force


def test_secure_report_propagates_unavailable_target_inventory_on_both_exits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    malformed = tmp_path / "main.py"
    malformed.write_text("def broken(:\n", encoding="utf-8")

    normal = ChangeMapper(malformed, secure_ast=True, use_cache=False)
    monkeypatch.setattr(normal, "_preanalyze_mypy", lambda _callback: None)
    normal._mypy_analyzer = _NoopMypyAnalyzer()  # type: ignore[assignment]
    normal_report = normal.analyze_diff("")

    scip = ChangeMapper(malformed, secure_ast=True, use_scip=True, use_cache=False)
    scip._scip_analyzer = _NoopSCIPAnalyzer()  # type: ignore[assignment]
    scip_report = scip.analyze_diff("")

    for mapper, report in ((normal, normal_report), (scip, scip_report)):
        assert report.inventory_status == InventoryStatus.UNAVAILABLE
        assert report.inventory_status == mapper.inventory.status
        assert report.inventory_limitations == mapper.inventory.limitations
        assert report.inventory_limitations
        assert report.inventory_limitations[0].source_path == malformed.resolve()


def test_runtime_change_mapper_report_leaves_inventory_unset(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app_file = tmp_path / "main.py"
    app_file.write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n",
        encoding="utf-8",
    )
    mapper = ChangeMapper(app_file, use_cache=False)
    monkeypatch.setattr(mapper, "_preanalyze_mypy", lambda _callback: None)
    mapper._mypy_analyzer = _NoopMypyAnalyzer()  # type: ignore[assignment]

    report = mapper.analyze_diff("")

    assert report.inventory_status is None
    assert report.inventory_limitations == ()


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
