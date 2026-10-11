"""Complete contract coverage requires an untruncated endpoint call corpus."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from fastapi_endpoint_detector.analyzer import change_mapper
from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.analyzer.mypy_analyzer import (
    AnalysisLimitation,
    EndpointDependencies,
)


def _mapper(dependencies: EndpointDependencies) -> SimpleNamespace:
    return SimpleNamespace(
        _effect_contracts=object(),
        inventory=SimpleNamespace(endpoints=[object()]),
        mypy_analyzer=SimpleNamespace(
            get_endpoint_dependencies=lambda _endpoint: dependencies,
            resolver_version="1.19.1",
            verified_mypy_source_hashes={},
            verified_package_source_hashes={},
            verified_package_versions={},
        ),
        config=SimpleNamespace(
            parser=SimpleNamespace(max_depth=3),
            analysis=SimpleNamespace(track_transitive=False),
        ),
        app_path=Path("/project"),
        use_cache=False,
    )


@pytest.mark.parametrize("state", ["analysis_incomplete", "analysis_limitations", "build_failed"])
def test_limited_endpoint_corpus_cannot_produce_complete_audit(
    monkeypatch: pytest.MonkeyPatch, state: str
) -> None:
    dependencies = EndpointDependencies("GET /", ["GET"], "/")
    if state == "analysis_limitations":
        dependencies.analysis_limitations = [
            AnalysisLimitation("/project/main.py", 1, "MAX_AST_WALK_NODES", limit=1)
        ]
    else:
        setattr(dependencies, state, True)

    def unexpected_audit(*_args: object, **_kwargs: object) -> None:
        pytest.fail("a limited call corpus reached the complete-coverage auditor")

    monkeypatch.setattr(change_mapper, "audit_effect_contracts", unexpected_audit)
    assert ChangeMapper._build_effect_contract_audit(_mapper(dependencies)) is None


def test_complete_corpus_retains_audit_and_leaves_target_python_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dependencies = EndpointDependencies("GET /", ["GET"], "/")
    calls = []
    sentinel = object()

    def record_audit(*_args: object, **kwargs: object) -> object:
        calls.append(kwargs)
        return sentinel

    monkeypatch.setattr(change_mapper, "audit_effect_contracts", record_audit)
    assert ChangeMapper._build_effect_contract_audit(_mapper(dependencies)) is sentinel
    assert len(calls) == 1
    assert calls[0]["endpoint_call_sites"][0][1] == []
    assert "target_python_version" not in calls[0]
