from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.models.report import (
    ConfidenceLevel,
    DataObservationKind,
    EffectDisposition,
)

if TYPE_CHECKING:
    from pathlib import Path


def test_defensive_copy_ranks_observed_and_internal_paths_without_pruning(
    tmp_path: Path,
) -> None:
    service = tmp_path / "service.py"
    service.write_text(
        "def dispatch(payload: dict[str, str]) -> int:\n"
        "    payload = {**payload}\n"
        "    payload['model'] = 'base'\n"
        "    return 1\n"
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from fastapi import FastAPI\n"
        "from service import dispatch\n\n"
        "app = FastAPI()\n\n"
        "@app.get('/observed')\n"
        "def observed():\n"
        "    payload = {'model': 'preset'}\n"
        "    dispatch(payload)\n"
        "    return payload\n\n"
        "@app.get('/internal')\n"
        "def internal():\n"
        "    payload = {'model': 'preset'}\n"
        "    result = dispatch(payload)\n"
        "    return {'result': result}\n"
    )
    diff = (
        "diff --git a/service.py b/service.py\n"
        "--- a/service.py\n"
        "+++ b/service.py\n"
        "@@ -1,3 +1,4 @@\n"
        " def dispatch(payload: dict[str, str]) -> int:\n"
        "+    payload = {**payload}\n"
        "     payload['model'] = 'base'\n"
        "     return 1\n"
    )

    report = ChangeMapper(tmp_path, secure_ast=True, use_cache=False).analyze_diff(diff)

    candidates = {item.endpoint.identifier: item for item in report.candidate_endpoints}
    assert set(candidates) == {"GET /observed", "GET /internal"}
    assert candidates["GET /observed"].confidence == ConfidenceLevel.HIGH
    assert candidates["GET /internal"].confidence == ConfidenceLevel.LOW
    observed = candidates["GET /observed"].effect_evidence[-1]
    internal = candidates["GET /internal"].effect_evidence[-1]
    assert observed.observations == [DataObservationKind.RETURNED]
    assert observed.disposition == EffectDisposition.OBSERVABLE_BEHAVIOR
    assert internal.observations == [DataObservationKind.NOT_OBSERVED_AFTER_CALL]
    assert internal.disposition == EffectDisposition.NOT_OBSERVED_BY_CALLER
    assert {item.endpoint.identifier for item in report.affected_endpoints} == {"GET /observed"}
