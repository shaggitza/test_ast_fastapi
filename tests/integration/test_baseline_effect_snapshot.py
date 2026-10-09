"""Removed dependency effects are read from their independent baseline snapshot."""

from __future__ import annotations

from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.models.report import (
    ChangeEffectKind,
    ConfidenceLevel,
    EvidenceProducer,
)


@pytest.mark.parametrize(
    ("baseline_service", "target_service", "service_hunk", "expects_baseline_effect"),
    [
        (
            """def dispatch(payload: dict[str, str]) -> int:
    payload["model"] = "baseline"
    return 1
""",
            """def dispatch(payload: dict[str, str]) -> int:
    payload = {**payload}
    payload["model"] = "target"
    return 1
""",
            """@@ -1,3 +1,4 @@
 def dispatch(payload: dict[str, str]) -> int:
-    payload["model"] = "baseline"
-    return 1
+    payload = {**payload}
+    payload["model"] = "target"
+    return 1
""",
            False,
        ),
        (
            """def dispatch(payload: dict[str, str]) -> int:
    payload = {**payload}
    payload["model"] = "baseline"
    return 1
""",
            """def dispatch(payload: dict[str, str]) -> int:
    payload["model"] = "target"
    return 1
""",
            """@@ -1,4 +1,3 @@
 def dispatch(payload: dict[str, str]) -> int:
-    payload = {**payload}
-    payload["model"] = "baseline"
+    payload["model"] = "target"
     return 1
""",
            True,
        ),
    ],
    ids=["ignore-target-only-copy-at-old-line", "recognize-baseline-copy"],
)
def test_removed_effect_lines_use_baseline_source_and_callers(
    tmp_path: Path,
    baseline_service: str,
    target_service: str,
    service_hunk: str,
    expects_baseline_effect: bool,
) -> None:
    baseline_root = tmp_path / "baseline"
    target_root = tmp_path / "target"
    baseline_root.mkdir()
    target_root.mkdir()
    baseline_main = """from fastapi import FastAPI
from service import dispatch

app = FastAPI()

@app.get('/items')
def items():
    payload = {'model': 'preset'}
    dispatch(payload)
    return payload
"""
    target_main = """from fastapi import FastAPI

app = FastAPI()

@app.get('/items')
def items():
    payload = {'model': 'preset'}
    return payload
"""
    (baseline_root / "main.py").write_text(baseline_main, encoding="utf-8")
    (target_root / "main.py").write_text(target_main, encoding="utf-8")
    (baseline_root / "service.py").write_text(baseline_service, encoding="utf-8")
    (target_root / "service.py").write_text(target_service, encoding="utf-8")
    diff = f"""diff --git a/service.py b/service.py
--- a/service.py
+++ b/service.py
{service_hunk}"""

    report = ChangeMapper(
        target_root / "main.py",
        baseline_app_path=baseline_root / "main.py",
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)
    assert not report.errors
    candidate = next(
        item for item in report.candidate_endpoints if item.endpoint.identifier == "GET /items"
    )
    data_flow = [
        item for item in candidate.effect_evidence if item.producer == EvidenceProducer.DATA_FLOW
    ]

    if expects_baseline_effect:
        assert candidate.confidence == ConfidenceLevel.HIGH
        assert len(data_flow) == 1
        assert data_flow[0].effect == ChangeEffectKind.ARGUMENT_MUTATION_ISOLATED
        assert data_flow[0].changed_location is not None
        assert (
            Path(data_flow[0].changed_location.file_path).resolve()
            == (baseline_root / "service.py").resolve()
        )
    else:
        assert candidate.confidence == ConfidenceLevel.MEDIUM
        assert not data_flow
