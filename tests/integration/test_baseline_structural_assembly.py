"""Removed assembly is interpreted against its independent source snapshot."""

from __future__ import annotations

import difflib
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.models.report import (
    ChangeEffectKind,
    ConfidenceLevel,
    EvidenceProducer,
)


@pytest.mark.parametrize("operation", ["include_router", "mount"])
def test_removed_assembly_maps_exact_baseline_descendants(tmp_path: Path, operation: str) -> None:
    baseline = tmp_path / "baseline"
    target = tmp_path / "target"
    baseline.mkdir()
    target.mkdir()
    constructor = "APIRouter" if operation == "include_router" else "FastAPI"
    assembly = (
        "app.include_router(child)\n"
        if operation == "include_router"
        else "app.mount('/child', child)\n"
    )
    common = (
        "from fastapi import APIRouter, FastAPI\n"
        f"child = {constructor}()\n"
        "@child.get('/items')\n"
        "def items(): return 1\n"
        "@child.post('/other')\n"
        "def other(): return 2\n"
        "app = FastAPI()\n"
        "@app.get('/untouched')\n"
        "def untouched(): return 3\n"
    )
    before = common + assembly
    after = common
    (baseline / "main.py").write_text(before, encoding="utf-8")
    (target / "main.py").write_text(after, encoding="utf-8")
    diff = "diff --git a/main.py b/main.py\n" + "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile="a/main.py",
            tofile="b/main.py",
        )
    )
    report = ChangeMapper(
        target / "main.py",
        baseline_app_path=baseline / "main.py",
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)
    prefix = "" if operation == "include_router" else "/child"
    assert {item.endpoint.identifier for item in report.candidate_endpoints} == {
        f"GET {prefix}/items",
        f"POST {prefix}/other",
    }
    for candidate in report.candidate_endpoints:
        assert candidate.confidence == ConfidenceLevel.HIGH
        structural = [
            item
            for item in candidate.effect_evidence
            if item.producer == EvidenceProducer.STRUCTURAL
        ]
        assert len(structural) == 1
        assert structural[0].effect == ChangeEffectKind.ROUTE_ASSEMBLY
        assert structural[0].changed_location is not None
        assert structural[0].changed_location.file_path == "main.py"
        assert structural[0].changed_location.line_number == 10
    assert not report.orphan_changes
    assert not report.errors


def test_missing_baseline_preserves_target_handler_findings(tmp_path: Path) -> None:
    app = tmp_path / "main.py"
    app.write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/items')\n"
        "def items():\n    return 2\n",
        encoding="utf-8",
    )
    diff = """diff --git a/main.py b/main.py
--- a/main.py
+++ b/main.py
@@ -4,2 +4,2 @@
 def items():
-    return 1
+    return 2
"""
    report = ChangeMapper(
        app, baseline_app_path=tmp_path / "missing.py", secure_ast=True, use_cache=False
    ).analyze_diff(diff)
    assert any(item.endpoint.identifier == "GET /items" for item in report.candidate_endpoints)
    assert report.analysis_completeness == "partial"
    assert report.orphan_changes
    assert any("baseline" in warning.lower() for warning in report.warnings)


def test_recovered_baseline_retries_removed_assembly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    baseline = tmp_path / "baseline"
    target = tmp_path / "target"
    baseline.mkdir()
    target.mkdir()
    common = (
        "from fastapi import APIRouter, FastAPI\n"
        "child = APIRouter()\n"
        "@child.get('/items')\n"
        "def items(): return 1\n"
        "app = FastAPI()\n"
    )
    before = common + "app.include_router(child)\n"
    (baseline / "main.py").write_text(before, encoding="utf-8")
    (target / "main.py").write_text(common, encoding="utf-8")
    diff = "diff --git a/main.py b/main.py\n" + "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            common.splitlines(keepends=True),
            fromfile="a/main.py",
            tofile="b/main.py",
        )
    )
    mapper = ChangeMapper(
        target / "main.py",
        baseline_app_path=baseline / "main.py",
        secure_ast=True,
        use_cache=False,
    )
    preanalyze = mapper._preanalyze_mypy_registry
    attempts = 0

    def transient_failure(*args: object, **kwargs: object) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("temporary baseline analysis failure")
        preanalyze(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(mapper, "_preanalyze_mypy_registry", transient_failure)
    failed = mapper.analyze_diff(diff)
    assert failed.analysis_completeness == "partial"
    assert failed.orphan_changes
    assert not failed.candidate_endpoints
    assert any("temporary baseline analysis failure" in item for item in failed.warnings)

    recovered = mapper.analyze_diff(diff)
    assert attempts == 2
    assert {item.endpoint.identifier for item in recovered.candidate_endpoints} == {"GET /items"}
    assert recovered.candidate_endpoints[0].confidence == ConfidenceLevel.HIGH
    assert recovered.analysis_completeness == "complete"
    assert not recovered.orphan_changes
    assert not recovered.errors
    assert not any("temporary baseline analysis failure" in item for item in recovered.warnings)
