"""Tests for the bounded synthetic Pyright/mypy provider harness."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from benchmarks.providers import pyright_differential as harness


def test_rejects_malformed_pyright_json() -> None:
    with pytest.raises(harness.EvaluationError, match="malformed Pyright JSON"):
        harness._read_pyright("not-json", Path("/tmp/fixture"))


def test_rejects_stale_source_hashes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixtures = tmp_path / "fixtures"
    results = tmp_path / "results"
    fixture = fixtures / "sample"
    fixture.mkdir(parents=True)
    (fixture / "case.py").write_text("x = 1\n", encoding="utf-8")
    results.mkdir()
    (results / "sample.json").write_text(
        json.dumps(
            {"schema": "pyright-mypy-differential-v1", "fixture": "sample", "source_sha256": {}}
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(harness, "FIXTURES", fixtures)
    monkeypatch.setattr(harness, "RESULTS", results)
    with pytest.raises(harness.EvaluationError, match="stale source hashes"):
        harness.verify_records()


def test_timeout_is_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    def timeout(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired("pyright", 1)

    monkeypatch.setattr(harness.subprocess, "run", timeout)
    with pytest.raises(harness.EvaluationError, match="timed out"):
        harness._run(["pyright"], Path(), timeout=1)


def test_cli_records_definition_and_execution_as_unsupported() -> None:
    record = harness.evaluate(
        "callable",
        "/tmp/pyright-differential/node_modules/.bin/pyright",
        shutil.which("mypy") or "mypy",
        write=False,
    )
    unsupported = {item["query"] for item in record["unsupported"]}
    assert {"definition_target", "execution_or_reachability"} <= unsupported
    assert record["engines"]["pyright"].endswith(harness.PYRIGHT_VERSION)


def test_comparison_does_not_treat_absence_as_equivalence() -> None:
    result = harness._compare([], [])
    assert result["absence_is_not_equivalence"] is True
