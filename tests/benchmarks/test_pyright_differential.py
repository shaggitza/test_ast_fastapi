"""Adversarial controls for the bounded Pyright/mypy fixture evaluation."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from benchmarks.providers import pyright_differential as harness


def _validation_record(name: str) -> dict[str, Any]:
    """Build a test-only v2 record from the preserved v1 observations."""
    old = json.loads((harness.RESULTS / f"{name}.json").read_text(encoding="utf-8"))
    fixture = harness.FIXTURES / name
    files = harness._fixture_inputs(fixture)
    sources, configs = harness._input_hashes(fixture, files)
    configs["mypy.ini"] = hashlib.sha256(harness._MYPY_CONFIG).hexdigest()
    observations = []
    for raw in old["observations"]:
        item = dict(raw)
        item["end_line"] = item["line"] if item["provider"] == "pyright" else None
        item["end_column"] = item["column"] if item["provider"] == "pyright" else None
        observations.append(item)
    return {
        "schema": "pyright-mypy-differential-v2",
        "fixture": name,
        "source_sha256": sources,
        "config_sha256": configs,
        "engines": old["engines"],
        "provenance": {
            "pyright_command": [
                "/pinned/pyright",
                "--project",
                "<snapshot>/fixture",
                "--outputjson",
            ],
            "mypy_command": [
                "/pinned/mypy",
                "--config-file",
                "<snapshot>/mypy.ini",
                "--no-incremental",
                "--show-error-codes",
                "--no-error-summary",
                "--no-pretty",
                "--follow-imports",
                "silent",
                "<snapshot>/fixture",
            ],
            "fixture_root": name,
            "max_files": harness.MAX_FILES,
            "max_source_bytes": harness.MAX_BYTES,
            "provider_timeout_seconds": harness.TIMEOUT_SECONDS,
            "elapsed_seconds": 1.0,
            "consumed_source_sha256": sources,
            "consumed_config_sha256": configs,
            "working_directory": "<repository-root>",
        },
        "observations": observations,
        "comparison": harness._compare(
            [
                harness.Observation(**row)
                for row in old["observations"]
                if row["provider"] == "pyright"
            ],
            [
                harness.Observation(**row)
                for row in old["observations"]
                if row["provider"] == "mypy"
            ],
        ),
        "unsupported": [
            *old["unsupported"],
            {
                "query": "cross_engine_diagnostic_semantics",
                "status": "unsupported",
                "reason": "Rules and messages remain provider-specific.",
            },
        ],
        "scope": old["scope"],
    }


def _write_complete_v2(directory: Path) -> None:
    directory.mkdir()
    for name in harness.FIXTURE_NAMES:
        payload = json.dumps(_validation_record(name), allow_nan=False, sort_keys=True)
        (directory / f"{name}.json").write_text(payload, encoding="utf-8")


def _validation_record_v3(name: str) -> dict[str, Any]:
    row = _validation_record(name)
    row["schema"] = "pyright-mypy-differential-v3"
    row["provenance"]["pyright_command"][0] = "<pyright-package>/index.js"
    row["provenance"]["mypy_command"][0] = "<mypy-package>/bin/mypy"
    row["provenance"]["provider_artifacts"] = {
        key: {"executable_sha256": "a" * 64, "package_metadata_sha256": "b" * 64}
        for key in ("pyright", "mypy")
    }
    row["provenance"]["max_output_bytes"] = harness.MAX_OUTPUT_BYTES
    return row


def _write_complete_v3(directory: Path) -> None:
    directory.mkdir()
    for name in harness.FIXTURE_NAMES:
        payload = json.dumps(_validation_record_v3(name), allow_nan=False, sort_keys=True)
        (directory / f"{name}.json").write_text(payload, encoding="utf-8")


def test_strict_json_rejects_duplicate_keys_and_non_finite_values() -> None:
    with pytest.raises(harness.EvaluationError, match="duplicate JSON key"):
        harness._loads('{"version":"x","version":"y"}', "test")
    with pytest.raises(harness.EvaluationError, match="non-finite"):
        harness._loads('{"value":NaN}', "test")


def test_pyright_parser_rejects_malformed_output() -> None:
    with pytest.raises(harness.EvaluationError, match="invalid Pyright output JSON"):
        harness._read_pyright("not-json", Path("/tmp/fixture"))


@pytest.mark.skipif(os.name != "posix", reason="provider process groups require POSIX")
def test_timeout_is_explicit(tmp_path: Path) -> None:
    with pytest.raises(harness.EvaluationError, match="timed out"):
        harness._run([sys.executable, "-c", "import time; time.sleep(10)"], tmp_path, timeout=0.1)


def test_version_match_is_exact(monkeypatch: pytest.MonkeyPatch) -> None:
    def reported(
        command: list[str], _cwd: Path, _timeout: int = 25
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            command, 0, "mypy 1.12.0, compatibility string 2.4.0\n", ""
        )

    monkeypatch.setattr(harness, "_run", reported)
    with pytest.raises(harness.EvaluationError, match=r"expected mypy 2\.4\.0"):
        harness._version(["mypy", "--version"], "2.4.0", "mypy")


@pytest.mark.skipif(os.name != "posix", reason="provider process groups require POSIX")
def test_output_is_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(harness, "MAX_OUTPUT_BYTES", 1024)
    script = "import sys; sys.stdout.write('x' * 4096); sys.stdout.flush()"
    with pytest.raises(harness.EvaluationError, match="output exceeded"):
        harness._run([sys.executable, "-c", script], tmp_path, timeout=3)


@pytest.mark.skipif(
    sys.platform != "linux", reason="process-group cleanup control is Linux-specific"
)
def test_timeout_kills_descendant_process_group(tmp_path: Path) -> None:
    pid_file = tmp_path / "descendant.pid"
    child = "import time; time.sleep(30)"
    parent = (
        "import subprocess,sys,time,pathlib; "
        f"p=subprocess.Popen([sys.executable,'-c',{child!r}]); "
        f"pathlib.Path({str(pid_file)!r}).write_text(str(p.pid)); time.sleep(30)"
    )
    with pytest.raises(harness.EvaluationError, match="timed out"):
        harness._run([sys.executable, "-c", parent], tmp_path, timeout=0.3)
    descendant = int(pid_file.read_text())
    time.sleep(0.05)
    status = Path(f"/proc/{descendant}/status")
    assert not status.exists() or "State:\tZ" in status.read_text()


def test_fixture_rejects_out_of_root_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture_root = tmp_path / "fixtures"
    fixture = fixture_root / "sample"
    fixture.mkdir(parents=True)
    outside = tmp_path / "outside.py"
    outside.write_text("value = 1\n", encoding="utf-8")
    (fixture / "escape.py").symlink_to(outside)
    monkeypatch.setattr(harness, "FIXTURES", fixture_root)
    with pytest.raises(harness.EvaluationError, match="symlink"):
        harness._fixture_inputs(fixture)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda row: row["config_sha256"].update({"pyrightconfig.json": "sha256:bad"}),
            "config hashes",
        ),
        (lambda row: row.update(observations="bad"), "observations must be a list"),
        (lambda row: row["provenance"].update(consumed_source_sha256={}), "provenance"),
    ],
)
def test_record_verifier_rejects_unbound_or_malformed_records(
    tmp_path: Path, mutate: Any, message: str
) -> None:
    results = tmp_path / "results"
    _write_complete_v2(results)
    record_path = results / "callable.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    mutate(record)
    record_path.write_text(json.dumps(record, allow_nan=False), encoding="utf-8")
    with pytest.raises(harness.EvaluationError, match=message):
        harness._verify_result_directory(
            results, "pyright-mypy-differential-v2", allow_readme=False
        )


@pytest.mark.parametrize(
    ("provider", "substitute"),
    [("pyright", "/tmp/attacker/pyright"), ("mypy", "/tmp/attacker/mypy")],
)
def test_v3_record_rejects_substituted_executable(
    tmp_path: Path, provider: str, substitute: str
) -> None:
    results = tmp_path / "results-v3"
    _write_complete_v3(results)
    record_path = results / "callable.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["provenance"][f"{provider}_command"][0] = substitute
    record_path.write_text(json.dumps(record, allow_nan=False), encoding="utf-8")
    with pytest.raises(harness.EvaluationError, match="executable/package provenance"):
        harness._verify_result_directory(
            results, "pyright-mypy-differential-v3", allow_readme=False
        )


def test_result_verifier_rejects_empty_or_incomplete_directory(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(harness.EvaluationError, match="empty"):
        harness._verify_result_directory(empty, "pyright-mypy-differential-v2", allow_readme=False)
    incomplete = tmp_path / "incomplete"
    incomplete.mkdir()
    (incomplete / "junk.json").write_text("{}", encoding="utf-8")
    with pytest.raises(harness.EvaluationError, match="exactly cover"):
        harness._verify_result_directory(
            incomplete, "pyright-mypy-differential-v2", allow_readme=False
        )


def test_comparison_reports_location_overlap_without_semantic_equivalence() -> None:
    pyright = harness.Observation(
        "pyright", "diagnostic", "case.py", 3, 2, "error", "P says A", "ruleP", True
    )
    mypy = harness.Observation(
        "mypy", "diagnostic", "case.py", 3, 2, "error", "M says B", "ruleM", True
    )
    result = harness._compare([pyright], [mypy])
    assert result["overlapping_error_locations"] == [["case.py", 3]]
    assert result["semantic_equivalence"] == "unsupported"
    assert "normalized" not in result["policy"]


def test_real_provider_invocation_uses_snapshot_and_explicit_mypy_config() -> None:
    if os.name != "posix":
        pytest.skip("provider process groups require POSIX")
    pyright = os.environ.get("PYRIGHT_DIFFERENTIAL_PYRIGHT", "")
    mypy = os.environ.get("PYRIGHT_DIFFERENTIAL_MYPY", "")
    if not Path(pyright).is_file() or not Path(mypy).is_file():
        pytest.skip(
            "set explicit pinned PYRIGHT_DIFFERENTIAL_PYRIGHT and PYRIGHT_DIFFERENTIAL_MYPY paths"
        )
    try:
        harness._version([pyright, "--version"], harness.PYRIGHT_VERSION, "Pyright")
        harness._version([mypy, "--version"], harness.MYPY_VERSION, "mypy")
    except harness.EvaluationError as exc:
        pytest.skip(f"explicit provider paths are not pinned: {exc}")
    record = harness.evaluate(
        "callable",
        pyright,
        mypy,
        write=False,
    )
    assert record["schema"] == "pyright-mypy-differential-v3"
    assert record["provenance"]["provider_artifacts"]["mypy"]["executable_sha256"]
    assert record["provenance"]["consumed_source_sha256"] == record["source_sha256"]
    assert "--config-file" in record["provenance"]["mypy_command"]
    assert {item["query"] for item in record["unsupported"]} >= {
        "definition_target",
        "execution_or_reachability",
        "cross_engine_diagnostic_semantics",
    }


def test_provider_run_fails_if_live_fixture_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture_root = tmp_path / "fixtures"
    fixture_root.mkdir()
    shutil.copytree(harness.FIXTURES / "callable", fixture_root / "callable")
    source = fixture_root / "callable" / "case.py"
    monkeypatch.setattr(harness, "FIXTURES", fixture_root)
    monkeypatch.setattr(
        harness,
        "_version",
        lambda _command, expected, provider: f"{provider.lower()} {expected}",
    )
    monkeypatch.setattr(
        harness,
        "_artifact_identity",
        lambda provider, _path: (
            f"<{provider}-package>/cli",
            {"executable_sha256": "a" * 64, "package_metadata_sha256": "b" * 64},
        ),
    )

    def invoke(
        command: list[str], _cwd: Path, _timeout: int = 25
    ) -> subprocess.CompletedProcess[str]:
        if "--outputjson" in command:
            source.write_text("value = 2\n", encoding="utf-8")
            output = {
                "version": "1.1.411",
                "time": "0 sec",
                "generalDiagnostics": [],
                "summary": {
                    "filesAnalyzed": 1,
                    "errorCount": 0,
                    "warningCount": 0,
                    "informationCount": 0,
                    "timeInSec": 0,
                },
            }
            return subprocess.CompletedProcess(command, 0, json.dumps(output), "")
        return subprocess.CompletedProcess(command, 0, "Success: no issues found\n", "")

    monkeypatch.setattr(harness, "_run", invoke)
    with pytest.raises(harness.EvaluationError, match="changed during provider invocation"):
        harness.evaluate("callable", "pyright", "mypy", write=False)


def test_committed_result_sets_have_strict_exact_coverage() -> None:
    harness.verify_records()
