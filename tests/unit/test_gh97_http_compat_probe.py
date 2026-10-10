"""The GH97 probe must count source-backed package calls and preserve negatives."""

from __future__ import annotations

import platform
import subprocess
import zipfile
from pathlib import Path

import mypy.version
import pytest
from benchmarks.gh97_http_compat import probe
from benchmarks.gh97_http_compat.probe import (
    EXPECTED_WHEEL_SHA256,
    WHEELS,
    extract_python_sources,
    run,
)


@pytest.mark.skipif(
    platform.python_version() != "3.11.16" or not all(path.is_file() for path in WHEELS.values()),
    reason="requires the pinned Python and supplied local wheel artifacts",
)
def test_installed_artifact_calls_are_resolved_from_wheel_sources() -> None:
    report = run()

    assert report["preset"] == "http-clients-v1"
    observations = report["observations"]
    assert report["call_count"] == len(observations)
    assert report["matched_call_count"] == sum(
        row["audit_status"] == "matched" for row in observations
    )
    assert report["selector_supported_call_count"] == sum(
        row["resource"] is not None and row["resource"]["status"] in {"exact", "finite"}
        for row in observations
    )
    assert (
        sum(row["contract_id"] is not None for row in observations) == report["matched_call_count"]
    )
    foreign = next(row for row in observations if row["source_spelling"] == "foreign.get")
    assert foreign["canonical_symbol"] is None
    assert foreign["audit_status"] == "ambiguous"
    assert foreign["resolver_status"] == "ambiguous"
    assert foreign["reason_code"] == "open_receiver_dispatch"
    assert foreign["contract_id"] is None
    assert any(candidate.endswith("Foreign") for candidate in foreign["receiver_candidates"])
    forwarded = next(
        row
        for row in observations
        if row["line"] == report["fixture_controls"]["forwarded_wrapper_line"]
    )
    assert forwarded["source_spelling"] == "client.get"
    assert forwarded["contract_id"] == "requests-session-get"
    assert forwarded["audit_status"] == "matched"
    assert forwarded["resource"]["status"] == "exact"
    assert len(forwarded["resource"]["value_hashes"]) == 1
    # The 28 literal package calls plus the forwarded literal URL support selectors.
    assert report["selector_supported_call_count"] == 29
    assert not any(
        row["line"]
        in {
            report["fixture_controls"]["unused_wrapper"],
            report["fixture_controls"]["deferred_function"],
        }
        for row in observations
    )
    dynamic = next(
        row
        for row in observations
        if row["source_spelling"] == "client0.get"
        and row["resource"] is not None
        and row["resource"]["status"] == "unavailable"
    )
    assert dynamic["contract_id"] == "requests-session-get"
    assert dynamic["resource"]["status"] == "unavailable"
    assert {
        name: item["wheel_sha256"].removeprefix("sha256:")
        for name, item in report["packages"].items()
    } == EXPECTED_WHEEL_SHA256
    assert report["diagnostic_count"] == len(report["diagnostics"])
    assert report["fixture_diagnostics"] == []
    assert all(row["call_diagnostics"] == [] for row in observations)
    assert all(row["call_validation"] == "no_call_diagnostics" for row in observations)
    assert report["compatibility_complete"] is False
    assert report["analysis_config"]["module_root_policy"] == (
        "explicit_verified_extracted_package_root"
    )
    assert report["global_diagnostic_count"] > 0
    assert all(not Path(item["path"]).is_absolute() for item in report["product_imports"].values())
    assert all(not Path(item["wheel"]).is_absolute() for item in report["packages"].values())
    assert {
        "fastapi_endpoint_detector.analyzer.mypy_analyzer",
        "fastapi_endpoint_detector.analyzer.effect_contract_auditor",
        "fastapi_endpoint_detector.models.effect_contract",
        "fastapi_endpoint_detector.models.endpoint",
    } <= set(report["product_imports"])
    assert all(
        "[import-untyped]" in item or "[import-not-found]" in item
        for item in report["missing_dependency_diagnostics"]
    )


def test_modified_wheel_fails_before_metadata_or_extraction(tmp_path: Path) -> None:
    changed = tmp_path / "requests.whl"
    with zipfile.ZipFile(changed, "w") as archive:
        archive.writestr("requests/__init__.py", "# changed")
    with pytest.raises(ValueError, match="hash does not match pinned artifact"):
        extract_python_sources(changed, tmp_path / "out", "requests")


def test_wrong_python_version_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(platform, "python_version", lambda: "3.12.0")
    with pytest.raises(RuntimeError, match=r"expected pinned Python 3\.11\.16"):
        run()


def test_wrong_mypy_version_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(platform, "python_version", lambda: "3.11.16")
    monkeypatch.setattr(mypy.version, "__version__", "2.4.0")
    with pytest.raises(RuntimeError, match=r"expected mypy 1\.19\.1"):
        run()


def test_stale_product_module_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(platform, "python_version", lambda: "3.11.16")
    monkeypatch.setattr(probe, "_module_source", lambda _module: tmp_path / "stale.py")
    with pytest.raises(RuntimeError, match="did not load from candidate src tree"):
        run()


def test_diagnostic_paths_are_portable_without_losing_typeshed_locations() -> None:
    probe_root = Path("/var/tmp/gh97_http_wheels_random")
    item = (
        "/workspace/project/.venv/lib/python3.11/site-packages/mypy/typeshed/stdlib/builtins.pyi: "
        "note: /workspace/project/helper.py /workspace/project/.venv/lib/dependency.py "
        "/var/tmp/gh97_http_wheels_random/app/fixture.py:12: error; "
        "/tmp/gh97_http_wheels_unrelated/app/fixture.py:13: error"
    )
    normalized = probe._normalize_diagnostic(
        item,
        Path("/workspace/project"),
        Path("/workspace/project/.venv"),
        probe_root,
    )
    assert normalized == (
        "<typeshed>/stdlib/builtins.pyi: note: <analyzer-project>/helper.py "
        "<python-environment>/lib/dependency.py <private-probe>/app/fixture.py:12: error; "
        "/tmp/gh97_http_wheels_unrelated/app/fixture.py:13: error"
    )
    assert probe._diagnostic_line(normalized) == 12


def test_diagnostic_probe_root_accepts_windows_separators() -> None:
    normalized = probe._normalize_diagnostic(
        r"\var\tmp\gh97_http_wheels_random\app\fixture.py:7: error",
        Path("/checkout"),
        Path("/python"),
        Path("/var/tmp/gh97_http_wheels_random"),
    )
    assert normalized == r"<private-probe>\app\fixture.py:7: error"
    assert probe._diagnostic_line(normalized) == 7


@pytest.mark.parametrize(
    "diagnostic",
    [
        "<private-probe>/site/httpx/fixture_helpers.py:7: error",
        "<private-probe>/site/httpx/fixture.py:7: error",
        r"<private-probe>\site\httpx\other_fixture.py:7: error",
        "<private-probe>/app/fixture.py: error without a line number",
    ],
)
def test_package_diagnostics_are_not_classified_as_fixture_calls(diagnostic: str) -> None:
    assert probe._diagnostic_line(diagnostic) is None


def test_source_provenance_survives_result_commits_and_rejects_dirty_sources(
    tmp_path: Path,
) -> None:
    def git(*args: str) -> None:
        subprocess.run(["git", "-C", str(tmp_path), *args], check=True, capture_output=True)

    git("init")
    git("config", "user.name", "Probe test")
    git("config", "user.email", "probe-test@example.invalid")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "analyzer.py").write_text("VALUE = 1\n", encoding="utf-8")
    runner = tmp_path / "probe.py"
    runner.write_text("# runner\n", encoding="utf-8")
    git("add", ".")
    git("commit", "-m", "Source snapshot")
    original = probe._source_provenance(tmp_path, runner)
    (tmp_path / "result.json").write_text("{}\n", encoding="utf-8")
    git("add", "result.json")
    git("commit", "-m", "Evidence snapshot")
    assert probe._source_provenance(tmp_path, runner) == original
    runner.write_text("# modified runner\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="runner must match its committed revision"):
        probe._source_provenance(tmp_path, runner)
    runner.write_text("# runner\n", encoding="utf-8")
    (tmp_path / "src" / "untracked.py").write_text("# new code\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="source tree must match committed source bytes"):
        probe._source_provenance(tmp_path, runner)
