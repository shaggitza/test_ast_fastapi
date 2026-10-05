"""Regression tests for the non-Python evidence fixture and evaluation harness."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import benchmarks.real_world.evaluate_nonpython as evaluator
import pytest
from benchmarks.real_world.evaluate_nonpython import (
    HISTORICAL_SCANNER_COMMIT,
    SCANNER_COMMIT,
    NonPythonFixtureError,
    scan_literal_case,
    strict_json,
    validate_fixture,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "benchmarks/real_world/nonpython_v1"


def copied_fixture(tmp_path: Path) -> Path:
    target = tmp_path / "nonpython_v1"
    shutil.copytree(FIXTURE, target)
    return target


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def test_fixture_reports_six_prs_and_nine_separately_audited_atoms() -> None:
    validated = validate_fixture()
    assert len(validated["spec"]["cases"]) == 6
    assert validated["client_atom_count"] == 8
    assert validated["deployment_atom_count"] == 1
    assert "not establish" in validated["spec"]["unit_interpretation"]["note"]


def test_rejects_manifest_schema_tampering(tmp_path: Path) -> None:
    fixture = copied_fixture(tmp_path)
    manifest_path = fixture / "source_manifest.json"
    manifest = read_json(manifest_path)
    manifest["schema"] = "unknown"
    write_json(manifest_path, manifest)
    with pytest.raises(NonPythonFixtureError, match="schema"):
        validate_fixture(fixture)


@pytest.mark.parametrize(
    "raw_json",
    [
        '{"schema": "first", "schema": "second"}',
        '{"outer": {"schema": "first", "schema": "second"}}',
        '{"outer": [{"schema": "first", "schema": "second"}]}',
    ],
)
def test_rejects_duplicate_json_keys_at_every_nesting_depth(tmp_path: Path, raw_json: str) -> None:
    path = tmp_path / "duplicate-keys.json"
    path.write_text(raw_json, encoding="utf-8")
    with pytest.raises(NonPythonFixtureError, match="duplicate JSON object key"):
        strict_json(path)


def test_rejects_source_hash_metadata_tampering(tmp_path: Path) -> None:
    fixture = copied_fixture(tmp_path)
    manifest_path = fixture / "source_manifest.json"
    manifest = read_json(manifest_path)
    manifest["cases"]["khoj_1216"]["files"][0]["sha256"] = "0" * 64
    write_json(manifest_path, manifest)
    with pytest.raises(NonPythonFixtureError, match="SHA-256 mismatch"):
        validate_fixture(fixture)


def test_rejects_source_byte_hash_mismatch(tmp_path: Path) -> None:
    fixture = copied_fixture(tmp_path)
    source_path = fixture / "source/khoj_1216/src/khoj/routers/api_chat.py.txt"
    source_path.write_bytes(source_path.read_bytes() + b"\n")
    with pytest.raises(NonPythonFixtureError, match="SHA-256 mismatch"):
        validate_fixture(fixture)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_commit", "0" * 40),
        ("url", "https://example.invalid/LICENSE"),
    ],
)
def test_rejects_license_provenance_not_bound_to_snapshot(
    tmp_path: Path, field: str, value: str
) -> None:
    fixture = copied_fixture(tmp_path)
    manifest_path = fixture / "source_manifest.json"
    manifest = read_json(manifest_path)
    manifest["cases"]["khoj_1216"]["license"][field] = value
    write_json(manifest_path, manifest)
    with pytest.raises(NonPythonFixtureError, match=r"license provenance.*pinned PR snapshot"):
        validate_fixture(fixture)


def test_license_provenance_is_bound_to_each_pinned_snapshot() -> None:
    validated = validate_fixture()
    for case_id, case_key in validated["source_keys"].items():
        case = next(row for row in validated["spec"]["cases"] if row["case_id"] == case_id)
        license_record = validated["manifest"]["cases"][case_key]["license"]
        expected_url = (
            f"https://raw.githubusercontent.com/{case['repository']}/"
            f"{case['merge_snapshot']}/LICENSE"
        )
        assert license_record["source_commit"] == case["merge_snapshot"]
        assert license_record["url"] == expected_url


def test_scanner_execution_is_limited_to_two_approved_commits() -> None:
    assert evaluator._require_trusted_scanner_commit(SCANNER_COMMIT) == SCANNER_COMMIT
    assert (
        evaluator._require_trusted_scanner_commit(HISTORICAL_SCANNER_COMMIT)
        == HISTORICAL_SCANNER_COMMIT
    )


def test_rejects_unapproved_full_scanner_sha_before_git_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[object] = []

    def unexpected_git_call(*args: object, **kwargs: object) -> None:
        calls.append((args, kwargs))
        raise AssertionError("unapproved scanner SHA reached Git")

    monkeypatch.setattr(evaluator.subprocess, "run", unexpected_git_call)
    with pytest.raises(NonPythonFixtureError, match=r"not in the approved.*allowlist"):
        evaluator._archive_scanner(ROOT, "682e6239eb7ab8e75b39bfd736b1bfe3a5fd2c7d", tmp_path)
    assert calls == []


def test_rejects_route_atom_count_tampering(tmp_path: Path) -> None:
    fixture = copied_fixture(tmp_path)
    cases_path = fixture / "evaluation_cases.json"
    cases = read_json(cases_path)
    cases["cases"][1]["atoms"].pop()
    write_json(cases_path, cases)
    with pytest.raises(NonPythonFixtureError, match="unit-count mismatch"):
        validate_fixture(fixture)


def test_rejects_duplicate_method_path_within_one_pr(tmp_path: Path) -> None:
    fixture = copied_fixture(tmp_path)
    cases_path = fixture / "evaluation_cases.json"
    cases = read_json(cases_path)
    atoms = cases["cases"][1]["atoms"]
    atoms[2] = atoms[1].copy()
    atoms[2]["query_evidence"] = "client=obsidian&source=duplicate-control"
    write_json(cases_path, cases)
    with pytest.raises(NonPythonFixtureError, match="duplicate audited route identity"):
        validate_fixture(fixture)


def test_rejects_duplicate_surface_id_within_one_pr(tmp_path: Path) -> None:
    fixture = copied_fixture(tmp_path)
    cases_path = fixture / "evaluation_cases.json"
    cases = read_json(cases_path)
    atoms = cases["cases"][1]["atoms"]
    atoms[2]["surface_id"] = atoms[1]["surface_id"]
    write_json(cases_path, cases)
    with pytest.raises(NonPythonFixtureError, match="duplicate audited surface ID"):
        validate_fixture(fixture)


def test_same_route_and_surface_in_different_prs_remain_valid() -> None:
    spec = validate_fixture()["spec"]
    cases = {case["case_id"]: case for case in spec["cases"]}
    first = next(
        atom
        for atom in cases["khoj-ai/khoj#1221"]["atoms"]
        if atom["method"] == "PATCH" and atom["path"] == "/api/content"
    )
    second = next(
        atom
        for atom in cases["khoj-ai/khoj#1235"]["atoms"]
        if atom["method"] == "PATCH" and atom["path"] == "/api/content"
    )
    assert first["surface_id"] == second["surface_id"]
    assert first["query_evidence"] == "client=obsidian"
    assert second["query_evidence"] == "client=obsidian"


def test_build_result_scans_the_exact_bytes_validated_before_a_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = copied_fixture(tmp_path)
    spec = read_json(fixture / "evaluation_cases.json")
    manifest = read_json(fixture / "source_manifest.json")
    case = next(row for row in spec["cases"] if row["case_id"] == "khoj-ai/khoj#1216")
    case_manifest = manifest["cases"]["khoj_1216"]
    source_record = next(
        row for row in case_manifest["files"] if row["path"] in case["client_files"]
    )
    source_path = fixture / "source/khoj_1216" / source_record["storage_path"]
    validated_bytes = source_path.read_bytes()
    race_payload = b'\nfetch("/race-probe", {method: "GET"});\n'
    real_validate = evaluator.validate_fixture

    def validate_then_mutate(
        candidate: Path = evaluator.FIXTURE, evidence_root: Path | None = None
    ) -> dict:
        validated = real_validate(candidate, evidence_root)
        source_path.write_bytes(validated_bytes + race_payload)
        return validated

    monkeypatch.setattr(evaluator, "validate_fixture", validate_then_mutate)
    result = evaluator.build_result(fixture, repo_root=ROOT)
    output_case = next(row for row in result["cases"] if row["case_id"] == case["case_id"])
    assert all(
        observation["raw_route_path"] != "/race-probe"
        for observation in output_case["raw_client_observations"]
    )
    verified_source = next(
        row
        for row in result["verified_source_files"]
        if row["case_id"] == case["case_id"] and row["original_path"] == source_record["path"]
    )
    assert verified_source["sha256"] == source_record["sha256"]

    raced_text = source_path.read_text(encoding="utf-8")
    scanner_control = scan_literal_case(
        repo_root=ROOT,
        scanner_commit=SCANNER_COMMIT,
        source_path=source_record["path"],
        source_text=raced_text,
        surfaces=[],
    )
    assert any(
        observation["raw_route_path"] == "/race-probe"
        for observation in scanner_control["client_observations"]
    )


def test_vendored_python_sources_are_data_only() -> None:
    assert not list((FIXTURE / "source").rglob("*.py"))
    manifest = read_json(FIXTURE / "source_manifest.json")
    for case in manifest["cases"].values():
        for source in case["files"]:
            if source["path"].endswith(".py"):
                assert source["storage_path"].endswith(".py.txt")


def test_join_requires_exact_method_path_and_trusted_origin() -> None:
    result = scan_literal_case(
        repo_root=ROOT,
        scanner_commit=SCANNER_COMMIT,
        source_path="client.ts",
        source_text=('fetch("https://service.example/items?q=1"); fetch("/items");'),
        surfaces=[
            {
                "surface_id": "exact",
                "path": "/items",
                "method": "GET",
                "origin": "https://service.example",
                "trusted": True,
            },
            {
                "surface_id": "wrong-origin",
                "path": "/items",
                "method": "GET",
                "origin": "https://other.example",
                "trusted": True,
            },
            {
                "surface_id": "wrong-method",
                "path": "/items",
                "method": "POST",
                "origin": "https://service.example",
                "trusted": True,
            },
            {
                "surface_id": "untrusted",
                "path": "/items",
                "method": "GET",
                "origin": "https://service.example",
                "trusted": False,
            },
        ],
    )
    assert result["joined_surface_ids"] == ["exact"]
    assert len(result["client_observations"]) == 2
    assert result["client_observations"][0]["query_evidence"] == "q=1"
