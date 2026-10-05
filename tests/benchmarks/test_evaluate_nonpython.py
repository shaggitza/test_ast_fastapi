"""Regression tests for the non-Python evidence fixture and evaluation harness."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from benchmarks.real_world.evaluate_nonpython import (
    SCANNER_COMMIT,
    NonPythonFixtureError,
    scan_literal_case,
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


def test_rejects_route_atom_count_tampering(tmp_path: Path) -> None:
    fixture = copied_fixture(tmp_path)
    cases_path = fixture / "evaluation_cases.json"
    cases = read_json(cases_path)
    cases["cases"][1]["atoms"].pop()
    write_json(cases_path, cases)
    with pytest.raises(NonPythonFixtureError, match="unit-count mismatch"):
        validate_fixture(fixture)


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
