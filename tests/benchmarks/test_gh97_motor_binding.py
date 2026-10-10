"""Narrow contract checks for the exact Motor source-only probe result."""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from benchmarks.gh97_motor_binding.run import verified_product_path, verify_artifact_hash

ROOT = Path(__file__).resolve().parents[2]
HISTORICAL_RESULT = ROOT / "benchmarks/gh97_motor_binding/historical-source-only-v1.json"


def test_historical_motor_probe_is_pinned_and_preserves_original_finding() -> None:
    raw = HISTORICAL_RESULT.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == (
        "cabcfb198491c16788146f4983d650de5189238a99514e4d23194662fd0113e8"
    )
    result = json.loads(raw)

    assert result["probe_id"] == "gh97-motor-typed-binding-v1"
    assert result["python"] == "3.11.16"
    assert result["mypy"] == "1.19.1"
    assert result["analyzer_revision"] == "dd615f5c3fd298f5aa854a8e2c42b26a5bd0f404"
    assert result["analysis_config"] == {
        "max_depth": 1,
        "track_transitive": False,
        "audit_cache_enabled": False,
    }
    assert result["product_import"] == "src/fastapi_endpoint_detector/__init__.py"
    assert all(
        path.startswith("src/fastapi_endpoint_detector/")
        for path in result["product_module_paths"].values()
    )
    assert result["artifact_hashes"]["motor"]["sha256"] == (
        "sha256:9f07ed96f1754963d4386944e1b52d403a5350c687edc60da487d66f98dbf894"
    )
    assert result["artifact_hashes"]["pymongo"]["sha256"] == (
        "sha256:cec237c305fcbeef75c0bcbe9d223d1e22a6e3ba1b53b2f0b79d3d29c742b45b"
    )
    assert result["preset"]["contract_ids"] == [
        "pymongo-find-one",
        "pymongo-insert-one",
        "pymongo-update-one",
        "pymongo-delete-one",
    ]
    assert result["classification"] == {
        "all_calls": 5,
        "exact_resolution_and_audit_binding": 0,
        "resolved_but_unmatched": 2,
        "unsupported_or_ambiguous_resolution": 3,
    }
    assert result["extracted_python_source_hashes"]


def test_same_name_and_wrapper_controls_remain_unmatched() -> None:
    result = json.loads(HISTORICAL_RESULT.read_text())
    rows = {row["source_spelling"]: row for row in result["occurrences"]}

    assert rows["decoy.insert_one"]["canonical_symbol"].endswith("Decoy.insert_one")
    assert rows["decoy.insert_one"]["audit_status"] == "unmatched"
    assert rows["wrapped.insert_one"]["canonical_symbol"].endswith("Wrapper.insert_one")
    assert rows["wrapped.insert_one"]["audit_status"] == "unmatched"


def test_live_motor_probe_binds_real_vendor_stub_declarations() -> None:
    artifacts = os.environ.get("GH97_MOTOR_ARTIFACT_DIR", "/tmp/gh97-wheel-audit")
    if not Path(artifacts).is_dir():
        pytest.skip("pinned Motor and PyMongo artifacts are unavailable")
    with tempfile.TemporaryDirectory(prefix="gh97-motor-test-") as temp:
        output = Path(temp) / "live-result.json"
        repo = ROOT
        env = os.environ.copy()
        env["PYTHONPATH"] = str(repo / "src")
        subprocess.run(
            [
                sys.executable,
                str(repo / "benchmarks/gh97_motor_binding/run.py"),
                "--artifacts",
                artifacts,
                "--output",
                str(output),
            ],
            check=True,
            cwd=repo,
            env=env,
            capture_output=True,
            text=True,
        )
        result = json.loads(output.read_text())
    rows = {row["source_spelling"]: row for row in result["occurrences"]}

    for operation in ("insert_one", "update_one", "delete_one"):
        row = rows[f"collection.{operation}"]
        assert row["resolver_status"] == "exact"
        assert row["canonical_symbol"] == f"motor.core.AgnosticCollection.{operation}"
        assert row["audit_status"] == "matched"
    assert result["classification"] == {
        "all_calls": 8,
        "exact_resolution_and_audit_binding": 5,
        "resolved_but_unmatched": 2,
        "unsupported_or_ambiguous_resolution": 1,
    }
    assert rows["unknown_collection.insert_one"]["resolver_status"] == "unresolved"
    assert rows["unknown_collection.insert_one"]["reason_code"] == "dynamic_receiver"
    assert rows["unknown_collection.insert_one"]["audit_status"] == "unresolved"
    invalid_calls = [
        row
        for row in result["occurrences"]
        if row["source_spelling"] == "collection.insert_one" and not row["arguments"]
    ]
    assert len(invalid_calls) == 1
    assert invalid_calls[0]["resolver_status"] == "exact"
    diagnostics = result["fixture_diagnostics"]
    assert any('Missing positional argument "document"' in error for error in diagnostics)
    assert any('Unexpected keyword argument "mystery"' in error for error in diagnostics)
    source_hashes = result["extracted_typed_source_hashes"]["motor"]
    assert "motor/__init__.py" in source_hashes
    assert "motor/motor_asyncio.pyi" in source_hashes
    assert "motor/core.pyi" in source_hashes
    assert "motor/py.typed" in source_hashes
    assert result["verified_target_evidence"]["package_versions"]["motor"] == "3.6.0"
    assert (
        result["verified_target_evidence"]["package_metadata_hashes"][
            "motor-3.6.0.dist-info/METADATA"
        ]
        == "sha256:dce8b401625d673eed6b2c0c66d9d196a13de0649c0788da8b3e2a72edb2965d"
    )
    assert (
        result["verified_target_evidence"]["mypy_source_hashes"]["motor/__init__.py"]
        == source_hashes["motor/__init__.py"]
    )
    assert result["verified_target_evidence"]["audit_evidence_hash"].startswith("sha256:")


def test_motor_probe_rejects_modified_artifact_bytes(tmp_path: Path) -> None:
    changed = tmp_path / "motor-3.6.0-py3-none-any.whl"
    changed.write_bytes(b"different artifact bytes")

    with pytest.raises(ValueError, match="artifact SHA-256 mismatch"):
        verify_artifact_hash(changed, "motor")


def test_motor_probe_rejects_product_module_outside_expected_checkout(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="product module escaped candidate checkout"):
        verified_product_path(
            tmp_path,
            "fastapi_endpoint_detector.models.endpoint",
            "src/fastapi_endpoint_detector/models/endpoint.py",
        )
