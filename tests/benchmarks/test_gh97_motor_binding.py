"""Narrow contract checks for the exact Motor source-only probe result."""

import json
from pathlib import Path

import pytest
from benchmarks.gh97_motor_binding.run import verified_product_path, verify_artifact_hash

ROOT = Path(__file__).resolve().parents[2]
RESULT = ROOT / "benchmarks/gh97_motor_binding/result.json"


def test_motor_probe_is_pinned_and_reports_no_fabricated_positive_binding() -> None:
    result = json.loads(RESULT.read_text())

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
    assert not any(row["audit_status"] == "matched" for row in result["occurrences"])


def test_same_name_and_wrapper_controls_remain_unmatched() -> None:
    result = json.loads(RESULT.read_text())
    rows = {row["source_spelling"]: row for row in result["occurrences"]}

    assert rows["decoy.insert_one"]["canonical_symbol"].endswith("Decoy.insert_one")
    assert rows["decoy.insert_one"]["audit_status"] == "unmatched"
    assert rows["wrapped.insert_one"]["canonical_symbol"].endswith("Wrapper.insert_one")
    assert rows["wrapped.insert_one"]["audit_status"] == "unmatched"


def test_motor_collection_operations_abstain_when_receiver_is_dynamic() -> None:
    result = json.loads(RESULT.read_text())
    rows = {row["source_spelling"]: row for row in result["occurrences"]}

    for operation in ("insert_one", "update_one", "delete_one"):
        row = rows[f"collection.{operation}"]
        assert row["resolver_status"] == "unresolved"
        assert row["canonical_symbol"] is None
        assert row["reason_code"] == "dynamic_receiver"
        assert row["audit_status"] == "unresolved"


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
