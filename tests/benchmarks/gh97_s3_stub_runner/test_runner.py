from __future__ import annotations

import json
import os
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from benchmarks.gh97_s3_stub_runner.runner import (
    DEFAULT_MANIFEST,
    ProbeError,
    _binding_result,
    _load_candidate_product,
    _verify_candidate_module_path,
    extract_wheel,
    run_probe,
    verify_inputs,
)

WHEEL = Path("/tmp/gh97-wheel-audit/mypy_boto3_s3-1.35.92-py3-none-any.whl")


def test_manifest_rejects_wrong_digest(tmp_path: Path) -> None:
    changed = tmp_path / "manifest.json"
    changed.write_text("{}", encoding="utf-8")
    with pytest.raises(ProbeError, match="manifest SHA-256"):
        verify_inputs(WHEEL, changed)


def test_bounded_extractor_rejects_traversal(tmp_path: Path) -> None:
    wheel = tmp_path / "unsafe.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("../escape.py", "pass")
    with pytest.raises(ProbeError, match="unsafe ZIP member path"):
        extract_wheel(wheel, tmp_path / "extract")


def test_selector_binding_distinguishes_missing_and_positional_body() -> None:
    complete = {
        "keyword_bindings": ["Bucket", "Key", "Body"],
        "positional_argument_indexes": [],
        "canonical_symbol_status": "matched",
        "signature_resolved": True,
    }
    assert _binding_result(complete) == {
        "resource": "bound",
        "value": "bound",
        "binding_status": "complete",
    }
    omitted_args = {
        "keyword_bindings": ["Bucket", "Key"],
        "positional_argument_indexes": [],
        "canonical_symbol_status": "matched",
        "signature_resolved": True,
    }
    omitted = _binding_result(omitted_args)
    assert omitted["value"] == "missing_or_misbound"
    misbound = _binding_result(
        {
            "keyword_bindings": [],
            "positional_argument_indexes": [0, 1, 2],
            "canonical_symbol_status": "matched",
            "signature_resolved": True,
        }
    )
    assert misbound["binding_status"] == "misbound_positional_to_keyword_only_parameters"


def test_invalid_typed_calls_are_classified_from_call_diagnostics() -> None:
    invalid = {
        "keyword_bindings": ["Bucket", "Key", "Body", "Bogus"],
        "positional_argument_indexes": [],
        "canonical_symbol_status": "matched",
        "signature_resolved": True,
        "fixture_call_diagnostics": [{"raw": "unexpected keyword"}],
    }
    assert _binding_result(invalid)["binding_status"] == "invalid_call"


def test_candidate_product_import_fails_closed_when_checkout_is_missing(tmp_path: Path) -> None:
    with pytest.raises(ProbeError, match="candidate product package is missing"):
        _load_candidate_product(tmp_path)


def test_product_module_path_outside_checkout_is_rejected(tmp_path: Path) -> None:
    package_root = tmp_path / "src/fastapi_endpoint_detector"
    outside = tmp_path / "stale/analyzer.py"
    outside.parent.mkdir(parents=True)
    outside.write_text("", encoding="utf-8")
    with pytest.raises(ProbeError, match="escaped candidate checkout"):
        _verify_candidate_module_path(
            "analyzer", SimpleNamespace(__file__=str(outside)), package_root
        )


@pytest.mark.skipif(
    not os.environ.get("GH97_S3_WHEEL"),
    reason="set GH97_S3_WHEEL for the pinned artifact probe",
)
def test_exact_release_end_to_end_report() -> None:
    report = run_probe(Path(os.environ["GH97_S3_WHEEL"]), DEFAULT_MANIFEST)
    assert report["schema_version"] == 1
    assert report["artifact"]["version"] == "1.35.92"
    cases = {row["fixture"]: row for row in report["canonical_symbol_resolution"]["cases"]}
    assert cases["complete"]["canonical_symbol"] == "mypy_boto3_s3.client.S3Client.put_object"
    assert cases["omitted_body"]["canonical_symbol_status"] == "matched"
    assert cases["omitted_body"]["selector_binding_results"]["value"] == "missing_or_misbound"
    misbound = cases["misbound_body"]["selector_binding_results"]["binding_status"]
    assert misbound.startswith("misbound")
    assert cases["foreign_same_name"]["canonical_symbol"] == "__main__.Foreign.put_object"
    assert (
        cases["foreign_same_name"]["selector_binding_results"]["binding_status"]
        == "unvalidated_unmatched_canonical"
    )
    assert cases["bogus_keyword"]["selector_binding_results"]["binding_status"] == "invalid_call"
    assert cases["wrong_type"]["selector_binding_results"]["binding_status"] == "invalid_call"
    assert cases["omitted_body"]["selector_binding_results"]["binding_status"] == "incomplete"
    assert report["source_execution"] is False
    assert report["upstream_package_code_imported_or_executed"] is False
    product = report["product_adapter"]
    assert product["status"] in {"completed", "partially_validated", "unvalidated"}
    assert "calls" in product
    assert product["resolver"] == "1.19.1"
    expected_root = (Path(__file__).resolve().parents[3] / "src").resolve()
    assert Path(product["product_root"]).resolve() == expected_root
    for module_path in product["product_module_paths"].values():
        assert Path(module_path).resolve().is_relative_to(expected_root)
    assert set(product["product_source_sha256"]) == {
        "fastapi_endpoint_detector.analyzer.mypy_analyzer",
        "fastapi_endpoint_detector.analyzer.effect_contract_auditor",
        "fastapi_endpoint_detector.models.effect_contract",
        "fastapi_endpoint_detector.models.endpoint",
    }
    assert product["preset"]["name"] == "object-storage-v1"
    if product["status"] == "completed":
        assert len(product["calls"]) == 1
        assert product["calls"][0]["canonical_symbol"] == (
            "mypy_boto3_s3.client.S3Client.put_object"
        )
        assert product["calls"][0]["status"] == "exact"
        assert product["calls"][0]["arguments"][2]["status"] == "unavailable"
        assert product["calls"][0]["arguments"][2]["reason_code"] == "dynamic_argument"
        assert product["audit"]["summary"]["matched_calls"] == 1
    json.dumps(report)
