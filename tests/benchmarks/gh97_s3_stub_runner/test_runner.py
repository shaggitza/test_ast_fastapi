from __future__ import annotations

import json
import os
import shutil
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from benchmarks.gh97_s3_stub_runner.runner import (
    DEFAULT_MANIFEST,
    ProbeError,
    _binding_result,
    _load_candidate_product,
    _product_adapter,
    _verified_input_snapshot,
    _verify_candidate_module_path,
    extract_wheel,
    run_probe,
    sha256,
    verify_inputs,
)

from benchmarks.gh97_s3_stub_runner import runner

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


@pytest.mark.parametrize("cwd", [Path("/tmp"), Path("/var/tmp/external review cwd")])
def test_private_root_serialization_is_stable_and_component_bounded(
    tmp_path: Path, cwd: Path
) -> None:
    private = Path("/tmp/gh97 s3 private root")
    cwd.mkdir(parents=True, exist_ok=True)
    relative = os.path.relpath(private, cwd)
    payload = {
        "calls": [
            {
                "file_path": str(private / "fixture/complete.py"),
                "canonical_symbol": runner.CANONICAL,
            }
        ],
        "diagnostics": [{"raw": f"{relative}/stubtree/client.pyi:8: note"}],
        "unrelated": f"prefix{relative}/stubtree/file suffix {relative}-suffix",
        "source_sha256": {"complete.py": "sha256:abc"},
        "matched_calls": 1,
    }
    normalized = runner._normalize_private_paths(payload, private, cwd)
    assert normalized["calls"][0]["file_path"] == ("<private-s3-probe>/fixture/complete.py")
    assert normalized["calls"][0]["canonical_symbol"] == runner.CANONICAL
    assert normalized["diagnostics"][0]["raw"] == ("<private-s3-probe>/stubtree/client.pyi:8: note")
    assert normalized["unrelated"] == payload["unrelated"]
    assert normalized["source_sha256"] == payload["source_sha256"]
    assert normalized["matched_calls"] == 1


def test_different_windows_drives_keep_absolute_private_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = Path("D:/temp/private s3 root")
    cwd = Path("C:/work")
    monkeypatch.setattr(
        os.path,
        "relpath",
        lambda _path, _cwd: (_ for _ in ()).throw(ValueError("different drives")),
    )
    normalized = runner._normalize_private_paths(
        {"file_path": r"D:\temp\private s3 root\fixture\complete.py"},
        private,
        cwd,
    )
    assert normalized["file_path"] == "<private-s3-probe>\\fixture\\complete.py"


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


def test_missing_private_stub_cannot_claim_completed_product_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private = tmp_path / "private"
    fixture = private / "fixture"
    fixture.mkdir(parents=True)
    source = fixture / "complete.py"
    source.write_text(
        "from mypy_boto3_s3.client import S3Client\n\n"
        "def run(client: S3Client) -> None:\n"
        "    client.put_object(Bucket='bucket', Key='key', Body=b'payload')\n",
        encoding="utf-8",
    )
    ambient = tmp_path / "ambient" / "mypy_boto3_s3"
    ambient.mkdir(parents=True)
    (ambient / "__init__.py").write_text("", encoding="utf-8")
    (ambient / "client.py").write_text(
        "class S3Client:\n"
        "    def put_object(self, *, Bucket: str, Key: str, Body: bytes) -> None: ...\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("MYPYPATH", str(ambient.parent))

    result = _product_adapter(source)

    assert result["status"] == "partially_validated"
    assert result["binding_complete"] is False
    assert not any(
        call["canonical_symbol"] == "mypy_boto3_s3.client.S3Client.put_object"
        for call in result["calls"]
    )
    assert os.environ["MYPYPATH"] == str(ambient.parent)


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
    assert product["status"] == "completed"
    assert product["binding_complete"] is True
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
        "fastapi_endpoint_detector.models.effect_contract_audit",
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
        audit_model = _load_candidate_product(runner.ROOT)["EffectContractAudit"]
        assert (
            audit_model.model_validate(product["audit"]).model_dump(mode="json") == product["audit"]
        )
    json.dumps(report)


@pytest.mark.skipif(not WHEEL.is_file(), reason="requires the supplied pinned wheel")
@pytest.mark.parametrize("cwd_kind", ["tmp", "external"])
def test_outside_cwd_preserves_all_six_diagnostic_bindings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cwd_kind: str
) -> None:
    monkeypatch.chdir(Path("/tmp") if cwd_kind == "tmp" else tmp_path)
    report = run_probe(WHEEL, DEFAULT_MANIFEST)
    cases = {row["fixture"]: row for row in report["canonical_symbol_resolution"]["cases"]}
    assert cases["complete"]["selector_binding_results"]["binding_status"] == "complete"
    assert cases["omitted_body"]["selector_binding_results"]["binding_status"] == "incomplete"
    assert cases["misbound_body"]["selector_binding_results"]["binding_status"].startswith(
        "misbound"
    )
    assert cases["foreign_same_name"]["selector_binding_results"]["binding_status"] == (
        "unvalidated_unmatched_canonical"
    )
    for name in ("bogus_keyword", "wrong_type"):
        assert cases[name]["selector_binding_results"]["binding_status"] == "invalid_call"
    for name in ("misbound_body", "bogus_keyword", "wrong_type"):
        assert cases[name]["fixture_call_diagnostics"]
    assert cases["omitted_body"]["selector_binding_results"]["binding_status"] == "incomplete"
    assert cases["misbound_body"]["selector_binding_results"]["binding_status"].startswith(
        "misbound"
    )
    for name in ("complete", "omitted_body", "foreign_same_name"):
        assert cases[name]["fixture_call_diagnostics"] == []
    assert report["status"] == report["product_adapter"]["status"]
    assert report["product_adapter"]["audit"]["summary"]["physical_occurrences"] == 1
    assert report["product_adapter"]["audit"]["summary"]["matched_calls"] == 1


def test_main_returns_nonzero_for_partial_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "partial.json"
    monkeypatch.setattr(
        runner,
        "run_probe",
        lambda _wheel, _manifest: {
            "status": "partially_validated",
            "product_adapter": {"status": "partially_validated"},
        },
    )
    assert runner.main(["--wheel", str(WHEEL), "--output", str(destination)]) == 2
    assert json.loads(destination.read_text(encoding="utf-8"))["status"] == ("partially_validated")


@pytest.mark.skipif(not WHEEL.is_file(), reason="requires the pinned supplied wheel")
def test_authenticated_snapshot_survives_wheel_and_manifest_replacement(tmp_path: Path) -> None:
    wheel = tmp_path / WHEEL.name
    manifest = tmp_path / "manifest.json"
    shutil.copyfile(WHEEL, wheel)
    shutil.copyfile(DEFAULT_MANIFEST, manifest)
    artifact, matrix, snapshot = _verified_input_snapshot(wheel, manifest)
    wheel.write_bytes(b"replacement archive")
    manifest.write_text("{}", encoding="utf-8")
    destination = tmp_path / "extracted"
    extract_wheel(snapshot, destination)
    assert artifact["wheel_sha256"] == "sha256:" + sha256(snapshot)
    package = next(row for row in matrix["packages"] if row["distribution"] == "mypy-boto3-s3")
    for row in package["inspected_sources"]:
        assert sha256((destination / row["path"]).read_bytes()) == row["sha256"]


def test_wheel_read_remains_bounded_after_stat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wheel = tmp_path / runner.WHEEL_NAME
    wheel.write_bytes(b"x" * 17)
    monkeypatch.setattr(runner, "MAX_WHEEL_BYTES", 16)
    original_stat = Path.stat

    def stale_stat(path: Path, *, follow_symlinks: bool = True) -> os.stat_result | SimpleNamespace:
        if path == wheel:
            return SimpleNamespace(st_size=1)
        return original_stat(path, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "stat", stale_stat)
    with pytest.raises(ProbeError, match="size limit"):
        _verified_input_snapshot(wheel, DEFAULT_MANIFEST)
