from __future__ import annotations

import importlib
import importlib.metadata
import json
import platform
import shutil
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import benchmarks.providers.effect_preset_frozen_runner as frozen_runner
import benchmarks.providers.effect_preset_matrix as matrix_provider
import pytest
from benchmarks.providers.effect_preset_matrix import (
    ANALYZER_SNAPSHOT_PATH,
    MANIFEST_PATH,
    RESULTS_PATH,
    MatrixEvidenceError,
    exact_release_status,
    load_controlled_results,
    load_manifest,
    load_package_analyzer_results,
    load_source_signature_observations,
    summarize_matrix,
    verify_artifacts,
    verify_declared_python_signatures,
    verify_preset_contracts,
)

from fastapi_endpoint_detector.analyzer.effect_contract_auditor import audit_effect_contracts
from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.models.effect_contract import load_effect_preset
from fastapi_endpoint_detector.models.endpoint import (
    Endpoint,
    EndpointInventory,
    EndpointMethod,
    HandlerInfo,
)

if TYPE_CHECKING:
    from fastapi_endpoint_detector.models.effect_contract_audit import (
        EffectContractAuditOccurrence,
    )


def _assert_foreign_call_is_unmatched_or_open_dispatch(
    occurrence: EffectContractAuditOccurrence,
) -> str:
    method = occurrence.source_spelling.split(".", 1)[1]
    assert occurrence.audit_status.value != "matched"
    assert occurrence.contract_id is None and occurrence.contract_hash is None
    if occurrence.resolver_status.value == "exact":
        assert occurrence.audit_status.value == "unmatched"
        assert occurrence.canonical_symbol is not None
        assert tuple(occurrence.canonical_symbol.rsplit(".", 2)[-2:]) == ("Foreign", method)
        assert occurrence.invocation is not None
        return "exact"
    if occurrence.resolver_status.value == "ambiguous":
        assert occurrence.audit_status.value == "ambiguous"
        assert occurrence.canonical_symbol is None
        assert occurrence.reason_code == "open_receiver_dispatch"
        assert occurrence.invocation is None
        return "ambiguous"
    pytest.fail(
        f"unexpected resolver status for {occurrence.source_spelling}: "
        f"{occurrence.resolver_status.value!r}"
    )


def _endpoint(path: Path, line: int) -> Endpoint:
    return Endpoint(
        path="/matrix",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="handler",
            module="main",
            file_path=path,
            line_number=line,
        ),
    )


def test_frozen_matrix_is_explicit_and_does_not_expand_version_ranges() -> None:
    manifest = load_manifest()

    assert exact_release_status("redis", "5.2.1", manifest) == "audited_exact_release"
    assert exact_release_status("redis", "6.0.0", manifest) == "not_audited"
    assert exact_release_status("motor", "3.6.0", manifest) == "audited_exact_release"
    assert exact_release_status("motor", "3.7.0", manifest) == "not_audited"
    assert exact_release_status("sqlalchemy", "2.0.36", manifest) == "audited_exact_release"
    assert exact_release_status("sqlalchemy", "2.0.37", manifest) == "not_audited"
    assert exact_release_status("mypy-boto3-sqs", "1.35.91", manifest) == "audited_exact_release"
    assert exact_release_status("mypy-boto3-sqs", "1.35.92", manifest) == "not_audited"
    summary = summarize_matrix(manifest)
    assert summary["package_releases"] == 12
    assert len(verify_preset_contracts(manifest)) == 6
    assert summary["source_inspected"] == 9
    assert summary["source_partially_inspected"] == 3
    assert summary["analyzer_observations"] == 1
    assert summary["unsupported_cases"] == 2
    assert (
        summary["range_compatibility"]
        == "not_evaluated; each release row is one exact artifact only"
    )
    assert summary["real_world_evaluation"] == "not_evaluated"


def test_unrecorded_python_mypy_environment_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(platform, "python_version", lambda: "3.13.0")
    monkeypatch.setattr(importlib.metadata, "version", lambda _name: "1.19.1")

    with pytest.raises(MatrixEvidenceError, match="no frozen replay result for exact environment"):
        matrix_provider._replay_environment()


def test_exact_package_signatures_and_selectors_are_explicit() -> None:
    manifest = load_manifest()
    packages = {row["distribution"]: row for row in manifest["packages"]}
    requests_get = next(
        row
        for row in packages["requests"]["declared_symbols"]
        if row["symbol"].endswith("Session.get")
    )
    assert requests_get["source_signature"] == "(self, url, **kwargs)"
    assert requests_get["resource"] == "arg0/url; kwargs forwarded to request(method,url)"
    aiohttp = packages["aiohttp"]["declared_symbols"]
    aiohttp_by_name = {row["symbol"].rsplit(".", 1)[-1]: row for row in aiohttp}
    assert aiohttp_by_name["head"]["parameters"] == ["url", "allow_redirects=False", "**kwargs"]
    assert aiohttp_by_name["post"]["parameters"] == ["url", "data=None", "**kwargs"]
    assert "StrOrURL" in aiohttp_by_name["get"]["source_signature"]
    assert "mypy_boto3_s3/type_defs.py" in {
        item["path"] for item in packages["mypy-boto3-s3"]["inspected_sources"]
    }
    s3_put = next(
        row
        for row in packages["mypy-boto3-s3"]["declared_symbols"]
        if row["symbol"].endswith("S3Client.put_object")
    )
    assert s3_put["parameters"] == [
        "Bucket",
        "Key",
        "ACL",
        "Body",
        "CacheControl",
        "ContentDisposition",
        "ContentEncoding",
        "ContentLanguage",
        "ContentLength",
        "ContentMD5",
        "ContentType",
        "ChecksumAlgorithm",
        "ChecksumCRC32",
        "ChecksumCRC32C",
        "ChecksumSHA1",
        "ChecksumSHA256",
        "Expires",
        "IfMatch",
        "IfNoneMatch",
        "GrantFullControl",
        "GrantRead",
        "GrantReadACP",
        "GrantWriteACP",
        "WriteOffsetBytes",
        "Metadata",
        "ServerSideEncryption",
        "StorageClass",
        "WebsiteRedirectLocation",
        "SSECustomerAlgorithm",
        "SSECustomerKey",
        "SSEKMSKeyId",
        "SSEKMSEncryptionContext",
        "BucketKeyEnabled",
        "RequestPayer",
        "Tagging",
        "ObjectLockMode",
        "ObjectLockRetainUntilDate",
        "ObjectLockLegalHoldStatus",
        "ExpectedBucketOwner",
    ]
    assert "ChecksumCRC64NVME" not in s3_put["parameters"]
    assert s3_put["value"] == "keyword Body"


def test_matrix_rejects_missing_signature_provenance(tmp_path: Path) -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    del manifest["packages"][0]["declared_symbols"][0]["source_signature"]
    altered = tmp_path / "altered-package-symbols.json"
    altered.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(MatrixEvidenceError, match="invalid fields"):
        load_manifest(altered)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("version", "99.0.0"),
        ("revision", "99"),
        ("contract_count", 9999),
        ("preset_semantic_sha256", "0" * 64),
    ],
)
def test_preset_contract_verification_rejects_unbacked_identity_claims(
    field: str, value: object
) -> None:
    manifest = load_manifest()
    manifest["versioned_contract_sets"][0][field] = value

    with pytest.raises(MatrixEvidenceError, match="supplied package manifest differs"):
        verify_preset_contracts(manifest)


def test_preset_contract_verification_rejects_unbacked_selector_claims() -> None:
    manifest = load_manifest()
    declaration = next(
        row
        for package in manifest["packages"]
        for row in package["declared_symbols"]
        if row["preset_contract"] is not None
    )
    declaration["contract_resource_selector"]["index"] += 1

    with pytest.raises(MatrixEvidenceError, match="supplied package manifest differs"):
        verify_preset_contracts(manifest)


def test_duplicate_and_nonfinite_json_fail_closed(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":2,"schema_version":2}', encoding="utf-8")
    nonfinite = tmp_path / "nonfinite.json"
    nonfinite.write_text('{"schema_version":NaN}', encoding="utf-8")

    for path in (duplicate, nonfinite):
        with pytest.raises(MatrixEvidenceError):
            load_manifest(path)

    duplicate_result = tmp_path / "duplicate-result.json"
    duplicate_result.write_text('{"status":"completed","status":"failed"}', encoding="utf-8")
    with pytest.raises(MatrixEvidenceError, match="duplicate JSON key"):
        load_controlled_results(duplicate_result)


def test_malformed_optional_artifact_metadata_raises_matrix_error() -> None:
    manifest = load_manifest()
    manifest["packages"][0]["metadata_sha256"] = None

    with pytest.raises(MatrixEvidenceError, match="wheel metadata"):
        verify_artifacts(Path("/unread-artifact-dir"), manifest)


def test_source_signature_report_rejects_missing_artifacts(tmp_path: Path) -> None:
    with pytest.raises(MatrixEvidenceError, match="missing frozen package artifact"):
        load_source_signature_observations(tmp_path)


def test_python_signature_audit_requires_exact_supplied_artifacts(tmp_path: Path) -> None:
    with pytest.raises(MatrixEvidenceError, match="missing frozen package artifact"):
        verify_declared_python_signatures(tmp_path)


def test_artifact_verification_fails_closed_when_packages_are_not_supplied(tmp_path: Path) -> None:
    with pytest.raises(MatrixEvidenceError, match="missing frozen package artifact"):
        verify_artifacts(tmp_path)


def test_matrix_rejects_wildcard_or_grouped_symbol_claims(tmp_path: Path) -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    manifest["packages"][0]["declared_symbols"][0]["symbol"] = (
        "redis.commands.core.BasicKeyCommands.*"
    )
    altered = tmp_path / "altered-package-symbols.json"
    altered.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(MatrixEvidenceError, match="exact symbol evidence"):
        load_manifest(altered)


def test_artifact_verification_rejects_a_present_but_changed_wheel(tmp_path: Path) -> None:
    manifest = load_manifest()
    first = manifest["packages"][0]
    (tmp_path / first["artifact"]).write_bytes(b"not the pinned artifact")

    with pytest.raises(MatrixEvidenceError, match="artifact hash mismatch"):
        verify_artifacts(tmp_path, manifest)


def test_controlled_result_provenance_and_denominator_are_valid() -> None:
    result = load_controlled_results()

    assert result["controlled_evaluation"]["observed"]["physical_calls"] == 11
    assert result["controlled_evaluation"]["observed"]["matched_calls"] == 4
    assert result["controlled_evaluation"]["observed"]["unmatched_calls"] == 7
    assert result["controlled_evaluation"]["observed"]["unresolved_calls"] == 0
    assert len(result["controlled_evaluation"]["observations"]) == 11
    assert result["controlled_evaluation"]["fixture_contract_set"]["version"] == "2.0.0"


def test_historical_source_bundle_is_verified_independently_of_live_source() -> None:
    frozen_hashes, _ = matrix_provider._load_analyzer_source_snapshots()
    result = load_controlled_results()
    assert result["controlled_evaluation"]["observed"]["physical_calls"] == 11
    assert len(result["controlled_evaluation"]["observations"]) == 11
    assert frozen_hashes["src/fastapi_endpoint_detector/analyzer/mypy_analyzer.py"].startswith(
        "sha256:"
    )


def test_historical_v4_artifact_tree_rejects_extra_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    copied_root = tmp_path / "effect-preset-matrix-v4"
    shutil.copytree(matrix_provider.MATRIX_ROOT, copied_root)
    (copied_root / "uncommitted-extra.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(matrix_provider, "MATRIX_ROOT", copied_root)

    with pytest.raises(
        MatrixEvidenceError,
        match="historical v4 artifact tree has missing or extra",
    ):
        matrix_provider._load_analyzer_source_snapshots()


def test_frozen_runtime_manifest_cannot_reauthorize_altered_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    copied_runtime = tmp_path / "effect-preset-matrix-v5"
    shutil.copytree(matrix_provider.FROZEN_RUNTIME_ROOT, copied_runtime)
    copied_project = copied_runtime / "frozen-project"
    source = copied_project / "src/fastapi_endpoint_detector/analyzer/mypy_analyzer.py"
    source.write_text(source.read_text(encoding="utf-8") + "\n# altered\n", encoding="utf-8")
    runtime_manifest_path = copied_runtime / "frozen-runtime.json"
    manifest = json.loads(runtime_manifest_path.read_text(encoding="utf-8"))
    source_row = next(
        row
        for row in manifest["files"]
        if row["path"] == "src/fastapi_endpoint_detector/analyzer/mypy_analyzer.py"
    )
    source_row["sha256"] = matrix_provider._sha256(source.read_bytes())
    runtime_manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(matrix_provider, "FROZEN_RUNTIME_ROOT", copied_runtime)
    monkeypatch.setattr(matrix_provider, "FROZEN_PROJECT_ROOT", copied_project)
    monkeypatch.setattr(matrix_provider, "FROZEN_RUNTIME_MANIFEST_PATH", runtime_manifest_path)
    monkeypatch.setattr(
        matrix_provider,
        "FROZEN_RUNNER_PATH",
        Path(matrix_provider.__file__).with_name("effect_preset_frozen_runner.py"),
    )

    with pytest.raises(MatrixEvidenceError, match="frozen analyzer runtime manifest hash mismatch"):
        matrix_provider._load_analyzer_source_snapshots()


def test_replay_environment_locks_match_runtime_manifest() -> None:
    tomllib = importlib.import_module("tomllib" if sys.version_info >= (3, 11) else "tomli")
    runtime = json.loads(matrix_provider.FROZEN_RUNTIME_MANIFEST_PATH.read_text(encoding="utf-8"))
    environment_rows = runtime["replay_environment_files"]
    project_files = {
        row["path"].rsplit("/", 1)[0]: row["path"]
        for row in environment_rows
        if row["path"].endswith("/pyproject.toml")
    }
    assert len(project_files) == 4
    for environment, pyproject_path in project_files.items():
        lock_path = f"{environment}/uv.lock"
        assert lock_path in {row["path"] for row in environment_rows}
        lock = tomllib.loads((matrix_provider.FROZEN_RUNTIME_ROOT / lock_path).read_text())
        versions = {row["name"].lower(): row["version"] for row in lock["package"]}
        directory_name = Path(environment).name
        expected_mypy = directory_name.rsplit("-mypy-", 1)[1]
        assert versions["mypy"] == expected_mypy
        for distribution, version in runtime["runtime_distributions"].items():
            assert versions[distribution.lower()] == version
        project = tomllib.loads((matrix_provider.FROZEN_RUNTIME_ROOT / pyproject_path).read_text())
        python_version = directory_name.split("-mypy-", 1)[0].removeprefix("python-")
        major, minor = python_version.split(".")[:2]
        assert project["project"]["requires-python"] == (
            f">={major}.{minor},<{major}.{int(minor) + 1}"
        )


def test_frozen_replay_rejects_wrong_runtime_dependency_version() -> None:
    def wrong_librt_version(distribution: str) -> str:
        if distribution == "librt":
            return "0.0.0"
        return frozen_runner._RUNTIME_DISTRIBUTIONS[distribution]

    with pytest.raises(frozen_runner.FrozenReplayError, match="identity mismatch: librt"):
        frozen_runner._verify_runtime_distributions(wrong_librt_version)


def test_controlled_results_reject_forged_aggregates(tmp_path: Path) -> None:
    result = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
    result["controlled_evaluation"]["observed"]["matched_calls"] = 11
    result["controlled_evaluation"]["observed"]["unmatched_calls"] = 0
    altered = tmp_path / "altered-controlled-results.json"
    altered.write_text(json.dumps(result), encoding="utf-8")

    with pytest.raises(MatrixEvidenceError, match="aggregate does not match raw"):
        load_controlled_results(altered)


def test_pinned_package_symbol_cases_replay_with_same_name_negatives() -> None:
    result = load_package_analyzer_results()
    assert len(result["cases"]) == 6
    assert {(row["distribution"], row["version"]) for row in result["cases"]} == {
        ("requests", "2.32.3"),
        ("aiohttp", "3.11.11"),
        ("redis", "5.2.1"),
        ("pymongo", "4.10.1"),
        ("sqlalchemy", "2.0.36"),
        ("mypy-boto3-s3", "1.35.92"),
    }
    assert result["observed"]["matched_calls"] == 6
    assert result["observed"]["unrelated_same_name_negative_calls"] == 6
    assert result["observed"]["unmatched_calls"] == 6
    assert result["observed"]["selector_binding_negative_controls"] == 2
    assert result["source_execution"] is False
    assert result["upstream_package_code_imported_or_executed"] is False
    s3_case = next(row for row in result["cases"] if row["case_id"].startswith("typed-s3-"))
    assert s3_case["signature_evidence"]["source_signature"] == (
        "(self, **kwargs: Unpack[PutObjectRequestRequestTypeDef])"
    )
    assert "Bucket" in s3_case["signature_evidence"]["selector_parameters"]
    assert s3_case["signature_evidence"]["selector_required_parameters"] == ["Bucket", "Key"]
    assert "BogusField" not in s3_case["generated_signature"]
    assert s3_case["generated_signature"].startswith(
        "def method(self, Bucket, Key, ACL = ..., Body = ..."
    )
    assert all(row["binding_status"] == "present" for row in s3_case["selector_bindings"])
    assert [row["control_id"] for row in s3_case["binding_controls"]] == [
        "missing-selected-body",
        "body-bound-positionally",
    ]
    assert all(
        row["selector_binding_status"] == "rejected_incomplete_or_wrong_binding"
        and row["analyzer_audit_status"] == "matched"
        for row in s3_case["binding_controls"]
    )
    assert {row["reason_code"] for row in result["unsupported_cases"]} == {
        "descriptor_signature_unavailable",
        "no_exact_preset_contract",
    }


def test_pinned_typed_dict_signature_rejects_unknown_case_keyword() -> None:
    manifest = load_manifest()
    package = next(row for row in manifest["packages"] if row["distribution"] == "mypy-boto3-s3")
    declaration = next(
        row
        for row in package["declared_symbols"]
        if row["symbol"] == "mypy_boto3_s3.client.S3Client.put_object"
    )
    evidence = matrix_provider._package_signature_evidence(package, declaration)
    case = json.loads(matrix_provider.PACKAGE_CASES_PATH.read_text(encoding="utf-8"))["cases"][-1]
    preset = load_effect_preset(case["preset_selector"])
    contract = next(
        item for item in preset.document.contracts if item.id == declaration["preset_contract"]
    )
    assert contract.value is not None
    selectors = {
        "resource": contract.resource.model_dump(mode="json"),
        "value": contract.value.model_dump(mode="json"),
    }
    altered = json.loads(json.dumps(case))
    altered["arguments"][0]["name"] = "BogusField"

    with pytest.raises(MatrixEvidenceError, match="absent from pinned TypedDict selector"):
        matrix_provider._replay_package_case(altered, evidence, selectors)

    missing_body = json.loads(json.dumps(case))
    missing_body["arguments"] = [arg for arg in missing_body["arguments"] if arg["name"] != "Body"]
    with pytest.raises(MatrixEvidenceError, match=r"contract-selected value argument.*Body"):
        matrix_provider._replay_package_case(missing_body, evidence, selectors)

    wrong_binding = json.loads(json.dumps(case))
    body_arg = next(arg for arg in wrong_binding["arguments"] if arg.get("name") == "Body")
    wrong_binding["arguments"].remove(body_arg)
    wrong_binding["arguments"].append({"kind": "positional", "value": body_arg["value"]})
    with pytest.raises(MatrixEvidenceError, match=r"contract-selected value argument.*Body"):
        matrix_provider._replay_package_case(wrong_binding, evidence, selectors)


def test_package_case_rejects_duplicate_keyword_bindings() -> None:
    with pytest.raises(MatrixEvidenceError, match="repeats a keyword binding"):
        matrix_provider._render_case_arguments(
            [
                {"kind": "keyword", "name": "Body", "value": "first"},
                {"kind": "keyword", "name": "Body", "value": "second"},
            ]
        )


def test_package_symbol_results_reject_forged_aggregates(tmp_path: Path) -> None:
    source = matrix_provider.PACKAGE_CASE_RESULTS_PATH
    result = json.loads(source.read_text(encoding="utf-8"))
    result["observed"]["matched_calls"] = 12
    altered = tmp_path / "altered-package-results.json"
    altered.write_text(json.dumps(result), encoding="utf-8")

    with pytest.raises(MatrixEvidenceError, match="aggregate does not match raw"):
        load_package_analyzer_results(altered)


def test_controlled_results_require_exact_analyzer_source_hash_path_set(tmp_path: Path) -> None:
    result = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
    hashes = result["controlled_evaluation"]["analyzer_source_hashes"]
    hashes.pop("src/fastapi_endpoint_detector/analyzer/mypy_analyzer.py")
    altered = tmp_path / "missing-mypy-analyzer-hash.json"
    altered.write_text(json.dumps(result), encoding="utf-8")

    with pytest.raises(MatrixEvidenceError, match="path set is incomplete or excessive"):
        load_controlled_results(altered)


def test_controlled_results_reject_extra_analyzer_source_hash(tmp_path: Path) -> None:
    result = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
    result["controlled_evaluation"]["analyzer_source_hashes"]["src/extra.py"] = "sha256:" + "0" * 64
    altered = tmp_path / "extra-analyzer-hash.json"
    altered.write_text(json.dumps(result), encoding="utf-8")

    with pytest.raises(MatrixEvidenceError, match="path set is incomplete or excessive"):
        load_controlled_results(altered)


def test_committed_analyzer_source_snapshot_requires_exact_unique_path_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot = json.loads(ANALYZER_SNAPSHOT_PATH.read_text(encoding="utf-8"))
    snapshot["source_files"].append(snapshot["source_files"][-1])
    altered = tmp_path / "duplicate-source-path.json"
    altered.write_text(json.dumps(snapshot), encoding="utf-8")

    monkeypatch.setattr(matrix_provider, "ANALYZER_SNAPSHOT_PATH", altered)
    with pytest.raises(MatrixEvidenceError, match="snapshot path set is invalid"):
        load_controlled_results()


def test_controlled_results_reject_raw_rows_that_disagree_with_replay(
    tmp_path: Path,
) -> None:
    result = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
    row = next(
        item
        for item in result["controlled_evaluation"]["observations"]
        if item["source_spelling"] == "foreign.get"
    )
    row["audit_status"] = "matched"
    row["contract_id"] = "forged-contract"
    row["contract_hash"] = "sha256:" + "0" * 64
    altered = tmp_path / "altered-raw-observations.json"
    altered.write_text(json.dumps(result), encoding="utf-8")

    with pytest.raises(MatrixEvidenceError, match="negative fixture call unexpectedly matched"):
        load_controlled_results(altered)


def test_controlled_result_rejects_invalid_status_types(tmp_path: Path) -> None:
    result = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
    result["controlled_evaluation"]["observations"][0]["audit_status"] = []
    altered = tmp_path / "malformed-status.json"
    altered.write_text(json.dumps(result), encoding="utf-8")

    with pytest.raises(MatrixEvidenceError, match="invalid identity or status"):
        load_controlled_results(altered)


def test_exact_pathlib_calls_match_and_unrelated_same_name_methods_do_not(
    tmp_path: Path,
) -> None:
    main = tmp_path / "main.py"
    main.write_text(
        "from pathlib import Path\n\n"
        "class Foreign:\n"
        "    def read_text(self) -> str: ...\n"
        "    def get(self, value: str) -> str: ...\n"
        "    def set(self, value: str, item: str) -> None: ...\n"
        "    def write(self, value: str) -> None: ...\n"
        "    def send(self, target: str, value: str) -> None: ...\n\n"
        "def handler(path: Path, foreign: Foreign) -> None:\n"
        "    path.read_text(encoding='utf-8')\n"
        "    path.write_text('active', encoding='utf-8')\n"
        "    opened = path.open('r', encoding='utf-8')\n"
        "    opened.read()\n"
        "    handle = open('fixture.txt', 'r', encoding='utf-8')\n"
        "    handle.read()\n"
        "    foreign.read_text()\n"
        "    foreign.get('acct:42')\n"
        "    foreign.set('acct:42', 'active')\n"
        "    foreign.write('active')\n"
        "    foreign.send('events', 'payload')\n",
        encoding="utf-8",
    )
    endpoint = _endpoint(main, 10)
    dependencies = MypyAnalyzer(tmp_path, max_depth=1).analyze_endpoint(endpoint)
    audit = audit_effect_contracts(
        load_effect_preset("filesystem-v1"),
        source_root=tmp_path,
        inventory=EndpointInventory(endpoints=[endpoint]),
        endpoint_call_sites=[(endpoint, dependencies.get_resolved_call_sites())],
        track_transitive=False,
        max_depth=1,
        cache_enabled=False,
        resolver_versions=(f"mypy@{MypyAnalyzer(tmp_path).resolver_version}",),
    )

    assert len(audit.occurrences) == 11, [
        (item.source_spelling, item.canonical_symbol, item.reason_code)
        for item in audit.occurrences
    ]
    assert audit.summary.matched_calls == 4, [
        (item.source_spelling, item.canonical_symbol, item.reason_code)
        for item in audit.occurrences
    ]
    assert {item.contract_id for item in audit.occurrences if item.contract_id} == {
        "pathlib-read-text",
        "pathlib-write-text",
        "io-text-read",
    }
    negative_spellings = {
        "foreign.read_text",
        "foreign.get",
        "foreign.set",
        "foreign.write",
        "foreign.send",
    }
    negative_calls = [
        item for item in audit.occurrences if item.source_spelling in negative_spellings
    ]
    assert {item.source_spelling for item in negative_calls} == negative_spellings
    resolver_statuses = {
        item.source_spelling: _assert_foreign_call_is_unmatched_or_open_dispatch(item)
        for item in negative_calls
    }
    exact_negative_spellings = {
        spelling for spelling, status in resolver_statuses.items() if status == "exact"
    }
    ambiguous_negative_spellings = {
        spelling for spelling, status in resolver_statuses.items() if status == "ambiguous"
    }
    assert exact_negative_spellings.isdisjoint(ambiguous_negative_spellings)
    assert exact_negative_spellings | ambiguous_negative_spellings == negative_spellings
    assert audit.summary.unmatched_calls == 2 + len(exact_negative_spellings)
    assert audit.summary.ambiguous_calls == len(ambiguous_negative_spellings)
    open_unmatched_symbols = {
        item.canonical_symbol
        for item in audit.occurrences
        if item.source_spelling == "open" and item.audit_status.value == "unmatched"
    }
    assert open_unmatched_symbols == {"builtins.open"}
    open_constructors = [
        item for item in audit.occurrences if item.source_spelling in {"open", "path.open"}
    ]
    assert {item.source_spelling for item in open_constructors} == {"open", "path.open"}
    assert all(
        item.audit_status.value == "unmatched" and item.contract_id is None
        for item in open_constructors
    )
    write_site = next(
        item
        for item in dependencies.get_resolved_call_sites()
        if item.source_spelling == "path.write_text"
    )
    assert [(item.keyword, item.positional_index) for item in write_site.arguments] == [
        (None, 0),
        ("encoding", None),
    ]
    assert write_site.arguments[0].status.value == "exact"
    reads = [item for item in audit.occurrences if item.contract_id == "io-text-read"]
    assert len(reads) == 2
    by_line = {item.line: item for item in reads}
    path_open_line = next(
        item.line
        for item in dependencies.get_resolved_call_sites()
        if item.source_spelling == "opened.read"
    )
    builtin_open_line = next(
        item.line
        for item in dependencies.get_resolved_call_sites()
        if item.source_spelling == "handle.read"
    )
    path_origin = by_line[path_open_line].receiver_origin
    builtin_origin = by_line[builtin_open_line].receiver_origin
    assert path_origin is not None
    assert path_origin.status.value == "unavailable"
    assert builtin_origin is not None
    assert builtin_origin.status.value == "exact"
