from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from benchmarks.providers.effect_preset_matrix import (
    MANIFEST_PATH,
    RESULTS_PATH,
    MatrixEvidenceError,
    exact_release_status,
    load_controlled_results,
    load_manifest,
    summarize_matrix,
    verify_artifacts,
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
    from pathlib import Path


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
    assert exact_release_status("mypy-boto3-sqs", "1.35.91", manifest) == "audited_exact_release"
    assert exact_release_status("mypy-boto3-sqs", "1.35.92", manifest) == "not_audited"
    summary = summarize_matrix(manifest)
    assert summary["package_releases"] == 11
    assert len(verify_preset_contracts(manifest)) == 5
    assert summary["source_inspected"] == 8
    assert summary["source_partially_inspected"] == 3
    assert summary["analyzer_observations"] == 1
    assert summary["unsupported_cases"] == 2
    assert (
        summary["range_compatibility"]
        == "not_evaluated; each release row is one exact artifact only"
    )
    assert summary["real_world_evaluation"] == "not_evaluated"


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


def test_preset_contract_hashes_fail_closed(tmp_path: Path) -> None:
    manifest = load_manifest()
    contract = manifest["versioned_contract_sets"][0]
    path = tmp_path / "altered-preset.yaml"
    path.write_text("changed: true\n", encoding="utf-8")
    contract["preset_path"] = str(path)

    with pytest.raises(MatrixEvidenceError, match="preset contract source hash mismatch"):
        verify_preset_contracts(manifest)


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

    with pytest.raises(MatrixEvidenceError, match="exact dotted names"):
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


def test_controlled_results_reject_forged_denominator(tmp_path: Path) -> None:
    result = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
    result["controlled_evaluation"]["observed"]["unmatched_calls"] = 6
    altered = tmp_path / "altered-controlled-results.json"
    altered.write_text(json.dumps(result), encoding="utf-8")

    with pytest.raises(MatrixEvidenceError, match="call totals"):
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

    assert audit.summary.matched_calls == 4, [
        (item.source_spelling, item.canonical_symbol, item.reason_code)
        for item in audit.occurrences
    ]
    assert audit.summary.unmatched_calls == 7
    assert {item.contract_id for item in audit.occurrences if item.contract_id} == {
        "pathlib-read-text",
        "pathlib-write-text",
        "io-text-read",
    }
    unmatched_symbols = {
        item.canonical_symbol.rsplit(".", 1)[-1]
        for item in audit.occurrences
        if item.canonical_symbol is not None and item.audit_status.value == "unmatched"
    }
    assert unmatched_symbols == {
        "read_text",
        "open",
        "get",
        "set",
        "write",
        "send",
    }
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
    assert by_line[path_open_line].receiver_origin is not None
    assert by_line[path_open_line].receiver_origin.status.value == "unavailable"
    assert by_line[builtin_open_line].receiver_origin is not None
    assert by_line[builtin_open_line].receiver_origin.status.value == "exact"
