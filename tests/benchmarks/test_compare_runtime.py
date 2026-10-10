"""Frozen secure/runtime comparison protocol tests."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from typing import TYPE_CHECKING, Any

import pytest
from benchmarks.real_world import compare_runtime
from benchmarks.real_world.compare_runtime import (
    ComparisonError,
    compare,
    compare_target_baseline,
    main,
)

if TYPE_CHECKING:
    from pathlib import Path

from fastapi_endpoint_detector.analyzer.framework_phase_bridge import SourceIdentity
from fastapi_endpoint_detector.analyzer.framework_phase_runtime import (
    PhaseManifest,
    PhaseManifestEntry,
    PhaseObservation,
)
from fastapi_endpoint_detector.analyzer.runtime_custody import (
    CustodyBinding,
    RuntimeCustodyError,
    custody_digest,
    runtime_custody_authority_from_environment,
    runtime_record_request_digest,
    verify_runtime_record_custody,
)
from fastapi_endpoint_detector.models.surface_contract import load_surface_preset

CUSTODY_TEST_KEY = "controlled-custody-test-secret-at-least-32-bytes"


@pytest.fixture(autouse=True)
def controlled_custody_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    # Synthetic comparator inputs use a test authority, never a real sandbox receipt.
    monkeypatch.setenv("FASTAPI_DETECTOR_RUNTIME_CUSTODY_KEY", CUSTODY_TEST_KEY)
    monkeypatch.setenv("FASTAPI_DETECTOR_RUNTIME_CUSTODY_KEY_ID", "fixture-custody-authority")
    monkeypatch.setenv("FASTAPI_DETECTOR_RUNTIME_TRUST_VERSION", "controlled protocol fixture")


H = "sha256:" + "a" * 64


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _record(
    mode: str,
    *,
    snapshot: str = "target",
    lock: str = H,
    measured: bool = True,
) -> dict[str, Any]:
    inventory = {
        "inventory_status": "established" if mode == "secure" else "runtime_observed",
        "endpoints": [
            {"methods": ["GET"], "path": "/users/{user_id}", "surface": None},
            {"methods": ["POST"], "path": "/jobs", "surface": None},
        ],
    }
    impact = {
        "candidate_endpoints": [
            {
                "endpoint": {
                    "methods": ["GET"],
                    "path": "/users/{user_id}" if mode == "secure" else "/users/{id}",
                    "surface": None,
                }
            }
        ]
    }
    state: dict[str, object]
    resource: dict[str, object]
    if measured:
        state = {"status": "measured", "seconds": 1.0}
        resource = {"status": "measured", "bytes": 104857600}
    else:
        state = {"status": "not_measured", "reason": "collector_unavailable"}
        resource = {"status": "not_measured", "reason": "collector_unavailable"}
    configuration: dict[str, object] = {
        "app_entry": None,
        "bootstrap_entry": None,
        "app_variable": "app",
        "backend": "mypy",
        "dependency_lock_sha256": lock,
    }
    source = _digest("b" if snapshot == "target" else "c")
    image = f"registry.example/detector@{_digest('d' if snapshot == 'target' else 'e')}"
    provenance = {
        "source_sha256": source,
        "tool_sha256": _digest("f"),
        "effective_invocation_sha256": _digest("1" if mode == "secure" else "2"),
        "dependency_lock_sha256": lock,
        "runtime_image_digest": image,
        "runtime_sbom_sha256": _digest("3" if snapshot == "target" else "4"),
    }
    if mode == "runtime":
        provenance.update(
            runtime_seccomp_sha256=_digest("5"),
            runtime_policy_sha256=_digest("6"),
            runtime_attestation_sha256=_digest("7"),
            runtime_canary_receipt_sha256=_digest("8"),
        )
    value = {
        "schema_version": 1,
        "mode": mode,
        "snapshot": snapshot,
        "status": "success",
        "configuration": configuration,
        "timing": {"list": dict(state), "impact": dict(state)},
        "resources": {"peak_rss_bytes": resource},
        "failure": None,
        "inventory": inventory,
        "impact": impact,
        "provenance": provenance,
    }
    manifest = _phase_manifest(source)
    value["framework_phase_manifest"] = manifest
    if mode == "runtime":
        observations = {
            phase: PhaseObservation(
                manifest_sha256=PhaseManifest.model_validate(manifest).digest,
                observed=(),
                unavailable=(),
                execution_status="completed",
            ).model_dump(mode="json")
            for phase in ("list", "impact")
        }
        value["framework_phase"] = {
            "manifest": manifest,
            "observations": observations,
            "role": "positive_observation_only",
        }
    return value


def _phase_manifest(source: str) -> dict[str, Any]:
    identity = SourceIdentity(
        module="app",
        symbol="startup",
        file="/snapshot/app.py",
        line=1,
        column=0,
        source_sha256=source,
    )
    digest = source.removeprefix("sha256:")
    entry = PhaseManifestEntry(
        callback=identity,
        registration=identity,
        phase="startup",
        execution_conditions=("startup succeeds",),
        contract_id="fastapi-lifespan-startup",
        contract_sha256=load_surface_preset("framework-v1").document.contract_hashes[
            "fastapi-lifespan-startup"
        ],
        source_sha256=source,
        callback_file_sha256=digest,
        registration_file_sha256=digest,
        inventory_sha256=source,
        engine_sha256=source,
        config_sha256=source,
    )
    return PhaseManifest(entries=(entry,)).model_dump(mode="json")


def _sign_controlled_record(value: dict[str, Any]) -> None:
    """Seal the final synthetic fixture; mutations after this must fail verification."""
    envelopes = {}
    for phase in ("list", "impact"):
        binding = CustodyBinding(
            snapshot=value["snapshot"],
            phase=phase,
            nonce=secrets.token_hex(16),
            request_sha256=runtime_record_request_digest(value),
            canary_receipt_sha256=value["provenance"]["runtime_canary_receipt_sha256"],
            runtime_version="controlled protocol fixture",
        )
        result = {
            "inventory": value["inventory"] if phase == "list" else None,
            "impact": value["impact"] if phase == "impact" else None,
            "seconds": value["timing"][phase].get("seconds"),
            "peak_rss_bytes": value["resources"]["peak_rss_bytes"].get("bytes"),
            "phase_manifest": value["framework_phase_manifest"],
            "phase_observation": value["framework_phase"]["observations"][phase],
        }
        now = int(time.time())
        receipt = {
            "binding": binding.model_dump(mode="json"),
            "result_sha256": custody_digest(result),
            "key_id": "fixture-custody-authority",
            "issued_at": now,
            "expires_at": now + 60,
        }
        signature = hmac.new(
            CUSTODY_TEST_KEY.encode(),
            json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode(),
            hashlib.sha256,
        ).hexdigest()
        envelopes[phase] = {
            "binding": binding.model_dump(mode="json"),
            "result": result,
            "receipt": {**receipt, "signature": signature},
        }
    value["runtime_custody"] = envelopes


def _write(path: Path, value: object) -> None:
    if (
        isinstance(value, dict)
        and value.get("mode") == "runtime"
        and value.get("status") == "success"
        and isinstance(value.get("provenance"), dict)
        and "runtime_canary_receipt_sha256" in value["provenance"]
    ):
        _sign_controlled_record(value)
    path.write_text(json.dumps(value), encoding="utf-8")


def _matrix_paths(tmp_path: Path) -> dict[tuple[str, str], Path]:
    paths: dict[tuple[str, str], Path] = {}
    for snapshot in ("target", "baseline"):
        lock = _digest("7" if snapshot == "target" else "8")
        for mode in ("secure", "runtime"):
            path = tmp_path / f"{mode}-{snapshot}.json"
            _write(path, _record(mode, snapshot=snapshot, lock=lock))
            paths[(snapshot, mode)] = path
    return paths


@pytest.mark.parametrize(
    "mutation",
    [
        "inventory",
        "impact",
        "request",
        "receipt",
        "rss",
        "phase_manifest",
        "callback",
        "observation",
    ],
)
def test_runtime_custody_rejects_changes_after_receipt_issuance(
    tmp_path: Path, mutation: str
) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    _write(secure, _record("secure"))
    record = _record("runtime")
    _sign_controlled_record(record)
    if mutation == "inventory":
        record["inventory"]["endpoints"] = []
    elif mutation == "impact":
        record["impact"]["candidate_endpoints"] = []
    elif mutation == "request":
        record["provenance"]["runtime_canary_receipt_sha256"] = _digest("9")
    elif mutation == "receipt":
        record.pop("runtime_custody")
    elif mutation == "phase_manifest":
        record["framework_phase_manifest"]["entries"][0]["contract_sha256"] = _digest("9")
        record["framework_phase"]["manifest"] = record["framework_phase_manifest"]
    elif mutation == "callback":
        record["framework_phase_manifest"]["entries"][0]["callback"]["symbol"] = "altered"
        record["framework_phase"]["manifest"] = record["framework_phase_manifest"]
    elif mutation == "observation":
        record["framework_phase"]["observations"]["list"]["execution_status"] = "unavailable"
    else:
        record["resources"]["peak_rss_bytes"]["bytes"] += 1
    # Deliberately write without the fixture signer: retained receipts are immutable.
    runtime.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(ComparisonError):
        compare(secure, runtime)


def test_runtime_comparator_rejects_success_without_phase_observations(tmp_path: Path) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    _write(secure, _record("secure"))
    record = _record("runtime")
    _sign_controlled_record(record)
    record.pop("framework_phase")
    record.pop("framework_phase_manifest")
    runtime.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(ComparisonError, match="phase comparison"):
        compare(secure, runtime)


def test_runtime_comparator_accepts_signed_completed_empty_phase_inventory(tmp_path: Path) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    secure_record = _record("secure")
    record = _record("runtime")
    manifest = PhaseManifest(entries=()).model_dump(mode="json")
    digest = PhaseManifest.model_validate(manifest).digest
    secure_record["framework_phase_manifest"] = manifest
    _write(secure, secure_record)
    record["framework_phase_manifest"] = manifest
    record["framework_phase"] = {
        "manifest": manifest,
        "observations": {
            phase: PhaseObservation(
                manifest_sha256=digest,
                observed=(),
                unavailable=(),
                execution_status="completed",
            ).model_dump(mode="json")
            for phase in ("list", "impact")
        },
        "role": "positive_observation_only",
    }
    _write(runtime, record)

    compare(secure, runtime)


def test_phase_manifest_accepts_distinct_snapshot_and_segment_hashes(tmp_path: Path) -> None:
    secure_record = _record("secure")
    record = _record("runtime")
    manifest = secure_record["framework_phase_manifest"]
    entry = manifest["entries"][0]
    entry["callback"]["source_sha256"] = _digest("1")
    entry["registration"] = {**entry["registration"], "source_sha256": _digest("2")}
    record["framework_phase_manifest"] = manifest
    record["framework_phase"]["manifest"] = manifest
    digest = PhaseManifest.model_validate(manifest).digest
    for phase in ("list", "impact"):
        record["framework_phase"]["observations"][phase]["manifest_sha256"] = digest
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    _write(secure, secure_record)
    _write(runtime, record)
    compare(secure, runtime)
    # The separate hash domains remain authenticated by the custody envelope.
    record["framework_phase_manifest"]["entries"][0]["callback"]["source_sha256"] = _digest("9")
    runtime.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(ComparisonError):
        compare(secure, runtime)


def test_failed_lifespan_cannot_claim_positive_phase_observations(tmp_path: Path) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    _write(secure, _record("secure"))
    record = _record("runtime")
    record["framework_phase"]["observations"]["list"]["execution_status"] = "unavailable"
    record["framework_phase"]["observations"]["list"]["observed"] = [{"phase": "startup"}]
    _sign_controlled_record(record)
    runtime.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(ComparisonError, match="phase comparison"):
        compare(secure, runtime)


def test_archival_comparison_retains_custody_after_launch_receipt_expiry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    _write(secure, _record("secure"))
    record = _record("runtime")
    _write(runtime, record)
    later = record["runtime_custody"]["list"]["receipt"]["issued_at"] + 3600
    # Receipt freshness still protects production admission; reading an archive
    # authenticates the retained execution rather than claiming a new launch.
    with pytest.raises(RuntimeCustodyError, match="validity window"):
        verify_runtime_record_custody(
            record, authority=runtime_custody_authority_from_environment(), now=later
        )
    monkeypatch.setattr(
        "fastapi_endpoint_detector.analyzer.runtime_artifact_comparison.time.time", lambda: later
    )
    assert compare(secure, runtime)["quality_eligible"] is True
    record["runtime_custody"]["impact"]["receipt"]["signature"] = "0" * 64
    runtime.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(ComparisonError, match="signature"):
        compare(secure, runtime)


@pytest.mark.parametrize("phase_value", [{}, {"observations": []}, "invalid", None])
def test_failed_runtime_forbids_unsigned_phase_metadata(
    tmp_path: Path, phase_value: object
) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    _write(secure, _record("secure"))
    record = _record("runtime")
    record.update(
        status="failure",
        failure={"phase": "unavailable", "message": "abstain"},
        inventory=None,
        impact=None,
        framework_phase=phase_value,
    )
    _write(runtime, record)
    with pytest.raises(ComparisonError, match="failed records forbid runtime phase"):
        compare(secure, runtime)


def _compare_matrix(paths: dict[tuple[str, str], Path]) -> dict[str, Any]:
    return compare_target_baseline(
        secure_target_path=paths[("target", "secure")],
        runtime_target_path=paths[("target", "runtime")],
        secure_baseline_path=paths[("baseline", "secure")],
        runtime_baseline_path=paths[("baseline", "runtime")],
    )


def _cli_arguments(paths: dict[tuple[str, str], Path], output: Path) -> list[str]:
    return [
        "--secure-target",
        str(paths[("target", "secure")]),
        "--runtime-target",
        str(paths[("target", "runtime")]),
        "--secure-baseline",
        str(paths[("baseline", "secure")]),
        "--runtime-baseline",
        str(paths[("baseline", "runtime")]),
        "--output",
        str(output),
    ]


def test_paired_success_preserves_exact_and_normalized_metrics(tmp_path: Path) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    _write(secure, _record("secure"))
    runtime_record = _record("runtime")
    runtime_record["inventory"]["endpoints"].append(
        {"methods": ["DELETE"], "path": "/runtime-only", "surface": None}
    )
    _write(runtime, runtime_record)

    result = compare(secure, runtime)

    assert result["runtime_role"] == "positive_observation_comparator_not_truth"
    assert result["paired_success"] is True
    assert result["quality_eligible"] is True
    assert result["inventory"]["runtime_only"] == ["DELETE /runtime-only"]
    assert result["inventory"]["interpretation"] == "requires_source_adjudication"
    assert result["impact_exact"]["intersection_count"] == 0
    assert result["impact_normalized"]["intersection_count"] == 1
    assert result["inventory_strength"] == {
        "secure": "established",
        "runtime": "runtime_observed",
    }
    assert result["provenance_digests"]["runtime"].startswith("sha256:")


def test_failure_phase_abstains_from_quality_metrics(tmp_path: Path) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    _write(secure, _record("secure"))
    failed = _record("runtime")
    failed.update(
        status="failure",
        failure={"phase": "import", "message": "missing dependency"},
        inventory=None,
        impact=None,
    )
    failed.pop("framework_phase")
    _write(runtime, failed)

    result = compare(secure, runtime)

    assert result["paired_success"] is False
    assert result["quality_eligible"] is False
    assert result["inventory"] is None
    assert result["failure"]["runtime"]["phase"] == "import"


@pytest.mark.parametrize("field", ["app_entry", "bootstrap_entry"])
def test_runtime_entry_selection_is_operational_abstention(tmp_path: Path, field: str) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    secure_record = _record("secure")
    runtime_record = _record("runtime")
    secure_record["configuration"][field] = "main:create_app"
    runtime_record["configuration"][field] = "main:create_app"
    runtime_record.update(
        status="failure",
        failure={"phase": "app_resolution", "message": "runtime entry support unavailable"},
        inventory=None,
        impact=None,
    )
    runtime_record.pop("framework_phase")
    _write(secure, secure_record)
    _write(runtime, runtime_record)

    result = compare(secure, runtime)
    assert result["paired_success"] is False
    assert result["quality_eligible"] is False
    assert result["failure"]["runtime"]["phase"] == "app_resolution"


@pytest.mark.parametrize("mode", ["secure", "runtime"])
def test_absent_provenance_fails_closed(tmp_path: Path, mode: str) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    records = {name: _record(name) for name in ("secure", "runtime")}
    records[mode].pop("provenance")
    _write(secure, records["secure"])
    _write(runtime, records["runtime"])

    with pytest.raises(ComparisonError, match="missing required"):
        compare(secure, runtime)


def test_spoofed_mode_or_digest_provenance_fails_closed(tmp_path: Path) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    secure_record = _record("secure")
    runtime_record = _record("runtime")
    runtime_record["provenance"] = dict(secure_record["provenance"])
    _write(secure, secure_record)
    _write(runtime, runtime_record)
    with pytest.raises(ComparisonError, match="mode-specific"):
        compare(secure, runtime)

    runtime_record = _record("runtime")
    runtime_record["provenance"]["runtime_policy_sha256"] = "sha256:" + "A" * 64
    _write(runtime, runtime_record)
    with pytest.raises(ComparisonError, match="lowercase sha256"):
        compare(secure, runtime)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("timing", {"arbitrary": {"status": "measured", "seconds": 1}}),
        ("timing", {"list": {"status": "invented"}, "impact": {"status": "invented"}}),
        ("resources", {"rss_mib": 100}),
    ],
)
def test_arbitrary_telemetry_fails_closed(tmp_path: Path, field: str, value: object) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    secure_record = _record("secure")
    secure_record[field] = value
    _write(secure, secure_record)
    _write(runtime, _record("runtime"))

    with pytest.raises(ComparisonError):
        compare(secure, runtime)


@pytest.mark.parametrize(
    ("mode", "status"),
    [("secure", "invented"), ("runtime", "established"), ("runtime", "invented")],
)
def test_arbitrary_inventory_status_fails_closed(tmp_path: Path, mode: str, status: str) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    records = {name: _record(name) for name in ("secure", "runtime")}
    records[mode]["inventory"]["inventory_status"] = status
    _write(secure, records["secure"])
    _write(runtime, records["runtime"])

    with pytest.raises(ComparisonError, match="inventory status"):
        compare(secure, runtime)


def test_not_measured_attestations_suppress_quality_but_remain_operational(
    tmp_path: Path,
) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    _write(secure, _record("secure", measured=False))
    _write(runtime, _record("runtime"))

    result = compare(secure, runtime)

    assert result["paired_success"] is True
    assert result["quality_eligible"] is False
    assert result["inventory"] is None
    assert result["timing"]["secure"]["list"]["status"] == "not_measured"


def test_not_measured_pair_rejects_malformed_success_artifact(tmp_path: Path) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    malformed = _record("secure", measured=False)
    malformed["inventory"].pop("endpoints")
    _write(secure, malformed)
    _write(runtime, _record("runtime"))

    with pytest.raises(ComparisonError, match="inventory endpoints must be an array"):
        compare(secure, runtime)


@pytest.mark.parametrize(
    "phase",
    ["dependency", "import", "app_resolution", "extraction", "timeout", "unavailable"],
)
def test_all_failure_phases_are_versioned(tmp_path: Path, phase: str) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    first = _record("secure")
    second = _record("runtime")
    for record in (first, second):
        record.update(
            status="failure",
            failure={"phase": phase, "message": "abstain"},
            inventory=None,
            impact=None,
        )
    second.pop("framework_phase")
    _write(secure, first)
    _write(runtime, second)

    assert compare(secure, runtime)["paired_success"] is False


@pytest.mark.parametrize("invalid", [True, float("nan"), float("inf"), -1.0])
def test_measurement_rejects_bool_non_finite_and_negative_values(
    tmp_path: Path, invalid: object
) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    secure_record = _record("secure")
    secure_record["timing"]["impact"] = {"status": "measured", "seconds": invalid}
    _write(secure, secure_record)
    _write(runtime, _record("runtime"))

    with pytest.raises(ComparisonError):
        compare(secure, runtime)


def test_comparison_rejects_duplicate_json_members(tmp_path: Path) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    secure.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
    _write(runtime, _record("runtime"))

    with pytest.raises(ComparisonError, match="duplicate JSON member"):
        compare(secure, runtime)


def test_target_baseline_permits_snapshot_specific_environments(tmp_path: Path) -> None:
    paths = _matrix_paths(tmp_path)

    result = _compare_matrix(paths)

    assert (
        result["configuration"]["snapshots"]["target"]["dependency_lock_sha256"]
        != result["configuration"]["snapshots"]["baseline"]["dependency_lock_sha256"]
    )
    assert result["operational"]["peak_rss_bytes"] == {
        "secure": {"status": "measured", "bytes": 104857600},
        "runtime": {"status": "measured", "bytes": 104857600},
    }
    assert result["paired_success_quality"]["eligible_snapshots"] == ["target", "baseline"]
    assert set(result["provenance_digests"]) == {"target", "baseline"}


def test_matrix_rejects_within_snapshot_environment_mismatch(tmp_path: Path) -> None:
    paths = _matrix_paths(tmp_path)
    runtime = _record("runtime", snapshot="target", lock=_digest("9"))
    _write(paths[("target", "runtime")], runtime)

    with pytest.raises(ComparisonError, match="snapshot configuration"):
        _compare_matrix(paths)

    runtime = _record("runtime", snapshot="target", lock=_digest("7"))
    runtime["provenance"]["runtime_sbom_sha256"] = _digest("0")
    _write(paths[("target", "runtime")], runtime)
    with pytest.raises(ComparisonError, match="runtime_sbom_sha256"):
        _compare_matrix(paths)


def test_matrix_keeps_failures_operational_and_excludes_them_from_quality(
    tmp_path: Path,
) -> None:
    paths = _matrix_paths(tmp_path)
    failed = _record("runtime", snapshot="baseline", lock=_digest("8"))
    failed.update(
        status="failure",
        failure={"phase": "dependency", "message": "lock install failed"},
        inventory=None,
        impact=None,
    )
    failed.pop("framework_phase")
    _write(paths[("baseline", "runtime")], failed)

    result = _compare_matrix(paths)

    assert result["operational"]["success_count"] == {"secure": 2, "runtime": 1}
    assert result["operational"]["failure_phase_counts"]["runtime"] == {"dependency": 1}
    assert result["paired_success_quality"]["eligible_snapshots"] == ["target"]
    assert result["lifecycle"]["runtime"] is None


def test_matrix_rejects_malformed_success_with_failed_counterpart(tmp_path: Path) -> None:
    paths = _matrix_paths(tmp_path)
    malformed = _record("runtime", snapshot="target", lock=_digest("7"), measured=False)
    malformed["impact"] = {}
    failed = _record("runtime", snapshot="baseline", lock=_digest("8"))
    failed.update(
        status="failure",
        failure={"phase": "dependency", "message": "lock install failed"},
        inventory=None,
        impact=None,
    )
    failed.pop("framework_phase")
    _write(paths[("target", "runtime")], malformed)
    _write(paths[("baseline", "runtime")], failed)

    with pytest.raises(ComparisonError, match="candidate_endpoints must be an array"):
        _compare_matrix(paths)


def test_matrix_rejects_snapshot_or_entry_configuration_mismatch(tmp_path: Path) -> None:
    paths = _matrix_paths(tmp_path)
    record = _record("secure", snapshot="target", lock=_digest("8"))
    _write(paths[("baseline", "secure")], record)
    with pytest.raises(ComparisonError, match="declares target"):
        _compare_matrix(paths)

    record = _record("secure", snapshot="baseline", lock=_digest("8"))
    record["configuration"]["app_variable"] = "application"
    _write(paths[("baseline", "secure")], record)
    with pytest.raises(ComparisonError, match="snapshot configuration"):
        _compare_matrix(paths)


def test_duplicate_or_malformed_endpoint_rows_fail_closed(tmp_path: Path) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    secure_record = _record("secure")
    secure_record["inventory"]["endpoints"].append(
        {"methods": ["GET"], "path": "/users/{user_id}", "surface": None}
    )
    _write(secure, secure_record)
    _write(runtime, _record("runtime"))
    with pytest.raises(ComparisonError, match="duplicate inventory"):
        compare(secure, runtime)

    secure_record = _record("secure")
    secure_record["impact"]["candidate_endpoints"] = ["bad"]
    _write(secure, secure_record)
    with pytest.raises(ComparisonError, match="endpoint objects"):
        compare(secure, runtime)


def test_cli_matrix_is_no_clobber(tmp_path: Path) -> None:
    paths = _matrix_paths(tmp_path)
    output = tmp_path / "comparison.json"
    arguments = _cli_arguments(paths, output)

    assert main(arguments) == 0
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["runtime_role"] == "positive_observation_comparator_not_truth"
    with pytest.raises(SystemExit) as raised:
        main(arguments)
    assert raised.value.code == 2


def test_cli_rejects_existing_and_absent_frozen_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _matrix_paths(tmp_path)
    existing = tmp_path / "frozen.json"
    existing.write_text("frozen", encoding="utf-8")
    absent = tmp_path / "absent-frozen.json"
    monkeypatch.setattr(compare_runtime, "_FROZEN_FILES", (existing, absent))
    monkeypatch.setattr(compare_runtime, "_FROZEN_ROOTS", ())

    for output in (existing, absent):
        with pytest.raises(SystemExit) as raised:
            main(_cli_arguments(paths, output))
        assert raised.value.code == 2
        assert not absent.exists()
    assert existing.read_text(encoding="utf-8") == "frozen"


def test_cli_rejects_frozen_root_and_symlinked_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _matrix_paths(tmp_path)
    frozen_root = tmp_path / "results"
    frozen_root.mkdir()
    alias = tmp_path / "results-alias"
    alias.symlink_to(frozen_root, target_is_directory=True)
    monkeypatch.setattr(compare_runtime, "_FROZEN_FILES", ())
    monkeypatch.setattr(compare_runtime, "_FROZEN_ROOTS", (frozen_root,))

    for output in (frozen_root / "new.json", alias / "new.json"):
        with pytest.raises(SystemExit) as raised:
            main(_cli_arguments(paths, output))
        assert raised.value.code == 2
        assert not (frozen_root / "new.json").exists()
