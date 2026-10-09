"""Canonical phase catalog and fail-closed runtime receipt checks."""

import json
from pathlib import Path

from fastapi_endpoint_detector.analyzer.framework_phase_bridge import (
    FrameworkPhase,
    canonical_framework_phase,
)
from fastapi_endpoint_detector.analyzer.framework_phase_comparison import (
    compare_phase_artifacts,
)
from fastapi_endpoint_detector.models.surface_contract import (
    CallbackRangeMode,
    load_surface_preset,
)


def test_canonical_lifespan_contract_reconciles_phase_and_range() -> None:
    selected = load_surface_preset("framework-v1")
    startup = next(
        item for item in selected.document.contracts if item.id == "fastapi-lifespan-startup"
    )
    shutdown = next(
        item for item in selected.document.contracts if item.id == "fastapi-lifespan-shutdown"
    )

    assert (
        canonical_framework_phase(startup, "startup", CallbackRangeMode.BEFORE_YIELD, selected)
        == FrameworkPhase.STARTUP
    )
    assert (
        canonical_framework_phase(shutdown, "shutdown", CallbackRangeMode.AFTER_YIELD, selected)
        == FrameworkPhase.SHUTDOWN
    )
    assert canonical_framework_phase(startup, "startup", CallbackRangeMode.FULL, selected) is None
    assert (
        canonical_framework_phase(shutdown, "shutdown", CallbackRangeMode.BEFORE_YIELD, selected)
        is None
    )


def test_arbitrary_contract_payload_cannot_enter_canonical_catalog() -> None:
    selected = load_surface_preset("framework-v1")
    event = next(item for item in selected.document.contracts if item.id == "fastapi-on-event")
    altered = event.model_copy(update={"callback_range": CallbackRangeMode.BEFORE_YIELD})

    assert canonical_framework_phase(altered, "startup", altered.callback_range, selected) is None


def test_runtime_phase_receipt_is_unavailable_without_validated_artifacts(tmp_path: Path) -> None:
    result = compare_phase_artifacts(
        tmp_path / "invented-secure.json",
        tmp_path / "invented-runtime.json",
        phase=FrameworkPhase.STARTUP,
    )

    assert result.status == "unavailable"
    assert "receipt validation failed" in result.reason


def test_valid_aggregate_pair_still_cannot_claim_phase_comparison(tmp_path: Path) -> None:
    def digest(char: str) -> str:
        return "sha256:" + char * 64

    common = {
        "schema_version": 1,
        "snapshot": "target",
        "status": "success",
        "configuration": {
            "app_entry": None,
            "bootstrap_entry": None,
            "app_variable": "app",
            "backend": "mypy",
            "dependency_lock_sha256": digest("a"),
        },
        "timing": {
            "list": {"status": "measured", "seconds": 1.0},
            "impact": {"status": "measured", "seconds": 1.0},
        },
        "resources": {"peak_rss_bytes": {"status": "measured", "bytes": 1}},
        "failure": None,
        "inventory": {
            "inventory_status": "established",
            "endpoints": [{"methods": ["GET"], "path": "/", "surface": None}],
        },
        "impact": {
            "candidate_endpoints": [
                {"endpoint": {"methods": ["GET"], "path": "/", "surface": None}}
            ]
        },
    }
    secure = dict(
        common,
        mode="secure",
        provenance={
            "source_sha256": digest("b"),
            "tool_sha256": digest("c"),
            "effective_invocation_sha256": digest("7"),
            "dependency_lock_sha256": digest("a"),
            "runtime_image_digest": f"registry.example/test@{digest('e')}",
            "runtime_sbom_sha256": digest("f"),
        },
    )
    runtime = dict(
        common,
        mode="runtime",
        inventory={
            "inventory_status": "runtime_observed",
            "endpoints": common["inventory"]["endpoints"],
        },
        provenance={
            "source_sha256": digest("b"),
            "tool_sha256": digest("c"),
            "effective_invocation_sha256": digest("8"),
            "dependency_lock_sha256": digest("a"),
            "runtime_image_digest": f"registry.example/test@{digest('e')}",
            "runtime_sbom_sha256": digest("f"),
            "runtime_seccomp_sha256": digest("1"),
            "runtime_policy_sha256": digest("0"),
        },
    )
    secure_path, runtime_path = tmp_path / "secure.json", tmp_path / "runtime.json"
    secure_path.write_text(json.dumps(secure), encoding="utf-8")
    runtime_path.write_text(json.dumps(runtime), encoding="utf-8")

    result = compare_phase_artifacts(secure_path, runtime_path, phase=FrameworkPhase.STARTUP)

    assert result.status == "unavailable"
    assert result.paired_comparison_status == "validated_aggregate_only"
    assert "no phase callback receipts" in result.reason
