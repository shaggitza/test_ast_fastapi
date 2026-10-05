"""Synthetic contract tests for the GH104 typed framework bridge."""

import pytest
from pydantic import ValidationError

from fastapi_endpoint_detector.analyzer.framework_phase_bridge import (
    EvidenceStrength,
    FrameworkPhase,
    TypedFrameworkCallback,
)
from fastapi_endpoint_detector.analyzer.framework_phase_comparison import (
    PhaseObservation,
    compare_phase_observations,
)
from fastapi_endpoint_detector.models.surface_contract import CallbackRangeMode

H = "sha256:" + "a" * 64


def callback(**changes: object) -> TypedFrameworkCallback:
    base: dict[str, object] = {
        "callback": {
            "module": "app",
            "symbol": "startup",
            "file": "app.py",
            "line": 4,
            "column": 0,
            "source_sha256": H,
        },
        "registration": {
            "module": "app",
            "symbol": "build",
            "file": "app.py",
            "line": 8,
            "column": 4,
            "source_sha256": H,
        },
        "trusted_framework_symbol": "fastapi.FastAPI.on_event",
        "contract_id": "fastapi-lifecycle-startup-v1",
        "phase": "startup",
        "callback_range": CallbackRangeMode.BEFORE_YIELD,
        "exact_typed_identity": True,
        "selected_surface": True,
        "reachable_registration": True,
        "backend": "mypy",
        "source_sha256": H,
        "inventory_sha256": H,
        "engine_sha256": H,
        "config_sha256": H,
    }
    base.update(changes)
    return TypedFrameworkCallback.model_validate(base)


def test_exact_typed_registration_is_established_and_occurrence_bound() -> None:
    evidence = callback()
    assert evidence.strength == EvidenceStrength.ESTABLISHED
    assert evidence.registration.line == 8


@pytest.mark.parametrize(
    "changes",
    [
        {"exact_typed_identity": False},
        {"selected_surface": False},
        {"reachable_registration": False},
        {"trusted_framework_symbol": None},
    ],
)
def test_unproven_callback_cannot_claim_phase(changes: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        callback(**changes)


def test_shutdown_requires_post_yield_range() -> None:
    with pytest.raises(ValidationError, match="post-yield"):
        callback(phase=FrameworkPhase.SHUTDOWN, callback_range=CallbackRangeMode.BEFORE_YIELD)


def test_scip_capability_is_explicit() -> None:
    with pytest.raises(ValidationError, match="capability"):
        callback(backend="scip")


def test_phase_comparison_preserves_registration_multiplicity_and_is_observational() -> None:
    secure = PhaseObservation(
        phase="startup",
        callbacks=("app.startup@8", "app.startup@8"),
        source_sha256=H,
        inventory_sha256=H,
        engine_sha256=H,
        config_sha256=H,
        validated=True,
    )
    runtime = secure.model_copy(update={"callbacks": ("app.startup@8",)})
    result = compare_phase_observations(secure, runtime)
    assert result.status == "compared"
    assert result.secure_only == ("app.startup@8",)
    assert result.shared == ("app.startup@8",)
    assert result.role == "runtime_observation_only"


def test_missing_runtime_phase_is_explicitly_unavailable() -> None:
    secure = PhaseObservation(
        phase="shutdown",
        callbacks=(),
        source_sha256=H,
        inventory_sha256=H,
        engine_sha256=H,
        config_sha256=H,
        validated=True,
    )
    result = compare_phase_observations(secure, None)
    assert result.status == "unavailable"
    assert result.reason == "actual isolated runtime phase observation absent"
