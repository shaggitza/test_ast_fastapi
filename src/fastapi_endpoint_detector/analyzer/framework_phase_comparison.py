"""Compare validated phase observations without promoting runtime to truth."""

from __future__ import annotations

from collections import Counter
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Phase = Literal["startup", "shutdown", "request", "background", "middleware", "dependency"]


class PhaseObservation(BaseModel):
    """A validated secure observation or externally attested runtime observation."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    phase: Phase
    callbacks: tuple[str, ...]
    source_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    inventory_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    engine_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    config_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    validated: bool = False


class PhaseComparison(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    status: Literal["compared", "unavailable"]
    role: Literal["runtime_observation_only"] = "runtime_observation_only"
    phase: Phase
    secure_only: tuple[str, ...] = ()
    runtime_only: tuple[str, ...] = ()
    shared: tuple[str, ...] = ()
    reason: str | None = None


def compare_phase_observations(
    secure: PhaseObservation,
    runtime: PhaseObservation | None,
) -> PhaseComparison:
    """Compare only same-phase, snapshot- and configuration-matched evidence.

    A missing actual isolated runtime phase observation remains unavailable.
    This function does not execute workloads, attest runtime provenance, or
    modify canonical secure classifications.
    """
    if runtime is None:
        return PhaseComparison(
            status="unavailable",
            phase=secure.phase,
            reason="actual isolated runtime phase observation absent",
        )
    if not secure.validated or not runtime.validated:
        return PhaseComparison(
            status="unavailable", phase=secure.phase, reason="phase observation failed validation"
        )
    if secure.phase != runtime.phase:
        reason = "phase mismatch"
    elif (
        secure.source_sha256,
        secure.inventory_sha256,
        secure.engine_sha256,
        secure.config_sha256,
    ) != (
        runtime.source_sha256,
        runtime.inventory_sha256,
        runtime.engine_sha256,
        runtime.config_sha256,
    ):
        reason = "source, inventory, engine, or configuration identity mismatch"
    else:
        reason = None
    if reason:
        return PhaseComparison(status="unavailable", phase=secure.phase, reason=reason)
    left, right = Counter(secure.callbacks), Counter(runtime.callbacks)
    return PhaseComparison(
        status="compared",
        phase=secure.phase,
        secure_only=tuple(sorted((left - right).elements())),
        runtime_only=tuple(sorted((right - left).elements())),
        shared=tuple(sorted((left & right).elements())),
    )
