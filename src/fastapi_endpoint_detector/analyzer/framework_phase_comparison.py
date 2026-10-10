"""Fail-closed phase comparison over the existing secure/runtime trust chain."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict

from fastapi_endpoint_detector.analyzer.framework_phase_bridge import FrameworkPhase  # noqa: TC001
from fastapi_endpoint_detector.analyzer.runtime_artifact_comparison import ComparisonError, compare

if TYPE_CHECKING:
    from pathlib import Path


class PhaseComparison(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    status: Literal["unavailable"] = "unavailable"
    role: Literal["runtime_observation_only"] = "runtime_observation_only"
    phase: FrameworkPhase | None = None
    reason: str
    paired_comparison_status: str | None = None


def compare_phase_artifacts(
    secure_artifact: Path,
    runtime_artifact: Path,
    *,
    phase: FrameworkPhase | None = None,
) -> PhaseComparison:
    """Validate artifacts with comparator #307, then require phase receipts.

    Comparator #307 validates secure/runtime artifact shape, pair equivalence,
    and provenance. Its current artifact schema has no phase callback receipts,
    so a valid aggregate pair still cannot establish a phase comparison. This
    API deliberately returns unavailable until that receipt chain exists.
    """
    try:
        aggregate = compare(secure_artifact, runtime_artifact)
    except (ComparisonError, OSError) as error:
        return PhaseComparison(
            phase=phase,
            reason=f"secure/runtime receipt validation failed: {error}",
        )
    if not aggregate.get("paired_success"):
        return PhaseComparison(
            phase=phase,
            reason="validated secure/runtime artifacts are not a successful pair",
            paired_comparison_status="paired_failure_or_ineligible",
        )
    return PhaseComparison(
        phase=phase,
        reason="validated aggregate artifacts contain no phase callback receipts",
        paired_comparison_status="validated_aggregate_only",
    )
