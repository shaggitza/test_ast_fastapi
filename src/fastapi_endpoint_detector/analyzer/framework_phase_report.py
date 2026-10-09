"""Project typed framework phase evidence into a report-ready stable shape."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from fastapi_endpoint_detector.analyzer.framework_phase_integration import (
        FrameworkPhaseIntegration,
    )


class FrameworkPhaseReport(BaseModel):
    """Narrow report payload for parent AnalysisReport integration."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: int = 1
    backend: str
    backend_version: str
    snapshot_side: str = Field(pattern="^(target|baseline)$")
    record_count: int = Field(ge=0)
    established_count: int = Field(ge=0)
    conditional_count: int = Field(ge=0)
    unavailable_count: int = Field(ge=0)
    records: tuple[dict[str, object], ...]
    lifecycle_conditional_surfaces: tuple[dict[str, object], ...]
    limitations: tuple[str, ...]
    source_digests: tuple[str, ...]
    inventory_digests: tuple[str, ...]
    engine_digests: tuple[str, ...]
    config_digests: tuple[str, ...]


def phase_report_payload(evidence: FrameworkPhaseIntegration) -> FrameworkPhaseReport:
    """Serialize immutable evidence without changing its strength or truth role."""
    counts = {
        state: sum(record.status == state for record in evidence.records)
        for state in ("established", "conditional", "unavailable")
    }
    return FrameworkPhaseReport(
        backend=evidence.backend,
        backend_version=evidence.backend_version,
        snapshot_side=evidence.snapshot_side,
        record_count=len(evidence.records),
        established_count=counts["established"],
        conditional_count=counts["conditional"],
        unavailable_count=counts["unavailable"],
        records=tuple(
            {**record.model_dump(mode="json"), "status": record.status}
            for record in evidence.records
        ),
        lifecycle_conditional_surfaces=tuple(
            item.model_dump(mode="json") for item in evidence.lifecycle_conditional_surfaces
        ),
        limitations=evidence.limitations,
        source_digests=tuple(sorted({item.source_sha256 for item in evidence.records})),
        inventory_digests=tuple(sorted({item.inventory_sha256 for item in evidence.records})),
        engine_digests=tuple(sorted({item.engine_sha256 for item in evidence.records})),
        config_digests=tuple(sorted({item.config_sha256 for item in evidence.records})),
    )
