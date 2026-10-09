"""Canonical framework-v1 contract to execution-phase mapping."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from fastapi_endpoint_detector.models.surface_contract import (
    CallbackRangeMode,
    LoadedSurfaceContracts,
    SurfaceContract,
    load_surface_preset,
)


class FrameworkPhase(str, Enum):
    STARTUP = "startup"
    SHUTDOWN = "shutdown"
    REQUEST = "request"
    BACKGROUND = "background"
    MIDDLEWARE = "middleware"
    DEPENDENCY = "dependency"


class SourceIdentity(BaseModel):
    """Physical source identity emitted by a typed integration adapter."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    module: str = Field(min_length=1)
    symbol: str = Field(min_length=1)
    file: str = Field(min_length=1)
    line: int = Field(ge=1)
    column: int = Field(ge=0)
    end_line: int | None = Field(default=None, ge=1)
    end_column: int | None = Field(default=None, ge=0)
    source_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_span(self) -> SourceIdentity:
        if (self.end_line is None) != (self.end_column is None):
            raise ValueError("source identity end line and column must be provided together")
        return self


_CANONICAL_PHASES: dict[str, tuple[str, CallbackRangeMode, FrameworkPhase]] = {
    "fastapi-lifespan-startup": ("startup", CallbackRangeMode.BEFORE_YIELD, FrameworkPhase.STARTUP),
    "fastapi-lifespan-shutdown": (
        "shutdown",
        CallbackRangeMode.AFTER_YIELD,
        FrameworkPhase.SHUTDOWN,
    ),
    "fastapi-on-event": ("startup-or-shutdown", CallbackRangeMode.FULL, FrameworkPhase.STARTUP),
    "fastapi-add-event-handler": (
        "startup-or-shutdown",
        CallbackRangeMode.FULL,
        FrameworkPhase.STARTUP,
    ),
    "starlette-on-event": (
        "startup-or-shutdown",
        CallbackRangeMode.FULL,
        FrameworkPhase.STARTUP,
    ),
    "starlette-add-event-handler": (
        "startup-or-shutdown",
        CallbackRangeMode.FULL,
        FrameworkPhase.STARTUP,
    ),
    "fastapi-http-middleware": ("http", CallbackRangeMode.FULL, FrameworkPhase.MIDDLEWARE),
    "fastapi-base-http-middleware": ("http", CallbackRangeMode.FULL, FrameworkPhase.MIDDLEWARE),
    "starlette-base-http-middleware": (
        "http",
        CallbackRangeMode.FULL,
        FrameworkPhase.MIDDLEWARE,
    ),
}


def canonical_framework_phase(  # noqa: PLR0911
    contract: SurfaceContract,
    resource: str,
    callback_range: CallbackRangeMode,
    selected: LoadedSurfaceContracts,
) -> FrameworkPhase | None:
    """Resolve only an unchanged contract from the bundled framework-v1 catalog.

    The selected document must contain the exact canonical contract payload.
    Arbitrary IDs, symbols, phases, and ranges never establish a phase.
    """
    catalog = load_surface_preset("framework-v1")
    canonical = next((item for item in catalog.document.contracts if item.id == contract.id), None)
    selected_copy = next(
        (item for item in selected.document.contracts if item.id == contract.id), None
    )
    if canonical is None or selected_copy is None:
        return None
    if catalog.document.contract_hashes[contract.id] != selected.document.contract_hashes.get(
        contract.id
    ):
        return None
    if contract.model_dump(mode="json") != canonical.model_dump(mode="json"):
        return None
    allowed = _CANONICAL_PHASES.get(contract.id)
    if allowed is None or callback_range != allowed[1]:
        return None
    resource_contract, _range, phase = allowed
    if resource_contract == "startup-or-shutdown":
        if resource not in {"startup", "shutdown"}:
            return None
        return FrameworkPhase(resource)
    if resource != resource_contract:
        return None
    return phase
