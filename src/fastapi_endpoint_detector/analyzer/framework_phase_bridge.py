"""Typed, fail-closed bridge for exact framework callback phase evidence.

This module deliberately consumes evidence from a typed frontend; it does not
discover callbacks by spelling or inspect framework implementation code.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from fastapi_endpoint_detector.models.surface_contract import CallbackRangeMode


class FrameworkPhase(str, Enum):
    STARTUP = "startup"
    SHUTDOWN = "shutdown"
    REQUEST = "request"
    BACKGROUND = "background"
    MIDDLEWARE = "middleware"
    DEPENDENCY = "dependency"


class EvidenceStrength(str, Enum):
    ESTABLISHED = "established"
    CONDITIONAL = "conditional"
    UNAVAILABLE = "unavailable"


class SourceIdentity(BaseModel):
    """Canonical source identity bound to the exact typed callable target."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    module: str = Field(min_length=1)
    symbol: str = Field(min_length=1)
    file: str = Field(min_length=1)
    line: int = Field(ge=1)
    column: int = Field(ge=0)
    source_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class TypedFrameworkCallback(BaseModel):
    """One registration occurrence resolved by an authoritative typed frontend.

    ``trusted_framework_symbol`` must be supplied from the type resolver's
    resolved callable symbol, never inferred from source text. The source
    callback and registration occurrence are separate identities on purpose.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)
    callback: SourceIdentity
    registration: SourceIdentity
    trusted_framework_symbol: str | None = Field(default=None, min_length=3)
    contract_id: str | None = None
    phase: FrameworkPhase | None = None
    callback_range: CallbackRangeMode = CallbackRangeMode.FULL
    execution_condition: str | None = Field(default=None, min_length=1)
    lifecycle_conditional: bool = False
    exact_typed_identity: bool = False
    selected_surface: bool = False
    reachable_registration: bool = False
    backend: Literal["mypy", "scip", "unknown"] = "unknown"
    backend_capability: str | None = None
    source_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    inventory_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    engine_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    config_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def enforce_proof_gates(self) -> TypedFrameworkCallback:
        proven = (
            self.exact_typed_identity
            and self.selected_surface
            and self.reachable_registration
            and self.trusted_framework_symbol is not None
            and self.contract_id is not None
            and self.phase is not None
        )
        if not proven and self.phase is not None:
            raise ValueError(
                "a phase requires exact typed identity, selected contract, and reachability"
            )
        if self.backend == "scip" and self.exact_typed_identity and not self.backend_capability:
            raise ValueError("SCIP exact identity requires an explicit backend capability record")
        if self.phase == FrameworkPhase.STARTUP and self.lifecycle_conditional:
            raise ValueError(
                "startup execution is phase evidence; lifecycle conditionality belongs to surfaces"
            )
        if self.phase == FrameworkPhase.STARTUP and self.callback_range not in {
            CallbackRangeMode.FULL,
            CallbackRangeMode.BEFORE_YIELD,
        }:
            raise ValueError("startup evidence must use the pre-yield callback range")
        if self.phase == FrameworkPhase.SHUTDOWN and self.callback_range not in {
            CallbackRangeMode.FULL,
            CallbackRangeMode.AFTER_YIELD,
        }:
            raise ValueError("shutdown evidence must use the post-yield callback range")
        return self

    @property
    def strength(self) -> EvidenceStrength:
        if not (
            self.exact_typed_identity
            and self.selected_surface
            and self.reachable_registration
            and self.trusted_framework_symbol
            and self.contract_id
            and self.phase
        ):
            return EvidenceStrength.UNAVAILABLE
        if self.execution_condition or self.lifecycle_conditional:
            return EvidenceStrength.CONDITIONAL
        return EvidenceStrength.ESTABLISHED


def bind_framework_callback(evidence: TypedFrameworkCallback) -> TypedFrameworkCallback:
    """Narrow public bridge seam for extractor/reverse-graph integration."""
    return evidence
