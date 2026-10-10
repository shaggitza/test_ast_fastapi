"""Strict data contracts shared by phase manifests and runtime observations."""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from fastapi_endpoint_detector.analyzer.framework_phase_bridge import FrameworkPhase, SourceIdentity


class PhaseManifestEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    callback: SourceIdentity
    registration: SourceIdentity
    phase: Literal["startup", "shutdown"]
    execution_conditions: tuple[str, ...]
    contract_id: str = Field(min_length=1)
    contract_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    source_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    callback_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    registration_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    inventory_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    engine_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    config_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_contract_binding(self) -> PhaseManifestEntry:
        from fastapi_endpoint_detector.models.surface_contract import (  # noqa: PLC0415
            load_surface_preset,
        )

        catalog = load_surface_preset("framework-v1")
        expected_id = f"fastapi-lifespan-{self.phase}"
        event_contracts = {
            "fastapi-on-event",
            "fastapi-add-event-handler",
            "starlette-on-event",
            "starlette-add-event-handler",
            "fastapi-router-on-event",
            "fastapi-router-add-event-handler",
            "fastapi-constructor-on-startup-list",
            "fastapi-constructor-on-shutdown-list",
            "fastapi-router-constructor-on-startup-list",
            "fastapi-router-constructor-on-shutdown-list",
        }
        if self.contract_id != expected_id and self.contract_id not in event_contracts:
            raise ValueError(
                "runtime phase manifest contract is not a supported lifecycle callback"
            )
        if catalog.document.contract_hashes.get(self.contract_id) != self.contract_sha256:
            raise ValueError("runtime phase manifest contract digest does not match framework-v1")
        return self


class PhaseManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal[1] = 1
    protocol: Literal["framework-phase-manifest-v1"] = "framework-phase-manifest-v1"
    entries: tuple[PhaseManifestEntry, ...]

    @model_validator(mode="after")
    def validate_unique_occurrences(self) -> PhaseManifest:
        keys = [
            (
                item.phase,
                item.callback.file,
                item.callback.line,
                item.callback.column,
                item.callback.end_line,
                item.callback.end_column,
                item.registration.file,
                item.registration.line,
                item.registration.column,
                item.registration.end_line,
                item.registration.end_column,
            )
            for item in self.entries
        ]
        if len(set(keys)) != len(keys):
            raise ValueError("runtime phase manifest contains duplicate callback registrations")
        return self

    @property
    def digest(self) -> str:
        value = self.model_dump(mode="json")
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        return "sha256:" + hashlib.sha256(encoded).hexdigest()


class PhaseObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal[1] = 1
    protocol: Literal["framework-phase-observation-v1"] = "framework-phase-observation-v1"
    manifest_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    observed: tuple[dict[str, object], ...]
    unavailable: tuple[dict[str, object], ...]
    execution_status: Literal["completed", "startup_failed", "unavailable"]
    role: Literal["positive_observation_only", "self_reported_nonpositive"] = (
        "positive_observation_only"
    )


def manifest_from_report(report: object) -> PhaseManifest:
    """Build a runtime manifest only from fully bound static phase records."""
    records = getattr(report, "records", ())
    entries: list[PhaseManifestEntry] = []
    for record in records:
        phase = getattr(record, "phase", None)
        if phase not in {FrameworkPhase.STARTUP, FrameworkPhase.SHUTDOWN}:
            continue
        if getattr(record, "contract_id", None) not in {
            "fastapi-lifespan-startup",
            "fastapi-lifespan-shutdown",
            "fastapi-on-event",
            "fastapi-add-event-handler",
            "starlette-on-event",
            "starlette-add-event-handler",
            "fastapi-router-on-event",
            "fastapi-router-add-event-handler",
            "fastapi-constructor-on-startup-list",
            "fastapi-constructor-on-shutdown-list",
            "fastapi-router-constructor-on-startup-list",
            "fastapi-router-constructor-on-shutdown-list",
        }:
            continue
        callback = getattr(record, "callback", None)
        registration = getattr(record, "registration", None)
        required = (
            callback,
            registration,
            getattr(record, "framework_declaration_sha256", None),
            getattr(record, "callback_file_sha256", None),
            getattr(record, "registration_file_sha256", None),
            getattr(record, "typed_callback_symbol", None),
            getattr(record, "typed_framework_symbol", None),
            getattr(record, "registration_call_site", None),
        )
        limitations = getattr(record, "limitations", None)
        if any(item is None for item in required) or bool(limitations):
            continue
        if not isinstance(callback, SourceIdentity) or not isinstance(registration, SourceIdentity):
            continue
        entries.append(
            PhaseManifestEntry(
                callback=callback,
                registration=registration,
                phase=phase.value,
                execution_conditions=tuple(record.execution_conditions),
                contract_id=record.contract_id,
                contract_sha256=record.canonical_contract_sha256,
                source_sha256=record.source_sha256,
                callback_file_sha256=record.callback_file_sha256,
                registration_file_sha256=record.registration_file_sha256,
                inventory_sha256=record.inventory_sha256,
                engine_sha256=record.engine_sha256,
                config_sha256=record.config_sha256,
            )
        )
    return PhaseManifest(entries=tuple(entries))
