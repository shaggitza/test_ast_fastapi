"""Strict data contracts shared by phase manifests and runtime observations."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_serializer, model_validator

from fastapi_endpoint_detector.analyzer.framework_phase_bridge import FrameworkPhase, SourceIdentity


class ConstructorRegistrationEvidence(BaseModel):
    """Strict identity for a direct FastAPI constructor lifespan binding."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    constructor_symbol: str = Field(min_length=1)
    constructor_file: str = Field(min_length=1)
    constructor_file_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    provider_capture_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    constructor_line: int = Field(ge=1)
    constructor_column: int = Field(ge=0)
    constructor_end_line: int = Field(ge=1)
    constructor_end_column: int = Field(ge=0)
    callback_symbol: str = Field(min_length=1)
    callback: SourceIdentity

    @model_validator(mode="after")
    def validate_constructor(self) -> ConstructorRegistrationEvidence:
        if self.constructor_symbol != "fastapi.applications.FastAPI" or self.callback_symbol != (
            f"{self.callback.module}.{self.callback.symbol}"
        ):
            raise ValueError("constructor evidence is not bound to typed FastAPI and callback")
        return self


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
    constructor_lifespan: ConstructorRegistrationEvidence | None = None

    @model_serializer(mode="wrap")
    def omit_absent_constructor(self, handler: Any) -> Any:
        value = handler(self)
        if self.constructor_lifespan is None:
            value.pop("constructor_lifespan", None)
        return value

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
        if self.constructor_lifespan is not None:
            if not self.contract_id.startswith("fastapi-lifespan-"):
                raise ValueError("constructor evidence is only valid for FastAPI lifespan entries")
            if (
                self.registration.line != self.constructor_lifespan.constructor_line
                or self.registration.column != self.constructor_lifespan.constructor_column
                or self.registration.end_line != self.constructor_lifespan.constructor_end_line
                or self.registration.end_column != self.constructor_lifespan.constructor_end_column
                or self.callback != self.constructor_lifespan.callback
                or self.registration.symbol != "FastAPI"
            ):
                raise ValueError("constructor evidence does not match manifest identities")
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


MAX_PHASE_COMPARISON_ROWS = 10_000
MAX_PHASE_UNAVAILABLE_REASON_CHARS = 2_048
MAX_PHASE_IDENTITY_TEXT_CHARS = 4_096
MAX_PHASE_CONDITIONS = 128
_MAX_PHASE_COORDINATE = 2**31 - 1


class PhaseComparisonRow(BaseModel):
    """One exact static occurrence compared with positive-only observations."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    phase: Literal["startup", "shutdown"]
    callback: SourceIdentity
    registration: SourceIdentity
    execution_conditions: tuple[str, ...]
    status: Literal[
        "observed_positive",
        "self_reported_observation",
        "callback_unavailable",
        "not_observed_positive_only",
    ]
    unavailable_reasons: tuple[str, ...] = ()


class PhaseComparison(BaseModel):
    """A protocol comparison; it does not attest to an isolated execution."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal[1] = 1
    protocol: Literal["framework-phase-comparison-v1"] = "framework-phase-comparison-v1"
    manifest_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    execution_status: Literal["completed", "startup_failed", "unavailable"]
    observation_role: Literal["positive_observation_only", "self_reported_nonpositive"]
    rows: tuple[PhaseComparisonRow, ...]


def _checked_phase_identity(raw: object) -> SourceIdentity:
    if isinstance(raw, SourceIdentity):
        raw = raw.model_dump(mode="python")
    fields = {
        "module",
        "symbol",
        "file",
        "line",
        "column",
        "end_line",
        "end_column",
        "source_sha256",
    }
    if not isinstance(raw, dict) or set(raw) != fields:
        raise ValueError("phase observation has malformed source identity fields")
    for name in ("module", "symbol", "file", "source_sha256"):
        value = raw[name]
        if type(value) is not str or not value or len(value) > MAX_PHASE_IDENTITY_TEXT_CHARS:
            raise ValueError("phase source identity text exceeds its exact bounded schema")
    for name, minimum in (("line", 1), ("column", 0), ("end_line", 1), ("end_column", 0)):
        value = raw[name]
        if value is None and name.startswith("end_"):
            continue
        if type(value) is not int or not minimum <= value <= _MAX_PHASE_COORDINATE:
            raise ValueError("phase source identity coordinate is not a bounded exact integer")
    identity = SourceIdentity.model_validate(raw, strict=True)
    if identity.end_line is not None and (identity.end_line, identity.end_column or 0) < (
        identity.line,
        identity.column,
    ):
        raise ValueError("phase source identity has a reversed span")
    return identity


def _phase_identity_key(value: SourceIdentity) -> tuple[object, ...]:
    return (
        value.module,
        value.symbol,
        value.file,
        value.line,
        value.column,
        value.end_line,
        value.end_column,
        value.source_sha256,
    )


def _checked_phase_conditions(raw: object) -> tuple[str, ...]:
    if (
        not isinstance(raw, (tuple, list))
        or len(raw) > MAX_PHASE_CONDITIONS
        or any(
            type(value) is not str or len(value) > MAX_PHASE_UNAVAILABLE_REASON_CHARS
            for value in raw
        )
    ):
        raise ValueError("phase execution conditions are malformed or exceed their budget")
    return tuple(raw)


def _checked_phase_models(
    manifest: PhaseManifest, observation: PhaseObservation
) -> tuple[PhaseManifest, PhaseObservation]:
    if type(manifest) is not PhaseManifest or type(observation) is not PhaseObservation:
        raise TypeError("phase comparison requires manifest and observation models")
    collections = (manifest.entries, observation.observed, observation.unavailable)
    if any(not isinstance(rows, (tuple, list)) for rows in collections):
        raise ValueError("phase comparison collections must be arrays")
    if sum(len(rows) for rows in collections) > MAX_PHASE_COMPARISON_ROWS:
        raise ValueError("phase comparison exceeds row budget")
    for entry in manifest.entries:
        if type(entry) is not PhaseManifestEntry:
            raise ValueError("static phase manifest contains an invalid entry")
        _checked_phase_identity(entry.callback)
        _checked_phase_identity(entry.registration)
        _checked_phase_conditions(entry.execution_conditions)
    if (
        type(manifest.schema_version) is not int
        or manifest.schema_version != 1
        or type(observation.schema_version) is not int
        or observation.schema_version != 1
        or type(manifest.protocol) is not str
        or manifest.protocol != "framework-phase-manifest-v1"
        or type(observation.protocol) is not str
        or observation.protocol != "framework-phase-observation-v1"
    ):
        raise ValueError("phase comparison schema or protocol is unsupported")
    if (
        type(observation.execution_status) is not str
        or observation.execution_status not in {"completed", "startup_failed", "unavailable"}
        or type(observation.role) is not str
        or observation.role not in {"positive_observation_only", "self_reported_nonpositive"}
    ):
        raise ValueError("phase comparison execution status or role is malformed")
    checked_manifest = PhaseManifest.model_validate(manifest.model_dump(mode="python"), strict=True)
    digest = checked_manifest.digest
    # Validate raw row shapes before serializing possibly caller-built model updates.
    for row in observation.observed:
        _phase_observed_row(row, digest)
    for row in observation.unavailable:
        _phase_unavailable_row(row)
    checked_observation = PhaseObservation.model_validate(
        observation.model_dump(mode="python"), strict=True
    )
    return checked_manifest, checked_observation


def _phase_observed_row(raw: object, digest: str) -> tuple[tuple[object, ...], tuple[str, ...]]:
    if not isinstance(raw, dict) or set(raw) != {
        "callback",
        "registration",
        "phase",
        "manifest_sha256",
        "execution_conditions",
    }:
        raise ValueError("phase observation has malformed observed-row fields")
    if not isinstance(raw["callback"], dict) or not isinstance(raw["registration"], dict):
        raise ValueError("phase observation identities must be JSON objects")
    callback = _checked_phase_identity(raw["callback"])
    registration = _checked_phase_identity(raw["registration"])
    phase = raw["phase"]
    if type(phase) is not str or phase not in {"startup", "shutdown"}:
        raise ValueError("phase observation row has malformed phase")
    if type(raw["manifest_sha256"]) is not str or raw["manifest_sha256"] != digest:
        raise ValueError("phase observation row has mismatched manifest")
    return (
        (phase, _phase_identity_key(callback), _phase_identity_key(registration)),
        _checked_phase_conditions(raw["execution_conditions"]),
    )


def _phase_unavailable_row(raw: object) -> tuple[tuple[object, ...], str]:
    if not isinstance(raw, dict) or set(raw) != {"callback", "reason"}:
        raise ValueError("phase observation has malformed unavailable-row fields")
    if not isinstance(raw["callback"], dict):
        raise ValueError("phase unavailable identity must be a JSON object")
    callback = _checked_phase_identity(raw["callback"])
    reason = raw["reason"]
    if type(reason) is not str or not reason or len(reason) > MAX_PHASE_UNAVAILABLE_REASON_CHARS:
        raise ValueError("phase unavailable reason must be bounded nonempty text")
    return _phase_identity_key(callback), reason


def _phase_unavailable_occurrences(
    raw_rows: tuple[dict[str, object], ...],
    callback_keys: dict[tuple[object, ...], list[tuple[object, ...]]],
    observed: set[tuple[object, ...]],
) -> dict[tuple[object, ...], set[str]]:
    reasons_by_callback: dict[tuple[object, ...], set[str]] = {}
    for raw in raw_rows:
        callback_key, reason = _phase_unavailable_row(raw)
        if callback_key not in callback_keys:
            raise ValueError("unavailable callback is absent from the static manifest")
        reasons_by_callback.setdefault(callback_key, set()).add(reason)
    reasons_by_occurrence: dict[tuple[object, ...], set[str]] = {}
    expanded = 0
    for callback_key, reasons in reasons_by_callback.items():
        remaining = [key for key in callback_keys[callback_key] if key not in observed]
        if not remaining:
            raise ValueError("callback is both observed and unavailable")
        expanded += len(remaining) * len(reasons)
        if expanded > MAX_PHASE_COMPARISON_ROWS:
            raise ValueError("phase comparison unavailable-reason fanout exceeds row budget")
        for key in remaining:
            reasons_by_occurrence[key] = reasons
    return reasons_by_occurrence


def _phase_comparison_rows(
    expected: dict[tuple[object, ...], PhaseManifestEntry],
    observed: set[tuple[object, ...]],
    unavailable: dict[tuple[object, ...], set[str]],
    role: str,
) -> tuple[PhaseComparisonRow, ...]:
    ordered_keys = sorted(expected, key=lambda key: json.dumps(key, separators=(",", ":")))
    return tuple(
        PhaseComparisonRow(
            phase=expected[key].phase,
            callback=expected[key].callback,
            registration=expected[key].registration,
            execution_conditions=expected[key].execution_conditions,
            status=(
                "observed_positive"
                if key in observed and role == "positive_observation_only"
                else "self_reported_observation"
                if key in observed
                else "callback_unavailable"
                if key in unavailable
                else "not_observed_positive_only"
            ),
            unavailable_reasons=tuple(sorted(unavailable.get(key, ()))),
        )
        for key in ordered_keys
    )


def compare_phase_observation(
    manifest: PhaseManifest, observation: PhaseObservation
) -> PhaseComparison:
    """Join exact lifecycle identities without treating absence as negative truth."""
    manifest, observation = _checked_phase_models(manifest, observation)
    digest = manifest.digest
    if observation.manifest_sha256 != digest:
        raise ValueError("phase observation is bound to a different manifest")
    expected: dict[tuple[object, ...], PhaseManifestEntry] = {}
    callback_keys: dict[tuple[object, ...], list[tuple[object, ...]]] = {}
    for entry in manifest.entries:
        callback_key = _phase_identity_key(entry.callback)
        key = (entry.phase, callback_key, _phase_identity_key(entry.registration))
        if key in expected:
            raise ValueError("static phase manifest repeats an exact occurrence")
        expected[key] = entry
        callback_keys.setdefault(callback_key, []).append(key)
    observed: set[tuple[object, ...]] = set()
    for raw in observation.observed:
        observed_key, conditions = _phase_observed_row(raw, digest)
        expected_entry = expected.get(observed_key)
        if expected_entry is None or conditions != expected_entry.execution_conditions:
            raise ValueError("runtime phase row does not exactly match the static manifest")
        if observed_key in observed:
            raise ValueError("phase observation repeats a static occurrence")
        observed.add(observed_key)
    if observation.execution_status != "completed" and observed:
        raise ValueError("failed execution cannot carry phase observations")
    unavailable = _phase_unavailable_occurrences(observation.unavailable, callback_keys, observed)
    return PhaseComparison(
        manifest_sha256=digest,
        execution_status=observation.execution_status,
        observation_role=observation.role,
        rows=_phase_comparison_rows(expected, observed, unavailable, observation.role),
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
        required: tuple[object | None, ...] = (
            callback,
            registration,
            getattr(record, "framework_declaration_sha256", None),
            getattr(record, "callback_file_sha256", None),
            getattr(record, "registration_file_sha256", None),
            getattr(record, "typed_callback_symbol", None),
            getattr(record, "typed_framework_symbol", None),
            getattr(record, "registration_call_site", None),
        )
        constructor = getattr(record, "constructor_lifespan", None)
        if record.contract_id in {"fastapi-lifespan-startup", "fastapi-lifespan-shutdown"}:
            required = required[:-2]
            if constructor is None:
                continue
        elif constructor is not None:
            continue
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
                constructor_lifespan=(
                    ConstructorRegistrationEvidence.model_validate(
                        constructor.model_dump(mode="python")
                    )
                    if constructor is not None
                    else None
                ),
            )
        )
    return PhaseManifest(entries=tuple(entries))
