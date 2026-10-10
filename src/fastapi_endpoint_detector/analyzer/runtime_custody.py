"""Authenticate broker-issued result receipts against out-of-band authority pins.

This verifier does not issue receipts or establish that a sandbox was operated.
Its caller must obtain the authority configuration independently of the worker.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

_DIGEST = r"^sha256:[0-9a-f]{64}$"


class CustodyBinding(BaseModel):
    """Host-generated challenge identifying one exact isolated invocation."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    protocol: Literal["runtime-result-custody-v1"] = "runtime-result-custody-v1"
    snapshot: Literal["target", "baseline"]
    phase: Literal["list", "impact", "lifespan"]
    nonce: str = Field(pattern=r"^[0-9a-f]{32}$")
    request_sha256: str = Field(pattern=_DIGEST)
    manifest_sha256: str | None = Field(default=None, pattern=_DIGEST)
    canary_receipt_sha256: str = Field(pattern=_DIGEST)
    runtime_version: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_manifest(self) -> CustodyBinding:
        if (self.phase == "lifespan") != (self.manifest_sha256 is not None):
            raise ValueError("only lifespan custody requires an exact manifest digest")
        return self


class RuntimeCustodyReceipt(BaseModel):
    """Broker signature binds the challenge and complete retained result bytes."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    binding: CustodyBinding
    result_sha256: str = Field(pattern=_DIGEST)
    key_id: str = Field(min_length=1)
    issued_at: int = Field(gt=0)
    expires_at: int = Field(gt=0)
    signature: str = Field(pattern=r"^[0-9a-f]{64}$")

    def signed_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude={"signature"})


@dataclass(frozen=True)
class RuntimeCustodyAuthority:
    """Operator configuration, never taken from receipt or worker payload."""

    key_id: str
    secret: bytes
    runtime_version: str
    max_validity_seconds: int = 300

    def __post_init__(self) -> None:
        if not self.key_id.strip() or not self.runtime_version.strip():
            raise ValueError("custody authority identity and runtime pin are required")
        if not isinstance(self.secret, bytes) or len(self.secret) < 32:
            raise ValueError("custody authority requires at least 32 secret bytes")
        if type(self.max_validity_seconds) is not int or not 1 <= self.max_validity_seconds <= 3600:
            raise ValueError("custody authority validity limit is invalid")


class RuntimeCustodyError(ValueError):
    """No positive runtime evidence may be published after custody rejection."""


def custody_digest(value: object) -> str:
    """Digest exact canonical retained JSON; non-finite values are forbidden."""
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    except (TypeError, ValueError) as error:
        raise RuntimeCustodyError("custody result is not finite JSON") from error
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def verify_runtime_custody(
    receipt: object,
    *,
    expected: CustodyBinding,
    result: object,
    authority: RuntimeCustodyAuthority,
    now: int,
) -> RuntimeCustodyReceipt:
    """Check a signed result against a fresh host challenge and trusted authority.

    The caller creates a new unpredictable nonce before launching each invocation;
    a worker cannot select its own expected binding or signing authority.
    """
    try:
        parsed = RuntimeCustodyReceipt.model_validate(receipt)
    except ValueError as error:
        raise RuntimeCustodyError("custody receipt schema is invalid") from error
    if type(now) is not int or now <= 0:
        raise RuntimeCustodyError("custody verification requires trusted current time")
    if expected.runtime_version != authority.runtime_version:
        raise RuntimeCustodyError("custody runtime version does not match the authority pin")
    if parsed.key_id != authority.key_id or parsed.binding != expected:
        raise RuntimeCustodyError("custody receipt does not match the host challenge")
    if parsed.result_sha256 != custody_digest(result):
        raise RuntimeCustodyError("custody result differs from the broker-signed result")
    if (
        parsed.issued_at > now
        or parsed.expires_at <= now
        or parsed.expires_at <= parsed.issued_at
        or parsed.expires_at - parsed.issued_at > authority.max_validity_seconds
    ):
        raise RuntimeCustodyError("custody receipt validity window is rejected")
    canonical = json.dumps(
        parsed.signed_payload(), sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    signature = hmac.new(authority.secret, canonical, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(parsed.signature, signature):
        raise RuntimeCustodyError("custody receipt signature authentication failed")
    return parsed


def runtime_custody_authority_from_environment() -> RuntimeCustodyAuthority:
    """Load host/operator pins independently of worker or artifact data."""
    import os  # noqa: PLC0415

    try:
        return RuntimeCustodyAuthority(
            key_id=os.environ["FASTAPI_DETECTOR_RUNTIME_CUSTODY_KEY_ID"],
            secret=os.environ["FASTAPI_DETECTOR_RUNTIME_CUSTODY_KEY"].encode(),
            runtime_version=os.environ["FASTAPI_DETECTOR_RUNTIME_TRUST_VERSION"],
        )
    except (KeyError, ValueError) as error:
        raise RuntimeCustodyError("independent runtime custody authority is unavailable") from error


def runtime_record_request_digest(record: dict[str, object]) -> str:
    """Bind every retained source, configuration and environment pin."""
    return custody_digest(
        {
            "protocol": "runtime-record-request-v1",
            "snapshot": record["snapshot"],
            "configuration": record["configuration"],
            "provenance": record["provenance"],
        }
    )


def verify_runtime_record_custody(
    record: dict[str, object], *, authority: RuntimeCustodyAuthority, now: int
) -> None:
    """Authenticate both runtime phases and their retained payload/telemetry."""
    envelopes = record.get("runtime_custody")
    if not isinstance(envelopes, dict) or set(envelopes) != {"list", "impact"}:
        raise RuntimeCustodyError("successful runtime record requires both result receipts")
    provenance = record["provenance"]
    timing = record["timing"]
    if not isinstance(provenance, dict) or not isinstance(timing, dict):
        raise RuntimeCustodyError("runtime custody provenance/telemetry is invalid")
    canary = provenance.get("runtime_canary_receipt_sha256")
    if not isinstance(canary, str):
        raise RuntimeCustodyError("runtime custody canary pin is missing")
    nonces: set[str] = set()
    rss_values: list[int | None] = []
    for phase in ("list", "impact"):
        envelope = envelopes[phase]
        if not isinstance(envelope, dict) or set(envelope) != {"binding", "result", "receipt"}:
            raise RuntimeCustodyError("runtime custody envelope fields are invalid")
        try:
            challenge = CustodyBinding.model_validate(envelope["binding"])
        except ValueError as error:
            raise RuntimeCustodyError("runtime custody challenge schema is invalid") from error
        expected = CustodyBinding(
            snapshot=record["snapshot"],  # type: ignore[arg-type]
            phase=phase,
            nonce=challenge.nonce,
            request_sha256=runtime_record_request_digest(record),
            canary_receipt_sha256=canary,
            runtime_version=authority.runtime_version,
        )
        if challenge.nonce in nonces:
            raise RuntimeCustodyError("runtime phases cannot reuse a host nonce")
        nonces.add(challenge.nonce)
        result = envelope["result"]
        if not isinstance(result, dict) or set(result) != {
            "inventory",
            "impact",
            "seconds",
            "peak_rss_bytes",
            "phase_manifest",
            "phase_observation",
        }:
            raise RuntimeCustodyError("runtime custody result fields are invalid")
        selected = "inventory" if phase == "list" else "impact"
        other = "impact" if phase == "list" else "inventory"
        phase_timing = timing.get(phase)
        if not isinstance(phase_timing, dict):
            raise RuntimeCustodyError("runtime custody phase timing is missing")
        seconds = phase_timing.get("seconds") if phase_timing.get("status") == "measured" else None
        if (
            result[selected] != record[selected]
            or result[other] is not None
            or result["seconds"] != seconds
        ):
            raise RuntimeCustodyError("runtime record differs from its signed phase result")
        rss = result["peak_rss_bytes"]
        if rss is not None and (type(rss) is not int or rss < 0):
            raise RuntimeCustodyError("runtime custody RSS is invalid")
        rss_values.append(rss)
        verify_runtime_custody(
            envelope["receipt"], expected=expected, result=result, authority=authority, now=now
        )
    _verify_runtime_resource_summary(record["resources"], rss_values)


def _verify_runtime_resource_summary(resources: object, rss_values: list[int | None]) -> None:
    if not isinstance(resources, dict):
        raise RuntimeCustodyError("runtime custody resource summary is missing")
    resource = resources.get("peak_rss_bytes")
    if all(value is not None for value in rss_values):
        expected_rss = {
            "status": "measured",
            "bytes": max(value for value in rss_values if value is not None),
        }
        if resource != expected_rss:
            raise RuntimeCustodyError("runtime RSS summary differs from its signed measurements")
    elif (
        not isinstance(resource, dict)
        or resource.get("status") != "not_measured"
        or "bytes" in resource
    ):
        raise RuntimeCustodyError("runtime RSS requires signed phase measurements")
