"""Strict report-only finite resource coupling configuration and graph models."""

from __future__ import annotations

import hashlib
import json
import sys
from enum import Enum
from pathlib import Path  # noqa: TC003 - Pydantic consumes paths at runtime
from typing import Any, Literal

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[import-not-found]

import yaml
from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

from fastapi_endpoint_detector.models.effect_contract import EffectChannel, EffectOperation
from fastapi_endpoint_detector.strict_data import (
    DuplicateKeyError,
    load_json_unique,
    load_yaml_unique,
)


class ResourceCouplingError(ValueError):
    """Raised when report-only resource coupling cannot be configured safely."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def semantic_hash(payload: object) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


class ResourceCouplingGroup(_StrictModel):
    """Operator-qualified resource space and closed producer/consumer contract sets."""

    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    resource_space: str = Field(min_length=1, max_length=256)
    producer_contract_ids: tuple[str, ...] = Field(min_length=1, max_length=64)
    consumer_contract_ids: tuple[str, ...] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def validate_contract_ids(self) -> ResourceCouplingGroup:
        for label, values in (
            ("producer", self.producer_contract_ids),
            ("consumer", self.consumer_contract_ids),
        ):
            if values != tuple(sorted(set(values))):
                raise ValueError(f"{label} contract ids must be sorted and unique")
        if set(self.producer_contract_ids) & set(self.consumer_contract_ids):
            raise ValueError("producer and consumer contract ids must be disjoint")
        return self


class ResourceCouplingLimits(_StrictModel):
    """Deterministic hard limits; overflowing components are omitted atomically."""

    max_endpoint_links_per_resource: StrictInt = Field(default=32, ge=1, le=128)
    max_edges: StrictInt = Field(default=1000, ge=1, le=10_000)


class ResourceCouplingDocument(_StrictModel):
    """Versioned report-only coupling configuration."""

    schema_version: Literal[1] = 1
    mode: Literal["report_only"] = "report_only"
    groups: tuple[ResourceCouplingGroup, ...] = Field(min_length=1, max_length=64)
    limits: ResourceCouplingLimits = Field(default_factory=ResourceCouplingLimits)

    @field_validator("schema_version", mode="before")
    @classmethod
    def validate_schema_version_type(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("schema_version must be the integer 1")
        return value

    @model_validator(mode="after")
    def validate_groups(self) -> ResourceCouplingDocument:
        ids = [group.id for group in self.groups]
        if ids != sorted(set(ids)):
            raise ValueError("coupling groups must have sorted unique ids")
        return self

    def normalized_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class LoadedResourceCoupling(_StrictModel):
    source_path: Path
    raw_hash: str
    config_hash: str
    document: ResourceCouplingDocument


class CouplingStrength(str, Enum):
    EXACT = "exact"
    FINITE_OVERLAP = "finite_overlap"


class ResourceCouplingGroupEvidence(_StrictModel):
    id: str
    group_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    resource_space_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    channel: EffectChannel
    producer_contract_ids: tuple[str, ...]
    consumer_contract_ids: tuple[str, ...]

    @model_validator(mode="after")
    def validate_hash(self) -> ResourceCouplingGroupEvidence:
        for values in (self.producer_contract_ids, self.consumer_contract_ids):
            if values != tuple(sorted(set(values))):
                raise ValueError("coupling evidence contract ids must be sorted and unique")
        if set(self.producer_contract_ids) & set(self.consumer_contract_ids):
            raise ValueError("coupling evidence producer/consumer ids must be disjoint")
        expected = semantic_hash(
            {
                "id": self.id,
                "resource_space_hash": self.resource_space_hash,
                "channel": self.channel,
                "producer_contract_ids": self.producer_contract_ids,
                "consumer_contract_ids": self.consumer_contract_ids,
            }
        )
        if self.group_hash != expected:
            raise ValueError("coupling group hash does not match group evidence")
        return self


class ResourceCouplingEdge(_StrictModel):
    id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    group_id: str
    group_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    resource_space_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    resource_value_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    strength: CouplingStrength
    channel: EffectChannel
    producer_operation: EffectOperation
    consumer_operation: EffectOperation
    producer_contract_id: str
    consumer_contract_id: str
    producer_occurrence_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    consumer_occurrence_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    producer_endpoint_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    consumer_endpoint_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    def identity_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"id"})

    @model_validator(mode="after")
    def validate_edge(self) -> ResourceCouplingEdge:
        if self.producer_endpoint_id == self.consumer_endpoint_id:
            raise ValueError("cross-request coupling edges must connect distinct endpoints")
        if self.id != semantic_hash(self.identity_payload()):
            raise ValueError("coupling edge id does not match edge identity")
        return self


class ResourceCouplingDiagnostic(_StrictModel):
    reason_code: Literal[
        "resource_fanout_limit_exceeded",
        "global_edge_limit_exceeded",
    ]
    group_id: str | None = None
    resource_node_hash: str | None = Field(
        default=None,
        pattern=r"^sha256:[0-9a-f]{64}$",
    )
    omitted_edges: StrictInt = Field(ge=1)

    @model_validator(mode="after")
    def validate_shape(self) -> ResourceCouplingDiagnostic:
        component = self.reason_code == "resource_fanout_limit_exceeded"
        if component != (self.group_id is not None and self.resource_node_hash is not None):
            raise ValueError("coupling diagnostic fields do not match its reason")
        return self


class ResourceCouplingGraph(_StrictModel):
    """Deterministic report-only graph; it never changes endpoint candidates."""

    schema_version: Literal[1] = 1
    mode: Literal["report_only"] = "report_only"
    status: Literal["diagnostic_only"] = "diagnostic_only"
    raw_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    config_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    effect_audit_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    groups: tuple[ResourceCouplingGroupEvidence, ...]
    edges: tuple[ResourceCouplingEdge, ...]
    diagnostics: tuple[ResourceCouplingDiagnostic, ...] = ()
    graph_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    def graph_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"graph_hash"})

    @model_validator(mode="after")
    def validate_graph(self) -> ResourceCouplingGraph:
        group_ids = [group.id for group in self.groups]
        if group_ids != sorted(set(group_ids)):
            raise ValueError("coupling graph groups must be sorted and unique")
        edge_ids = [edge.id for edge in self.edges]
        if edge_ids != sorted(set(edge_ids)):
            raise ValueError("coupling graph edges must be sorted and unique")
        group_by_id = {group.id: group for group in self.groups}
        if any(edge.group_id not in group_by_id for edge in self.edges):
            raise ValueError("coupling edge references an unknown group")
        if any(
            edge.channel != group_by_id[edge.group_id].channel
            or edge.group_hash != group_by_id[edge.group_id].group_hash
            or edge.resource_space_hash != group_by_id[edge.group_id].resource_space_hash
            or edge.producer_contract_id not in group_by_id[edge.group_id].producer_contract_ids
            or edge.consumer_contract_id not in group_by_id[edge.group_id].consumer_contract_ids
            for edge in self.edges
        ):
            raise ValueError("coupling edge differs from its group evidence")
        if any(
            edge.producer_operation
            not in {
                EffectOperation.WRITE,
                EffectOperation.UPDATE,
                EffectOperation.DELETE,
                EffectOperation.APPEND,
            }
            or edge.consumer_operation != EffectOperation.READ
            for edge in self.edges
        ):
            raise ValueError("coupling edge uses an unsupported operation direction")
        if self.graph_hash != semantic_hash(self.graph_payload()):
            raise ValueError("coupling graph hash does not match graph contents")
        return self


def load_resource_coupling(path: Path) -> LoadedResourceCoupling:
    """Load strict YAML, JSON, or TOML coupling configuration without execution."""
    source = path.resolve()
    if not source.is_file():
        raise ResourceCouplingError(f"resource coupling file not found: {path}")
    raw = source.read_bytes()
    if len(raw) > 1_048_576:
        raise ResourceCouplingError("resource coupling document exceeds the 1 MiB limit")
    try:
        if source.suffix.lower() == ".json":
            data = load_json_unique(raw.decode("utf-8"))
        elif source.suffix.lower() == ".toml":
            data = tomllib.loads(raw.decode("utf-8"))
        elif source.suffix.lower() in {".yaml", ".yml"}:
            data = load_yaml_unique(raw.decode("utf-8"))
        else:
            raise ResourceCouplingError("resource coupling file must be YAML, JSON, or TOML")
        if not isinstance(data, dict):
            raise ResourceCouplingError("resource coupling document root must be a mapping")
        document = ResourceCouplingDocument.model_validate(data)
    except ResourceCouplingError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        tomllib.TOMLDecodeError,
        yaml.YAMLError,
        DuplicateKeyError,
    ) as exc:
        raise ResourceCouplingError(f"invalid resource coupling document: {exc}") from exc
    except Exception as exc:
        raise ResourceCouplingError(f"resource coupling validation failed: {exc}") from exc
    return LoadedResourceCoupling(
        source_path=source,
        raw_hash=f"sha256:{hashlib.sha256(raw).hexdigest()}",
        config_hash=semantic_hash(document.normalized_payload()),
        document=document,
    )
