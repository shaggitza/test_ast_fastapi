"""Strict data-only contracts for custom application entrypoint surfaces."""

from __future__ import annotations

import hashlib
import json
import keyword
import sys
from enum import Enum
from pathlib import Path
from typing import Any, Literal

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[import-not-found]

import yaml
from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

from fastapi_endpoint_detector.models.effect_contract import (
    ContractProvenance,
    InvocationKind,
    PresetMetadata,
)
from fastapi_endpoint_detector.strict_data import (
    DuplicateKeyError,
    load_json_unique,
    load_yaml_unique,
)

BUNDLED_SURFACE_PRESETS = {
    "event-listeners-v1": Path(__file__).resolve().parent.parent
    / "presets"
    / "event_listeners_v1.yaml",
    "mcp-v1": Path(__file__).resolve().parent.parent / "presets" / "mcp_v1.yaml",
    "workers-v1": Path(__file__).resolve().parent.parent / "presets" / "workers_v1.yaml",
    "framework-v1": Path(__file__).resolve().parent.parent / "presets" / "framework_v1.yaml",
}


class SurfaceContractError(ValueError):
    """Raised when a custom-surface contract document is unsafe or invalid."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SurfaceMatchKind(str, Enum):
    """Whether registration matching is exact or bounded wildcard matching."""

    EXACT = "exact"
    WILDCARD = "wildcard"


class HandlerSelectorKind(str, Enum):
    """How the registered handler is selected from source syntax."""

    DECORATED_FUNCTION = "decorated_function"
    ARGUMENT = "argument"
    KEYWORD = "keyword"
    ARGUMENT_CLASS_METHOD = "argument_class_method"


class HandlerNameNormalization(str, Enum):
    """Documented transformation from a Python handler to a public ID."""

    EXACT = "exact"
    KEBAB_CASE = "kebab_case"


class ResourceSelectorKind(str, Enum):
    """How one or more finite surface resource identities are selected."""

    ARGUMENT = "argument"
    ARGUMENT_OR_KEYWORD = "argument_or_keyword"
    ARGUMENTS = "arguments"
    KEYWORD = "keyword"
    KEYWORD_OR_HANDLER_NAME = "keyword_or_handler_name"
    HANDLER_NAME = "handler_name"
    LITERAL = "literal"


class SurfaceExecutionMode(str, Enum):
    """Declared framework boundary that invokes the registered callback."""

    DIRECT = "direct"
    EVENT_LOOP = "event_loop"
    THREADPOOL = "threadpool"
    PROCESS_WORKER = "process_worker"
    SCHEDULER = "scheduler"
    CLI_DISPATCH = "cli_dispatch"
    FRAMEWORK = "framework"


class CallbackMode(str, Enum):
    """Declared executable shape of the selected callback."""

    EITHER = "either"
    SYNC = "sync"
    ASYNC = "async"
    GENERATOR = "generator"
    ASYNC_GENERATOR = "async_generator"


class CallbackRangeMode(str, Enum):
    """Bounded portion of a callback body executed by a framework phase."""

    FULL = "full"
    BEFORE_YIELD = "before_yield"
    AFTER_YIELD = "after_yield"


class RegistrationMatcher(_StrictModel):
    """Exact or segment-bounded registration callable identity."""

    symbol: str = Field(min_length=3)
    invocation: InvocationKind
    receiver_type: str | None = Field(default=None, min_length=3)

    @field_validator("symbol")
    @classmethod
    def validate_symbol(cls, value: str) -> str:
        parts = value.split(".")
        if len(parts) < 2 or any(
            part != "*" and (not part.isidentifier() or keyword.iskeyword(part)) for part in parts
        ):
            raise ValueError("registration symbol must be a dotted Python identity pattern")
        if parts[-1] == "*":
            raise ValueError("registration wildcard cannot replace the callable name")
        if "*" in parts and sum(part != "*" for part in parts[:-1]) < 2:
            raise ValueError("wildcard registrations require two exact leading identity segments")
        return value

    @field_validator("receiver_type")
    @classmethod
    def validate_receiver_type(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parts = value.split(".")
        if len(parts) < 2 or any(
            not part.isidentifier() or keyword.iskeyword(part) for part in parts
        ):
            raise ValueError("receiver_type must be an exact dotted Python identity")
        return value

    @model_validator(mode="after")
    def validate_receiver(self) -> RegistrationMatcher:
        is_method = self.invocation in {
            InvocationKind.INSTANCE_METHOD,
            InvocationKind.CLASS_METHOD,
        }
        if is_method != (self.receiver_type is not None):
            raise ValueError("method registrations require receiver_type; functions forbid it")
        if self.receiver_type is not None:
            pattern_parts = self.symbol.split(".")
            receiver_parts = self.receiver_type.split(".")
            if len(pattern_parts) != len(receiver_parts) + 1 or any(
                pattern not in ("*", actual)
                for pattern, actual in zip(pattern_parts[:-1], receiver_parts, strict=True)
            ):
                raise ValueError("registration symbol owner must match receiver_type")
        return self

    @property
    def match_kind(self) -> SurfaceMatchKind:
        return (
            SurfaceMatchKind.WILDCARD if "*" in self.symbol.split(".") else SurfaceMatchKind.EXACT
        )


class HandlerSelector(_StrictModel):
    """Bounded callback selector with no expression evaluation."""

    kind: HandlerSelectorKind
    index: StrictInt | None = Field(default=None, ge=0)
    name: str | None = Field(default=None, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    base: str | None = Field(default=None, min_length=3)

    @field_validator("base")
    @classmethod
    def validate_base(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parts = value.split(".")
        if len(parts) < 2 or any(
            not part.isidentifier() or keyword.iskeyword(part) for part in parts
        ):
            raise ValueError("handler base must be an exact dotted Python identity")
        return value

    @model_validator(mode="after")
    def validate_shape(self) -> HandlerSelector:
        if self.kind == HandlerSelectorKind.ARGUMENT:
            if self.index is None or self.name is not None or self.base is not None:
                raise ValueError("argument handler selectors require only index")
        elif self.kind == HandlerSelectorKind.KEYWORD:
            if self.name is None or self.index is not None or self.base is not None:
                raise ValueError("keyword handler selectors require only name")
        elif self.kind == HandlerSelectorKind.ARGUMENT_CLASS_METHOD:
            if self.index is None or self.name is None or self.base is None:
                raise ValueError(
                    "argument_class_method selectors require index, method name, and exact base"
                )
        elif self.index is not None or self.name is not None or self.base is not None:
            raise ValueError("decorated_function selectors forbid index, name, and base")
        return self


class ResourceSelector(_StrictModel):
    """Finite string resource selector used to build a surface ID."""

    kind: ResourceSelectorKind
    index: StrictInt | None = Field(default=None, ge=0)
    name: str | None = Field(default=None, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    value: str | None = Field(default=None, min_length=1, max_length=256)
    handler_name_normalization: HandlerNameNormalization = HandlerNameNormalization.EXACT

    @model_validator(mode="after")
    def validate_shape(self) -> ResourceSelector:
        if self.kind in {
            ResourceSelectorKind.ARGUMENT,
            ResourceSelectorKind.ARGUMENTS,
        }:
            valid = self.index is not None and self.name is None and self.value is None
        elif self.kind == ResourceSelectorKind.ARGUMENT_OR_KEYWORD:
            valid = self.index is not None and self.name is not None and self.value is None
        elif self.kind in {
            ResourceSelectorKind.KEYWORD,
            ResourceSelectorKind.KEYWORD_OR_HANDLER_NAME,
        }:
            valid = self.name is not None and self.index is None and self.value is None
        elif self.kind == ResourceSelectorKind.LITERAL:
            valid = self.value is not None and self.index is None and self.name is None
        else:
            valid = self.index is None and self.name is None and self.value is None
        if not valid:
            raise ValueError("resource selector fields do not match its kind")
        if self.handler_name_normalization != HandlerNameNormalization.EXACT and self.kind not in {
            ResourceSelectorKind.HANDLER_NAME,
            ResourceSelectorKind.KEYWORD_OR_HANDLER_NAME,
        }:
            raise ValueError("handler name normalization requires a handler-name selector")
        return self


class SurfaceIdentity(_StrictModel):
    """Surface kind and bounded ID formatting."""

    kind: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$", max_length=64)
    id_template: str = Field(min_length=1, max_length=256)
    resource: ResourceSelector

    @field_validator("id_template")
    @classmethod
    def validate_template(cls, value: str) -> str:
        if value.count("{resource}") != 1 or value.replace("{resource}", "").find("{") >= 0:
            raise ValueError("id_template must contain exactly one {resource} placeholder")
        if "}" in value.replace("{resource}", ""):
            raise ValueError("id_template contains an unsupported closing brace")
        return value


class SurfaceContract(_StrictModel):
    """One custom registration-to-handler surface contract."""

    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    registration: RegistrationMatcher
    handler: HandlerSelector
    handler_optional: bool = False
    surface: SurfaceIdentity
    callback_mode: CallbackMode = CallbackMode.EITHER
    callback_range: CallbackRangeMode = CallbackRangeMode.FULL
    execution_mode: SurfaceExecutionMode = SurfaceExecutionMode.DIRECT
    activates_routes: bool = False
    conditions: tuple[str, ...] = ()
    provenance: ContractProvenance | None = None

    @field_validator("conditions")
    @classmethod
    def validate_conditions(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item.strip() or len(item) > 256 for item in value):
            raise ValueError("conditions must be non-blank strings of at most 256 characters")
        if len(set(value)) != len(value):
            raise ValueError("conditions must be unique")
        return value

    @model_validator(mode="after")
    def validate_decorator_shape(self) -> SurfaceContract:
        if self.handler_optional and self.handler.kind != HandlerSelectorKind.KEYWORD:
            raise ValueError("optional handlers require a keyword selector")
        if (
            self.handler.kind == HandlerSelectorKind.DECORATED_FUNCTION
            and self.registration.invocation == InvocationKind.CONSTRUCTOR
        ):
            raise ValueError("constructor registrations cannot decorate handlers")
        if self.callback_range != CallbackRangeMode.FULL and self.callback_mode not in {
            CallbackMode.GENERATOR,
            CallbackMode.ASYNC_GENERATOR,
        }:
            raise ValueError("yield-relative callback ranges require a generator callback")
        if self.activates_routes and (
            self.execution_mode != SurfaceExecutionMode.FRAMEWORK
            or self.surface.kind != "framework.lifecycle"
        ):
            raise ValueError("route activation requires a framework lifecycle contract")
        return self


class SurfaceContractDocument(_StrictModel):
    """Versioned deterministic custom-surface contract set."""

    schema_version: Literal[1, 2, 3, 4, 5] = 1
    preset: PresetMetadata
    contracts: tuple[SurfaceContract, ...] = Field(min_length=1)

    @field_validator("schema_version", mode="before")
    @classmethod
    def validate_schema_version_type(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("schema_version must be the integer 1, 2, 3, 4, or 5")
        return value

    @model_validator(mode="after")
    def validate_unique_contracts(self) -> SurfaceContractDocument:
        if self.schema_version == 1 and any(
            contract.execution_mode != SurfaceExecutionMode.DIRECT
            or contract.surface.resource.handler_name_normalization
            != HandlerNameNormalization.EXACT
            for contract in self.contracts
        ):
            raise ValueError(
                "non-direct execution and handler normalization require schema_version 2"
            )
        if self.schema_version < 3 and any(
            contract.registration.invocation == InvocationKind.CONSTRUCTOR
            or contract.callback_range != CallbackRangeMode.FULL
            or contract.handler_optional
            for contract in self.contracts
        ):
            raise ValueError(
                "constructor registrations and callback ranges require schema_version 3"
            )
        if self.schema_version < 4 and any(
            contract.handler.kind == HandlerSelectorKind.ARGUMENT_CLASS_METHOD
            for contract in self.contracts
        ):
            raise ValueError("class-method handlers require schema_version 4")
        if self.schema_version < 5 and any(
            contract.activates_routes for contract in self.contracts
        ):
            raise ValueError("route-activating lifecycle contracts require schema_version 5")
        ids: set[str] = set()
        keys: set[
            tuple[
                str,
                InvocationKind,
                HandlerSelectorKind,
                int | None,
                str | None,
                str | None,
                CallbackRangeMode,
            ]
        ] = set()
        wildcards: list[SurfaceContract] = []
        for contract in self.contracts:
            if contract.id in ids:
                raise ValueError(f"duplicate surface contract id: {contract.id}")
            ids.add(contract.id)
            key = (
                contract.registration.symbol,
                contract.registration.invocation,
                contract.handler.kind,
                contract.handler.index,
                contract.handler.name,
                contract.handler.base,
                contract.callback_range,
            )
            if key in keys:
                raise ValueError("duplicate registration and handler selector contract")
            keys.add(key)
            if contract.registration.match_kind == SurfaceMatchKind.WILDCARD:
                wildcards.append(contract)
        for index, left in enumerate(wildcards):
            for right in wildcards[index + 1 :]:
                left_parts = left.registration.symbol.split(".")
                right_parts = right.registration.symbol.split(".")
                same_selector = (
                    left.registration.invocation == right.registration.invocation
                    and left.registration.receiver_type == right.registration.receiver_type
                    and left.handler == right.handler
                )
                overlaps = len(left_parts) == len(right_parts) and all(
                    left_part == right_part or "*" in (left_part, right_part)
                    for left_part, right_part in zip(left_parts, right_parts, strict=True)
                )
                if same_selector and overlaps:
                    raise ValueError("overlapping wildcard registration contracts")
        return self

    def normalized_payload(self) -> dict[str, Any]:
        payload = self.model_dump(mode="json", exclude_none=True)
        payload["contracts"] = sorted(payload["contracts"], key=lambda item: item["id"])
        return payload

    @property
    def config_hash(self) -> str:
        return _semantic_hash(self.normalized_payload())

    @property
    def preset_hash(self) -> str:
        payload = self.normalized_payload()
        return _semantic_hash({"preset": payload["preset"], "contracts": payload["contracts"]})

    @property
    def contract_hashes(self) -> dict[str, str]:
        return {
            contract.id: _semantic_hash(contract.model_dump(mode="json", exclude_none=True))
            for contract in sorted(self.contracts, key=lambda item: item.id)
        }


class LoadedSurfaceContracts(_StrictModel):
    """Validated contracts plus raw and semantic provenance."""

    source_path: Path
    raw_hash: str
    config_hash: str
    preset_hash: str
    contract_hashes: dict[str, str]
    document: SurfaceContractDocument


def load_surface_preset(name: str) -> LoadedSurfaceContracts:
    """Load one named package-owned surface preset as strict data."""
    path = BUNDLED_SURFACE_PRESETS.get(name)
    if path is None:
        choices = ", ".join(sorted(BUNDLED_SURFACE_PRESETS))
        raise SurfaceContractError(f"unknown surface preset {name!r}; choose from: {choices}")
    return load_surface_contracts(path)


def load_surface_contracts(path: Path) -> LoadedSurfaceContracts:
    """Load YAML, JSON, or TOML custom surfaces without executing project code."""
    source = path.resolve()
    if not source.is_file():
        raise SurfaceContractError(f"surface contract file not found: {path}")
    raw = source.read_bytes()
    if len(raw) > 1_048_576:
        raise SurfaceContractError("surface contract document exceeds the 1 MiB limit")
    try:
        suffix = source.suffix.lower()
        if suffix == ".json":
            data = load_json_unique(raw.decode("utf-8"))
        elif suffix == ".toml":
            data = tomllib.loads(raw.decode("utf-8"))
        elif suffix in {".yaml", ".yml"}:
            data = load_yaml_unique(raw.decode("utf-8"))
        else:
            raise SurfaceContractError("surface contract file must be YAML, JSON, or TOML")
        if not isinstance(data, dict):
            raise SurfaceContractError("surface contract document root must be a mapping")
        document = SurfaceContractDocument.model_validate(data)
    except SurfaceContractError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        tomllib.TOMLDecodeError,
        yaml.YAMLError,
        DuplicateKeyError,
    ) as exc:
        raise SurfaceContractError(f"invalid surface contract document: {exc}") from exc
    except Exception as exc:
        raise SurfaceContractError(f"surface contract validation failed: {exc}") from exc
    return LoadedSurfaceContracts(
        source_path=source,
        raw_hash=f"sha256:{hashlib.sha256(raw).hexdigest()}",
        config_hash=document.config_hash,
        preset_hash=document.preset_hash,
        contract_hashes=document.contract_hashes,
        document=document,
    )


def _semantic_hash(payload: object) -> str:
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"
