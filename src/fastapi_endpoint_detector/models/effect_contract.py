"""Strict declarative contracts for externally observable state effects."""

from __future__ import annotations

import hashlib
import json
import keyword
import re
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

from fastapi_endpoint_detector.strict_data import (
    DuplicateKeyError,
    load_json_unique,
    load_yaml_unique,
)

BUNDLED_EFFECT_PRESETS = {
    "filesystem-v1": Path(__file__).parent.parent / "presets" / "effects_filesystem_v1.yaml",
    "http-clients-v1": Path(__file__).parent.parent / "presets" / "effects_http_clients_v1.yaml",
    "message-bus-v1": Path(__file__).parent.parent / "presets" / "effects_message_bus_v1.yaml",
    "mongodb-v1": Path(__file__).parent.parent / "presets" / "effects_mongodb_v1.yaml",
    "object-storage-v1": (
        Path(__file__).parent.parent / "presets" / "effects_object_storage_v1.yaml"
    ),
    "redis-v1": Path(__file__).parent.parent / "presets" / "effects_redis_v1.yaml",
    "sqlalchemy-v1": Path(__file__).parent.parent / "presets" / "effects_sqlalchemy_v1.yaml",
}


class EffectContractError(ValueError):
    """Raised when an effect-contract document cannot be loaded safely."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class InvocationKind(str, Enum):
    """Statically resolvable callable shape."""

    FUNCTION = "function"
    INSTANCE_METHOD = "instance_method"
    CLASS_METHOD = "class_method"
    CONSTRUCTOR = "constructor"


class EffectOperation(str, Enum):
    """Declared state or I/O operation."""

    READ = "read"
    WRITE = "write"
    UPDATE = "update"
    DELETE = "delete"
    APPEND = "append"
    PUBLISH = "publish"
    CONSUME = "consume"
    REQUEST = "request"
    EXECUTE = "execute"
    STAGE = "stage"
    FLUSH = "flush"
    BEGIN = "begin"
    COMMIT = "commit"
    ROLLBACK = "rollback"


class EffectChannel(str, Enum):
    """Externally meaningful effect channel."""

    REDIS = "redis"
    MONGODB = "mongodb"
    SQL = "sql"
    FILESYSTEM = "filesystem"
    OUTBOUND_HTTP = "outbound_http"
    MESSAGE_BUS = "message_bus"
    OBJECT_STORAGE = "object_storage"
    CACHE = "cache"
    PROCESS = "process"
    CUSTOM = "custom"


class SelectorKind(str, Enum):
    """Bounded data-only selector for resource or value evidence."""

    NONE = "none"
    RECEIVER = "receiver"
    ARGUMENT = "argument"
    KEYWORD = "keyword"


class AsyncMode(str, Enum):
    """Whether the declared operation is synchronous or asynchronous."""

    SYNC = "sync"
    ASYNC = "async"
    EITHER = "either"


class EffectTiming(str, Enum):
    """When a call is declared to produce its effect."""

    IMMEDIATE = "immediate"
    AWAIT = "await"
    STAGED = "staged"
    CONTEXT_ENTER = "context_enter"
    CONTEXT_EXIT = "context_exit"


class TransactionScope(str, Enum):
    """Declared SQL boundary scope without runtime transaction identity."""

    NONE = "none"
    TRANSACTION = "transaction"
    SAVEPOINT = "savepoint"


class ContextExitSemantics(str, Enum):
    """Declared normal/exceptional outcome of an exact SQL context boundary."""

    TRANSACTION_COMMIT_ROLLBACK = "transaction_commit_rollback"
    SAVEPOINT_RELEASE_ROLLBACK = "savepoint_release_rollback"


class ProvenanceKind(str, Enum):
    """Origin of a contract set."""

    USER = "user"
    PRESET = "preset"
    INTERNAL = "internal"


class ContractProvenance(_StrictModel):
    """Auditable, non-executable provenance metadata."""

    kind: ProvenanceKind
    source: str = Field(min_length=1)
    revision: str | None = Field(default=None, min_length=1)


class PresetMetadata(_StrictModel):
    """Identity and version of one contract collection."""

    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    version: str = Field(min_length=1)
    provenance: ContractProvenance


class PackageApplicability(_StrictModel):
    """Target-environment applicability metadata; v1 does not enforce it."""

    distribution: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    version: str | None = Field(default=None, min_length=1)
    python: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def validate_scope(self) -> PackageApplicability:
        if (self.distribution is None) != (self.version is None):
            raise ValueError("distribution and version must be provided together")
        if self.distribution is None and self.python is None:
            raise ValueError("package applicability requires a distribution or Python range")
        return self


class EffectSelector(_StrictModel):
    """A selector that never evaluates application code."""

    kind: SelectorKind = SelectorKind.NONE
    index: StrictInt | None = Field(default=None, ge=0)
    name: str | None = Field(default=None, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    path: tuple[str, ...] = ()

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item.isidentifier() for item in value):
            raise ValueError("selector path components must be identifiers")
        return value

    @model_validator(mode="after")
    def validate_shape(self) -> EffectSelector:
        if self.kind == SelectorKind.ARGUMENT:
            if self.index is None or self.name is not None:
                raise ValueError("argument selectors require only a non-negative index")
        elif self.kind == SelectorKind.KEYWORD:
            if self.name is None or self.index is not None:
                raise ValueError("keyword selectors require only a keyword name")
        elif self.index is not None or self.name is not None:
            raise ValueError("receiver/none selectors forbid index and name")
        if self.kind == SelectorKind.NONE and self.path:
            raise ValueError("none selectors forbid an attribute path")
        return self


class CompositeEffectSelector(_StrictModel):
    """Ordered, domain-separated resource identity components."""

    kind: Literal["composite"]
    components: tuple[EffectSelector, ...] = Field(min_length=2, max_length=4)

    @model_validator(mode="after")
    def validate_components(self) -> CompositeEffectSelector:
        if any(component.kind == SelectorKind.NONE for component in self.components):
            raise ValueError("composite resource components cannot be none selectors")
        return self


EffectResourceSelector = EffectSelector | CompositeEffectSelector


class EffectBehavior(_StrictModel):
    """Declared call timing without implied control-flow proof."""

    async_mode: AsyncMode = AsyncMode.EITHER
    timing: EffectTiming = EffectTiming.IMMEDIATE
    transaction_scope: TransactionScope | None = None
    context_exit: ContextExitSemantics | None = None

    @model_validator(mode="after")
    def validate_async_timing(self) -> EffectBehavior:
        if self.timing == EffectTiming.AWAIT and self.async_mode == AsyncMode.SYNC:
            raise ValueError("await timing cannot be declared synchronous")
        return self


class EffectContract(_StrictModel):
    """Exact symbol contract describing state or I/O semantics."""

    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    symbol: str = Field(min_length=3)
    invocation: InvocationKind
    operation: EffectOperation
    channel: EffectChannel
    resource: EffectResourceSelector = Field(default_factory=EffectSelector)
    value: EffectSelector | None = None
    behavior: EffectBehavior = Field(default_factory=EffectBehavior)
    package: PackageApplicability | None = None
    provenance: ContractProvenance | None = None
    http_method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] | None = None

    @field_validator("symbol")
    @classmethod
    def validate_symbol(cls, value: str) -> str:
        parts = value.split(".")
        if any(not part.isidentifier() or keyword.iskeyword(part) for part in parts):
            raise ValueError("symbol must be an exact dotted Python identifier")
        if len(parts) < 2:
            raise ValueError("symbol must include a module and callable")
        return value

    @model_validator(mode="after")
    def validate_invocation(self) -> EffectContract:
        if (
            self.invocation
            in {
                InvocationKind.INSTANCE_METHOD,
                InvocationKind.CLASS_METHOD,
            }
            and len(self.symbol.split(".")) < 3
        ):
            raise ValueError("method contracts require a class-qualified exact symbol")
        scope = self.behavior.transaction_scope
        context_exit = self.behavior.context_exit
        if scope not in {None, TransactionScope.NONE} and (
            self.channel != EffectChannel.SQL
            or self.operation != EffectOperation.BEGIN
            or self.behavior.timing != EffectTiming.CONTEXT_ENTER
        ):
            raise ValueError(
                "transaction scopes require a SQL begin operation with context_enter timing"
            )
        if context_exit is not None:
            expected_scope = (
                TransactionScope.TRANSACTION
                if context_exit == ContextExitSemantics.TRANSACTION_COMMIT_ROLLBACK
                else TransactionScope.SAVEPOINT
            )
            if scope != expected_scope:
                raise ValueError("context-exit semantics must match the declared transaction scope")
        if self.http_method is not None and (
            self.channel != EffectChannel.OUTBOUND_HTTP or self.operation != EffectOperation.REQUEST
        ):
            raise ValueError("HTTP methods require an outbound_http request contract")
        resource_selectors = (
            self.resource.components
            if isinstance(self.resource, CompositeEffectSelector)
            else (self.resource,)
        )
        selectors = (*resource_selectors, self.value)
        if self.invocation in {InvocationKind.FUNCTION, InvocationKind.CONSTRUCTOR} and any(
            selector is not None and selector.kind == SelectorKind.RECEIVER
            for selector in selectors
        ):
            raise ValueError("function/constructor contracts cannot select a receiver")
        return self


class EffectContractDocument(_StrictModel):
    """Versioned root document for a deterministic contract set."""

    schema_version: Literal[1, 2, 3, 4] = 1
    preset: PresetMetadata
    contracts: tuple[EffectContract, ...] = Field(min_length=1)

    @field_validator("schema_version", mode="before")
    @classmethod
    def validate_schema_version_type(cls, value: object) -> object:
        if type(value) is not int:  # bool is intentionally excluded
            raise ValueError("schema_version must be the integer 1, 2, 3, or 4")
        return value

    @model_validator(mode="after")
    def validate_contract_keys(self) -> EffectContractDocument:
        if self.schema_version < 2 and any(
            contract.behavior.transaction_scope is not None
            or contract.behavior.context_exit is not None
            for contract in self.contracts
        ):
            raise ValueError("transaction scopes and context exits require schema_version 2")
        if self.schema_version < 3 and any(
            contract.http_method is not None for contract in self.contracts
        ):
            raise ValueError("structured HTTP methods require schema_version 3")
        if self.schema_version < 4 and any(
            isinstance(contract.resource, CompositeEffectSelector) for contract in self.contracts
        ):
            raise ValueError("composite resource selectors require schema_version 4")
        ids: set[str] = set()
        keys: dict[tuple[str, InvocationKind], EffectContract] = {}
        for contract in self.contracts:
            if contract.id in ids:
                raise ValueError(f"duplicate contract id: {contract.id}")
            ids.add(contract.id)
            key = (contract.symbol, contract.invocation)
            previous = keys.get(key)
            if previous is not None:
                raise ValueError(
                    "duplicate exact symbol/invocation contract: "
                    f"{contract.symbol} ({contract.invocation.value})"
                )
            keys[key] = contract
        return self

    def normalized_payload(self) -> dict[str, Any]:
        """Return canonical semantic content, independent of YAML ordering."""
        payload = self.model_dump(mode="json", exclude_none=True)
        payload["contracts"] = sorted(payload["contracts"], key=lambda item: item["id"])
        return payload

    @property
    def config_hash(self) -> str:
        """Hash the complete validated semantic document."""
        return _semantic_hash(self.normalized_payload())

    @property
    def preset_hash(self) -> str:
        """Hash preset identity together with its normalized contracts."""
        payload = self.normalized_payload()
        return _semantic_hash(
            {
                "preset": payload["preset"],
                "contracts": payload["contracts"],
            }
        )

    @property
    def contract_hashes(self) -> dict[str, str]:
        """Return deterministic per-contract semantic hashes."""
        return {
            contract.id: _semantic_hash(contract.model_dump(mode="json", exclude_none=True))
            for contract in sorted(self.contracts, key=lambda item: item.id)
        }


class LoadedEffectContracts(_StrictModel):
    """Validated document plus source-byte and semantic provenance."""

    source_path: Path
    raw_hash: str
    config_hash: str
    preset_hash: str
    contract_hashes: dict[str, str]
    document: EffectContractDocument


class CallResolutionStatus(str, Enum):
    """Typed resolver outcome for a source call site."""

    EXACT = "exact"
    AMBIGUOUS = "ambiguous"
    UNRESOLVED = "unresolved"


class FiniteValueStatus(str, Enum):
    """Strength of one bounded source value set."""

    EXACT = "exact"
    FINITE = "finite"
    UNAVAILABLE = "unavailable"


class CallArgumentEvidence(_StrictModel):
    """Hashed finite string evidence for one source call argument."""

    source_index: StrictInt = Field(ge=0)
    positional_index: StrictInt | None = Field(default=None, ge=0)
    keyword: str | None = Field(default=None, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    status: FiniteValueStatus
    value_hashes: tuple[str, ...] = Field(default=(), max_length=8)
    reason_code: str | None = None

    @model_validator(mode="after")
    def validate_evidence(self) -> CallArgumentEvidence:
        if (self.positional_index is None) == (self.keyword is None):
            raise ValueError("argument evidence requires one positional or keyword identity")
        if self.value_hashes != tuple(sorted(set(self.value_hashes))):
            raise ValueError("argument value hashes must be sorted and unique")
        if any(re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None for item in self.value_hashes):
            raise ValueError("argument values must be SHA-256 identities")
        if self.status == FiniteValueStatus.EXACT:
            if len(self.value_hashes) != 1 or self.reason_code is not None:
                raise ValueError("exact argument evidence requires one hash and no reason")
        elif self.status == FiniteValueStatus.FINITE:
            if len(self.value_hashes) < 2 or self.reason_code is not None:
                raise ValueError("finite argument evidence requires multiple hashes and no reason")
        elif self.value_hashes or not self.reason_code:
            raise ValueError("unavailable argument evidence requires only a reason code")
        return self


class ResourceIdentityEvidence(_StrictModel):
    """Versioned finite resource identity without exposing source literals."""

    schema_version: Literal[1] = 1
    status: FiniteValueStatus
    value_hashes: tuple[str, ...] = Field(default=(), max_length=8)
    reason_code: str | None = None

    @model_validator(mode="after")
    def validate_identity(self) -> ResourceIdentityEvidence:
        if self.value_hashes != tuple(sorted(set(self.value_hashes))):
            raise ValueError("resource value hashes must be sorted and unique")
        if any(re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None for item in self.value_hashes):
            raise ValueError("resource values must be SHA-256 identities")
        expected = (
            FiniteValueStatus.EXACT
            if len(self.value_hashes) == 1
            else FiniteValueStatus.FINITE
            if self.value_hashes
            else FiniteValueStatus.UNAVAILABLE
        )
        if self.status != expected:
            raise ValueError("resource identity status does not match value cardinality")
        if (self.status == FiniteValueStatus.UNAVAILABLE) != bool(self.reason_code):
            raise ValueError("only unavailable resource identities require a reason")
        return self


class ResolvedCallSite(_StrictModel):
    """Backend-neutral seam required before exact contract matching."""

    file_path: str
    line: StrictInt = Field(ge=1)
    column: StrictInt = Field(ge=0)
    end_line: StrictInt | None = Field(default=None, ge=1)
    end_column: StrictInt | None = Field(default=None, ge=0)
    source_spelling: str = Field(min_length=1)
    canonical_symbol: str | None = None
    invocation: InvocationKind | None = None
    status: CallResolutionStatus
    resolver: str = Field(min_length=1)
    resolver_version: str = Field(min_length=1)
    receiver_candidates: tuple[str, ...] = ()
    reason_code: str | None = None
    arguments: tuple[CallArgumentEvidence, ...] = Field(default=(), max_length=64)
    receiver_origin: ResourceIdentityEvidence | None = None

    @field_validator("file_path", "source_spelling", "resolver", "resolver_version")
    @classmethod
    def validate_nonblank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("call-site identity fields must not be blank")
        return value

    @model_validator(mode="after")
    def validate_resolution(self) -> ResolvedCallSite:
        if (self.end_line is None) != (self.end_column is None):
            raise ValueError("end_line and end_column must be provided together")
        if self.end_line is not None and (self.end_line, self.end_column or 0) < (
            self.line,
            self.column,
        ):
            raise ValueError("call-site end position cannot precede its start")
        if self.status == CallResolutionStatus.EXACT:
            if self.canonical_symbol is None or self.invocation is None:
                raise ValueError("exact call sites require canonical symbol and invocation")
            EffectContract.validate_symbol(self.canonical_symbol)
            if (
                self.invocation
                in {
                    InvocationKind.INSTANCE_METHOD,
                    InvocationKind.CLASS_METHOD,
                }
                and len(self.canonical_symbol.split(".")) < 3
            ):
                raise ValueError("exact method call sites require a class-qualified symbol")
        elif self.canonical_symbol is not None:
            raise ValueError("ambiguous/unresolved call sites forbid a canonical symbol")
        if self.status != CallResolutionStatus.EXACT and not self.reason_code:
            raise ValueError("ambiguous/unresolved call sites require a reason code")
        source_indexes = [item.source_index for item in self.arguments]
        if source_indexes != sorted(set(source_indexes)):
            raise ValueError("call argument source indexes must be sorted and unique")
        positional_indexes = [
            item.positional_index for item in self.arguments if item.positional_index is not None
        ]
        if positional_indexes != list(range(len(positional_indexes))):
            raise ValueError("positional argument indexes must be contiguous")
        keywords = [item.keyword for item in self.arguments if item.keyword is not None]
        if len(keywords) != len(set(keywords)):
            raise ValueError("call argument keywords must be unique")
        if self.receiver_origin is not None and (
            self.status != CallResolutionStatus.EXACT
            or self.invocation != InvocationKind.INSTANCE_METHOD
        ):
            raise ValueError("receiver origins require an exact instance-method call")
        return self


def load_effect_contracts(path: Path) -> LoadedEffectContracts:
    """Load YAML, JSON, or TOML contracts without executing application code."""
    source = path.resolve()
    if not source.is_file():
        raise EffectContractError(f"effect contract file not found: {path}")
    raw = source.read_bytes()
    if len(raw) > 1_048_576:
        raise EffectContractError("effect contract document exceeds the 1 MiB limit")
    try:
        if source.suffix.lower() == ".json":
            data = load_json_unique(raw.decode("utf-8"))
        elif source.suffix.lower() == ".toml":
            data = tomllib.loads(raw.decode("utf-8"))
        elif source.suffix.lower() in {".yaml", ".yml"}:
            data = load_yaml_unique(raw.decode("utf-8"))
        else:
            raise EffectContractError("effect contract file must be YAML, JSON, or TOML")
        if not isinstance(data, dict):
            raise EffectContractError("effect contract document root must be a mapping")
        document = EffectContractDocument.model_validate(data)
    except EffectContractError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        tomllib.TOMLDecodeError,
        yaml.YAMLError,
        DuplicateKeyError,
    ) as exc:
        raise EffectContractError(f"invalid effect contract document: {exc}") from exc
    except Exception as exc:
        raise EffectContractError(f"effect contract validation failed: {exc}") from exc
    return LoadedEffectContracts(
        source_path=source,
        raw_hash=f"sha256:{hashlib.sha256(raw).hexdigest()}",
        config_hash=document.config_hash,
        preset_hash=document.preset_hash,
        contract_hashes=document.contract_hashes,
        document=document,
    )


def load_effect_preset(name: str) -> LoadedEffectContracts:
    """Load one immutable package-owned effect preset by its versioned name."""
    path = BUNDLED_EFFECT_PRESETS.get(name)
    if path is None:
        available = ", ".join(sorted(BUNDLED_EFFECT_PRESETS))
        raise EffectContractError(
            f"unknown effect preset: {name!r}; available presets: {available}"
        )
    return load_effect_contracts(path)


def _semantic_hash(payload: object) -> str:
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"
