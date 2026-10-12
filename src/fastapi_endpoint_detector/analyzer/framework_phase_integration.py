"""Adapt selected framework surfaces to typed mypy callback evidence.

This is the source integration seam for phase-aware framework analysis. It
starts only from the selected surface inventory and never explores external
framework implementation bodies.
"""

from __future__ import annotations

import ast
import hashlib
import importlib.metadata
import json
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING, Any

from mypy.nodes import (
    AssignmentExpr,
    AssignmentStmt,
    Block,
    CallExpr,
    CastExpr,
    ClassDef,
    ComparisonExpr,
    ConditionalExpr,
    Decorator,
    DictExpr,
    ExpressionStmt,
    ForStmt,
    FuncDef,
    IfStmt,
    IndexExpr,
    ListExpr,
    MatchStmt,
    MemberExpr,
    NameExpr,
    OpExpr,
    RevealExpr,
    SetExpr,
    SliceExpr,
    StarExpr,
    TryStmt,
    TupleExpr,
    TypeInfo,
    UnaryExpr,
    WhileStmt,
    WithStmt,
)
from pydantic import BaseModel, ConfigDict, Field, model_serializer, model_validator

from fastapi_endpoint_detector.analyzer.framework_phase_bridge import (
    FrameworkPhase,
    SourceIdentity,
    canonical_framework_phase,
)
from fastapi_endpoint_detector.analyzer.immutable_typed_source import (
    ImmutableTypedSource,
    SourceCaptureError,
)
from fastapi_endpoint_detector.models.effect_contract import (
    CallResolutionStatus,
    ResolvedCallSite,
)
from fastapi_endpoint_detector.models.endpoint import (
    Endpoint,
    EndpointInventory,
    SnapshotSide,
)
from fastapi_endpoint_detector.models.surface_contract import (
    CallbackRangeMode,
    LoadedSurfaceContracts,
    SurfaceContract,
    SurfaceExecutionMode,
    load_surface_preset,
)
from fastapi_endpoint_detector.parser.custom_surface_extractor import CustomSurfaceExtractor

_CONSTRUCTOR_SCAN_MAX_NODES = 20_000
_CONSTRUCTOR_SCAN_MAX_DEPTH = 64
_CONSTRUCTOR_SCAN_MAX_ITEMS = 20_000

if TYPE_CHECKING:
    from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
    from fastapi_endpoint_detector.analyzer.mypy_incremental import TypedBuild


class ConstructorLifespanEvidence(BaseModel):
    """Typed evidence for a literal FastAPI(lifespan=callback) binding."""

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
    def validate_constructor(self) -> ConstructorLifespanEvidence:
        if self.constructor_symbol != "fastapi.applications.FastAPI":
            raise ValueError("constructor evidence must identify FastAPI's exact typed constructor")
        return self


class FrameworkPhaseRecord(BaseModel):
    """One selected surface's phase binding and typed callback-body evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    phase: FrameworkPhase
    callback: SourceIdentity
    typed_callback_symbol: str | None = None
    registration: SourceIdentity | None = None
    typed_framework_symbol: str | None = None
    registration_call_site: ResolvedCallSite | None = None
    constructor_lifespan: ConstructorLifespanEvidence | None = None
    resource: str = Field(min_length=1)
    callback_file_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    registration_file_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    framework_declaration_sha256: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    canonical_contract_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    typed_provider_fingerprint: str | None = Field(default=None, min_length=1)
    contract_id: str
    snapshot_side: str = Field(pattern="^(target|baseline)$")
    callback_range: CallbackRangeMode
    execution_conditions: tuple[str, ...] = ()
    body_call_sites: tuple[ResolvedCallSite, ...] = ()
    limitations: tuple[str, ...] = ()
    source_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    inventory_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    engine_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    config_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_serializer(mode="wrap")
    def omit_absent_constructor(self, handler: Any) -> Any:
        value = handler(self)
        if self.constructor_lifespan is None:
            value.pop("constructor_lifespan", None)
        return value

    @model_validator(mode="after")
    def validate_typed_registration(self) -> FrameworkPhaseRecord:
        site = self.registration_call_site
        canonical = load_surface_preset("framework-v1")
        contract = next(
            (item for item in canonical.document.contracts if item.id == self.contract_id),
            None,
        )
        if (
            contract is None
            or canonical.document.contract_hashes.get(self.contract_id)
            != self.canonical_contract_sha256
            or canonical_framework_phase(
                contract,
                self.resource,
                self.callback_range,
                canonical,
            )
            != self.phase
        ):
            raise ValueError(
                "phase, range, and contract must match the canonical framework catalog"
            )
        if self.typed_callback_symbol is not None and self.typed_callback_symbol != (
            f"{self.callback.module}.{self.callback.symbol}"
        ):
            raise ValueError("typed callback symbol must equal its source-qualified identity")
        if site is not None and (
            site.status != CallResolutionStatus.EXACT
            or site.canonical_symbol != self.typed_framework_symbol
            or self.registration is None
            or Path(site.file_path).resolve() != Path(self.registration.file).resolve()
            or (site.line, site.column) != (self.registration.line, self.registration.column)
            or (site.end_line, site.end_column)
            != (self.registration.end_line, self.registration.end_column)
            or site.invocation != contract.registration.invocation
            or site.canonical_symbol is None
            or site.canonical_symbol.split(".")[0] != contract.registration.symbol.split(".")[0]
            or site.canonical_symbol.split(".")[-1] != contract.registration.symbol.split(".")[-1]
            or (
                contract.registration.receiver_type is not None
                and (
                    len(site.receiver_candidates) != 1
                    or site.receiver_candidates[0].split(".")[0]
                    != contract.registration.receiver_type.split(".")[0]
                    or site.receiver_candidates[0].split(".")[-1]
                    != contract.registration.receiver_type.split(".")[-1]
                )
            )
        ):
            raise ValueError("typed registration site must match exact physical provenance")
        constructor = self.constructor_lifespan
        if constructor is not None and (
            self.contract_id not in {"fastapi-lifespan-startup", "fastapi-lifespan-shutdown"}
            or site is not None
            or self.registration is None
            or self.registration.line != constructor.constructor_line
            or self.registration.column != constructor.constructor_column
            or self.registration.end_line != constructor.constructor_end_line
            or self.registration.end_column != constructor.constructor_end_column
            or self.callback != constructor.callback
            or self.typed_callback_symbol != constructor.callback_symbol
            or self.framework_declaration_sha256 != constructor.constructor_file_sha256
        ):
            raise ValueError("constructor lifespan evidence must match exact phase identities")
        if self.contract_id in {"fastapi-lifespan-startup", "fastapi-lifespan-shutdown"} and (
            site is not None or self.typed_framework_symbol is not None
        ):
            raise ValueError("FastAPI lifespan constructor evidence cannot be a method call site")
        return self

    @property
    def status(self) -> str:
        has_registration = (
            self.constructor_lifespan is not None
            if self.contract_id in {"fastapi-lifespan-startup", "fastapi-lifespan-shutdown"}
            else self.registration_call_site is not None
        )
        if (
            self.limitations
            or self.registration is None
            or not has_registration
            or self.typed_callback_symbol is None
            or (
                self.contract_id not in {"fastapi-lifespan-startup", "fastapi-lifespan-shutdown"}
                and self.typed_framework_symbol is None
            )
            or self.framework_declaration_sha256 is None
            or self.callback_file_sha256 is None
            or self.registration_file_sha256 is None
            or self.typed_provider_fingerprint is None
        ):
            return "unavailable"
        return "conditional"


class LifecycleConditionalSurface(BaseModel):
    """A route/surface that exists only after a proven startup activation."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    surface_id: str
    lifecycle_surface_id: str
    phase: FrameworkPhase = FrameworkPhase.STARTUP
    condition: str = "installed only if startup lifecycle execution succeeds"
    registration_file: str
    registration_line: int = Field(ge=1)
    activation_file: str
    activation_line: int = Field(ge=1)
    activation_source_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class FrameworkPhaseIntegration(BaseModel):
    """Bounded output suitable for report/mapper integration."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: int = 1
    backend: str
    backend_version: str
    snapshot_side: str = Field(pattern="^(target|baseline)$")
    records: tuple[FrameworkPhaseRecord, ...]
    lifecycle_conditional_surfaces: tuple[LifecycleConditionalSurface, ...]
    limitations: tuple[str, ...] = ()


def _digest(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _phase(
    endpoint: Endpoint,
    contracts: LoadedSurfaceContracts,
) -> FrameworkPhase | None:
    surface = endpoint.surface
    if surface is None:
        return None
    contract = _contract_for(endpoint, contracts)
    if contract is None:
        return None
    return canonical_framework_phase(contract, surface.resource, surface.callback_range, contracts)


def _contract_for(
    endpoint: Endpoint,
    contracts: LoadedSurfaceContracts,
) -> SurfaceContract | None:
    assert endpoint.surface is not None
    return next(
        (item for item in contracts.document.contracts if item.id == endpoint.surface.contract_id),
        None,
    )


def _typed_registration(
    endpoint: Endpoint,
    contract: SurfaceContract,
    sites: list[ResolvedCallSite],
    typed_build: TypedBuild,
    source_root: Path,
) -> tuple[ResolvedCallSite, str] | None:
    """Join source-selected contract evidence to one exact typed occurrence.

    Re-exported framework classes can have different public alias and defining
    module names. We preserve mypy's exact symbol, and join through the
    physical registration occurrence plus exact invocation, receiver class,
    and member identity. Multiple candidates fail closed.
    """
    surface = endpoint.surface
    if surface is None:
        return None
    registration_contract = contract.registration
    if surface.registration_symbol != registration_contract.symbol:
        return None
    source_path = str(surface.registration_file.resolve())
    expected_parts = registration_contract.symbol.split(".")
    expected_package = expected_parts[0]
    expected_member = expected_parts[-1]
    receiver_type = registration_contract.receiver_type
    receiver_leaf = receiver_type.rsplit(".", maxsplit=1)[-1] if receiver_type else None
    matched: list[ResolvedCallSite] = []
    for site in sites:
        if (
            Path(site.file_path).resolve() != Path(source_path)
            or site.line != surface.registration_line
            or site.column != surface.registration_column
            or site.status != CallResolutionStatus.EXACT
            or site.invocation != registration_contract.invocation
            or site.canonical_symbol is None
        ):
            continue
        symbol_parts = site.canonical_symbol.split(".")
        if symbol_parts[0] != expected_package or symbol_parts[-1] != expected_member:
            continue
        if receiver_leaf is not None:
            receiver_types = set(site.receiver_candidates)
            if len(receiver_types) != 1:
                continue
            receiver = next(iter(receiver_types)).split(".")
            if receiver[0] != expected_package or receiver[-1] != receiver_leaf:
                continue
        elif len(symbol_parts) < 2 or symbol_parts[-1] != expected_parts[-1]:
            continue
        matched.append(site)
    if len(matched) != 1:
        return None
    site = matched[0]
    trusted_source = _trusted_framework_source(site, typed_build, source_root)
    if trusted_source is None:
        return None
    return site, trusted_source[1]


def _typed_module_path(module_name: str, typed_build: TypedBuild) -> Path | None:
    state = typed_build.modules.get(module_name)
    tree = getattr(state, "tree", None) if state is not None else None
    path = getattr(tree, "path", None)
    return Path(path).resolve() if isinstance(path, str) and path else None


def _constructor_lifespan_evidence(  # noqa: PLR0911, PLR0912, PLR0915
    endpoint: Endpoint,
    typed_build: TypedBuild,
    source_root: Path,
    typed_callback: str | None,
    captured_sources: ImmutableTypedSource,
) -> ConstructorLifespanEvidence | None:
    """Prove one module-level FastAPI constructor and its direct callback binding."""
    surface = endpoint.surface
    if surface is None:
        return None
    if surface.registration_file.resolve() != endpoint.handler.file_path.resolve():
        return None
    state = typed_build.modules.get(endpoint.handler.module)
    tree = getattr(state, "tree", None) if state is not None else None
    if tree is None or Path(tree.path).resolve() != endpoint.handler.file_path.resolve():
        return None
    constructors: list[tuple[CallExpr, NameExpr | MemberExpr, TypeInfo]] = []
    # Walk only known module-level syntax edges. Semantic links (node/info/type)
    # can fan out into the whole imported program and are deliberately excluded.
    pending: list[tuple[object, int]] = [(item, 0) for item in getattr(tree, "defs", ())]
    seen: set[int] = set()
    work = 0
    exhausted = False
    while pending:
        work += 1
        if work > _CONSTRUCTOR_SCAN_MAX_NODES or len(pending) > _CONSTRUCTOR_SCAN_MAX_ITEMS:
            exhausted = True
            break
        value, depth = pending.pop()
        if depth > _CONSTRUCTOR_SCAN_MAX_DEPTH:
            exhausted = True
            break
        if isinstance(value, (list, tuple)):
            if len(value) > _CONSTRUCTOR_SCAN_MAX_ITEMS:
                exhausted = True
                break
            pending.extend((child, depth + 1) for child in value)
            continue
        if not hasattr(type(value), "__mypyc_attrs__") or id(value) in seen:
            continue
        seen.add(id(value))
        if len(seen) > _CONSTRUCTOR_SCAN_MAX_NODES:
            exhausted = True
            break
        if isinstance(value, (FuncDef, ClassDef, Decorator)):
            continue
        if isinstance(value, CallExpr) and isinstance(value.callee, (NameExpr, MemberExpr)):
            target = value.callee.node
            if isinstance(target, TypeInfo) and target.name == "FastAPI":
                constructors.append((value, value.callee, target))
        fields: tuple[str, ...] = ()
        if isinstance(value, AssignmentStmt):
            fields = ("lvalues", "rvalue")
        elif isinstance(value, ExpressionStmt):
            fields = ("expr",)
        elif isinstance(value, IfStmt):
            fields = ("expr", "body", "else_body")
        elif isinstance(value, WithStmt):
            fields = ("expr", "target", "body")
        elif isinstance(value, TryStmt):
            fields = ("body", "handlers", "else_body", "finally_body")
        elif isinstance(value, (ForStmt, WhileStmt)):
            fields = ("expr", "body", "else_body")
        elif isinstance(value, MatchStmt):
            fields = ("subject", "patterns", "guards", "bodies")
        elif isinstance(value, Block):
            fields = ("body",)
        elif isinstance(value, CallExpr):
            fields = ("args",)
        elif isinstance(value, (ListExpr, TupleExpr, SetExpr, DictExpr)):
            fields = ("items",)
        elif isinstance(value, IndexExpr):
            fields = ("base", "index")
        elif isinstance(value, UnaryExpr):
            fields = ("expr",)
        elif isinstance(value, OpExpr):
            fields = ("left", "right")
        elif isinstance(value, ConditionalExpr):
            fields = ("cond", "if_expr", "else_expr")
        elif isinstance(value, ComparisonExpr):
            fields = ("operands",)
        elif isinstance(value, (CastExpr, RevealExpr, StarExpr)):
            fields = ("expr",)
        elif isinstance(value, AssignmentExpr):
            fields = ("target", "value")
        elif isinstance(value, SliceExpr):
            fields = ("begin_index", "end_index", "stride")
        elif isinstance(value, (NameExpr, MemberExpr)):
            fields = ("expr",) if isinstance(value, MemberExpr) else ()
        for field in fields:
            child = getattr(value, field, None)
            if child is not None:
                pending.append((child, depth + 1))
    if exhausted:
        return None
    if len(constructors) != 1:
        return None
    call, callee, info = constructors[0]
    if not (
        (isinstance(callee, NameExpr) and callee.name == "FastAPI")
        or (
            isinstance(callee, MemberExpr)
            and callee.name == "FastAPI"
            and isinstance(callee.expr, NameExpr)
            and callee.expr.name == "fastapi"
        )
    ):
        return None
    constructor_symbol = info.fullname
    module_name = info.module_name
    module_path = _typed_module_path(module_name, typed_build)
    if (
        constructor_symbol != "fastapi.applications.FastAPI"
        or module_name != "fastapi.applications"
        or module_path is None
        or module_path.is_relative_to(source_root.resolve())
        or module_path.suffix != ".py"
    ):
        return None
    try:
        distribution = importlib.metadata.distribution("fastapi")
    except importlib.metadata.PackageNotFoundError:
        return None
    files = distribution.files
    if files is None or module_path not in {
        Path(str(distribution.locate_file(item))).resolve() for item in files
    }:
        return None
    module_matches = [
        (name, candidate)
        for name, candidate in typed_build.modules.items()
        if (candidate_tree := getattr(candidate, "tree", None)) is not None
        and (candidate_path := getattr(candidate_tree, "path", None)) is not None
        and Path(candidate_path).resolve() == module_path
    ]
    if len(module_matches) != 1 or module_matches[0][0] != module_name:
        return None
    captured = captured_sources.files.get(str(module_path))
    if captured is None or str(module_path) not in captured_sources.typed_paths:
        return None
    framework_source_digest = captured.sha256
    framework_digest = "sha256:" + framework_source_digest
    lifespan_values = [
        expression
        for name, expression in zip(call.arg_names, call.args, strict=True)
        if name == "lifespan"
    ]
    if len(lifespan_values) != 1 or not isinstance(lifespan_values[0], NameExpr):
        return None
    value = lifespan_values[0]
    callback_node = value.node
    callback_func = callback_node.func if isinstance(callback_node, Decorator) else callback_node
    if (
        not isinstance(callback_func, FuncDef)
        or typed_callback is None
        or callback_func.name != endpoint.handler.name
        or callback_func.line is None
        or callback_func.line > endpoint.handler.line_number
        or callback_func.end_line is None
        or (
            endpoint.handler.end_line_number is not None
            and callback_func.end_line < endpoint.handler.end_line_number
        )
    ):
        return None
    selected_callback = _selected_callback_node(tree, endpoint, typed_callback)
    if selected_callback is None or callback_func is not selected_callback:
        return None
    if call.line != surface.registration_line or call.column != surface.registration_column:
        return None
    end_line = call.end_line
    end_column = call.end_column
    if end_line is None or end_column is None:
        return None
    handler_path = str(endpoint.handler.file_path.resolve())
    handler_capture = captured_sources.files.get(handler_path)
    if handler_capture is None or handler_path not in captured_sources.typed_paths:
        return None
    source_digest = handler_capture.sha256
    try:
        raw_digest = hashlib.sha256(_bounded_source_bytes(endpoint.handler.file_path)).hexdigest()
    except OSError:
        return None
    if source_digest != raw_digest:
        return None
    callback = _callback_identity(endpoint, typed_callback)
    return ConstructorLifespanEvidence(
        constructor_symbol=constructor_symbol,
        constructor_file=str(module_path),
        constructor_file_sha256=framework_digest,
        provider_capture_sha256="sha256:" + captured_sources.identity,
        constructor_line=call.line,
        constructor_column=call.column,
        constructor_end_line=end_line,
        constructor_end_column=end_column,
        callback_symbol=typed_callback,
        callback=callback,
    )


def _trusted_framework_source(  # noqa: PLR0911
    site: ResolvedCallSite,
    typed_build: TypedBuild,
    source_root: Path,
) -> tuple[Path, str] | None:
    """Require typed symbol ownership by installed FastAPI/Starlette sources."""
    if site.canonical_symbol is None or not site.canonical_symbol.startswith(
        ("fastapi.", "starlette.")
    ):
        return None
    package = site.canonical_symbol.split(".", maxsplit=1)[0]
    receiver = site.receiver_candidates[0] if len(site.receiver_candidates) == 1 else None
    if receiver is not None:
        module_name = receiver.rpartition(".")[0]
    else:
        parts = site.canonical_symbol.split(".")[:-1]
        module_name = ""
        for end in range(len(parts), 0, -1):
            candidate = ".".join(parts[:end])
            if _typed_module_path(candidate, typed_build) is not None:
                module_name = candidate
                break
    module_path = _typed_module_path(module_name, typed_build) if module_name else None
    if module_path is None or module_path.is_relative_to(source_root.resolve()):
        return None
    # A declaration stub proves type identity, not runtime lifecycle behavior.
    if module_path.suffix != ".py":
        return None
    distributions = {"fastapi": "fastapi", "starlette": "starlette"}
    try:
        distribution = importlib.metadata.distribution(distributions[package])
    except (KeyError, importlib.metadata.PackageNotFoundError):
        return None
    installed_files = distribution.files
    if installed_files is None:
        return None
    owned_paths = {Path(str(distribution.locate_file(item))).resolve() for item in installed_files}
    if module_path not in owned_paths:
        return None
    try:
        digest = "sha256:" + hashlib.sha256(module_path.read_bytes()).hexdigest()
    except OSError:
        return None
    return module_path, digest


def _condition(endpoint: Endpoint, phase: FrameworkPhase) -> tuple[str, ...]:
    values = [f"framework executes {phase.value} callback only when that phase is dispatched"]
    values.extend(item.reason for item in endpoint.discovery_conditions)
    if endpoint.surface is not None:
        values.extend(endpoint.surface.conditions)
    return tuple(dict.fromkeys(values))


def _callback_identity(endpoint: Endpoint, typed_symbol: str | None) -> SourceIdentity:
    surface = endpoint.surface
    assert surface is not None
    raw = endpoint.handler.file_path.read_bytes()
    module_ast = ast.parse(raw, filename=str(endpoint.handler.file_path))
    matches = [
        node
        for node in ast.walk(module_ast)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == endpoint.handler.name
        and node.lineno <= endpoint.handler.line_number <= (node.end_lineno or node.lineno)
    ]
    if len(matches) == 1:
        definition = matches[0]
        start_line = definition.lineno
        start_column = definition.col_offset
        end_line = definition.end_lineno
        end_column = definition.end_col_offset
    else:
        start_line = endpoint.handler.line_number
        start_column = 0
        end_line = None
        end_column = None
    return SourceIdentity(
        module=endpoint.handler.module,
        symbol=(
            typed_symbol.removeprefix(f"{endpoint.handler.module}.")
            if typed_symbol
            else endpoint.handler.name
        ),
        file=str(endpoint.handler.file_path.resolve()),
        line=start_line,
        column=start_column,
        end_line=end_line,
        end_column=end_column,
        source_sha256=surface.handler_source_hash,
    )


def _typed_callback_symbol(endpoint: Endpoint, typed_build: TypedBuild | None) -> str | None:
    """Resolve the selected handler to one declaration in the retained typed graph."""
    if typed_build is None:
        return None
    state = typed_build.modules.get(endpoint.handler.module)
    tree = getattr(state, "tree", None) if state is not None else None
    if tree is None or Path(tree.path).resolve() != endpoint.handler.file_path.resolve():
        return None
    identities: set[str] = set()

    def declaration_fullname(node: object) -> str | None:
        if isinstance(node, Decorator):
            node = node.func
        if isinstance(node, FuncDef) and node.line <= endpoint.handler.line_number <= (
            node.end_line or node.line
        ):
            return node.fullname
        return None

    direct = tree.names.get(endpoint.handler.name)
    if direct is not None:
        fullname = declaration_fullname(direct.node)
        if fullname:
            identities.add(fullname)
    for symbol in tree.names.values():
        node = symbol.node
        if not isinstance(node, TypeInfo):
            continue
        method = node.names.get(endpoint.handler.name)
        if method is None:
            continue
        fullname = declaration_fullname(method.node)
        if fullname:
            identities.add(fullname)
    return next(iter(identities)) if len(identities) == 1 else None


def _registration_identity(endpoint: Endpoint, site: ResolvedCallSite) -> SourceIdentity:
    surface = endpoint.surface
    assert surface is not None
    return SourceIdentity(
        module=endpoint.handler.module,
        symbol=surface.registration_symbol,
        file=str(surface.registration_file.resolve()),
        line=surface.registration_line,
        column=surface.registration_column,
        end_line=site.end_line,
        end_column=site.end_column,
        source_sha256=surface.registration_source_hash,
    )


def _bounded_source_bytes(path: Path, *, max_bytes: int = 8 * 1024 * 1024) -> bytes:
    """Read one regular source file with a strict per-file bound."""
    if not path.is_file() or path.stat().st_size > max_bytes:
        raise OSError("source file is not regular or exceeds the evidence read limit")
    with path.open("rb") as source:
        data = source.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise OSError("source file grew beyond the evidence read limit")
    return data


def _captured_file_digest(path: Path, captured: ImmutableTypedSource | None) -> str | None:
    if captured is None:
        return None
    canonical = str(path.resolve())
    item = captured.files.get(canonical)
    return item.sha256 if item is not None and canonical in captured.typed_paths else None


def _selected_callback_node(
    tree: object, endpoint: Endpoint, typed_callback: str | None
) -> FuncDef | None:
    """Return the unique retained module declaration matching inventory identity."""
    if typed_callback is None or (
        Path(getattr(tree, "path", "")).resolve() != endpoint.handler.file_path.resolve()
    ):
        return None
    matches: list[FuncDef] = []
    for item in getattr(tree, "defs", ()):
        candidate = item.func if isinstance(item, Decorator) else item
        if (
            isinstance(candidate, FuncDef)
            and candidate.name == endpoint.handler.name
            and candidate.fullname == typed_callback
            and candidate.line is not None
            and candidate.end_line is not None
            and candidate.line <= endpoint.handler.line_number <= candidate.end_line
            and (
                endpoint.handler.end_line_number is None
                or endpoint.handler.end_line_number <= candidate.end_line
            )
        ):
            matches.append(candidate)
    return matches[0] if len(matches) == 1 else None


def _source_snapshot_hash(inventory: EndpointInventory) -> str:
    return _digest(
        sorted(
            (
                str(item.surface.registration_file.resolve()),
                item.surface.registration_source_hash,
                str(item.handler.file_path.resolve()),
                item.surface.handler_source_hash,
            )
            for item in inventory.endpoints
            if item.surface is not None
        )
    )


def _surface_key(endpoint: Endpoint) -> str | None:
    if endpoint.surface is None:
        return None
    return json.dumps(
        endpoint.surface.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    )


def _activation_key(endpoint: Endpoint) -> str | None:
    if endpoint.activation is None:
        return None
    return json.dumps(
        endpoint.activation.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    )


def collect_framework_phase_evidence(  # noqa: PLR0912, PLR0915
    inventory: EndpointInventory,
    contracts: LoadedSurfaceContracts,
    analyzer: MypyAnalyzer,
    typed_build: TypedBuild | None,
    *,
    snapshot_side: SnapshotSide = SnapshotSide.TARGET,
    app_variable: str = "app",
    app_entry: str | None = None,
    bootstrap_entry: str | None = None,
) -> FrameworkPhaseIntegration:
    """Analyze selected lifecycle/middleware callbacks using bounded mypy APIs.

    For each selected contract, analyze only its source callback. The callback
    range comes from the validated contract, and no framework implementation
    body is followed. The physical registration must also occur as one exact
    mypy call site in that callback's typed source slice.
    """
    provider_sources: dict[str, str] = {}
    provider_source_error: str | None = None
    captured_sources: ImmutableTypedSource | None = None
    if typed_build is not None:
        try:
            captured_sources = ImmutableTypedSource.capture_build_result(
                typed_build.result,
                source_inventory=analyzer.source_inventory,
            )
            for module, raw_path in typed_build.module_paths.items():
                path = str(Path(raw_path).resolve())
                state = typed_build.modules.get(module)
                tree_path = getattr(getattr(state, "tree", None), "path", None)
                if (
                    tree_path is None
                    or Path(tree_path).resolve() != Path(path)
                    or path not in captured_sources.files
                    or path not in captured_sources.typed_paths
                ):
                    raise SourceCaptureError(
                        f"provider module path is absent from retained source capture: {module}"
                    )
                provider_sources[module] = captured_sources.files[path].sha256
        except (SourceCaptureError, OSError, ValueError) as exc:
            provider_source_error = f"retained typed provider source capture unavailable: {exc}"
    canonical_inventory = CustomSurfaceExtractor(
        analyzer.source_root,
        contracts,
        app_variable=app_variable,
        app_entry=app_entry,
        bootstrap_entry=bootstrap_entry,
    ).extract_inventory()
    selected_surface_counts = Counter(
        key for endpoint in canonical_inventory.endpoints if (key := _surface_key(endpoint))
    )
    selected_activation_counts = Counter(
        key for endpoint in canonical_inventory.endpoints if (key := _activation_key(endpoint))
    )
    source_hash = _digest(
        {
            "selected_surface_sources": _source_snapshot_hash(inventory),
            "provider_sources": sorted(provider_sources.items()),
        }
    )
    inventory_hash = _digest(
        {
            "side": snapshot_side.value,
            "status": inventory.status.value,
            "provider_inventory_fingerprint": (
                typed_build.report.inventory_fingerprint if typed_build is not None else None
            ),
            "provider_modules": (
                sorted(typed_build.module_paths.items()) if typed_build is not None else []
            ),
            "endpoints": [
                {
                    "id": item.identifier,
                    "surface": item.surface.model_dump(mode="json") if item.surface else None,
                    "activation": item.activation.model_dump(mode="json")
                    if item.activation
                    else None,
                    "conditions": [
                        condition.model_dump(mode="json") for condition in item.discovery_conditions
                    ],
                }
                for item in inventory.endpoints
            ],
        }
    )
    engine_hash = _digest(
        {
            "backend": "mypy",
            "version": analyzer.resolver_version,
            "execution_summary_version": analyzer.EXECUTION_SUMMARY_VERSION,
            "typed_provider": (
                typed_build.report.cache_fingerprint if typed_build is not None else None
            ),
            "phase_bridge_schema": 3,
            "typed_source_capture": captured_sources.identity if captured_sources else None,
        }
    )
    config_hash = _digest(
        {
            "surface_contracts": contracts.config_hash,
            "provider_cache_fingerprint": (
                typed_build.report.cache_fingerprint if typed_build is not None else None
            ),
        }
    )
    constructor_evidence_by_endpoint: dict[int, ConstructorLifespanEvidence | None] = {}
    if typed_build is not None and provider_source_error is None and captured_sources is not None:
        evidence_by_binding: dict[tuple[object, ...], ConstructorLifespanEvidence | None] = {}
        endpoint_bindings: list[tuple[int, tuple[object, ...]]] = []
        for endpoint in inventory.endpoints:
            contract = _contract_for(endpoint, contracts) if endpoint.surface is not None else None
            if contract is not None and contract.id in {
                "fastapi-lifespan-startup",
                "fastapi-lifespan-shutdown",
            }:
                callback_symbol = _typed_callback_symbol(endpoint, typed_build)
                surface = endpoint.surface
                assert surface is not None
                binding_key = (
                    callback_symbol,
                    str(endpoint.handler.file_path.resolve()),
                )
                evidence = evidence_by_binding.get(binding_key)
                if evidence is None:
                    evidence = _constructor_lifespan_evidence(
                        endpoint,
                        typed_build,
                        analyzer.source_root,
                        callback_symbol,
                        captured_sources,
                    )
                    evidence_by_binding[binding_key] = evidence
                endpoint_bindings.append((id(endpoint), binding_key))
        constructor_evidence_by_endpoint.update(
            (endpoint_id, evidence_by_binding[binding_key])
            for endpoint_id, binding_key in endpoint_bindings
        )
    records: list[FrameworkPhaseRecord] = []
    limitations: set[str] = set()
    for endpoint in inventory.endpoints:
        phase = _phase(endpoint, contracts)
        if phase is None or endpoint.surface is None:
            continue
        surface_key = _surface_key(endpoint)
        if surface_key is None or selected_surface_counts[surface_key] <= 0:
            limitations.add(
                f"{endpoint.surface.contract_id}: supplied surface is not present in a fresh "
                "canonical source extraction"
            )
            continue
        selected_surface_counts[surface_key] -= 1
        contract = _contract_for(endpoint, contracts)
        reason: list[str] = []
        if provider_source_error:
            reason.append(provider_source_error)
        if contract is None:
            deps = None
            reason.append("selected surface contract is absent from loaded contract snapshot")
        elif contract.execution_mode != SurfaceExecutionMode.FRAMEWORK:
            deps = None
            reason.append("selected surface is not declared as framework execution")
        elif contract.callback_range != endpoint.surface.callback_range:
            deps = None
            reason.append("selected callback range does not match the loaded contract")
        else:
            deps = None
        if typed_build is None:
            reason.append("retained typed provider evidence is absent")
        sites: list[ResolvedCallSite] = []
        is_constructor_lifespan = contract is not None and contract.id in {
            "fastapi-lifespan-startup",
            "fastapi-lifespan-shutdown",
        }
        typed_callback = _typed_callback_symbol(endpoint, typed_build)
        constructor_evidence = constructor_evidence_by_endpoint.get(id(endpoint))
        if (
            contract is not None
            and contract.execution_mode == SurfaceExecutionMode.FRAMEWORK
            and (contract.callback_range == endpoint.surface.callback_range)
        ):
            deps = analyzer.analyze_endpoint(endpoint)
        sites = deps.resolved_call_sites if deps is not None else []
        typed_registration = (
            _typed_registration(endpoint, contract, sites, typed_build, analyzer.source_root)
            if contract is not None and typed_build is not None and not is_constructor_lifespan
            else None
        )
        if typed_registration is None and constructor_evidence is None:
            reason.append("no unique typed registration evidence matched the physical occurrence")
        callback_file_digest = (
            _captured_file_digest(endpoint.handler.file_path, captured_sources)
            if typed_build is not None
            else None
        )
        registration_file_digest = (
            _captured_file_digest(endpoint.surface.registration_file, captured_sources)
            if typed_build is not None
            else None
        )
        if callback_file_digest is None or registration_file_digest is None:
            reason.append("callback or registration file is absent from provider source inventory")
        conditions = _condition(endpoint, phase)
        if typed_callback is None:
            reason.append("selected callback does not resolve to one retained typed declaration")
        record = FrameworkPhaseRecord(
            phase=phase,
            callback=_callback_identity(endpoint, typed_callback),
            typed_callback_symbol=typed_callback,
            registration=(
                _registration_identity(endpoint, typed_registration[0])
                if typed_registration
                else SourceIdentity(
                    module=endpoint.handler.module,
                    symbol="FastAPI",
                    file=str(endpoint.surface.registration_file.resolve()),
                    line=constructor_evidence.constructor_line,
                    column=constructor_evidence.constructor_column,
                    end_line=constructor_evidence.constructor_end_line,
                    end_column=constructor_evidence.constructor_end_column,
                    source_sha256=endpoint.surface.registration_source_hash,
                )
                if constructor_evidence is not None
                else None
            ),
            typed_framework_symbol=(
                typed_registration[0].canonical_symbol if typed_registration else None
            ),
            registration_call_site=typed_registration[0] if typed_registration else None,
            constructor_lifespan=constructor_evidence,
            callback_file_sha256=callback_file_digest,
            registration_file_sha256=registration_file_digest,
            framework_declaration_sha256=(
                typed_registration[1]
                if typed_registration
                else constructor_evidence.constructor_file_sha256
                if constructor_evidence is not None
                else None
            ),
            canonical_contract_sha256=contracts.document.contract_hashes[
                endpoint.surface.contract_id
            ],
            typed_provider_fingerprint=(
                _digest(
                    {
                        "provider": typed_build.report.cache_fingerprint,
                        "source_capture": (captured_sources.identity if captured_sources else None),
                    }
                )
                if typed_build is not None
                else None
            ),
            contract_id=endpoint.surface.contract_id,
            resource=endpoint.surface.resource,
            snapshot_side=snapshot_side.value,
            callback_range=endpoint.surface.callback_range,
            execution_conditions=conditions,
            body_call_sites=tuple(sites),
            limitations=tuple(reason),
            source_sha256=source_hash,
            inventory_sha256=inventory_hash,
            engine_sha256=engine_hash,
            config_sha256=config_hash,
        )
        records.append(record)
        limitations.update(reason)

    lifecycle_surfaces_list: list[LifecycleConditionalSurface] = []
    for endpoint in inventory.endpoints:
        if endpoint.activation is None:
            continue
        activation_key = _activation_key(endpoint)
        if activation_key is None or selected_activation_counts[activation_key] <= 0:
            limitations.add(
                f"{endpoint.path}: lifecycle activation is not present in a fresh canonical "
                "source extraction"
            )
            continue
        selected_activation_counts[activation_key] -= 1
        lifecycle_surfaces_list.append(
            LifecycleConditionalSurface(
                surface_id=endpoint.path,
                lifecycle_surface_id=endpoint.activation.lifecycle_surface_id,
                registration_file=str(endpoint.activation.registration_file.resolve()),
                registration_line=endpoint.activation.registration_line,
                activation_file=str(endpoint.activation.activation_file.resolve()),
                activation_line=endpoint.activation.activation_line,
                activation_source_sha256=endpoint.activation.activation_source_hash,
            )
        )
    lifecycle_surfaces = tuple(lifecycle_surfaces_list)
    limitations.update(f"inventory: {item.reason}" for item in inventory.limitations)
    return FrameworkPhaseIntegration(
        backend="mypy",
        backend_version=analyzer.resolver_version,
        snapshot_side=snapshot_side.value,
        records=tuple(records),
        lifecycle_conditional_surfaces=lifecycle_surfaces,
        limitations=tuple(sorted(limitations)),
    )
