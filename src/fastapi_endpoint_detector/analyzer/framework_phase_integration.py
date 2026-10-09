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
from typing import TYPE_CHECKING

from mypy.nodes import Decorator, FuncDef, TypeInfo
from pydantic import BaseModel, ConfigDict, Field, model_validator

from fastapi_endpoint_detector.analyzer.framework_phase_bridge import (
    FrameworkPhase,
    SourceIdentity,
    canonical_framework_phase,
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

if TYPE_CHECKING:
    from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
    from fastapi_endpoint_detector.analyzer.mypy_incremental import TypedBuild


class FrameworkPhaseRecord(BaseModel):
    """One selected surface's phase binding and typed callback-body evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    phase: FrameworkPhase
    callback: SourceIdentity
    typed_callback_symbol: str | None = None
    registration: SourceIdentity | None = None
    typed_framework_symbol: str | None = None
    registration_call_site: ResolvedCallSite | None = None
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
        return self

    @property
    def status(self) -> str:
        if (
            self.limitations
            or self.registration is None
            or self.registration_call_site is None
            or self.typed_callback_symbol is None
            or self.typed_framework_symbol is None
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


def _provider_file_digest(path: Path, typed_build: TypedBuild) -> str | None:
    resolved = path.resolve()
    for module, module_path in typed_build.module_paths.items():
        if Path(module_path).resolve() != resolved:
            continue
        return dict(typed_build.report.source_digests_after).get(module)
    return None


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


def _provider_source_snapshot(typed_build: TypedBuild | None) -> tuple[dict[str, str], str | None]:
    if typed_build is None:
        return {}, None
    digest_rows = dict(typed_build.report.source_digests_after)
    if not digest_rows:
        return digest_rows, "retained typed provider source snapshot is incomplete"
    for module, path in typed_build.module_paths.items():
        expected = digest_rows.get(module)
        if expected is None:
            return digest_rows, f"provider source digest is absent for module {module}"
        try:
            actual = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        except OSError:
            return digest_rows, f"provider source file is unreadable for module {module}"
        if actual != expected:
            return digest_rows, (
                f"provider source file changed after typed build for module {module}"
            )
    return digest_rows, None


def collect_framework_phase_evidence(  # noqa: PLR0912, PLR0915
    inventory: EndpointInventory,
    contracts: LoadedSurfaceContracts,
    analyzer: MypyAnalyzer,
    typed_build: TypedBuild | None,
    *,
    snapshot_side: SnapshotSide = SnapshotSide.TARGET,
) -> FrameworkPhaseIntegration:
    """Analyze selected lifecycle/middleware callbacks using bounded mypy APIs.

    For each selected contract, analyze only its source callback. The callback
    range comes from the validated contract, and no framework implementation
    body is followed. The physical registration must also occur as one exact
    mypy call site in that callback's typed source slice.
    """
    provider_sources, provider_source_error = _provider_source_snapshot(typed_build)
    canonical_inventory = CustomSurfaceExtractor(
        analyzer.source_root, contracts
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
            "phase_bridge_schema": 2,
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
            deps = analyzer.analyze_endpoint(endpoint)
        if typed_build is None:
            reason.append("retained typed provider evidence is absent")
        sites = deps.resolved_call_sites if deps is not None else []
        typed_registration = (
            _typed_registration(endpoint, contract, sites, typed_build, analyzer.source_root)
            if contract is not None and typed_build is not None
            else None
        )
        if typed_registration is None:
            reason.append(
                "no unique exact mypy call site matched the physical registration occurrence; "
                "registration form may lie outside callback scope"
            )
        callback_file_digest = (
            _provider_file_digest(endpoint.handler.file_path, typed_build)
            if typed_build is not None
            else None
        )
        registration_file_digest = (
            _provider_file_digest(endpoint.surface.registration_file, typed_build)
            if typed_build is not None
            else None
        )
        if callback_file_digest is None or registration_file_digest is None:
            reason.append("callback or registration file is absent from provider source inventory")
        conditions = _condition(endpoint, phase)
        typed_callback = _typed_callback_symbol(endpoint, typed_build)
        if typed_callback is None:
            reason.append("selected callback does not resolve to one retained typed declaration")
        record = FrameworkPhaseRecord(
            phase=phase,
            callback=_callback_identity(endpoint, typed_callback),
            typed_callback_symbol=typed_callback,
            registration=(
                _registration_identity(endpoint, typed_registration[0])
                if typed_registration
                else None
            ),
            typed_framework_symbol=(
                typed_registration[0].canonical_symbol if typed_registration else None
            ),
            registration_call_site=typed_registration[0] if typed_registration else None,
            callback_file_sha256=callback_file_digest,
            registration_file_sha256=registration_file_digest,
            framework_declaration_sha256=(typed_registration[1] if typed_registration else None),
            canonical_contract_sha256=contracts.document.contract_hashes[
                endpoint.surface.contract_id
            ],
            typed_provider_fingerprint=(
                typed_build.report.cache_fingerprint if typed_build is not None else None
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
