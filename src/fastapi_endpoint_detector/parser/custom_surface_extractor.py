"""Execution-free discovery of data-declared custom application surfaces."""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from pathlib import Path

from fastapi_endpoint_detector.models.effect_contract import InvocationKind
from fastapi_endpoint_detector.models.endpoint import (
    Endpoint,
    EndpointDiscoveryCondition,
    EndpointDiscoveryStatus,
    EndpointInventory,
    EndpointMethod,
    HandlerInfo,
    InventoryStatus,
    RouteActivationEvidence,
    SurfaceRegistrationEvidence,
)
from fastapi_endpoint_detector.models.surface_contract import (
    CallbackMode,
    CallbackRangeMode,
    HandlerNameNormalization,
    HandlerSelectorKind,
    LoadedSurfaceContracts,
    ResourceSelectorKind,
    SurfaceContract,
    SurfaceMatchKind,
)


@dataclass(frozen=True)
class _Binding:
    kind: Literal["module", "symbol", "receiver", "function"]
    identity: str


@dataclass(frozen=True)
class _Module:
    name: str
    path: Path
    source: str
    tree: ast.Module


def merge_surface_inventory(
    native: EndpointInventory,
    custom: EndpointInventory,
) -> EndpointInventory:
    """Merge adapter inventories without weakening per-endpoint evidence."""
    endpoints = [*native.endpoints, *custom.endpoints]
    limitations = tuple(dict.fromkeys((*native.limitations, *custom.limitations)))
    if not limitations:
        status = InventoryStatus.ESTABLISHED
    elif endpoints:
        status = InventoryStatus.CONDITIONAL
    elif native.status == InventoryStatus.UNAVAILABLE:
        status = InventoryStatus.UNAVAILABLE
    else:
        status = InventoryStatus.CONDITIONAL
    return EndpointInventory(endpoints=endpoints, status=status, limitations=limitations)


class _StatementMutationVisitor(ast.NodeVisitor):
    """Collect calls/mutations without entering deferred callable or class bodies."""

    def __init__(self) -> None:
        self.calls: list[ast.Call] = []
        self.has_named_expression = False

    def visit_Call(self, node: ast.Call) -> None:
        self.calls.append(node)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.has_named_expression = True
        self.generic_visit(node)

    def visit_FunctionDef(self, _node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, _node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, _node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, _node: ast.Lambda) -> None:
        return


class _ClassAttributeMutationVisitor(ast.NodeVisitor):
    """Detect direct class-body rebinding without entering nested scopes."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.found = False

    def visit_Name(self, node: ast.Name) -> None:
        if node.id == self.name and isinstance(node.ctx, (ast.Store, ast.Del)):
            self.found = True

    def _visit_function_header(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        if node.name == self.name or node.decorator_list:
            self.found = True
        for decorator in node.decorator_list:
            self.visit(decorator)
        self.visit(node.args)
        if node.returns is not None:
            self.visit(node.returns)
        for type_parameter in getattr(node, "type_params", ()):
            self.visit(type_parameter)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function_header(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function_header(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.found = True
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for class_keyword in node.keywords:
            self.visit(class_keyword.value)
        for type_parameter in getattr(node, "type_params", ()):
            self.visit(type_parameter)

    def visit_Import(self, _node: ast.Import) -> None:
        self.found = True

    def visit_ImportFrom(self, _node: ast.ImportFrom) -> None:
        self.found = True

    def visit_Call(self, _node: ast.Call) -> None:
        self.found = True

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name == self.name:
            self.found = True
        self.generic_visit(node)

    def visit_MatchAs(self, node: ast.MatchAs) -> None:
        if node.name == self.name:
            self.found = True
        self.generic_visit(node)

    def visit_MatchStar(self, node: ast.MatchStar) -> None:
        if node.name == self.name:
            self.found = True

    def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
        if node.rest == self.name:
            self.found = True
        self.generic_visit(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self.visit(node.args)


class _YieldVisitor(ast.NodeVisitor):
    """Detect yields in one callback body without entering nested callables."""

    def __init__(self, root: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.root = root
        self.found = False
        self.count = 0

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if node is self.root:
            self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        if node is self.root:
            self.generic_visit(node)

    def visit_Lambda(self, _node: ast.Lambda) -> None:
        return

    def visit_Yield(self, _node: ast.Yield) -> None:
        self.found = True
        self.count += 1

    def visit_YieldFrom(self, _node: ast.YieldFrom) -> None:
        self.found = True
        self.count += 1


class CustomSurfaceExtractorError(ValueError):
    """Raised when an explicit custom-surface root is invalid."""


class CustomSurfaceExtractor:
    """Match finite source registrations against strict data-only contracts."""

    MAX_RESOURCES_PER_REGISTRATION = 32

    def __init__(
        self,
        app_path: Path,
        contracts: LoadedSurfaceContracts,
        bootstrap_entry: str | None = None,
    ) -> None:
        self.app_path = app_path.resolve()
        self.contracts = contracts
        self.bootstrap_entry = bootstrap_entry
        self.root = self.app_path if self.app_path.is_dir() else self.app_path.parent
        self._modules: dict[str, _Module] = {}
        self._functions: dict[
            str, list[tuple[_Module, ast.FunctionDef | ast.AsyncFunctionDef]]
        ] = {}
        self._classes: dict[str, list[tuple[_Module, ast.ClassDef]]] = {}
        self._class_bases: dict[str, tuple[str, ...] | None] = {}
        self._endpoints: list[Endpoint] = []
        self._limitations: list[EndpointDiscoveryCondition] = []
        self._seen: set[tuple[str, int, int, str, str, str]] = set()
        self._startup_route_seen: set[tuple[str, int, str, tuple[EndpointMethod, ...], str]] = set()
        self._module_states: dict[str, dict[str, _Binding | None]] = {}
        self._building_states = False
        self._declared_receiver_types = {
            contract.registration.receiver_type
            for contract in contracts.document.contracts
            if contract.registration.receiver_type is not None
        }

    def extract_inventory(self) -> EndpointInventory:
        """Return all finite registrations and inventory-strength evidence."""
        self._load_modules()
        self._building_states = True
        try:
            for module in self._modules.values():
                state: dict[str, _Binding | None] = {}
                self._process_statements(
                    module,
                    module.tree.body,
                    state,
                    (),
                    process_functions=False,
                )
                self._module_states[module.name] = state
        finally:
            self._building_states = False
        for module in self._modules.values():
            self._process_statements(
                module,
                module.tree.body,
                {},
                (),
                process_functions=False,
            )
        self._process_bootstrap()
        collapsed: dict[tuple[str, str, int], Endpoint] = {}
        for endpoint in self._endpoints:
            key = (
                endpoint.identifier,
                str(endpoint.handler.file_path),
                endpoint.handler.line_number,
            )
            previous = collapsed.get(key)
            if previous is None or (
                previous.surface is not None
                and endpoint.surface is not None
                and previous.surface.match_kind == SurfaceMatchKind.WILDCARD
                and endpoint.surface.match_kind == SurfaceMatchKind.EXACT
            ):
                collapsed[key] = endpoint
        by_identifier: dict[str, list[Endpoint]] = {}
        for endpoint in collapsed.values():
            by_identifier.setdefault(endpoint.identifier, []).append(endpoint)
        normalized: list[Endpoint] = []
        for identifier, matches in by_identifier.items():
            if len(matches) == 1:
                normalized.extend(matches)
                continue
            for endpoint in matches:
                surface = endpoint.surface
                condition = EndpointDiscoveryCondition(
                    source_path=(
                        surface.registration_file
                        if surface is not None
                        else endpoint.handler.file_path
                    ),
                    source_line=(
                        surface.registration_line
                        if surface is not None
                        else endpoint.handler.line_number
                    ),
                    reason=f"custom surface identity {identifier!r} maps to multiple handlers",
                )
                normalized.append(
                    endpoint.model_copy(
                        update={
                            "discovery_status": EndpointDiscoveryStatus.CONDITIONAL,
                            "discovery_conditions": tuple(
                                dict.fromkeys((*endpoint.discovery_conditions, condition))
                            ),
                        }
                    )
                )
                self._limitations.append(condition)
        for endpoint in normalized:
            self._limitations.extend(endpoint.discovery_conditions)
        endpoints = sorted(
            normalized,
            key=lambda item: (
                item.identifier,
                str(item.handler.file_path),
                item.handler.line_number,
                item.surface.registration_line if item.surface else 0,
            ),
        )
        limitations = tuple(
            sorted(
                set(self._limitations),
                key=lambda item: (str(item.source_path), item.source_line, item.reason),
            )
        )
        return EndpointInventory(
            endpoints=endpoints,
            status=InventoryStatus.CONDITIONAL if limitations else InventoryStatus.ESTABLISHED,
            limitations=limitations,
        )

    def _process_bootstrap(self) -> None:
        if self.bootstrap_entry is None:
            return
        parts = self.bootstrap_entry.split(":")
        if (
            len(parts) != 2
            or not parts[0]
            or not parts[1]
            or any(not item.isidentifier() for item in parts[0].split("."))
            or not parts[1].isidentifier()
        ):
            raise CustomSurfaceExtractorError(
                "bootstrap_entry must use an exact project-local MODULE:FUNCTION"
            )
        module_name, function_name = parts
        module = self._modules.get(module_name)
        candidates = self._functions.get(f"{module_name}.{function_name}", [])
        if module is None or len(candidates) != 1:
            raise CustomSurfaceExtractorError(
                f"custom surface bootstrap {self.bootstrap_entry!r} is absent or ambiguous"
            )
        _handler_module, function = candidates[0]
        if isinstance(function, ast.AsyncFunctionDef) or function.decorator_list:
            raise CustomSurfaceExtractorError(
                "custom surface bootstrap must be synchronous and undecorated"
            )
        state = dict(self._module_states[module_name])
        for argument in [
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        ]:
            state[argument.arg] = None
        self._process_statements(
            module,
            function.body,
            state,
            (),
            process_functions=False,
        )

    def _load_modules(self) -> None:
        paths = [self.app_path] if self.app_path.is_file() else sorted(self.root.rglob("*.py"))
        for path in paths:
            try:
                source = path.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(path))
            except (OSError, SyntaxError, UnicodeError) as exc:
                self._limitations.append(
                    EndpointDiscoveryCondition(
                        source_path=path,
                        source_line=max(getattr(exc, "lineno", 1) or 1, 1),
                        reason="custom surface inventory omitted an unparseable Python module",
                    )
                )
                continue
            relative = path.relative_to(self.root).with_suffix("")
            parts = list(relative.parts)
            if parts and parts[-1] == "__init__":
                parts.pop()
            name = ".".join(parts) or path.parent.name
            module = _Module(name=name, path=path.resolve(), source=source, tree=tree)
            self._modules[name] = module
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self._functions.setdefault(f"{name}.{node.name}", []).append((module, node))
                elif isinstance(node, ast.ClassDef):
                    self._classes.setdefault(f"{name}.{node.name}", []).append((module, node))

    def _process_statements(  # noqa: PLR0912, PLR0915
        self,
        module: _Module,
        statements: list[ast.stmt],
        state: dict[str, _Binding | None],
        inherited_conditions: tuple[EndpointDiscoveryCondition, ...],
        *,
        process_functions: bool,
    ) -> None:
        for statement in statements:
            if isinstance(statement, ast.Import):
                for alias in statement.names:
                    state[alias.asname or alias.name.split(".")[0]] = _Binding("module", alias.name)
                continue
            if isinstance(statement, ast.ImportFrom):
                imported = self._resolve_import(module.name, statement.module, statement.level)
                for alias in statement.names:
                    if alias.name == "*":
                        continue
                    state[alias.asname or alias.name] = _Binding(
                        "symbol", f"{imported}.{alias.name}" if imported else alias.name
                    )
                continue
            if isinstance(statement, ast.ClassDef):
                identity = f"{module.name}.{statement.name}"
                if self._building_states:
                    bases = tuple(
                        self._direct_symbol_identity(base, state) or "" for base in statement.bases
                    )
                    self._class_bases[identity] = bases if all(bases) else None
                state[statement.name] = _Binding("symbol", identity)
                continue
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in statement.decorator_list:
                    registration = self._decorator_call(decorator)
                    if registration is not None:
                        self._inspect_registration(
                            module,
                            registration,
                            state,
                            inherited_conditions,
                            decorated_handler=statement,
                        )
                identity = f"{module.name}.{statement.name}"
                state[statement.name] = _Binding("function", identity)
                local = dict(state)
                for argument in [
                    *statement.args.posonlyargs,
                    *statement.args.args,
                    *statement.args.kwonlyargs,
                ]:
                    local[argument.arg] = None
                # Function bodies are deferred; only an explicit bootstrap body is walked.
                continue
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = statement.value
                if isinstance(value, ast.Call):
                    self._inspect_registration(
                        module, value, state, inherited_conditions, decorated_handler=None
                    )
                binding = self._binding_from_expression(value, state)
                targets = (
                    statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                )
                for target in targets:
                    if isinstance(target, ast.Name):
                        state[target.id] = binding
                    else:
                        state.clear()
                continue
            if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
                self._inspect_registration(
                    module,
                    statement.value,
                    state,
                    inherited_conditions,
                    decorated_handler=None,
                )
                continue
            if isinstance(statement, (ast.AugAssign, ast.Delete)):
                state.clear()
                continue
            if isinstance(statement, ast.If):
                condition = EndpointDiscoveryCondition(
                    source_path=module.path,
                    source_line=statement.lineno,
                    reason="custom surface registration is guarded by source control flow",
                )
                branch_conditions = (*inherited_conditions, condition)
                self._process_statements(
                    module,
                    statement.body,
                    dict(state),
                    branch_conditions,
                    process_functions=process_functions,
                )
                self._process_statements(
                    module,
                    statement.orelse,
                    dict(state),
                    branch_conditions,
                    process_functions=process_functions,
                )
                state.clear()
                continue
            if isinstance(
                statement, (ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith)
            ):
                condition = EndpointDiscoveryCondition(
                    source_path=module.path,
                    source_line=statement.lineno,
                    reason="custom surface registration appears in unsupported control flow",
                )
                bodies: list[list[ast.stmt]] = []
                for attribute in ("body", "orelse", "finalbody"):
                    body = getattr(statement, attribute, None)
                    if body:
                        bodies.append(body)
                for body in bodies:
                    self._process_statements(
                        module,
                        body,
                        {},
                        (*inherited_conditions, condition),
                        process_functions=process_functions,
                    )
                state.clear()
                continue
            # Unknown mutation/call shapes invalidate finite receiver and callback bindings.
            mutation = _StatementMutationVisitor()
            mutation.visit(statement)
            for call in mutation.calls:
                self._inspect_registration(
                    module,
                    call,
                    state,
                    inherited_conditions,
                    decorated_handler=None,
                )
            if mutation.calls or mutation.has_named_expression:
                state.clear()

    @staticmethod
    def _decorator_call(decorator: ast.expr) -> ast.Call | None:
        """Normalize bare and called decorators without evaluating expressions."""
        if isinstance(decorator, ast.Call):
            return decorator
        if isinstance(decorator, (ast.Name, ast.Attribute)):
            return ast.copy_location(
                ast.Call(func=decorator, args=[], keywords=[]),
                decorator,
            )
        return None

    def _inspect_registration(  # noqa: PLR0912, PLR0915
        self,
        module: _Module,
        call: ast.Call,
        state: dict[str, _Binding | None],
        inherited_conditions: tuple[EndpointDiscoveryCondition, ...],
        *,
        decorated_handler: ast.FunctionDef | ast.AsyncFunctionDef | None,
    ) -> None:
        if self._building_states:
            return
        resolved = self._resolve_call(call.func, state)
        if resolved is None:
            callable_name = (
                call.func.id
                if isinstance(call.func, ast.Name)
                else call.func.attr
                if isinstance(call.func, ast.Attribute)
                else ""
            )
            if callable_name in {
                item.registration.symbol.rsplit(".", maxsplit=1)[-1]
                for item in self.contracts.document.contracts
            }:
                self._limitations.append(
                    EndpointDiscoveryCondition(
                        source_path=module.path,
                        source_line=call.lineno,
                        reason=(
                            "potential custom surface registration has unresolved "
                            f"callable identity: {callable_name}"
                        ),
                    )
                )
            return
        symbol, invocation, receiver_type = resolved
        for contract in self.contracts.document.contracts:
            if not self._matches(contract, symbol, invocation, receiver_type):
                continue
            handler_expression: ast.expr | None = None
            if contract.handler.kind == HandlerSelectorKind.DECORATED_FUNCTION:
                handler_result = (
                    (module, decorated_handler) if decorated_handler is not None else None
                )
            else:
                handler_result = None
                if contract.handler.kind in {
                    HandlerSelectorKind.ARGUMENT,
                    HandlerSelectorKind.ARGUMENT_CLASS_METHOD,
                }:
                    index = contract.handler.index or 0
                    if index < len(call.args):
                        handler_expression = call.args[index]
                else:
                    handler_expression = next(
                        (item.value for item in call.keywords if item.arg == contract.handler.name),
                        None,
                    )
                if handler_expression is not None:
                    if contract.handler.kind == HandlerSelectorKind.ARGUMENT_CLASS_METHOD:
                        handler_result = self._resolve_class_method(
                            handler_expression,
                            state,
                            contract.handler.name or "",
                            contract.handler.base or "",
                        )
                    else:
                        handler_result = self._resolve_handler(handler_expression, state)
                elif contract.handler_optional:
                    continue
            if handler_result is None or not self._callback_matches(
                contract.callback_mode, handler_result[1]
            ):
                self._limitations.append(
                    EndpointDiscoveryCondition(
                        source_path=module.path,
                        source_line=call.lineno,
                        reason=(
                            f"custom surface contract {contract.id!r} matched but "
                            "handler was unresolved"
                        ),
                    )
                )
                continue
            handler_module, function = handler_result
            handler_range = self._handler_range(contract.callback_range, function)
            if handler_range is None:
                self._limitations.append(
                    EndpointDiscoveryCondition(
                        source_path=handler_module.path,
                        source_line=function.lineno,
                        reason=(
                            f"custom surface contract {contract.id!r} requires one "
                            "unconditional top-level yield"
                        ),
                    )
                )
                continue
            resources = self._resources(contract, call, function)
            if resources is None:
                self._limitations.append(
                    EndpointDiscoveryCondition(
                        source_path=module.path,
                        source_line=call.lineno,
                        reason=(
                            f"custom surface contract {contract.id!r} matched but "
                            "resource set was not finite literal data"
                        ),
                    )
                )
                continue
            conditions = list(inherited_conditions)
            for declared in contract.conditions:
                conditions.append(
                    EndpointDiscoveryCondition(
                        source_path=module.path,
                        source_line=call.lineno,
                        reason=f"declared surface condition: {declared}",
                    )
                )
            if contract.registration.match_kind == SurfaceMatchKind.WILDCARD:
                conditions.append(
                    EndpointDiscoveryCondition(
                        source_path=module.path,
                        source_line=call.lineno,
                        reason=f"LOW-only wildcard surface match: {contract.registration.symbol}",
                    )
                )
            merged = tuple(dict.fromkeys(conditions))
            for resource in resources:
                surface_id = contract.surface.id_template.replace("{resource}", resource)
                key = (
                    str(module.path),
                    call.lineno,
                    call.col_offset,
                    contract.id,
                    handler_module.name,
                    resource,
                )
                if key in self._seen:
                    continue
                self._seen.add(key)
                evidence = SurfaceRegistrationEvidence(
                    schema_version=self.contracts.document.schema_version,
                    surface_kind=contract.surface.kind,
                    surface_id=surface_id,
                    resource=resource,
                    callback_mode=contract.callback_mode,
                    callback_range=contract.callback_range,
                    execution_mode=contract.execution_mode,
                    activates_routes=contract.activates_routes,
                    contract_id=contract.id,
                    match_kind=contract.registration.match_kind,
                    registration_symbol=symbol,
                    registration_file=module.path,
                    registration_line=call.lineno,
                    registration_column=call.col_offset,
                    registration_source_hash=self._source_hash(module, call),
                    handler_source_hash=self._source_hash(handler_module, function),
                    contract_source_path=str(self.contracts.source_path),
                    raw_hash=self.contracts.raw_hash,
                    config_hash=self.contracts.config_hash,
                    preset_hash=self.contracts.preset_hash,
                    contract_hash=self.contracts.contract_hashes[contract.id],
                    conditions=contract.conditions,
                )
                self._endpoints.append(
                    Endpoint(
                        path=surface_id,
                        methods=[EndpointMethod.CUSTOM],
                        handler=HandlerInfo(
                            name=function.name,
                            module=handler_module.name,
                            file_path=handler_module.path,
                            line_number=handler_range[0],
                            end_line_number=handler_range[1],
                        ),
                        discovery_status=(
                            EndpointDiscoveryStatus.CONDITIONAL
                            if merged
                            else EndpointDiscoveryStatus.ESTABLISHED
                        ),
                        discovery_conditions=merged,
                        surface=evidence,
                    )
                )
                if contract.activates_routes and resources == ("startup",):
                    self._emit_startup_routes(
                        contract,
                        call,
                        handler_module,
                        function,
                        handler_range,
                        merged,
                        evidence,
                        state,
                    )

    def _emit_startup_routes(  # noqa: PLR0912, PLR0915
        self,
        contract: SurfaceContract,
        registration_call: ast.Call,
        handler_module: _Module,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        handler_range: tuple[int, int],
        inherited_conditions: tuple[EndpointDiscoveryCondition, ...],
        lifecycle_evidence: SurfaceRegistrationEvidence,
        registration_state: dict[str, _Binding | None],
    ) -> None:
        """Emit only direct finite routes installed by one exact startup callback."""
        state = dict(self._module_states.get(handler_module.name, {}))
        arguments = [
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        ]
        for argument in arguments:
            state[argument.arg] = None
        expected_receiver_names: set[str] = set()
        if contract.registration.invocation == InvocationKind.CONSTRUCTOR and arguments:
            state[arguments[0].arg] = _Binding("receiver", contract.registration.symbol)
            expected_receiver_names.add(arguments[0].arg)
        elif isinstance(registration_call.func, ast.Attribute) and isinstance(
            registration_call.func.value, ast.Name
        ):
            receiver_name = registration_call.func.value.id
            receiver = registration_state.get(receiver_name)
            if receiver is not None and receiver.kind == "receiver":
                expected_receiver_names.add(receiver_name)

        supported = {
            "add_api_route",
            "add_route",
            "add_api_websocket_route",
            "add_websocket_route",
        }
        route_mutations = {*supported, "include_router", "include_routes", "mount"}
        start_line, end_line = handler_range
        for statement in function.body:
            if statement.lineno < start_line or statement.lineno > end_line:
                continue
            if isinstance(statement, (ast.Return, ast.Raise)):
                break
            direct_call = (
                statement.value
                if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call)
                else None
            )
            if (
                direct_call is not None
                and self._is_expected_route_call(
                    direct_call, expected_receiver_names, route_mutations
                )
                and not self._is_route_receiver_call(direct_call, state, route_mutations)
            ):
                self._record_startup_route_limitation(
                    handler_module,
                    statement.lineno,
                    "startup route receiver was rebound or became unresolved",
                )
                continue
            if direct_call is not None and self._is_route_receiver_call(
                direct_call, state, route_mutations
            ):
                assert isinstance(direct_call.func, ast.Attribute)
                operation = direct_call.func.attr
                if operation not in supported:
                    self._record_startup_route_limitation(
                        handler_module,
                        statement.lineno,
                        f"startup route mutation {operation!r} is not finitely modeled",
                    )
                    continue
                route = self._startup_route_from_call(
                    direct_call,
                    state,
                    operation,
                )
                if route is None:
                    self._record_startup_route_limitation(
                        handler_module,
                        statement.lineno,
                        "startup route registration has dynamic or unresolved arguments",
                    )
                    continue
                path, methods, route_handler = route
                condition = EndpointDiscoveryCondition(
                    source_path=handler_module.path,
                    source_line=statement.lineno,
                    reason="route is registered only if framework startup lifecycle executes",
                )
                conditions = tuple(dict.fromkeys((*inherited_conditions, condition)))
                key = (
                    str(handler_module.path),
                    statement.lineno,
                    path,
                    methods,
                    f"{route_handler[0].name}.{route_handler[1].name}",
                )
                if key in self._startup_route_seen:
                    continue
                self._startup_route_seen.add(key)
                route_module, route_function = route_handler
                self._endpoints.append(
                    Endpoint(
                        path=path,
                        methods=list(methods),
                        handler=HandlerInfo(
                            name=route_function.name,
                            module=route_module.name,
                            file_path=route_module.path,
                            line_number=route_function.lineno,
                            end_line_number=route_function.end_lineno,
                        ),
                        discovery_status=EndpointDiscoveryStatus.CONDITIONAL,
                        discovery_conditions=conditions,
                        activation=RouteActivationEvidence(
                            lifecycle_surface_id=lifecycle_evidence.surface_id,
                            contract_id=lifecycle_evidence.contract_id,
                            registration_file=lifecycle_evidence.registration_file,
                            registration_line=lifecycle_evidence.registration_line,
                            activation_file=handler_module.path,
                            activation_line=statement.lineno,
                            activation_source_hash=self._source_hash(handler_module, direct_call),
                            contract_source_path=lifecycle_evidence.contract_source_path,
                            raw_hash=lifecycle_evidence.raw_hash,
                            config_hash=lifecycle_evidence.config_hash,
                            preset_hash=lifecycle_evidence.preset_hash,
                            contract_hash=lifecycle_evidence.contract_hash,
                        ),
                    )
                )
                continue

            mutation = _StatementMutationVisitor()
            mutation.visit(statement)
            if any(
                self._is_expected_route_call(call, expected_receiver_names, route_mutations)
                and not self._is_route_receiver_call(call, state, route_mutations)
                for call in mutation.calls
            ):
                self._record_startup_route_limitation(
                    handler_module,
                    statement.lineno,
                    "startup route receiver was rebound or became unresolved",
                )
                continue
            if any(
                self._is_route_receiver_call(call, state, route_mutations)
                for call in mutation.calls
            ):
                self._record_startup_route_limitation(
                    handler_module,
                    statement.lineno,
                    "startup route registration appears in unsupported control flow or expression",
                )
                continue
            if self._statement_uses_startup_receiver(statement, state):
                self._record_startup_route_limitation(
                    handler_module,
                    statement.lineno,
                    "startup app receiver escapes through an unsupported expression",
                )

    @staticmethod
    def _is_expected_route_call(
        call: ast.Call, receiver_names: set[str], operations: set[str]
    ) -> bool:
        return (
            isinstance(call.func, ast.Attribute)
            and call.func.attr in operations
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id in receiver_names
        )

    def _statement_uses_startup_receiver(
        self, statement: ast.stmt, state: dict[str, _Binding | None]
    ) -> bool:
        for node in ast.walk(statement):
            if not isinstance(node, ast.Name):
                continue
            binding = state.get(node.id)
            if binding is None:
                continue
            binding = self._follow_project_binding(binding)
            if binding.kind == "receiver" and binding.identity in {
                "fastapi.FastAPI",
                "starlette.applications.Starlette",
            }:
                return True
        return False

    def _is_route_receiver_call(
        self,
        call: ast.Call,
        state: dict[str, _Binding | None],
        operations: set[str],
    ) -> bool:
        if (
            not isinstance(call.func, ast.Attribute)
            or call.func.attr not in operations
            or not isinstance(call.func.value, ast.Name)
        ):
            return False
        binding = state.get(call.func.value.id)
        if binding is None:
            return False
        binding = self._follow_project_binding(binding)
        return binding.kind == "receiver" and binding.identity in {
            "fastapi.FastAPI",
            "starlette.applications.Starlette",
        }

    def _startup_route_from_call(  # noqa: PLR0911
        self,
        call: ast.Call,
        state: dict[str, _Binding | None],
        operation: str,
    ) -> (
        tuple[
            str,
            tuple[EndpointMethod, ...],
            tuple[_Module, ast.FunctionDef | ast.AsyncFunctionDef],
        ]
        | None
    ):
        if any(isinstance(argument, ast.Starred) for argument in call.args) or any(
            keyword.arg is None for keyword in call.keywords
        ):
            return None

        def selected(index: int, name: str) -> ast.expr | None:
            if index < len(call.args):
                if any(keyword.arg == name for keyword in call.keywords):
                    return None
                return call.args[index]
            values = [keyword.value for keyword in call.keywords if keyword.arg == name]
            return values[0] if len(values) == 1 else None

        path_expression = selected(0, "path")
        handler_expression = selected(1, "endpoint")
        paths = self._literal_resources(path_expression)
        handler = (
            self._resolve_handler(handler_expression, state)
            if handler_expression is not None
            else None
        )
        if paths is None or len(paths) != 1 or handler is None:
            return None

        methods: tuple[EndpointMethod, ...]
        if operation in {"add_api_websocket_route", "add_websocket_route"}:
            methods = (EndpointMethod.WEBSOCKET,)
        else:
            method_values = [keyword.value for keyword in call.keywords if keyword.arg == "methods"]
            if len(method_values) > 1:
                return None
            methods_expression = method_values[0] if method_values else None
            if methods_expression is None:
                methods = (EndpointMethod.GET,)
            else:
                values = self._literal_resources(methods_expression)
                if values is None or not values:
                    return None
                try:
                    methods = tuple(
                        sorted(
                            {EndpointMethod(value.upper()) for value in values},
                            key=lambda item: item.value,
                        )
                    )
                except ValueError:
                    return None
                if EndpointMethod.CUSTOM in methods or EndpointMethod.WEBSOCKET in methods:
                    return None
        return paths[0], methods, handler

    def _record_startup_route_limitation(self, module: _Module, line: int, reason: str) -> None:
        self._limitations.append(
            EndpointDiscoveryCondition(
                source_path=module.path,
                source_line=line,
                reason=reason,
            )
        )

    def _matches(
        self,
        contract: SurfaceContract,
        symbol: str,
        invocation: InvocationKind,
        receiver_type: str | None,
    ) -> bool:
        matcher = contract.registration
        if invocation != matcher.invocation or receiver_type != matcher.receiver_type:
            return False
        pattern = matcher.symbol.split(".")
        actual = symbol.split(".")
        return len(pattern) == len(actual) and all(
            expected in ("*", found) for expected, found in zip(pattern, actual, strict=True)
        )

    def _resolve_call(  # noqa: PLR0911
        self, expression: ast.expr, state: dict[str, _Binding | None]
    ) -> tuple[str, InvocationKind, str | None] | None:
        if isinstance(expression, ast.Name):
            binding = state.get(expression.id)
            if binding is None or binding.kind == "module":
                return None
            constructor_symbols = {
                contract.registration.symbol
                for contract in self.contracts.document.contracts
                if contract.registration.invocation == InvocationKind.CONSTRUCTOR
            }
            invocation = (
                InvocationKind.CONSTRUCTOR
                if binding.identity in constructor_symbols
                else InvocationKind.FUNCTION
            )
            return binding.identity, invocation, None
        if not isinstance(expression, ast.Attribute) or not isinstance(expression.value, ast.Name):
            return None
        binding = state.get(expression.value.id)
        if binding is None:
            return None
        binding = self._follow_project_binding(binding)
        if binding.kind == "module":
            return f"{binding.identity}.{expression.attr}", InvocationKind.FUNCTION, None
        if binding.kind == "receiver":
            return (
                f"{binding.identity}.{expression.attr}",
                InvocationKind.INSTANCE_METHOD,
                binding.identity,
            )
        if binding.kind == "symbol":
            return (
                f"{binding.identity}.{expression.attr}",
                InvocationKind.CLASS_METHOD,
                binding.identity,
            )
        return None

    def _follow_project_binding(self, binding: _Binding) -> _Binding:
        """Follow exact project module-global aliases without factory guessing."""
        current = binding
        seen: set[tuple[str, str]] = set()
        for _depth in range(16):
            key = (current.kind, current.identity)
            if key in seen or current.kind != "symbol":
                return current
            seen.add(key)
            candidates = [
                module
                for module in self._module_states
                if current.identity.startswith(f"{module}.")
            ]
            if not candidates:
                return current
            longest = max(len(module) for module in candidates)
            selected = [module for module in candidates if len(module) == longest]
            if len(selected) != 1:
                return current
            module_name = selected[0]
            exported_name = current.identity[len(module_name) + 1 :]
            if "." in exported_name:
                return current
            replacement = self._module_states[module_name].get(exported_name)
            if replacement is None:
                return current
            current = replacement
        return current

    def _binding_from_expression(
        self, expression: ast.expr | None, state: dict[str, _Binding | None]
    ) -> _Binding | None:
        if isinstance(expression, ast.Name):
            return state.get(expression.id)
        if isinstance(expression, ast.Attribute) and isinstance(expression.value, ast.Name):
            owner = state.get(expression.value.id)
            if owner is not None and owner.kind == "module":
                return _Binding("symbol", f"{owner.identity}.{expression.attr}")
        if isinstance(expression, ast.Call):
            resolved = self._resolve_call(expression.func, state)
            if (
                resolved is not None
                and resolved[1] in {InvocationKind.FUNCTION, InvocationKind.CONSTRUCTOR}
                and resolved[0] in self._declared_receiver_types
            ):
                return _Binding("receiver", resolved[0])
        return None

    def _resolve_class_method(
        self,
        expression: ast.expr,
        state: dict[str, _Binding | None],
        method_name: str,
        required_base: str,
    ) -> tuple[_Module, ast.FunctionDef | ast.AsyncFunctionDef] | None:
        """Resolve one direct method on one exact local class with one exact base."""
        identity = self._symbol_identity(expression, state)
        candidates = self._classes.get(identity or "", [])
        if len(candidates) != 1 or self._class_bases.get(identity or "") != (required_base,):
            return None
        module, class_node = candidates[0]
        if class_node.decorator_list or class_node.keywords:
            return None
        methods = [
            item
            for item in class_node.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            and item.name == method_name
            and not item.decorator_list
        ]
        mutation = _ClassAttributeMutationVisitor(method_name)
        for item in class_node.body:
            if item not in methods:
                mutation.visit(item)
        if len(methods) != 1 or mutation.found:
            return None
        header_risk = _ClassAttributeMutationVisitor("__surface_dynamic_header__")
        header_risk._visit_function_header(methods[0])
        if header_risk.found:
            return None
        return module, methods[0]

    def _direct_symbol_identity(
        self, expression: ast.expr, state: dict[str, _Binding | None]
    ) -> str | None:
        binding: _Binding | None = None
        if isinstance(expression, ast.Name):
            binding = state.get(expression.id)
        elif isinstance(expression, ast.Attribute) and isinstance(expression.value, ast.Name):
            owner = state.get(expression.value.id)
            if owner is not None and owner.kind == "module":
                binding = _Binding("symbol", f"{owner.identity}.{expression.attr}")
        return binding.identity if binding is not None and binding.kind == "symbol" else None

    def _symbol_identity(  # noqa: PLR0911
        self, expression: ast.expr, state: dict[str, _Binding | None]
    ) -> str | None:
        identity = self._direct_symbol_identity(expression, state)
        if identity is None:
            return None
        current = _Binding("symbol", identity)
        seen: set[str] = set()
        for _depth in range(16):
            if current.identity in seen:
                return current.identity
            seen.add(current.identity)
            candidates = [
                module
                for module in self._module_states
                if current.identity.startswith(f"{module}.")
            ]
            if not candidates:
                return current.identity
            longest = max(len(module) for module in candidates)
            selected = [module for module in candidates if len(module) == longest]
            if len(selected) != 1:
                return None
            module_name = selected[0]
            exported_name = current.identity[len(module_name) + 1 :]
            if "." in exported_name:
                return None
            replacement = self._module_states[module_name].get(exported_name)
            if replacement is None or replacement.kind != "symbol":
                return None
            if replacement.identity == current.identity:
                return current.identity
            current = replacement
        return None

    def _resolve_handler(
        self, expression: ast.expr, state: dict[str, _Binding | None]
    ) -> tuple[_Module, ast.FunctionDef | ast.AsyncFunctionDef] | None:
        identity: str | None = None
        if isinstance(expression, ast.Name):
            binding = state.get(expression.id)
            if binding is not None and binding.kind in ("function", "symbol"):
                identity = binding.identity
        elif isinstance(expression, ast.Attribute) and isinstance(expression.value, ast.Name):
            owner = state.get(expression.value.id)
            if owner is not None and owner.kind == "module":
                identity = f"{owner.identity}.{expression.attr}"
        candidates = self._functions.get(identity or "", [])
        return candidates[0] if len(candidates) == 1 else None

    @staticmethod
    def _callback_matches(
        mode: CallbackMode, function: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> bool:
        is_async = isinstance(function, ast.AsyncFunctionDef)
        visitor = _YieldVisitor(function)
        visitor.visit(function)
        has_yield = visitor.found
        return (
            mode == CallbackMode.EITHER
            or (mode == CallbackMode.SYNC and not is_async and not has_yield)
            or (mode == CallbackMode.ASYNC and is_async and not has_yield)
            or (mode == CallbackMode.GENERATOR and not is_async and has_yield)
            or (mode == CallbackMode.ASYNC_GENERATOR and is_async and has_yield)
        )

    @staticmethod
    def _handler_range(
        mode: CallbackRangeMode,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> tuple[int, int] | None:
        if mode == CallbackRangeMode.FULL:
            return function.lineno, function.end_lineno or function.lineno
        direct_yields = [
            statement
            for statement in function.body
            if isinstance(statement, ast.Expr)
            and isinstance(statement.value, (ast.Yield, ast.YieldFrom))
        ]
        visitor = _YieldVisitor(function)
        visitor.visit(function)
        if len(direct_yields) != 1 or visitor.count != 1:
            return None
        boundary = direct_yields[0]
        if mode == CallbackRangeMode.BEFORE_YIELD:
            return function.lineno, boundary.end_lineno or boundary.lineno
        return boundary.lineno, function.end_lineno or boundary.lineno

    @classmethod
    def _resources(  # noqa: PLR0912
        cls,
        contract: SurfaceContract,
        call: ast.Call,
        handler: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> tuple[str, ...] | None:
        """Resolve one bounded literal resource set without widening dynamic values."""
        selector = contract.surface.resource
        values: tuple[str, ...]
        if selector.kind == ResourceSelectorKind.HANDLER_NAME:
            values = (cls._handler_resource(handler.name, selector.handler_name_normalization),)
        elif selector.kind == ResourceSelectorKind.LITERAL:
            if selector.value is None:
                return None
            values = (selector.value,)
        elif selector.kind == ResourceSelectorKind.ARGUMENTS:
            start = selector.index or 0
            selected = call.args[start:]
            groups = [cls._literal_resources(expression) for expression in selected]
            if not groups or any(group is None for group in groups):
                return None
            values = tuple(value for group in groups for value in group or ())
        elif selector.kind == ResourceSelectorKind.KEYWORD_OR_HANDLER_NAME:
            expression = next(
                (item.value for item in call.keywords if item.arg == selector.name),
                None,
            )
            if expression is None:
                values = (
                    cls._handler_resource(
                        handler.name,
                        selector.handler_name_normalization,
                    ),
                )
            else:
                resolved = cls._literal_resources(expression)
                if resolved is None:
                    return None
                values = resolved
        else:
            if selector.kind == ResourceSelectorKind.ARGUMENT:
                index = selector.index or 0
                selected_expression = call.args[index] if index < len(call.args) else None
            elif selector.kind == ResourceSelectorKind.ARGUMENT_OR_KEYWORD:
                index = selector.index or 0
                selected_expression = (
                    call.args[index]
                    if index < len(call.args)
                    else next(
                        (item.value for item in call.keywords if item.arg == selector.name),
                        None,
                    )
                )
            else:
                selected_expression = next(
                    (item.value for item in call.keywords if item.arg == selector.name),
                    None,
                )
            resolved = cls._literal_resources(selected_expression)
            if resolved is None:
                return None
            values = resolved
        normalized = tuple(
            sorted(
                {
                    value
                    for value in values
                    if value is not None and value.strip() and len(value) <= 256
                }
            )
        )
        if len(normalized) != len(set(values)) or not (
            1 <= len(normalized) <= cls.MAX_RESOURCES_PER_REGISTRATION
        ):
            return None
        return normalized

    @staticmethod
    def _handler_resource(name: str, normalization: HandlerNameNormalization) -> str:
        return (
            name.replace("_", "-") if normalization == HandlerNameNormalization.KEBAB_CASE else name
        )

    @classmethod
    def _literal_resources(cls, expression: ast.expr | None) -> tuple[str, ...] | None:
        if isinstance(expression, ast.Constant) and isinstance(expression.value, str):
            return (expression.value,)
        if isinstance(expression, (ast.List, ast.Tuple, ast.Set)):
            values: list[str] = []
            for item in expression.elts:
                resolved = cls._literal_resources(item)
                if resolved is None:
                    return None
                values.extend(resolved)
            return tuple(values)
        return None

    @staticmethod
    def _source_hash(module: _Module, node: ast.AST) -> str:
        segment = ast.get_source_segment(module.source, node) or ""
        payload = json.dumps(
            {
                "module": module.name,
                "start": [getattr(node, "lineno", 0), getattr(node, "col_offset", 0)],
                "end": [getattr(node, "end_lineno", 0), getattr(node, "end_col_offset", 0)],
                "source": segment,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return f"sha256:{hashlib.sha256(payload).hexdigest()}"

    @staticmethod
    def _resolve_import(current: str, module: str | None, level: int) -> str:
        if level == 0:
            return module or ""
        parts = current.split(".")
        base = parts[: max(len(parts) - level, 0)]
        if module:
            base.extend(module.split("."))
        return ".".join(base)
