"""Execution-free discovery of data-declared custom application surfaces."""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

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
from fastapi_endpoint_detector.parser._static_evaluation import (
    MAX_CUSTOM_RESOURCE_CHARS,
    StaticEvaluationResult,
    StaticStringEvaluator,
)


@dataclass(frozen=True)
class _Binding:
    kind: Literal["module", "symbol", "receiver", "function"]
    identity: str
    instance_token: tuple[str, int, int] | None = None


@dataclass(frozen=True)
class _EvaluatedArgument:
    """Capture one call argument immediately after its evaluation."""

    expression: ast.expr
    state: dict[str, _Binding | None]
    binding: _Binding | None


@dataclass(frozen=True)
class _CallEvaluation:
    """Capture callable identity and per-argument binding states."""

    callable_state: dict[str, _Binding | None]
    callable_resolution: tuple[str, InvocationKind, str | None] | None
    positional: tuple[_EvaluatedArgument, ...]
    keywords: tuple[_EvaluatedArgument, ...]


@dataclass(frozen=True)
class _ResolvedResources:
    values: tuple[str, ...] | None
    reason: str


_FrameworkToken = tuple[str, int, int]


@dataclass(frozen=True)
class _FrameworkRegistrationEvent:
    token: _FrameworkToken
    endpoint: Endpoint


@dataclass(frozen=True)
class _FrameworkIncludeEvent:
    parent: _FrameworkToken
    child: _FrameworkToken | None
    condition: EndpointDiscoveryCondition | None


_FrameworkEvent = _FrameworkRegistrationEvent | _FrameworkIncludeEvent


@dataclass(frozen=True)
class _StartupRouteResult:
    route: (
        tuple[
            str,
            tuple[EndpointMethod, ...],
            tuple[_Module, ast.FunctionDef | ast.AsyncFunctionDef],
        ]
        | None
    )
    failure: str | None = None


def _resource_failure(result: StaticEvaluationResult, fallback: str) -> str:
    return fallback if result.failure == "unsupported" else result.reason


@dataclass
class _StartupScopeFrame:
    """Keep startup function-local and module-global bindings distinct."""

    local_state: dict[str, _Binding | None]
    global_state: dict[str, _Binding | None]
    local_names: frozenset[str]


_Fallthrough = Literal["always", "maybe", "never"]


@dataclass(frozen=True)
class _Module:
    name: str
    path: Path
    source: str
    tree: ast.Module
    postponed_annotations: bool


def _endpoint_sort_key(endpoint: Endpoint) -> tuple[str, str, int, str]:
    """Return a total canonical order for inventory merges."""
    return (
        endpoint.identifier,
        str(endpoint.handler.file_path),
        endpoint.handler.line_number,
        json.dumps(endpoint.model_dump(mode="json"), sort_keys=True, separators=(",", ":")),
    )


def merge_surface_inventory(
    native: EndpointInventory,
    custom: EndpointInventory,
) -> EndpointInventory:
    """Merge adapters and apply route-wide uncertainty to native route surfaces."""
    route_conditions = tuple(
        sorted(
            {*native.route_conditions, *custom.route_conditions},
            key=lambda item: (str(item.source_path), item.source_line, item.reason),
        )
    )
    endpoints: list[Endpoint] = []
    for endpoint in (*native.endpoints, *custom.endpoints):
        if endpoint.surface is None and route_conditions:
            endpoints.append(
                endpoint.model_copy(
                    update={
                        "discovery_status": EndpointDiscoveryStatus.CONDITIONAL,
                        "discovery_conditions": tuple(
                            dict.fromkeys((*endpoint.discovery_conditions, *route_conditions))
                        ),
                    }
                )
            )
        else:
            endpoints.append(endpoint)
    limitations = tuple(
        sorted(
            {*native.limitations, *custom.limitations, *route_conditions},
            key=lambda item: (str(item.source_path), item.source_line, item.reason),
        )
    )
    statuses = (native.status, custom.status)
    if endpoints:
        status = (
            InventoryStatus.ESTABLISHED
            if all(item == InventoryStatus.ESTABLISHED for item in statuses)
            else InventoryStatus.CONDITIONAL
        )
    elif InventoryStatus.UNAVAILABLE in statuses:
        status = InventoryStatus.UNAVAILABLE
    elif any(item == InventoryStatus.CONDITIONAL for item in statuses):
        status = InventoryStatus.CONDITIONAL
    else:
        status = InventoryStatus.ESTABLISHED
    return EndpointInventory(
        endpoints=sorted(endpoints, key=_endpoint_sort_key),
        status=status,
        limitations=limitations,
        route_conditions=route_conditions,
    )


def _target_names(target: ast.AST) -> set[str]:
    """Return names rebound by one assignment/delete target."""
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, ast.Starred):
        return _target_names(target.value)
    if isinstance(target, (ast.Tuple, ast.List)):
        return {name for item in target.elts for name in _target_names(item)}
    return set()


def _mutation_root_name(target: ast.AST) -> str | None:
    """Return the local name whose object an attribute/subscript target mutates."""
    root = target
    while isinstance(root, (ast.Attribute, ast.Subscript)):
        root = root.value
    if isinstance(root, ast.Name):
        return root.id
    if isinstance(root, ast.NamedExpr):
        return root.target.id
    return None


def _uses_future_annotations(tree: ast.Module) -> bool:
    """Return whether this module postpones annotation evaluation."""
    return any(
        isinstance(statement, ast.ImportFrom)
        and statement.module == "__future__"
        and any(alias.name == "annotations" for alias in statement.names)
        for statement in tree.body
    )


def _pattern_names(pattern: ast.pattern) -> set[str]:
    """Return names captured by a structural pattern."""
    if isinstance(pattern, ast.MatchAs):
        names = {pattern.name} if pattern.name is not None else set()
        if pattern.pattern is not None:
            names.update(_pattern_names(pattern.pattern))
        return names
    if isinstance(pattern, ast.MatchStar):
        return {pattern.name} if pattern.name is not None else set()
    if isinstance(pattern, ast.MatchMapping):
        names = {pattern.rest} if pattern.rest is not None else set()
        for child in pattern.patterns:
            names.update(_pattern_names(child))
        return names
    if isinstance(pattern, (ast.MatchSequence, ast.MatchOr)):
        return {name for child in pattern.patterns for name in _pattern_names(child)}
    if isinstance(pattern, ast.MatchClass):
        return {
            name
            for child in (*pattern.patterns, *pattern.kwd_patterns)
            for name in _pattern_names(child)
        }
    return set()


class _IterativeBinOpVisitor(ast.NodeVisitor):
    """Visit deeply associated binary-expression operands without Python recursion."""

    def visit_BinOp(self, node: ast.BinOp) -> None:
        pending: list[ast.expr] = [node]
        while pending:
            operand = pending.pop()
            if isinstance(operand, ast.BinOp):
                pending.append(operand.right)
                pending.append(operand.left)
            else:
                self.visit(operand)


class _StatementMutationVisitor(_IterativeBinOpVisitor):
    """Collect calls/mutations without entering deferred callable or class bodies."""

    def __init__(self) -> None:
        self.calls: list[ast.Call] = []
        self.named_expression_targets: set[str] = set()

    def visit_Call(self, node: ast.Call) -> None:
        self.calls.append(node)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.named_expression_targets.update(_target_names(node.target))
        self.generic_visit(node)

    def visit_FunctionDef(self, _node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, _node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, _node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, _node: ast.Lambda) -> None:
        return


class _LoopBreakVisitor(_IterativeBinOpVisitor):
    """Detect a break owned by the current loop, excluding nested scopes/loops."""

    def __init__(self) -> None:
        self.found = False

    def visit_Break(self, _node: ast.Break) -> None:
        self.found = True

    def visit_For(self, _node: ast.For) -> None:
        return

    def visit_AsyncFor(self, _node: ast.AsyncFor) -> None:
        return

    def visit_While(self, _node: ast.While) -> None:
        return

    def visit_FunctionDef(self, _node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, _node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, _node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, _node: ast.Lambda) -> None:
        return


class _EagerStateMutationVisitor(_IterativeBinOpVisitor):
    """Collect bindings that may change while directly executing statements."""

    def __init__(self) -> None:
        self.rebound_names: set[str] = set()
        self.mutated_roots: set[str] = set()

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.rebound_names.add(node.id)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            root = _mutation_root_name(node)
            if root is not None:
                self.mutated_roots.add(root)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            root = _mutation_root_name(node)
            if root is not None:
                self.mutated_roots.add(root)
        self.generic_visit(node)

    def _visit_function_header(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.rebound_names.add(node.name)
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
        self.rebound_names.add(node.name)
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword.value)
        for type_parameter in getattr(node, "type_params", ()):
            self.visit(type_parameter)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self.visit(node.args)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.rebound_names.add(alias.asname or alias.name.split(".")[0])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name != "*":
                self.rebound_names.add(alias.asname or alias.name)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name is not None:
            self.rebound_names.add(node.name)
        self.generic_visit(node)

    def visit_Match(self, node: ast.Match) -> None:
        for case in node.cases:
            self.rebound_names.update(_pattern_names(case.pattern))
        self.generic_visit(node)

    def _visit_comprehension(
        self,
        node: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp,
    ) -> None:
        for generator in node.generators:
            self.visit(generator.iter)
            for condition in generator.ifs:
                self.visit(condition)
        if isinstance(node, ast.DictComp):
            self.visit(node.key)
            self.visit(node.value)
        else:
            self.visit(node.elt)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(node)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension(node)


class _FunctionScopeBindingVisitor(_EagerStateMutationVisitor):
    """Collect whole-function locals and explicit scope declarations."""

    def __init__(self, root: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        super().__init__()
        self.root = root
        self.globals: set[str] = set()
        self.nonlocals: set[str] = set()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if node is self.root:
            for statement in node.body:
                self.visit(statement)
        else:
            self._visit_function_header(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        if node is self.root:
            for statement in node.body:
                self.visit(statement)
        else:
            self._visit_function_header(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        super().visit_ClassDef(node)

    def visit_Global(self, node: ast.Global) -> None:
        self.globals.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.nonlocals.update(node.names)


class _ClassScopeDeclarationVisitor(_IterativeBinOpVisitor):
    """Collect declarations owned by one class body, excluding nested scopes."""

    def __init__(self) -> None:
        self.globals: set[str] = set()
        self.nonlocals: set[str] = set()

    def visit_Global(self, node: ast.Global) -> None:
        self.globals.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.nonlocals.update(node.names)

    def visit_FunctionDef(self, _node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, _node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, _node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, _node: ast.Lambda) -> None:
        return


@dataclass
class _FunctionScopeFrame:
    """Track one selected function's local and module-global binding frames."""

    local_state: dict[str, _Binding | None]
    global_state: dict[str, _Binding | None]
    local_names: frozenset[str]


@dataclass
class _ClassScopeFrame:
    """Track one class namespace and its non-class lookup and target frames."""

    lookup_state: dict[str, _Binding | None]
    global_state: dict[str, _Binding | None]
    nonlocal_state: dict[str, _Binding | None]
    class_state: dict[str, _Binding | None]
    globals: frozenset[str]
    nonlocals: frozenset[str]
    local_names: set[str]


@dataclass(frozen=True)
class _StartupAssignmentEffect:
    targets: tuple[ast.expr, ...]
    value: ast.expr | None


@dataclass(frozen=True)
class _StartupReturnEffect:
    value: ast.expr


_StartupEffect = ast.Call | _StartupAssignmentEffect | _StartupReturnEffect


class _StartupStatementEffectsVisitor(_EagerStateMutationVisitor):
    """Collect eager statement effects in Python evaluation order."""

    def __init__(self) -> None:
        super().__init__()
        self.events: list[_StartupEffect] = []

    def visit_Call(self, node: ast.Call) -> None:
        self.generic_visit(node)
        self.events.append(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        self.visit(node.target)
        self.events.append(_StartupAssignmentEffect((node.target,), node.value))

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        for value in node.values:
            self.visit(value)
            truth = CustomSurfaceExtractor._literal_truth(value)
            if (isinstance(node.op, ast.And) and truth is False) or (
                isinstance(node.op, ast.Or) and truth is True
            ):
                return

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self.visit(node.test)
        truth = CustomSurfaceExtractor._literal_truth(node.test)
        if truth is None:
            self.visit(node.body)
            self.visit(node.orelse)
        else:
            self.visit(node.body if truth else node.orelse)

    def _visit_comprehension(
        self,
        node: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp,
    ) -> None:
        first = node.generators[0] if node.generators else None
        if first is not None and CustomSurfaceExtractor._literal_truth(first.iter) is False:
            self.visit(first.iter)
            return
        super()._visit_comprehension(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        for target in node.targets:
            self.visit(target)
        self.events.append(_StartupAssignmentEffect(tuple(node.targets), node.value))

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
        self.visit(node.target)
        if node.value is not None:
            self.events.append(_StartupAssignmentEffect((node.target,), node.value))

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.target)
        self.visit(node.value)
        self.events.append(_StartupAssignmentEffect((node.target,), node.value))

    def visit_Delete(self, node: ast.Delete) -> None:
        for target in node.targets:
            self.visit(target)
        self.events.append(_StartupAssignmentEffect(tuple(node.targets), None))

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is not None:
            self.visit(node.value)
            self.events.append(_StartupReturnEffect(node.value))


class _ClassAttributeMutationVisitor(_IterativeBinOpVisitor):
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


class _YieldVisitor(_IterativeBinOpVisitor):
    """Detect yields in one callback body without entering nested callables."""

    def __init__(self, root: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.root = root
        self.found = False
        self.count = 0

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if node is self.root:
            for statement in node.body:
                self.visit(statement)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        if node is self.root:
            for statement in node.body:
                self.visit(statement)

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
        *,
        app_variable: str = "app",
        app_entry: str | None = None,
    ) -> None:
        self.app_path = app_path.resolve()
        self.contracts = contracts
        self.bootstrap_entry = bootstrap_entry
        self.app_variable = app_variable
        self.app_entry = app_entry
        if self.app_path.is_dir():
            self.root = self.app_path
        elif self.app_path.is_file():
            self.root = self.app_path.parent
        else:
            self.root = self.app_path
        self._modules: dict[str, _Module] = {}
        self._functions: dict[
            str, list[tuple[_Module, ast.FunctionDef | ast.AsyncFunctionDef]]
        ] = {}
        self._classes: dict[str, list[tuple[_Module, ast.ClassDef]]] = {}
        self._class_bases: dict[str, tuple[str, ...] | None] = {}
        self._endpoints: list[Endpoint] = []
        self._limitations: list[EndpointDiscoveryCondition] = []
        self._route_conditions: list[EndpointDiscoveryCondition] = []
        self._seen: set[tuple[str, int, int, str, str, str]] = set()
        self._startup_route_seen: set[tuple[str, int, str, tuple[EndpointMethod, ...], str]] = set()
        self._module_states: dict[str, dict[str, _Binding | None]] = {}
        self._class_scope_frames: list[_ClassScopeFrame] = []
        self._function_scope_states: list[_FunctionScopeFrame] = []
        self._building_states = False
        self._inventory_unavailable = False
        self._framework_events: list[_FrameworkEvent] = []
        self._framework_selected_tokens: set[_FrameworkToken] = set()
        self._framework_root_condition: EndpointDiscoveryCondition | None = None
        self._framework_factory: tuple[_Module, ast.FunctionDef | ast.AsyncFunctionDef] | None = (
            None
        )
        self._scope_framework_surfaces = contracts.document.preset.id == "framework-callbacks"
        self._declared_receiver_types = {
            contract.registration.receiver_type
            for contract in contracts.document.contracts
            if contract.registration.receiver_type is not None
        }

    def extract_inventory(self) -> EndpointInventory:
        """Return all finite registrations and inventory-strength evidence."""
        self._load_modules()
        if self._inventory_unavailable:
            limitations = tuple(
                sorted(
                    set(self._limitations),
                    key=lambda item: (str(item.source_path), item.source_line, item.reason),
                )
            )
            return EndpointInventory(
                status=InventoryStatus.UNAVAILABLE,
                limitations=limitations,
                route_conditions=tuple(self._route_conditions),
            )
        self._building_states = True
        try:
            for module in self._modules.values():
                state: dict[str, _Binding | None] = {}
                self._process_statements(
                    module,
                    module.tree.body,
                    state,
                    (),
                    evaluate_variable_annotations=not module.postponed_annotations,
                )
                self._module_states[module.name] = state
        finally:
            self._building_states = False
        self._resolve_framework_root()
        for module in self._modules.values():
            self._process_statements(
                module,
                module.tree.body,
                {},
                (),
                evaluate_variable_annotations=not module.postponed_annotations,
            )
        self._process_app_factory()
        self._process_bootstrap()
        self._filter_framework_surfaces()
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
        route_conditions = tuple(
            sorted(
                set(self._route_conditions),
                key=lambda item: (str(item.source_path), item.source_line, item.reason),
            )
        )
        if route_conditions:
            normalized = [
                (
                    endpoint.model_copy(
                        update={
                            "discovery_status": EndpointDiscoveryStatus.CONDITIONAL,
                            "discovery_conditions": tuple(
                                dict.fromkeys((*endpoint.discovery_conditions, *route_conditions))
                            ),
                        }
                    )
                    if endpoint.surface is None
                    else endpoint
                )
                for endpoint in normalized
            ]
        for endpoint in normalized:
            self._limitations.extend(endpoint.discovery_conditions)
        endpoints = sorted(normalized, key=_endpoint_sort_key)
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
            route_conditions=route_conditions,
        )

    @staticmethod
    def _framework_receiver_token(binding: _Binding | None) -> _FrameworkToken | None:
        if binding is None or binding.kind != "receiver" or binding.instance_token is None:
            return None
        if binding.identity not in {
            "fastapi.FastAPI",
            "starlette.applications.Starlette",
            "fastapi.APIRouter",
        }:
            return None
        return binding.instance_token

    def _framework_condition(self, module: _Module, line: int, reason: str) -> None:
        condition = EndpointDiscoveryCondition(
            source_path=module.path,
            source_line=line,
            reason=reason,
        )
        self._framework_root_condition = condition

    def _resolve_framework_root(self) -> None:  # noqa: PLR0912
        """Resolve the exact selected application after source-ordered module binding."""
        if not self._scope_framework_surfaces:
            return
        candidates: list[tuple[_Module, str]] = []
        if self.app_entry is not None:
            parts = self.app_entry.split(":")
            if (
                len(parts) != 2
                or not parts[0]
                or not parts[1]
                or any(not item.isidentifier() for item in parts[0].split("."))
                or not parts[1].isidentifier()
            ):
                raise CustomSurfaceExtractorError(
                    "app_entry must use an exact project-local MODULE:SYMBOL"
                )
            module = self._modules.get(parts[0])
            if module is None:
                raise CustomSurfaceExtractorError(
                    f"custom surface app entry {self.app_entry!r} has no project module"
                )
            candidates.append((module, parts[1]))
        elif self.app_path.is_file():
            module = next(
                (item for item in self._modules.values() if item.path == self.app_path),
                None,
            )
            if module is not None:
                candidates.append((module, self.app_variable))
        else:
            candidates.extend((module, self.app_variable) for module in self._modules.values())

        selected: set[_FrameworkToken] = set()
        unresolved: list[tuple[_Module, str]] = []
        for module, symbol in candidates:
            binding = self._module_states.get(module.name, {}).get(symbol)
            if binding is not None:
                binding = self._follow_project_binding(binding)
            token = self._framework_receiver_token(binding)
            if (
                token is not None
                and binding is not None
                and binding.identity != "fastapi.APIRouter"
            ):
                selected.add(token)
                continue
            function_candidates = self._functions.get(f"{module.name}.{symbol}", [])
            if self.app_entry is not None and len(function_candidates) == 1:
                self._framework_factory = function_candidates[0]
                continue
            if self.app_entry is not None or binding is not None:
                unresolved.append((module, symbol))

        if len(selected) == 1:
            self._framework_selected_tokens = selected
            return
        if len(selected) > 1:
            module, _symbol = candidates[0]
            self._framework_condition(
                module,
                1,
                "selected framework application binding is ambiguous across project modules",
            )
            return
        if self._framework_factory is not None:
            return
        module, symbol = (
            unresolved or candidates or [(next(iter(self._modules.values())), self.app_variable)]
        )[0]
        rebound_lines: list[int] = []
        for statement in module.tree.body:
            visitor = _EagerStateMutationVisitor()
            visitor.visit(statement)
            if symbol in visitor.rebound_names:
                rebound_lines.append(statement.lineno)
        line = max(rebound_lines, default=1)
        self._framework_condition(
            module,
            line,
            "selected framework application binding is unresolved or was rebound",
        )

    def _process_app_factory(self) -> None:
        """Interpret one explicitly selected zero-argument factory and retain its return token."""
        if self._framework_factory is None:
            return
        module, function = self._framework_factory
        if isinstance(function, ast.AsyncFunctionDef) or function.decorator_list:
            raise CustomSurfaceExtractorError(
                "custom surface app factory must be synchronous and undecorated"
            )
        positional = [*function.args.posonlyargs, *function.args.args]
        if (
            len(positional) - len(function.args.defaults)
            or any(default is None for default in function.args.kw_defaults)
            or function.args.vararg is not None
            or function.args.kwarg is not None
        ):
            raise CustomSurfaceExtractorError(
                "custom surface app factory must be callable with zero arguments and not variadic"
            )
        returns = [item for item in function.body if isinstance(item, ast.Return)]
        if len(returns) != 1 or function.body[-1] is not returns[0] or returns[0].value is None:
            self._framework_condition(
                module,
                function.lineno,
                "selected framework app factory has unsupported return control flow",
            )
            return

        state = dict(self._module_states[module.name])
        scope = _FunctionScopeBindingVisitor(function)
        scope.visit(function)
        local_names = scope.rebound_names - scope.globals - scope.nonlocals
        for name in local_names:
            state[name] = None
        frame = _FunctionScopeFrame(
            local_state=state,
            global_state=self._module_states[module.name],
            local_names=frozenset(local_names),
        )
        self._function_scope_states.append(frame)
        try:
            self._process_statements(
                module,
                function.body,
                state,
                (),
                evaluate_variable_annotations=False,
            )
        finally:
            self._function_scope_states.pop()
        token = self._framework_receiver_token(
            self._binding_from_expression(returns[0].value, state, module.name)
        )
        if token is None:
            self._framework_condition(
                module,
                returns[0].lineno,
                "selected framework app factory return is unresolved or not an application",
            )
            return
        self._framework_selected_tokens = {token}

    @staticmethod
    def _is_framework_endpoint(endpoint: Endpoint) -> bool:
        return endpoint.surface is not None and endpoint.surface.surface_kind.startswith(
            "framework."
        )

    @staticmethod
    def _framework_include_ancestors(
        token: _FrameworkToken,
        included_by: dict[_FrameworkToken, set[_FrameworkToken]],
    ) -> tuple[_FrameworkToken, ...]:
        """Return prior include ancestors in deterministic, graph-bounded order."""
        ancestors: list[_FrameworkToken] = []
        seen = {token}
        pending = sorted(included_by.get(token, ()), reverse=True)
        while pending:
            ancestor = pending.pop()
            if ancestor in seen:
                continue
            seen.add(ancestor)
            ancestors.append(ancestor)
            pending.extend(sorted(included_by.get(ancestor, ()), reverse=True))
        return tuple(ancestors)

    def _filter_framework_surfaces(self) -> None:
        """Apply selected-app identity and APIRouter copy-at-include semantics."""
        if not self._scope_framework_surfaces:
            return
        live: dict[_FrameworkToken, list[Endpoint]] = {}
        conditions: dict[_FrameworkToken, list[EndpointDiscoveryCondition]] = {}
        included_by: dict[_FrameworkToken, set[_FrameworkToken]] = {}
        for event in self._framework_events:
            if isinstance(event, _FrameworkRegistrationEvent):
                live.setdefault(event.token, []).append(event.endpoint)
                surface = event.endpoint.surface
                if surface is not None:
                    condition = EndpointDiscoveryCondition(
                        source_path=surface.registration_file,
                        source_line=surface.registration_line,
                        reason=(
                            "router lifecycle registered after include_router has "
                            "runtime-version-dependent execution"
                        ),
                    )
                    for ancestor in self._framework_include_ancestors(event.token, included_by):
                        conditions.setdefault(ancestor, []).append(condition)
                continue
            if event.child is None:
                if event.condition is not None:
                    conditions.setdefault(event.parent, []).append(event.condition)
                    for ancestor in self._framework_include_ancestors(event.parent, included_by):
                        conditions.setdefault(ancestor, []).append(event.condition)
                continue
            live.setdefault(event.parent, []).extend(live.get(event.child, ()))
            conditions.setdefault(event.parent, []).extend(conditions.get(event.child, ()))
            included_by.setdefault(event.child, set()).add(event.parent)

        accepted = {
            id(endpoint)
            for token in self._framework_selected_tokens
            for endpoint in live.get(token, ())
        }
        self._endpoints = [
            endpoint
            for endpoint in self._endpoints
            if not self._is_framework_endpoint(endpoint) or id(endpoint) in accepted
        ]
        for token in self._framework_selected_tokens:
            self._limitations.extend(conditions.get(token, ()))
        if self._framework_root_condition is not None:
            self._limitations.append(self._framework_root_condition)

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
        yield_visitor = _YieldVisitor(function)
        yield_visitor.visit(function)
        if yield_visitor.found:
            raise CustomSurfaceExtractorError("custom surface bootstrap must not be a generator")
        positional = [*function.args.posonlyargs, *function.args.args]
        required_positional = len(positional) - len(function.args.defaults)
        required_keyword_only = any(default is None for default in function.args.kw_defaults)
        if (
            required_positional
            or required_keyword_only
            or function.args.vararg is not None
            or function.args.kwarg is not None
        ):
            raise CustomSurfaceExtractorError(
                "custom surface bootstrap must be callable with zero arguments "
                "and must not be variadic"
            )
        state = dict(self._module_states[module_name])
        for argument in [
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        ]:
            state[argument.arg] = None
        scope = _FunctionScopeBindingVisitor(function)
        scope.visit(function)
        local_names = scope.rebound_names - scope.globals - scope.nonlocals
        local_names.update(argument.arg for argument in positional)
        local_names.update(argument.arg for argument in function.args.kwonlyargs)
        self._function_scope_states.append(
            _FunctionScopeFrame(
                local_state=state,
                global_state=self._module_states[module_name],
                local_names=frozenset(local_names),
            )
        )
        try:
            self._process_statements(
                module,
                function.body,
                state,
                (),
                evaluate_variable_annotations=False,
            )
        finally:
            self._function_scope_states.pop()

    def _load_modules(self) -> None:
        if self.app_path.is_file():
            paths = [self.app_path]
        elif self.app_path.is_dir():
            paths = sorted(self.root.rglob("*.py"))
        else:
            self._inventory_unavailable = True
            self._limitations.append(
                EndpointDiscoveryCondition(
                    source_path=self.app_path,
                    source_line=1,
                    reason="custom surface root is missing or is not a file or directory",
                )
            )
            return
        for path in paths:
            try:
                source = path.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(path))
            except (OSError, RecursionError, SyntaxError, UnicodeError) as exc:
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
            module = _Module(
                name=name,
                path=path.resolve(),
                source=source,
                tree=tree,
                postponed_annotations=_uses_future_annotations(tree),
            )
            self._modules[name] = module
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self._functions.setdefault(f"{name}.{node.name}", []).append((module, node))
                elif isinstance(node, ast.ClassDef):
                    self._classes.setdefault(f"{name}.{node.name}", []).append((module, node))
        if not self._modules:
            self._inventory_unavailable = True
            self._limitations.append(
                EndpointDiscoveryCondition(
                    source_path=self.app_path,
                    source_line=1,
                    reason="custom surface root has no successfully parsed Python modules",
                )
            )

    def _process_statements(  # noqa: PLR0911, PLR0912, PLR0915
        self,
        module: _Module,
        statements: list[ast.stmt],
        state: dict[str, _Binding | None],
        inherited_conditions: tuple[EndpointDiscoveryCondition, ...],
        *,
        evaluate_variable_annotations: bool,
    ) -> _Fallthrough:
        current_conditions = inherited_conditions
        overall_flow: _Fallthrough = "always"
        for statement in statements:
            if isinstance(statement, (ast.Return, ast.Raise)):
                value = statement.value if isinstance(statement, ast.Return) else statement.exc
                if value is not None:
                    self._inspect_expression(module, value, state, current_conditions)
                if isinstance(statement, ast.Raise) and statement.cause is not None:
                    self._inspect_expression(module, statement.cause, state, current_conditions)
                return "never"
            if isinstance(statement, (ast.Break, ast.Continue)):
                return "never"
            if isinstance(statement, ast.Import):
                for alias in statement.names:
                    local_name = alias.asname or alias.name.split(".")[0]
                    identity = alias.name if alias.asname else alias.name.split(".")[0]
                    state[local_name] = _Binding("module", identity)
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
                class_flow = self._process_class_definition(
                    module,
                    statement,
                    state,
                    current_conditions,
                )
                if class_flow == "never":
                    return "never"
                if class_flow == "maybe":
                    current_conditions = (
                        *current_conditions,
                        self._control_flow_condition(module, statement.lineno),
                    )
                    overall_flow = "maybe"
                continue
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._process_function_definition(
                    module,
                    statement,
                    state,
                    current_conditions,
                )
                # Function bodies are deferred; only an explicit bootstrap body is walked.
                continue
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = statement.value
                if isinstance(statement, ast.AnnAssign) and value is None:
                    self._inspect_target_expression(
                        module, statement.target, state, current_conditions
                    )
                    if evaluate_variable_annotations:
                        self._inspect_expression(
                            module,
                            statement.annotation,
                            state,
                            current_conditions,
                        )
                    continue
                if value is not None:
                    self._inspect_expression(module, value, state, current_conditions)
                binding = self._binding_from_expression(value, state, module.name)
                targets = (
                    statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                )
                for target in targets:
                    self._inspect_target_expression(module, target, state, current_conditions)
                    names = _target_names(target)
                    for name in names:
                        state[name] = binding if isinstance(target, ast.Name) else None
                    self._invalidate_mutated_target(target, state)
                if isinstance(statement, ast.AnnAssign) and evaluate_variable_annotations:
                    self._inspect_expression(
                        module,
                        statement.annotation,
                        state,
                        current_conditions,
                    )
                continue
            if isinstance(statement, ast.Expr):
                self._inspect_expression(module, statement.value, state, current_conditions)
                continue
            if isinstance(statement, ast.AugAssign):
                self._inspect_target_expression(module, statement.target, state, current_conditions)
                self._inspect_expression(module, statement.value, state, current_conditions)
                for name in _target_names(statement.target):
                    state[name] = None
                self._invalidate_mutated_target(statement.target, state)
                continue
            if isinstance(statement, ast.Delete):
                for target in statement.targets:
                    self._inspect_target_expression(module, target, state, current_conditions)
                    for name in _target_names(target):
                        state[name] = None
                    self._invalidate_mutated_target(target, state)
                continue
            if isinstance(statement, ast.If):
                self._inspect_expression(module, statement.test, state, current_conditions)
                truth = self._literal_truth(statement.test)
                if truth is not None:
                    selected = statement.body if truth else statement.orelse
                    branch_flow = self._process_statements(
                        module,
                        selected,
                        state,
                        current_conditions,
                        evaluate_variable_annotations=evaluate_variable_annotations,
                    )
                else:
                    condition = self._control_flow_condition(module, statement.lineno)
                    branch_conditions = (*current_conditions, condition)
                    body_state = dict(state)
                    else_state = dict(state)
                    body_flow = self._process_statements(
                        module,
                        statement.body,
                        body_state,
                        branch_conditions,
                        evaluate_variable_annotations=evaluate_variable_annotations,
                    )
                    else_flow = self._process_statements(
                        module,
                        statement.orelse,
                        else_state,
                        branch_conditions,
                        evaluate_variable_annotations=evaluate_variable_annotations,
                    )
                    reachable = [
                        branch_state
                        for branch_state, flow in (
                            (body_state, body_flow),
                            (else_state, else_flow),
                        )
                        if flow != "never"
                    ]
                    if reachable:
                        self._replace_state(state, self._join_states(reachable))
                    branch_flow = self._branch_flow(body_flow, else_flow)
                if branch_flow == "never":
                    return "never"
                if branch_flow == "maybe":
                    current_conditions = (
                        *current_conditions,
                        self._control_flow_condition(module, statement.lineno),
                    )
                    overall_flow = "maybe"
                continue
            if isinstance(statement, ast.Match):
                self._inspect_expression(module, statement.subject, state, current_conditions)
                condition = self._control_flow_condition(module, statement.lineno)
                branch_conditions = (*current_conditions, condition)
                remaining_state = dict(state)
                outgoing: list[dict[str, _Binding | None]] = []
                body_flows: list[_Fallthrough] = []
                for case in statement.cases:
                    case_state = dict(remaining_state)
                    for name in _pattern_names(case.pattern):
                        case_state[name] = None
                    if case.guard is not None:
                        self._inspect_expression(module, case.guard, case_state, branch_conditions)
                        guard_truth = self._literal_truth(case.guard)
                    else:
                        guard_truth = True
                    body_state = dict(case_state)
                    if guard_truth is not False:
                        body_flow = self._process_statements(
                            module,
                            case.body,
                            body_state,
                            branch_conditions,
                            evaluate_variable_annotations=evaluate_variable_annotations,
                        )
                        body_flows.append(body_flow)
                        if body_flow != "never":
                            outgoing.append(body_state)
                    if guard_truth is not True:
                        remaining_state = self._join_states((remaining_state, case_state))
                # Do not prove pattern exhaustiveness in this bounded model.
                outgoing.append(remaining_state)
                self._replace_state(state, self._join_states(outgoing))
                if any(flow != "always" for flow in body_flows):
                    # The no-match/failed-guard path still reaches the next statement.
                    overall_flow = "maybe"
                    current_conditions = (*current_conditions, condition)
                continue
            if isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
                if isinstance(statement, (ast.For, ast.AsyncFor)):
                    self._inspect_expression(module, statement.iter, state, current_conditions)
                else:
                    self._inspect_expression(module, statement.test, state, current_conditions)
                branch_conditions = (
                    *current_conditions,
                    self._control_flow_condition(module, statement.lineno),
                )
                body_state = dict(state)
                if isinstance(statement, (ast.For, ast.AsyncFor)):
                    for name in _target_names(statement.target):
                        body_state[name] = None
                body_flow = self._process_statements(
                    module,
                    statement.body,
                    body_state,
                    branch_conditions,
                    evaluate_variable_annotations=evaluate_variable_annotations,
                )
                if isinstance(statement, ast.While) and self._literal_truth(statement.test) is True:
                    break_visitor = _LoopBreakVisitor()
                    for body_statement in statement.body:
                        break_visitor.visit(body_statement)
                    if not break_visitor.found:
                        return "never"
                loop_state = self._join_states((state, body_state))
                else_state = dict(loop_state)
                else_flow = self._process_statements(
                    module,
                    statement.orelse,
                    else_state,
                    branch_conditions,
                    evaluate_variable_annotations=evaluate_variable_annotations,
                )
                reachable = [loop_state]
                if else_flow != "never":
                    reachable.append(else_state)
                self._replace_state(state, self._join_states(reachable))
                if body_flow != "always" or else_flow != "always":
                    current_conditions = branch_conditions
                    overall_flow = "maybe"
                continue
            if isinstance(statement, (ast.With, ast.AsyncWith)):
                for item in statement.items:
                    self._inspect_expression(module, item.context_expr, state, current_conditions)
                body_state = dict(state)
                for item in statement.items:
                    if item.optional_vars is not None:
                        for name in _target_names(item.optional_vars):
                            body_state[name] = None
                condition = self._control_flow_condition(module, statement.lineno)
                branch_conditions = (*current_conditions, condition)
                body_flow = self._process_statements(
                    module,
                    statement.body,
                    body_state,
                    branch_conditions,
                    evaluate_variable_annotations=evaluate_variable_annotations,
                )
                if body_flow == "never":
                    return "never"
                self._replace_state(state, body_state)
                if body_flow == "maybe":
                    current_conditions = branch_conditions
                    overall_flow = "maybe"
                continue
            if isinstance(statement, ast.Try) or statement.__class__.__name__ == "TryStar":
                try_flow = self._process_try_statement(
                    module,
                    statement,
                    state,
                    current_conditions,
                    evaluate_variable_annotations=evaluate_variable_annotations,
                )
                if try_flow == "never":
                    return "never"
                if try_flow == "maybe":
                    current_conditions = (
                        *current_conditions,
                        self._control_flow_condition(module, statement.lineno),
                    )
                    overall_flow = "maybe"
                continue
            # Keep unknown eager shapes fail-closed without discarding unrelated bindings.
            mutation = _StatementMutationVisitor()
            mutation.visit(statement)
            fallback_conditions = (
                *current_conditions,
                self._control_flow_condition(module, statement.lineno),
            )
            for call in mutation.calls:
                self._inspect_registration(
                    module, call, state, fallback_conditions, decorated_handler=None
                )
            for name in mutation.named_expression_targets:
                state[name] = None
        return overall_flow

    def _process_function_definition(
        self,
        module: _Module,
        statement: ast.FunctionDef | ast.AsyncFunctionDef,
        state: dict[str, _Binding | None],
        inherited_conditions: tuple[EndpointDiscoveryCondition, ...],
    ) -> None:
        """Evaluate one function header in Python order without entering its body."""
        for decorator in statement.decorator_list:
            self._inspect_decorator_expression(
                module,
                decorator,
                state,
                inherited_conditions,
                decorated_handler=statement,
            )
        for expression in (*statement.args.defaults, *statement.args.kw_defaults):
            if expression is not None:
                self._inspect_expression(module, expression, state, inherited_conditions)
        if not module.postponed_annotations:
            for expression in self._function_annotation_expressions(statement):
                self._inspect_expression(module, expression, state, inherited_conditions)
        state[statement.name] = _Binding("function", f"{module.name}.{statement.name}")

    def _process_class_definition(  # noqa: PLR0912
        self,
        module: _Module,
        statement: ast.ClassDef,
        state: dict[str, _Binding | None],
        inherited_conditions: tuple[EndpointDiscoveryCondition, ...],
    ) -> _Fallthrough:
        """Evaluate one class definition while keeping its namespace isolated."""
        for decorator in statement.decorator_list:
            self._inspect_decorator_expression(
                module,
                decorator,
                state,
                inherited_conditions,
                decorated_handler=None,
            )

        resolved_bases: list[str] = []
        for base in statement.bases:
            resolved_bases.append(self._direct_symbol_identity(base, state) or "")
            self._inspect_expression(module, base, state, inherited_conditions)
        if self._building_states:
            identity = f"{module.name}.{statement.name}"
            bases = tuple(resolved_bases)
            self._class_bases[identity] = bases if all(bases) else None
        for keyword in statement.keywords:
            self._inspect_expression(module, keyword.value, state, inherited_conditions)

        declarations = _ClassScopeDeclarationVisitor()
        for body_statement in statement.body:
            declarations.visit(body_statement)
        globals_ = frozenset(declarations.globals)
        nonlocals = frozenset(declarations.nonlocals)

        if self._class_scope_frames:
            parent = self._class_scope_frames[-1]
            lookup_state = dict(parent.lookup_state)
            for name in parent.globals | parent.nonlocals:
                lookup_state[name] = state.get(name)
            global_state = parent.global_state
            nonlocal_state = parent.nonlocal_state
        elif self._function_scope_states:
            function_scope = self._function_scope_states[-1]
            nonlocal_state = function_scope.local_state
            global_state = function_scope.global_state
            lookup_state = dict(state)
        else:
            lookup_state = state
            global_state = state
            nonlocal_state = state

        class_state = dict(lookup_state)
        for name in globals_:
            class_state[name] = global_state.get(name)
        for name in nonlocals:
            class_state[name] = nonlocal_state.get(name)
        frame = _ClassScopeFrame(
            lookup_state=lookup_state,
            global_state=global_state,
            nonlocal_state=nonlocal_state,
            class_state=class_state,
            globals=globals_,
            nonlocals=nonlocals,
            local_names=set(),
        )
        self._class_scope_frames.append(frame)
        try:
            class_flow = self._process_class_body(
                module,
                statement.body,
                frame,
                inherited_conditions,
            )
        finally:
            self._class_scope_frames.pop()

        if self._class_scope_frames:
            parent = self._class_scope_frames[-1]
            for name in parent.globals:
                if name not in parent.local_names:
                    state[name] = parent.global_state.get(name)
            for name in parent.nonlocals:
                if name not in parent.local_names:
                    state[name] = parent.nonlocal_state.get(name)
        if class_flow != "never":
            state[statement.name] = _Binding("symbol", f"{module.name}.{statement.name}")
        return class_flow

    def _process_class_body(
        self,
        module: _Module,
        statements: list[ast.stmt],
        frame: _ClassScopeFrame,
        inherited_conditions: tuple[EndpointDiscoveryCondition, ...],
    ) -> _Fallthrough:
        """Execute a class body while synchronizing declared outer bindings."""
        current_conditions = inherited_conditions
        overall_flow: _Fallthrough = "always"
        for statement in statements:
            flow = self._process_statements(
                module,
                [statement],
                frame.class_state,
                current_conditions,
                evaluate_variable_annotations=not module.postponed_annotations,
            )
            frame.local_names = self._transfer_definite_class_locals(
                [statement], frame.local_names, frame.globals | frame.nonlocals
            )
            self._sync_class_outer_bindings(frame)
            if flow == "never":
                return "never"
            if flow == "maybe":
                current_conditions = (
                    *current_conditions,
                    self._control_flow_condition(module, statement.lineno),
                )
                overall_flow = "maybe"
        return overall_flow

    def _transfer_definite_class_locals(  # noqa: PLR0912, PLR0915
        self,
        statements: list[ast.stmt],
        initial: set[str],
        declared_outer: frozenset[str],
    ) -> set[str]:
        """Transfer names definitely present in a class namespace on fallthrough."""
        local_names = set(initial)
        for statement in statements:
            if isinstance(statement, ast.If):
                truth = self._literal_truth(statement.test)
                if truth is not None:
                    local_names = self._transfer_definite_class_locals(
                        statement.body if truth else statement.orelse,
                        local_names,
                        declared_outer,
                    )
                else:
                    body_names = self._transfer_definite_class_locals(
                        statement.body, local_names, declared_outer
                    )
                    else_names = self._transfer_definite_class_locals(
                        statement.orelse, local_names, declared_outer
                    )
                    local_names = body_names & else_names
                continue
            if isinstance(statement, ast.Match):
                branch_names = [set(local_names)]
                branch_names.extend(
                    self._transfer_definite_class_locals(case.body, local_names, declared_outer)
                    for case in statement.cases
                )
                local_names = set.intersection(*branch_names)
                continue
            if isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
                body_names = self._transfer_definite_class_locals(
                    statement.body, local_names, declared_outer
                )
                else_names = self._transfer_definite_class_locals(
                    statement.orelse, local_names, declared_outer
                )
                local_names &= body_names & else_names
                continue
            if isinstance(statement, (ast.With, ast.AsyncWith)):
                local_names = self._transfer_definite_class_locals(
                    statement.body, local_names, declared_outer
                )
                continue
            if isinstance(statement, (ast.Try,)) or statement.__class__.__name__ == "TryStar":
                paths = [set(local_names)]
                paths.append(
                    self._transfer_definite_class_locals(
                        getattr(statement, "body"),  # noqa: B009 - Try/TryStar compatibility
                        local_names,
                        declared_outer,
                    )
                )
                paths.extend(
                    self._transfer_definite_class_locals(handler.body, local_names, declared_outer)
                    for handler in getattr(statement, "handlers")  # noqa: B009
                )
                local_names = set.intersection(*paths)
                local_names = self._transfer_definite_class_locals(
                    getattr(statement, "finalbody"),  # noqa: B009 - Try/TryStar compatibility
                    local_names,
                    declared_outer,
                )
                continue

            if isinstance(statement, ast.Delete):
                for target in statement.targets:
                    local_names.difference_update(_target_names(target))
                continue
            if isinstance(statement, ast.Assign):
                for target in statement.targets:
                    local_names.update(_target_names(target) - declared_outer)
                continue
            if isinstance(statement, ast.AnnAssign):
                if statement.value is not None:
                    local_names.update(_target_names(statement.target) - declared_outer)
                continue
            if isinstance(statement, ast.AugAssign):
                local_names.update(_target_names(statement.target) - declared_outer)
                continue
            if isinstance(statement, (ast.Import, ast.ImportFrom)):
                visitor = _EagerStateMutationVisitor()
                visitor.visit(statement)
                local_names.update(visitor.rebound_names - declared_outer)
                continue
            if (
                isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and statement.name not in declared_outer
            ):
                local_names.add(statement.name)
        return local_names

    def _sync_class_outer_bindings(self, frame: _ClassScopeFrame) -> None:
        """Publish class global/nonlocal writes to their distinct target frames."""
        updates = {
            **{name: (frame.global_state, frame.class_state.get(name)) for name in frame.globals},
            **{
                name: (frame.nonlocal_state, frame.class_state.get(name))
                for name in frame.nonlocals
            },
        }
        for name, (target_state, binding) in updates.items():
            target_state[name] = binding
            frame.lookup_state[name] = binding
            if (
                name in frame.globals
                and self._function_scope_states
                and name not in self._function_scope_states[-1].local_names
            ):
                self._function_scope_states[-1].local_state[name] = binding
            for ancestor in self._class_scope_frames:
                if ancestor is frame:
                    continue
                if name in ancestor.local_names:
                    continue
                if name in ancestor.globals:
                    ancestor.class_state[name] = ancestor.global_state.get(name)
                elif name in ancestor.nonlocals:
                    ancestor.class_state[name] = ancestor.nonlocal_state.get(name)
                else:
                    ancestor.class_state[name] = binding
                    ancestor.lookup_state[name] = binding

    def _inspect_decorator_expression(
        self,
        module: _Module,
        decorator: ast.expr,
        state: dict[str, _Binding | None],
        inherited_conditions: tuple[EndpointDiscoveryCondition, ...],
        *,
        decorated_handler: ast.FunctionDef | ast.AsyncFunctionDef | None,
    ) -> None:
        """Inspect one decorator without revisiting its registration root."""
        registration = self._decorator_call(decorator)
        if registration is None:
            self._inspect_expression(module, decorator, state, inherited_conditions)
            return
        if isinstance(decorator, ast.Call):
            self._inspect_call_expression(
                module,
                decorator,
                state,
                inherited_conditions,
                decorated_handler=decorated_handler,
            )
            return

        if isinstance(decorator, ast.Attribute):
            self._inspect_expression(module, decorator.value, state, inherited_conditions)
        callable_state = dict(state)
        evaluation = _CallEvaluation(
            callable_state=callable_state,
            callable_resolution=self._resolve_call(registration.func, callable_state),
            positional=(),
            keywords=(),
        )
        self._inspect_registration(
            module,
            registration,
            state,
            inherited_conditions,
            decorated_handler=decorated_handler,
            evaluation=evaluation,
        )

    def _inspect_call_expression(
        self,
        module: _Module,
        call: ast.Call,
        state: dict[str, _Binding | None],
        inherited_conditions: tuple[EndpointDiscoveryCondition, ...],
        *,
        decorated_handler: ast.FunctionDef | ast.AsyncFunctionDef | None,
    ) -> None:
        """Evaluate a call in CPython AST order with per-argument captures."""
        self._inspect_expression(module, call.func, state, inherited_conditions)
        callable_state = dict(state)
        callable_resolution = self._resolve_call(call.func, callable_state)
        positional: list[_EvaluatedArgument] = []
        for argument in call.args:
            self._inspect_expression(module, argument, state, inherited_conditions)
            positional.append(
                _EvaluatedArgument(
                    expression=argument,
                    state=dict(state),
                    binding=self._binding_from_expression(argument, state, module.name),
                )
            )
        keywords: list[_EvaluatedArgument] = []
        for keyword in call.keywords:
            self._inspect_expression(module, keyword.value, state, inherited_conditions)
            keywords.append(
                _EvaluatedArgument(
                    expression=keyword.value,
                    state=dict(state),
                    binding=self._binding_from_expression(keyword.value, state, module.name),
                )
            )
        self._inspect_registration(
            module,
            call,
            state,
            inherited_conditions,
            decorated_handler=decorated_handler,
            evaluation=_CallEvaluation(
                callable_state=callable_state,
                callable_resolution=callable_resolution,
                positional=tuple(positional),
                keywords=tuple(keywords),
            ),
        )

    @staticmethod
    def _function_annotation_expressions(
        statement: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> tuple[ast.expr, ...]:
        """Return annotations in CPython compiler evaluation order, then the return."""
        expressions = [
            argument.annotation
            for argument in (*statement.args.args, *statement.args.posonlyargs)
            if argument.annotation is not None
        ]
        if statement.args.vararg is not None and statement.args.vararg.annotation is not None:
            expressions.append(statement.args.vararg.annotation)
        expressions.extend(
            argument.annotation
            for argument in statement.args.kwonlyargs
            if argument.annotation is not None
        )
        if statement.args.kwarg is not None and statement.args.kwarg.annotation is not None:
            expressions.append(statement.args.kwarg.annotation)
        if statement.returns is not None:
            expressions.append(statement.returns)
        return tuple(expressions)

    @staticmethod
    def _branch_flow(left: _Fallthrough, right: _Fallthrough) -> _Fallthrough:
        if left == right:
            return left
        return "maybe"

    @staticmethod
    def _replace_state(
        state: dict[str, _Binding | None], replacement: dict[str, _Binding | None]
    ) -> None:
        state.clear()
        state.update(replacement)

    @staticmethod
    def _join_states(
        states: tuple[dict[str, _Binding | None], ...] | list[dict[str, _Binding | None]],
    ) -> dict[str, _Binding | None]:
        if not states:
            return {}
        names = set().union(*(item.keys() for item in states))
        joined: dict[str, _Binding | None] = {}
        for name in sorted(names):
            values = [item.get(name) for item in states]
            if all(value == values[0] for value in values[1:]):
                joined[name] = values[0]
        return joined

    @staticmethod
    def _control_flow_condition(module: _Module, line: int) -> EndpointDiscoveryCondition:
        return EndpointDiscoveryCondition(
            source_path=module.path,
            source_line=line,
            reason="custom surface registration is guarded by source control flow",
        )

    def _process_try_statement(  # noqa: PLR0912
        self,
        module: _Module,
        statement: ast.stmt,
        state: dict[str, _Binding | None],
        inherited_conditions: tuple[EndpointDiscoveryCondition, ...],
        *,
        evaluate_variable_annotations: bool,
    ) -> _Fallthrough:
        conditions = (
            *inherited_conditions,
            self._control_flow_condition(module, statement.lineno),
        )
        entry_state = dict(state)
        try_state = dict(state)
        try_flow = self._process_statements(
            module,
            getattr(statement, "body"),  # noqa: B009 - Try/TryStar compatibility
            try_state,
            conditions,
            evaluate_variable_annotations=evaluate_variable_annotations,
        )
        outgoing: list[dict[str, _Binding | None]] = []
        flows: list[_Fallthrough] = [try_flow]
        if try_flow != "never":
            normal_state = dict(try_state)
            normal_flow = self._process_statements(
                module,
                getattr(statement, "orelse"),  # noqa: B009 - Try/TryStar compatibility
                normal_state,
                conditions,
                evaluate_variable_annotations=evaluate_variable_annotations,
            )
            flows.append(normal_flow)
            if normal_flow != "never":
                outgoing.append(normal_state)
        exceptional_state = self._join_states((entry_state, try_state))
        mutations = _EagerStateMutationVisitor()
        for try_statement in getattr(statement, "body"):  # noqa: B009
            mutations.visit(try_statement)
        for name in mutations.rebound_names:
            exceptional_state[name] = None
        for root_name in mutations.mutated_roots:
            self._invalidate_binding_aliases(root_name, exceptional_state)
        exceptional_states = [exceptional_state]
        for handler in getattr(statement, "handlers"):  # noqa: B009
            # An exception may be raised before or after any modeled try mutation.
            # TryStar handlers can also observe effects from earlier handlers.
            handler_state = self._join_states(exceptional_states)
            if handler.type is not None:
                self._inspect_expression(module, handler.type, handler_state, conditions)
            if handler.name is not None:
                handler_state[handler.name] = None
            handler_flow = self._process_statements(
                module,
                handler.body,
                handler_state,
                conditions,
                evaluate_variable_annotations=evaluate_variable_annotations,
            )
            if handler.name is not None:
                handler_state[handler.name] = None
            exceptional_states.append(handler_state)
            flows.append(handler_flow)
            if handler_flow != "never":
                outgoing.append(handler_state)
        finalbody = getattr(statement, "finalbody")  # noqa: B009
        if finalbody:
            # Normal/handled paths may leave finally. A still-propagating exception
            # executes finally for effects but never becomes ordinary fallthrough.
            finalized: list[dict[str, _Binding | None]] = []
            for outgoing_state in outgoing:
                final_state = dict(outgoing_state)
                final_flow = self._process_statements(
                    module,
                    finalbody,
                    final_state,
                    conditions,
                    evaluate_variable_annotations=evaluate_variable_annotations,
                )
                flows.append(final_flow)
                if final_flow != "never":
                    finalized.append(final_state)
            pending_state = self._join_states(exceptional_states)
            pending_flow = self._process_statements(
                module,
                finalbody,
                pending_state,
                conditions,
                evaluate_variable_annotations=evaluate_variable_annotations,
            )
            flows.append(pending_flow)
            outgoing = finalized
        if not outgoing:
            return "never"
        self._replace_state(state, self._join_states(outgoing))
        return "always" if all(flow == "always" for flow in flows) else "maybe"

    def _inspect_expression(  # noqa: PLR0911, PLR0912, PLR0915
        self,
        module: _Module,
        expression: ast.expr,
        state: dict[str, _Binding | None],
        inherited_conditions: tuple[EndpointDiscoveryCondition, ...],
    ) -> None:
        if isinstance(expression, ast.Lambda):
            return
        if isinstance(expression, ast.BinOp):
            pending: list[ast.expr] = [expression]
            while pending:
                operand = pending.pop()
                if isinstance(operand, ast.BinOp):
                    pending.append(operand.right)
                    pending.append(operand.left)
                else:
                    self._inspect_expression(module, operand, state, inherited_conditions)
            return
        if isinstance(expression, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            self._inspect_comprehension(module, expression, state, inherited_conditions)
            return
        if isinstance(expression, ast.NamedExpr):
            self._inspect_expression(module, expression.value, state, inherited_conditions)
            state[expression.target.id] = self._binding_from_expression(
                expression.value, state, module.name
            )
            return
        if isinstance(expression, ast.BoolOp):
            skipped: list[dict[str, _Binding | None]] = []
            conditional = False
            working = dict(state)
            for value in expression.values:
                conditions = inherited_conditions
                if conditional:
                    conditions = (
                        *conditions,
                        self._expression_condition(module, value.lineno),
                    )
                self._inspect_expression(module, value, working, conditions)
                truth = self._literal_truth(value)
                continues = (
                    truth
                    if isinstance(expression.op, ast.And)
                    else (None if truth is None else not truth)
                )
                if continues is False:
                    self._replace_state(state, self._join_states((*skipped, working)))
                    return
                if continues is None:
                    skipped.append(dict(working))
                    conditional = True
            self._replace_state(state, self._join_states((*skipped, working)))
            return
        if isinstance(expression, ast.IfExp):
            self._inspect_expression(module, expression.test, state, inherited_conditions)
            truth = self._literal_truth(expression.test)
            if truth is not None:
                selected = expression.body if truth else expression.orelse
                self._inspect_expression(module, selected, state, inherited_conditions)
                return
            conditions = (
                *inherited_conditions,
                self._expression_condition(module, expression.lineno),
            )
            body_state = dict(state)
            else_state = dict(state)
            self._inspect_expression(module, expression.body, body_state, conditions)
            self._inspect_expression(module, expression.orelse, else_state, conditions)
            self._replace_state(state, self._join_states((body_state, else_state)))
            return
        if isinstance(expression, ast.Compare):
            self._inspect_expression(module, expression.left, state, inherited_conditions)
            previous = expression.left
            conditional = False
            compare_skipped: list[dict[str, _Binding | None]] = []
            working = dict(state)
            for index, (operator, comparator) in enumerate(
                zip(expression.ops, expression.comparators, strict=True)
            ):
                conditions = inherited_conditions
                if conditional:
                    conditions = (
                        *conditions,
                        self._expression_condition(module, comparator.lineno),
                    )
                self._inspect_expression(module, comparator, working, conditions)
                comparison = self._literal_comparison(previous, operator, comparator)
                if comparison is False:
                    self._replace_state(state, self._join_states((*compare_skipped, working)))
                    return
                if comparison is None and index < len(expression.comparators) - 1:
                    compare_skipped.append(dict(working))
                    conditional = True
                previous = comparator
            self._replace_state(state, self._join_states((*compare_skipped, working)))
            return
        if isinstance(expression, ast.Call):
            self._inspect_call_expression(
                module,
                expression,
                state,
                inherited_conditions,
                decorated_handler=None,
            )
            return
        for child in ast.iter_child_nodes(expression):
            if isinstance(child, ast.expr):
                self._inspect_expression(module, child, state, inherited_conditions)
            elif isinstance(child, ast.keyword):
                self._inspect_expression(module, child.value, state, inherited_conditions)

    @staticmethod
    def _literal_truth(expression: ast.expr) -> bool | None:
        if isinstance(expression, ast.Constant):
            return bool(expression.value)
        if isinstance(expression, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
            elements = expression.keys if isinstance(expression, ast.Dict) else expression.elts
            if not elements:
                return False
        return None

    @staticmethod
    def _literal_comparison(  # noqa: PLR0911
        left: ast.expr, operator: ast.cmpop, right: ast.expr
    ) -> bool | None:
        if not isinstance(left, ast.Constant) or not isinstance(right, ast.Constant):
            return None
        if isinstance(operator, ast.Eq):
            return left.value == right.value
        if isinstance(operator, ast.NotEq):
            return left.value != right.value
        if isinstance(operator, ast.Is) and (left.value is None or right.value is None):
            return left.value is right.value
        if isinstance(operator, ast.IsNot) and (left.value is None or right.value is None):
            return left.value is not right.value
        left_value: Any = left.value
        right_value: Any = right.value
        try:
            if isinstance(operator, ast.Lt):
                return bool(left_value < right_value)
            if isinstance(operator, ast.LtE):
                return bool(left_value <= right_value)
            if isinstance(operator, ast.Gt):
                return bool(left_value > right_value)
            if isinstance(operator, ast.GtE):
                return bool(left_value >= right_value)
        except TypeError:
            return None
        return None

    @staticmethod
    def _expression_condition(module: _Module, line: int) -> EndpointDiscoveryCondition:
        return EndpointDiscoveryCondition(
            source_path=module.path,
            source_line=line,
            reason="custom surface registration is conditional on expression short-circuiting",
        )

    def _inspect_target_expression(
        self,
        module: _Module,
        target: ast.expr,
        state: dict[str, _Binding | None],
        inherited_conditions: tuple[EndpointDiscoveryCondition, ...],
    ) -> None:
        """Inspect eager evaluation needed to locate an assignment/delete target."""
        if isinstance(target, ast.Attribute):
            self._inspect_expression(module, target.value, state, inherited_conditions)
        elif isinstance(target, ast.Subscript):
            self._inspect_expression(module, target.value, state, inherited_conditions)
            self._inspect_expression(module, target.slice, state, inherited_conditions)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self._inspect_target_expression(module, item, state, inherited_conditions)
        elif isinstance(target, ast.Starred):
            self._inspect_target_expression(module, target.value, state, inherited_conditions)

    @staticmethod
    def _invalidate_aliases_for_binding(
        binding: _Binding | None,
        state: dict[str, _Binding | None],
    ) -> None:
        if binding is None:
            return
        for name, candidate in state.items():
            if candidate == binding:
                state[name] = None

    @classmethod
    def _invalidate_binding_aliases(
        cls,
        root_name: str,
        state: dict[str, _Binding | None],
    ) -> None:
        cls._invalidate_aliases_for_binding(state.get(root_name), state)

    def _invalidate_mutated_target(
        self,
        target: ast.expr,
        state: dict[str, _Binding | None],
    ) -> None:
        if not isinstance(target, (ast.Attribute, ast.Subscript)):
            return
        root_name = _mutation_root_name(target)
        if root_name is None:
            return
        binding = state.get(root_name)
        self._invalidate_aliases_for_binding(binding, state)
        if not self._class_scope_frames:
            return
        current = self._class_scope_frames[-1]
        self._invalidate_aliases_for_binding(binding, current.global_state)
        self._invalidate_aliases_for_binding(binding, current.nonlocal_state)
        self._invalidate_aliases_for_binding(binding, current.lookup_state)
        for frame in self._class_scope_frames:
            self._invalidate_aliases_for_binding(binding, frame.class_state)

    def _inspect_comprehension(
        self,
        module: _Module,
        expression: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp,
        state: dict[str, _Binding | None],
        inherited_conditions: tuple[EndpointDiscoveryCondition, ...],
    ) -> None:
        conditions = (
            *inherited_conditions,
            EndpointDiscoveryCondition(
                source_path=module.path,
                source_line=expression.lineno,
                reason="custom surface registration is conditional on comprehension iteration",
            ),
        )
        local = dict(
            self._class_scope_frames[-1].lookup_state if self._class_scope_frames else state
        )
        walrus = _StatementMutationVisitor()
        walrus.visit(expression)
        for index, generator in enumerate(expression.generators):
            # A class-body comprehension evaluates only its outermost iterable in
            # the class namespace; its implicit scope cannot resolve class locals.
            iteration_state = state if self._class_scope_frames and index == 0 else local
            self._inspect_expression(module, generator.iter, iteration_state, conditions)
            for name in _target_names(generator.target):
                local[name] = None
            for filter_expression in generator.ifs:
                self._inspect_expression(module, filter_expression, local, conditions)
        if isinstance(expression, ast.DictComp):
            self._inspect_expression(module, expression.key, local, conditions)
            self._inspect_expression(module, expression.value, local, conditions)
        else:
            self._inspect_expression(module, expression.elt, local, conditions)
        for name in walrus.named_expression_targets:
            assigned = local.get(name)
            if state.get(name) != assigned:
                state[name] = None

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

    def _resolve_captured_handler(
        self, capture: _EvaluatedArgument
    ) -> tuple[_Module, ast.FunctionDef | ast.AsyncFunctionDef] | None:
        resolved = self._resolve_handler(capture.expression, capture.state)
        if resolved is not None or capture.binding is None:
            return resolved
        name = ast.Name(id="__captured_handler__", ctx=ast.Load())
        return self._resolve_handler(name, {name.id: capture.binding})

    def _resolve_captured_class_method(
        self,
        capture: _EvaluatedArgument,
        registration_module: str,
        method_name: str,
        required_base: str,
    ) -> tuple[_Module, ast.FunctionDef | ast.AsyncFunctionDef] | None:
        if (
            capture.binding is not None
            and capture.binding.kind == "symbol"
            and capture.binding.identity.startswith(f"{registration_module}.")
        ):
            resolved = self._resolve_class_method_identity(
                capture.binding.identity,
                method_name,
                required_base,
            )
            if resolved is not None:
                return resolved
        resolved = self._resolve_class_method(
            capture.expression,
            capture.state,
            method_name,
            required_base,
        )
        if resolved is not None or capture.binding is None:
            return resolved
        name = ast.Name(id="__captured_class__", ctx=ast.Load())
        return self._resolve_class_method(
            name,
            {name.id: capture.binding},
            method_name,
            required_base,
        )

    def _framework_call_token(
        self,
        call: ast.Call,
        evaluation: _CallEvaluation | None,
        state: dict[str, _Binding | None],
    ) -> _FrameworkToken | None:
        if not isinstance(call.func, ast.Attribute):
            return None
        lookup = evaluation.callable_state if evaluation is not None else state
        return self._framework_receiver_token(self._expression_binding(call.func.value, lookup))

    def _record_framework_include(
        self,
        module: _Module,
        call: ast.Call,
        state: dict[str, _Binding | None],
        evaluation: _CallEvaluation | None,
    ) -> None:
        if not self._scope_framework_surfaces or not isinstance(call.func, ast.Attribute):
            return
        if call.func.attr != "include_router":
            return
        parent = self._framework_call_token(call, evaluation, state)
        if parent is None:
            return
        capture = (
            evaluation.positional[0] if evaluation is not None and evaluation.positional else None
        )
        if capture is None and evaluation is not None:
            capture = next(
                (
                    item
                    for keyword, item in zip(call.keywords, evaluation.keywords, strict=True)
                    if keyword.arg == "router"
                ),
                None,
            )
        child = self._framework_receiver_token(capture.binding if capture is not None else None)
        condition = None
        if child is None:
            condition = EndpointDiscoveryCondition(
                source_path=module.path,
                source_line=call.lineno,
                reason=(
                    "selected application include_router target is dynamic or unresolved; "
                    "framework surface inventory is incomplete"
                ),
            )
        self._framework_events.append(
            _FrameworkIncludeEvent(parent=parent, child=child, condition=condition)
        )

    def _record_framework_registration(
        self,
        module: _Module,
        call: ast.Call,
        state: dict[str, _Binding | None],
        evaluation: _CallEvaluation | None,
        endpoint: Endpoint,
    ) -> None:
        if not self._scope_framework_surfaces or not self._is_framework_endpoint(endpoint):
            return
        token = (
            self._framework_call_token(call, evaluation, state)
            if isinstance(call.func, ast.Attribute)
            else None
        )
        if (
            token is None
            and endpoint.surface is not None
            and endpoint.surface.registration_symbol
            in {
                "fastapi.FastAPI",
                "starlette.applications.Starlette",
            }
        ):
            token = (module.name, call.lineno, call.col_offset)
        if token is not None:
            self._framework_events.append(_FrameworkRegistrationEvent(token, endpoint))

    def _inspect_registration(  # noqa: PLR0912, PLR0915
        self,
        module: _Module,
        call: ast.Call,
        state: dict[str, _Binding | None],
        inherited_conditions: tuple[EndpointDiscoveryCondition, ...],
        *,
        decorated_handler: ast.FunctionDef | ast.AsyncFunctionDef | None,
        evaluation: _CallEvaluation | None = None,
    ) -> None:
        if self._building_states:
            return
        resolved = (
            evaluation.callable_resolution
            if evaluation is not None
            else self._resolve_call(call.func, state)
        )
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
        self._record_framework_include(module, call, state, evaluation)
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
                capture: _EvaluatedArgument | None = None
                if contract.handler.kind in {
                    HandlerSelectorKind.ARGUMENT,
                    HandlerSelectorKind.ARGUMENT_CLASS_METHOD,
                }:
                    index = contract.handler.index or 0
                    if index < len(call.args):
                        handler_expression = call.args[index]
                        if evaluation is not None and index < len(evaluation.positional):
                            capture = evaluation.positional[index]
                else:
                    keyword_index = next(
                        (
                            index
                            for index, item in enumerate(call.keywords)
                            if item.arg == contract.handler.name
                        ),
                        None,
                    )
                    if keyword_index is not None:
                        handler_expression = call.keywords[keyword_index].value
                        if evaluation is not None and keyword_index < len(evaluation.keywords):
                            capture = evaluation.keywords[keyword_index]
                if (
                    contract.handler_optional
                    and isinstance(handler_expression, ast.Constant)
                    and handler_expression.value is None
                ):
                    continue
                if handler_expression is not None and capture is not None:
                    if contract.handler.kind == HandlerSelectorKind.ARGUMENT_CLASS_METHOD:
                        handler_result = self._resolve_captured_class_method(
                            capture,
                            module.name,
                            contract.handler.name or "",
                            contract.handler.base or "",
                        )
                    else:
                        handler_result = self._resolve_captured_handler(capture)
                elif handler_expression is None and contract.handler_optional:
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
            resource_result = self._resources(contract, call, function)
            resources = resource_result.values
            if resources is None:
                self._limitations.append(
                    EndpointDiscoveryCondition(
                        source_path=module.path,
                        source_line=call.lineno,
                        reason=(
                            f"custom surface contract {contract.id!r} matched but "
                            f"{resource_result.reason}"
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
                endpoint = Endpoint(
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
                self._endpoints.append(endpoint)
                self._record_framework_registration(module, call, state, evaluation, endpoint)
                if contract.activates_routes and resources == ("startup",):
                    self._emit_startup_routes(
                        contract,
                        call,
                        handler_module,
                        function,
                        handler_range,
                        merged,
                        evidence,
                        evaluation.callable_state if evaluation is not None else None,
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
        registration_callable_state: dict[str, _Binding | None] | None,
    ) -> None:
        """Interpret exact, straight-line startup route effects in source order."""
        module_state = dict(self._module_states.get(handler_module.name, {}))
        state = dict(module_state)
        arguments = [
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        ]
        scope = _FunctionScopeBindingVisitor(function)
        scope.visit(function)
        local_names = scope.rebound_names - scope.globals - scope.nonlocals
        local_names.update(argument.arg for argument in arguments)
        for name in local_names:
            state[name] = None
        startup_scope = _StartupScopeFrame(
            local_state=state,
            global_state=module_state,
            local_names=frozenset(local_names),
        )

        selected: _Binding | None = None
        expected_receiver_names: set[str] = set()
        if contract.registration.invocation == InvocationKind.CONSTRUCTOR and arguments:
            registration_module = next(
                (
                    module.name
                    for module in self._modules.values()
                    if module.path == lifecycle_evidence.registration_file
                ),
                handler_module.name,
            )
            selected = _Binding(
                "receiver",
                contract.registration.symbol,
                (registration_module, registration_call.lineno, registration_call.col_offset),
            )
            state[arguments[0].arg] = selected
            expected_receiver_names.add(arguments[0].arg)
        elif (
            isinstance(registration_call.func, ast.Attribute)
            and registration_callable_state is not None
        ):
            selected = self._expression_binding(
                registration_call.func.value, registration_callable_state
            )
            if isinstance(registration_call.func.value, ast.Name):
                expected_receiver_names.add(registration_call.func.value.id)
        if selected is None or selected.kind != "receiver" or selected.instance_token is None:
            return
        selected_token = selected.instance_token

        tracked_scope = {
            name
            for name, binding in state.items()
            if self._binding_has_token(binding, selected_token)
        } | expected_receiver_names
        if (scope.globals | scope.nonlocals) & tracked_scope:
            self._record_startup_route_limitation(
                handler_module,
                function.lineno,
                "startup tracked state uses unsupported global or nonlocal binding",
            )
            return

        supported = {
            "add_api_route",
            "add_route",
            "add_api_websocket_route",
            "add_websocket_route",
        }
        additive = {*supported, "include_router", "include_routes", "mount"}
        disabled = False
        start_line, end_line = handler_range
        for statement in function.body:
            if statement.lineno < start_line or statement.lineno > end_line:
                continue
            if isinstance(statement, (ast.Return, ast.Raise)):
                value = statement.value if isinstance(statement, ast.Return) else statement.exc
                if value is not None:
                    effects = _StartupStatementEffectsVisitor()
                    effects.visit(value)
                    for event in effects.events:
                        if isinstance(event, ast.Call):
                            self._inspect_startup_call_effect(
                                event,
                                handler_module,
                                state,
                                selected_token,
                                supported,
                                additive,
                                expected_receiver_names,
                                inherited_conditions,
                                lifecycle_evidence,
                                direct_registration=False,
                                disabled=disabled,
                            )
                    if self._expression_escapes_exact_receiver(value, state, selected_token):
                        self._taint_startup_routes(
                            handler_module,
                            statement.lineno,
                            "exact startup app escapes from the lifecycle callback",
                            state,
                            selected_token,
                        )
                break
            if isinstance(statement, (ast.Global, ast.Nonlocal, ast.Pass)):
                continue
            if isinstance(statement, (ast.Import, ast.ImportFrom)):
                aliases = statement.names
                for alias in aliases:
                    if isinstance(statement, ast.Import) or alias.name != "*":
                        state[alias.asname or alias.name.split(".")[0]] = None
                continue
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                for expression in self._startup_definition_header_expressions(
                    handler_module, statement
                ):
                    self._apply_startup_header_expression(
                        expression,
                        handler_module,
                        state,
                        selected_token,
                        supported,
                        additive,
                        expected_receiver_names,
                        inherited_conditions,
                        lifecycle_evidence,
                        disabled,
                    )
                if isinstance(statement, ast.ClassDef):
                    disabled, class_flow = self._inspect_startup_class_body_effects(
                        statement,
                        handler_module,
                        state,
                        selected_token,
                        supported,
                        additive,
                        expected_receiver_names,
                        inherited_conditions,
                        lifecycle_evidence,
                        disabled,
                        scope=startup_scope,
                    )
                    if class_flow == "never":
                        break
                    if class_flow == "maybe":
                        disabled = True
                        self._record_startup_route_limitation(
                            handler_module,
                            statement.lineno,
                            "startup nested class body may not fall through",
                        )
                state[statement.name] = None
                continue
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = statement.value
                targets = tuple(
                    statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                )
                if isinstance(statement, ast.AnnAssign) and value is None:
                    effects = _StartupStatementEffectsVisitor()
                    effects.visit(statement.target)
                    for event in effects.events:
                        if isinstance(event, ast.Call):
                            self._inspect_startup_call_effect(
                                event,
                                handler_module,
                                state,
                                selected_token,
                                supported,
                                additive,
                                expected_receiver_names,
                                inherited_conditions,
                                lifecycle_evidence,
                                direct_registration=False,
                                disabled=disabled,
                            )
                    continue
                if value is not None:
                    effects = _StartupStatementEffectsVisitor()
                    effects.visit(value)
                    for event in effects.events:
                        if isinstance(event, ast.Call):
                            self._inspect_startup_call_effect(
                                event,
                                handler_module,
                                state,
                                selected_token,
                                supported,
                                additive,
                                expected_receiver_names,
                                inherited_conditions,
                                lifecycle_evidence,
                                direct_registration=False,
                                disabled=disabled,
                            )
                binding = self._binding_from_expression(value, state, handler_module.name)
                destructive_target = any(
                    self._startup_destructive_target(target, state, selected_token)
                    for target in targets
                )
                escapes = self._assignment_escapes_exact_receiver(
                    targets, value, binding, state, selected_token
                )
                if destructive_target:
                    self._taint_startup_routes(
                        handler_module,
                        statement.lineno,
                        "startup may replace or mutate the exact app router or route collection",
                        state,
                        selected_token,
                    )
                elif escapes:
                    self._taint_startup_routes(
                        handler_module,
                        statement.lineno,
                        "exact startup app escapes into an unresolved value",
                        state,
                        selected_token,
                    )
                for target in targets:
                    if self._startup_registration_target(target, state, selected_token, additive):
                        disabled = True
                        self._record_startup_route_limitation(
                            handler_module,
                            statement.lineno,
                            "startup route registration method is replaced",
                        )
                    for name in _target_names(target):
                        state[name] = binding if isinstance(target, ast.Name) else None
                        if self._binding_has_token(binding, selected_token):
                            expected_receiver_names.add(name)
                continue
            if isinstance(statement, ast.Delete):
                destructive = any(
                    self._startup_destructive_target(target, state, selected_token)
                    for target in statement.targets
                )
                if destructive:
                    self._taint_startup_routes(
                        handler_module,
                        statement.lineno,
                        "startup may delete from the exact app router or route collection",
                        state,
                        selected_token,
                    )
                for target in statement.targets:
                    if self._startup_registration_target(target, state, selected_token, additive):
                        disabled = True
                    for name in _target_names(target):
                        state[name] = None
                continue

            direct_call = (
                statement.value
                if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call)
                else None
            )
            if direct_call is not None:
                effects = _StartupStatementEffectsVisitor()
                effects.visit(direct_call)
                for event in effects.events:
                    if isinstance(event, ast.Call):
                        self._inspect_startup_call_effect(
                            event,
                            handler_module,
                            state,
                            selected_token,
                            supported,
                            additive,
                            expected_receiver_names,
                            inherited_conditions,
                            lifecycle_evidence,
                            direct_registration=event is direct_call,
                            disabled=disabled,
                        )
                continue

            effects = _StartupStatementEffectsVisitor()
            effects.visit(statement)
            for event in effects.events:
                if isinstance(event, ast.Call):
                    self._inspect_startup_call_effect(
                        event,
                        handler_module,
                        state,
                        selected_token,
                        supported,
                        additive,
                        expected_receiver_names,
                        inherited_conditions,
                        lifecycle_evidence,
                        direct_registration=False,
                        disabled=disabled,
                    )
                    continue
                if isinstance(event, _StartupReturnEffect):
                    if self._expression_escapes_exact_receiver(event.value, state, selected_token):
                        self._taint_startup_routes(
                            handler_module,
                            event.value.lineno,
                            "exact startup app escapes from the lifecycle callback",
                            state,
                            selected_token,
                        )
                    continue
                targets, value = event.targets, event.value
                if any(
                    self._startup_registration_target(target, state, selected_token, additive)
                    for target in targets
                ):
                    disabled = True
                    self._record_startup_route_limitation(
                        handler_module,
                        statement.lineno,
                        "startup route registration method is replaced",
                    )
                binding = self._binding_from_expression(value, state, handler_module.name)
                if any(
                    self._startup_destructive_target(target, state, selected_token)
                    for target in targets
                ):
                    self._taint_startup_routes(
                        handler_module,
                        statement.lineno,
                        "startup may replace, delete, or mutate the exact app router "
                        "or route collection",
                        state,
                        selected_token,
                    )
                elif value is not None and self._assignment_escapes_exact_receiver(
                    targets,
                    value,
                    binding,
                    state,
                    selected_token,
                ):
                    self._taint_startup_routes(
                        handler_module,
                        statement.lineno,
                        "exact startup app escapes into an unresolved value",
                        state,
                        selected_token,
                    )
                for target in targets:
                    for name in _target_names(target):
                        state[name] = binding if isinstance(target, ast.Name) else None
            # A compound statement may not execute, so no branch-local proof survives its join.
            for name in effects.rebound_names | effects.mutated_roots:
                state[name] = None

    def _apply_startup_header_expression(
        self,
        expression: ast.expr,
        module: _Module,
        state: dict[str, _Binding | None],
        token: tuple[str, int, int],
        supported: set[str],
        additive: set[str],
        expected_receiver_names: set[str],
        inherited_conditions: tuple[EndpointDiscoveryCondition, ...],
        lifecycle: SurfaceRegistrationEvidence,
        disabled: bool,
    ) -> None:
        """Apply source-ordered call and walrus effects from one eager header."""
        effects = _StartupStatementEffectsVisitor()
        effects.visit(expression)
        for event in effects.events:
            if isinstance(event, ast.Call):
                self._inspect_startup_call_effect(
                    event,
                    module,
                    state,
                    token,
                    supported,
                    additive,
                    expected_receiver_names,
                    inherited_conditions,
                    lifecycle,
                    direct_registration=False,
                    disabled=disabled,
                )
                continue
            if isinstance(event, _StartupReturnEffect):
                continue
            binding = self._binding_from_expression(event.value, state, module.name)
            for target in event.targets:
                for name in _target_names(target):
                    state[name] = binding if isinstance(target, ast.Name) else None
                    if self._binding_has_token(binding, token):
                        expected_receiver_names.add(name)
        if self._expression_escapes_exact_receiver(expression, state, token):
            self._taint_startup_routes(
                module,
                expression.lineno,
                "exact startup app escapes through an eager nested-definition header",
                state,
                token,
            )

    def _startup_possible_exact_join(
        self,
        states: tuple[dict[str, _Binding | None], ...],
        token: tuple[str, int, int],
    ) -> dict[str, _Binding | None]:
        joined: dict[str, _Binding | None] = {}
        for name in set().union(*(state.keys() for state in states)):
            binding = next(
                (
                    state.get(name)
                    for state in states
                    if self._binding_has_token(state.get(name), token)
                ),
                None,
            )
            if binding is not None:
                joined[name] = binding
        return joined

    def _inspect_startup_possible_expression(
        self,
        expression: ast.AST,
        possible_state: dict[str, _Binding | None],
        module: _Module,
        actual_state: dict[str, _Binding | None],
        token: tuple[str, int, int],
        supported: set[str],
        additive: set[str],
        expected_receiver_names: set[str],
        inherited_conditions: tuple[EndpointDiscoveryCondition, ...],
        lifecycle: SurfaceRegistrationEvidence,
        disabled: bool,
        ancestor_class_states: tuple[dict[str, _Binding | None], ...],
    ) -> dict[str, _Binding | None]:
        effects = _StartupStatementEffectsVisitor()
        effects.visit(expression)
        for event in effects.events:
            if isinstance(event, ast.Call):
                condition_count = len(self._route_conditions)
                self._inspect_startup_call_effect(
                    event,
                    module,
                    possible_state,
                    token,
                    supported,
                    additive,
                    expected_receiver_names,
                    inherited_conditions,
                    lifecycle,
                    direct_registration=False,
                    disabled=disabled,
                )
                if len(self._route_conditions) > condition_count and not any(
                    self._binding_has_token(binding, token) for binding in possible_state.values()
                ):
                    self._invalidate_token(actual_state, token)
                    for ancestor in ancestor_class_states:
                        self._invalidate_token(ancestor, token)
                continue
            if isinstance(event, _StartupReturnEffect):
                continue
            binding = self._binding_from_expression(event.value, possible_state, module.name)
            for target in event.targets:
                for name in _target_names(target):
                    possible_state[name] = (
                        binding if self._binding_has_token(binding, token) else None
                    )
        return possible_state

    def _inspect_startup_possible_statements(
        self,
        statements: list[ast.stmt],
        possible_state: dict[str, _Binding | None],
        module: _Module,
        actual_state: dict[str, _Binding | None],
        token: tuple[str, int, int],
        supported: set[str],
        additive: set[str],
        expected_receiver_names: set[str],
        inherited_conditions: tuple[EndpointDiscoveryCondition, ...],
        lifecycle: SurfaceRegistrationEvidence,
        disabled: bool,
        ancestor_class_states: tuple[dict[str, _Binding | None], ...],
    ) -> dict[str, _Binding | None]:
        current = dict(possible_state)
        for statement in statements:
            if isinstance(statement, ast.If):
                current = self._inspect_startup_possible_expression(
                    statement.test,
                    current,
                    module,
                    actual_state,
                    token,
                    supported,
                    additive,
                    expected_receiver_names,
                    inherited_conditions,
                    lifecycle,
                    disabled,
                    ancestor_class_states,
                )
                truth = self._literal_truth(statement.test)
                if truth is not None:
                    current = self._inspect_startup_possible_statements(
                        statement.body if truth else statement.orelse,
                        current,
                        module,
                        actual_state,
                        token,
                        supported,
                        additive,
                        expected_receiver_names,
                        inherited_conditions,
                        lifecycle,
                        disabled,
                        ancestor_class_states,
                    )
                else:
                    body_state = self._inspect_startup_possible_statements(
                        statement.body,
                        dict(current),
                        module,
                        actual_state,
                        token,
                        supported,
                        additive,
                        expected_receiver_names,
                        inherited_conditions,
                        lifecycle,
                        disabled,
                        ancestor_class_states,
                    )
                    else_state = self._inspect_startup_possible_statements(
                        statement.orelse,
                        dict(current),
                        module,
                        actual_state,
                        token,
                        supported,
                        additive,
                        expected_receiver_names,
                        inherited_conditions,
                        lifecycle,
                        disabled,
                        ancestor_class_states,
                    )
                    current = self._startup_possible_exact_join((body_state, else_state), token)
                continue
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                for expression in self._startup_definition_header_expressions(module, statement):
                    current = self._inspect_startup_possible_expression(
                        expression,
                        current,
                        module,
                        actual_state,
                        token,
                        supported,
                        additive,
                        expected_receiver_names,
                        inherited_conditions,
                        lifecycle,
                        disabled,
                        ancestor_class_states,
                    )
                continue
            current = self._inspect_startup_possible_expression(
                statement,
                current,
                module,
                actual_state,
                token,
                supported,
                additive,
                expected_receiver_names,
                inherited_conditions,
                lifecycle,
                disabled,
                ancestor_class_states,
            )
        return current

    def _inspect_startup_class_body_effects(  # noqa: PLR0912, PLR0915
        self,
        statement: ast.ClassDef,
        module: _Module,
        state: dict[str, _Binding | None],
        token: tuple[str, int, int],
        supported: set[str],
        additive: set[str],
        expected_receiver_names: set[str],
        inherited_conditions: tuple[EndpointDiscoveryCondition, ...],
        lifecycle: SurfaceRegistrationEvidence,
        disabled: bool,
        *,
        scope: _StartupScopeFrame,
        fallback_state: dict[str, _Binding | None] | None = None,
        possible_exact_state: dict[str, _Binding | None] | None = None,
        ancestor_class_states: tuple[dict[str, _Binding | None], ...] = (),
    ) -> tuple[bool, _Fallthrough]:
        """Fail closed on exact-app effects from one eagerly executed class body."""
        declarations = _ClassScopeDeclarationVisitor()
        for body_statement in statement.body:
            declarations.visit(body_statement)
        globals_ = declarations.globals
        nonlocals = declarations.nonlocals
        declared_outer = globals_ | nonlocals
        fallback = state if fallback_state is None else fallback_state
        class_state = dict(fallback)
        for name in globals_:
            class_state[name] = scope.global_state.get(name)
        for name in nonlocals:
            class_state[name] = scope.local_state.get(name)
        possible_state = (
            {
                name: binding
                for name, binding in class_state.items()
                if self._binding_has_token(binding, token)
            }
            if possible_exact_state is None
            else dict(possible_exact_state)
        )
        for name in globals_:
            binding = scope.global_state.get(name)
            possible_state[name] = binding if self._binding_has_token(binding, token) else None
        for name in nonlocals:
            binding = scope.local_state.get(name)
            possible_state[name] = binding if self._binding_has_token(binding, token) else None
        class_expected_names = {
            name
            for name in expected_receiver_names
            if self._binding_has_token(class_state.get(name), token)
        }

        overall_flow: _Fallthrough = "always"
        body_statements = self._startup_reachable_class_statements(statement.body)
        for body_statement in body_statements:
            possible_state = self._inspect_startup_possible_statements(
                [body_statement],
                possible_state,
                module,
                state,
                token,
                supported,
                additive,
                class_expected_names,
                inherited_conditions,
                lifecycle,
                disabled,
                ancestor_class_states,
            )
            statement_flow = self._startup_statement_flow(body_statement)
            conservative_effects = (
                statement_flow == "maybe"
                or (
                    isinstance(body_statement, ast.If)
                    and self._literal_truth(body_statement.test) is None
                )
                or (
                    isinstance(body_statement, (ast.For, ast.AsyncFor, ast.While))
                    and self._literal_truth(
                        body_statement.test
                        if isinstance(body_statement, ast.While)
                        else body_statement.iter
                    )
                    is None
                )
            )
            entry_class_state = dict(class_state)
            if isinstance(
                body_statement,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
            ):
                header_expressions = self._startup_definition_header_expressions(
                    module, body_statement
                )
                visitors: list[tuple[_StartupStatementEffectsVisitor, ast.expr | None]] = []
                for expression in header_expressions:
                    effects = _StartupStatementEffectsVisitor()
                    effects.visit(expression)
                    visitors.append((effects, expression))
            else:
                effects = _StartupStatementEffectsVisitor()
                effects.visit(body_statement)
                visitors = [(effects, None)]
                if isinstance(body_statement, ast.AnnAssign) and not module.postponed_annotations:
                    annotation_effects = _StartupStatementEffectsVisitor()
                    annotation_effects.visit(body_statement.annotation)
                    visitors.append((annotation_effects, body_statement.annotation))

            for effects, header_expression in visitors:
                for event in effects.events:
                    if isinstance(event, ast.Call):
                        if conservative_effects:
                            conservative_state = dict(entry_class_state)
                            condition_count = len(self._route_conditions)
                            self._inspect_startup_call_effect(
                                event,
                                module,
                                conservative_state,
                                token,
                                supported,
                                additive,
                                class_expected_names,
                                inherited_conditions,
                                lifecycle,
                                direct_registration=False,
                                disabled=disabled,
                            )
                            if len(self._route_conditions) > condition_count and not any(
                                self._binding_has_token(binding, token)
                                for binding in conservative_state.values()
                            ):
                                self._invalidate_token(state, token)
                                for ancestor in ancestor_class_states:
                                    self._invalidate_token(ancestor, token)
                        had_exact_receiver = any(
                            self._binding_has_token(binding, token)
                            for binding in class_state.values()
                        )
                        route_condition_count = len(self._route_conditions)
                        self._inspect_startup_call_effect(
                            event,
                            module,
                            class_state,
                            token,
                            supported,
                            additive,
                            class_expected_names,
                            inherited_conditions,
                            lifecycle,
                            direct_registration=False,
                            disabled=disabled,
                        )
                        if (
                            had_exact_receiver
                            and len(self._route_conditions) > route_condition_count
                            and not any(
                                self._binding_has_token(binding, token)
                                for binding in class_state.values()
                            )
                        ):
                            self._invalidate_token(state, token)
                            for ancestor in ancestor_class_states:
                                self._invalidate_token(ancestor, token)
                        continue
                    if isinstance(event, _StartupReturnEffect):
                        if self._expression_escapes_exact_receiver(event.value, class_state, token):
                            self._taint_startup_routes(
                                module,
                                event.value.lineno,
                                "exact startup app escapes from an eager nested class body",
                                state,
                                token,
                            )
                            self._invalidate_token(class_state, token)
                            for ancestor in ancestor_class_states:
                                self._invalidate_token(ancestor, token)
                        continue

                    targets, value = event.targets, event.value
                    if any(
                        self._startup_registration_target(target, class_state, token, additive)
                        for target in targets
                    ):
                        disabled = True
                        self._record_startup_route_limitation(
                            module,
                            body_statement.lineno,
                            "startup route registration method is replaced in an eager class body",
                        )
                    binding = self._binding_from_expression(value, class_state, module.name)
                    destructive = any(
                        self._startup_destructive_target(target, class_state, token)
                        for target in targets
                    )
                    escapes_to_class_namespace = self._binding_has_token(binding, token) and any(
                        isinstance(target, ast.Name) and target.id not in declared_outer
                        for target in targets
                    )
                    escapes = escapes_to_class_namespace or self._assignment_escapes_exact_receiver(
                        targets,
                        value,
                        binding,
                        class_state,
                        token,
                    )
                    if destructive or escapes:
                        reason = (
                            "startup may replace, delete, or mutate the exact app router "
                            "or route collection in an eager class body"
                            if destructive
                            else "exact startup app escapes from an eager nested class body"
                        )
                        self._taint_startup_routes(
                            module,
                            body_statement.lineno,
                            reason,
                            state,
                            token,
                        )
                        self._invalidate_token(class_state, token)
                        for ancestor in ancestor_class_states:
                            self._invalidate_token(ancestor, token)
                        binding = None
                    for target in targets:
                        for name in _target_names(target):
                            class_state[name] = binding if isinstance(target, ast.Name) else None
                            if self._binding_has_token(binding, token):
                                class_expected_names.add(name)
                            elif name not in declared_outer:
                                class_expected_names.discard(name)

                if header_expression is not None and self._expression_escapes_exact_receiver(
                    header_expression, class_state, token
                ):
                    self._taint_startup_routes(
                        module,
                        header_expression.lineno,
                        "exact startup app escapes through an eager nested-definition header",
                        state,
                        token,
                    )
                    self._invalidate_token(class_state, token)
                    for ancestor in ancestor_class_states:
                        self._invalidate_token(ancestor, token)

                if not isinstance(
                    body_statement,
                    (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete, ast.Expr),
                ):
                    for name in effects.rebound_names:
                        class_state[name] = None
                        if name not in declared_outer:
                            class_expected_names.discard(name)

            if isinstance(body_statement, ast.ClassDef):
                disabled, nested_flow = self._inspect_startup_class_body_effects(
                    body_statement,
                    module,
                    state,
                    token,
                    supported,
                    additive,
                    expected_receiver_names,
                    inherited_conditions,
                    lifecycle,
                    disabled,
                    scope=scope,
                    fallback_state=fallback,
                    possible_exact_state=possible_state,
                    ancestor_class_states=(*ancestor_class_states, class_state),
                )
                if not any(self._binding_has_token(binding, token) for binding in state.values()):
                    self._invalidate_token(class_state, token)
                if nested_flow == "never":
                    return disabled, "never"
                if nested_flow == "maybe":
                    overall_flow = "maybe"
            if isinstance(
                body_statement,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
            ):
                class_state[body_statement.name] = None
                class_expected_names.discard(body_statement.name)

            for name in globals_:
                binding = class_state.get(name)
                scope.global_state[name] = binding
                if name not in scope.local_names:
                    scope.local_state[name] = binding
                    fallback[name] = binding
                for ancestor in ancestor_class_states:
                    ancestor[name] = None
                if self._binding_has_token(binding, token):
                    expected_receiver_names.add(name)
            for name in nonlocals:
                binding = class_state.get(name)
                scope.local_state[name] = binding
                fallback[name] = binding
                for ancestor in ancestor_class_states:
                    ancestor[name] = None
                if self._binding_has_token(binding, token):
                    expected_receiver_names.add(name)

            if statement_flow == "never":
                return disabled, "never"
            if statement_flow == "maybe":
                overall_flow = "maybe"

        return disabled, overall_flow

    def _startup_reachable_class_statements(self, statements: list[ast.stmt]) -> list[ast.stmt]:
        """Select only trivially reachable class statements without widening branches."""
        selected: list[ast.stmt] = []
        for statement in statements:
            if isinstance(statement, ast.If):
                truth = self._literal_truth(statement.test)
                if truth is not None:
                    selected.extend(
                        self._startup_reachable_class_statements(
                            statement.body if truth else statement.orelse
                        )
                    )
                    continue
            if isinstance(statement, ast.While) and self._literal_truth(statement.test) is False:
                selected.extend(self._startup_reachable_class_statements(statement.orelse))
                continue
            if (
                isinstance(statement, (ast.For, ast.AsyncFor))
                and self._literal_truth(statement.iter) is False
            ):
                selected.extend(self._startup_reachable_class_statements(statement.orelse))
                continue
            selected.append(statement)
        return selected

    def _startup_statement_flow(  # noqa: PLR0911
        self, statement: ast.stmt
    ) -> _Fallthrough:
        """Return a bounded fallthrough classification for one class statement."""
        if isinstance(statement, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
            return "never"
        if isinstance(statement, ast.If):
            truth = self._literal_truth(statement.test)
            if truth is not None:
                return self._startup_statements_flow(statement.body if truth else statement.orelse)
            return self._branch_flow(
                self._startup_statements_flow(statement.body),
                self._startup_statements_flow(statement.orelse),
            )
        if isinstance(statement, ast.While):
            truth = self._literal_truth(statement.test)
            if truth is False:
                return self._startup_statements_flow(statement.orelse)
            return "maybe"
        if isinstance(statement, (ast.For, ast.AsyncFor)):
            if self._literal_truth(statement.iter) is False:
                return self._startup_statements_flow(statement.orelse)
            return "maybe"
        if isinstance(statement, (ast.Try,)) or statement.__class__.__name__ == "TryStar":
            return "maybe"
        return "always"

    def _startup_statements_flow(self, statements: list[ast.stmt]) -> _Fallthrough:
        overall: _Fallthrough = "always"
        for statement in self._startup_reachable_class_statements(statements):
            flow = self._startup_statement_flow(statement)
            if flow == "never":
                return "never"
            if flow == "maybe":
                overall = "maybe"
        return overall

    def _startup_definition_header_expressions(
        self,
        module: _Module,
        statement: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
    ) -> tuple[ast.expr, ...]:
        """Return eager nested-definition expressions without entering deferred bodies."""
        expressions: list[ast.expr] = list(statement.decorator_list)
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            expressions.extend(statement.args.defaults)
            expressions.extend(
                default for default in statement.args.kw_defaults if default is not None
            )
            if not module.postponed_annotations:
                expressions.extend(self._function_annotation_expressions(statement))
        else:
            expressions.extend(statement.bases)
            expressions.extend(keyword.value for keyword in statement.keywords)
        return tuple(expressions)

    def _inspect_startup_call_effect(  # noqa: PLR0911
        self,
        call: ast.Call,
        module: _Module,
        state: dict[str, _Binding | None],
        token: tuple[str, int, int],
        supported: set[str],
        additive: set[str],
        expected_receiver_names: set[str],
        inherited_conditions: tuple[EndpointDiscoveryCondition, ...],
        lifecycle: SurfaceRegistrationEvidence,
        *,
        direct_registration: bool,
        disabled: bool,
    ) -> None:
        """Inspect one eager call before later source-ordered state effects."""
        destructive_reason = self._startup_destructive_call(call, state, token)
        if destructive_reason is not None:
            self._taint_startup_routes(module, call.lineno, destructive_reason, state, token)
            return

        collection_operation = self._startup_route_collection_operation(call, state, token)
        if collection_operation is not None:
            self._record_startup_route_limitation(
                module,
                call.lineno,
                "startup route collection mutation "
                f"{collection_operation!r} is not finitely modeled",
            )
            return

        operation = self._exact_receiver_operation(call, state, token)
        if operation in additive:
            if disabled and operation in supported:
                return
            if operation not in supported:
                self._record_startup_route_limitation(
                    module,
                    call.lineno,
                    f"startup route mutation {operation!r} is not finitely modeled",
                )
                return
            if not direct_registration:
                self._record_startup_route_limitation(
                    module,
                    call.lineno,
                    "startup route registration appears in unsupported control flow or expression",
                )
                return
            route_result = self._startup_route_from_call(call, state, operation)
            if route_result.route is None:
                self._record_startup_route_limitation(
                    module,
                    call.lineno,
                    route_result.failure
                    or "startup route registration has dynamic or unresolved arguments",
                )
                return
            self._append_startup_route(
                route_result.route, call, module, inherited_conditions, lifecycle
            )
            return

        if self._call_escapes_exact_receiver(call, state, token):
            self._taint_startup_routes(
                module,
                call.lineno,
                "exact startup app receiver escapes by being passed to unresolved code",
                state,
                token,
            )
        elif (
            isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)
            and call.func.attr in additive
            and call.func.value.id in expected_receiver_names
        ):
            self._record_startup_route_limitation(
                module,
                call.lineno,
                "startup route receiver was rebound or became unresolved",
            )

    def _append_startup_route(
        self,
        route: tuple[
            str,
            tuple[EndpointMethod, ...],
            tuple[_Module, ast.FunctionDef | ast.AsyncFunctionDef],
        ],
        call: ast.Call,
        module: _Module,
        inherited_conditions: tuple[EndpointDiscoveryCondition, ...],
        lifecycle: SurfaceRegistrationEvidence,
    ) -> None:
        path, methods, (route_module, route_function) = route
        condition = EndpointDiscoveryCondition(
            source_path=module.path,
            source_line=call.lineno,
            reason="route is registered only if framework startup lifecycle executes",
        )
        conditions = tuple(dict.fromkeys((*inherited_conditions, condition)))
        key = (
            str(module.path),
            call.lineno,
            path,
            methods,
            f"{route_module.name}.{route_function.name}",
        )
        if key in self._startup_route_seen:
            return
        self._startup_route_seen.add(key)
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
                    lifecycle_surface_id=lifecycle.surface_id,
                    contract_id=lifecycle.contract_id,
                    registration_file=lifecycle.registration_file,
                    registration_line=lifecycle.registration_line,
                    activation_file=module.path,
                    activation_line=call.lineno,
                    activation_source_hash=self._source_hash(module, call),
                    contract_source_path=lifecycle.contract_source_path,
                    raw_hash=lifecycle.raw_hash,
                    config_hash=lifecycle.config_hash,
                    preset_hash=lifecycle.preset_hash,
                    contract_hash=lifecycle.contract_hash,
                ),
            )
        )

    def _binding_has_token(self, binding: _Binding | None, token: tuple[str, int, int]) -> bool:
        if binding is None:
            return False
        resolved = self._follow_project_binding(binding)
        return resolved.kind == "receiver" and resolved.instance_token == token

    def _expression_is_exact_receiver(
        self,
        expression: ast.expr,
        state: dict[str, _Binding | None],
        token: tuple[str, int, int],
    ) -> bool:
        return (
            isinstance(expression, ast.Name)
            and isinstance(expression.ctx, ast.Load)
            and self._binding_has_token(state.get(expression.id), token)
        )

    def _expression_escapes_exact_receiver(
        self,
        expression: ast.expr,
        state: dict[str, _Binding | None],
        token: tuple[str, int, int],
    ) -> bool:
        if self._expression_is_exact_receiver(expression, state, token):
            escaped = True
        elif isinstance(expression, (ast.Attribute, ast.Subscript)):
            chain = self._startup_route_chain(expression, state, token)
            escaped = chain in {("router",), ("routes",), ("router", "routes")}
            if not escaped and isinstance(expression, ast.Subscript):
                escaped = self._expression_escapes_exact_receiver(expression.slice, state, token)
        elif isinstance(expression, ast.Call):
            escaped = self._call_escapes_exact_receiver(expression, state, token)
        elif isinstance(expression, (ast.List, ast.Tuple, ast.Set)):
            escaped = any(
                self._expression_escapes_exact_receiver(item, state, token)
                for item in expression.elts
            )
        elif isinstance(expression, ast.Dict):
            escaped = any(
                item is not None and self._expression_escapes_exact_receiver(item, state, token)
                for item in (*expression.keys, *expression.values)
            )
        else:
            escaped = any(
                self._expression_escapes_exact_receiver(child, state, token)
                for child in ast.iter_child_nodes(expression)
                if isinstance(child, ast.expr)
            )
        return escaped

    def _assignment_escapes_exact_receiver(
        self,
        targets: tuple[ast.expr, ...],
        value: ast.expr | None,
        binding: _Binding | None,
        state: dict[str, _Binding | None],
        token: tuple[str, int, int],
    ) -> bool:
        if value is None:
            return False
        if self._binding_has_token(binding, token) and all(
            isinstance(target, ast.Name) for target in targets
        ):
            return False
        return self._expression_escapes_exact_receiver(value, state, token)

    def _exact_receiver_operation(
        self,
        call: ast.Call,
        state: dict[str, _Binding | None],
        token: tuple[str, int, int],
    ) -> str | None:
        if not isinstance(call.func, ast.Attribute) or not self._expression_is_exact_receiver(
            call.func.value, state, token
        ):
            return None
        return call.func.attr

    def _startup_route_chain(
        self,
        expression: ast.expr,
        state: dict[str, _Binding | None],
        token: tuple[str, int, int],
    ) -> tuple[str, ...] | None:
        attributes: list[str] = []
        current = expression
        while isinstance(current, (ast.Attribute, ast.Subscript)):
            if isinstance(current, ast.Attribute):
                attributes.append(current.attr)
                current = current.value
            else:
                attributes.append("[]")
                current = current.value
        if not self._expression_is_exact_receiver(current, state, token):
            return None
        return tuple(reversed(attributes))

    def _startup_destructive_target(
        self,
        target: ast.expr,
        state: dict[str, _Binding | None],
        token: tuple[str, int, int],
    ) -> bool:
        chain = self._startup_route_chain(target, state, token)
        return chain is not None and (
            chain == ("router",) or chain[:1] == ("routes",) or chain[:2] == ("router", "routes")
        )

    def _startup_registration_target(
        self,
        target: ast.expr,
        state: dict[str, _Binding | None],
        token: tuple[str, int, int],
        operations: set[str],
    ) -> bool:
        chain = self._startup_route_chain(target, state, token)
        return chain is not None and len(chain) == 1 and chain[0] in operations

    def _startup_route_collection_operation(
        self,
        call: ast.Call,
        state: dict[str, _Binding | None],
        token: tuple[str, int, int],
    ) -> str | None:
        if not isinstance(call.func, ast.Attribute):
            return None
        chain = self._startup_route_chain(call.func.value, state, token)
        if chain is None or not (chain[:1] == ("routes",) or chain[:2] == ("router", "routes")):
            return None
        return call.func.attr

    def _startup_destructive_call(
        self,
        call: ast.Call,
        state: dict[str, _Binding | None],
        token: tuple[str, int, int],
    ) -> str | None:
        operation = self._startup_route_collection_operation(call, state, token)
        if operation not in {"clear", "pop", "remove"}:
            return None
        return f"startup may destructively call {operation!r} on the exact app routes"

    def _call_escapes_exact_receiver(
        self,
        call: ast.Call,
        state: dict[str, _Binding | None],
        token: tuple[str, int, int],
    ) -> bool:
        if self._exact_receiver_operation(call, state, token) is not None:
            return True
        return any(
            self._expression_escapes_exact_receiver(argument, state, token)
            for argument in call.args
        ) or any(
            self._expression_escapes_exact_receiver(keyword.value, state, token)
            for keyword in call.keywords
        )

    def _invalidate_token(
        self, state: dict[str, _Binding | None], token: tuple[str, int, int]
    ) -> None:
        for name, binding in state.items():
            if self._binding_has_token(binding, token):
                state[name] = None

    def _startup_route_from_call(  # noqa: PLR0911
        self,
        call: ast.Call,
        state: dict[str, _Binding | None],
        operation: str,
    ) -> _StartupRouteResult:
        if any(isinstance(argument, ast.Starred) for argument in call.args) or any(
            keyword.arg is None for keyword in call.keywords
        ):
            return _StartupRouteResult(None)

        def selected(index: int, name: str) -> ast.expr | None:
            if index < len(call.args):
                if any(keyword.arg == name for keyword in call.keywords):
                    return None
                return call.args[index]
            values = [keyword.value for keyword in call.keywords if keyword.arg == name]
            return values[0] if len(values) == 1 else None

        path_expression = selected(0, "path")
        handler_expression = selected(1, "endpoint")
        path_result = self._literal_startup_path(path_expression)
        path = path_result.string
        path_failure = (
            f"startup route path {path_result.reason}"
            if path_result.failure not in {None, "unsupported"}
            else None
        )
        handler = (
            self._resolve_handler(handler_expression, state)
            if handler_expression is not None
            else None
        )
        if path is None or handler is None:
            return _StartupRouteResult(None, path_failure)

        methods: tuple[EndpointMethod, ...]
        if operation in {"add_api_websocket_route", "add_websocket_route"}:
            methods = (EndpointMethod.WEBSOCKET,)
        else:
            method_values = [keyword.value for keyword in call.keywords if keyword.arg == "methods"]
            if len(method_values) > 1:
                return _StartupRouteResult(None)
            methods_expression = method_values[0] if method_values else None
            if methods_expression is None:
                methods = (EndpointMethod.GET,)
            else:
                method_result = self._literal_startup_methods(methods_expression)
                values = method_result.values
                method_failure = (
                    f"startup route methods {method_result.reason}"
                    if method_result.failure not in {None, "unsupported"}
                    else None
                )
                if values is None or not values:
                    return _StartupRouteResult(None, method_failure)
                try:
                    methods = tuple(
                        sorted(
                            {EndpointMethod(value.upper()) for value in values},
                            key=lambda item: item.value,
                        )
                    )
                except ValueError:
                    return _StartupRouteResult(None)
                if EndpointMethod.CUSTOM in methods or EndpointMethod.WEBSOCKET in methods:
                    return _StartupRouteResult(None)
        return _StartupRouteResult((path, methods, handler))

    def _record_startup_route_limitation(self, module: _Module, line: int, reason: str) -> None:
        self._limitations.append(
            EndpointDiscoveryCondition(
                source_path=module.path,
                source_line=line,
                reason=reason,
            )
        )

    def _record_route_condition(self, module: _Module, line: int, reason: str) -> None:
        condition = EndpointDiscoveryCondition(
            source_path=module.path,
            source_line=line,
            reason=reason,
        )
        self._limitations.append(condition)
        self._route_conditions.append(condition)

    def _taint_startup_routes(
        self,
        module: _Module,
        line: int,
        reason: str,
        state: dict[str, _Binding | None],
        token: tuple[str, int, int],
    ) -> None:
        self._record_route_condition(module, line, reason)
        self._invalidate_token(state, token)

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
        if not isinstance(expression, ast.Attribute):
            return None
        binding = self._expression_binding(expression.value, state)
        if binding is None:
            return None
        binding = self._follow_project_binding(binding)
        symbol = f"{binding.identity}.{expression.attr}"
        if binding.kind == "module":
            invocation = (
                InvocationKind.CONSTRUCTOR
                if symbol in self._declared_receiver_types
                or any(
                    contract.registration.symbol == symbol
                    and contract.registration.invocation == InvocationKind.CONSTRUCTOR
                    for contract in self.contracts.document.contracts
                )
                else InvocationKind.FUNCTION
            )
            return symbol, invocation, None
        if binding.kind == "receiver":
            return symbol, InvocationKind.INSTANCE_METHOD, binding.identity
        if binding.kind == "symbol":
            if symbol in self._declared_receiver_types:
                invocation = InvocationKind.CONSTRUCTOR
            elif any(
                contract.registration.symbol == symbol
                and contract.registration.invocation == InvocationKind.FUNCTION
                for contract in self.contracts.document.contracts
            ):
                invocation = InvocationKind.FUNCTION
            else:
                invocation = InvocationKind.CLASS_METHOD
            return (
                symbol,
                invocation,
                None if invocation == InvocationKind.FUNCTION else binding.identity,
            )
        return None

    def _expression_binding(
        self, expression: ast.expr, state: dict[str, _Binding | None]
    ) -> _Binding | None:
        """Resolve a bounded exact Name/Attribute chain without suffix guessing."""
        attributes: list[str] = []
        current = expression
        for _depth in range(16):
            if isinstance(current, ast.Attribute):
                attributes.append(current.attr)
                current = current.value
                continue
            if not isinstance(current, ast.Name):
                return None
            binding = state.get(current.id)
            if binding is None:
                return None
            binding = self._follow_project_binding(binding)
            if not attributes:
                return binding
            if binding.kind not in {"module", "symbol"}:
                return None
            suffix = ".".join(reversed(attributes))
            return _Binding(binding.kind, f"{binding.identity}.{suffix}")
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
        self,
        expression: ast.expr | None,
        state: dict[str, _Binding | None],
        module_name: str,
    ) -> _Binding | None:
        if isinstance(expression, (ast.Name, ast.NamedExpr)):
            return state.get(
                expression.id if isinstance(expression, ast.Name) else expression.target.id
            )
        if isinstance(expression, ast.Attribute):
            owner = self._expression_binding(expression.value, state)
            if owner is not None and owner.kind in {"module", "symbol"}:
                return _Binding("symbol", f"{owner.identity}.{expression.attr}")
        if isinstance(expression, ast.Call):
            resolved = self._resolve_call(expression.func, state)
            if (
                resolved is not None
                and resolved[1] in {InvocationKind.FUNCTION, InvocationKind.CONSTRUCTOR}
                and resolved[0] in self._declared_receiver_types
            ):
                return _Binding(
                    "receiver",
                    resolved[0],
                    (module_name, expression.lineno, expression.col_offset),
                )
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
        return self._resolve_class_method_identity(identity, method_name, required_base)

    def _resolve_class_method_identity(
        self,
        identity: str | None,
        method_name: str,
        required_base: str,
    ) -> tuple[_Module, ast.FunctionDef | ast.AsyncFunctionDef] | None:
        """Resolve a method from an already captured exact class identity."""
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
        binding = self._expression_binding(expression, state)
        if binding is None:
            return None
        if binding.kind == "symbol" or (
            binding.kind == "module" and isinstance(expression, ast.Attribute)
        ):
            return binding.identity
        return None

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
        binding = self._expression_binding(expression, state)
        identity = (
            binding.identity
            if binding is not None and binding.kind in {"function", "symbol", "module"}
            else None
        )
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
    def _resources(  # noqa: PLR0911, PLR0912 - selector forms stay explicit
        cls,
        contract: SurfaceContract,
        call: ast.Call,
        handler: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> _ResolvedResources:
        """Resolve one bounded literal resource set without widening dynamic values."""
        selector = contract.surface.resource
        values: tuple[str, ...]
        failure = "resource set was not finite literal data"
        if selector.kind == ResourceSelectorKind.HANDLER_NAME:
            values = (cls._handler_resource(handler.name, selector.handler_name_normalization),)
        elif selector.kind == ResourceSelectorKind.LITERAL:
            if selector.value is None:
                return _ResolvedResources(None, failure)
            values = (selector.value,)
        elif selector.kind == ResourceSelectorKind.ARGUMENTS:
            start = selector.index or 0
            selected = call.args[start:]
            if not selected:
                return _ResolvedResources(None, failure)
            evaluator = StaticStringEvaluator(max_string_chars=MAX_CUSTOM_RESOURCE_CHARS)
            collected: list[str] = []
            for expression in selected:
                result = evaluator.evaluate_more_values(expression)
                if result.values is None:
                    return _ResolvedResources(None, _resource_failure(result, failure))
                if len(result.values) > cls.MAX_RESOURCES_PER_REGISTRATION - len(collected):
                    return _ResolvedResources(
                        None, "bounded static evaluation values limit exceeded"
                    )
                collected.extend(result.values)
            values = tuple(collected)
        elif selector.kind == ResourceSelectorKind.KEYWORD_OR_HANDLER_NAME:
            selected_keyword_expression = next(
                (item.value for item in call.keywords if item.arg == selector.name),
                None,
            )
            if selected_keyword_expression is None:
                values = (
                    cls._handler_resource(
                        handler.name,
                        selector.handler_name_normalization,
                    ),
                )
            else:
                result = cls._literal_resource_result(selected_keyword_expression)
                if result.values is None:
                    return _ResolvedResources(None, _resource_failure(result, failure))
                values = result.values
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
            result = cls._literal_resource_result(selected_expression)
            if result.values is None:
                return _ResolvedResources(None, _resource_failure(result, failure))
            values = result.values
        normalized = tuple(sorted({value for value in values if value.strip()}))
        if (
            any(len(value) > MAX_CUSTOM_RESOURCE_CHARS for value in values)
            or len(normalized) != len(set(values))
            or not (1 <= len(normalized) <= cls.MAX_RESOURCES_PER_REGISTRATION)
        ):
            return _ResolvedResources(None, failure)
        return _ResolvedResources(normalized, "")

    @staticmethod
    def _handler_resource(name: str, normalization: HandlerNameNormalization) -> str:
        return (
            name.replace("_", "-") if normalization == HandlerNameNormalization.KEBAB_CASE else name
        )

    @staticmethod
    def _literal_resource_result(expression: ast.expr | None) -> StaticEvaluationResult:
        return StaticStringEvaluator(max_string_chars=MAX_CUSTOM_RESOURCE_CHARS).evaluate_values(
            expression
        )

    @staticmethod
    def _literal_startup_path(expression: ast.expr | None) -> StaticEvaluationResult:
        return StaticStringEvaluator().evaluate_string(expression)

    @staticmethod
    def _literal_startup_methods(expression: ast.expr | None) -> StaticEvaluationResult:
        return StaticStringEvaluator().evaluate_flat_values(expression)

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
