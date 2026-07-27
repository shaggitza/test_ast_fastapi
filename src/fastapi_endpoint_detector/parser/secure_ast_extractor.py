"""Conservative, execution-free FastAPI route discovery."""

from __future__ import annotations

import ast
import tokenize
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path  # noqa: TC003 - Pydantic models consume paths at runtime
from typing import TYPE_CHECKING, ClassVar, Literal

if TYPE_CHECKING:
    from collections.abc import Callable

from fastapi_endpoint_detector.models.endpoint import (
    Endpoint,
    EndpointDiscoveryCondition,
    EndpointDiscoveryStatus,
    EndpointInventory,
    EndpointMethod,
    HandlerInfo,
    InventoryStatus,
)


class SecureASTExtractorError(Exception):
    """Error during secure AST extraction."""


ObjectKey = tuple[str, str]
ObjectKind = Literal["app", "router"]
CompositionMode = Literal["copy", "live"]
EndpointImpact = Literal["none", "prior", "subsequent", "all"]
_ORDER_SCALE = 1_000_000


@dataclass(frozen=True)
class _Object:
    key: ObjectKey
    variable: str
    kind: ObjectKind
    prefix: str
    line: int
    discovery_conditions: tuple[EndpointDiscoveryCondition, ...] = ()


@dataclass(frozen=True)
class _Route:
    owner: ObjectKey
    path: str
    methods: tuple[str, ...]
    handler: HandlerInfo
    line: int
    discovery_conditions: tuple[EndpointDiscoveryCondition, ...] = ()


@dataclass(frozen=True)
class _Edge:
    parent: ObjectKey
    child: ObjectKey
    prefix: str
    line: int
    child_cutoff: int | None
    limitation_cutoff: tuple[str, int] | None
    mode: CompositionMode


@dataclass(frozen=True)
class _OrderedInventoryLimitation:
    origin_module: str
    order: int
    condition: EndpointDiscoveryCondition
    endpoint_impact: EndpointImpact = "none"


@dataclass(frozen=True)
class _FactoryCall:
    variable: str
    line: int
    call: ast.Call


@dataclass(frozen=True)
class _ImportBinding:
    line: int
    module: str
    symbol: str | None = None


@dataclass
class _FactoryGraph:
    root: _Object
    objects: list[_Object] = field(default_factory=list)
    routes: list[_Route] = field(default_factory=list)
    edges: list[_Edge] = field(default_factory=list)


@dataclass
class _Module:
    name: str
    path: Path
    tree: ast.Module
    is_package: bool
    imports: dict[str, tuple[str, str]] = field(default_factory=dict)
    module_imports: dict[str, str] = field(default_factory=dict)
    import_lines: dict[str, int] = field(default_factory=dict)
    import_bindings: dict[str, list[_ImportBinding]] = field(default_factory=dict)
    fastapi_names: set[str] = field(default_factory=set)
    router_names: set[str] = field(default_factory=set)
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = field(default_factory=dict)
    function_history: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]] = field(
        default_factory=dict
    )
    objects: dict[str, list[_Object]] = field(default_factory=dict)
    assignments: dict[str, list[int]] = field(default_factory=dict)
    strings: dict[str, list[tuple[int, str | None]]] = field(default_factory=dict)
    factory_calls: list[_FactoryCall] = field(default_factory=list)
    factory_objects: list[_Object] = field(default_factory=list)
    factory_routes: list[_Route] = field(default_factory=list)
    factory_edges: list[_Edge] = field(default_factory=list)
    object_limitations: dict[ObjectKey, list[EndpointDiscoveryCondition]] = field(
        default_factory=dict
    )
    inventory_only_limitations: dict[ObjectKey, list[EndpointDiscoveryCondition]] = field(
        default_factory=dict
    )
    ordered_inventory_limitations: dict[ObjectKey, list[_OrderedInventoryLimitation]] = field(
        default_factory=dict
    )
    modeled_route_effects: set[int] = field(default_factory=set)


class SecureASTExtractor:
    """Discover statically provable FastAPI routes without importing project code."""

    HTTP_METHODS: ClassVar[set[str]] = {
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "options",
        "head",
        "trace",
        "websocket",
    }

    def __init__(
        self,
        app_path: Path,
        app_variable: str = "app",
        app_entry: str | None = None,
        bootstrap_entry: str | None = None,
    ) -> None:
        self.app_path = app_path.resolve()
        self.app_variable = app_variable
        self.app_entry = app_entry
        self.bootstrap_entry = bootstrap_entry
        self._app_entry_parts = self._parse_entry(app_entry, "--app-entry")
        self._bootstrap_entry_parts = self._parse_entry(bootstrap_entry, "--bootstrap-entry")

    @staticmethod
    def _parse_entry(value: str | None, option: str) -> tuple[str, str] | None:
        if value is None:
            return None
        parts = value.split(":")
        if (
            len(parts) != 2
            or not parts[0]
            or not parts[1]
            or any(not part.isidentifier() for part in parts[0].split("."))
            or not parts[1].isidentifier()
        ):
            raise SecureASTExtractorError(f"{option} must use an exact project-local MODULE:SYMBOL")
        return parts[0], parts[1]

    def extract_endpoints(self) -> list[Endpoint]:
        """Compatibility wrapper returning only discovered endpoints."""
        return self.extract_inventory().endpoints

    def extract_inventory(self) -> EndpointInventory:  # noqa: PLR0912, PLR0915
        """Return endpoints together with whole-inventory completeness evidence."""
        if not self.app_path.exists():
            limitation = EndpointDiscoveryCondition(
                source_path=self.app_path,
                source_line=1,
                reason="configured source path does not exist",
            )
            return EndpointInventory(
                status=InventoryStatus.UNAVAILABLE,
                limitations=(limitation,),
            )
        modules, entry_module, parse_failures = self._load_modules()
        if self.app_path.is_file() and entry_module is None:
            limitation = next(
                (item for item in parse_failures if item.source_path.resolve() == self.app_path),
                EndpointDiscoveryCondition(
                    source_path=self.app_path,
                    source_line=1,
                    reason="configured source did not contain a project-local Python module",
                ),
            )
            return EndpointInventory(
                status=InventoryStatus.UNAVAILABLE,
                limitations=(limitation,),
            )
        if not modules:
            if parse_failures:
                return EndpointInventory(
                    status=InventoryStatus.UNAVAILABLE,
                    limitations=parse_failures,
                )
            raise SecureASTExtractorError("no project-local Python modules were found")

        aliases = self._module_aliases(modules)
        for module in modules.values():
            self._collect_symbols(module, aliases, modules)

        explicit_module: _Module | None = None
        explicit_variable: str | None = None
        explicit_object: _Object | None = None
        if self._app_entry_parts is not None:
            module_name, symbol = self._app_entry_parts
            explicit_module = modules.get(module_name)
            if explicit_module is None:
                raise SecureASTExtractorError(
                    f"explicit app entry module {module_name!r} is not project-local or unique"
                )
            explicit_object = self._object_at(explicit_module, symbol, None)
            if explicit_object is not None:
                if explicit_object.kind != "app":
                    raise SecureASTExtractorError("explicit app entry object is not a FastAPI app")
            else:
                factory_bindings = [
                    call
                    for call in explicit_module.factory_calls
                    if call.variable == symbol
                    and self._latest_binding_line(explicit_module, symbol, 2**31 - 1) == call.line
                ]
                if len(factory_bindings) == 1:
                    explicit_variable = symbol
                else:
                    history = explicit_module.function_history.get(symbol, [])
                    function = self._function_at(explicit_module, symbol, 2**31 - 1)
                    if len(history) != 1 or function is None:
                        raise SecureASTExtractorError(
                            f"explicit app entry symbol {self.app_entry!r} is absent, "
                            "ambiguous, or rebound"
                        )
                    explicit_variable = f"__explicit_app_entry_{symbol}"
                    explicit_module.assignments.setdefault(explicit_variable, []).append(2**31 - 1)
                    call = ast.Call(func=ast.Name(id=symbol, ctx=ast.Load()), args=[], keywords=[])
                    ast.copy_location(call, function)
                    explicit_module.factory_calls.append(
                        _FactoryCall(explicit_variable, 2**31 - 1, call)
                    )

        # Factory-created exports can be consumed by modules sorted before their
        # providers. Iterate to a fixed point; each call is materialized once.
        for _iteration in range(len(modules) + 1):
            before = sum(len(module.factory_objects) for module in modules.values())
            for module in modules.values():
                self._collect_factory_graphs(
                    module,
                    aliases,
                    modules,
                    explicit_binding=(
                        (explicit_module.name, explicit_variable)
                        if explicit_module is not None and explicit_variable is not None
                        else None
                    ),
                )
            after = sum(len(module.factory_objects) for module in modules.values())
            if after == before:
                break

        objects = {
            item.key: item
            for module in modules.values()
            for item in [
                *(object_item for history in module.objects.values() for object_item in history),
                *module.factory_objects,
            ]
        }
        routes = [
            route
            for module in modules.values()
            for route in [
                *self._collect_routes(module, aliases, modules),
                *module.factory_routes,
            ]
        ]
        edges = [
            edge
            for module in modules.values()
            for edge in [
                *self._collect_edges(module, aliases, modules),
                *module.factory_edges,
            ]
        ]
        for module in modules.values():
            self._collect_control_flow_limitations(module, aliases, modules)

        referenced = {edge.child for edge in edges}
        if self._app_entry_parts is not None:
            if explicit_object is not None:
                roots = [explicit_object.key]
            else:
                assert explicit_module is not None and explicit_variable is not None
                selected = self._object_at(explicit_module, explicit_variable, None)
                if selected is None or selected.kind != "app":
                    raise SecureASTExtractorError(
                        f"explicit app entry factory {self.app_entry!r} cannot be summarized safely"
                    )
                roots = [selected.key]
        else:
            candidates = [
                item
                for module in modules.values()
                if (item := self._object_at(module, self.app_variable, None)) is not None
                and item.kind == "app"
            ]
            if entry_module is not None:
                candidates = [item for item in candidates if item.key[0] == entry_module]
            roots = (
                [item.key for item in candidates]
                if entry_module is not None
                else [item.key for item in candidates if item.key not in referenced]
            )

            # A router-only file is useful when explicitly selected, but an app selection
            # must never silently fall back to a differently named app/router.
            if not roots and entry_module is not None:
                module = modules[entry_module]
                selected = self._object_at(module, self.app_variable, None)
                roots = [selected.key] if selected is not None and selected.kind == "router" else []

        if not roots:
            source_module = (
                modules[entry_module] if entry_module is not None else modules[sorted(modules)[0]]
            )
            limitation = EndpointDiscoveryCondition(
                source_path=source_module.path,
                source_line=1,
                reason=(
                    f"configured app variable {self.app_variable!r} did not resolve "
                    "to an app or router"
                ),
            )
            return EndpointInventory(
                status=InventoryStatus.UNAVAILABLE,
                limitations=(limitation,),
            )

        if self._bootstrap_entry_parts is not None:
            if len(set(roots)) != 1:
                raise SecureASTExtractorError(
                    "bootstrap_entry requires one uniquely selected app root"
                )
            bootstrap_module_name, bootstrap_symbol = self._bootstrap_entry_parts
            bootstrap_module = modules.get(bootstrap_module_name)
            if bootstrap_module is None:
                raise SecureASTExtractorError(
                    f"bootstrap entry module {bootstrap_module_name!r} is not project-local"
                )
            history = bootstrap_module.function_history.get(bootstrap_symbol, [])
            bootstrap_function = self._function_at(bootstrap_module, bootstrap_symbol, 2**31 - 1)
            if len(history) != 1 or bootstrap_function is None:
                raise SecureASTExtractorError(
                    f"bootstrap entry {self.bootstrap_entry!r} is absent, ambiguous, or rebound"
                )
            if (
                isinstance(bootstrap_function, ast.AsyncFunctionDef)
                or bootstrap_function.decorator_list
            ):
                raise SecureASTExtractorError("bootstrap entry must be synchronous and undecorated")
            selected_root = objects[roots[0]]
            if selected_root.kind != "app":
                raise SecureASTExtractorError("bootstrap_entry requires a FastAPI app root")
            self._apply_bootstrap_registration(
                bootstrap_module,
                bootstrap_function,
                selected_root,
                aliases,
                modules,
                routes,
                edges,
            )

        routes_by_owner: dict[ObjectKey, list[_Route]] = {}
        edges_by_parent: dict[ObjectKey, list[_Edge]] = {}
        for route in routes:
            routes_by_owner.setdefault(route.owner, []).append(route)
        for edge in edges:
            edges_by_parent.setdefault(edge.parent, []).append(edge)

        object_limitations: dict[ObjectKey, tuple[EndpointDiscoveryCondition, ...]] = {}
        inventory_only_limitations: dict[ObjectKey, tuple[EndpointDiscoveryCondition, ...]] = {}
        ordered_inventory_limitations: dict[ObjectKey, tuple[_OrderedInventoryLimitation, ...]] = {}
        for candidate in modules.values():
            for key, conditions in candidate.object_limitations.items():
                object_limitations[key] = _merge_discovery_conditions(
                    object_limitations.get(key, ()), tuple(conditions)
                )
            for key, conditions in candidate.inventory_only_limitations.items():
                inventory_only_limitations[key] = _merge_discovery_conditions(
                    inventory_only_limitations.get(key, ()), tuple(conditions)
                )
            for key, limitations in candidate.ordered_inventory_limitations.items():
                ordered_inventory_limitations[key] = _merge_ordered_limitations(
                    ordered_inventory_limitations.get(key, ()), tuple(limitations)
                )
        found: list[Endpoint] = []
        inventory_limitations: tuple[EndpointDiscoveryCondition, ...] = (
            tuple(parse_failures) if self.app_path.is_dir() else ()
        )

        def visit(
            owner: ObjectKey,
            inherited: str,
            cutoff: int | None,
            limitation_cutoff: tuple[str, int] | None,
            stack: frozenset[ObjectKey],
            inherited_conditions: tuple[EndpointDiscoveryCondition, ...],
        ) -> None:
            nonlocal inventory_limitations
            if owner in stack:
                return
            item = objects[owner]
            prefix = _join_paths(inherited, item.prefix)
            object_conditions = _merge_discovery_conditions(
                inherited_conditions,
                item.discovery_conditions,
                object_limitations.get(owner, ()),
            )
            active_ordered_limitations = tuple(
                limitation
                for limitation in ordered_inventory_limitations.get(owner, ())
                if (
                    limitation_cutoff is None
                    or limitation.origin_module != limitation_cutoff[0]
                    or limitation.order <= limitation_cutoff[1]
                )
            )
            ordered_conditions = tuple(
                limitation.condition for limitation in active_ordered_limitations
            )
            inventory_limitations = _merge_discovery_conditions(
                inventory_limitations,
                object_conditions,
                inventory_only_limitations.get(owner, ()),
                ordered_conditions,
            )
            for route in routes_by_owner.get(owner, []):
                if cutoff is not None and route.line > cutoff:
                    continue
                route_effect_conditions = tuple(
                    limitation.condition
                    for limitation in active_ordered_limitations
                    if limitation.endpoint_impact == "all"
                    or (
                        limitation.endpoint_impact == "prior"
                        and (limitation.origin_module != owner[0] or route.line <= limitation.order)
                    )
                    or (
                        limitation.endpoint_impact == "subsequent"
                        and (limitation.origin_module != owner[0] or route.line >= limitation.order)
                    )
                )
                discovery_conditions = _merge_discovery_conditions(
                    object_conditions,
                    route.discovery_conditions,
                    route_effect_conditions,
                )
                found.append(
                    Endpoint(
                        path=_join_paths(prefix, route.path),
                        methods=[EndpointMethod(method) for method in route.methods],
                        handler=route.handler,
                        discovery_status=(
                            EndpointDiscoveryStatus.CONDITIONAL
                            if discovery_conditions
                            else EndpointDiscoveryStatus.ESTABLISHED
                        ),
                        discovery_conditions=discovery_conditions,
                    )
                )
            for edge in edges_by_parent.get(owner, []):
                if cutoff is not None and edge.line > cutoff:
                    continue
                edge_effect_conditions = tuple(
                    limitation.condition
                    for limitation in active_ordered_limitations
                    if limitation.endpoint_impact == "all"
                    or (
                        limitation.endpoint_impact == "prior"
                        and (limitation.origin_module != owner[0] or edge.line <= limitation.order)
                    )
                    or (
                        limitation.endpoint_impact == "subsequent"
                        and (limitation.origin_module != owner[0] or edge.line >= limitation.order)
                    )
                )
                visit(
                    edge.child,
                    _join_paths(prefix, edge.prefix),
                    edge.child_cutoff,
                    edge.limitation_cutoff,
                    stack | {owner},
                    _merge_discovery_conditions(
                        object_conditions,
                        edge_effect_conditions,
                    ),
                )

        for root in sorted(set(roots)):
            visit(root, "", None, None, frozenset(), ())
        endpoints = sorted(
            found,
            key=lambda endpoint: (
                endpoint.identifier,
                str(endpoint.handler.file_path),
                endpoint.handler.line_number,
            ),
        )
        return EndpointInventory(
            endpoints=endpoints,
            status=(
                InventoryStatus.CONDITIONAL
                if inventory_limitations
                else InventoryStatus.ESTABLISHED
            ),
            limitations=inventory_limitations,
        )

    def _source_root(self) -> Path:
        if self.app_path.is_dir():
            return self.app_path
        package = self.app_path.parent
        while (package / "__init__.py").exists():
            package = package.parent
        return package

    def _find_python_files(self, root: Path) -> list[Path]:
        if self.app_path.is_dir():
            return sorted(root.rglob("*.py"))
        # Parsing project-local files is execution-free. Exact root selection below
        # prevents unrelated modules from becoming public endpoints.
        return sorted(root.rglob("*.py"))

    def _load_modules(
        self,
    ) -> tuple[dict[str, _Module], str | None, tuple[EndpointDiscoveryCondition, ...]]:
        root = self._source_root()
        modules: dict[str, _Module] = {}
        entry_module: str | None = None
        parse_failures: list[EndpointDiscoveryCondition] = []
        try:
            paths = self._find_python_files(root)
        except OSError as error:
            return (
                {},
                None,
                (
                    EndpointDiscoveryCondition(
                        source_path=self.app_path,
                        source_line=1,
                        reason=f"project-local Python sources could not be enumerated: {error}",
                    ),
                ),
            )
        for path in paths:
            try:
                with tokenize.open(path) as source_file:
                    source = source_file.read()
                tree = ast.parse(source, filename=str(path))
            except (OSError, SyntaxError, UnicodeError) as error:
                parse_failures.append(
                    EndpointDiscoveryCondition(
                        source_path=path.resolve(),
                        source_line=max(getattr(error, "lineno", 1) or 1, 1),
                        reason="project-local Python module could not be read, decoded, or parsed",
                    )
                )
                continue
            relative = path.relative_to(root).with_suffix("")
            parts = list(relative.parts)
            is_package = bool(parts and parts[-1] == "__init__")
            if is_package:
                parts.pop()
            name = ".".join(parts) or path.parent.name
            modules[name] = _Module(name, path, tree, is_package)
            if self.app_path.is_file() and path.resolve() == self.app_path:
                entry_module = name
        return modules, entry_module, tuple(parse_failures)

    def _module_aliases(self, modules: dict[str, _Module]) -> dict[str, str]:
        aliases: dict[str, str] = {}
        root_name = self._source_root().name
        for name in modules:
            aliases[name] = name
            aliases[f"{root_name}.{name}"] = name
        return aliases

    def _collect_symbols(  # noqa: PLR0912, PLR0915 - ordered module interpreter
        self,
        module: _Module,
        aliases: dict[str, str],
        modules: dict[str, _Module],
    ) -> None:
        evaluate_annotations = not _uses_future_annotations(module.tree)

        def invalidate_additional_bindings(
            node: ast.AST,
            excluded: frozenset[str] = frozenset(),
        ) -> None:
            candidate_line = getattr(node, "end_lineno", None) or getattr(node, "lineno", 1)
            binding_line = candidate_line if isinstance(candidate_line, int) else 1
            for name in (
                _scope_bound_names(
                    node,
                    evaluate_annotations=evaluate_annotations,
                )
                - excluded
            ):
                self._invalidate_binding(module, name, binding_line)

        for node in module.tree.body:
            if isinstance(node, ast.ImportFrom):
                target_module = self._absolute_import(module, node)
                for alias in node.names:
                    local = alias.asname or alias.name
                    module.import_lines[local] = node.lineno
                    module.functions.pop(local, None)
                    submodule = aliases.get(f"{target_module}.{alias.name}")
                    package_name = aliases.get(target_module, target_module)
                    package = modules.get(package_name)
                    package_exports_symbol = package is not None and _module_binds_name(
                        package.tree, alias.name
                    )
                    if submodule in modules and not package_exports_symbol:
                        module.module_imports[local] = submodule
                        binding = _ImportBinding(node.lineno, submodule)
                    else:
                        module.imports[local] = (target_module, alias.name)
                        binding = _ImportBinding(node.lineno, target_module, alias.name)
                    module.import_bindings.setdefault(local, []).append(binding)
                    if node.module == "fastapi" and alias.name == "FastAPI":
                        module.fastapi_names.add(local)
                    if node.module == "fastapi" and alias.name == "APIRouter":
                        module.router_names.add(local)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    module.import_lines[local] = node.lineno
                    module.functions.pop(local, None)
                    imported_module = alias.name if alias.asname else alias.name.split(".")[0]
                    module.import_bindings.setdefault(local, []).append(
                        _ImportBinding(node.lineno, imported_module)
                    )
                    module.module_imports[local] = aliases.get(imported_module, imported_module)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                module.functions[node.name] = node
                module.function_history.setdefault(node.name, []).append(node)
                module.assignments.setdefault(node.name, []).append(node.lineno)
                invalidate_additional_bindings(node, frozenset({node.name}))
            elif isinstance(node, ast.ClassDef):
                module.assignments.setdefault(node.name, []).append(node.lineno)
                module.functions.pop(node.name, None)
                invalidate_additional_bindings(node, frozenset({node.name}))
                binding_line = node.end_lineno or node.lineno
                for name in _class_global_bound_names(
                    node,
                    evaluate_annotations=evaluate_annotations,
                ):
                    self._invalidate_binding(module, name, binding_line)
            elif isinstance(node, ast.If):
                binding_line = node.end_lineno or node.lineno
                conditional_name = self._exhaustive_conditional_app_binding(node, module)
                bound_names = _scope_bound_names(
                    node,
                    evaluate_annotations=evaluate_annotations,
                )
                if conditional_name is not None:
                    bound_names.discard(conditional_name)
                    self._invalidate_binding(module, conditional_name, binding_line)
                    item = _Object(
                        key=(module.name, f"{conditional_name}@{_node_token(node)}"),
                        variable=conditional_name,
                        kind="app",
                        prefix="",
                        line=binding_line,
                    )
                    module.objects.setdefault(conditional_name, []).append(item)
                for name in bound_names:
                    self._invalidate_binding(module, name, binding_line)
            elif isinstance(
                node,
                (
                    ast.For,
                    ast.AsyncFor,
                    ast.While,
                    ast.Try,
                    ast.With,
                    ast.AsyncWith,
                    ast.Match,
                ),
            ) or _is_try_star(node):
                binding_line = node.end_lineno or node.lineno
                for name in _scope_bound_names(
                    node,
                    evaluate_annotations=evaluate_annotations,
                ):
                    self._invalidate_binding(module, name, binding_line)
            elif isinstance(node, ast.AugAssign):
                binding_line = node.end_lineno or node.lineno
                for name in _bound_names(node.target):
                    self._invalidate_binding(module, name, binding_line)
            elif isinstance(node, ast.Expr) or _is_type_alias(node):
                invalidate_additional_bindings(node)
            elif isinstance(node, ast.Delete):
                for target in node.targets:
                    for name in _bound_names(target):
                        module.assignments.setdefault(name, []).append(node.lineno)
                        module.functions.pop(name, None)
                        module.strings.setdefault(name, []).append((node.lineno, None))
                        module.fastapi_names.discard(name)
                        module.router_names.discard(name)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                assigned_name = _assignment_name(node)
                value = node.value
                if assigned_name is None or value is None:
                    targets: list[ast.expr] = (
                        [node.target] if isinstance(node, ast.AnnAssign) else node.targets
                    )
                    target_names: set[str] = set()
                    for target in targets:
                        for name in _bound_names(target):
                            target_names.add(name)
                            module.assignments.setdefault(name, []).append(node.lineno)
                            module.functions.pop(name, None)
                    invalidate_additional_bindings(node, frozenset(target_names))
                    continue
                module.assignments.setdefault(assigned_name, []).append(node.lineno)
                module.functions.pop(assigned_name, None)
                string = self._literal_string(value, module, node.lineno)
                module.strings.setdefault(assigned_name, []).append((node.lineno, string))
                constructor = self._constructor_kind(value, module, node.lineno)
                if constructor is not None:
                    assert isinstance(value, ast.Call)
                    prefix = self._keyword_string(value, "prefix", module, node.lineno) or ""
                    item = _Object(
                        key=(module.name, f"{assigned_name}@{_node_token(node)}"),
                        variable=assigned_name,
                        kind=constructor,
                        prefix=prefix,
                        line=node.lineno,
                    )
                    module.objects.setdefault(assigned_name, []).append(item)
                elif isinstance(value, ast.Call):
                    # Resolve candidate factories only after every module's symbols
                    # are collected, so module iteration order cannot affect results.
                    module.factory_calls.append(_FactoryCall(assigned_name, node.lineno, value))
                # Python assignments can shadow imported constructors. Constructor
                # recognition after this statement must follow the rebound name.
                module.fastapi_names.discard(assigned_name)
                module.router_names.discard(assigned_name)
                invalidate_additional_bindings(node, frozenset({assigned_name}))

    @staticmethod
    def _invalidate_binding(module: _Module, name: str, line: int) -> None:
        module.assignments.setdefault(name, []).append(line)
        module.functions.pop(name, None)
        module.strings.setdefault(name, []).append((line, None))
        module.fastapi_names.discard(name)
        module.router_names.discard(name)

    def _exhaustive_conditional_app_binding(self, node: ast.If, module: _Module) -> str | None:
        """Return one app name bound by every assignment-only if/elif/else leaf."""
        branches: list[list[ast.stmt]] = []
        current = node
        while True:
            if any(isinstance(item, ast.NamedExpr) for item in ast.walk(current.test)):
                return None
            branches.append(current.body)
            if len(current.orelse) == 1 and isinstance(current.orelse[0], ast.If):
                current = current.orelse[0]
                continue
            if not current.orelse:
                return None
            branches.append(current.orelse)
            break
        assigned_names: list[str] = []
        for branch in branches:
            if len(branch) != 1 or not isinstance(branch[0], (ast.Assign, ast.AnnAssign)):
                return None
            statement = branch[0]
            assigned_name = _assignment_name(statement)
            if assigned_name is None or statement.value is None:
                return None
            if self._constructor_kind(statement.value, module, statement.lineno) != "app":
                return None
            assigned_names.append(assigned_name)
        return assigned_names[0] if len(set(assigned_names)) == 1 else None

    def _latest_assignment(self, module: _Module, name: str, line: int) -> int | None:
        eligible = [item for item in module.assignments.get(name, []) if item <= line]
        if not eligible or eligible.count(eligible[-1]) > 1:
            return None
        return eligible[-1]

    def _latest_binding_line(self, module: _Module, name: str, line: int) -> int | None:
        candidates = [
            *(item for item in module.assignments.get(name, []) if item <= line),
            *(item.line for item in module.import_bindings.get(name, []) if item.line <= line),
        ]
        return max(candidates) if candidates else None

    def _import_binding_at(self, module: _Module, name: str, line: int) -> _ImportBinding | None:
        eligible = [item for item in module.import_bindings.get(name, []) if item.line <= line]
        if not eligible:
            return None
        binding = eligible[-1]
        if sum(item.line == binding.line for item in eligible) != 1:
            return None
        assigned_lines = [item for item in module.assignments.get(name, []) if item <= line]
        return binding if not assigned_lines or binding.line > max(assigned_lines) else None

    def _function_at(
        self, module: _Module, name: str, line: int
    ) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        eligible = [item for item in module.function_history.get(name, []) if item.lineno <= line]
        if not eligible:
            return None
        function = eligible[-1]
        return (
            function if self._latest_binding_line(module, name, line) == function.lineno else None
        )

    def _factory_target(
        self,
        value: ast.expr,
        module: _Module,
        aliases: dict[str, str],
        modules: dict[str, _Module],
        line: int,
    ) -> tuple[_Module, ast.FunctionDef | ast.AsyncFunctionDef] | None:
        if not isinstance(value, ast.Call):
            return None
        if isinstance(value.func, ast.Name):
            local = self._function_at(module, value.func.id, line)
            if local is not None:
                return module, local
            binding = self._import_binding_at(module, value.func.id, line)
            if binding is not None and binding.symbol is not None:
                target = modules.get(aliases.get(binding.module, binding.module))
                if target is not None:
                    function = self._function_at(target, binding.symbol, 2**31 - 1)
                    if function is not None:
                        return target, function
        elif isinstance(value.func, ast.Attribute) and isinstance(value.func.value, ast.Name):
            binding = self._import_binding_at(module, value.func.value.id, line)
            target_name = binding.module if binding is not None and binding.symbol is None else ""
            target = modules.get(aliases.get(target_name, target_name))
            if target is not None:
                function = self._function_at(target, value.func.attr, 2**31 - 1)
                if function is not None:
                    return target, function
        return None

    def _constructor_kind(self, value: ast.expr, module: _Module, line: int) -> ObjectKind | None:
        if not isinstance(value, ast.Call):
            return None

        if isinstance(value.func, ast.Name):
            binding = self._import_binding_at(module, value.func.id, line)
            imported = (binding.module, binding.symbol) if binding is not None else None
            if imported == ("fastapi", "FastAPI"):
                return "app"
            if imported == ("fastapi", "APIRouter"):
                return "router"
        if isinstance(value.func, ast.Attribute) and isinstance(value.func.value, ast.Name):
            binding = self._import_binding_at(module, value.func.value.id, line)
            imported_module = (
                binding.module if binding is not None and binding.symbol is None else None
            )
            if imported_module == "fastapi":
                if value.func.attr == "FastAPI":
                    return "app"
                if value.func.attr == "APIRouter":
                    return "router"
        return None

    def _object_at(self, module: _Module, name: str, line: int | None) -> _Object | None:
        history = module.objects.get(name, [])
        eligible = history if line is None else [item for item in history if item.line <= line]
        if not eligible:
            return None
        assignments = module.assignments.get(name, [])
        eligible_assignments = (
            assignments if line is None else [item for item in assignments if item <= line]
        )
        item = eligible[-1]
        if eligible_assignments.count(eligible_assignments[-1]) > 1:
            return None
        latest_binding = self._latest_binding_line(
            module, name, line if line is not None else 2**31 - 1
        )
        return item if eligible_assignments and item.line == latest_binding else None

    def _collect_factory_graphs(
        self,
        module: _Module,
        aliases: dict[str, str],
        modules: dict[str, _Module],
        *,
        explicit_binding: tuple[str, str] | None,
    ) -> None:
        for call in module.factory_calls:
            call_token = _node_token(call.call)
            desired_key = (module.name, f"{call.variable}@{call_token}")
            if any(
                item.key == desired_key for history in module.objects.values() for item in history
            ):
                continue
            target = self._factory_target(call.call, module, aliases, modules, call.line)
            if target is None:
                continue
            definition_module, function = target
            resolve_call_argument: Callable[[ast.expr], str | None] = partial(
                self._literal_string, module=module, line=call.line
            )

            graph = self._summarize_factory(
                definition_module,
                function,
                aliases,
                modules,
                desired_key=desired_key,
                desired_variable=call.variable,
                call_line=call.line,
                call_order=(
                    _line_end_order(call.line) if call.line >= 2**31 - 1 else _node_order(call.call)
                ),
                namespace=f"{module.name}:{call.variable}@{call_token}",
                stack=frozenset(),
                call=call.call,
                argument_resolver=resolve_call_argument,
                allow_conditional=explicit_binding == (module.name, call.variable),
            )
            if graph is None:
                continue
            history = module.objects.setdefault(call.variable, [])
            root = _Object(
                graph.root.key,
                graph.root.variable,
                graph.root.kind,
                graph.root.prefix,
                call.line,
                graph.root.discovery_conditions,
            )
            history.append(root)
            history.sort(key=lambda item: item.line)
            module.factory_objects.extend(graph.objects)
            module.factory_routes.extend(graph.routes)
            module.factory_edges.extend(graph.edges)

    def _bind_factory_arguments(
        self,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        call: ast.Call,
        resolve_call: Callable[[ast.expr], str | None],
        resolve_default: Callable[[ast.expr], str | None],
    ) -> dict[str, str] | None:
        """Bind a safe subset of literal factory arguments."""
        if function.args.vararg or function.args.kwarg:
            return None
        positional_only = list(function.args.posonlyargs)
        positional = [*positional_only, *function.args.args]
        keyword_only = list(function.args.kwonlyargs)
        if len(call.args) > len(positional) or any(
            keyword.arg is None for keyword in call.keywords
        ):
            return None
        expressions: dict[str, ast.expr] = {
            parameter.arg: argument
            for parameter, argument in zip(positional, call.args, strict=False)
        }
        known = {parameter.arg for parameter in [*positional, *keyword_only]}
        for keyword in call.keywords:
            assert keyword.arg is not None
            if (
                keyword.arg not in known
                or keyword.arg in expressions
                or keyword.arg in {parameter.arg for parameter in positional_only}
            ):
                return None
            expressions[keyword.arg] = keyword.value
        defaults: dict[str, ast.expr] = {}
        if function.args.defaults:
            defaults.update(
                {
                    parameter.arg: default
                    for parameter, default in zip(
                        positional[-len(function.args.defaults) :],
                        function.args.defaults,
                        strict=True,
                    )
                }
            )
        defaults.update(
            {
                parameter.arg: default
                for parameter, default in zip(keyword_only, function.args.kw_defaults, strict=True)
                if default is not None
            }
        )
        bound: dict[str, str] = {}
        for parameter in [*positional, *keyword_only]:
            expression = expressions.get(parameter.arg)
            is_default = expression is None
            if expression is None:
                expression = defaults.get(parameter.arg)
            if expression is None:
                return None
            value = resolve_default(expression) if is_default else resolve_call(expression)
            if value is None:
                return None
            bound[parameter.arg] = value
        return bound

    def _summarize_factory(  # noqa: PLR0911, PLR0912, PLR0915 - safe subset
        self,
        module: _Module,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        aliases: dict[str, str],
        modules: dict[str, _Module],
        *,
        desired_key: ObjectKey,
        desired_variable: str,
        call_line: int,
        call_order: int,
        namespace: str,
        stack: frozenset[str],
        call: ast.Call,
        argument_resolver: Callable[[ast.expr], str | None] | None = None,
        allow_conditional: bool = False,
    ) -> _FactoryGraph | None:
        function_identity = f"{module.name}.{function.name}@{_node_token(function)}"
        if (
            isinstance(function, ast.AsyncFunctionDef)
            or function.decorator_list
            or function_identity in stack
        ):
            return None
        resolver = argument_resolver or (
            lambda expression: self._literal_string(expression, module, call_line)
        )
        bound_arguments = self._bind_factory_arguments(
            function,
            call,
            resolver,
            lambda expression: self._literal_string(expression, module, function.lineno),
        )
        if bound_arguments is None:
            return None
        meaningful = [
            statement
            for statement in function.body
            if not isinstance(statement, ast.Pass)
            and not (
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Constant)
                and isinstance(statement.value.value, str)
            )
        ]
        if not meaningful or not isinstance(meaningful[-1], ast.Return):
            return None
        returns = _returns_outside_nested_functions(function.body)
        if len(returns) != 1 or not isinstance(returns[0].value, ast.Name):
            return None
        returned_name = returns[0].value.id
        returned_binding_tokens = [
            _node_token(statement)
            for statement in meaningful
            if isinstance(statement, (ast.Assign, ast.AnnAssign))
            and _assignment_name(statement) == returned_name
        ]
        if not returned_binding_tokens:
            return None
        final_returned_binding = returned_binding_tokens[-1]

        local_objects: dict[str, _Object] = {}
        local_strings: dict[str, str | None] = dict(bound_arguments)
        local_bindings = _function_bindings(function)
        local_functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        emitted_objects: list[_Object] = []
        routes: list[_Route] = []
        edges: list[_Edge] = []
        factory_conditions: list[EndpointDiscoveryCondition] = []
        module_object_keys = {
            item.key
            for candidate_module in modules.values()
            for history in candidate_module.objects.values()
            for item in history
        }

        def literal(expression: ast.expr | None, line: int) -> str | None:
            if isinstance(expression, ast.Name):
                if expression.id in local_strings:
                    return local_strings[expression.id]
                if expression.id in local_bindings:
                    return None
            if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Add):
                left = literal(expression.left, line)
                right = literal(expression.right, line)
                return left + right if left is not None and right is not None else None
            return self._literal_string(expression, module, call_line)

        def object_for(expression: ast.expr | None) -> _Object | None:
            if isinstance(expression, ast.Name):
                if expression.id in local_objects:
                    return local_objects[expression.id]
                if expression.id in local_bindings:
                    return None
            if (
                isinstance(expression, ast.Attribute)
                and isinstance(expression.value, ast.Name)
                and expression.value.id in local_bindings
            ):
                return None
            return self._resolve_object(expression, module, aliases, modules, call_line)

        def snapshot_local_object(item: _Object, operation: ast.AST) -> _Object:
            """Freeze current local routes/edges at an include operation."""
            snapshot_key = (
                module.name,
                f"{namespace}:snapshot:{item.variable}@{_node_token(operation)}",
            )
            snapshot = _Object(
                snapshot_key,
                item.variable,
                item.kind,
                item.prefix,
                call_line,
                item.discovery_conditions,
            )
            emitted_objects.append(snapshot)
            routes.extend(
                _Route(
                    snapshot_key,
                    route.path,
                    route.methods,
                    route.handler,
                    call_order,
                    route.discovery_conditions,
                )
                for route in list(routes)
                if route.owner == item.key
            )
            edges.extend(
                _Edge(
                    snapshot_key,
                    edge.child,
                    edge.prefix,
                    call_order,
                    edge.child_cutoff,
                    edge.limitation_cutoff,
                    edge.mode,
                )
                for edge in list(edges)
                if edge.parent == item.key
            )
            return snapshot

        def handler_for(expression: ast.expr | None) -> HandlerInfo | None:
            if isinstance(expression, ast.Name):
                if expression.id in local_functions:
                    return self._handler(module, local_functions[expression.id])
                if expression.id in local_bindings:
                    return None
            return self._resolve_handler(expression, module, aliases, modules, call_line)

        def conditionalize(statement: ast.AST, reason: str) -> None:
            condition = EndpointDiscoveryCondition(
                source_path=module.path,
                source_line=getattr(statement, "lineno", function.lineno),
                reason=reason,
            )
            if condition not in factory_conditions:
                factory_conditions.append(condition)

        def modeled_state_assignment(statement: ast.Assign | ast.AnnAssign) -> bool:
            targets = (
                [statement.target] if isinstance(statement, ast.AnnAssign) else statement.targets
            )
            if len(targets) != 1:
                return False
            target = targets[0]
            return (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Attribute)
                and target.value.attr == "state"
                and isinstance(target.value.value, ast.Name)
                and target.value.value.id in local_objects
            )

        def unresolved_call_touches_modeled(call_node: ast.Call) -> bool:
            modeled = set(local_objects)
            if isinstance(call_node.func, ast.Attribute) and any(
                isinstance(descendant, ast.Name) and descendant.id in modeled
                for descendant in ast.walk(call_node.func.value)
            ):
                return True
            return any(
                isinstance(descendant, ast.Name) and descendant.id in modeled
                for argument in [
                    *call_node.args,
                    *(keyword.value for keyword in call_node.keywords),
                ]
                for descendant in ast.walk(argument)
            )

        def touches_modeled_binding(node: ast.AST) -> bool:
            modeled = set(local_objects)

            def inspect(current: ast.AST) -> bool:  # noqa: PLR0911
                if isinstance(
                    current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
                ):
                    return False
                if (
                    isinstance(current, ast.Name)
                    and current.id in modeled
                    and isinstance(current.ctx, (ast.Store, ast.Del))
                ):
                    return True
                if (
                    isinstance(current, ast.Attribute)
                    and isinstance(current.ctx, (ast.Store, ast.Del))
                    and any(
                        isinstance(descendant, ast.Name) and descendant.id in modeled
                        for descendant in ast.walk(current.value)
                    )
                ):
                    return True
                if isinstance(current, (ast.Assign, ast.AnnAssign)):
                    value = current.value
                    if (
                        isinstance(current, ast.Assign)
                        and len(current.targets) != 1
                        and value is not None
                        and any(
                            isinstance(descendant, ast.Name) and descendant.id in modeled
                            for descendant in ast.walk(value)
                        )
                    ):
                        return True
                    if value is not None and any(
                        isinstance(descendant, ast.Name) and descendant.id in modeled
                        for descendant in ast.walk(value)
                    ):
                        target = (
                            current.target
                            if isinstance(current, ast.AnnAssign)
                            else current.targets[0]
                        )
                        if not isinstance(target, ast.Name):
                            return True
                if isinstance(current, ast.Call):
                    if isinstance(current.func, ast.Name) and current.func.id in local_functions:
                        return True
                    if isinstance(current.func, ast.Attribute) and any(
                        isinstance(descendant, ast.Name) and descendant.id in modeled
                        for descendant in ast.walk(current.func.value)
                    ):
                        return True
                    arguments = [
                        *current.args,
                        *(keyword.value for keyword in current.keywords),
                    ]
                    if any(
                        any(
                            isinstance(descendant, ast.Name) and descendant.id in modeled
                            for descendant in ast.walk(argument)
                        )
                        for argument in arguments
                    ):
                        return True
                return any(inspect(child) for child in ast.iter_child_nodes(current))

            return inspect(node)

        for statement in meaningful:
            if isinstance(statement, ast.Return):
                break
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                assigned = _assignment_name(statement)
                value = statement.value
                if modeled_state_assignment(statement):
                    if not allow_conditional:
                        return None
                    if value is not None and not isinstance(value, ast.Constant):
                        conditionalize(
                            statement,
                            "unresolved app.state value may have dynamic initialization semantics",
                        )
                    continue
                if assigned is None or value is None:
                    if touches_modeled_binding(statement):
                        return None
                    continue
                aliased_object = object_for(value)
                if aliased_object is not None:
                    local_objects[assigned] = aliased_object
                    local_strings.pop(assigned, None)
                    continue

                constructor_receiver = None
                if isinstance(value, ast.Call):
                    if isinstance(value.func, ast.Name):
                        constructor_receiver = value.func.id
                    elif isinstance(value.func, ast.Attribute) and isinstance(
                        value.func.value, ast.Name
                    ):
                        constructor_receiver = value.func.value.id
                constructor = (
                    None
                    if constructor_receiver in local_bindings
                    else self._constructor_kind(value, module, call_line)
                )
                if constructor is not None:
                    assert isinstance(value, ast.Call)
                    statement_token = _node_token(statement)
                    key = (
                        desired_key
                        if assigned == returned_name and statement_token == final_returned_binding
                        else (module.name, f"{namespace}:{assigned}@{statement_token}")
                    )
                    variable = desired_variable if assigned == returned_name else assigned
                    prefix = literal(_keyword_expr(value, "prefix"), statement.lineno) or ""
                    item = _Object(key, variable, constructor, prefix, call_line)
                    local_objects[assigned] = item
                    local_strings.pop(assigned, None)
                    if key != desired_key:
                        emitted_objects.append(item)
                    continue

                helper_target: tuple[_Module, ast.FunctionDef | ast.AsyncFunctionDef] | None = None
                if isinstance(value, ast.Call):
                    if isinstance(value.func, ast.Name) and value.func.id in local_functions:
                        helper_target = module, local_functions[value.func.id]
                    elif not (
                        isinstance(value.func, ast.Name) and value.func.id in local_bindings
                    ) and not (
                        isinstance(value.func, ast.Attribute)
                        and isinstance(value.func.value, ast.Name)
                        and value.func.value.id in local_bindings
                    ):
                        helper_target = self._factory_target(
                            value, module, aliases, modules, call_line
                        )
                if helper_target is not None:
                    assert isinstance(value, ast.Call)
                    helper_module, helper = helper_target
                    nested_line = statement.lineno

                    def resolve_nested_argument(
                        expression: ast.expr, line: int = nested_line
                    ) -> str | None:
                        return literal(expression, line)

                    statement_token = _node_token(statement)
                    key = (
                        desired_key
                        if assigned == returned_name and statement_token == final_returned_binding
                        else (module.name, f"{namespace}:{assigned}@{statement_token}")
                    )
                    nested = self._summarize_factory(
                        helper_module,
                        helper,
                        aliases,
                        modules,
                        desired_key=key,
                        desired_variable=(
                            desired_variable if assigned == returned_name else assigned
                        ),
                        call_line=(call_line if helper_module.name == module.name else 2**31 - 1),
                        call_order=call_order,
                        namespace=f"{namespace}:{assigned}@{statement_token}",
                        stack=stack | {function_identity},
                        call=value,
                        argument_resolver=resolve_nested_argument,
                        allow_conditional=allow_conditional,
                    )
                    if nested is not None:
                        local_objects[assigned] = nested.root
                        if nested.root.key != desired_key:
                            emitted_objects.append(nested.root)
                        emitted_objects.extend(nested.objects)
                        routes.extend(nested.routes)
                        edges.extend(nested.edges)
                        continue
                if any(
                    isinstance(descendant, ast.Name) and descendant.id in local_objects
                    for descendant in ast.walk(value)
                ):
                    return None
                local_objects.pop(assigned, None)
                local_strings[assigned] = literal(value, statement.lineno)
                continue
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                local_functions[statement.name] = statement
                handler = self._handler(module, statement)
                for decorator in statement.decorator_list:
                    if not (
                        isinstance(decorator, ast.Call)
                        and isinstance(decorator.func, ast.Attribute)
                    ):
                        continue
                    owner = object_for(decorator.func.value)
                    method = decorator.func.attr
                    if owner is None or (method not in self.HTTP_METHODS and method != "api_route"):
                        continue
                    path_expr = (
                        decorator.args[0] if decorator.args else _keyword_expr(decorator, "path")
                    )
                    path = literal(path_expr, statement.lineno)
                    if path is None:
                        continue
                    methods_expr = _keyword_expr(decorator, "methods")
                    methods = (
                        _literal_methods(methods_expr)
                        if method == "api_route" and methods_expr is not None
                        else (("GET",) if method == "api_route" else (method.upper(),))
                    )
                    if method == "websocket":
                        methods = ("WEBSOCKET",)
                    if methods:
                        routes.append(
                            _Route(
                                owner.key,
                                path,
                                methods,
                                handler,
                                call_order,
                            )
                        )
                continue
            if (
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Call)
                and not isinstance(statement.value.func, ast.Attribute)
            ):
                if allow_conditional and unresolved_call_touches_modeled(statement.value):
                    conditionalize(
                        statement,
                        "unresolved call may mutate or escape the explicitly selected app",
                    )
                    continue
                if touches_modeled_binding(statement):
                    return None
                continue
            if not (
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Call)
                and isinstance(statement.value.func, ast.Attribute)
            ):
                # Ignore unrelated setup, but reject control-flow or helpers that
                # can rebind/mutate an object whose public routes we are proving.
                if touches_modeled_binding(statement):
                    return None
                continue
            call = statement.value
            call_function = call.func
            if not isinstance(call_function, ast.Attribute):
                continue
            parent = object_for(call_function.value)
            if parent is None:
                if allow_conditional and unresolved_call_touches_modeled(call):
                    conditionalize(
                        statement,
                        "unresolved call may mutate or escape the explicitly selected app",
                    )
                    continue
                if touches_modeled_binding(statement):
                    return None
                continue
            if call_function.attr == "include_router":
                child_expr = call.args[0] if call.args else _keyword_expr(call, "router")
                child = object_for(child_expr)
                if child is None or child.kind != "router":
                    if not allow_conditional:
                        return None
                    conditionalize(
                        statement,
                        "unresolved router registration may mutate the explicitly selected app",
                    )
                    continue
                prefix = literal(_keyword_expr(call, "prefix"), statement.lineno) or ""
                cutoff = (
                    call_order
                    if child.key in module_object_keys and child.key[0] == module.name
                    else None
                )
                included_child = (
                    child
                    if child.key in module_object_keys
                    else snapshot_local_object(child, statement)
                )
                edges.append(
                    _Edge(
                        parent.key,
                        included_child.key,
                        prefix,
                        call_order,
                        cutoff,
                        (module.name, call_order),
                        "copy",
                    )
                )
            elif call_function.attr == "mount":
                path_expr = call.args[0] if call.args else _keyword_expr(call, "path")
                child_expr = call.args[1] if len(call.args) > 1 else _keyword_expr(call, "app")
                path = literal(path_expr, statement.lineno)
                child = object_for(child_expr)
                if path is None or child is None or child.kind != "app":
                    if not allow_conditional:
                        return None
                    conditionalize(
                        statement,
                        "unresolved mount may mutate the explicitly selected app",
                    )
                    continue
                # Mount retains this exact object; later name rebinding cannot redirect it.
                edges.append(
                    _Edge(
                        parent.key,
                        child.key,
                        path,
                        call_order,
                        None,
                        None,
                        "live",
                    )
                )
            elif call_function.attr in {
                "add_api_route",
                "add_api_websocket_route",
                "add_websocket_route",
            }:
                path_expr = call.args[0] if call.args else _keyword_expr(call, "path")
                handler_expr = (
                    call.args[1] if len(call.args) > 1 else _keyword_expr(call, "endpoint")
                )
                path = literal(path_expr, statement.lineno)
                imperative_handler = handler_for(handler_expr)
                if call_function.attr == "add_api_route":
                    methods_expr = _keyword_expr(call, "methods")
                    methods = (
                        _literal_methods(methods_expr) if methods_expr is not None else ("GET",)
                    )
                else:
                    methods = ("WEBSOCKET",)
                if path is None or imperative_handler is None or not methods:
                    if not allow_conditional:
                        return None
                    conditionalize(
                        statement,
                        "unresolved imperative route may mutate the explicitly selected app",
                    )
                    continue
                routes.append(
                    _Route(
                        parent.key,
                        path,
                        methods,
                        imperative_handler,
                        call_order,
                    )
                )
            elif call_function.attr not in {
                "add_exception_handler",
                "add_event_handler",
                "add_middleware",
            }:
                if not allow_conditional:
                    return None
                conditionalize(
                    statement,
                    "unresolved call may mutate the explicitly selected app",
                )

        root = local_objects.get(returned_name)
        if root is None:
            return None
        combined_conditions = _merge_discovery_conditions(
            root.discovery_conditions, tuple(factory_conditions)
        )
        if root.key != desired_key:
            old_key = root.key
            root = _Object(
                desired_key,
                desired_variable,
                root.kind,
                root.prefix,
                call_line,
                combined_conditions,
            )
            emitted_objects = [item for item in emitted_objects if item.key != old_key]
            routes = [
                _Route(
                    desired_key if route.owner == old_key else route.owner,
                    route.path,
                    route.methods,
                    route.handler,
                    route.line,
                    route.discovery_conditions,
                )
                for route in routes
            ]
            edges = [
                _Edge(
                    desired_key if edge.parent == old_key else edge.parent,
                    desired_key if edge.child == old_key else edge.child,
                    edge.prefix,
                    edge.line,
                    edge.child_cutoff,
                    edge.limitation_cutoff,
                    edge.mode,
                )
                for edge in edges
            ]
        elif combined_conditions != root.discovery_conditions:
            root = _Object(
                root.key,
                root.variable,
                root.kind,
                root.prefix,
                root.line,
                combined_conditions,
            )
            emitted_objects = [root if item.key == root.key else item for item in emitted_objects]
        return _FactoryGraph(root, emitted_objects, routes, edges)

    def _apply_bootstrap_registration(  # noqa: PLR0915
        self,
        module: _Module,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        root: _Object,
        aliases: dict[str, str],
        modules: dict[str, _Module],
        routes: list[_Route],
        edges: list[_Edge],
    ) -> None:
        """Interpret one explicitly attested, bounded registration call slice."""
        budget = [max(32, min(512, len(modules) * 8))]
        operation_order = [_line_end_order(2**31 - 2)]

        def next_order() -> int:
            operation_order[0] += 1
            return operation_order[0]

        def limit(current_module: _Module, owner: _Object, node: ast.AST, reason: str) -> None:
            self._record_object_limitation(current_module, owner, node, reason)

        def apply(  # noqa: PLR0912, PLR0915
            current_module: _Module,
            current: ast.FunctionDef | ast.AsyncFunctionDef,
            object_env: dict[str, _Object],
            string_env: dict[str, str],
            stack: frozenset[tuple[str, str, int]],
        ) -> None:
            identity = (current_module.name, current.name, current.lineno)
            if (
                budget[0] <= 0
                or identity in stack
                or isinstance(current, ast.AsyncFunctionDef)
                or current.decorator_list
                or current.args.vararg is not None
                or current.args.kwarg is not None
                or any(isinstance(item, (ast.Yield, ast.YieldFrom)) for item in ast.walk(current))
            ):
                for owner in set(object_env.values()):
                    limit(
                        current_module,
                        owner,
                        current,
                        "bootstrap helper is unsupported or recursive",
                    )
                return
            budget[0] -= 1
            local_objects = dict(object_env)
            local_strings = dict(string_env)
            local_modules: dict[str, _Module] = {}
            local_functions: dict[str, tuple[_Module, ast.FunctionDef | ast.AsyncFunctionDef]] = {}
            local_handlers: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
            global_names: set[str] = set()
            bound_names = {
                parameter.arg
                for parameter in [
                    *current.args.posonlyargs,
                    *current.args.args,
                    *current.args.kwonlyargs,
                ]
            }
            for imported_name in current_module.import_bindings:
                if imported_name in bound_names:
                    continue
                binding = self._import_binding_at(current_module, imported_name, 2**31 - 1)
                if binding is not None and binding.symbol is None:
                    imported = modules.get(aliases.get(binding.module, binding.module))
                    if imported is not None:
                        local_modules[imported_name] = imported

            def object_for(expression: ast.expr | None, line: int) -> _Object | None:
                if isinstance(expression, ast.Name):
                    if expression.id in local_objects:
                        return local_objects[expression.id]
                    if expression.id in bound_names:
                        return None
                    return self._resolve_object(expression, current_module, aliases, modules, line)
                if isinstance(expression, ast.Attribute) and isinstance(expression.value, ast.Name):
                    imported = local_modules.get(expression.value.id)
                    if imported is not None:
                        return self._resolve_exported_object(
                            imported,
                            expression.attr,
                            2**31 - 1,
                            aliases,
                            modules,
                            frozenset(),
                            min(len(modules) + 1, 64),
                        )
                return self._resolve_object(expression, current_module, aliases, modules, line)

            def literal(expression: ast.expr | None, line: int) -> str | None:
                if isinstance(expression, ast.Name) and expression.id in local_strings:
                    return local_strings[expression.id]
                if isinstance(expression, ast.Name) and expression.id in bound_names:
                    return None
                if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Add):
                    left = literal(expression.left, line)
                    right = literal(expression.right, line)
                    return left + right if left is not None and right is not None else None
                return self._literal_string(expression, current_module, line)

            def handler_for(expression: ast.expr | None, line: int) -> HandlerInfo | None:
                if isinstance(expression, ast.Name) and expression.id in local_handlers:
                    handler = local_handlers[expression.id]
                    return (
                        None if handler.decorator_list else self._handler(current_module, handler)
                    )
                return self._resolve_handler(expression, current_module, aliases, modules, line)

            def touches_tracked(node: ast.AST) -> bool:
                tracked = set(local_objects)
                return any(
                    isinstance(item, ast.Name) and item.id in tracked for item in ast.walk(node)
                )

            for statement in current.body:
                if isinstance(statement, (ast.Global, ast.Nonlocal)):
                    global_names.update(statement.names)
                    continue
                if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    local_objects.pop(statement.name, None)
                    local_strings.pop(statement.name, None)
                    local_modules.pop(statement.name, None)
                    bound_names.add(statement.name)
                    local_handlers[statement.name] = statement
                    local_functions[statement.name] = (current_module, statement)
                    continue
                if isinstance(statement, ast.ImportFrom):
                    target_name = self._absolute_import(current_module, statement)
                    for imported_alias in statement.names:
                        if imported_alias.name == "*":
                            for owner in set(local_objects.values()):
                                limit(current_module, owner, statement, "wildcard bootstrap import")
                            continue
                        local = imported_alias.asname or imported_alias.name
                        bound_names.add(local)
                        submodule_name = aliases.get(f"{target_name}.{imported_alias.name}")
                        if submodule_name in modules:
                            local_modules[local] = modules[submodule_name]
                            continue
                        imported_module = modules.get(aliases.get(target_name, target_name))
                        if imported_module is None:
                            continue
                        exported = self._resolve_exported_object(
                            imported_module,
                            imported_alias.name,
                            2**31 - 1,
                            aliases,
                            modules,
                            frozenset(),
                            min(len(modules) + 1, 64),
                        )
                        if exported is not None:
                            local_objects[local] = exported
                            continue
                        imported_function = self._function_at(
                            imported_module, imported_alias.name, 2**31 - 1
                        )
                        if imported_function is not None:
                            local_functions[local] = (
                                imported_module,
                                imported_function,
                            )
                    continue
                if isinstance(statement, ast.Import):
                    for imported_alias in statement.names:
                        local = imported_alias.asname or imported_alias.name.split(".")[0]
                        bound_names.add(local)
                        target_name = aliases.get(imported_alias.name, imported_alias.name)
                        imported_module = modules.get(target_name)
                        if imported_module is not None:
                            local_modules[local] = imported_module
                        local_functions.pop(local, None)
                        local_objects.pop(local, None)
                    continue
                if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                    name = _assignment_name(statement)
                    value = statement.value
                    if name is None or value is None:
                        if touches_tracked(statement):
                            for owner in set(local_objects.values()):
                                limit(
                                    current_module,
                                    owner,
                                    statement,
                                    "unsupported bootstrap assignment",
                                )
                        continue
                    bound_names.add(name)
                    local_functions.pop(name, None)
                    local_modules.pop(name, None)
                    local_handlers.pop(name, None)
                    aliased = object_for(value, statement.lineno)
                    if aliased is not None:
                        if name in global_names:
                            limit(
                                current_module,
                                aliased,
                                statement,
                                "bootstrap object escapes through global assignment",
                            )
                        local_objects[name] = aliased
                        local_strings.pop(name, None)
                    else:
                        escaped = [
                            owner
                            for tracked_name, owner in local_objects.items()
                            if any(
                                isinstance(item, ast.Name) and item.id == tracked_name
                                for item in ast.walk(value)
                            )
                        ]
                        for owner in set(escaped):
                            limit(
                                current_module,
                                owner,
                                statement,
                                "bootstrap object escapes through assignment",
                            )
                        local_objects.pop(name, None)
                        value_string = literal(value, statement.lineno)
                        if value_string is not None:
                            local_strings[name] = value_string
                    continue
                if isinstance(statement, ast.Return):
                    if statement.value is not None and touches_tracked(statement.value):
                        for owner in set(local_objects.values()):
                            limit(
                                current_module,
                                owner,
                                statement,
                                "bootstrap object escapes through return",
                            )
                    break
                if not (isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call)):
                    if touches_tracked(statement):
                        for owner in set(local_objects.values()):
                            limit(
                                current_module,
                                owner,
                                statement,
                                "unsupported bootstrap control flow",
                            )
                    continue
                call = statement.value
                line = statement.lineno
                parent = (
                    object_for(call.func.value, line)
                    if isinstance(call.func, ast.Attribute)
                    else None
                )
                operation = call.func.attr if isinstance(call.func, ast.Attribute) else ""
                registration_operations = {
                    "include_router",
                    "mount",
                    "add_api_route",
                    "add_api_websocket_route",
                    "add_websocket_route",
                }
                if parent is None and operation in registration_operations:
                    limit(
                        current_module,
                        root,
                        statement,
                        "bootstrap registration receiver is unresolved",
                    )
                    continue
                if parent is not None and operation in registration_operations:
                    if any(isinstance(argument, ast.Starred) for argument in call.args) or any(
                        keyword.arg is None for keyword in call.keywords
                    ):
                        limit(
                            current_module,
                            parent,
                            statement,
                            "starred bootstrap registration arguments are unsupported",
                        )
                        continue
                    positional_names = {
                        "include_router": ("router",),
                        "mount": ("path", "app"),
                        "add_api_route": ("path", "endpoint"),
                        "add_api_websocket_route": ("path", "endpoint"),
                        "add_websocket_route": ("path", "endpoint"),
                    }[operation]
                    keyword_names = [keyword.arg for keyword in call.keywords]
                    duplicate_binding = any(
                        name in keyword_names for name in positional_names[: len(call.args)]
                    ) or len(keyword_names) != len(set(keyword_names))
                    if len(call.args) > len(positional_names) or duplicate_binding:
                        limit(
                            current_module,
                            parent,
                            statement,
                            "bootstrap registration arguments are ambiguous",
                        )
                        continue
                    order = next_order()
                    if operation == "include_router":
                        child_expr = call.args[0] if call.args else _keyword_expr(call, "router")
                        child = object_for(child_expr, line)
                        prefix_expr = _keyword_expr(call, "prefix")
                        prefix = "" if prefix_expr is None else literal(prefix_expr, line)
                        if prefix is None:
                            limit(
                                current_module,
                                parent,
                                statement,
                                "bootstrap router prefix is unresolved",
                            )
                        elif child is None or child.kind != "router":
                            limit(
                                current_module, parent, statement, "bootstrap router is unresolved"
                            )
                        else:
                            edges.append(
                                _Edge(
                                    parent.key,
                                    child.key,
                                    prefix,
                                    order,
                                    order,
                                    (current_module.name, order),
                                    "copy",
                                )
                            )
                    elif operation == "mount":
                        path_expr = call.args[0] if call.args else _keyword_expr(call, "path")
                        child_expr = (
                            call.args[1] if len(call.args) > 1 else _keyword_expr(call, "app")
                        )
                        path = literal(path_expr, line)
                        child = object_for(child_expr, line)
                        if path is None or child is None or child.kind != "app":
                            limit(
                                current_module, parent, statement, "bootstrap mount is unresolved"
                            )
                        else:
                            edges.append(
                                _Edge(
                                    parent.key,
                                    child.key,
                                    path,
                                    order,
                                    None,
                                    None,
                                    "live",
                                )
                            )
                    else:
                        path_expr = call.args[0] if call.args else _keyword_expr(call, "path")
                        handler_expr = (
                            call.args[1] if len(call.args) > 1 else _keyword_expr(call, "endpoint")
                        )
                        path = literal(path_expr, line)
                        handler = handler_for(handler_expr, line)
                        methods: tuple[str, ...] = ("WEBSOCKET",)
                        if operation == "add_api_route":
                            methods_expr = _keyword_expr(call, "methods")
                            methods = (
                                _literal_methods(methods_expr)
                                if methods_expr is not None
                                else ("GET",)
                            )
                        if path is None or handler is None or not methods:
                            limit(
                                current_module, parent, statement, "bootstrap route is unresolved"
                            )
                        else:
                            routes.append(_Route(parent.key, path, methods, handler, order))
                    continue

                helper_target: tuple[_Module, ast.FunctionDef | ast.AsyncFunctionDef] | None = None
                if isinstance(call.func, ast.Name):
                    helper_target = local_functions.get(call.func.id)
                    if helper_target is None and call.func.id in bound_names:
                        helper_target = None
                    elif helper_target is None:
                        local_function = self._function_at(current_module, call.func.id, line)
                        if local_function is not None:
                            helper_target = (current_module, local_function)
                    if helper_target is None and call.func.id not in bound_names:
                        helper_target = self._factory_target(
                            call, current_module, aliases, modules, line
                        )
                elif isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
                    imported_module = local_modules.get(call.func.value.id)
                    if imported_module is not None:
                        imported_function = self._function_at(
                            imported_module, call.func.attr, 2**31 - 1
                        )
                        if imported_function is not None:
                            helper_target = (imported_module, imported_function)
                if helper_target is not None:
                    target_module, target_function = helper_target
                    parameters = [
                        *target_function.args.posonlyargs,
                        *target_function.args.args,
                        *target_function.args.kwonlyargs,
                    ]
                    if target_function.args.vararg or target_function.args.kwarg:
                        for owner in set(local_objects.values()):
                            limit(current_module, owner, statement, "variadic bootstrap helper")
                        continue
                    positional_parameters = [
                        *target_function.args.posonlyargs,
                        *target_function.args.args,
                    ]
                    actuals: dict[str, ast.expr] = {
                        parameter.arg: argument
                        for parameter, argument in zip(
                            positional_parameters, call.args, strict=False
                        )
                    }
                    invalid_arguments = len(call.args) > len(positional_parameters) or any(
                        isinstance(argument, ast.Starred) for argument in call.args
                    )
                    positional_only = {
                        parameter.arg for parameter in target_function.args.posonlyargs
                    }
                    known_parameters = {parameter.arg for parameter in parameters}
                    for keyword in call.keywords:
                        if (
                            keyword.arg is None
                            or keyword.arg not in known_parameters
                            or keyword.arg in positional_only
                            or keyword.arg in actuals
                        ):
                            invalid_arguments = True
                        else:
                            actuals[keyword.arg] = keyword.value
                    required_count = len(positional_parameters) - len(target_function.args.defaults)
                    required_parameters = {
                        parameter.arg for parameter in positional_parameters[:required_count]
                    }
                    required_parameters.update(
                        parameter.arg
                        for parameter, default in zip(
                            target_function.args.kwonlyargs,
                            target_function.args.kw_defaults,
                            strict=True,
                        )
                        if default is None
                    )
                    if invalid_arguments or any(
                        parameter not in actuals for parameter in required_parameters
                    ):
                        for owner in set(local_objects.values()):
                            limit(
                                current_module,
                                owner,
                                statement,
                                "bootstrap helper arguments are ambiguous",
                            )
                        continue
                    nested_objects: dict[str, _Object] = {}
                    nested_strings: dict[str, str] = {}
                    positional_defaults = (
                        {
                            parameter.arg: default
                            for parameter, default in zip(
                                positional_parameters[-len(target_function.args.defaults) :],
                                target_function.args.defaults,
                                strict=True,
                            )
                        }
                        if target_function.args.defaults
                        else {}
                    )
                    keyword_defaults = {
                        parameter.arg: default
                        for parameter, default in zip(
                            target_function.args.kwonlyargs,
                            target_function.args.kw_defaults,
                            strict=True,
                        )
                        if default is not None
                    }
                    for parameter in parameters:
                        expression = actuals.get(parameter.arg)
                        uses_default = expression is None
                        if expression is None:
                            expression = positional_defaults.get(
                                parameter.arg, keyword_defaults.get(parameter.arg)
                            )
                        if expression is None:
                            continue
                        actual_object = (
                            self._resolve_object(
                                expression,
                                target_module,
                                aliases,
                                modules,
                                target_function.lineno,
                            )
                            if uses_default
                            else object_for(expression, line)
                        )
                        if actual_object is not None:
                            nested_objects[parameter.arg] = actual_object
                        actual_string = (
                            self._literal_string(expression, target_module, target_function.lineno)
                            if uses_default
                            else literal(expression, line)
                        )
                        if actual_string is not None:
                            nested_strings[parameter.arg] = actual_string
                    if not nested_objects:
                        for owner in set(local_objects.values()):
                            limit(
                                current_module,
                                owner,
                                statement,
                                "helper without tracked object flow may mutate route globals",
                            )
                        continue
                    apply(
                        target_module,
                        target_function,
                        nested_objects,
                        nested_strings,
                        stack | {identity},
                    )
                    continue
                if touches_tracked(call):
                    for owner in set(local_objects.values()):
                        limit(
                            current_module, owner, statement, "unresolved bootstrap object escape"
                        )

        positional = [*function.args.posonlyargs, *function.args.args]
        required = len(positional) - len(function.args.defaults)
        required_keywords = any(default is None for default in function.args.kw_defaults)
        if function.args.vararg or function.args.kwarg or required or required_keywords:
            raise SecureASTExtractorError(
                "bootstrap entry must be safely callable without arguments"
            )
        initial_objects: dict[str, _Object] = {}
        visible_names = {
            *module.objects,
            *module.import_bindings,
        }
        for name in visible_names:
            visible = self._resolve_object(
                ast.Name(id=name, ctx=ast.Load()),
                module,
                aliases,
                modules,
                2**31 - 1,
            )
            if visible is not None and visible.key == root.key:
                initial_objects[name] = root
        initial_strings: dict[str, str] = {}
        parameters = [*function.args.posonlyargs, *function.args.args]
        for parameter in [*parameters, *function.args.kwonlyargs]:
            initial_objects.pop(parameter.arg, None)
        default_pairs = (
            list(
                zip(
                    parameters[-len(function.args.defaults) :],
                    function.args.defaults,
                    strict=True,
                )
            )
            if function.args.defaults
            else []
        )
        default_pairs.extend(
            (parameter, default)
            for parameter, default in zip(
                function.args.kwonlyargs, function.args.kw_defaults, strict=True
            )
            if default is not None
        )
        for parameter, default in default_pairs:
            default_object = self._resolve_object(
                default, module, aliases, modules, function.lineno
            )
            if default_object is not None:
                initial_objects[parameter.arg] = default_object
            value = self._literal_string(default, module, function.lineno)
            if value is not None:
                initial_strings[parameter.arg] = value
        apply(module, function, initial_objects, initial_strings, frozenset())

    @staticmethod
    def _record_object_limitation(
        module: _Module,
        owner: _Object,
        node: ast.AST,
        reason: str,
        *,
        inventory_only: bool = False,
    ) -> None:
        condition = EndpointDiscoveryCondition(
            source_path=module.path,
            source_line=getattr(node, "lineno", 1),
            reason=reason,
        )
        destination = (
            module.inventory_only_limitations if inventory_only else module.object_limitations
        )
        limitations = destination.setdefault(owner.key, [])
        if condition not in limitations:
            limitations.append(condition)

    @staticmethod
    def _record_ordered_inventory_limitation(
        module: _Module,
        owner: _Object,
        node: ast.AST,
        reason: str,
        *,
        endpoint_impact: EndpointImpact = "none",
    ) -> None:
        limitation = _OrderedInventoryLimitation(
            origin_module=module.name,
            order=_node_order(node),
            condition=EndpointDiscoveryCondition(
                source_path=module.path,
                source_line=getattr(node, "lineno", 1),
                reason=reason,
            ),
            endpoint_impact=endpoint_impact,
        )
        limitations = module.ordered_inventory_limitations.setdefault(owner.key, [])
        if limitation not in limitations:
            limitations.append(limitation)

    def _collect_control_flow_limitations(  # noqa: PLR0915
        self,
        module: _Module,
        aliases: dict[str, str],
        modules: dict[str, _Module],
    ) -> None:
        """Record source-ordered uncertainty from executed module/header effects."""
        evaluate_annotations = not _uses_future_annotations(module.tree)
        registration_methods = {
            *self.HTTP_METHODS,
            "api_route",
            "include_router",
            "include_routes",
            "mount",
            "add_route",
            "add_api_route",
            "add_api_websocket_route",
            "add_websocket_route",
        }
        route_collection_mutators = {
            "append",
            "clear",
            "extend",
            "insert",
            "pop",
            "remove",
            "reverse",
            "sort",
        }
        known_aliases: dict[str, frozenset[_Object]] = {}
        dynamic_callable_aliases: set[str] = set()
        discarded_decorator_factories: set[int] = set()

        def collect_discarded_decorator_factories(statements: list[ast.stmt]) -> None:
            for statement in statements:
                if (
                    isinstance(statement, ast.Expr)
                    and isinstance(statement.value, ast.Call)
                    and isinstance(statement.value.func, ast.Attribute)
                    and statement.value.func.attr in {*self.HTTP_METHODS, "api_route"}
                ):
                    discarded_decorator_factories.add(_node_order(statement.value))
                if isinstance(statement, ast.ClassDef):
                    collect_discarded_decorator_factories(statement.body)
                elif isinstance(
                    statement,
                    (
                        ast.If,
                        ast.For,
                        ast.AsyncFor,
                        ast.While,
                        ast.Try,
                        ast.With,
                        ast.AsyncWith,
                        ast.Match,
                    ),
                ) or _is_try_star(statement):
                    nested: list[ast.stmt] = []
                    for attribute in ("body", "orelse", "finalbody"):
                        nested.extend(getattr(statement, attribute, ()))
                    if _is_try_like(statement):
                        nested.extend(
                            item for handler in _try_handlers(statement) for item in handler.body
                        )
                    if isinstance(statement, ast.Match):
                        nested.extend(item for case in statement.cases for item in case.body)
                    collect_discarded_decorator_factories(nested)

        collect_discarded_decorator_factories(module.tree.body)

        def object_root(  # noqa: PLR0911
            expression: ast.expr | None, line: int
        ) -> _Object | None:
            if expression is None:
                return None
            if isinstance(expression, ast.Name):
                aliased = known_aliases.get(expression.id, frozenset())
                if len(aliased) == 1:
                    return next(iter(aliased))
            resolved = self._resolve_object(expression, module, aliases, modules, line)
            if resolved is not None:
                return resolved
            current = expression.value if isinstance(expression, ast.Subscript) else expression
            if isinstance(current, ast.Name):
                aliased = known_aliases.get(current.id, frozenset())
                if len(aliased) == 1:
                    return next(iter(aliased))
            attributes = attribute_names(current)
            if attributes not in {("router",), ("routes",), ("router", "routes")}:
                return None
            while isinstance(current, ast.Attribute):
                current = current.value
                if isinstance(current, ast.Name):
                    aliased = known_aliases.get(current.id, frozenset())
                    if len(aliased) == 1:
                        return next(iter(aliased))
                resolved = self._resolve_object(current, module, aliases, modules, line)
                if resolved is not None:
                    return resolved
            return None

        def attribute_names(expression: ast.expr | None) -> tuple[str, ...]:
            names: list[str] = []
            current = expression
            while isinstance(current, (ast.Attribute, ast.Subscript)):
                if isinstance(current, ast.Attribute):
                    names.append(current.attr)
                current = current.value
            return tuple(reversed(names))

        def route_state_owner(expression: ast.expr, line: int) -> _Object | None:
            attributes = attribute_names(expression)
            if not attributes or attributes[0] not in {"router", "routes"}:
                return None
            current: ast.expr = expression
            while isinstance(current, (ast.Attribute, ast.Subscript)):
                resolved = object_root(current, line)
                if resolved is not None:
                    return resolved
                current = current.value
            return None

        def referenced_objects(expression: ast.AST, line: int) -> set[_Object]:
            found: set[_Object] = set()

            def collect(item: ast.AST) -> None:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                    return
                if isinstance(item, (ast.Name, ast.Attribute)):
                    if isinstance(item, ast.Name):
                        found.update(known_aliases.get(item.id, ()))
                    resolved = object_root(item, line)
                    if resolved is not None:
                        found.add(resolved)
                    # Passing app.title does not pass app itself. An exact imported
                    # module.router attribute, however, resolves above.
                    return
                for child in ast.iter_child_nodes(item):
                    collect(child)

            collect(expression)
            return found

        def alias_objects(expression: ast.expr, line: int) -> frozenset[_Object]:
            if isinstance(expression, ast.Name):
                aliased = known_aliases.get(expression.id)
                if aliased is not None:
                    return aliased
                resolved = self._resolve_object(expression, module, aliases, modules, line)
                return frozenset({resolved}) if resolved is not None else frozenset()
            if isinstance(expression, ast.Attribute):
                resolved = object_root(expression, line)
                return frozenset({resolved}) if resolved is not None else frozenset()
            if isinstance(expression, (ast.List, ast.Tuple, ast.Set)):
                return frozenset(
                    owner for item in expression.elts for owner in alias_objects(item, line)
                )
            if isinstance(expression, ast.Dict):
                return frozenset(
                    owner for item in expression.values for owner in alias_objects(item, line)
                )
            return frozenset()

        def expression_is_dynamic_callable(expression: ast.expr, line: int) -> bool:
            if isinstance(expression, ast.Name):
                if expression.id in dynamic_callable_aliases:
                    return True
                binding = self._import_binding_at(module, expression.id, line)
                if binding is not None:
                    return (binding.module, binding.symbol) in {
                        ("builtins", "exec"),
                        ("builtins", "eval"),
                    }
                return (
                    expression.id in {"exec", "eval"}
                    and self._latest_binding_line(module, expression.id, line) is None
                )
            if isinstance(expression, ast.Attribute) and isinstance(expression.value, ast.Name):
                binding = self._import_binding_at(module, expression.value.id, line)
                return (
                    binding is not None
                    and binding.module == "builtins"
                    and binding.symbol is None
                    and expression.attr in {"exec", "eval"}
                )
            return False

        def update_aliases(statement: ast.stmt, *, conditionally_executed: bool) -> None:
            assignments: list[tuple[str, ast.expr]] = []
            rebound = _scope_bound_names(
                statement,
                evaluate_annotations=evaluate_annotations,
            )
            if isinstance(statement, ast.Assign):
                for target in statement.targets:
                    assignments.extend(_assignment_pairs(target, statement.value))
            elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
                assignments.extend(_assignment_pairs(statement.target, statement.value))
            assignments.extend(
                _executed_named_expr_bindings(
                    statement,
                    evaluate_annotations=evaluate_annotations,
                )
            )
            if not conditionally_executed:
                for name in rebound:
                    known_aliases.pop(name, None)
                    dynamic_callable_aliases.discard(name)
            for name, value in assignments:
                resolved = alias_objects(value, statement.lineno)
                if resolved:
                    known_aliases[name] = (
                        known_aliases.get(name, frozenset()) | resolved
                        if conditionally_executed
                        else resolved
                    )
                if expression_is_dynamic_callable(value, statement.lineno):
                    dynamic_callable_aliases.add(name)

        def current_objects(line: int) -> set[_Object]:
            found: set[_Object] = set()
            for name in {*module.objects, *module.import_bindings}:
                resolved = self._resolve_object(
                    ast.Name(id=name, ctx=ast.Load()),
                    module,
                    aliases,
                    modules,
                    line,
                )
                if resolved is not None:
                    found.add(resolved)
            for owners in known_aliases.values():
                found.update(owners)
            found.update(item for item in module.factory_objects if item.line <= line)
            return found

        def resolves_builtin(call: ast.Call, names: set[str]) -> bool:
            if isinstance(call.func, ast.Name):
                if call.func.id in dynamic_callable_aliases and names & {"exec", "eval"}:
                    return True
                binding = self._import_binding_at(module, call.func.id, call.lineno)
                if binding is not None:
                    return binding.module == "builtins" and binding.symbol in names
                return (
                    call.func.id in names
                    and self._latest_binding_line(module, call.func.id, call.lineno) is None
                )
            if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
                binding = self._import_binding_at(module, call.func.value.id, call.lineno)
                return (
                    binding is not None
                    and binding.module == "builtins"
                    and binding.symbol is None
                    and call.func.attr in names
                )
            return False

        def is_dynamic_execution(call: ast.Call) -> bool:
            return resolves_builtin(call, {"exec", "eval"})

        def safe_setattr(call: ast.Call) -> bool:
            return (
                resolves_builtin(call, {"setattr"})
                and len(call.args) >= 2
                and isinstance(call.args[1], ast.Constant)
                and call.args[1].value
                in {
                    "debug",
                    "description",
                    "docs_url",
                    "openapi_url",
                    "redoc_url",
                    "root_path",
                    "title",
                    "version",
                }
            )

        def record(
            owner: _Object,
            node: ast.AST,
            reason: str,
            *,
            endpoint_impact: EndpointImpact = "none",
        ) -> None:
            self._record_ordered_inventory_limitation(
                module,
                owner,
                node,
                reason,
                endpoint_impact=endpoint_impact,
            )

        def visit(  # noqa: PLR0912, PLR0915 - explicit executed-effect taxonomy
            node: ast.AST, *, conditional: bool
        ) -> None:
            if isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
                loop_evidence = node.iter if isinstance(node, ast.comprehension) else node
                for owner in referenced_objects(node.iter, loop_evidence.lineno):
                    record(
                        owner,
                        loop_evidence,
                        "module-level loop aliases a route object conditionally",
                    )
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in node.decorator_list:
                    visit(decorator, conditional=conditional)
                for default in [*node.args.defaults, *node.args.kw_defaults]:
                    if default is not None:
                        visit(default, conditional=conditional)
                if evaluate_annotations:
                    for annotation in [
                        *(item.annotation for item in node.args.args),
                        *(item.annotation for item in node.args.posonlyargs),
                        *(item.annotation for item in node.args.kwonlyargs),
                        node.args.vararg.annotation if node.args.vararg is not None else None,
                        node.args.kwarg.annotation if node.args.kwarg is not None else None,
                        node.returns,
                    ]:
                        if annotation is not None:
                            visit(annotation, conditional=conditional)
                return
            if isinstance(node, ast.ClassDef):
                for expression in [
                    *node.decorator_list,
                    *node.bases,
                    *(item.value for item in node.keywords),
                ]:
                    visit(expression, conditional=conditional)
                for statement in node.body:
                    visit(statement, conditional=conditional)
                return
            if isinstance(node, ast.Lambda):
                for default in [*node.args.defaults, *node.args.kw_defaults]:
                    if default is not None:
                        visit(default, conditional=conditional)
                return
            if _is_type_alias(node):
                return
            if isinstance(node, ast.Call):
                receiver_expression = (
                    node.func.value if isinstance(node.func, ast.Attribute) else None
                )
                exact_receiver = self._resolve_object(
                    receiver_expression, module, aliases, modules, node.lineno
                )
                receiver = object_root(receiver_expression, node.lineno)
                operation = node.func.attr if isinstance(node.func, ast.Attribute) else ""
                receiver_attributes = attribute_names(receiver_expression)
                modeled = _node_order(node) in module.modeled_route_effects
                discarded_decorator_factory = _node_order(node) in discarded_decorator_factories
                inventory_neutral_method = (
                    operation
                    in {
                        "add_event_handler",
                        "add_exception_handler",
                        "add_middleware",
                    }
                    and exact_receiver is not None
                )
                route_collection_mutation = operation in route_collection_mutators and (
                    receiver_attributes in {("routes",), ("router", "routes")}
                )
                if discarded_decorator_factory or inventory_neutral_method:
                    pass
                elif (
                    conditional
                    and receiver is not None
                    and (operation in registration_methods or route_collection_mutation)
                ):
                    record(
                        receiver,
                        node,
                        "module-level control flow may conditionally mutate route inventory",
                        endpoint_impact=(
                            "prior" if operation in {"clear", "pop", "remove"} else "none"
                        ),
                    )
                elif conditional and receiver is None and operation in registration_methods:
                    for owner in referenced_objects(receiver_expression or node.func, node.lineno):
                        record(
                            owner,
                            node,
                            "module-level control flow has a conditional registration receiver",
                        )
                elif not conditional and receiver is not None and route_collection_mutation:
                    record(
                        receiver,
                        node,
                        "direct module-level route collection mutation is not modeled",
                        endpoint_impact=(
                            "prior" if operation in {"clear", "pop", "remove"} else "none"
                        ),
                    )
                elif not conditional and receiver is not None and operation in registration_methods:
                    if not modeled:
                        record(
                            receiver,
                            node,
                            "direct module-level route registration could not be modeled",
                        )
                elif receiver is not None and not modeled:
                    record(
                        receiver,
                        node,
                        "module-level execution invokes an unresolved route-state method",
                        endpoint_impact="all",
                    )
                if is_dynamic_execution(node):
                    for owner in current_objects(node.lineno):
                        record(
                            owner,
                            node,
                            "dynamic module-level execution can alter route inventory",
                            endpoint_impact="all",
                        )
                if (
                    operation not in registration_methods
                    and not modeled
                    and not inventory_neutral_method
                    and not safe_setattr(node)
                ):
                    if exact_receiver is not None and receiver is None:
                        record(
                            exact_receiver,
                            node,
                            "module-level execution invokes an unresolved route-object method",
                            endpoint_impact="all",
                        )
                    for argument in [*node.args, *(item.value for item in node.keywords)]:
                        for owner in referenced_objects(argument, node.lineno):
                            record(
                                owner,
                                node,
                                "module-level execution passes a route object "
                                "to an unresolved call",
                                endpoint_impact="all",
                            )
            elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete)):
                targets: list[ast.expr] = []
                value = node.value if not isinstance(node, ast.Delete) else None
                if value is not None and conditional:
                    for owner in referenced_objects(value, node.lineno):
                        record(
                            owner,
                            node,
                            "module-level control flow aliases a route object conditionally",
                            endpoint_impact="all",
                        )
                if isinstance(value, ast.Attribute) and value.attr in registration_methods:
                    escaped_owner = object_root(value.value, node.lineno)
                    if escaped_owner is not None:
                        record(
                            escaped_owner,
                            node,
                            "route registration method escapes into an unresolved alias",
                        )
                if isinstance(node, ast.Assign):
                    targets.extend(node.targets)
                elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
                    targets.append(node.target)
                else:
                    targets.extend(node.targets)
                for target in targets:
                    if isinstance(target, ast.Attribute) and target.attr in registration_methods:
                        registration_owner = object_root(target.value, node.lineno)
                        if registration_owner is not None:
                            record(
                                registration_owner,
                                node,
                                "module-level execution may replace a route registration method",
                                endpoint_impact="subsequent",
                            )
                    attribute_target = target.value if isinstance(target, ast.Subscript) else target
                    target_attributes = attribute_names(attribute_target)
                    mutates_route_state = (
                        target_attributes == ("router",)
                        or target_attributes[:1] == ("routes",)
                        or target_attributes[:2] == ("router", "routes")
                    )
                    if not mutates_route_state:
                        continue
                    target_owner = route_state_owner(target, node.lineno)
                    if target_owner is not None:
                        record(
                            target_owner,
                            node,
                            "module-level execution may replace route state",
                            endpoint_impact="prior",
                        )
                if isinstance(node, ast.AnnAssign):
                    if node.value is not None:
                        visit(node.value, conditional=conditional)
                    if evaluate_annotations:
                        visit(node.annotation, conditional=conditional)
                    return
            for child in ast.iter_child_nodes(node):
                visit(child, conditional=conditional)

        control_flow_types = (
            ast.If,
            ast.For,
            ast.AsyncFor,
            ast.While,
            ast.Try,
            ast.With,
            ast.AsyncWith,
            ast.Match,
        )
        for statement in module.tree.body:
            conditional = (
                isinstance(statement, control_flow_types)
                or _is_try_star(statement)
                or (
                    _has_executed_expression_control(
                        statement,
                        evaluate_annotations=evaluate_annotations,
                    )
                )
            )
            visit(statement, conditional=conditional)
            update_aliases(statement, conditionally_executed=conditional)

    def _route_registration_owner(
        self,
        expression: ast.expr | None,
        module: _Module,
        aliases: dict[str, str],
        modules: dict[str, _Module],
        line: int,
    ) -> _Object | None:
        owner = self._resolve_object(expression, module, aliases, modules, line)
        if owner is not None:
            return owner
        if isinstance(expression, ast.Attribute) and expression.attr == "router":
            return self._resolve_object(expression.value, module, aliases, modules, line)
        return None

    def _collect_routes(  # noqa: PLR0912 - registration forms stay explicit
        self,
        module: _Module,
        aliases: dict[str, str],
        modules: dict[str, _Module],
    ) -> list[_Route]:
        routes: list[_Route] = []
        for node in module.tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                handler = self._handler(module, node)
                for decorator in node.decorator_list:
                    parsed = self._decorator_route(decorator, module, node.lineno)
                    if parsed is not None:
                        decorated_owner, decorated_path, methods = parsed
                        if not methods:
                            self._record_object_limitation(
                                module,
                                decorated_owner,
                                decorator,
                                "decorated route methods could not be resolved",
                                inventory_only=True,
                            )
                            continue
                        module.modeled_route_effects.add(_node_order(decorator))
                        routes.append(
                            _Route(
                                decorated_owner.key,
                                decorated_path,
                                methods,
                                handler,
                                _node_order(node),
                            )
                        )
                    elif (
                        isinstance(decorator, ast.Call)
                        and isinstance(decorator.func, ast.Attribute)
                        and decorator.func.attr in {*self.HTTP_METHODS, "api_route"}
                    ):
                        owner = self._route_registration_owner(
                            decorator.func.value,
                            module,
                            aliases,
                            modules,
                            node.lineno,
                        )
                        if owner is not None:
                            self._record_object_limitation(
                                module,
                                owner,
                                decorator,
                                "decorated route path or methods could not be resolved",
                                inventory_only=True,
                            )
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                call = node.value
                if not isinstance(call.func, ast.Attribute) or call.func.attr not in {
                    "add_api_route",
                    "add_api_websocket_route",
                    "add_websocket_route",
                }:
                    continue
                imperative_owner = self._route_registration_owner(
                    call.func.value,
                    module,
                    aliases,
                    modules,
                    node.lineno,
                )
                if imperative_owner is None:
                    continue
                if imperative_owner.key[0] != module.name:
                    self._record_object_limitation(
                        module,
                        imperative_owner,
                        node,
                        "imperative registration mutates an imported route object",
                        inventory_only=True,
                    )
                    continue
                path_expr = call.args[0] if call.args else _keyword_expr(call, "path")
                handler_expr = (
                    call.args[1] if len(call.args) > 1 else _keyword_expr(call, "endpoint")
                )
                imperative_path = self._literal_string(path_expr, module, node.lineno)
                imperative_handler = self._resolve_handler(
                    handler_expr, module, aliases, modules, node.lineno
                )
                if imperative_path is None or imperative_handler is None:
                    self._record_object_limitation(
                        module,
                        imperative_owner,
                        node,
                        "imperative route path or handler could not be resolved",
                        inventory_only=True,
                    )
                    continue
                if call.func.attr == "add_api_route":
                    methods_expr = _keyword_expr(call, "methods")
                    methods = (
                        _literal_methods(methods_expr) if methods_expr is not None else ("GET",)
                    )
                else:
                    methods = ("WEBSOCKET",)
                if not methods:
                    self._record_object_limitation(
                        module,
                        imperative_owner,
                        node,
                        "imperative route methods could not be resolved",
                        inventory_only=True,
                    )
                    continue
                if methods:
                    module.modeled_route_effects.add(_node_order(call))
                    routes.append(
                        _Route(
                            imperative_owner.key,
                            imperative_path,
                            methods,
                            imperative_handler,
                            _node_order(node),
                        )
                    )
        return routes

    def _decorator_route(
        self, decorator: ast.expr, module: _Module, line: int
    ) -> tuple[_Object, str, tuple[str, ...]] | None:
        if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
            return None
        if not isinstance(decorator.func.value, ast.Name):
            return None
        owner = self._object_at(module, decorator.func.value.id, line)
        if owner is None:
            return None
        method = decorator.func.attr
        if method not in self.HTTP_METHODS and method != "api_route":
            return None
        path_expr = decorator.args[0] if decorator.args else _keyword_expr(decorator, "path")
        path = self._literal_string(path_expr, module, line)
        if path is None:
            return None
        if method == "api_route":
            methods_expr = _keyword_expr(decorator, "methods")
            methods = _literal_methods(methods_expr) if methods_expr is not None else ("GET",)
        else:
            methods = ("WEBSOCKET",) if method == "websocket" else (method.upper(),)
        return owner, path, methods

    def _collect_edges(
        self,
        module: _Module,
        aliases: dict[str, str],
        modules: dict[str, _Module],
    ) -> list[_Edge]:
        edges: list[_Edge] = []
        for node in module.tree.body:
            if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Call):
                continue
            call = node.value
            if not isinstance(call.func, ast.Attribute):
                continue
            parent = self._resolve_object(call.func.value, module, aliases, modules, node.lineno)
            if parent is None:
                continue
            if parent.key[0] != module.name:
                self._record_object_limitation(
                    module,
                    parent,
                    node,
                    "composition mutates an imported route object",
                    inventory_only=True,
                )
                continue
            if call.func.attr == "include_router":
                child_expr = call.args[0] if call.args else _keyword_expr(call, "router")
                child = self._resolve_object(child_expr, module, aliases, modules, node.lineno)
                if child is None or child.kind != "router":
                    self._record_object_limitation(
                        module,
                        parent,
                        node,
                        "included router could not be resolved",
                        inventory_only=True,
                    )
                    continue
                prefix = self._keyword_string(call, "prefix", module, node.lineno) or ""
                cutoff = _node_order(node) if child.key[0] == module.name else None
                module.modeled_route_effects.add(_node_order(call))
                edges.append(
                    _Edge(
                        parent.key,
                        child.key,
                        prefix,
                        _node_order(node),
                        cutoff,
                        (module.name, _node_order(node)),
                        "copy",
                    )
                )
            elif call.func.attr == "mount":
                path_expr = call.args[0] if call.args else _keyword_expr(call, "path")
                child_expr = call.args[1] if len(call.args) > 1 else _keyword_expr(call, "app")
                path = self._literal_string(path_expr, module, node.lineno)
                child = self._resolve_object(child_expr, module, aliases, modules, node.lineno)
                if path is None or child is None or child.kind != "app":
                    self._record_object_limitation(
                        module,
                        parent,
                        node,
                        "mounted path or application could not be resolved",
                        inventory_only=True,
                    )
                    continue
                module.modeled_route_effects.add(_node_order(call))
                edges.append(
                    _Edge(
                        parent.key,
                        child.key,
                        path,
                        _node_order(node),
                        None,
                        None,
                        "live",
                    )
                )
        return edges

    def _resolve_object(
        self,
        expression: ast.expr | None,
        module: _Module,
        aliases: dict[str, str],
        modules: dict[str, _Module],
        line: int,
    ) -> _Object | None:
        hop_budget = min(len(modules) + 1, 64)
        if isinstance(expression, ast.Name):
            local = self._object_at(module, expression.id, line)
            if local is not None:
                return local
            return self._resolve_exported_object(
                module,
                expression.id,
                line,
                aliases,
                modules,
                frozenset(),
                hop_budget,
            )
        if isinstance(expression, ast.Attribute) and isinstance(expression.value, ast.Name):
            binding = self._import_binding_at(module, expression.value.id, line)
            if binding is None or binding.symbol is not None:
                return None
            target_name = aliases.get(binding.module, binding.module)
            target = modules.get(target_name)
            if target is None:
                return None
            return self._resolve_exported_object(
                target,
                expression.attr,
                2**31 - 1,
                aliases,
                modules,
                frozenset(),
                hop_budget,
            )
        return None

    def _resolve_exported_object(
        self,
        module: _Module,
        symbol: str,
        line: int,
        aliases: dict[str, str],
        modules: dict[str, _Module],
        visited: frozenset[tuple[str, str, int]],
        remaining_hops: int,
    ) -> _Object | None:
        """Follow exact project-local symbol re-exports to one modeled object."""
        if remaining_hops <= 0:
            return None
        local = self._object_at(module, symbol, line)
        if local is not None:
            return local
        binding = self._import_binding_at(module, symbol, line)
        if binding is None or binding.symbol is None or binding.symbol == "*":
            return None
        target_name = aliases.get(binding.module, binding.module)
        target = modules.get(target_name)
        if target is None:
            return None
        token = (module.name, symbol, binding.line)
        if token in visited:
            return None
        return self._resolve_exported_object(
            target,
            binding.symbol,
            2**31 - 1,
            aliases,
            modules,
            visited | {token},
            remaining_hops - 1,
        )

    def _resolve_handler(
        self,
        expression: ast.expr | None,
        module: _Module,
        aliases: dict[str, str],
        modules: dict[str, _Module],
        line: int | None = None,
    ) -> HandlerInfo | None:
        lookup_line = line if line is not None else 2**31 - 1
        if isinstance(expression, ast.Name):
            function = self._function_at(module, expression.id, lookup_line)
            if function is not None:
                return self._handler(module, function)
            binding = self._import_binding_at(module, expression.id, lookup_line)
            if binding is not None and binding.symbol is not None:
                target = modules.get(aliases.get(binding.module, ""))
                if target is not None:
                    function = self._function_at(target, binding.symbol, 2**31 - 1)
                    if function is not None:
                        return self._handler(target, function)
        if isinstance(expression, ast.Attribute) and isinstance(expression.value, ast.Name):
            binding = self._import_binding_at(module, expression.value.id, lookup_line)
            target_name = binding.module if binding is not None and binding.symbol is None else ""
            target = modules.get(aliases.get(target_name, target_name))
            if target is not None:
                function = self._function_at(target, expression.attr, 2**31 - 1)
                if function is not None:
                    return self._handler(target, function)
        return None

    def _literal_string(  # noqa: PLR0911 - bounded expression taxonomy
        self, expression: ast.expr | None, module: _Module, line: int
    ) -> str | None:
        if isinstance(expression, ast.Constant) and isinstance(expression.value, str):
            return expression.value
        if isinstance(expression, ast.Name):
            history = [item for item in module.strings.get(expression.id, []) if item[0] <= line]
            if not history:
                return None
            item_line, value = history[-1]
            return (
                value
                if item_line == self._latest_binding_line(module, expression.id, line)
                else None
            )
        if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Add):
            left = self._literal_string(expression.left, module, line)
            right = self._literal_string(expression.right, module, line)
            return left + right if left is not None and right is not None else None
        if isinstance(expression, ast.JoinedStr):
            parts: list[str] = []
            for joined_value in expression.values:
                if isinstance(joined_value, ast.Constant) and isinstance(joined_value.value, str):
                    parts.append(joined_value.value)
                    continue
                if (
                    not isinstance(joined_value, ast.FormattedValue)
                    or joined_value.conversion != -1
                    or joined_value.format_spec is not None
                ):
                    return None
                resolved = self._literal_string(joined_value.value, module, line)
                if resolved is None:
                    return None
                parts.append(resolved)
            return "".join(parts)
        return None

    def _keyword_string(self, call: ast.Call, name: str, module: _Module, line: int) -> str | None:
        return self._literal_string(_keyword_expr(call, name), module, line)

    def _handler(
        self, module: _Module, function: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> HandlerInfo:
        return HandlerInfo(
            name=function.name,
            module=module.name,
            file_path=module.path,
            line_number=function.lineno,
            end_line_number=function.end_lineno or function.lineno,
        )

    def _absolute_import(self, module: _Module, node: ast.ImportFrom) -> str:
        if node.level == 0:
            return node.module or ""
        package = module.name if module.is_package else module.name.rpartition(".")[0]
        parts = package.split(".") if package else []
        remove = max(node.level - 1, 0)
        if remove:
            parts = parts[:-remove]
        if node.module:
            parts.extend(node.module.split("."))
        return ".".join(parts)


def _returns_outside_nested_functions(statements: list[ast.stmt]) -> list[ast.Return]:
    """Collect returns belonging to one function, including control-flow branches."""
    returns: list[ast.Return] = []

    def visit(node: ast.AST) -> None:
        if isinstance(node, ast.Return):
            returns.append(node)
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            return
        for child in ast.iter_child_nodes(node):
            visit(child)

    for statement in statements:
        visit(statement)
    return returns


def _function_bindings(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    """Collect bindings in one function scope without descending into nested scopes."""

    class BindingVisitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.names: set[str] = set()

        def visit_Name(self, node: ast.Name) -> None:
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                self.names.add(node.id)

        def visit_Import(self, node: ast.Import) -> None:
            for alias in node.names:
                self.names.add(alias.asname or alias.name.split(".")[0])

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            for alias in node.names:
                self.names.add(alias.asname or alias.name)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self.names.add(node.name)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self.names.add(node.name)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            self.names.add(node.name)

        def visit_Lambda(self, _node: ast.Lambda) -> None:
            return

    visitor = BindingVisitor()
    visitor.names.update(
        argument.arg
        for argument in [
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        ]
    )
    for statement in function.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            visitor.names.add(statement.name)
        else:
            visitor.visit(statement)
    return visitor.names


def _uses_future_annotations(tree: ast.Module) -> bool:
    """Return whether annotations are postponed for this module."""
    return any(
        isinstance(statement, ast.ImportFrom)
        and statement.module == "__future__"
        and any(alias.name == "annotations" for alias in statement.names)
        for statement in tree.body
    )


def _executed_named_expr_bindings(
    node: ast.AST,
    *,
    evaluate_annotations: bool,
) -> list[tuple[str, ast.expr]]:
    """Return exact assignment-expression bindings from definitely executed headers."""

    class NamedExpressionVisitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.bindings: list[tuple[str, ast.expr]] = []

        def visit_NamedExpr(self, child: ast.NamedExpr) -> None:
            if isinstance(child.target, ast.Name):
                self.bindings.append((child.target.id, child.value))
            self.visit(child.value)

        def _visit_function_header(self, child: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            for expression in [
                *child.decorator_list,
                *child.args.defaults,
                *(item for item in child.args.kw_defaults if item is not None),
            ]:
                self.visit(expression)
            if evaluate_annotations:
                for annotation in [
                    *(item.annotation for item in child.args.args),
                    *(item.annotation for item in child.args.posonlyargs),
                    *(item.annotation for item in child.args.kwonlyargs),
                    child.args.vararg.annotation if child.args.vararg is not None else None,
                    child.args.kwarg.annotation if child.args.kwarg is not None else None,
                    child.returns,
                ]:
                    if annotation is not None:
                        self.visit(annotation)

        def visit_FunctionDef(self, child: ast.FunctionDef) -> None:
            self._visit_function_header(child)

        def visit_AsyncFunctionDef(self, child: ast.AsyncFunctionDef) -> None:
            self._visit_function_header(child)

        def visit_ClassDef(self, child: ast.ClassDef) -> None:
            for expression in [
                *child.decorator_list,
                *child.bases,
                *(item.value for item in child.keywords),
            ]:
                self.visit(expression)

        def visit_Lambda(self, child: ast.Lambda) -> None:
            for expression in [
                *child.args.defaults,
                *(item for item in child.args.kw_defaults if item is not None),
            ]:
                self.visit(expression)

        def visit_AnnAssign(self, child: ast.AnnAssign) -> None:
            if child.value is not None:
                self.visit(child.value)
            if evaluate_annotations:
                self.visit(child.annotation)

        def visit_ListComp(self, _child: ast.ListComp) -> None:
            return

        def visit_SetComp(self, _child: ast.SetComp) -> None:
            return

        def visit_DictComp(self, _child: ast.DictComp) -> None:
            return

        def visit_GeneratorExp(self, _child: ast.GeneratorExp) -> None:
            return

        def visit_TypeAlias(self, _child: ast.AST) -> None:
            return

    visitor = NamedExpressionVisitor()
    visitor.visit(node)
    return visitor.bindings


def _class_global_bound_names(
    node: ast.ClassDef,
    *,
    evaluate_annotations: bool,
) -> set[str]:
    """Return module names rebound by ``global`` statements in executed class bodies."""

    class ClassScopeVisitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.globals: set[str] = set()
            self.bound: set[str] = set()
            self.nested_classes: list[ast.ClassDef] = []

        def visit_Global(self, child: ast.Global) -> None:
            self.globals.update(child.names)

        def visit_Name(self, child: ast.Name) -> None:
            if isinstance(child.ctx, (ast.Store, ast.Del)):
                self.bound.add(child.id)

        def visit_Import(self, child: ast.Import) -> None:
            self.bound.update(alias.asname or alias.name.split(".")[0] for alias in child.names)

        def visit_ImportFrom(self, child: ast.ImportFrom) -> None:
            self.bound.update(alias.asname or alias.name for alias in child.names)

        def _visit_function_header(self, child: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            self.bound.add(child.name)
            for expression in [
                *child.decorator_list,
                *child.args.defaults,
                *(item for item in child.args.kw_defaults if item is not None),
            ]:
                self.visit(expression)
            if evaluate_annotations:
                for annotation in [
                    *(item.annotation for item in child.args.args),
                    *(item.annotation for item in child.args.posonlyargs),
                    *(item.annotation for item in child.args.kwonlyargs),
                    child.args.vararg.annotation if child.args.vararg is not None else None,
                    child.args.kwarg.annotation if child.args.kwarg is not None else None,
                    child.returns,
                ]:
                    if annotation is not None:
                        self.visit(annotation)

        def visit_FunctionDef(self, child: ast.FunctionDef) -> None:
            self._visit_function_header(child)

        def visit_AsyncFunctionDef(self, child: ast.AsyncFunctionDef) -> None:
            self._visit_function_header(child)

        def visit_ClassDef(self, child: ast.ClassDef) -> None:
            self.bound.add(child.name)
            for expression in [
                *child.decorator_list,
                *child.bases,
                *(item.value for item in child.keywords),
            ]:
                self.visit(expression)
            self.nested_classes.append(child)

        def visit_Lambda(self, child: ast.Lambda) -> None:
            for expression in [
                *child.args.defaults,
                *(item for item in child.args.kw_defaults if item is not None),
            ]:
                self.visit(expression)

        def visit_ExceptHandler(self, child: ast.ExceptHandler) -> None:
            if child.name:
                self.bound.add(child.name)
            self.generic_visit(child)

        def visit_MatchAs(self, child: ast.MatchAs) -> None:
            if child.name:
                self.bound.add(child.name)
            self.generic_visit(child)

        def visit_MatchStar(self, child: ast.MatchStar) -> None:
            if child.name:
                self.bound.add(child.name)

        def visit_MatchMapping(self, child: ast.MatchMapping) -> None:
            if child.rest:
                self.bound.add(child.rest)
            self.generic_visit(child)

    visitor = ClassScopeVisitor()
    for statement in node.body:
        visitor.visit(statement)
    rebound = visitor.globals & visitor.bound
    for nested in visitor.nested_classes:
        rebound.update(
            _class_global_bound_names(
                nested,
                evaluate_annotations=evaluate_annotations,
            )
        )
    return rebound


def _has_executed_expression_control(
    node: ast.AST,
    *,
    evaluate_annotations: bool,
) -> bool:
    """Return whether an executed expression introduces conditional evaluation."""

    class ControlVisitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.found = False

        def visit_BoolOp(self, _child: ast.BoolOp) -> None:
            self.found = True

        def visit_IfExp(self, _child: ast.IfExp) -> None:
            self.found = True

        def visit_NamedExpr(self, _child: ast.NamedExpr) -> None:
            self.found = True

        def visit_comprehension(self, _child: ast.comprehension) -> None:
            self.found = True

        def _visit_function_header(self, child: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            for expression in [
                *child.decorator_list,
                *child.args.defaults,
                *(item for item in child.args.kw_defaults if item is not None),
            ]:
                self.visit(expression)
            if evaluate_annotations:
                for annotation in [
                    *(item.annotation for item in child.args.args),
                    *(item.annotation for item in child.args.posonlyargs),
                    *(item.annotation for item in child.args.kwonlyargs),
                    child.args.vararg.annotation if child.args.vararg is not None else None,
                    child.args.kwarg.annotation if child.args.kwarg is not None else None,
                    child.returns,
                ]:
                    if annotation is not None:
                        self.visit(annotation)

        def visit_FunctionDef(self, child: ast.FunctionDef) -> None:
            self._visit_function_header(child)

        def visit_AsyncFunctionDef(self, child: ast.AsyncFunctionDef) -> None:
            self._visit_function_header(child)

        def visit_ClassDef(self, child: ast.ClassDef) -> None:
            for expression in [
                *child.decorator_list,
                *child.bases,
                *(item.value for item in child.keywords),
            ]:
                self.visit(expression)
            for statement in child.body:
                self.visit(statement)

        def visit_Lambda(self, child: ast.Lambda) -> None:
            for expression in [
                *child.args.defaults,
                *(item for item in child.args.kw_defaults if item is not None),
            ]:
                self.visit(expression)

        def visit_AnnAssign(self, child: ast.AnnAssign) -> None:
            if child.value is not None:
                self.visit(child.value)
            if evaluate_annotations:
                self.visit(child.annotation)

        def visit_TypeAlias(self, _child: ast.AST) -> None:
            return

    visitor = ControlVisitor()
    visitor.visit(node)
    return visitor.found


def _scope_bound_names(
    node: ast.AST,
    *,
    evaluate_annotations: bool = True,
) -> set[str]:
    """Return containing-scope names one executed AST construct may bind or delete."""

    class BindingVisitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.names: set[str] = set()

        def visit_Name(self, child: ast.Name) -> None:
            if isinstance(child.ctx, (ast.Store, ast.Del)):
                self.names.add(child.id)

        def _visit_function_header(self, child: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            self.names.add(child.name)
            for expression in [
                *child.decorator_list,
                *child.args.defaults,
                *(item for item in child.args.kw_defaults if item is not None),
            ]:
                self.visit(expression)
            if evaluate_annotations:
                for annotation in [
                    *(item.annotation for item in child.args.args),
                    *(item.annotation for item in child.args.posonlyargs),
                    *(item.annotation for item in child.args.kwonlyargs),
                    child.args.vararg.annotation if child.args.vararg is not None else None,
                    child.args.kwarg.annotation if child.args.kwarg is not None else None,
                    child.returns,
                ]:
                    if annotation is not None:
                        self.visit(annotation)
            for type_parameter in getattr(child, "type_params", ()):
                self.visit(type_parameter)

        def visit_FunctionDef(self, child: ast.FunctionDef) -> None:
            self._visit_function_header(child)

        def visit_AsyncFunctionDef(self, child: ast.AsyncFunctionDef) -> None:
            self._visit_function_header(child)

        def visit_ClassDef(self, child: ast.ClassDef) -> None:
            self.names.add(child.name)
            for expression in [
                *child.decorator_list,
                *child.bases,
                *(item.value for item in child.keywords),
            ]:
                self.visit(expression)
            for type_parameter in getattr(child, "type_params", ()):
                self.visit(type_parameter)

        def visit_Lambda(self, child: ast.Lambda) -> None:
            for expression in [
                *child.args.defaults,
                *(item for item in child.args.kw_defaults if item is not None),
            ]:
                self.visit(expression)

        def visit_AnnAssign(self, child: ast.AnnAssign) -> None:
            self.visit(child.target)
            if child.value is not None:
                self.visit(child.value)
            if evaluate_annotations:
                self.visit(child.annotation)

        def visit_TypeAlias(self, child: ast.AST) -> None:
            name = getattr(child, "name", None)
            if isinstance(name, ast.Name):
                self.names.add(name.id)

        def _visit_comprehension(self, child: ast.AST) -> None:
            # Comprehension targets have their own scope. Named expressions in
            # executed value/filter expressions may bind the containing scope,
            # but nested callable bodies remain deferred.
            outer = self

            class NamedExpressionVisitor(ast.NodeVisitor):
                def visit_NamedExpr(self, item: ast.NamedExpr) -> None:
                    outer.names.update(_bound_names(item.target))
                    self.visit(item.value)

                def visit_FunctionDef(self, _item: ast.FunctionDef) -> None:
                    return

                def visit_AsyncFunctionDef(self, _item: ast.AsyncFunctionDef) -> None:
                    return

                def visit_ClassDef(self, _item: ast.ClassDef) -> None:
                    return

                def visit_Lambda(self, item: ast.Lambda) -> None:
                    for expression in [
                        *item.args.defaults,
                        *(value for value in item.args.kw_defaults if value is not None),
                    ]:
                        self.visit(expression)

            NamedExpressionVisitor().visit(child)

        def visit_ListComp(self, child: ast.ListComp) -> None:
            self._visit_comprehension(child)

        def visit_SetComp(self, child: ast.SetComp) -> None:
            self._visit_comprehension(child)

        def visit_DictComp(self, child: ast.DictComp) -> None:
            self._visit_comprehension(child)

        def visit_GeneratorExp(self, child: ast.GeneratorExp) -> None:
            self._visit_comprehension(child)

        def visit_Import(self, child: ast.Import) -> None:
            self.names.update(alias.asname or alias.name.split(".")[0] for alias in child.names)

        def visit_ImportFrom(self, child: ast.ImportFrom) -> None:
            self.names.update(alias.asname or alias.name.split(".")[0] for alias in child.names)

        def visit_ExceptHandler(self, child: ast.ExceptHandler) -> None:
            if child.name:
                self.names.add(child.name)
            self.generic_visit(child)

        def visit_MatchAs(self, child: ast.MatchAs) -> None:
            if child.name:
                self.names.add(child.name)
            self.generic_visit(child)

        def visit_MatchStar(self, child: ast.MatchStar) -> None:
            if child.name:
                self.names.add(child.name)

        def visit_MatchMapping(self, child: ast.MatchMapping) -> None:
            if child.rest:
                self.names.add(child.rest)
            self.generic_visit(child)

    visitor = BindingVisitor()
    visitor.visit(node)
    return visitor.names


def _is_try_star(node: ast.AST) -> bool:
    """Return whether *node* is Python 3.11's optional ``ast.TryStar`` node."""
    try_star = getattr(ast, "TryStar", None)
    return try_star is not None and isinstance(node, try_star)


def _is_try_like(node: ast.AST) -> bool:
    return isinstance(node, ast.Try) or _is_try_star(node)


def _try_handlers(node: ast.AST) -> tuple[ast.ExceptHandler, ...]:
    handlers = getattr(node, "handlers", ())
    return tuple(item for item in handlers if isinstance(item, ast.ExceptHandler))


def _is_type_alias(node: ast.AST) -> bool:
    """Return whether *node* is Python 3.12's optional ``ast.TypeAlias`` node."""
    type_alias = getattr(ast, "TypeAlias", None)
    return type_alias is not None and isinstance(node, type_alias)


def _assignment_pairs(target: ast.expr, value: ast.expr) -> list[tuple[str, ast.expr]]:
    """Return exact name/value pairs for bounded, shape-equal destructuring."""
    if isinstance(target, ast.Name):
        return [(target.id, value)]
    if (
        isinstance(target, (ast.Tuple, ast.List))
        and isinstance(value, (ast.Tuple, ast.List))
        and len(target.elts) == len(value.elts)
    ):
        return [
            pair
            for target_item, value_item in zip(target.elts, value.elts, strict=True)
            for pair in _assignment_pairs(target_item, value_item)
        ]
    return []


def _bound_names(target: ast.AST) -> set[str]:
    """Return names bound or deleted by one assignment target."""
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        return {name for item in target.elts for name in _bound_names(item)}
    return set()


def _merge_discovery_conditions(
    *groups: tuple[EndpointDiscoveryCondition, ...],
) -> tuple[EndpointDiscoveryCondition, ...]:
    """Merge immutable provenance deterministically without duplicates."""
    unique = {
        (str(condition.source_path), condition.source_line, condition.reason): condition
        for group in groups
        for condition in group
    }
    return tuple(unique[key] for key in sorted(unique))


def _merge_ordered_limitations(
    *groups: tuple[_OrderedInventoryLimitation, ...],
) -> tuple[_OrderedInventoryLimitation, ...]:
    """Merge source-ordered inventory limitations deterministically."""
    unique = {
        (
            limitation.origin_module,
            limitation.order,
            str(limitation.condition.source_path),
            limitation.condition.source_line,
            limitation.condition.reason,
            limitation.endpoint_impact,
        ): limitation
        for group in groups
        for limitation in group
    }
    return tuple(unique[key] for key in sorted(unique))


def _node_token(node: ast.AST) -> str:
    """Return a deterministic source-position identity for one operation."""
    return ":".join(
        str(value)
        for value in (
            getattr(node, "lineno", 0),
            getattr(node, "col_offset", 0),
            getattr(node, "end_lineno", 0),
            getattr(node, "end_col_offset", 0),
        )
    )


def _node_order(node: ast.AST) -> int:
    """Return a deterministic source-order token, including same-line statements."""
    return getattr(node, "lineno", 0) * _ORDER_SCALE + getattr(node, "col_offset", 0)


def _line_end_order(line: int) -> int:
    """Return an order token after every statement starting on one source line."""
    return line * _ORDER_SCALE + (_ORDER_SCALE - 1)


def _module_binds_name(tree: ast.Module, name: str) -> bool:
    """Return whether package initialization may bind or synthesize a name."""
    if any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "__getattr__"
        for node in tree.body
    ):
        return True
    return any(_statement_may_bind_name(node, name) for node in tree.body)


def _statement_may_bind_name(node: ast.stmt, name: str) -> bool:  # noqa: PLR0911
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return node.name == name
    if isinstance(node, ast.Import):
        return any((alias.asname or alias.name.split(".")[0]) == name for alias in node.names)
    if isinstance(node, ast.ImportFrom):
        return any(
            alias.name == "*" or (alias.asname or alias.name) == name for alias in node.names
        )
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        targets = [node.target] if isinstance(node, ast.AnnAssign) else node.targets
        return any(name in _bound_names(target) for target in targets)
    if isinstance(node, (ast.For, ast.AsyncFor)) and name in _bound_names(node.target):
        return True
    if isinstance(node, (ast.With, ast.AsyncWith)) and any(
        item.optional_vars is not None and name in _bound_names(item.optional_vars)
        for item in node.items
    ):
        return True
    nested: list[ast.stmt] = []
    for attribute in ("body", "orelse", "finalbody"):
        value = getattr(node, attribute, None)
        if isinstance(value, list):
            nested.extend(item for item in value if isinstance(item, ast.stmt))
    if _is_try_like(node):
        nested.extend(item for handler in _try_handlers(node) for item in handler.body)
    if isinstance(node, ast.Match):
        nested.extend(item for case in node.cases for item in case.body)
    return any(_statement_may_bind_name(item, name) for item in nested)


def _assignment_name(node: ast.Assign | ast.AnnAssign) -> str | None:
    if isinstance(node, ast.AnnAssign):
        return node.target.id if isinstance(node.target, ast.Name) else None
    if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
        return node.targets[0].id
    return None


def _keyword_expr(call: ast.Call, name: str) -> ast.expr | None:
    return next((keyword.value for keyword in call.keywords if keyword.arg == name), None)


def _literal_methods(expression: ast.expr) -> tuple[str, ...]:
    if not isinstance(expression, (ast.List, ast.Tuple, ast.Set)):
        return ()
    methods: list[str] = []
    for element in expression.elts:
        if not isinstance(element, ast.Constant) or not isinstance(element.value, str):
            return ()
        method = element.value.upper()
        if method not in EndpointMethod.__members__:
            return ()
        methods.append(method)
    return tuple(methods)


def _join_paths(prefix: str, path: str) -> str:
    if not prefix:
        return path if path.startswith("/") else f"/{path}" if path else "/"
    normalized_prefix = prefix if prefix.startswith("/") else f"/{prefix}"
    normalized_prefix = normalized_prefix.rstrip("/")
    if not path:
        return normalized_prefix or "/"
    if path == "/":
        return f"{normalized_prefix}/" if normalized_prefix else "/"
    return f"{normalized_prefix}/{path.lstrip('/')}"
