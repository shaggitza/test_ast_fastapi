"""Conservative, execution-free FastAPI route discovery."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path  # noqa: TC003 - Pydantic models consume paths at runtime
from typing import ClassVar, Literal

from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo


class SecureASTExtractorError(Exception):
    """Error during secure AST extraction."""


ObjectKey = tuple[str, str]
ObjectKind = Literal["app", "router"]


@dataclass(frozen=True)
class _Object:
    key: ObjectKey
    variable: str
    kind: ObjectKind
    prefix: str
    line: int


@dataclass(frozen=True)
class _Route:
    owner: ObjectKey
    path: str
    methods: tuple[str, ...]
    handler: HandlerInfo
    line: int


@dataclass(frozen=True)
class _Edge:
    parent: ObjectKey
    child: ObjectKey
    prefix: str
    line: int
    child_cutoff: int | None


@dataclass
class _Module:
    name: str
    path: Path
    tree: ast.Module
    is_package: bool
    imports: dict[str, tuple[str, str]] = field(default_factory=dict)
    module_imports: dict[str, str] = field(default_factory=dict)
    fastapi_names: set[str] = field(default_factory=set)
    router_names: set[str] = field(default_factory=set)
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = field(default_factory=dict)
    objects: dict[str, list[_Object]] = field(default_factory=dict)
    assignments: dict[str, list[int]] = field(default_factory=dict)
    strings: dict[str, list[tuple[int, str | None]]] = field(default_factory=dict)


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

    def __init__(self, app_path: Path, app_variable: str = "app") -> None:
        self.app_path = app_path.resolve()
        self.app_variable = app_variable

    def extract_endpoints(self) -> list[Endpoint]:
        modules, entry_module = self._load_modules()
        if not modules:
            return []

        aliases = self._module_aliases(modules)
        for module in modules.values():
            self._collect_symbols(module, aliases, modules)

        objects = {
            item.key: item
            for module in modules.values()
            for history in module.objects.values()
            for item in history
        }
        routes = [
            route
            for module in modules.values()
            for route in self._collect_routes(module, aliases, modules)
        ]
        edges = [
            edge
            for module in modules.values()
            for edge in self._collect_edges(module, aliases, modules)
        ]

        referenced = {edge.child for edge in edges}
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
            history = module.objects.get(self.app_variable, [])
            roots = [history[-1].key] if history and history[-1].kind == "router" else []

        routes_by_owner: dict[ObjectKey, list[_Route]] = {}
        edges_by_parent: dict[ObjectKey, list[_Edge]] = {}
        for route in routes:
            routes_by_owner.setdefault(route.owner, []).append(route)
        for edge in edges:
            edges_by_parent.setdefault(edge.parent, []).append(edge)

        found: list[Endpoint] = []

        def visit(
            owner: ObjectKey,
            inherited: str,
            cutoff: int | None,
            stack: frozenset[ObjectKey],
        ) -> None:
            if owner in stack:
                return
            item = objects[owner]
            prefix = _join_paths(inherited, item.prefix)
            for route in routes_by_owner.get(owner, []):
                if cutoff is not None and route.line > cutoff:
                    continue
                found.append(
                    Endpoint(
                        path=_join_paths(prefix, route.path),
                        methods=[EndpointMethod(method) for method in route.methods],
                        handler=route.handler,
                    )
                )
            for edge in edges_by_parent.get(owner, []):
                if cutoff is not None and edge.line > cutoff:
                    continue
                visit(
                    edge.child,
                    _join_paths(prefix, edge.prefix),
                    edge.child_cutoff,
                    stack | {owner},
                )

        for root in sorted(set(roots)):
            visit(root, "", None, frozenset())
        return sorted(
            found,
            key=lambda endpoint: (
                endpoint.identifier,
                str(endpoint.handler.file_path),
                endpoint.handler.line_number,
            ),
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

    def _load_modules(self) -> tuple[dict[str, _Module], str | None]:
        root = self._source_root()
        modules: dict[str, _Module] = {}
        entry_module: str | None = None
        for path in self._find_python_files(root):
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            except (OSError, SyntaxError, UnicodeError):
                continue
            relative = path.relative_to(root).with_suffix("")
            parts = list(relative.parts)
            is_package = bool(parts and parts[-1] == "__init__")
            if is_package:
                parts.pop()
            name = ".".join(parts) or path.parent.name
            modules[name] = _Module(name, path, tree, is_package)
            if self.app_path.is_file() and path == self.app_path:
                entry_module = name
        return modules, entry_module

    def _module_aliases(self, modules: dict[str, _Module]) -> dict[str, str]:
        aliases: dict[str, str] = {}
        root_name = self._source_root().name
        for name in modules:
            aliases[name] = name
            aliases[f"{root_name}.{name}"] = name
        return aliases

    def _collect_symbols(  # noqa: PLR0912 - one ordered pass models module execution
        self,
        module: _Module,
        aliases: dict[str, str],
        modules: dict[str, _Module],
    ) -> None:
        for node in module.tree.body:
            if isinstance(node, ast.ImportFrom):
                target_module = self._absolute_import(module, node)
                for alias in node.names:
                    local = alias.asname or alias.name
                    submodule = aliases.get(f"{target_module}.{alias.name}")
                    if submodule in modules:
                        module.module_imports[local] = submodule
                    else:
                        module.imports[local] = (target_module, alias.name)
                    if node.module == "fastapi" and alias.name == "FastAPI":
                        module.fastapi_names.add(local)
                    if node.module == "fastapi" and alias.name == "APIRouter":
                        module.router_names.add(local)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    imported_module = alias.name if alias.asname else alias.name.split(".")[0]
                    module.module_imports[local] = aliases.get(imported_module, imported_module)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                module.functions[node.name] = node
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                assigned_name = _assignment_name(node)
                value = node.value
                if assigned_name is None or value is None:
                    continue
                module.assignments.setdefault(assigned_name, []).append(node.lineno)
                string = self._literal_string(value, module, node.lineno)
                module.strings.setdefault(assigned_name, []).append((node.lineno, string))
                constructor = self._constructor_kind(value, module)
                if constructor is not None:
                    assert isinstance(value, ast.Call)
                    prefix = self._keyword_string(value, "prefix", module, node.lineno) or ""
                    item = _Object(
                        key=(module.name, f"{assigned_name}@{node.lineno}"),
                        variable=assigned_name,
                        kind=constructor,
                        prefix=prefix,
                        line=node.lineno,
                    )
                    module.objects.setdefault(assigned_name, []).append(item)
                # Python assignments can shadow imported constructors. Constructor
                # recognition after this statement must follow the rebound name.
                module.fastapi_names.discard(assigned_name)
                module.router_names.discard(assigned_name)

    def _constructor_kind(self, value: ast.expr, module: _Module) -> ObjectKind | None:
        if not isinstance(value, ast.Call):
            return None
        if isinstance(value.func, ast.Name):
            if value.func.id in module.fastapi_names:
                return "app"
            if value.func.id in module.router_names:
                return "router"
        if isinstance(value.func, ast.Attribute) and isinstance(value.func.value, ast.Name):
            imported = module.module_imports.get(value.func.value.id)
            if imported == "fastapi" and value.func.attr == "FastAPI":
                return "app"
            if imported == "fastapi" and value.func.attr == "APIRouter":
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
        return item if eligible_assignments and item.line == eligible_assignments[-1] else None

    def _collect_routes(
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
                        routes.append(
                            _Route(
                                decorated_owner.key,
                                decorated_path,
                                methods,
                                handler,
                                node.lineno,
                            )
                        )
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                call = node.value
                if not isinstance(call.func, ast.Attribute) or call.func.attr != "add_api_route":
                    continue
                imperative_owner = self._resolve_object(
                    call.func.value, module, aliases, modules, node.lineno
                )
                if imperative_owner is None or imperative_owner.key[0] != module.name:
                    # Mutating an imported router/app requires cross-module execution
                    # ordering. Skip rather than violating include-time snapshots.
                    continue
                path_expr = call.args[0] if call.args else _keyword_expr(call, "path")
                handler_expr = (
                    call.args[1] if len(call.args) > 1 else _keyword_expr(call, "endpoint")
                )
                imperative_path = self._literal_string(path_expr, module, node.lineno)
                imperative_handler = self._resolve_handler(handler_expr, module, aliases, modules)
                if imperative_path is None or imperative_handler is None:
                    continue
                methods_expr = _keyword_expr(call, "methods")
                methods = _literal_methods(methods_expr) if methods_expr is not None else ("GET",)
                if methods:
                    routes.append(
                        _Route(
                            imperative_owner.key,
                            imperative_path,
                            methods,
                            imperative_handler,
                            node.lineno,
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
            if parent is None or parent.key[0] != module.name:
                # Mutating an imported parent is dynamic cross-module state.
                continue
            if call.func.attr == "include_router":
                child_expr = call.args[0] if call.args else _keyword_expr(call, "router")
                child = self._resolve_object(child_expr, module, aliases, modules, node.lineno)
                if child is None or child.kind != "router":
                    continue
                prefix = self._keyword_string(call, "prefix", module, node.lineno) or ""
                cutoff = node.lineno if child.key[0] == module.name else None
                edges.append(_Edge(parent.key, child.key, prefix, node.lineno, cutoff))
            elif call.func.attr == "mount":
                path_expr = call.args[0] if call.args else _keyword_expr(call, "path")
                child_expr = call.args[1] if len(call.args) > 1 else _keyword_expr(call, "app")
                path = self._literal_string(path_expr, module, node.lineno)
                child = self._resolve_object(child_expr, module, aliases, modules, node.lineno)
                if path is None or child is None or child.kind != "app":
                    continue
                cutoff = node.lineno if child.key[0] == module.name else None
                edges.append(_Edge(parent.key, child.key, path, node.lineno, cutoff))
        return edges

    def _resolve_object(
        self,
        expression: ast.expr | None,
        module: _Module,
        aliases: dict[str, str],
        modules: dict[str, _Module],
        line: int,
    ) -> _Object | None:
        if isinstance(expression, ast.Name):
            local = self._object_at(module, expression.id, line)
            if local is not None:
                return local
            imported = module.imports.get(expression.id)
            if imported is not None:
                target = modules.get(aliases.get(imported[0], ""))
                if target is not None:
                    return self._object_at(target, imported[1], None)
        if isinstance(expression, ast.Attribute) and isinstance(expression.value, ast.Name):
            target_name = module.module_imports.get(expression.value.id)
            target = modules.get(aliases.get(target_name or "", target_name or ""))
            if target is not None:
                return self._object_at(target, expression.attr, None)
        return None

    def _resolve_handler(
        self,
        expression: ast.expr | None,
        module: _Module,
        aliases: dict[str, str],
        modules: dict[str, _Module],
    ) -> HandlerInfo | None:
        if isinstance(expression, ast.Name):
            function = module.functions.get(expression.id)
            if function is not None:
                return self._handler(module, function)
            imported = module.imports.get(expression.id)
            if imported is not None:
                target = modules.get(aliases.get(imported[0], ""))
                if target is not None and imported[1] in target.functions:
                    return self._handler(target, target.functions[imported[1]])
        if isinstance(expression, ast.Attribute) and isinstance(expression.value, ast.Name):
            target_name = module.module_imports.get(expression.value.id, "")
            target = modules.get(aliases.get(target_name, target_name))
            if target is not None and expression.attr in target.functions:
                return self._handler(target, target.functions[expression.attr])
        return None

    def _literal_string(
        self, expression: ast.expr | None, module: _Module, line: int
    ) -> str | None:
        if isinstance(expression, ast.Constant) and isinstance(expression.value, str):
            return expression.value
        if isinstance(expression, ast.Name):
            history = module.strings.get(expression.id, [])
            values = [value for item_line, value in history if item_line <= line]
            return values[-1] if values else None
        if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Add):
            left = self._literal_string(expression.left, module, line)
            right = self._literal_string(expression.right, module, line)
            return left + right if left is not None and right is not None else None
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
