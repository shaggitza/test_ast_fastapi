"""
Mypy-based dependency analyzer.

This module uses mypy's type analysis to determine which code paths
each endpoint handler actually uses, providing more precise dependency
tracking than import-based analysis.

It relies entirely on mypy for AST parsing and type resolution,
using mypy's internal data structures to track file/line references.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path, PurePosixPath
from typing import Any

from fastapi_endpoint_detector.models.endpoint import Endpoint

# Type alias for line-level progress callback (file_path, line_number, symbol_name)
LineProgressCallback = Callable[[str, int, str], None]


class MypyAnalyzerError(Exception):
    """Error during mypy analysis."""

    pass


@dataclass
class CallFrame:
    """A single frame in the call stack."""

    file_path: str
    line_number: int
    function_name: str
    code_context: str = ""


@dataclass
class SymbolReference:
    """A reference to a specific symbol (function/method/class) with its line range."""

    file_path: str
    symbol_name: str
    start_line: int
    end_line: int

    def contains_line(self, line: int) -> bool:
        """Check if a line number falls within this symbol's range."""
        return self.start_line <= line <= self.end_line


@dataclass
class EndpointDependencies:
    """Dependencies for a single endpoint determined by mypy."""

    endpoint_id: str
    methods: list[str]
    path: str
    referenced_files: dict[str, set[int]] = field(default_factory=dict)
    """Mapping of file path -> set of referenced line numbers."""
    referenced_symbols: list[SymbolReference] = field(default_factory=list)
    """List of symbol references with their file paths and line ranges."""
    call_stacks: dict[str, list[list[CallFrame]]] = field(default_factory=dict)
    """Mapping of file path -> list of call stacks showing all paths from handler to that file."""
    source_root: str = ""
    project_files: set[str] = field(default_factory=set)

    def add_reference(self, file_path: str, line: int, symbol_name: str = "") -> None:
        """Add a line reference to dependencies."""
        if file_path not in self.referenced_files:
            self.referenced_files[file_path] = set()
        self.referenced_files[file_path].add(line)

    def add_symbol_reference(
        self, file_path: str, symbol_name: str, start_line: int, end_line: int
    ) -> None:
        """Add a symbol reference and its line range to dependencies."""
        ref = SymbolReference(file_path, symbol_name, start_line, end_line)
        self.referenced_symbols.append(ref)

        if file_path not in self.referenced_files:
            self.referenced_files[file_path] = set()
        self.referenced_files[file_path].update(range(start_line, end_line + 1))

    @staticmethod
    def _parts(path: str) -> tuple[str, ...]:
        return PurePosixPath(path.replace("\\", "/")).parts

    def _canonical(self, path: str) -> str:
        candidate = Path(path.replace("\\", os.sep))
        if not candidate.is_absolute() and self.source_root:
            candidate = Path(self.source_root) / candidate
        return str(candidate.resolve())

    def _matching_paths(self, file_path: str, keys: set[str]) -> set[str]:
        """Resolve one query to project files, failing closed when ambiguous."""
        if not keys:
            return set()
        inventory = self.project_files or keys
        canonical_inventory: dict[str, set[str]] = {}
        for item in inventory:
            canonical_inventory.setdefault(self._canonical(item), set()).add(item)

        query_canonical = self._canonical(file_path)
        exact = canonical_inventory.get(query_canonical, set())
        if len(exact) == 1:
            selected = query_canonical
        else:
            query_parts = self._parts(file_path)
            suffixes = {
                canonical
                for canonical in canonical_inventory
                if len(query_parts) <= len(self._parts(canonical))
                and self._parts(canonical)[-len(query_parts) :] == query_parts
            }
            if len(suffixes) != 1:
                return set()
            selected = next(iter(suffixes))
        return {key for key in keys if self._canonical(key) == selected}

    def references_symbol_at_line(self, file_path: str, line: int) -> SymbolReference | None:
        """Check if any unambiguously resolved symbol contains the given line."""
        keys = {ref.file_path for ref in self.referenced_symbols}
        matches = self._matching_paths(file_path, keys)
        return next(
            (
                ref
                for ref in self.referenced_symbols
                if ref.file_path in matches and ref.contains_line(line)
            ),
            None,
        )

    def references_file(self, file_path: str) -> bool:
        """Check if this endpoint unambiguously references a file."""
        return bool(self._matching_paths(file_path, set(self.referenced_files)))

    def references_lines(self, file_path: str, lines: set[int]) -> set[int]:
        """Get referenced changed lines for one unambiguously resolved file."""
        matches = self._matching_paths(file_path, set(self.referenced_files))
        return (
            set().union(*(self.referenced_files[path] & lines for path in matches))
            if matches
            else set()
        )

    def get_call_stack(self, file_path: str) -> list[list[CallFrame]]:
        """Get all unique call stacks for one unambiguously resolved file."""
        matches = self._matching_paths(file_path, set(self.call_stacks))
        stacks: list[list[CallFrame]] = []
        for path in self.call_stacks:
            if path in matches:
                for stack in self.call_stacks[path]:
                    if stack not in stacks:
                        stacks.append(stack)
        return stacks


class MypyAnalyzer:
    """
    Analyze endpoint dependencies using mypy's type system.

    Uses mypy's build API with proper configuration to get typed ASTs
    and extract precise file/line information for all references.
    """

    CACHE_SCHEMA_VERSION = 3

    def __init__(self, app_path: Path, *, max_depth: int = 10) -> None:
        """Initialize the mypy analyzer."""
        if max_depth < 1:
            raise ValueError("max_depth must be at least 1")
        self.app_path = app_path.resolve()
        self.source_root = self.app_path.parent if self.app_path.is_file() else self.app_path
        self.max_depth = max_depth
        self._endpoint_deps: dict[str, EndpointDependencies] = {}
        self._mypy_available = self._check_mypy_available()
        self._cache_file: Path | None = None
        self._line_progress_callback: LineProgressCallback | None = None

        # Mypy build results - stored to prevent GC
        self._build_result: Any = None
        self._trees: dict[str, Any] = {}  # module_name -> MypyFile
        self._module_to_path: dict[str, str] = {}
        self._types_map: dict[Any, Any] = {}  # AST node -> Type

    @property
    def cache_path(self) -> Path:
        """Path to the mypy analysis cache file."""
        if self._cache_file:
            return self._cache_file
        return self.source_root / ".endpoint_mypy_cache.json"

    def set_cache_path(self, path: Path) -> None:
        """Set a custom cache file path."""
        self._cache_file = path

    def set_line_progress_callback(self, callback: LineProgressCallback | None) -> None:
        """Set a callback for line-level progress reporting."""
        self._line_progress_callback = callback

    def _check_mypy_available(self) -> bool:
        """Check if mypy is available."""
        try:
            from mypy.build import build
            from mypy.nodes import MypyFile

            return True
        except ImportError:
            return False

    def _get_source_root(self) -> Path:
        """Get the source root directory."""
        if self.app_path.is_file():
            return self.app_path.parent
        return self.app_path

    def _ensure_mypy_built(self) -> None:
        """Ensure mypy has analyzed the project and we have the typed ASTs."""
        if self._trees:
            return

        if not self._mypy_available:
            raise MypyAnalyzerError("mypy is not installed")

        from mypy.build import build as mypy_build
        from mypy.fscache import FileSystemCache
        from mypy.modulefinder import BuildSource
        from mypy.options import Options

        source_root = self._get_source_root()

        # Collect all Python files
        sources: list[BuildSource] = []
        for py_file in source_root.rglob("*.py"):
            if any(part.startswith((".", "__pycache__")) for part in py_file.parts):
                continue

            try:
                rel_path = py_file.relative_to(source_root.parent)
                if rel_path.name == "__init__.py":
                    module_name = str(rel_path.parent).replace("/", ".").replace("\\", ".")
                else:
                    module_name = str(rel_path.with_suffix("")).replace("/", ".").replace("\\", ".")
            except ValueError:
                module_name = py_file.stem

            sources.append(BuildSource(path=str(py_file), module=module_name))
            self._module_to_path[module_name] = str(py_file)

        # Configure mypy for full analysis with AST retention
        options = Options()
        options.ignore_missing_imports = True
        options.follow_imports = "normal"
        options.mypy_path = [str(source_root.parent)]
        options.namespace_packages = True
        options.explicit_package_bases = True
        options.preserve_asts = True
        options.incremental = False
        options.check_untyped_defs = True
        options.export_types = True  # Critical for type information!

        original_path = sys.path.copy()
        if str(source_root.parent) not in sys.path:
            sys.path.insert(0, str(source_root.parent))

        try:
            fscache = FileSystemCache()
            self._build_result = mypy_build(sources=sources, options=options, fscache=fscache)

            # Store the types map
            self._types_map = self._build_result.types

            # Capture modules with trees
            for module_name, state in self._build_result.graph.items():
                if state.path:
                    self._module_to_path[module_name] = state.path
                tree = state.tree
                if tree is not None:
                    self._trees[module_name] = tree

        finally:
            sys.path = original_path

    def _find_func_in_tree(
        self,
        tree: Any,
        func_name: str,
        *,
        qualified_name: str | None = None,
        line_hint: int | None = None,
    ) -> tuple[Any, str] | None:
        """Resolve one function by qualified identity or source location."""
        from mypy.nodes import ClassDef, Decorator, FuncDef, OverloadedFuncDef

        candidates: list[tuple[Any, str]] = []
        for defn in tree.defs:
            if isinstance(defn, FuncDef) and defn.name == func_name:
                candidates.append((defn, defn.name))
            elif isinstance(defn, Decorator) and defn.func.name == func_name:
                candidates.append((defn, defn.func.name))
            elif isinstance(defn, OverloadedFuncDef) and defn.name == func_name:
                if defn.items:
                    candidates.append((defn.items[0], defn.name))
            elif isinstance(defn, ClassDef):
                for item in defn.defs.body:
                    if isinstance(item, FuncDef) and item.name == func_name:
                        candidates.append((item, f"{defn.name}.{item.name}"))
                    elif isinstance(item, Decorator) and item.func.name == func_name:
                        candidates.append((item, f"{defn.name}.{item.func.name}"))

        if qualified_name:
            exact = [candidate for candidate in candidates if candidate[1] == qualified_name]
            if len(exact) == 1:
                return exact[0]
        if line_hint is not None:
            at_line = []
            for candidate in candidates:
                node = candidate[0].func if isinstance(candidate[0], Decorator) else candidate[0]
                start, end = self._get_func_lines(node)
                declaration_start = min(start, getattr(candidate[0], "line", start))
                if declaration_start <= line_hint <= end:
                    at_line.append(candidate)
            if len(at_line) == 1:
                return at_line[0]
        return candidates[0] if len(candidates) == 1 else None

    def _get_func_lines(self, func_node: Any) -> tuple[int, int]:
        """Get the start and end lines of a function node."""
        start = func_node.line
        end = getattr(func_node, "end_line", None)
        if end is None:
            end = start + 50  # Estimate
        return start, end

    def _resolve_fullname_to_file(self, fullname: str) -> tuple[str, str] | None:
        """
        Try to resolve a fullname to (file_path, module_name).

        Returns None if not found in our project.
        """
        parts = fullname.split(".")

        # Try progressively shorter module paths
        for i in range(len(parts), 0, -1):
            candidate = ".".join(parts[:i])
            if candidate in self._module_to_path:
                return self._module_to_path[candidate], candidate
            if candidate in self._trees:
                state = self._build_result.graph.get(candidate)
                if state and state.path:
                    return state.path, candidate

        # Source files are named relative to source_root.parent so a project in
        # ``/tmp/example`` is indexed as ``example.services``. Mypy can still
        # resolve ``from services import func`` as ``services.func`` when the
        # application directory itself is on Python's import path. Bridge that
        # representation mismatch, but only when the suffix identifies one
        # project module unambiguously.
        suffix_matches = [
            mod_name
            for mod_name in self._module_to_path
            if mod_name.endswith(f".{parts[0]}") or mod_name == parts[0]
        ]
        if len(suffix_matches) == 1:
            module_name = suffix_matches[0]
            return self._module_to_path[module_name], module_name

        # If not found by module path, search for the function/class by fullname match
        # This handles imported functions where fullname might not map directly to module structure
        for mod_name, tree in self._trees.items():
            if hasattr(tree, "defs"):
                for defn in tree.defs:
                    # Check if this definition's fullname matches what we're looking for
                    if hasattr(defn, "fullname"):
                        # Look for exact fullname match or name-based match
                        if defn.fullname == fullname:
                            # Exact match - this is the definition
                            if mod_name in self._module_to_path:
                                return self._module_to_path[mod_name], mod_name
                            state = self._build_result.graph.get(mod_name)
                            if state and state.path:
                                return state.path, mod_name

        return None

    def _get_type_from_node(self, node: Any) -> Any:
        """Get the type of an AST node from mypy's type map."""
        return self._types_map.get(node)

    def _import_map_for_tree(self, tree: Any, module_name: str) -> dict[str, str]:
        """Build local-to-full symbol aliases for one module's imports."""
        from mypy.nodes import Import, ImportFrom

        import_map: dict[str, str] = {}
        for definition in getattr(tree, "defs", []):
            if isinstance(definition, ImportFrom):
                imported_module = definition.id
                sibling = (
                    f"{module_name.rsplit('.', 1)[0]}.{imported_module}"
                    if "." in module_name
                    else imported_module
                )
                full_module = sibling if sibling in self._module_to_path else imported_module
                for original, alias in definition.names:
                    import_map[alias or original] = f"{full_module}.{original}"
            elif isinstance(definition, Import):
                for imported_module, alias in definition.ids:
                    import_map[alias or imported_module] = imported_module
        return import_map

    @staticmethod
    def _endpoint_key(endpoint: Endpoint) -> str:
        """Key dependency data by public route and physical handler identity."""
        handler = endpoint.handler
        return json.dumps(
            [
                endpoint.identifier,
                str(handler.file_path.resolve()),
                handler.line_number,
                handler.name,
                handler.module,
            ],
            separators=(",", ":"),
        )

    def analyze_endpoint(self, endpoint: Endpoint) -> EndpointDependencies:
        """Analyze a single endpoint using mypy's typed AST."""
        deps = EndpointDependencies(
            endpoint_id=endpoint.identifier,
            methods=[m.value for m in endpoint.methods],
            path=endpoint.path,
            source_root=str(self.source_root),
            project_files={str(path.resolve()) for path in self.source_root.rglob("*.py")},
        )

        handler = endpoint.handler
        if not handler.file_path:
            return deps

        try:
            self._ensure_mypy_built()
        except MypyAnalyzerError:
            return deps

        # Find the module containing the handler
        handler_path = str(Path(handler.file_path).resolve())
        handler_module: str | None = None

        for mod_name, mod_path in self._module_to_path.items():
            try:
                if Path(mod_path).resolve() == Path(handler_path).resolve():
                    handler_module = mod_name
                    break
            except Exception:
                continue

        if not handler_module or handler_module not in self._trees:
            # Module not found - retain only the attested handler span.
            start = handler.line_number
            end = handler.end_line_number or start
            deps.add_symbol_reference(handler_path, handler.name, start, end)
            self._endpoint_deps[self._endpoint_key(endpoint)] = deps
            return deps

        tree = self._trees[handler_module]

        # Find the handler function
        result = self._find_func_in_tree(tree, handler.name, line_hint=handler.line_number)
        if not result:
            start = handler.line_number
            end = handler.end_line_number or start
            deps.add_symbol_reference(handler_path, handler.name, start, end)
            self._endpoint_deps[self._endpoint_key(endpoint)] = deps
            return deps

        func_node, func_qname = result

        # If we got a Decorator, get the actual function for line numbers
        from mypy.nodes import Decorator as DecoratorNode

        actual_func = func_node.func if isinstance(func_node, DecoratorNode) else func_node

        start, end = self._get_func_lines(actual_func)
        deps.add_symbol_reference(handler_path, handler.name, start, end)

        import_map = self._import_map_for_tree(tree, handler_module)

        # Trace all references in the function body
        visited: dict[str, int] = {}
        call_stack = [CallFrame(handler_path, start, handler.name)]

        self._trace_references(
            func_node,
            deps,
            handler_path,
            handler_module,
            call_stack,
            visited,
            import_map,
            depth=0,
        )

        self._endpoint_deps[self._endpoint_key(endpoint)] = deps
        return deps

    def _trace_references(
        self,
        node: Any,
        deps: EndpointDependencies,
        current_file: str,
        current_module: str,
        call_stack: list[CallFrame],
        visited: dict[str, int],
        import_map: dict[str, str] | None = None,
        *,
        depth: int,
    ) -> None:
        """
        Trace all references in a mypy AST node.

        Uses mypy's types map to resolve method calls when type info is available.

        Args:
            import_map: Maps local names to their actual fullnames from imports
        """
        if import_map is None:
            import_map = {}

        from mypy.nodes import (
            AssertStmt,
            AssignmentStmt,
            AwaitExpr,
            Block,
            CallExpr,
            ClassDef,
            ComparisonExpr,
            ConditionalExpr,
            Decorator,
            DictExpr,
            DictionaryComprehension,
            ExpressionStmt,
            ForStmt,
            FuncDef,
            GeneratorExpr,
            IfStmt,
            Import,
            ImportFrom,
            IndexExpr,
            LambdaExpr,
            ListComprehension,
            ListExpr,
            MemberExpr,
            NameExpr,
            OpExpr,
            RaiseStmt,
            ReturnStmt,
            SetComprehension,
            SetExpr,
            TryStmt,
            TupleExpr,
            UnaryExpr,
            WhileStmt,
            WithStmt,
            YieldExpr,
            YieldFromExpr,
        )
        from mypy.types import Instance

        def resolve_and_trace(fullname: str, call_line: int) -> None:
            """Resolve a fullname at the next call depth and trace into it."""
            target_depth = depth + 1
            if target_depth > self.max_depth:
                return
            previous_depth = visited.get(fullname)
            should_recurse = previous_depth is None or target_depth < previous_depth
            if should_recurse:
                visited[fullname] = target_depth

            # Report progress
            if self._line_progress_callback:
                self._line_progress_callback(
                    current_file, call_line, fullname.rsplit(".", maxsplit=1)[-1]
                )

            # Try to find the target file
            result = self._resolve_fullname_to_file(fullname)
            if not result:
                return

            target_path, target_module = result

            # Skip if outside our project trees
            if target_module not in self._trees:
                return

            target_tree = self._trees[target_module]

            # Extract the symbol name from fullname
            parts = fullname.split(".")
            # The symbol name is everything after the module name
            if fullname.startswith(target_module):
                symbol_name = (
                    fullname[len(target_module) + 1 :] if len(fullname) > len(target_module) else ""
                )
            else:
                symbol_name = parts[-1]

            # Try to find the function in the target tree
            func_name = symbol_name.split(".")[-1] if symbol_name else parts[-1]
            func_result = self._find_func_in_tree(
                target_tree,
                func_name,
                qualified_name=symbol_name or None,
            )

            if func_result:
                target_func, qname = func_result
                start, end = self._get_func_lines(target_func)
                deps.add_symbol_reference(target_path, fullname, start, end)

                # Record call stack - store all unique paths
                if target_path not in deps.call_stacks:
                    deps.call_stacks[target_path] = []
                # Add this call stack if it's unique (not already recorded)
                current_stack = list(call_stack)
                if current_stack not in deps.call_stacks[target_path]:
                    deps.call_stacks[target_path].append(current_stack)

                # Recursively trace into the target function
                new_frame = CallFrame(target_path, start, fullname)
                new_stack = call_stack + [new_frame]

                if should_recurse and target_depth < self.max_depth:
                    self._trace_references(
                        target_func,
                        deps,
                        target_path,
                        target_module,
                        new_stack,
                        visited,
                        self._import_map_for_tree(target_tree, target_module),
                        depth=target_depth,
                    )
            else:
                class_candidates = [
                    definition
                    for definition in target_tree.defs
                    if isinstance(definition, ClassDef) and definition.name == func_name
                ]
                if len(class_candidates) == 1:
                    class_node = class_candidates[0]
                    start = class_node.line
                    end = class_node.end_line or start
                    deps.add_symbol_reference(target_path, fullname, start, end)
                    current_stack = list(call_stack)
                    stacks = deps.call_stacks.setdefault(target_path, [])
                    if current_stack not in stacks:
                        stacks.append(current_stack)
                # Ambiguous or unresolved symbols are not converted into
                # fabricated module ranges; doing so creates unrelated impacts.

        def handle_call_expr(call: CallExpr) -> None:
            """Handle a function/method call expression."""
            callee = call.callee

            if isinstance(callee, NameExpr):
                # Direct function call: func()
                if callee.fullname:
                    actual_fullname = callee.fullname

                    # Try to resolve using import map first
                    if callee.name in import_map:
                        actual_fullname = import_map[callee.name]
                    # Try to get the actual definition location from the node
                    elif hasattr(callee, "node") and callee.node:
                        node = callee.node
                        # Check if the node has a fullname (it's the actual definition)
                        if hasattr(node, "fullname") and node.fullname:
                            actual_fullname = node.fullname

                    deps.add_reference(current_file, call.line, actual_fullname)
                    resolve_and_trace(actual_fullname, call.line)

            elif isinstance(callee, MemberExpr):
                # Method call: obj.method()
                if callee.fullname:
                    # Mypy resolved the method name
                    deps.add_reference(current_file, call.line, callee.fullname)

                    # Try to get actual definition location
                    actual_fullname = callee.fullname
                    if hasattr(callee, "node") and callee.node:
                        node = callee.node
                        if hasattr(node, "fullname") and node.fullname:
                            actual_fullname = node.fullname

                    resolve_and_trace(actual_fullname, call.line)
                else:
                    # Try to resolve via type information
                    receiver_type = self._get_type_from_node(callee.expr)
                    if receiver_type and isinstance(receiver_type, Instance):
                        # We have type info - construct the method fullname
                        class_fullname = receiver_type.type.fullname
                        method_fullname = f"{class_fullname}.{callee.name}"
                        deps.add_reference(current_file, call.line, method_fullname)
                        resolve_and_trace(method_fullname, call.line)
                    # No type info - try to trace the receiver
                    elif isinstance(callee.expr, NameExpr) and callee.expr.fullname:
                        # Receiver is an imported module or class.
                        receiver = import_map.get(callee.expr.name, callee.expr.fullname)
                        combined = f"{receiver}.{callee.name}"
                        deps.add_reference(current_file, call.line, combined)
                        resolve_and_trace(combined, call.line)
                    elif (
                        isinstance(callee.expr, CallExpr)
                        and isinstance(callee.expr.callee, NameExpr)
                        and callee.expr.callee.fullname
                    ):
                        # Immediate construction: ImportedClass().method().
                        constructor = callee.expr.callee
                        receiver = import_map.get(constructor.name, constructor.fullname)
                        combined = f"{receiver}.{callee.name}"
                        deps.add_reference(current_file, call.line, combined)
                        resolve_and_trace(combined, call.line)

            # FastAPI dependency injection passes callables as values rather
            # than invoking them in the handler body. Treat the callable given
            # to Depends() as an executable dependency, while keeping ordinary
            # NameExpr arguments isolated to avoid broad over-tracing.
            if isinstance(callee, NameExpr) and callee.name == "Depends":
                for argument in call.args:
                    if isinstance(argument, NameExpr) and argument.fullname:
                        dependency_fullname = import_map.get(argument.name, argument.fullname)
                        deps.add_reference(current_file, argument.line, dependency_fullname)
                        resolve_and_trace(dependency_fullname, argument.line)

            # Walk callee and arguments
            walk_node(callee)
            for arg in call.args:
                walk_node(arg)

        def walk_node(n: Any) -> None:
            """Recursively walk a mypy AST node."""
            if n is None:
                return

            if isinstance(n, CallExpr):
                handle_call_expr(n)

            elif isinstance(n, MemberExpr):
                if n.fullname:
                    deps.add_reference(current_file, n.line, n.fullname)
                walk_node(n.expr)

            elif isinstance(n, NameExpr):
                if n.fullname:
                    # Resolve using import map if available
                    actual_fullname = n.fullname
                    if n.name in import_map:
                        actual_fullname = import_map[n.name]

                    deps.add_reference(current_file, n.line, actual_fullname)
                    # Note: We don't trace into every NameExpr to avoid over-tracing
                    # Decorators are handled specially by walking them explicitly

            elif isinstance(n, FuncDef):
                # Walk function arguments for default values and annotations
                if hasattr(n, "arguments"):
                    for arg in n.arguments:
                        # Walk default argument values
                        if hasattr(arg, "initializer") and arg.initializer:
                            walk_node(arg.initializer)
                        # Walk type annotations
                        if hasattr(arg, "type_annotation") and arg.type_annotation:
                            walk_node(arg.type_annotation)
                # Walk decorators
                if hasattr(n, "decorators"):
                    for decorator in n.decorators:
                        walk_node(decorator)
                # Walk function body
                if hasattr(n, "body"):
                    walk_node(n.body)

            elif isinstance(n, Block):
                for stmt in n.body:
                    walk_node(stmt)

            elif isinstance(n, ExpressionStmt):
                walk_node(n.expr)

            elif isinstance(n, AssignmentStmt):
                for lv in n.lvalues:
                    walk_node(lv)
                walk_node(n.rvalue)

            elif isinstance(n, ReturnStmt):
                walk_node(n.expr)

            elif isinstance(n, IfStmt):
                for expr in n.expr:
                    walk_node(expr)
                for body in n.body:
                    walk_node(body)
                if n.else_body:
                    walk_node(n.else_body)

            elif isinstance(n, WhileStmt) or isinstance(n, ForStmt):
                walk_node(n.expr)
                walk_node(n.body)

            elif isinstance(n, WithStmt):
                for expr in n.expr:
                    walk_node(expr)
                walk_node(n.body)

            elif isinstance(n, TryStmt):
                walk_node(n.body)
                # Walk exception handlers
                for handler in n.handlers:
                    walk_node(handler)
                # Walk exception types
                if hasattr(n, "types") and n.types:
                    for exc_type in n.types:
                        if exc_type:
                            walk_node(exc_type)
                if n.else_body:
                    walk_node(n.else_body)
                if n.finally_body:
                    walk_node(n.finally_body)

            elif isinstance(n, RaiseStmt) or isinstance(n, AssertStmt) or isinstance(n, AwaitExpr):
                walk_node(n.expr)

            elif isinstance(n, IndexExpr):
                walk_node(n.base)
                walk_node(n.index)

            elif isinstance(n, OpExpr):
                walk_node(n.left)
                walk_node(n.right)

            elif isinstance(n, ComparisonExpr):
                for op in n.operands:
                    walk_node(op)

            elif isinstance(n, UnaryExpr):
                walk_node(n.expr)

            elif isinstance(n, ConditionalExpr):
                # mypy uses cond/if_true/if_false but some versions use different names
                if hasattr(n, "cond"):
                    walk_node(n.cond)
                if hasattr(n, "if_true"):
                    walk_node(n.if_true)
                elif hasattr(n, "then"):
                    walk_node(n.then)
                if hasattr(n, "if_false"):
                    walk_node(n.if_false)
                elif hasattr(n, "else_"):
                    walk_node(n.else_)

            elif isinstance(n, (ListExpr, TupleExpr, SetExpr)):
                for item in n.items:
                    walk_node(item)

            elif isinstance(n, DictExpr):
                for key, value in n.items:
                    walk_node(key)
                    walk_node(value)

            elif isinstance(n, ListComprehension):
                # ListComprehension has a generator attribute
                if hasattr(n, "generator"):
                    walk_node(n.generator)

            elif isinstance(n, (SetComprehension, DictionaryComprehension)):
                # These might also have generator attribute
                if hasattr(n, "generator"):
                    walk_node(n.generator)

            elif isinstance(n, GeneratorExpr):
                # Walk the generator/element expression
                if hasattr(n, "left_expr"):
                    walk_node(n.left_expr)
                # Walk generator clauses (for x in sequence if condition)
                if hasattr(n, "sequences"):
                    for seq in n.sequences:
                        walk_node(seq)
                if hasattr(n, "condlists"):
                    for conds in n.condlists:
                        for cond in conds:
                            walk_node(cond)
                # For dict comprehensions, also walk key and value
                if hasattr(n, "key"):
                    walk_node(n.key)
                if hasattr(n, "value"):
                    walk_node(n.value)

            elif isinstance(n, LambdaExpr):
                # Walk lambda arguments (for default values)
                if hasattr(n, "arguments"):
                    for arg in n.arguments:
                        if hasattr(arg, "initializer") and arg.initializer:
                            walk_node(arg.initializer)
                # Walk lambda body
                walk_node(n.body)

            elif isinstance(n, (YieldExpr, YieldFromExpr)):
                walk_node(n.expr)

            elif isinstance(n, (ImportFrom, Import)):
                # Handle imports inside function bodies
                # The imported names are already resolved by mypy
                # We just need to ensure they're processed
                pass

            elif isinstance(n, Decorator):
                # Walk decorator arguments
                if hasattr(n, "decorators"):
                    for decorator in n.decorators:
                        walk_node(decorator)
                # Walk the decorated function
                if hasattr(n, "func"):
                    walk_node(n.func)

        # Start walking from the function
        # Walk decorators first
        if hasattr(node, "decorators") and node.decorators:
            for decorator in node.decorators:
                # Special handling for decorators - trace into them
                if isinstance(decorator, NameExpr) and decorator.fullname:
                    # Resolve using import map
                    actual_fullname = decorator.fullname
                    if decorator.name in import_map:
                        actual_fullname = import_map[decorator.name]
                    deps.add_reference(current_file, decorator.line, actual_fullname)
                    # Trace into the decorator function to find its dependencies
                    resolve_and_trace(actual_fullname, decorator.line)
                else:
                    # For CallExpr decorators, walk normally
                    walk_node(decorator)
        # Then walk the function signature and body. Decorated definitions are
        # represented by mypy as Decorator nodes; their executable function is
        # stored in ``node.func`` rather than directly on ``node``.
        function_node = node.func if isinstance(node, Decorator) else node
        if hasattr(function_node, "arguments"):
            for argument in function_node.arguments:
                if hasattr(argument, "initializer") and argument.initializer:
                    walk_node(argument.initializer)
        if hasattr(function_node, "body") and function_node.body:
            walk_node(function_node.body)

    def analyze_endpoints(
        self,
        endpoints: list[Endpoint],
        use_cache: bool = True,
    ) -> dict[str, EndpointDependencies]:
        """Analyze multiple endpoints."""
        # Try to load from cache
        if use_cache and self.cache_path.exists() and self._load_cache():
            all_cached = all(self._endpoint_key(ep) in self._endpoint_deps for ep in endpoints)
            if all_cached:
                return self._endpoint_deps
        else:
            self._endpoint_deps.clear()

        analysis_fingerprint, _sources = self._cache_fingerprint()

        # Build mypy once for all endpoints
        try:
            self._ensure_mypy_built()
        except MypyAnalyzerError:
            pass

        # Analyze uncached endpoints
        for endpoint in endpoints:
            if self._endpoint_key(endpoint) not in self._endpoint_deps:
                self.analyze_endpoint(endpoint)

        # Save cache
        if use_cache:
            current_fingerprint, _sources = self._cache_fingerprint()
            if current_fingerprint == analysis_fingerprint:
                self._save_cache()

        return self._endpoint_deps

    def _cache_fingerprint(self) -> tuple[str, dict[str, str]]:
        """Fingerprint all Python inputs and analysis semantics."""
        sources: dict[str, str] = {}
        for path in sorted(self.source_root.rglob("*.py")):
            try:
                relative = path.resolve().relative_to(self.source_root).as_posix()
                sources[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError:
                continue
        try:
            mypy_version = version("mypy")
        except PackageNotFoundError:
            mypy_version = "missing"
        payload = json.dumps(
            {
                "schema": self.CACHE_SCHEMA_VERSION,
                "max_depth": self.max_depth,
                "mypy": mypy_version,
                "python": list(sys.version_info[:3]),
                "source_root": str(self.source_root.resolve()),
                "sources": sources,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode()).hexdigest(), sources

    def _save_cache(self) -> None:
        """Atomically save versioned analysis data to the cache file."""
        endpoints_data: dict[str, Any] = {}
        for analysis_key, deps in self._endpoint_deps.items():
            endpoints_data[analysis_key] = {
                "endpoint_id": deps.endpoint_id,
                "methods": deps.methods,
                "path": deps.path,
                "referenced_files": {f: list(lines) for f, lines in deps.referenced_files.items()},
                "referenced_symbols": [
                    {
                        "file_path": ref.file_path,
                        "symbol_name": ref.symbol_name,
                        "start_line": ref.start_line,
                        "end_line": ref.end_line,
                    }
                    for ref in deps.referenced_symbols
                ],
                "call_stacks": {
                    f: [
                        [
                            {
                                "file_path": frame.file_path,
                                "line_number": frame.line_number,
                                "function_name": frame.function_name,
                                "code_context": frame.code_context,
                            }
                            for frame in stack
                        ]
                        for stack in stacks
                    ]
                    for f, stacks in deps.call_stacks.items()
                },
            }

        fingerprint, sources = self._cache_fingerprint()
        data = {
            "schema_version": self.CACHE_SCHEMA_VERSION,
            "fingerprint": fingerprint,
            "metadata": {
                "source_root": str(self.source_root),
                "max_depth": self.max_depth,
                "sources": sources,
            },
            "endpoints": endpoints_data,
        }
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{self.cache_path.name}.", dir=self.cache_path.parent
            )
            temporary = Path(temporary_name)
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    json.dump(data, handle, indent=2)
                    handle.flush()
                    os.fsync(handle.fileno())
                temporary.replace(self.cache_path)
            finally:
                temporary.unlink(missing_ok=True)
        except OSError:
            pass

    def _load_cache(self) -> bool:
        """Load only a current cache matching all source and semantic inputs."""
        self._endpoint_deps.clear()
        try:
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
            fingerprint, _sources = self._cache_fingerprint()
            if not isinstance(data, dict):
                return False
            if data.get("schema_version") != self.CACHE_SCHEMA_VERSION:
                return False
            if data.get("fingerprint") != fingerprint:
                return False
            endpoints_data = data.get("endpoints")
            if not isinstance(endpoints_data, dict):
                return False
            project_files = {str(path.resolve()) for path in self.source_root.rglob("*.py")}

            for analysis_key, deps_data in endpoints_data.items():
                if not isinstance(analysis_key, str) or not isinstance(deps_data, dict):
                    self._endpoint_deps.clear()
                    return False
                call_stacks: dict[str, list[list[CallFrame]]] = {}
                for f, stacks_data in deps_data.get("call_stacks", {}).items():
                    call_stacks[f] = [
                        [
                            CallFrame(
                                file_path=frame["file_path"],
                                line_number=frame["line_number"],
                                function_name=frame["function_name"],
                                code_context=frame.get("code_context", ""),
                            )
                            for frame in stack_data
                        ]
                        for stack_data in stacks_data
                    ]

                symbol_refs: list[SymbolReference] = []
                for ref_data in deps_data.get("referenced_symbols", []):
                    if isinstance(ref_data, dict):
                        symbol_refs.append(
                            SymbolReference(
                                file_path=ref_data["file_path"],
                                symbol_name=ref_data["symbol_name"],
                                start_line=ref_data["start_line"],
                                end_line=ref_data["end_line"],
                            )
                        )

                endpoint_id = deps_data.get("endpoint_id")
                if not isinstance(endpoint_id, str):
                    self._endpoint_deps.clear()
                    return False
                self._endpoint_deps[analysis_key] = EndpointDependencies(
                    endpoint_id=endpoint_id,
                    methods=deps_data["methods"],
                    path=deps_data["path"],
                    referenced_files={
                        f: set(lines) for f, lines in deps_data["referenced_files"].items()
                    },
                    referenced_symbols=symbol_refs,
                    call_stacks=call_stacks,
                    source_root=str(self.source_root),
                    project_files=project_files,
                )
            return True
        except (
            AttributeError,
            IndexError,
            OSError,
            ValueError,
            KeyError,
            TypeError,
            json.JSONDecodeError,
        ):
            self._endpoint_deps.clear()
            return False

    def clear_cache(self) -> None:
        """Clear the analysis cache."""
        if self.cache_path.exists():
            self.cache_path.unlink()
        self._endpoint_deps.clear()

    def get_endpoint_dependencies(
        self,
        endpoint: Endpoint | str,
    ) -> EndpointDependencies | None:
        """Get dependencies for a handler-aware endpoint key."""
        key = self._endpoint_key(endpoint) if isinstance(endpoint, Endpoint) else endpoint
        return self._endpoint_deps.get(key)
