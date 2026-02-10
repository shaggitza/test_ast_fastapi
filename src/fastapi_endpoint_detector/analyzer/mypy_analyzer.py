"""
Mypy-based dependency analyzer.

This module uses mypy's type analysis to determine which code paths
each endpoint handler actually uses, providing more precise dependency
tracking than import-based analysis.

It relies entirely on mypy for AST parsing and type resolution,
using mypy's internal data structures to track file/line references.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastapi_endpoint_detector.models.endpoint import Endpoint

if TYPE_CHECKING:
    from mypy.build import BuildResult
    from mypy.nodes import MypyFile

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
    call_stacks: dict[str, list[CallFrame]] = field(default_factory=dict)
    """Mapping of file path -> call stack showing how handler reaches that file."""
    
    def add_reference(self, file_path: str, line: int, symbol_name: str = "") -> None:
        """Add a line reference to dependencies."""
        if file_path not in self.referenced_files:
            self.referenced_files[file_path] = set()
        self.referenced_files[file_path].add(line)
    
    def add_symbol_reference(self, file_path: str, symbol_name: str, start_line: int, end_line: int) -> None:
        """Add a symbol reference and its line range to dependencies."""
        ref = SymbolReference(file_path, symbol_name, start_line, end_line)
        self.referenced_symbols.append(ref)
        
        if file_path not in self.referenced_files:
            self.referenced_files[file_path] = set()
        self.referenced_files[file_path].update(range(start_line, end_line + 1))
    
    def references_symbol_at_line(self, file_path: str, line: int) -> SymbolReference | None:
        """Check if any referenced symbol contains the given line."""
        file_path_resolved = str(Path(file_path).resolve())
        file_name = Path(file_path).name
        for ref in self.referenced_symbols:
            ref_resolved = str(Path(ref.file_path).resolve())
            ref_name = Path(ref.file_path).name
            # Match by resolved path, ending, or filename
            if (ref_resolved == file_path_resolved or
                ref.file_path.endswith(str(file_path)) or 
                file_path.endswith(ref.file_path) or
                ref_name == file_name):
                if ref.contains_line(line):
                    return ref
        return None
    
    def references_file(self, file_path: str) -> bool:
        """Check if this endpoint references a file."""
        file_path_resolved = str(Path(file_path).resolve())
        file_name = Path(file_path).name
        
        for ref_path in self.referenced_files:
            ref_resolved = str(Path(ref_path).resolve())
            ref_name = Path(ref_path).name
            if (ref_resolved == file_path_resolved or
                ref_path.endswith(str(file_path)) or
                file_path.endswith(ref_path) or
                ref_name == file_name):
                return True
        
        return False
    
    def references_lines(self, file_path: str, lines: set[int]) -> set[int]:
        """Get the intersection of referenced lines with given lines."""
        file_path_resolved = str(Path(file_path).resolve())
        file_name = Path(file_path).name
        
        for ref_path, ref_lines in self.referenced_files.items():
            ref_resolved = str(Path(ref_path).resolve())
            ref_name = Path(ref_path).name
            if (ref_resolved == file_path_resolved or
                ref_path.endswith(str(file_path)) or
                file_path.endswith(ref_path) or
                ref_name == file_name):
                return ref_lines & lines
        
        return set()
    
    def get_call_stack(self, file_path: str) -> list[CallFrame]:
        """Get the call stack for how the handler reaches a specific file."""
        file_path_resolved = str(Path(file_path).resolve())
        file_name = Path(file_path).name
        
        for ref_path, stack in self.call_stacks.items():
            ref_resolved = str(Path(ref_path).resolve())
            ref_name = Path(ref_path).name
            if (ref_resolved == file_path_resolved or
                ref_path.endswith(str(file_path)) or
                file_path.endswith(ref_path) or
                ref_name == file_name):
                return stack
        
        return []


class MypyAnalyzer:
    """
    Analyze endpoint dependencies using mypy's type system.
    
    Uses mypy's build API with proper configuration to get typed ASTs
    and extract precise file/line information for all references.
    """
    
    def __init__(self, app_path: Path) -> None:
        """Initialize the mypy analyzer."""
        self.app_path = app_path.resolve()
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
        return self.app_path.parent / ".endpoint_mypy_cache.json"
    
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
        from mypy.options import Options
        from mypy.fscache import FileSystemCache
        from mypy.modulefinder import BuildSource
        
        source_root = self._get_source_root()
        
        # Collect all Python files
        sources: list[BuildSource] = []
        for py_file in source_root.rglob("*.py"):
            if any(part.startswith(('.', '__pycache__')) for part in py_file.parts):
                continue
            
            try:
                rel_path = py_file.relative_to(source_root.parent)
                if rel_path.name == "__init__.py":
                    module_name = str(rel_path.parent).replace('/', '.').replace('\\', '.')
                else:
                    module_name = str(rel_path.with_suffix('')).replace('/', '.').replace('\\', '.')
            except ValueError:
                module_name = py_file.stem
            
            sources.append(BuildSource(path=str(py_file), module=module_name))
            self._module_to_path[module_name] = str(py_file)
        
        # Configure mypy for full analysis with AST retention
        options = Options()
        options.ignore_missing_imports = True
        options.follow_imports = 'normal'
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
    
    def _find_func_in_tree(self, tree: Any, func_name: str) -> tuple[Any, str] | None:
        """
        Find a function/method definition in a mypy AST.
        
        Returns (func_node, qualified_name) or None.
        """
        from mypy.nodes import FuncDef, Decorator, ClassDef, OverloadedFuncDef
        
        for defn in tree.defs:
            if isinstance(defn, FuncDef) and defn.name == func_name:
                return defn, defn.name
            if isinstance(defn, Decorator) and defn.func.name == func_name:
                return defn.func, defn.func.name
            if isinstance(defn, OverloadedFuncDef) and defn.name == func_name:
                # For overloaded functions, get the first implementation
                if defn.items:
                    first = defn.items[0]
                    if isinstance(first, Decorator):
                        return first.func, first.func.name
                return None
            if isinstance(defn, ClassDef):
                # Search methods in class
                for item in defn.defs.body:
                    if isinstance(item, FuncDef) and item.name == func_name:
                        return item, f"{defn.name}.{item.name}"
                    if isinstance(item, Decorator) and item.func.name == func_name:
                        return item.func, f"{defn.name}.{item.func.name}"
        return None
    
    def _get_func_lines(self, func_node: Any) -> tuple[int, int]:
        """Get the start and end lines of a function node."""
        start = func_node.line
        end = getattr(func_node, 'end_line', None)
        if end is None:
            end = start + 50  # Estimate
        return start, end
    
    def _resolve_fullname_to_file(self, fullname: str) -> tuple[str, str] | None:
        """
        Try to resolve a fullname to (file_path, module_name).
        
        Returns None if not found in our project.
        """
        parts = fullname.split('.')
        
        # Try progressively shorter module paths
        for i in range(len(parts), 0, -1):
            candidate = '.'.join(parts[:i])
            if candidate in self._module_to_path:
                return self._module_to_path[candidate], candidate
            if candidate in self._trees:
                state = self._build_result.graph.get(candidate)
                if state and state.path:
                    return state.path, candidate
        
        return None
    
    def _get_type_from_node(self, node: Any) -> Any:
        """Get the type of an AST node from mypy's type map."""
        return self._types_map.get(node)
    
    def analyze_endpoint(self, endpoint: Endpoint) -> EndpointDependencies:
        """Analyze a single endpoint using mypy's typed AST."""
        deps = EndpointDependencies(
            endpoint_id=endpoint.identifier,
            methods=[m.value for m in endpoint.methods],
            path=endpoint.path,
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
            # Module not found - add handler file as reference
            start = handler.line_number
            end = handler.end_line_number or start + 50
            deps.add_symbol_reference(handler_path, handler.name, start, end)
            self._endpoint_deps[endpoint.identifier] = deps
            return deps
        
        tree = self._trees[handler_module]
        
        # Find the handler function
        result = self._find_func_in_tree(tree, handler.name)
        if not result:
            start = handler.line_number
            end = handler.end_line_number or start + 50
            deps.add_symbol_reference(handler_path, handler.name, start, end)
            self._endpoint_deps[endpoint.identifier] = deps
            return deps
        
        func_node, func_qname = result
        start, end = self._get_func_lines(func_node)
        deps.add_symbol_reference(handler_path, handler.name, start, end)
        
        # Trace all references in the function body
        visited: set[str] = set()
        call_stack = [CallFrame(handler_path, start, handler.name)]
        
        self._trace_references(func_node, deps, handler_path, handler_module, call_stack, visited)
        
        self._endpoint_deps[endpoint.identifier] = deps
        return deps
    
    def _trace_references(
        self,
        node: Any,
        deps: EndpointDependencies,
        current_file: str,
        current_module: str,
        call_stack: list[CallFrame],
        visited: set[str],
    ) -> None:
        """
        Trace all references in a mypy AST node.
        
        Uses mypy's types map to resolve method calls when type info is available.
        """
        from mypy.nodes import (
            CallExpr, MemberExpr, NameExpr, RefExpr, FuncDef,
            Block, ExpressionStmt, AssignmentStmt,
            ReturnStmt, IfStmt, WhileStmt, ForStmt, WithStmt,
            TryStmt, RaiseStmt, AssertStmt, AwaitExpr,
            IndexExpr, OpExpr, ComparisonExpr, UnaryExpr,
            ConditionalExpr, ListExpr, TupleExpr, DictExpr, SetExpr,
            GeneratorExpr, ListComprehension, SetComprehension,
            DictionaryComprehension, LambdaExpr, YieldExpr, YieldFromExpr,
        )
        from mypy.types import Instance, CallableType
        
        def resolve_and_trace(fullname: str, call_line: int) -> None:
            """Resolve a fullname to file/line and trace into it."""
            if fullname in visited:
                return
            visited.add(fullname)
            
            # Report progress
            if self._line_progress_callback:
                self._line_progress_callback(
                    current_file, call_line, fullname.split('.')[-1]
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
            parts = fullname.split('.')
            # The symbol name is everything after the module name
            if fullname.startswith(target_module):
                symbol_name = fullname[len(target_module) + 1:] if len(fullname) > len(target_module) else ""
            else:
                symbol_name = parts[-1]
            
            # Try to find the function in the target tree
            func_name = symbol_name.split('.')[-1] if symbol_name else parts[-1]
            func_result = self._find_func_in_tree(target_tree, func_name)
            
            if func_result:
                target_func, qname = func_result
                start, end = self._get_func_lines(target_func)
                deps.add_symbol_reference(target_path, fullname, start, end)
                
                # Record call stack
                if target_path not in deps.call_stacks:
                    deps.call_stacks[target_path] = list(call_stack)
                
                # Recursively trace into the target function
                new_frame = CallFrame(target_path, start, fullname)
                new_stack = call_stack + [new_frame]
                
                self._trace_references(
                    target_func, deps, target_path, target_module, 
                    new_stack, visited
                )
            else:
                # Couldn't find specific function, add module reference
                deps.add_symbol_reference(target_path, fullname, 1, 20)
                if target_path not in deps.call_stacks:
                    deps.call_stacks[target_path] = list(call_stack)
        
        def handle_call_expr(call: CallExpr) -> None:
            """Handle a function/method call expression."""
            callee = call.callee
            
            if isinstance(callee, NameExpr):
                # Direct function call: func()
                if callee.fullname:
                    deps.add_reference(current_file, call.line, callee.fullname)
                    resolve_and_trace(callee.fullname, call.line)
            
            elif isinstance(callee, MemberExpr):
                # Method call: obj.method()
                if callee.fullname:
                    # Mypy resolved the method name
                    deps.add_reference(current_file, call.line, callee.fullname)
                    resolve_and_trace(callee.fullname, call.line)
                else:
                    # Try to resolve via type information
                    receiver_type = self._get_type_from_node(callee.expr)
                    if receiver_type and isinstance(receiver_type, Instance):
                        # We have type info - construct the method fullname
                        class_fullname = receiver_type.type.fullname
                        method_fullname = f"{class_fullname}.{callee.name}"
                        deps.add_reference(current_file, call.line, method_fullname)
                        resolve_and_trace(method_fullname, call.line)
                    else:
                        # No type info - try to trace the receiver
                        if isinstance(callee.expr, NameExpr) and callee.expr.fullname:
                            # Receiver is a module or class
                            combined = f"{callee.expr.fullname}.{callee.name}"
                            deps.add_reference(current_file, call.line, combined)
                            resolve_and_trace(combined, call.line)
            
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
                    deps.add_reference(current_file, n.line, n.fullname)
            
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
            
            elif isinstance(n, WhileStmt):
                walk_node(n.expr)
                walk_node(n.body)
            
            elif isinstance(n, ForStmt):
                walk_node(n.expr)
                walk_node(n.body)
            
            elif isinstance(n, WithStmt):
                for expr in n.expr:
                    walk_node(expr)
                walk_node(n.body)
            
            elif isinstance(n, TryStmt):
                walk_node(n.body)
                for handler in n.handlers:
                    walk_node(handler)
                if n.else_body:
                    walk_node(n.else_body)
                if n.finally_body:
                    walk_node(n.finally_body)
            
            elif isinstance(n, RaiseStmt):
                walk_node(n.expr)
            
            elif isinstance(n, AssertStmt):
                walk_node(n.expr)
            
            elif isinstance(n, AwaitExpr):
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
                if hasattr(n, 'cond'):
                    walk_node(n.cond)
                if hasattr(n, 'if_true'):
                    walk_node(n.if_true)
                elif hasattr(n, 'then'):
                    walk_node(n.then)
                if hasattr(n, 'if_false'):
                    walk_node(n.if_false)
                elif hasattr(n, 'else_'):
                    walk_node(n.else_)
            
            elif isinstance(n, (ListExpr, TupleExpr, SetExpr)):
                for item in n.items:
                    walk_node(item)
            
            elif isinstance(n, DictExpr):
                for key, value in n.items:
                    walk_node(key)
                    walk_node(value)
            
            elif isinstance(n, (GeneratorExpr, ListComprehension, SetComprehension, DictionaryComprehension)):
                if hasattr(n, 'left_expr'):
                    walk_node(n.left_expr)
                if hasattr(n, 'condlists'):
                    for conds in n.condlists:
                        for cond in conds:
                            walk_node(cond)
                if hasattr(n, 'sequences'):
                    for seq in n.sequences:
                        walk_node(seq)
            
            elif isinstance(n, LambdaExpr):
                walk_node(n.body)
            
            elif isinstance(n, (YieldExpr, YieldFromExpr)):
                walk_node(n.expr)
        
        # Start walking from the function body
        if hasattr(node, 'body') and node.body:
            walk_node(node.body)
    
    def analyze_endpoints(
        self,
        endpoints: list[Endpoint],
        use_cache: bool = True,
    ) -> dict[str, EndpointDependencies]:
        """Analyze multiple endpoints."""
        # Try to load from cache
        if use_cache and self.cache_path.exists():
            try:
                self._load_cache()
                all_cached = all(
                    ep.identifier in self._endpoint_deps
                    for ep in endpoints
                )
                if all_cached:
                    return self._endpoint_deps
            except Exception:
                pass
        
        # Build mypy once for all endpoints
        try:
            self._ensure_mypy_built()
        except MypyAnalyzerError:
            pass
        
        # Analyze uncached endpoints
        for endpoint in endpoints:
            if endpoint.identifier not in self._endpoint_deps:
                self.analyze_endpoint(endpoint)
        
        # Save cache
        if use_cache:
            self._save_cache()
        
        return self._endpoint_deps
    
    def _save_cache(self) -> None:
        """Save analysis data to cache file."""
        cache_data: dict[str, Any] = {}
        for endpoint_id, deps in self._endpoint_deps.items():
            cache_data[endpoint_id] = {
                "methods": deps.methods,
                "path": deps.path,
                "referenced_files": {
                    f: list(lines) for f, lines in deps.referenced_files.items()
                },
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
                        {
                            "file_path": frame.file_path,
                            "line_number": frame.line_number,
                            "function_name": frame.function_name,
                            "code_context": frame.code_context,
                        }
                        for frame in frames
                    ]
                    for f, frames in deps.call_stacks.items()
                },
            }
        
        try:
            self.cache_path.write_text(
                json.dumps(cache_data, indent=2),
                encoding="utf-8",
            )
        except Exception:
            pass
    
    def _load_cache(self) -> None:
        """Load analysis data from cache file."""
        try:
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
            
            for endpoint_id, deps_data in data.items():
                call_stacks: dict[str, list[CallFrame]] = {}
                for f, frames_data in deps_data.get("call_stacks", {}).items():
                    call_stacks[f] = [
                        CallFrame(
                            file_path=frame["file_path"],
                            line_number=frame["line_number"],
                            function_name=frame["function_name"],
                            code_context=frame.get("code_context", ""),
                        )
                        for frame in frames_data
                    ]
                
                symbol_refs: list[SymbolReference] = []
                for ref_data in deps_data.get("referenced_symbols", []):
                    if isinstance(ref_data, dict):
                        symbol_refs.append(SymbolReference(
                            file_path=ref_data["file_path"],
                            symbol_name=ref_data["symbol_name"],
                            start_line=ref_data["start_line"],
                            end_line=ref_data["end_line"],
                        ))
                
                self._endpoint_deps[endpoint_id] = EndpointDependencies(
                    endpoint_id=endpoint_id,
                    methods=deps_data["methods"],
                    path=deps_data["path"],
                    referenced_files={
                        f: set(lines)
                        for f, lines in deps_data["referenced_files"].items()
                    },
                    referenced_symbols=symbol_refs,
                    call_stacks=call_stacks,
                )
        except Exception:
            pass
    
    def clear_cache(self) -> None:
        """Clear the analysis cache."""
        if self.cache_path.exists():
            self.cache_path.unlink()
        self._endpoint_deps.clear()
    
    def get_endpoint_dependencies(
        self,
        endpoint_id: str,
    ) -> EndpointDependencies | None:
        """Get dependencies for a specific endpoint."""
        return self._endpoint_deps.get(endpoint_id)
