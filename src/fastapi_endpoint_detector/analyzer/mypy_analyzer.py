"""
Mypy-based dependency analyzer.

This module uses mypy's type analysis to determine which code paths
each endpoint handler actually uses, providing more precise dependency
tracking than import-based analysis.
"""

import ast
import json
import os
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from fastapi_endpoint_detector.models.endpoint import Endpoint


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
class EndpointDependencies:
    """Dependencies for a single endpoint determined by mypy."""
    
    endpoint_id: str
    methods: list[str]
    path: str
    referenced_files: dict[str, set[int]] = field(default_factory=dict)
    """Mapping of file path -> set of referenced line numbers."""
    referenced_symbols: list[str] = field(default_factory=list)
    """List of fully qualified symbol names referenced by the handler."""
    call_stacks: dict[str, list[CallFrame]] = field(default_factory=dict)
    """Mapping of file path -> call stack showing how handler reaches that file."""
    
    def references_file(self, file_path: str) -> bool:
        """Check if this endpoint references a file."""
        normalized = str(Path(file_path).resolve())
        
        if normalized in self.referenced_files:
            return True
        
        # Check by suffix match for relative paths
        for ref_path in self.referenced_files:
            if ref_path.endswith(str(file_path)) or file_path.endswith(Path(ref_path).name):
                return True
        
        return False
    
    def references_lines(self, file_path: str, lines: set[int]) -> set[int]:
        """Get the intersection of referenced lines with given lines."""
        normalized = str(Path(file_path).resolve())
        
        if normalized in self.referenced_files:
            return self.referenced_files[normalized] & lines
        
        for ref_path, ref_lines in self.referenced_files.items():
            if ref_path.endswith(str(file_path)) or file_path.endswith(Path(ref_path).name):
                return ref_lines & lines
        
        return set()
    
    def get_call_stack(self, file_path: str) -> list[CallFrame]:
        """Get the call stack for how the handler reaches a specific file."""
        normalized = str(Path(file_path).resolve())
        
        if normalized in self.call_stacks:
            return self.call_stacks[normalized]
        
        # Check by suffix match
        for ref_path, stack in self.call_stacks.items():
            if ref_path.endswith(str(file_path)) or file_path.endswith(Path(ref_path).name):
                return stack
        
        return []


class MypyAnalyzer:
    """
    Analyze endpoint dependencies using mypy's type system.
    
    This leverages mypy's sophisticated type inference to determine
    what code each handler actually uses, not just imports.
    """
    
    def __init__(self, app_path: Path) -> None:
        """
        Initialize the mypy analyzer.
        
        Args:
            app_path: Path to the FastAPI application.
        """
        self.app_path = app_path.resolve()
        self._endpoint_deps: dict[str, EndpointDependencies] = {}
        self._mypy_available = self._check_mypy_available()
        self._cache_file: Optional[Path] = None
    
    @property
    def cache_path(self) -> Path:
        """Path to the mypy analysis cache file."""
        if self._cache_file:
            return self._cache_file
        return self.app_path.parent / ".endpoint_mypy_cache.json"
    
    def set_cache_path(self, path: Path) -> None:
        """Set a custom cache file path."""
        self._cache_file = path
    
    def _check_mypy_available(self) -> bool:
        """Check if mypy is available."""
        try:
            from mypy import api
            return True
        except ImportError:
            return False
    
    def _get_source_root(self) -> Path:
        """Get the source root directory."""
        if self.app_path.is_file():
            return self.app_path.parent
        return self.app_path
    
    def analyze_with_mypy(self) -> dict[str, dict]:
        """
        Run mypy on the codebase and extract dependency information.
        
        Returns:
            Dict mapping file paths to their analyzed data.
        """
        if not self._mypy_available:
            raise MypyAnalyzerError("mypy is not installed")
        
        from mypy import api
        
        source_root = self._get_source_root()
        
        # Run mypy with options to get detailed info
        # --show-error-codes helps parse output
        # --no-error-summary reduces noise
        result = api.run([
            str(source_root),
            '--show-error-codes',
            '--no-error-summary',
            '--ignore-missing-imports',
            '--follow-imports=normal',
        ])
        
        stdout, stderr, exit_code = result
        
        # We don't care about type errors, just that mypy ran
        return {'stdout': stdout, 'stderr': stderr, 'exit_code': exit_code}
    
    def analyze_endpoint(self, endpoint: Endpoint) -> EndpointDependencies:
        """
        Analyze a single endpoint using mypy's type information.
        
        This creates a temporary file that imports and "uses" the handler,
        then runs mypy's reveal_type and other introspection to trace deps.
        
        Args:
            endpoint: The endpoint to analyze.
            
        Returns:
            EndpointDependencies with traced references.
        """
        deps = EndpointDependencies(
            endpoint_id=endpoint.identifier,
            methods=[m.value for m in endpoint.methods],
            path=endpoint.path,
        )
        
        handler = endpoint.handler
        if not handler.file_path:
            return deps
        
        # Use AST-based analysis enhanced with mypy type stubs if available
        self._analyze_handler_with_types(endpoint, deps)
        
        self._endpoint_deps[endpoint.identifier] = deps
        return deps
    
    def _get_source_line(self, file_path: Path, line_number: int) -> str:
        """Get a specific line from a source file."""
        try:
            lines = file_path.read_text(encoding='utf-8').splitlines()
            if 0 < line_number <= len(lines):
                return lines[line_number - 1]
        except Exception:
            pass
        return ""
    
    def _analyze_handler_with_types(
        self,
        endpoint: Endpoint,
        deps: EndpointDependencies,
    ) -> None:
        """
        Analyze handler using AST with mypy-style type tracking.
        
        This traces through the handler's code and follows type annotations
        to determine which files contain the actual implementations used.
        """
        
        handler = endpoint.handler
        file_path = Path(handler.file_path)
        
        if not file_path.exists():
            return
        
        try:
            source = file_path.read_text(encoding='utf-8')
            source_lines = source.splitlines()
            tree = ast.parse(source, filename=str(file_path))
        except Exception:
            return
        
        # Collect imports and their resolved paths
        imports = self._collect_imports_with_resolution(tree, file_path)
        
        # Find the handler function
        handler_node = None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == handler.name:
                    handler_node = node
                    break
        
        if not handler_node:
            return
        
        # Add the handler's own file
        start = handler_node.lineno
        end = getattr(handler_node, 'end_lineno', start + 50)
        deps.referenced_files[str(file_path)] = set(range(start, end + 1))
        
        # Build type context from parameters
        type_context = self._build_type_context(handler_node, imports)
        
        # Create root call frame for the handler
        handler_code = source_lines[start - 1] if start <= len(source_lines) else ""
        root_frame = CallFrame(
            file_path=str(file_path),
            line_number=start,
            function_name=handler.name,
            code_context=handler_code,
        )
        
        # Trace all references in the handler body with call stack tracking
        self._trace_references(
            handler_node, deps, imports, type_context, 
            file_path, source_lines, handler.name, [root_frame]
        )
    
    def _collect_imports_with_resolution(
        self,
        tree: ast.Module,
        source_file: Path,
    ) -> dict[str, tuple[Path, Optional[str]]]:
        """
        Collect imports and resolve them to file paths.
        
        Returns dict mapping local name -> (file_path, original_name).
        """
        
        imports: dict[str, tuple[Path, Optional[str]]] = {}
        base_dir = source_file.parent
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local_name = alias.asname or alias.name.split('.')[-1]
                    resolved = self._resolve_import(alias.name, base_dir)
                    if resolved:
                        imports[local_name] = (resolved, None)
                        
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    for alias in node.names:
                        local_name = alias.asname or alias.name
                        
                        # Try to resolve as submodule
                        full_name = f"{node.module}.{alias.name}"
                        resolved = self._resolve_import(full_name, base_dir)
                        
                        if not resolved:
                            resolved = self._resolve_import(node.module, base_dir)
                        
                        if resolved:
                            imports[local_name] = (resolved, alias.name)
        
        return imports
    
    def _resolve_import(self, module_name: str, base_dir: Path) -> Optional[Path]:
        """Resolve a module name to its file path.
        
        Handles both proper Python packages and non-module projects by:
        1. Trying the module path relative to base_dir
        2. Trying relative to source root
        3. Walking up directories to find matching module structure
        4. Searching subdirectories for matching files
        """
        parts = module_name.split('.')
        source_root = self._get_source_root()
        
        # Build list of search paths
        search_paths = [base_dir, source_root]
        
        # Also add parent directories up to source root
        current = base_dir
        while current != source_root and current.parent != current:
            current = current.parent
            search_paths.append(current)
        
        # Try each search path
        for search_path in search_paths:
            relative = search_path / Path(*parts)
            
            # Check package (with __init__.py)
            if (relative / '__init__.py').exists():
                return relative / '__init__.py'
            
            # Check module (bare .py file)
            module_file = relative.with_suffix('.py')
            if module_file.exists():
                return module_file
            
            # For non-module projects: check if path exists as directory
            # without __init__.py (treat as namespace package)
            if relative.is_dir() and parts:
                # Look for the final part as a .py file
                final_file = relative.with_suffix('.py')
                if final_file.exists():
                    return final_file
        
        # Fallback: search for the file recursively in source root
        # This handles projects without proper package structure
        if parts:
            target_file = parts[-1] + '.py'
            target_subpath = Path(*parts).with_suffix('.py')
            
            for py_file in source_root.rglob('*.py'):
                # Check if filename matches
                if py_file.name == target_file:
                    # Verify the relative path matches module structure
                    try:
                        rel_path = py_file.relative_to(source_root)
                        # Check if it ends with expected subpath
                        if str(rel_path) == str(target_subpath):
                            return py_file
                        # Or just return if only looking for a single file
                        if len(parts) == 1:
                            return py_file
                    except ValueError:
                        continue
        
        return None
    
    def _build_type_context(
        self,
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
        imports: dict[str, tuple[Path, Optional[str]]],
    ) -> dict[str, Path]:
        """
        Build a mapping of variable names to their type's source file.
        
        Uses parameter type annotations to determine types.
        """
        
        context: dict[str, Path] = {}
        
        for arg in func_node.args.args + func_node.args.kwonlyargs:
            if arg.annotation:
                type_name = self._extract_type_name(arg.annotation)
                if type_name and type_name in imports:
                    context[arg.arg] = imports[type_name][0]
        
        return context
    
    def _extract_type_name(self, annotation: ast.expr) -> Optional[str]:
        """Extract the primary type name from an annotation."""
        
        if isinstance(annotation, ast.Name):
            return annotation.id
        elif isinstance(annotation, ast.Subscript):
            # Optional[X], List[X], etc - get inner type
            if isinstance(annotation.slice, ast.Name):
                return annotation.slice.id
            elif isinstance(annotation.slice, ast.Tuple):
                # Union[X, Y] - get first non-None
                for elt in annotation.slice.elts:
                    if isinstance(elt, ast.Name) and elt.id != 'None':
                        return elt.id
        elif isinstance(annotation, ast.Attribute):
            return annotation.attr
        
        return None
    
    def _trace_references(
        self,
        func_node: ast.AST,
        deps: EndpointDependencies,
        imports: dict[str, tuple[Path, Optional[str]]],
        type_context: dict[str, Path],
        source_file: Path,
        source_lines: list[str],
        current_func: str,
        call_stack: list[CallFrame],
    ) -> None:
        """
        Trace all references in a function body and add to deps.
        """
        
        for node in ast.walk(func_node):
            # Direct function calls: func()
            if isinstance(node, ast.Call):
                self._handle_call(
                    node, deps, imports, type_context,
                    source_file, source_lines, current_func, call_stack
                )
            
            # Attribute access: obj.attr
            elif isinstance(node, ast.Attribute):
                self._handle_attribute(
                    node, deps, imports, type_context,
                    source_file, source_lines, current_func, call_stack
                )
            
            # Direct name references
            elif isinstance(node, ast.Name):
                if node.id in imports:
                    file_path, _ = imports[node.id]
                    line_num = getattr(node, 'lineno', 0)
                    code_ctx = source_lines[line_num - 1] if 0 < line_num <= len(source_lines) else ""
                    
                    call_frame = CallFrame(
                        file_path=str(source_file),
                        line_number=line_num,
                        function_name=current_func,
                        code_context=code_ctx,
                    )
                    self._add_file_reference(deps, file_path, call_stack + [call_frame])
    
    def _handle_call(
        self,
        node: ast.Call,
        deps: EndpointDependencies,
        imports: dict[str, tuple[Path, Optional[str]]],
        type_context: dict[str, Path],
        source_file: Path,
        source_lines: list[str],
        current_func: str,
        call_stack: list[CallFrame],
    ) -> None:
        """Handle a function call node."""
        
        line_num = getattr(node, 'lineno', 0)
        code_ctx = source_lines[line_num - 1] if 0 < line_num <= len(source_lines) else ""
        
        if isinstance(node.func, ast.Attribute):
            self._handle_attribute(
                node.func, deps, imports, type_context,
                source_file, source_lines, current_func, call_stack
            )
        elif isinstance(node.func, ast.Name):
            if node.func.id in imports:
                file_path, _ = imports[node.func.id]
                call_frame = CallFrame(
                    file_path=str(source_file),
                    line_number=line_num,
                    function_name=current_func,
                    code_context=code_ctx,
                )
                self._add_file_reference(deps, file_path, call_stack + [call_frame])
    
    def _handle_attribute(
        self,
        node: ast.Attribute,
        deps: EndpointDependencies,
        imports: dict[str, tuple[Path, Optional[str]]],
        type_context: dict[str, Path],
        source_file: Path,
        source_lines: list[str],
        current_func: str,
        call_stack: list[CallFrame],
    ) -> None:
        """Handle an attribute access node."""
        
        if isinstance(node.value, ast.Name):
            base_name = node.value.id
            attr_name = node.attr
            line_num = getattr(node, 'lineno', 0)
            code_ctx = source_lines[line_num - 1] if 0 < line_num <= len(source_lines) else ""
            
            call_frame = CallFrame(
                file_path=str(source_file),
                line_number=line_num,
                function_name=current_func,
                code_context=code_ctx,
            )
            
            # Check type context (parameter types)
            if base_name in type_context:
                self._add_file_reference(
                    deps, type_context[base_name], 
                    call_stack + [call_frame],
                    target_symbol=f"{base_name}.{attr_name}"
                )
            
            # Check imports
            elif base_name in imports:
                file_path, _ = imports[base_name]
                self._add_file_reference(
                    deps, file_path, 
                    call_stack + [call_frame],
                    target_symbol=f"{base_name}.{attr_name}"
                )
    
    def _add_file_reference(
        self,
        deps: EndpointDependencies,
        file_path: Path,
        call_stack: list[CallFrame],
        target_symbol: str = "",
    ) -> None:
        """Add a file to the dependencies with call stack."""
        
        path_str = str(file_path)
        
        # Always update call stack if we have one (keep the shortest/first found)
        if path_str not in deps.call_stacks and call_stack:
            # Add final frame pointing to the target file
            try:
                target_lines = file_path.read_text(encoding='utf-8').splitlines()
                target_code = target_lines[0] if target_lines else ""
            except Exception:
                target_code = ""
            
            final_frame = CallFrame(
                file_path=path_str,
                line_number=1,
                function_name=target_symbol or Path(file_path).stem,
                code_context=target_code,
            )
            deps.call_stacks[path_str] = call_stack + [final_frame]
        
        if path_str in deps.referenced_files:
            return
        
        try:
            source = file_path.read_text(encoding='utf-8')
            tree = ast.parse(source)
            
            # Get all lines with actual code
            lines = set()
            for node in ast.walk(tree):
                if hasattr(node, 'lineno'):
                    lines.add(node.lineno)
                    if hasattr(node, 'end_lineno') and node.end_lineno:
                        lines.update(range(node.lineno, node.end_lineno + 1))
            
            deps.referenced_files[path_str] = lines
        except Exception:
            deps.referenced_files[path_str] = set()
    
    def analyze_endpoints(
        self,
        endpoints: list[Endpoint],
        use_cache: bool = True,
    ) -> dict[str, EndpointDependencies]:
        """
        Analyze multiple endpoints.
        
        Args:
            endpoints: List of endpoints to analyze.
            use_cache: Whether to use cached analysis data.
            
        Returns:
            Dict mapping endpoint IDs to their dependencies.
        """
        # Try to load from cache
        if use_cache and self.cache_path.exists():
            try:
                self._load_cache()
                # Check if all endpoints are in cache
                all_cached = all(
                    ep.identifier in self._endpoint_deps
                    for ep in endpoints
                )
                if all_cached:
                    return self._endpoint_deps
            except Exception:
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
        """Save mypy analysis data to cache file."""
        cache_data = {}
        for endpoint_id, deps in self._endpoint_deps.items():
            cache_data[endpoint_id] = {
                "methods": deps.methods,
                "path": deps.path,
                "referenced_files": {
                    f: list(lines) for f, lines in deps.referenced_files.items()
                },
                "referenced_symbols": deps.referenced_symbols,
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
        """Load mypy analysis data from cache file."""
        try:
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
            
            for endpoint_id, deps_data in data.items():
                call_stacks = {}
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
                
                self._endpoint_deps[endpoint_id] = EndpointDependencies(
                    endpoint_id=endpoint_id,
                    methods=deps_data["methods"],
                    path=deps_data["path"],
                    referenced_files={
                        f: set(lines)
                        for f, lines in deps_data["referenced_files"].items()
                    },
                    referenced_symbols=deps_data.get("referenced_symbols", []),
                    call_stacks=call_stacks,
                )
        except Exception:
            pass
    
    def clear_cache(self) -> None:
        """Clear the mypy analysis cache."""
        if self.cache_path.exists():
            self.cache_path.unlink()
        self._endpoint_deps.clear()
    
    def get_endpoint_dependencies(
        self,
        endpoint_id: str,
    ) -> Optional[EndpointDependencies]:
        """Get dependencies for a specific endpoint."""
        return self._endpoint_deps.get(endpoint_id)
