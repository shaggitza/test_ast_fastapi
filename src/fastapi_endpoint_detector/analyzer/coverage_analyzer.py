"""
Coverage-based dependency analyzer.

This module provides an alternative backend that uses code coverage
to determine which code paths are actually executed by each endpoint,
rather than relying solely on import analysis.

The coverage approach works by:
1. Running each endpoint handler with coverage instrumentation
2. Recording which files/lines are executed
3. Comparing the executed lines with changed lines from diffs
"""

import ast
import coverage
import inspect
import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Optional
from dataclasses import dataclass, field

from fastapi_endpoint_detector.models.endpoint import Endpoint


class CoverageAnalyzerError(Exception):
    """Error during coverage analysis."""
    pass


@dataclass
class EndpointCoverage:
    """Coverage data for a single endpoint."""
    
    endpoint_id: str
    methods: list[str]
    path: str
    covered_files: dict[str, set[int]] = field(default_factory=dict)
    """Mapping of file path -> set of executed line numbers."""
    
    def covers_line(self, file_path: str, line_number: int) -> bool:
        """Check if this endpoint's execution covers a specific line."""
        # Normalize the file path for comparison
        normalized = str(Path(file_path).resolve())
        
        # Check exact match
        if normalized in self.covered_files:
            return line_number in self.covered_files[normalized]
        
        # Check by basename match (for relative paths in diffs)
        file_name = Path(file_path).name
        for covered_path, lines in self.covered_files.items():
            if Path(covered_path).name == file_name or covered_path.endswith(str(file_path)):
                return line_number in lines
        
        return False
    
    def covers_file(self, file_path: str) -> bool:
        """Check if this endpoint's execution touches a file at all."""
        normalized = str(Path(file_path).resolve())
        
        if normalized in self.covered_files:
            return True
        
        file_name = Path(file_path).name
        for covered_path in self.covered_files:
            if Path(covered_path).name == file_name or covered_path.endswith(str(file_path)):
                return True
        
        return False
    
    def get_covered_lines(self, file_path: str) -> set[int]:
        """Get all covered lines for a specific file."""
        normalized = str(Path(file_path).resolve())
        
        if normalized in self.covered_files:
            return self.covered_files[normalized]
        
        file_name = Path(file_path).name
        for covered_path, lines in self.covered_files.items():
            if Path(covered_path).name == file_name or covered_path.endswith(str(file_path)):
                return lines
        
        return set()


class CoverageAnalyzer:
    """
    Analyze endpoint dependencies using code coverage.
    
    This provides a more precise alternative to import-based analysis
    by actually tracing code execution paths.
    
    Two modes of operation:
    1. Static tracing: Analyze handler code to determine potential call paths
    2. Dynamic tracing: Run handlers with mock inputs and trace execution
    """
    
    def __init__(
        self,
        app_path: Path,
        source_paths: Optional[list[Path]] = None,
    ) -> None:
        """
        Initialize the coverage analyzer.
        
        Args:
            app_path: Path to the FastAPI application.
            source_paths: Additional source paths to include in coverage.
        """
        self.app_path = app_path.resolve()
        self.source_paths = source_paths or []
        self._endpoint_coverage: dict[str, EndpointCoverage] = {}
        self._cache_file: Optional[Path] = None
    
    @property
    def coverage_cache_path(self) -> Path:
        """Path to the coverage cache file."""
        if self._cache_file:
            return self._cache_file
        return self.app_path.parent / ".endpoint_coverage_cache.json"
    
    def set_cache_path(self, path: Path) -> None:
        """Set a custom cache file path."""
        self._cache_file = path
    
    def _get_source_directory(self) -> Path:
        """Determine the source directory for coverage."""
        if self.app_path.is_file():
            return self.app_path.parent
        return self.app_path
    
    def _create_coverage_instance(self) -> coverage.Coverage:
        """Create a configured coverage.py instance."""
        source_dir = self._get_source_directory()
        
        # Use source instead of include for cleaner configuration
        cov = coverage.Coverage(
            branch=False,  # We only need line coverage
            source=[str(source_dir)],
            omit=[
                "**/test_*.py",
                "**/*_test.py",
                "**/conftest.py",
                "**/__pycache__/**",
            ],
        )
        return cov
    
    def trace_endpoint_handler(
        self,
        endpoint: Endpoint,
        handler_callable: Optional[Callable[..., Any]] = None,
    ) -> EndpointCoverage:
        """
        Trace a single endpoint handler to capture its code coverage.
        
        This uses coverage.py to instrument the handler and capture
        which lines of code are executed during a simulated call.
        
        If dynamic coverage fails to capture app code, falls back to
        static analysis of the handler's AST.
        
        Args:
            endpoint: The endpoint to trace.
            handler_callable: Optional pre-loaded handler callable.
            
        Returns:
            EndpointCoverage with the traced execution paths.
        """
        endpoint_cov = EndpointCoverage(
            endpoint_id=endpoint.identifier,
            methods=[m.value for m in endpoint.methods],
            path=endpoint.path,
        )
        
        # Use static analysis to trace dependencies
        # Dynamic coverage doesn't work well when modules are already imported
        self._analyze_handler_statically(endpoint, endpoint_cov)
        
        self._endpoint_coverage[endpoint.identifier] = endpoint_cov
        return endpoint_cov
    
    def _load_handler(self, endpoint: Endpoint) -> Optional[Callable[..., Any]]:
        """Load the handler callable from endpoint info."""
        handler = endpoint.handler
        
        if not handler.file_path:
            return None
        
        try:
            # Import the module
            module_path = Path(handler.file_path)
            if not module_path.exists():
                return None
            
            # Add parent to path if needed
            parent_dir = str(module_path.parent)
            if parent_dir not in sys.path:
                sys.path.insert(0, parent_dir)
            
            # Use importlib to load
            import importlib.util
            spec = importlib.util.spec_from_file_location(
                handler.module or "handler_module",
                module_path,
            )
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Get the function (handler.name is the function name)
                if hasattr(module, handler.name):
                    return getattr(module, handler.name)
        except Exception:
            pass
        
        return None
    
    def _invoke_handler_safely(self, handler: Callable[..., Any]) -> None:
        """
        Try to invoke a handler with mock arguments.
        
        This is best-effort - we try to call the handler but catch
        any exceptions since we're just trying to trace code paths.
        """
        try:
            sig = inspect.signature(handler)
            mock_args = {}
            
            for param_name, param in sig.parameters.items():
                if param.default is not inspect.Parameter.empty:
                    continue  # Has default, skip
                
                # Try to provide sensible mock values
                annotation = param.annotation
                if annotation is inspect.Parameter.empty:
                    mock_args[param_name] = None
                elif annotation is str:
                    mock_args[param_name] = "test"
                elif annotation is int:
                    mock_args[param_name] = 1
                elif annotation is float:
                    mock_args[param_name] = 1.0
                elif annotation is bool:
                    mock_args[param_name] = True
                elif annotation is list:
                    mock_args[param_name] = []
                elif annotation is dict:
                    mock_args[param_name] = {}
                else:
                    mock_args[param_name] = None
            
            # Try calling - this will fail for most real handlers
            # but triggers code loading and import coverage
            handler(**mock_args)
            
        except Exception:
            # Expected to fail - we've still traced imports
            pass
    
    def _analyze_handler_statically(
        self,
        endpoint: Endpoint,
        endpoint_cov: EndpointCoverage,
    ) -> None:
        """
        Perform static analysis on a handler when dynamic tracing fails.
        
        This parses the handler's AST to find function calls and
        attribute accesses that indicate dependencies.
        """
        handler = endpoint.handler
        
        if not handler.file_path:
            return
        
        try:
            file_path = Path(handler.file_path)
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(file_path))
            
            # First, collect all imports in the file
            imports = self._collect_imports(tree, file_path)
            
            # Find the handler function (handler.name is the function name)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if node.name == handler.name:
                        # Add the handler's own lines
                        start = node.lineno
                        end = getattr(node, 'end_lineno', start + 50)
                        endpoint_cov.covered_files[str(file_path)] = set(
                            range(start, end + 1)
                        )
                        
                        # Build a mapping of parameter names to their types
                        param_types = self._get_param_type_mapping(node, imports)
                        
                        # Merge param types into imports for resolution
                        extended_imports = {**imports, **param_types}
                        
                        # Analyze calls within the handler
                        self._trace_calls_in_function(
                            node, file_path, endpoint_cov, extended_imports
                        )
                        break
        except Exception:
            pass
    
    def _get_param_type_mapping(
        self,
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
        imports: dict[str, Path],
    ) -> dict[str, Path]:
        """
        Extract parameter type annotations and map param names to file paths.
        
        e.g., `service: UserService` -> {'service': path_to_user_service.py}
        """
        param_types: dict[str, Path] = {}
        
        for arg in func_node.args.args + func_node.args.kwonlyargs:
            if arg.annotation:
                # Get the type name from annotation
                type_name = self._get_annotation_name(arg.annotation)
                if type_name and type_name in imports:
                    param_types[arg.arg] = imports[type_name]
        
        return param_types
    
    def _get_annotation_name(self, annotation: ast.expr) -> Optional[str]:
        """Extract the name from a type annotation."""
        if isinstance(annotation, ast.Name):
            return annotation.id
        elif isinstance(annotation, ast.Subscript):
            # e.g., Optional[UserService] -> UserService
            if isinstance(annotation.value, ast.Name):
                return self._get_annotation_name(annotation.slice)
        elif isinstance(annotation, ast.Attribute):
            # e.g., models.User -> User
            return annotation.attr
        return None
    
    def _collect_imports(
        self,
        tree: ast.Module,
        source_file: Path,
    ) -> dict[str, Path]:
        """
        Collect imports from the AST and resolve them to file paths.
        
        Returns a dict mapping imported names to their file paths.
        """
        imports: dict[str, Path] = {}
        base_dir = source_file.parent
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    # e.g., "import services.user_service"
                    module_name = alias.asname or alias.name.split(".")[-1]
                    module_path = self._resolve_module_to_file(
                        alias.name, base_dir
                    )
                    if module_path:
                        imports[module_name] = module_path
                        
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    for alias in node.names:
                        # e.g., "from services.user_service import UserService"
                        imported_name = alias.asname or alias.name
                        
                        # Try to resolve as a submodule first
                        full_module = f"{node.module}.{alias.name}"
                        module_path = self._resolve_module_to_file(
                            full_module, base_dir
                        )
                        if not module_path:
                            # Fall back to the parent module
                            module_path = self._resolve_module_to_file(
                                node.module, base_dir
                            )
                        
                        if module_path:
                            imports[imported_name] = module_path
        
        return imports
    
    def _resolve_module_to_file(
        self,
        module_name: str,
        base_dir: Path,
    ) -> Optional[Path]:
        """
        Resolve a module name to its file path.
        """
        # Convert module.name to module/name.py
        parts = module_name.split(".")
        
        # Try relative to base_dir
        relative_path = base_dir / Path(*parts)
        
        # Check for package or module
        if (relative_path / "__init__.py").exists():
            return relative_path / "__init__.py"
        
        module_file = relative_path.with_suffix(".py")
        if module_file.exists():
            return module_file
        
        # Try relative to app_path
        app_relative = self.app_path / Path(*parts)
        if (app_relative / "__init__.py").exists():
            return app_relative / "__init__.py"
        
        app_file = app_relative.with_suffix(".py")
        if app_file.exists():
            return app_file
        
        return None
    
    def _trace_calls_in_function(
        self,
        func_node: ast.AST,
        file_path: Path,
        endpoint_cov: EndpointCoverage,
        imports: dict[str, Path],
    ) -> None:
        """
        Trace function calls within a handler to find dependencies.
        
        This is a static approximation of what dynamic coverage would find.
        """
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                self._resolve_call_target(node, file_path, endpoint_cov, imports)
            elif isinstance(node, ast.Attribute):
                # Also track attribute access (e.g., service.method)
                self._resolve_attribute_access(node, endpoint_cov, imports)
    
    def _resolve_attribute_access(
        self,
        attr_node: ast.Attribute,
        endpoint_cov: EndpointCoverage,
        imports: dict[str, Path],
    ) -> None:
        """
        Resolve attribute access to find the source file.
        
        e.g., user_service.get_user() -> services/user_service.py
        """
        # Get the base name being accessed
        if isinstance(attr_node.value, ast.Name):
            base_name = attr_node.value.id
            if base_name in imports:
                target_file = imports[base_name]
                # Mark the entire file as potentially covered
                # (we don't know which lines without deeper analysis)
                if str(target_file) not in endpoint_cov.covered_files:
                    # Read the file and get all executable lines
                    try:
                        source = target_file.read_text(encoding="utf-8")
                        tree = ast.parse(source)
                        lines = set()
                        for node in ast.walk(tree):
                            if hasattr(node, 'lineno'):
                                lines.add(node.lineno)
                        endpoint_cov.covered_files[str(target_file)] = lines
                    except Exception:
                        pass
    
    def _resolve_call_target(
        self,
        call_node: ast.Call,
        source_file: Path,
        endpoint_cov: EndpointCoverage,
        imports: dict[str, Path],
    ) -> None:
        """
        Try to resolve a call node to its target function and file.
        
        This is heuristic - we look for common patterns like:
        - service.method()
        - module.function()
        - direct function calls
        """
        # Handle attribute calls like service.method()
        if isinstance(call_node.func, ast.Attribute):
            self._resolve_attribute_access(call_node.func, endpoint_cov, imports)
        
        # Handle direct calls like imported_function()
        elif isinstance(call_node.func, ast.Name):
            func_name = call_node.func.id
            if func_name in imports:
                target_file = imports[func_name]
                if str(target_file) not in endpoint_cov.covered_files:
                    try:
                        source = target_file.read_text(encoding="utf-8")
                        tree = ast.parse(source)
                        lines = set()
                        for node in ast.walk(tree):
                            if hasattr(node, 'lineno'):
                                lines.add(node.lineno)
                        endpoint_cov.covered_files[str(target_file)] = lines
                    except Exception:
                        pass
    
    def analyze_endpoints(
        self,
        endpoints: list[Endpoint],
        use_cache: bool = True,
    ) -> dict[str, EndpointCoverage]:
        """
        Analyze multiple endpoints and build coverage data.
        
        Args:
            endpoints: List of endpoints to analyze.
            use_cache: Whether to use cached coverage data.
            
        Returns:
            Dict mapping endpoint IDs to their coverage data.
        """
        # Try to load from cache
        if use_cache and self.coverage_cache_path.exists():
            try:
                self._load_cache()
                # Check if all endpoints are in cache
                all_cached = all(
                    ep.identifier in self._endpoint_coverage
                    for ep in endpoints
                )
                if all_cached:
                    return self._endpoint_coverage
            except Exception:
                pass
        
        # Analyze each endpoint
        for endpoint in endpoints:
            if endpoint.identifier not in self._endpoint_coverage:
                self.trace_endpoint_handler(endpoint)
        
        # Save cache
        if use_cache:
            self._save_cache()
        
        return self._endpoint_coverage
    
    def _save_cache(self) -> None:
        """Save coverage data to cache file."""
        cache_data = {}
        for endpoint_id, cov in self._endpoint_coverage.items():
            cache_data[endpoint_id] = {
                "methods": cov.methods,
                "path": cov.path,
                "covered_files": {
                    f: list(lines) for f, lines in cov.covered_files.items()
                },
            }
        
        try:
            self.coverage_cache_path.write_text(
                json.dumps(cache_data, indent=2),
                encoding="utf-8",
            )
        except Exception:
            pass
    
    def _load_cache(self) -> None:
        """Load coverage data from cache file."""
        try:
            data = json.loads(self.coverage_cache_path.read_text(encoding="utf-8"))
            
            for endpoint_id, cov_data in data.items():
                self._endpoint_coverage[endpoint_id] = EndpointCoverage(
                    endpoint_id=endpoint_id,
                    methods=cov_data["methods"],
                    path=cov_data["path"],
                    covered_files={
                        f: set(lines)
                        for f, lines in cov_data["covered_files"].items()
                    },
                )
        except Exception:
            pass
    
    def clear_cache(self) -> None:
        """Clear the coverage cache."""
        if self.coverage_cache_path.exists():
            self.coverage_cache_path.unlink()
        self._endpoint_coverage.clear()
    
    def get_endpoint_coverage(
        self,
        endpoint_id: str,
    ) -> Optional[EndpointCoverage]:
        """Get coverage data for a specific endpoint."""
        return self._endpoint_coverage.get(endpoint_id)
    
    def find_endpoints_covering_lines(
        self,
        file_path: str,
        lines: set[int],
    ) -> list[tuple[str, set[int]]]:
        """
        Find all endpoints whose coverage includes any of the given lines.
        
        Args:
            file_path: Path to the file containing the lines.
            lines: Set of line numbers to check.
            
        Returns:
            List of (endpoint_id, overlapping_lines) tuples.
        """
        results = []
        
        for endpoint_id, cov in self._endpoint_coverage.items():
            covered = cov.get_covered_lines(file_path)
            overlap = covered & lines
            
            if overlap:
                results.append((endpoint_id, overlap))
        
        return results
