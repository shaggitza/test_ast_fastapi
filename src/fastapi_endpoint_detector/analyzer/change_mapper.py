"""
Change mapper - maps code changes to affected endpoints.

This module combines diff parsing, endpoint registry, and dependency
graph to determine which endpoints are affected by code changes.

Supports three backends for dependency analysis:
- import: Uses grimp to analyze Python imports (default, faster)
- coverage: Uses coverage.py + AST to trace code execution paths
- mypy: Uses mypy-style type analysis for precise dependency tracking
"""

import time
from enum import Enum
from pathlib import Path
from typing import Callable, Literal, Optional

from fastapi_endpoint_detector.config import Config
from fastapi_endpoint_detector.models.diff import DiffFile, ChangeType
from fastapi_endpoint_detector.models.endpoint import Endpoint
from fastapi_endpoint_detector.models.report import (
    AffectedEndpoint,
    AnalysisReport,
    CallStackFrame,
    ConfidenceLevel,
)
from fastapi_endpoint_detector.parser.diff_parser import DiffParser
from fastapi_endpoint_detector.parser.fastapi_extractor import FastAPIExtractor
from fastapi_endpoint_detector.analyzer.dependency_graph import DependencyGraph
from fastapi_endpoint_detector.analyzer.endpoint_registry import EndpointRegistry


# Type alias for backend selection
DependencyBackend = Literal["import", "coverage", "mypy"]

# Progress callback type: (current, total, description) -> None
ProgressCallback = Callable[[int, int, str], None]


class ChangeMapperError(Exception):
    """Error during change mapping."""
    pass


class ChangeMapper:
    """
    Map code changes to affected FastAPI endpoints.
    
    This is the main orchestration class that:
    1. Extracts endpoints from a FastAPI app
    2. Builds the dependency graph (using chosen backend)
    3. Parses diff files
    4. Determines which endpoints are affected
    
    Supports three dependency analysis backends:
    - "import": Uses grimp for import-based dependency analysis (default, fast)
    - "coverage": Uses coverage.py + AST to trace code execution paths
    - "mypy": Uses mypy-style type analysis for precise dependency tracking
    """
    
    def __init__(
        self,
        app_path: Path,
        config: Optional[Config] = None,
        app_variable: str = "app",
        backend: DependencyBackend = "import",
        use_cache: bool = True,
    ) -> None:
        """
        Initialize the change mapper.
        
        Args:
            app_path: Path to the FastAPI application.
            config: Optional configuration object.
            app_variable: Name of the FastAPI app variable.
            backend: Dependency analysis backend ("import", "coverage", or "mypy").
            use_cache: Whether to use cached analysis results (default True).
        """
        self.app_path = app_path.resolve()
        self.config = config or Config()
        self.app_variable = app_variable
        self.backend = backend
        self.use_cache = use_cache
        
        # These are lazily initialized
        self._extractor: Optional[FastAPIExtractor] = None
        self._registry: Optional[EndpointRegistry] = None
        self._dep_graph: Optional[DependencyGraph] = None
        self._coverage_analyzer: Optional["CoverageAnalyzer"] = None
        self._mypy_analyzer: Optional["MypyAnalyzer"] = None
    
    @property
    def extractor(self) -> FastAPIExtractor:
        """Get the FastAPI extractor, initializing if needed."""
        if self._extractor is None:
            self._extractor = FastAPIExtractor(
                app_path=self.app_path,
                app_variable=self.app_variable,
            )
        return self._extractor
    
    @property
    def registry(self) -> EndpointRegistry:
        """Get the endpoint registry, populating if needed."""
        if self._registry is None:
            self._registry = EndpointRegistry()
            endpoints = self.extractor.extract_endpoints()
            self._registry.register_many(endpoints)
        return self._registry
    
    @property
    def dep_graph(self) -> DependencyGraph:
        """Get the dependency graph, building if needed."""
        if self._dep_graph is None:
            # Determine package path
            if self.app_path.is_file():
                package_path = self.app_path.parent
            else:
                package_path = self.app_path
            
            self._dep_graph = DependencyGraph(package_path)
            self._dep_graph.build()
        return self._dep_graph
    
    @property
    def coverage_analyzer(self) -> "CoverageAnalyzer":
        """Get the coverage analyzer, initializing if needed."""
        if self._coverage_analyzer is None:
            from fastapi_endpoint_detector.analyzer.coverage_analyzer import (
                CoverageAnalyzer,
            )
            
            if self.app_path.is_file():
                package_path = self.app_path.parent
            else:
                package_path = self.app_path
            
            self._coverage_analyzer = CoverageAnalyzer(package_path)
            # Pre-analyze all endpoints
            self._coverage_analyzer.analyze_endpoints(self.registry.get_all(), use_cache=self.use_cache)
        return self._coverage_analyzer
    
    @property
    def mypy_analyzer(self) -> "MypyAnalyzer":
        """Get the mypy analyzer, initializing if needed."""
        if self._mypy_analyzer is None:
            from fastapi_endpoint_detector.analyzer.mypy_analyzer import (
                MypyAnalyzer,
            )
            
            if self.app_path.is_file():
                package_path = self.app_path.parent
            else:
                package_path = self.app_path
            
            self._mypy_analyzer = MypyAnalyzer(package_path)
            # Pre-analyze all endpoints
            self._mypy_analyzer.analyze_endpoints(self.registry.get_all(), use_cache=self.use_cache)
        return self._mypy_analyzer
    
    def _check_direct_handler_change(
        self,
        endpoint: Endpoint,
        diff_file: DiffFile,
        added_lines: list[int],
        removed_lines: list[int],
    ) -> Optional[AffectedEndpoint]:
        """
        Check if a diff directly modifies an endpoint's handler.
        
        Args:
            endpoint: The endpoint to check.
            diff_file: The diff file.
            added_lines: Lines added in the diff.
            removed_lines: Lines removed in the diff.
            
        Returns:
            AffectedEndpoint if directly affected, None otherwise.
        """
        handler = endpoint.handler
        handler_end = handler.end_line_number or handler.line_number + 50
        
        # Check if any changed lines overlap with handler
        all_changed = set(added_lines) | set(removed_lines)
        handler_lines = set(range(handler.line_number, handler_end + 1))
        
        if all_changed & handler_lines:
            return AffectedEndpoint(
                endpoint=endpoint,
                confidence=ConfidenceLevel.HIGH,
                reason=f"Handler function directly modified in {diff_file.path}",
                dependency_chain=[str(diff_file.path)],
                changed_files=[str(diff_file.path)],
            )
        
        return None
    
    def _check_module_dependency(
        self,
        endpoint: Endpoint,
        changed_module: str,
        diff_file: DiffFile,
    ) -> Optional[AffectedEndpoint]:
        """
        Check if an endpoint depends on a changed module.
        
        Args:
            endpoint: The endpoint to check.
            changed_module: The module that changed.
            diff_file: The diff file.
            
        Returns:
            AffectedEndpoint if affected via dependency, None otherwise.
        """
        handler_module = endpoint.handler.module
        
        if not handler_module or handler_module == changed_module:
            return None
        
        # Build list of modules to check (the changed module and its parent packages)
        # e.g., "services.user_service" -> ["services.user_service", "services"]
        modules_to_check = [changed_module]
        parts = changed_module.split(".")
        for i in range(len(parts) - 1, 0, -1):
            modules_to_check.append(".".join(parts[:i]))
        
        try:
            # Check direct imports
            direct_imports = self.dep_graph.get_modules_imported_by(handler_module)
            
            for mod in modules_to_check:
                if mod in direct_imports:
                    return AffectedEndpoint(
                        endpoint=endpoint,
                        confidence=ConfidenceLevel.MEDIUM,
                        reason=f"Handler imports {mod} (changed: {changed_module})",
                        dependency_chain=[handler_module, mod],
                        changed_files=[str(diff_file.path)],
                    )
            
            # Check transitive dependencies if enabled
            if self.config.analysis.track_transitive:
                upstream = self.dep_graph.get_upstream_modules(handler_module)
                
                for mod in modules_to_check:
                    if mod in upstream:
                        # Find the path
                        chain = self.dep_graph.get_shortest_path(
                            from_module=handler_module,
                            to_module=mod,
                        )
                        chain_list = list(chain) if chain else [handler_module, mod]
                        
                        return AffectedEndpoint(
                            endpoint=endpoint,
                            confidence=ConfidenceLevel.LOW,
                            reason=f"Handler transitively depends on {mod} (changed: {changed_module})",
                            dependency_chain=chain_list,
                            changed_files=[str(diff_file.path)],
                        )
        except Exception:
            # Dependency graph might not cover all modules
            pass
        
        return None
    
    def _check_coverage_dependency(
        self,
        endpoint: Endpoint,
        diff_file: DiffFile,
        added_lines: list[int],
        removed_lines: list[int],
    ) -> Optional[AffectedEndpoint]:
        """
        Check if an endpoint's coverage intersects with changed lines.
        
        Uses the coverage-based backend to determine if the endpoint
        actually executes code in the changed lines.
        
        Args:
            endpoint: The endpoint to check.
            diff_file: The diff file.
            added_lines: Lines added in the diff.
            removed_lines: Lines removed in the diff.
            
        Returns:
            AffectedEndpoint if coverage intersects, None otherwise.
        """
        cov_data = self.coverage_analyzer.get_endpoint_coverage(endpoint.identifier)
        
        if not cov_data:
            return None
        
        file_path = str(diff_file.path)
        
        # Check if the file is covered at all
        if not cov_data.covers_file(file_path):
            return None
        
        # Check if the endpoint's coverage intersects with changed lines
        changed_lines = set(added_lines) | set(removed_lines)
        
        # Also check context lines (for added lines that don't exist yet)
        context_lines = set()
        for line in changed_lines:
            context_lines.update(range(max(1, line - 3), line + 4))
        
        covered_lines = cov_data.get_covered_lines(file_path)
        overlap = covered_lines & (changed_lines | context_lines)
        
        if overlap:
            direct_overlap = covered_lines & changed_lines
            display_lines = direct_overlap if direct_overlap else overlap
            
            return AffectedEndpoint(
                endpoint=endpoint,
                confidence=ConfidenceLevel.MEDIUM,
                reason=f"Coverage intersects with {diff_file.path} (lines {sorted(display_lines)[:5]}{'...' if len(display_lines) > 5 else ''})",
                dependency_chain=[endpoint.handler.module or "unknown", file_path],
                changed_files=[file_path],
            )
        
        return None
    
    def _check_mypy_dependency(
        self,
        endpoint: Endpoint,
        diff_file: DiffFile,
        added_lines: list[int],
        removed_lines: list[int],
    ) -> Optional[AffectedEndpoint]:
        """
        Check if an endpoint's dependencies (via mypy analysis) intersect with changes.
        
        Uses mypy-style type analysis to determine actual code dependencies.
        
        Args:
            endpoint: The endpoint to check.
            diff_file: The diff file.
            added_lines: Lines added in the diff.
            removed_lines: Lines removed in the diff.
            
        Returns:
            AffectedEndpoint if dependencies intersect, None otherwise.
        """
        deps = self.mypy_analyzer.get_endpoint_dependencies(endpoint.identifier)
        
        if not deps:
            return None
        
        # Check if the endpoint references the changed file at all
        file_path = str(diff_file.path)
        
        if not deps.references_file(file_path):
            return None
        
        # Check for line-level intersection
        changed_lines = set(added_lines) | set(removed_lines)
        
        # Also check context lines (for added lines that don't exist yet)
        context_lines = set()
        for line in changed_lines:
            context_lines.update(range(max(1, line - 3), line + 4))
        
        overlap = deps.references_lines(file_path, changed_lines | context_lines)
        
        if overlap:
            # Filter to show most relevant lines
            direct_overlap = deps.references_lines(file_path, changed_lines)
            display_lines = direct_overlap if direct_overlap else overlap
            
            # Get call stack for traceback-style output
            call_stack: list[CallStackFrame] = []
            raw_stack = deps.get_call_stack(file_path)
            if raw_stack:
                for frame in raw_stack:
                    call_stack.append(CallStackFrame(
                        file_path=frame.file_path,
                        line_number=frame.line_number,
                        function_name=frame.function_name,
                        code_context=frame.code_context,
                    ))
            
            return AffectedEndpoint(
                endpoint=endpoint,
                confidence=ConfidenceLevel.MEDIUM,
                reason=f"Type analysis shows dependency on {diff_file.path} (lines {sorted(display_lines)[:5]}{'...' if len(display_lines) > 5 else ''})",
                dependency_chain=[endpoint.handler.module or "unknown", file_path],
                changed_files=[file_path],
                call_stack=call_stack,
            )
        
        return None
    
    def _analyze_diff_file(
        self,
        diff_file: DiffFile,
    ) -> list[AffectedEndpoint]:
        """
        Analyze a single diff file and find affected endpoints.
        
        Uses the selected backend (import, coverage, or mypy) for dependency analysis.
        
        Args:
            diff_file: The parsed diff file.
            
        Returns:
            List of affected endpoints from this file.
        """
        affected: list[AffectedEndpoint] = []
        seen_endpoints: set[str] = set()
        
        # Get changed lines
        added_lines, removed_lines = DiffParser.get_changed_line_numbers(diff_file)
        
        # Find endpoints in the changed file
        file_endpoints = self.registry.get_by_file(diff_file.path)
        
        # Check for direct handler changes (applies to all backends)
        for endpoint in file_endpoints:
            result = self._check_direct_handler_change(
                endpoint, diff_file, added_lines, removed_lines
            )
            if result:
                affected.append(result)
                seen_endpoints.add(endpoint.identifier)
        
        # Use the appropriate backend for dependency analysis
        if self.backend == "coverage":
            # Coverage-based: check all endpoints against changed lines
            for endpoint in self.registry:
                if endpoint.identifier in seen_endpoints:
                    continue
                
                result = self._check_coverage_dependency(
                    endpoint, diff_file, added_lines, removed_lines
                )
                if result:
                    affected.append(result)
                    seen_endpoints.add(endpoint.identifier)
                    
        elif self.backend == "mypy":
            # Mypy-based: use type analysis for precise dependency tracking
            for endpoint in self.registry:
                if endpoint.identifier in seen_endpoints:
                    continue
                
                result = self._check_mypy_dependency(
                    endpoint, diff_file, added_lines, removed_lines
                )
                if result:
                    affected.append(result)
                    seen_endpoints.add(endpoint.identifier)
        else:
            # Import-based: use grimp dependency graph (default)
            # Falls back to coverage-based if dependency graph fails
            try:
                changed_module = self.dep_graph.file_path_to_module(diff_file.path)
                
                if changed_module:
                    # Check all endpoints for module dependencies
                    for endpoint in self.registry:
                        if endpoint.identifier in seen_endpoints:
                            continue
                        
                        result = self._check_module_dependency(
                            endpoint, changed_module, diff_file
                        )
                        if result:
                            affected.append(result)
                            seen_endpoints.add(endpoint.identifier)
            except Exception:
                # Fallback to coverage-based analysis if grimp fails
                # (e.g., for non-module projects)
                for endpoint in self.registry:
                    if endpoint.identifier in seen_endpoints:
                        continue
                    
                    result = self._check_coverage_dependency(
                        endpoint, diff_file, added_lines, removed_lines
                    )
                    if result:
                        affected.append(result)
                        seen_endpoints.add(endpoint.identifier)
        
        return affected
    
    def analyze_diff(
        self,
        diff_source: Path | str,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> AnalysisReport:
        """
        Analyze a diff and generate a report of affected endpoints.
        
        Args:
            diff_source: Path to diff file or diff content string.
            progress_callback: Optional callback for progress updates.
                              Called with (current, total, description).
            
        Returns:
            AnalysisReport with all affected endpoints.
        """
        start_time = time.time()
        errors: list[str] = []
        warnings: list[str] = []
        
        def report_progress(current: int, total: int, desc: str) -> None:
            if progress_callback:
                progress_callback(current, total, desc)
        
        # Parse the diff
        report_progress(0, 100, "Parsing diff...")
        try:
            if isinstance(diff_source, Path):
                diff_files = DiffParser.parse_file(diff_source)
                diff_source_str = str(diff_source)
            else:
                diff_files = DiffParser.parse_string(diff_source)
                diff_source_str = "stdin"
        except Exception as e:
            errors.append(f"Failed to parse diff: {e}")
            diff_files = []
            diff_source_str = str(diff_source)
        
        # Filter to Python files
        python_files = DiffParser.get_python_files(diff_files)
        
        # Initialize endpoints (this triggers backend analysis)
        report_progress(5, 100, "Extracting endpoints...")
        total_endpoints = len(self.registry)
        
        # Pre-analyze endpoints with the selected backend
        if self.backend == "coverage":
            report_progress(10, 100, f"Analyzing {total_endpoints} endpoints (coverage)...")
            self._preanalyze_coverage(progress_callback)
        elif self.backend == "mypy":
            report_progress(10, 100, f"Analyzing {total_endpoints} endpoints (mypy)...")
            self._preanalyze_mypy(progress_callback)
        else:
            report_progress(10, 100, "Building dependency graph...")
            # Import backend builds graph lazily
            _ = self.dep_graph
        
        # Analyze each Python file
        report_progress(70, 100, f"Checking {len(python_files)} changed files...")
        all_affected: list[AffectedEndpoint] = []
        seen_endpoints: set[str] = set()
        
        for i, diff_file in enumerate(python_files):
            try:
                report_progress(
                    70 + int(20 * (i + 1) / max(len(python_files), 1)),
                    100,
                    f"Analyzing {diff_file.path.name}..."
                )
                file_affected = self._analyze_diff_file(diff_file)
                for ae in file_affected:
                    if ae.endpoint.identifier not in seen_endpoints:
                        all_affected.append(ae)
                        seen_endpoints.add(ae.endpoint.identifier)
            except Exception as e:
                warnings.append(f"Error analyzing {diff_file.path}: {e}")
        
        # Filter by confidence threshold
        report_progress(95, 100, "Filtering results...")
        threshold = self.config.analysis.confidence_threshold
        confidence_order = {
            ConfidenceLevel.HIGH: 1.0,
            ConfidenceLevel.MEDIUM: 0.7,
            ConfidenceLevel.LOW: 0.3,
        }
        
        filtered_affected = [
            ae for ae in all_affected
            if confidence_order[ae.confidence] >= threshold
        ]
        
        # Calculate duration
        duration_ms = (time.time() - start_time) * 1000
        report_progress(100, 100, "Complete!")
        
        return AnalysisReport(
            app_path=str(self.app_path),
            diff_source=diff_source_str,
            total_endpoints=len(self.registry),
            affected_endpoints=filtered_affected,
            total_files_changed=len(diff_files),
            python_files_changed=len(python_files),
            analysis_duration_ms=duration_ms,
            errors=errors,
            warnings=warnings,
        )
    
    def _preanalyze_coverage(
        self,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> None:
        """Pre-analyze all endpoints with coverage backend."""
        endpoints = self.registry.get_all()
        total = len(endpoints)
        
        for i, endpoint in enumerate(endpoints):
            if progress_callback:
                progress_callback(
                    10 + int(55 * (i + 1) / max(total, 1)),
                    100,
                    f"Analyzing endpoint {i + 1}/{total}: {endpoint.path}"
                )
            if endpoint.identifier not in self.coverage_analyzer._endpoint_coverage:
                self.coverage_analyzer.trace_endpoint_handler(endpoint)
    
    def _preanalyze_mypy(
        self,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> None:
        """Pre-analyze all endpoints with mypy backend."""
        endpoints = self.registry.get_all()
        total = len(endpoints)
        
        for i, endpoint in enumerate(endpoints):
            if progress_callback:
                progress_callback(
                    10 + int(55 * (i + 1) / max(total, 1)),
                    100,
                    f"Analyzing endpoint {i + 1}/{total}: {endpoint.path}"
                )
            if endpoint.identifier not in self.mypy_analyzer._endpoint_deps:
                self.mypy_analyzer.analyze_endpoint(endpoint)
    
    def get_endpoints(self) -> list[Endpoint]:
        """Get all endpoints in the application."""
        return self.registry.get_all()
    
    def clear_cache(self) -> None:
        """Clear cached analysis results for the selected backend."""
        if self.backend == "coverage":
            if self._coverage_analyzer is not None:
                self._coverage_analyzer.clear_cache()
            else:
                # Initialize and clear the cache file even if analyzer not loaded
                from fastapi_endpoint_detector.analyzer.coverage_analyzer import (
                    CoverageAnalyzer,
                )
                if self.app_path.is_file():
                    package_path = self.app_path.parent
                else:
                    package_path = self.app_path
                temp_analyzer = CoverageAnalyzer(package_path)
                temp_analyzer.clear_cache()
        elif self.backend == "mypy":
            if self._mypy_analyzer is not None:
                self._mypy_analyzer.clear_cache()
            else:
                # Initialize and clear the cache file even if analyzer not loaded
                from fastapi_endpoint_detector.analyzer.mypy_analyzer import (
                    MypyAnalyzer,
                )
                if self.app_path.is_file():
                    package_path = self.app_path.parent
                else:
                    package_path = self.app_path
                temp_analyzer = MypyAnalyzer(package_path)
                temp_analyzer.clear_cache()
