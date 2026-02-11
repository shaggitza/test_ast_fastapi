"""
Change mapper - maps code changes to affected endpoints.

This module combines diff parsing, endpoint registry, and mypy-based
dependency analysis to determine which endpoints are affected by code changes.

Uses mypy for type-aware, precise dependency tracking.
"""

import time
from collections.abc import Callable
from pathlib import Path

from fastapi_endpoint_detector.analyzer.endpoint_registry import EndpointRegistry
from fastapi_endpoint_detector.config import Config
from fastapi_endpoint_detector.models.diff import DiffFile
from fastapi_endpoint_detector.models.endpoint import Endpoint
from fastapi_endpoint_detector.models.report import (
    AffectedEndpoint,
    AnalysisReport,
    CallStackFrame,
    ConfidenceLevel,
)
from fastapi_endpoint_detector.parser.diff_parser import DiffParser
from fastapi_endpoint_detector.parser.fastapi_extractor import FastAPIExtractor

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
    2. Analyzes dependencies using mypy
    3. Parses diff files
    4. Determines which endpoints are affected
    
    Uses mypy for type-aware, precise dependency tracking.
    """

    def __init__(
        self,
        app_path: Path,
        config: Config | None = None,
        app_variable: str = "app",
        use_cache: bool = True,
    ) -> None:
        """
        Initialize the change mapper.
        
        Args:
            app_path: Path to the FastAPI application.
            config: Optional configuration object.
            app_variable: Name of the FastAPI app variable.
            use_cache: Whether to use cached analysis results (default True).
        """
        self.app_path = app_path.resolve()
        self.config = config or Config()
        self.app_variable = app_variable
        self.use_cache = use_cache

        # These are lazily initialized
        self._extractor: FastAPIExtractor | None = None
        self._registry: EndpointRegistry | None = None
        self._mypy_analyzer: MypyAnalyzer | None = None

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
    def mypy_analyzer(self) -> "MypyAnalyzer":
        """Get the mypy analyzer, initializing if needed (does NOT pre-analyze)."""
        if self._mypy_analyzer is None:
            from fastapi_endpoint_detector.analyzer.mypy_analyzer import (
                MypyAnalyzer,
            )

            if self.app_path.is_file():
                package_path = self.app_path.parent
            else:
                package_path = self.app_path

            self._mypy_analyzer = MypyAnalyzer(package_path)
            # NOTE: We don't pre-analyze here - that's done in _preanalyze_mypy
            # with progress reporting
        return self._mypy_analyzer

    def _check_direct_handler_change(
        self,
        endpoint: Endpoint,
        diff_file: DiffFile,
        added_lines: list[int],
        removed_lines: list[int],
    ) -> AffectedEndpoint | None:
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

    def _check_mypy_dependency(
        self,
        endpoint: Endpoint,
        diff_file: DiffFile,
        added_lines: list[int],
        removed_lines: list[int],
    ) -> AffectedEndpoint | None:
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

                # Add frames showing the actual changed lines
                # Group consecutive lines together for cleaner display
                if display_lines:
                    # Sort the changed lines
                    sorted_lines = sorted(display_lines)

                    # Read the file once for all lines
                    lines_list = []
                    try:
                        file_path_obj = Path(file_path)
                        if file_path_obj.exists():
                            with open(file_path_obj, encoding="utf-8") as f:
                                lines_list = f.readlines()
                    except (OSError, UnicodeDecodeError):
                        pass

                    # Group consecutive lines together
                    if sorted_lines:  # Safety check
                        line_groups = []
                        current_group = [sorted_lines[0]]

                        for i in range(1, len(sorted_lines)):
                            if sorted_lines[i] == sorted_lines[i-1] + 1:
                                # Consecutive line, add to current group
                                current_group.append(sorted_lines[i])
                            else:
                                # Non-consecutive, start a new group
                                line_groups.append(current_group)
                                current_group = [sorted_lines[i]]

                        # Don't forget the last group
                        line_groups.append(current_group)

                        # Add a frame for each group of lines
                        for group in line_groups:
                            first_line = group[0]
                            last_line = group[-1]

                            # Try to get the function name from symbol references
                            function_name = "module"
                            for sym_ref in deps.referenced_symbols:
                                if (sym_ref.file_path == file_path and
                                    sym_ref.contains_line(first_line)):
                                    function_name = sym_ref.symbol_name
                                    break

                            # Try to get code context from the file
                            # For ranges, show all lines in the group
                            code_context = ""
                            if lines_list and 0 < first_line <= len(lines_list):
                                if len(group) > 1:
                                    # Multiple lines - show all of them
                                    context_lines = []
                                    for line_num in group:
                                        if 0 < line_num <= len(lines_list):
                                            context_lines.append(lines_list[line_num - 1].rstrip())
                                    code_context = f"[lines {first_line}-{last_line}]\n" + "\n".join(context_lines)
                                else:
                                    # Single line
                                    code_context = lines_list[first_line - 1].rstrip()

                            call_stack.append(CallStackFrame(
                                file_path=file_path,
                                line_number=first_line,
                                function_name=function_name,
                                code_context=code_context,
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
        
        Uses mypy for type-aware dependency analysis.
        
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

        # Check for direct handler changes
        for endpoint in file_endpoints:
            result = self._check_direct_handler_change(
                endpoint, diff_file, added_lines, removed_lines
            )
            if result:
                affected.append(result)
                seen_endpoints.add(endpoint.identifier)

        # Use mypy for type-aware dependency analysis
        for endpoint in self.registry:
            if endpoint.identifier in seen_endpoints:
                continue

            result = self._check_mypy_dependency(
                endpoint, diff_file, added_lines, removed_lines
            )
            if result:
                affected.append(result)
                seen_endpoints.add(endpoint.identifier)

        return affected

    def analyze_diff(
        self,
        diff_source: Path | str,
        progress_callback: ProgressCallback | None = None,
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

        # Initialize endpoints
        report_progress(5, 100, "Extracting endpoints...")
        total_endpoints = len(self.registry)

        # Pre-analyze endpoints with mypy
        report_progress(10, 100, f"Analyzing {total_endpoints} endpoints (mypy)...")
        self._preanalyze_mypy(progress_callback)

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

    def _preanalyze_mypy(
        self,
        progress_callback: ProgressCallback | None = None,
    ) -> None:
        """Pre-analyze all endpoints with mypy."""
        endpoints = self.registry.get_all()
        total = len(endpoints)

        # Try to load from cache first
        if self.use_cache and self.mypy_analyzer.cache_path.exists():
            if progress_callback:
                progress_callback(10, 100, "Loading cached analysis...")
            try:
                self.mypy_analyzer._load_cache()
                # Check if all endpoints are cached
                all_cached = all(
                    ep.identifier in self.mypy_analyzer._endpoint_deps
                    for ep in endpoints
                )
                if all_cached:
                    if progress_callback:
                        progress_callback(65, 100, f"Loaded {total} endpoints from cache")
                    return
            except Exception:
                pass

        # Analyze uncached endpoints
        for i, endpoint in enumerate(endpoints):
            if progress_callback:
                progress_callback(
                    10 + int(55 * (i + 1) / max(total, 1)),
                    100,
                    f"Analyzing endpoint {i + 1}/{total}: {endpoint.path}"
                )
            if endpoint.identifier not in self.mypy_analyzer._endpoint_deps:
                self.mypy_analyzer.analyze_endpoint(endpoint)

        # Save cache after analysis
        if self.use_cache:
            self.mypy_analyzer._save_cache()

    def get_endpoints(self) -> list[Endpoint]:
        """Get all endpoints in the application."""
        return self.registry.get_all()

    def clear_cache(self) -> None:
        """Clear cached analysis results for mypy."""
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
