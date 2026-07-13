"""
Change mapper - maps code changes to affected endpoints.

This module combines diff parsing, endpoint registry, and mypy-based
dependency analysis to determine which endpoints are affected by code changes.

Uses mypy for type-aware, precise dependency tracking.
"""

import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from fastapi_endpoint_detector.analyzer.endpoint_registry import EndpointRegistry
from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.analyzer.scip_analyzer import (
    SCIPAnalyzer,
    SCIPAnalyzerError,
    SCIPDefinition,
)
from fastapi_endpoint_detector.config import Config
from fastapi_endpoint_detector.models.diff import ChangeType, DiffFile
from fastapi_endpoint_detector.models.endpoint import Endpoint
from fastapi_endpoint_detector.models.report import (
    AffectedEndpoint,
    AnalysisReport,
    CallStackFrame,
    ConfidenceLevel,
    OrphanChange,
)
from fastapi_endpoint_detector.parser.diff_parser import DiffParser
from fastapi_endpoint_detector.parser.fastapi_extractor import FastAPIExtractor
from fastapi_endpoint_detector.parser.secure_ast_extractor import SecureASTExtractor

# Progress callback type: (current, total, description) -> None
ProgressCallback = Callable[[int, int, str], None]

_CONFIDENCE_SCORE = {
    ConfidenceLevel.HIGH: 1.0,
    ConfidenceLevel.MEDIUM: 0.7,
    ConfidenceLevel.LOW: 0.3,
}


def _endpoint_result_key(endpoint: Endpoint) -> tuple[str, str, int, str, str]:
    handler = endpoint.handler
    return (
        endpoint.identifier,
        str(handler.file_path.resolve()),
        handler.line_number,
        handler.name,
        handler.module,
    )


def _stack_key(stack: list[CallStackFrame]) -> tuple[tuple[str, int, str, str | None], ...]:
    return tuple(
        (frame.file_path, frame.line_number, frame.function_name, frame.code_context)
        for frame in stack
    )


@dataclass
class _AffectedAccumulator:
    endpoint: Endpoint
    confidence: ConfidenceLevel
    reason: str
    dependency_chain: list[str]
    changed_files: list[str] = field(default_factory=list)
    dependency_chains: list[list[str]] = field(default_factory=list)
    call_stacks: list[list[CallStackFrame]] = field(default_factory=list)

    @classmethod
    def from_candidate(cls, candidate: AffectedEndpoint) -> "_AffectedAccumulator":
        accumulator = cls(
            endpoint=candidate.endpoint,
            confidence=candidate.confidence,
            reason=candidate.reason,
            dependency_chain=list(candidate.dependency_chain),
        )
        accumulator.merge(candidate)
        return accumulator

    def merge(self, candidate: AffectedEndpoint) -> None:
        if _CONFIDENCE_SCORE[candidate.confidence] > _CONFIDENCE_SCORE[self.confidence]:
            self.confidence = candidate.confidence
            self.reason = candidate.reason
            self.dependency_chain = list(candidate.dependency_chain)
        for file_path in candidate.changed_files:
            if file_path not in self.changed_files:
                self.changed_files.append(file_path)
        for chain in candidate.all_dependency_chains:
            if chain not in self.dependency_chains:
                self.dependency_chains.append(list(chain))
        stack_keys = {_stack_key(stack) for stack in self.call_stacks}
        for stack in candidate.call_stacks:
            key = _stack_key(stack)
            if key not in stack_keys:
                self.call_stacks.append(list(stack))
                stack_keys.add(key)

    def materialize(self) -> AffectedEndpoint:
        return AffectedEndpoint(
            endpoint=self.endpoint,
            confidence=self.confidence,
            reason=self.reason,
            dependency_chain=self.dependency_chain,
            dependency_chains=self.dependency_chains,
            changed_files=self.changed_files,
            call_stacks=self.call_stacks,
        )


def _merge_affected(
    accumulated: dict[tuple[str, str, int, str, str], _AffectedAccumulator],
    candidate: AffectedEndpoint,
) -> None:
    key = _endpoint_result_key(candidate.endpoint)
    existing = accumulated.get(key)
    if existing is None:
        accumulated[key] = _AffectedAccumulator.from_candidate(candidate)
    else:
        existing.merge(candidate)


def _normalized_diff_path(path: Path | str) -> str:
    return os.path.normcase(os.path.normpath(str(path).replace("\\", "/")))


@dataclass
class _OrphanAccumulator:
    file_path: str
    reason: str
    added: set[int] = field(default_factory=set)
    removed: set[int] = field(default_factory=set)
    processed_added: set[int] = field(default_factory=set)
    processed_removed: set[int] = field(default_factory=set)

    def materialize(self) -> OrphanChange | None:
        orphan_added = sorted(self.added - self.processed_added)
        orphan_removed = sorted(self.removed - self.processed_removed)
        if not orphan_added and not orphan_removed:
            return None
        return OrphanChange(
            file_path=self.file_path,
            added_lines=orphan_added,
            removed_lines=orphan_removed,
            reason=self.reason,
        )


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
        secure_ast: bool = False,
        use_scip: bool = False,
    ) -> None:
        """
        Initialize the change mapper.

        Args:
            app_path: Path to the FastAPI application.
            config: Optional configuration object.
            app_variable: Name of the FastAPI app variable.
            use_cache: Whether to use cached analysis results (default True).
            secure_ast: Discover endpoints without importing application code.
            use_scip: Use SCIP rather than mypy for reverse dependency analysis.
        """
        self.app_path = app_path.resolve()
        self.config = config or Config()
        self.app_variable = app_variable
        self.use_cache = use_cache
        self.secure_ast = secure_ast
        self.use_scip = use_scip

        # These are lazily initialized
        self._extractor: FastAPIExtractor | SecureASTExtractor | None = None
        self._registry: EndpointRegistry | None = None
        self._mypy_analyzer: MypyAnalyzer | None = None
        self._scip_analyzer: SCIPAnalyzer | None = None

    @property
    def extractor(self) -> FastAPIExtractor | SecureASTExtractor:
        """Get the configured endpoint extractor, initializing if needed."""
        if self._extractor is None:
            extractor_class = SecureASTExtractor if self.secure_ast else FastAPIExtractor
            self._extractor = extractor_class(
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
    def scip_analyzer(self) -> SCIPAnalyzer:
        """Get the SCIP analyzer, initializing if needed."""
        if self._scip_analyzer is None:
            package_path = self.app_path.parent if self.app_path.is_file() else self.app_path
            self._scip_analyzer = SCIPAnalyzer(package_path, use_cache=self.use_cache)
        return self._scip_analyzer

    @property
    def mypy_analyzer(self) -> "MypyAnalyzer":
        """Get the mypy analyzer, initializing if needed (does NOT pre-analyze)."""
        if self._mypy_analyzer is None:
            if self.app_path.is_file():
                package_path = self.app_path.parent
            else:
                package_path = self.app_path

            effective_depth = (
                self.config.parser.max_depth if self.config.analysis.track_transitive else 1
            )
            self._mypy_analyzer = MypyAnalyzer(package_path, max_depth=effective_depth)
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
        deps = self.mypy_analyzer.get_endpoint_dependencies(endpoint)

        if not deps:
            return None

        # Check if the endpoint references the changed file at all
        file_path = str(diff_file.path)

        if not deps.references_file(file_path):
            return None

        # Check for line-level intersection
        changed_lines = set(added_lines) | set(removed_lines)

        # Also check context lines (for added lines that don't exist yet)
        context_lines: set[int] = set()
        for line in changed_lines:
            context_lines.update(range(max(1, line - 3), line + 4))

        overlap = deps.references_lines(file_path, changed_lines | context_lines)

        if overlap:
            # Filter to show most relevant lines
            direct_overlap = deps.references_lines(file_path, changed_lines)
            display_lines = direct_overlap if direct_overlap else overlap

            # Get call stacks for traceback-style output - all paths
            all_call_stacks: list[list[CallStackFrame]] = []
            raw_stacks = deps.get_call_stack(file_path)

            for raw_stack in raw_stacks:
                call_stack: list[CallStackFrame] = []

                # Add a marker frame at the beginning to show where this trace originates from
                call_stack.append(
                    CallStackFrame(
                        file_path=str(endpoint.handler.file_path or ""),
                        line_number=endpoint.handler.line_number,
                        function_name=f"[ENDPOINT] {endpoint.identifier}",
                        code_context=f"Handler: {endpoint.handler.name}",
                    )
                )

                # Add the actual call stack frames
                for frame in raw_stack:
                    call_stack.append(
                        CallStackFrame(
                            file_path=frame.file_path,
                            line_number=frame.line_number,
                            function_name=frame.function_name,
                            code_context=frame.code_context,
                        )
                    )

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
                            if sorted_lines[i] == sorted_lines[i - 1] + 1:
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
                                if sym_ref.file_path == file_path and sym_ref.contains_line(
                                    first_line
                                ):
                                    function_name = sym_ref.symbol_name
                                    break

                            # Try to get code context from the file
                            # For ranges, show all lines in the group
                            code_context = ""
                            if lines_list and 0 < first_line <= len(lines_list):
                                if len(group) > 1:
                                    # Multiple lines - show all of them
                                    context_code_lines = []
                                    for line_num in group:
                                        if 0 < line_num <= len(lines_list):
                                            context_code_lines.append(
                                                lines_list[line_num - 1].rstrip()
                                            )
                                    code_context = (
                                        f"[lines {first_line}-{last_line}]\n"
                                        + "\n".join(context_code_lines)
                                    )
                                else:
                                    # Single line
                                    code_context = lines_list[first_line - 1].rstrip()

                            call_stack.append(
                                CallStackFrame(
                                    file_path=file_path,
                                    line_number=first_line,
                                    function_name=function_name,
                                    code_context=code_context,
                                )
                            )

                # Add this completed call stack to the list
                all_call_stacks.append(call_stack)

            return AffectedEndpoint(
                endpoint=endpoint,
                confidence=ConfidenceLevel.MEDIUM,
                reason=f"Type analysis shows dependency on {diff_file.path} (lines {sorted(display_lines)[:5]}{'...' if len(display_lines) > 5 else ''})",
                dependency_chain=[endpoint.handler.module or "unknown", file_path],
                changed_files=[file_path],
                call_stacks=all_call_stacks,
            )

        return None

    def _analyze_diff_file(
        self,
        diff_file: DiffFile,
    ) -> tuple[list[AffectedEndpoint], set[int], set[int]]:
        """
        Analyze a single diff file and find affected endpoints.

        Uses mypy for type-aware dependency analysis.

        Args:
            diff_file: The parsed diff file.

        Returns:
            Tuple of (affected endpoints, processed added lines, processed removed lines).
            Processed lines are those that were matched to any endpoint.
        """
        affected: dict[tuple[str, str, int, str, str], _AffectedAccumulator] = {}
        processed_added_lines: set[int] = set()
        processed_removed_lines: set[int] = set()

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
                _merge_affected(affected, result)
                # Mark lines as processed
                handler = endpoint.handler
                handler_end = handler.end_line_number or handler.line_number + 50
                handler_lines = set(range(handler.line_number, handler_end + 1))
                processed_added_lines.update(ln for ln in added_lines if ln in handler_lines)
                processed_removed_lines.update(ln for ln in removed_lines if ln in handler_lines)

        # Use mypy for type-aware dependency analysis
        for endpoint in self.registry:
            result = self._check_mypy_dependency(endpoint, diff_file, added_lines, removed_lines)
            if result:
                _merge_affected(affected, result)
                # Mark lines as processed - get the actual lines that were referenced
                deps = self.mypy_analyzer.get_endpoint_dependencies(endpoint)
                if deps:
                    file_path = str(diff_file.path)
                    changed_lines = set(added_lines) | set(removed_lines)
                    context_lines: set[int] = set()
                    for line in changed_lines:
                        context_lines.update(range(max(1, line - 3), line + 4))
                    referenced = deps.references_lines(file_path, changed_lines | context_lines)
                    if referenced:
                        # Only mark the directly changed lines as processed
                        processed_added_lines.update(ln for ln in added_lines if ln in referenced)
                        processed_removed_lines.update(
                            ln for ln in removed_lines if ln in referenced
                        )

        return (
            [item.materialize() for item in affected.values()],
            processed_added_lines,
            processed_removed_lines,
        )

    def _analyze_with_scip(
        self,
        python_files: list[DiffFile],
        progress_callback: ProgressCallback | None,
    ) -> tuple[list[AffectedEndpoint], list[OrphanChange]]:
        """Map changed definitions through SCIP reverse impact to endpoint handlers."""
        if progress_callback:
            progress_callback(10, 100, "Indexing Python with SCIP...")
        self.scip_analyzer.ensure_index(force=not self.use_cache)
        affected: dict[tuple[str, str, int, str, str], _AffectedAccumulator] = {}
        orphan_evidence: dict[str, _OrphanAccumulator] = {}
        project_root = self.app_path.parent if self.app_path.is_file() else self.app_path

        for index, diff_file in enumerate(python_files):
            if progress_callback:
                progress_callback(
                    20 + int(70 * (index + 1) / max(len(python_files), 1)),
                    100,
                    f"Querying SCIP impact for {diff_file.path.name}...",
                )
            added_lines, removed_lines = DiffParser.get_changed_line_numbers(diff_file)
            if diff_file.change_type == ChangeType.DELETED or any(
                hunk.removed_lines and not hunk.added_lines for hunk in diff_file.hunks
            ):
                raise SCIPAnalyzerError(
                    f"SCIP post-change index cannot analyze deleted definitions in {diff_file.path}; "
                    "baseline dual-index support is required"
                )

            seed_evidence: dict[str, tuple[SCIPDefinition, set[int], set[int]]] = {}
            for hunk in diff_file.hunks:
                for line in hunk.added_lines:
                    for seed in self.scip_analyzer.definitions_at(diff_file.path, {line}):
                        existing_seed = seed_evidence.get(seed.symbol)
                        if existing_seed is None:
                            seed_evidence[seed.symbol] = (
                                seed,
                                {line},
                                set(hunk.removed_lines),
                            )
                        else:
                            existing_seed[1].add(line)
                            existing_seed[2].update(hunk.removed_lines)

            processed_added: set[int] = set()
            processed_removed: set[int] = set()
            for seed_value, seed_added, seed_removed in seed_evidence.values():
                seed = seed_value
                seed_reached_endpoint = False
                max_depth = (
                    self.config.parser.max_depth if self.config.analysis.track_transitive else 1
                )
                for reached in self.scip_analyzer.affected(seed, max_depth=max_depth):
                    definition = reached.definition
                    endpoints = self.registry.get_by_line_range(
                        project_root / definition.file_path,
                        definition.start_line,
                        definition.end_line,
                    )
                    for endpoint in endpoints:
                        seed_reached_endpoint = True
                        confidence = (
                            ConfidenceLevel.HIGH if reached.depth == 0 else ConfidenceLevel.MEDIUM
                        )
                        candidate = AffectedEndpoint(
                            endpoint=endpoint,
                            confidence=confidence,
                            reason=(
                                f"SCIP reverse impact from {seed.short_name} "
                                f"to {definition.short_name} at depth {reached.depth}"
                            ),
                            dependency_chain=[seed.symbol, definition.symbol],
                            changed_files=[str(diff_file.path)],
                        )
                        _merge_affected(affected, candidate)
                if seed_reached_endpoint:
                    processed_added.update(seed_added)
                    processed_removed.update(seed_removed)

            orphan_key = _normalized_diff_path(diff_file.path)
            evidence = orphan_evidence.setdefault(
                orphan_key,
                _OrphanAccumulator(
                    file_path=str(diff_file.path),
                    reason=("Changed lines did not resolve through SCIP to a registered endpoint"),
                ),
            )
            evidence.added.update(added_lines)
            evidence.removed.update(removed_lines)
            evidence.processed_added.update(processed_added)
            evidence.processed_removed.update(processed_removed)

        orphan_changes = [
            orphan
            for evidence in orphan_evidence.values()
            if (orphan := evidence.materialize()) is not None
        ]
        return [item.materialize() for item in affected.values()], orphan_changes

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

        if self.use_scip:
            report_progress(10, 100, f"Analyzing {total_endpoints} endpoints (SCIP)...")
            scip_affected, scip_orphans = self._analyze_with_scip(python_files, progress_callback)
            threshold = self.config.analysis.confidence_threshold
            filtered = [
                item for item in scip_affected if _CONFIDENCE_SCORE[item.confidence] >= threshold
            ]
            duration_ms = (time.time() - start_time) * 1000
            report_progress(100, 100, "Complete!")
            return AnalysisReport(
                app_path=str(self.app_path),
                diff_source=diff_source_str,
                total_endpoints=total_endpoints,
                affected_endpoints=filtered,
                orphan_changes=scip_orphans,
                total_files_changed=len(diff_files),
                python_files_changed=len(python_files),
                analysis_duration_ms=duration_ms,
                errors=errors,
                warnings=warnings,
            )

        # Pre-analyze endpoints with mypy
        report_progress(10, 100, f"Analyzing {total_endpoints} endpoints (mypy)...")
        self._preanalyze_mypy(progress_callback)

        # Analyze each Python file
        report_progress(70, 100, f"Checking {len(python_files)} changed files...")
        all_affected: dict[tuple[str, str, int, str, str], _AffectedAccumulator] = {}
        orphan_evidence: dict[str, _OrphanAccumulator] = {}

        for i, diff_file in enumerate(python_files):
            try:
                report_progress(
                    70 + int(20 * (i + 1) / max(len(python_files), 1)),
                    100,
                    f"Analyzing {diff_file.path.name}...",
                )
                file_affected, processed_added, processed_removed = self._analyze_diff_file(
                    diff_file
                )
                for candidate in file_affected:
                    _merge_affected(all_affected, candidate)

                added_lines, removed_lines = DiffParser.get_changed_line_numbers(diff_file)
                orphan_key = _normalized_diff_path(diff_file.path)
                evidence = orphan_evidence.setdefault(
                    orphan_key,
                    _OrphanAccumulator(
                        file_path=str(diff_file.path),
                        reason=(
                            "Code changes not related to any endpoint "
                            "(possibly unused, unrelated, or has type issues)"
                        ),
                    ),
                )
                evidence.added.update(added_lines)
                evidence.removed.update(removed_lines)
                evidence.processed_added.update(processed_added)
                evidence.processed_removed.update(processed_removed)
            except Exception as e:
                warnings.append(f"Error analyzing {diff_file.path}: {e}")

        # Filter by confidence threshold
        report_progress(95, 100, "Filtering results...")
        threshold = self.config.analysis.confidence_threshold
        materialized = [item.materialize() for item in all_affected.values()]
        filtered_affected = [
            item for item in materialized if _CONFIDENCE_SCORE[item.confidence] >= threshold
        ]
        orphan_changes = [
            orphan
            for evidence in orphan_evidence.values()
            if (orphan := evidence.materialize()) is not None
        ]

        # Calculate duration
        duration_ms = (time.time() - start_time) * 1000
        report_progress(100, 100, "Complete!")

        return AnalysisReport(
            app_path=str(self.app_path),
            diff_source=diff_source_str,
            total_endpoints=len(self.registry),
            affected_endpoints=filtered_affected,
            orphan_changes=orphan_changes,
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
                    self.mypy_analyzer.get_endpoint_dependencies(endpoint) is not None
                    for endpoint in endpoints
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
                    f"Analyzing endpoint {i + 1}/{total}: {endpoint.path}",
                )
            if self.mypy_analyzer.get_endpoint_dependencies(endpoint) is None:
                self.mypy_analyzer.analyze_endpoint(endpoint)

        # Save cache after analysis
        if self.use_cache:
            self.mypy_analyzer._save_cache()

    def get_endpoints(self) -> list[Endpoint]:
        """Get all endpoints in the application."""
        return self.registry.get_all()

    def clear_cache(self) -> None:
        """Clear or bypass cached analysis results for the selected backend."""
        if self.use_scip:
            # scip-query owns its cache; force a deterministic reindex for this run.
            self.use_cache = False
            if self._scip_analyzer is not None:
                self._scip_analyzer.use_cache = False
            return
        if self._mypy_analyzer is not None:
            self._mypy_analyzer.clear_cache()
        else:
            # Initialize and clear the cache file even if analyzer not loaded
            if self.app_path.is_file():
                package_path = self.app_path.parent
            else:
                package_path = self.app_path
            temp_analyzer = MypyAnalyzer(package_path)
            temp_analyzer.clear_cache()
