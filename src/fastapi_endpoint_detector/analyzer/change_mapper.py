"""
Change mapper - maps code changes to affected endpoints.

This module combines diff parsing, endpoint registry, and mypy-based
dependency analysis to determine which endpoints are affected by code changes.

Uses mypy for type-aware, precise dependency tracking.
"""

from __future__ import annotations

import heapq
import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi_endpoint_detector.analyzer.effect_analyzer import EffectAnalyzer
from fastapi_endpoint_detector.analyzer.effect_contract_auditor import (
    audit_effect_contracts,
    build_audit_endpoint,
)
from fastapi_endpoint_detector.analyzer.endpoint_registry import EndpointRegistry
from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.analyzer.resource_coupling import build_resource_coupling_graph
from fastapi_endpoint_detector.analyzer.scip_analyzer import (
    SCIPAnalyzer,
    SCIPAnalyzerError,
    SCIPDefinition,
    SCIPReachedDefinition,
)
from fastapi_endpoint_detector.analyzer.sql_transaction import (
    build_sql_transaction_diagnostics,
)
from fastapi_endpoint_detector.analyzer.sql_transaction_paths import (
    build_sql_transaction_path_diagnostics,
)
from fastapi_endpoint_detector.config import Config
from fastapi_endpoint_detector.models.endpoint import (
    Endpoint,
    EndpointDiscoveryStatus,
    EndpointInventory,
)
from fastapi_endpoint_detector.models.report import (
    AffectedEndpoint,
    AnalysisReport,
    CallStackFrame,
    ChangeEffectKind,
    CodeReference,
    ConfidenceLevel,
    ContractEffectEvidence,
    EffectDisposition,
    EffectEvidence,
    EvidenceProducer,
    EvidenceStatus,
    ImpactChannel,
    OrphanChange,
)
from fastapi_endpoint_detector.models.resource_coupling import (
    ResourceCouplingCandidateEvidence,
    ResourceCouplingEdge,
    ResourceCouplingError,
)
from fastapi_endpoint_detector.parser.custom_surface_extractor import (
    CustomSurfaceExtractor,
    merge_surface_inventory,
)
from fastapi_endpoint_detector.parser.diff_parser import DiffParser
from fastapi_endpoint_detector.parser.fastapi_extractor import FastAPIExtractor
from fastapi_endpoint_detector.parser.secure_ast_extractor import SecureASTExtractor

if TYPE_CHECKING:
    from fastapi_endpoint_detector.models.diff import DiffFile
    from fastapi_endpoint_detector.models.effect_contract import LoadedEffectContracts
    from fastapi_endpoint_detector.models.effect_contract_audit import (
        EffectContractAudit,
        EffectContractAuditOccurrence,
    )
    from fastapi_endpoint_detector.models.resource_coupling import (
        LoadedResourceCoupling,
        ResourceCouplingGraph,
    )
    from fastapi_endpoint_detector.models.sql_transaction import (
        SQLTransactionPathReport,
        SQLTransactionReport,
    )
    from fastapi_endpoint_detector.models.surface_contract import LoadedSurfaceContracts

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


def _stack_key(
    stack: list[CallStackFrame],
) -> tuple[tuple[str, int, str, str | None, str | None, int | None], ...]:
    return tuple(
        (
            frame.file_path,
            frame.line_number,
            frame.function_name,
            frame.code_context,
            frame.caller_file_path,
            frame.caller_line_number,
        )
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
    effect_evidence: list[EffectEvidence] = field(default_factory=list)

    @classmethod
    def from_candidate(cls, candidate: AffectedEndpoint) -> _AffectedAccumulator:
        accumulator = cls(
            endpoint=candidate.endpoint,
            confidence=candidate.confidence,
            reason=candidate.reason,
            dependency_chain=list(candidate.dependency_chain),
        )
        accumulator.merge(candidate)
        return accumulator

    def merge(self, candidate: AffectedEndpoint) -> None:
        if (
            self.endpoint.discovery_status == EndpointDiscoveryStatus.CONDITIONAL
            and candidate.endpoint.discovery_status == EndpointDiscoveryStatus.ESTABLISHED
        ):
            self.endpoint = candidate.endpoint
        elif (
            self.endpoint.discovery_status == EndpointDiscoveryStatus.CONDITIONAL
            and candidate.endpoint.discovery_status == EndpointDiscoveryStatus.CONDITIONAL
        ):
            conditions = {
                (
                    str(condition.source_path),
                    condition.source_line,
                    condition.reason,
                ): condition
                for condition in (
                    *self.endpoint.discovery_conditions,
                    *candidate.endpoint.discovery_conditions,
                )
            }
            self.endpoint = self.endpoint.model_copy(
                update={
                    "discovery_conditions": tuple(conditions[key] for key in sorted(conditions))
                }
            )
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
        for evidence in candidate.effect_evidence:
            if evidence not in self.effect_evidence:
                self.effect_evidence.append(evidence)

    def materialize(self) -> AffectedEndpoint:
        return AffectedEndpoint(
            endpoint=self.endpoint,
            confidence=self.confidence,
            reason=self.reason,
            dependency_chain=self.dependency_chain,
            dependency_chains=self.dependency_chains,
            changed_files=self.changed_files,
            call_stacks=self.call_stacks,
            effect_evidence=self.effect_evidence,
        )


def _merge_affected(
    accumulated: dict[tuple[str, str, int, str, str], _AffectedAccumulator],
    candidate: AffectedEndpoint,
) -> None:
    if (
        candidate.endpoint.discovery_status == EndpointDiscoveryStatus.CONDITIONAL
        and candidate.confidence != ConfidenceLevel.LOW
    ):
        candidate = candidate.model_copy(update={"confidence": ConfidenceLevel.LOW})
    key = _endpoint_result_key(candidate.endpoint)
    existing = accumulated.get(key)
    if existing is None:
        accumulated[key] = _AffectedAccumulator.from_candidate(candidate)
    else:
        existing.merge(candidate)


def _scip_confidence(seed: SCIPDefinition, depth: int) -> ConfidenceLevel:
    if depth == 0 and "(" in seed.short_name:
        return ConfidenceLevel.HIGH
    # A SCIP reverse-reference path establishes call/reference reachability, not
    # that the changed value is returned, persisted, emitted, or otherwise
    # observed by the endpoint. Keep every transitive route as a candidate, but
    # require independent effect/data-flow corroboration before promotion.
    return ConfidenceLevel.LOW


@dataclass(frozen=True)
class _ExpandedSCIPDefinition:
    definition: SCIPDefinition
    depth: int
    dependency_chain: tuple[str, ...]


def _scip_definition_key(definition: SCIPDefinition) -> tuple[str, str, str, int, int]:
    return (
        definition.symbol,
        definition.short_name,
        definition.file_path.as_posix(),
        definition.start_line,
        definition.end_line,
    )


def _expanded_scip_affected(
    analyzer: SCIPAnalyzer,
    seed: SCIPDefinition,
    max_depth: int,
    warnings: list[str] | None = None,
) -> tuple[_ExpandedSCIPDefinition, ...]:
    """Close native SCIP reachability over explicit override-to-base bridges."""
    initial = analyzer.affected(seed, max_depth=max_depth)
    best_depth_by_symbol: dict[str, int] = {}
    definition_by_symbol: dict[str, SCIPDefinition] = {}
    chain_by_symbol: dict[str, tuple[str, ...]] = {}
    worklist: list[tuple[int, str, tuple[str, ...]]] = []

    def record(definition: SCIPDefinition, depth: int, chain: tuple[str, ...]) -> None:
        symbol = definition.symbol
        previous_depth = best_depth_by_symbol.get(symbol)
        previous_definition = definition_by_symbol.get(symbol)
        previous_chain = chain_by_symbol.get(symbol)
        improves = previous_depth is None or depth < previous_depth
        if (
            depth == previous_depth
            and previous_definition is not None
            and previous_chain is not None
        ):
            improves = (chain, _scip_definition_key(definition)) < (
                previous_chain,
                _scip_definition_key(previous_definition),
            )
        if not improves:
            return
        best_depth_by_symbol[symbol] = depth
        definition_by_symbol[symbol] = definition
        chain_by_symbol[symbol] = chain
        heapq.heappush(worklist, (depth, symbol, chain))

    for reached in initial:
        native_chain: tuple[str, ...] = (seed.symbol,)
        if reached.definition.symbol != seed.symbol:
            native_chain = (*native_chain, reached.definition.symbol)
        record(reached.definition, reached.depth, native_chain)

    base_resolver = getattr(analyzer, "base_method_definitions", None)
    if not callable(base_resolver):
        return tuple(
            _ExpandedSCIPDefinition(
                definition_by_symbol[symbol],
                best_depth_by_symbol[symbol],
                chain_by_symbol[symbol],
            )
            for symbol in sorted(
                best_depth_by_symbol,
                key=lambda item: (best_depth_by_symbol[item], item),
            )
        )

    affected_cache: dict[
        tuple[str, int], tuple[SCIPReachedDefinition, ...] | SCIPAnalyzerError
    ] = {}
    while worklist:
        depth, symbol, current_chain = heapq.heappop(worklist)
        if depth != best_depth_by_symbol[symbol] or current_chain != chain_by_symbol[symbol]:
            continue
        if depth >= max_depth:
            continue
        definition = definition_by_symbol[symbol]
        try:
            bases = base_resolver(definition)
        except SCIPAnalyzerError as error:
            if warnings is not None:
                warnings.append(
                    f"SCIP override bridge from {definition.short_name} failed: {error}"
                )
            continue
        unique_bases: dict[str, SCIPDefinition] = {}
        for candidate in bases:
            existing = unique_bases.get(candidate.symbol)
            if existing is None or _scip_definition_key(candidate) < _scip_definition_key(existing):
                unique_bases[candidate.symbol] = candidate
        for base in sorted(unique_bases.values(), key=_scip_definition_key):
            remaining = max_depth - depth - 1
            cache_key = (base.symbol, remaining)
            base_affected = affected_cache.get(cache_key)
            if base_affected is None:
                try:
                    base_affected = analyzer.affected(base, max_depth=remaining)
                except SCIPAnalyzerError as error:
                    base_affected = error
                    if warnings is not None:
                        warnings.append(
                            f"SCIP override bridge from {definition.short_name} "
                            f"to {base.short_name} failed: {error}"
                        )
                affected_cache[cache_key] = base_affected
            if isinstance(base_affected, SCIPAnalyzerError):
                continue
            bridge_chain = (*current_chain, base.symbol)
            for reached in base_affected:
                adjusted_depth = depth + 1 + reached.depth
                if adjusted_depth > max_depth:
                    continue
                adjusted_chain: tuple[str, ...] = bridge_chain
                if reached.definition.symbol != base.symbol:
                    adjusted_chain = (*adjusted_chain, reached.definition.symbol)
                record(reached.definition, adjusted_depth, adjusted_chain)

    return tuple(
        _ExpandedSCIPDefinition(
            definition_by_symbol[symbol],
            best_depth_by_symbol[symbol],
            chain_by_symbol[symbol],
        )
        for symbol in sorted(
            best_depth_by_symbol,
            key=lambda item: (best_depth_by_symbol[item], item),
        )
    )


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
        app_entry: str | None = None,
        use_cache: bool = True,
        secure_ast: bool = False,
        use_scip: bool = False,
        baseline_app_path: Path | None = None,
        bootstrap_entry: str | None = None,
    ) -> None:
        """
        Initialize the change mapper.

        Args:
            app_path: Path to the FastAPI application.
            config: Optional configuration object.
            app_variable: Name of the FastAPI app variable.
            app_entry: Exact secure-AST MODULE:SYMBOL root selection.
            use_cache: Whether to use cached analysis results (default True).
            secure_ast: Discover endpoints without importing application code.
            use_scip: Use SCIP rather than mypy for reverse dependency analysis.
            baseline_app_path: Explicit baseline snapshot used for removed SCIP lines.
            bootstrap_entry: Exact secure-AST MODULE:FUNCTION registration seed.
        """
        self.app_path = app_path.resolve()
        self.config = config or Config()
        self._effect_contracts: LoadedEffectContracts | None = (
            self.config.load_effect_contract_snapshot()
        )
        self._resource_coupling: LoadedResourceCoupling | None = (
            self.config.load_resource_coupling_snapshot()
        )
        self._surface_contracts: LoadedSurfaceContracts | None = (
            self.config.load_surface_contract_snapshot()
        )
        if self._surface_contracts is not None and not secure_ast:
            raise ChangeMapperError("custom surface contracts require secure_ast=True")
        if self._effect_contracts is not None:
            if not secure_ast:
                raise ChangeMapperError("effect contract evidence requires secure_ast=True")
            if use_scip:
                raise ChangeMapperError("effect contract evidence requires the mypy backend")
            if baseline_app_path is not None:
                raise ChangeMapperError("effect contract evidence is target-only")
        self.app_variable = app_variable
        self.app_entry = app_entry
        self.bootstrap_entry = bootstrap_entry
        self.use_cache = use_cache
        self.secure_ast = secure_ast
        self.use_scip = use_scip
        if app_entry is not None and not secure_ast:
            raise ChangeMapperError("app_entry requires secure_ast=True")
        if bootstrap_entry is not None and not secure_ast:
            raise ChangeMapperError("bootstrap_entry requires secure_ast=True")
        if baseline_app_path is not None and not use_scip:
            raise ChangeMapperError("baseline_app_path is valid only with use_scip=True")
        self.baseline_app_path = baseline_app_path.resolve() if baseline_app_path else None
        target_project_root = self.app_path.parent if self.app_path.is_file() else self.app_path
        self.target_project_root = target_project_root
        baseline_project_root = (
            self.baseline_app_path.parent
            if self.baseline_app_path is not None and self.baseline_app_path.is_file()
            else self.baseline_app_path
        )
        if baseline_project_root == target_project_root:
            raise ChangeMapperError(
                "baseline_app_path project root must differ from the target app_path root"
            )

        # These are lazily initialized
        self._extractor: FastAPIExtractor | SecureASTExtractor | None = None
        self._registry: EndpointRegistry | None = None
        self._inventory: EndpointInventory | None = None
        self._effect_contract_audit: EffectContractAudit | None = None
        self._resource_coupling_graph: ResourceCouplingGraph | None = None
        self._sql_transaction_report: SQLTransactionReport | None = None
        self._sql_transaction_path_report: SQLTransactionPathReport | None = None
        self._mypy_analyzer: MypyAnalyzer | None = None
        self._effect_analyzer = EffectAnalyzer(target_project_root)
        self._scip_analyzer: SCIPAnalyzer | None = None
        self._baseline_registry: EndpointRegistry | None = None
        self._baseline_scip_analyzer: SCIPAnalyzer | None = None

    @property
    def extractor(self) -> FastAPIExtractor | SecureASTExtractor:
        """Get the configured endpoint extractor, initializing if needed."""
        if self._extractor is None:
            if self.secure_ast:
                self._extractor = SecureASTExtractor(
                    app_path=self.app_path,
                    app_variable=self.app_variable,
                    app_entry=self.app_entry,
                    bootstrap_entry=self.bootstrap_entry,
                )
            else:
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
            if isinstance(self.extractor, SecureASTExtractor):
                native_inventory = self.extractor.extract_inventory()
                self._inventory = self._merge_surface_inventory(self.app_path, native_inventory)
                endpoints = self._inventory.endpoints
            else:
                endpoints = self.extractor.extract_endpoints()
            self._registry.register_many(endpoints)
        return self._registry

    def _merge_surface_inventory(
        self,
        app_path: Path,
        native: EndpointInventory,
    ) -> EndpointInventory:
        """Merge custom surfaces before registry population and preserve limitations."""
        if self._surface_contracts is None:
            return native
        custom = CustomSurfaceExtractor(
            app_path,
            self._surface_contracts,
            bootstrap_entry=self.bootstrap_entry,
        ).extract_inventory()
        return merge_surface_inventory(native, custom)

    @property
    def inventory(self) -> EndpointInventory:
        """Return the exact execution-free inventory used to populate the registry."""
        _registry = self.registry
        if self._inventory is None:
            raise ChangeMapperError("endpoint inventory is unavailable outside secure AST mode")
        return self._inventory

    @property
    def scip_analyzer(self) -> SCIPAnalyzer:
        """Get the SCIP analyzer, initializing if needed."""
        if self._scip_analyzer is None:
            package_path = self.app_path.parent if self.app_path.is_file() else self.app_path
            self._scip_analyzer = SCIPAnalyzer(package_path, use_cache=self.use_cache)
        return self._scip_analyzer

    @property
    def baseline_registry(self) -> EndpointRegistry:
        """Securely discover endpoints from the explicit baseline snapshot."""
        if self.baseline_app_path is None:
            raise SCIPAnalyzerError("Removed Python lines require --baseline-app with --scip")
        if self._baseline_registry is None:
            extractor = SecureASTExtractor(
                app_path=self.baseline_app_path,
                app_variable=self.app_variable,
                app_entry=self.app_entry,
                bootstrap_entry=self.bootstrap_entry,
            )
            self._baseline_registry = EndpointRegistry()
            native = extractor.extract_inventory()
            combined = self._merge_surface_inventory(self.baseline_app_path, native)
            self._baseline_registry.register_many(combined.endpoints)
        return self._baseline_registry

    @property
    def baseline_scip_analyzer(self) -> SCIPAnalyzer:
        """Get the SCIP analyzer for the explicit baseline snapshot."""
        if self.baseline_app_path is None:
            raise SCIPAnalyzerError("Removed Python lines require --baseline-app with --scip")
        if self._baseline_scip_analyzer is None:
            package_path = (
                self.baseline_app_path.parent
                if self.baseline_app_path.is_file()
                else self.baseline_app_path
            )
            self._baseline_scip_analyzer = SCIPAnalyzer(package_path, use_cache=self.use_cache)
        return self._baseline_scip_analyzer

    @property
    def mypy_analyzer(self) -> MypyAnalyzer:
        """Get the mypy analyzer, initializing if needed (does NOT pre-analyze)."""
        if self._mypy_analyzer is None:
            package_path = self.app_path.parent if self.app_path.is_file() else self.app_path

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
                effect_evidence=[
                    EffectEvidence(
                        producer=EvidenceProducer.DIRECT,
                        status=EvidenceStatus.ESTABLISHED,
                        effect=ChangeEffectKind.HANDLER_IMPLEMENTATION,
                        channel=ImpactChannel.UNKNOWN,
                        disposition=EffectDisposition.INTERNAL_EFFECT,
                        summary=(
                            "Changed source overlaps the registered endpoint handler; "
                            "the specific observation channel is not yet classified."
                        ),
                        changed_location=CodeReference(
                            file_path=str(diff_file.path),
                            line_number=min(all_changed & handler_lines),
                            symbol=handler.name,
                        ),
                    )
                ],
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

        file_path = str(diff_file.path)
        changed_lines = set(added_lines) | set(removed_lines)

        # Dependency ranges already cover complete callable definitions. Expanding
        # by nearby physical lines lets a new sibling definition inherit evidence
        # from the preceding unchanged function and creates massive false fanout.
        overlap = deps.references_lines(file_path, changed_lines)

        if overlap:
            display_lines = overlap

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
                            caller_file_path=frame.caller_file_path,
                            caller_line_number=frame.caller_line_number,
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
                            with file_path_obj.open(encoding="utf-8") as f:
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

            effect_result = self._effect_analyzer.analyze(
                file_path,
                set(display_lines),
                all_call_stacks,
            )
            low_only_points_to = deps.references_lines_low_only(file_path, changed_lines)
            confidence = (
                ConfidenceLevel.LOW
                if low_only_points_to
                else effect_result.confidence
                if effect_result
                else ConfidenceLevel.MEDIUM
            )
            effect_summary = (
                f"; effect analysis: {effect_result.evidence[0].summary}" if effect_result else ""
            )
            return AffectedEndpoint(
                endpoint=endpoint,
                confidence=confidence,
                reason=(
                    f"{'LOW finite points-to' if low_only_points_to else 'Type analysis'} "
                    f"shows dependency on {diff_file.path} "
                    f"(lines {sorted(display_lines)[:5]}"
                    f"{'...' if len(display_lines) > 5 else ''}){effect_summary}"
                ),
                dependency_chain=[endpoint.handler.module or "unknown", file_path],
                changed_files=[file_path],
                call_stacks=all_call_stacks,
                effect_evidence=[
                    EffectEvidence(
                        producer=EvidenceProducer.MYPY,
                        status=EvidenceStatus.REACHABILITY_ONLY,
                        effect=ChangeEffectKind.UNKNOWN,
                        channel=ImpactChannel.UNKNOWN,
                        disposition=EffectDisposition.REACHABILITY_ONLY,
                        summary=(
                            "Mypy resolves a typed call path; effect evidence is "
                            "reported separately."
                        ),
                        changed_location=CodeReference(
                            file_path=file_path,
                            line_number=min(display_lines),
                        ),
                        limitations=[
                            "Call reachability alone does not establish an externally "
                            "observable effect."
                        ],
                    ),
                    *(list(effect_result.evidence) if effect_result else []),
                ],
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
                    referenced = deps.references_lines(file_path, changed_lines)
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
        warnings: list[str],
        progress_callback: ProgressCallback | None,
    ) -> tuple[list[AffectedEndpoint], list[OrphanChange]]:
        """Map target additions and baseline removals through separate SCIP indexes."""
        has_removed = any(
            (diff_file.source_path or diff_file.path).suffix == ".py"
            and bool(DiffParser.get_changed_line_numbers(diff_file)[1])
            for diff_file in python_files
        )
        if has_removed and self.baseline_app_path is None:
            raise SCIPAnalyzerError(
                "SCIP analysis of removed Python lines requires an explicit --baseline-app snapshot"
            )
        if progress_callback:
            progress_callback(10, 100, "Indexing target Python with SCIP...")
        self.scip_analyzer.ensure_index(force=not self.use_cache)
        if has_removed:
            self.baseline_scip_analyzer.ensure_index(force=not self.use_cache)

        affected: dict[tuple[str, str, int, str, str], _AffectedAccumulator] = {}
        orphan_evidence: dict[str, _OrphanAccumulator] = {}
        target_root = self.app_path.parent if self.app_path.is_file() else self.app_path
        baseline_root = (
            self.baseline_app_path.parent
            if self.baseline_app_path is not None and self.baseline_app_path.is_file()
            else self.baseline_app_path
        )
        max_depth = self.config.parser.max_depth if self.config.analysis.track_transitive else 1

        def target_equivalent(endpoint: Endpoint) -> Endpoint:
            # Public route identity survives ordinary handler/module renames. Use
            # the target occurrence when it is unambiguous; otherwise preserve
            # baseline evidence rather than guessing among duplicate routes.
            matches = [
                candidate
                for candidate in self.registry
                if candidate.identifier == endpoint.identifier
            ]
            return matches[0] if len(matches) == 1 else endpoint

        def analyze_side(
            analyzer: SCIPAnalyzer,
            registry: EndpointRegistry,
            root: Path,
            file_path: Path,
            lines: list[int],
            side: str,
        ) -> set[int]:
            seeds: dict[str, tuple[SCIPDefinition, set[int]]] = {}
            for line in lines:
                for seed in analyzer.definitions_at(file_path, {line}):
                    existing = seeds.get(seed.symbol)
                    if existing is None:
                        seeds[seed.symbol] = (seed, {line})
                    else:
                        existing[1].add(line)
            processed: set[int] = set()

            for seed, seed_lines in seeds.values():
                reached_endpoint = False
                try:
                    reached_definitions = _expanded_scip_affected(
                        analyzer, seed, max_depth, warnings
                    )
                except SCIPAnalyzerError as error:
                    warnings.append(
                        f"SCIP skipped unresolved {side} seed {seed.short_name}: {error}"
                    )
                    continue
                for reached in reached_definitions:
                    definition = reached.definition
                    endpoints = registry.get_by_line_range(
                        root / definition.file_path,
                        definition.start_line,
                        definition.end_line,
                    )
                    for discovered in endpoints:
                        reached_endpoint = True
                        endpoint = (
                            target_equivalent(discovered) if side == "baseline" else discovered
                        )
                        confidence = _scip_confidence(seed, reached.depth)
                        _merge_affected(
                            affected,
                            AffectedEndpoint(
                                endpoint=endpoint,
                                confidence=confidence,
                                reason=(
                                    f"SCIP {side} reverse impact from {seed.short_name} "
                                    f"to {definition.short_name} at depth {reached.depth}"
                                ),
                                dependency_chain=list(reached.dependency_chain),
                                changed_files=[str(file_path)],
                                effect_evidence=[
                                    EffectEvidence(
                                        producer=EvidenceProducer.SCIP,
                                        status=EvidenceStatus.REACHABILITY_ONLY,
                                        effect=ChangeEffectKind.UNKNOWN,
                                        channel=ImpactChannel.UNKNOWN,
                                        disposition=EffectDisposition.REACHABILITY_ONLY,
                                        summary=(
                                            f"SCIP resolves a {side} reverse-reference path "
                                            f"at depth {reached.depth}."
                                        ),
                                        changed_location=CodeReference(
                                            file_path=str(file_path),
                                            line_number=min(seed_lines),
                                            symbol=seed.short_name,
                                        ),
                                        limitations=[
                                            "Reference reachability does not establish "
                                            "runtime data observation."
                                        ],
                                    )
                                ],
                            ),
                        )
                if reached_endpoint:
                    processed.update(seed_lines)
            return processed

        for index, diff_file in enumerate(python_files):
            if progress_callback:
                progress_callback(
                    20 + int(70 * (index + 1) / max(len(python_files), 1)),
                    100,
                    f"Querying SCIP impact for {diff_file.path.name}...",
                )
            added_lines, removed_lines = DiffParser.get_changed_line_numbers(diff_file)
            processed_added: set[int] = set()
            if diff_file.path.suffix == ".py" and added_lines:
                processed_added = analyze_side(
                    self.scip_analyzer,
                    self.registry,
                    target_root,
                    diff_file.path,
                    added_lines,
                    "target",
                )
            processed_removed: set[int] = set()
            source_path = diff_file.source_path or diff_file.path
            if removed_lines and source_path.suffix == ".py":
                assert baseline_root is not None
                processed_removed = analyze_side(
                    self.baseline_scip_analyzer,
                    self.baseline_registry,
                    baseline_root,
                    source_path,
                    removed_lines,
                    "baseline",
                )

            reason = "Changed lines did not resolve through SCIP to a registered endpoint"
            if diff_file.path.suffix == ".py" and added_lines:
                target_key = _normalized_diff_path(diff_file.path)
                target_evidence = orphan_evidence.setdefault(
                    target_key,
                    _OrphanAccumulator(file_path=str(diff_file.path), reason=reason),
                )
                target_evidence.added.update(added_lines)
                target_evidence.processed_added.update(processed_added)
            if source_path.suffix == ".py" and removed_lines:
                source_key = _normalized_diff_path(source_path)
                source_evidence = orphan_evidence.setdefault(
                    source_key,
                    _OrphanAccumulator(file_path=str(source_path), reason=reason),
                )
                source_evidence.removed.update(removed_lines)
                source_evidence.processed_removed.update(processed_removed)

        orphan_changes = [
            orphan
            for evidence in orphan_evidence.values()
            if (orphan := evidence.materialize()) is not None
        ]
        return [item.materialize() for item in affected.values()], orphan_changes

    def _build_effect_contract_audit(self) -> EffectContractAudit | None:
        """Audit configured contracts over the exact pre-analyzed target inventory."""
        if self._effect_contracts is None:
            return None
        rows = []
        for endpoint in self.inventory.endpoints:
            dependencies = self.mypy_analyzer.get_endpoint_dependencies(endpoint)
            if dependencies is None:
                raise ChangeMapperError(
                    "effect contract audit requires complete typed endpoint analysis"
                )
            rows.append((endpoint, dependencies.get_resolved_call_sites()))
        effective_depth = (
            self.config.parser.max_depth if self.config.analysis.track_transitive else 1
        )
        source_root = self.app_path.parent if self.app_path.is_file() else self.app_path
        return audit_effect_contracts(
            self._effect_contracts,
            source_root=source_root,
            inventory=self.inventory,
            endpoint_call_sites=rows,
            track_transitive=self.config.analysis.track_transitive,
            max_depth=effective_depth,
            cache_enabled=self.use_cache,
            resolver_versions=(f"mypy@{self.mypy_analyzer.resolver_version}",),
        )

    def _attach_contract_evidence(
        self,
        candidates: list[AffectedEndpoint],
        audit: EffectContractAudit | None,
    ) -> list[AffectedEndpoint]:
        """Decorate existing candidates without changing reachability or confidence."""
        if audit is None or self._effect_contracts is None:
            return candidates
        source_root = self.app_path.parent if self.app_path.is_file() else self.app_path
        contract_by_id = {
            contract.id: contract for contract in self._effect_contracts.document.contracts
        }
        matched_by_endpoint: dict[str, list[EffectContractAuditOccurrence]] = {}
        for occurrence in audit.occurrences:
            if occurrence.contract_id is None:
                continue
            for endpoint in occurrence.endpoints:
                matched_by_endpoint.setdefault(endpoint.id, []).append(occurrence)
        enriched: list[AffectedEndpoint] = []
        for candidate in candidates:
            endpoint_id = build_audit_endpoint(candidate.endpoint, source_root).id
            evidence: list[ContractEffectEvidence] = []
            for occurrence in matched_by_endpoint.get(endpoint_id, []):
                contract_id = occurrence.contract_id
                if contract_id is None:
                    continue
                contract = contract_by_id[contract_id]
                resource_identity = occurrence.resource_identity
                if resource_identity is None:
                    continue
                evidence.append(
                    ContractEffectEvidence(
                        contract=contract,
                        contract_hash=self._effect_contracts.contract_hashes[contract_id],
                        config_hash=audit.provenance.config_hash,
                        preset_hash=audit.provenance.preset_hash,
                        raw_hash=audit.provenance.raw_hash,
                        audit_hash=audit.provenance.audit_hash,
                        occurrence_corpus_hash=audit.provenance.occurrence_corpus_hash,
                        contract_source_path=audit.provenance.contract_source_path,
                        occurrence_id=occurrence.id,
                        endpoint_audit_id=endpoint_id,
                        call_location=CodeReference(
                            file_path=occurrence.file_path,
                            line_number=occurrence.line,
                            end_line_number=occurrence.end_line,
                            symbol=occurrence.canonical_symbol,
                        ),
                        resolver=occurrence.resolver,
                        resolver_version=occurrence.resolver_version,
                        matcher=audit.provenance.matcher,
                        resource_identity_status=resource_identity.status,
                        resource_identity=resource_identity,
                        limitations=(
                            "The contract declares call semantics; changed-code to call flow "
                            "is not established.",
                            "Resource identities are hashed finite source evidence; receiver "
                            "origins and dynamic arguments remain unavailable.",
                            "Contract evidence does not change candidate reachability "
                            "or confidence.",
                        ),
                    )
                )
            enriched.append(
                candidate.model_copy(
                    update={"contract_evidence": tuple(evidence)},
                )
            )
        return enriched

    def _expand_resource_coupling_candidates(
        self,
        candidates: list[AffectedEndpoint],
        diff_files: list[DiffFile],
    ) -> list[AffectedEndpoint]:
        """Add atomic LOW-only targets from exact added producer callsites."""
        graph = self._resource_coupling_graph
        configured = self._resource_coupling
        audit = self._effect_contract_audit
        if (
            graph is None
            or configured is None
            or audit is None
            or graph.mode != "changed_callsite_candidates"
        ):
            return candidates
        source_root = self.app_path.parent if self.app_path.is_file() else self.app_path
        added_by_path: dict[str, set[int]] = {}
        for diff_file in diff_files:
            added_lines, _removed_lines = DiffParser.get_changed_line_numbers(diff_file)
            if not added_lines:
                continue
            path = diff_file.path
            if path.is_absolute():
                try:
                    path = path.resolve().relative_to(source_root.resolve())
                except ValueError:
                    continue
            added_by_path.setdefault(_normalized_diff_path(path), set()).update(added_lines)

        occurrence_by_id = {item.id: item for item in audit.occurrences}
        direct_endpoint_ids = {
            build_audit_endpoint(candidate.endpoint, source_root).id for candidate in candidates
        }
        endpoint_by_id = {
            build_audit_endpoint(endpoint, source_root).id: endpoint
            for endpoint in self.inventory.endpoints
        }
        eligible: list[tuple[ResourceCouplingEdge, ResourceCouplingCandidateEvidence]] = []
        for edge in graph.edges:
            if edge.producer_endpoint_id not in direct_endpoint_ids:
                continue
            occurrence = occurrence_by_id.get(edge.producer_occurrence_id)
            if occurrence is None:
                continue
            changed = added_by_path.get(_normalized_diff_path(occurrence.file_path), set())
            end_line = occurrence.end_line or occurrence.line
            overlapping = sorted(line for line in changed if occurrence.line <= line <= end_line)
            if not overlapping or edge.consumer_endpoint_id not in endpoint_by_id:
                continue
            evidence = ResourceCouplingCandidateEvidence(
                edge_id=edge.id,
                graph_hash=graph.graph_hash,
                producer_occurrence_id=edge.producer_occurrence_id,
                producer_endpoint_id=edge.producer_endpoint_id,
                consumer_endpoint_id=edge.consumer_endpoint_id,
                changed_file=occurrence.file_path,
                changed_line=overlapping[0],
                resource_value_hash=edge.resource_value_hash,
                strength=edge.strength,
                limitations=(
                    "The exact producer callsite was added, but runtime execution, ordering, "
                    "persistence, and downstream observation are not established.",
                    "This potential cross-request edge is LOW-only and non-recursive.",
                ),
            )
            eligible.append((edge, evidence))

        new_target_ids = {
            evidence.consumer_endpoint_id
            for _edge, evidence in eligible
            if evidence.consumer_endpoint_id not in direct_endpoint_ids
        }
        if len(new_target_ids) > configured.document.limits.max_new_candidates:
            raise ResourceCouplingError(
                "resource coupling candidate limit exceeded; expansion aborted atomically"
            )
        evidence_by_target: dict[str, dict[str, ResourceCouplingCandidateEvidence]] = {}
        for edge, evidence in eligible:
            evidence_by_target.setdefault(edge.consumer_endpoint_id, {})[edge.id] = evidence

        enriched: list[AffectedEndpoint] = []
        seen_target_ids: set[str] = set()
        for candidate in candidates:
            target_id = build_audit_endpoint(candidate.endpoint, source_root).id
            seen_target_ids.add(target_id)
            additions = evidence_by_target.get(target_id, {})
            if not additions:
                enriched.append(candidate)
                continue
            merged = {item.edge_id: item for item in candidate.resource_coupling_evidence}
            merged.update(additions)
            enriched.append(
                candidate.model_copy(
                    update={
                        "resource_coupling_evidence": tuple(merged[item] for item in sorted(merged))
                    }
                )
            )
        for target_id in sorted(new_target_ids - seen_target_ids):
            endpoint = endpoint_by_id[target_id]
            target_evidence = evidence_by_target[target_id]
            changed_files = sorted({item.changed_file for item in target_evidence.values()})
            enriched.append(
                AffectedEndpoint(
                    endpoint=endpoint,
                    confidence=ConfidenceLevel.LOW,
                    reason="Potential cross-request finite resource coupling",
                    changed_files=changed_files,
                    resource_coupling_evidence=tuple(
                        target_evidence[item] for item in sorted(target_evidence)
                    ),
                )
            )
        return enriched

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
            scip_affected, scip_orphans = self._analyze_with_scip(
                python_files, warnings, progress_callback
            )
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
                candidate_endpoints=scip_affected,
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
        self._effect_contract_audit = self._build_effect_contract_audit()
        if self.config.analysis.sql_transaction_diagnostics:
            if self._effect_contracts is None or self._effect_contract_audit is None:
                raise ChangeMapperError(
                    "SQL transaction diagnostics require a complete effect audit"
                )
            self._sql_transaction_report = build_sql_transaction_diagnostics(
                self._effect_contracts,
                self._effect_contract_audit,
            )
            if self.config.analysis.sql_transaction_ordered_paths:
                self._sql_transaction_path_report = build_sql_transaction_path_diagnostics(
                    self.target_project_root,
                    self._effect_contract_audit,
                    self._sql_transaction_report,
                    max_pairs=self.config.analysis.sql_transaction_path_max_pairs,
                )
        if self._resource_coupling is not None:
            if self._effect_contracts is None or self._effect_contract_audit is None:
                raise ChangeMapperError("resource coupling requires a complete effect audit")
            self._resource_coupling_graph = build_resource_coupling_graph(
                self._resource_coupling,
                self._effect_contracts,
                self._effect_contract_audit,
            )

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
        materialized = self._expand_resource_coupling_candidates(materialized, python_files)
        materialized = self._attach_contract_evidence(
            materialized,
            self._effect_contract_audit,
        )
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

        report = AnalysisReport(
            app_path=str(self.app_path),
            diff_source=diff_source_str,
            total_endpoints=len(self.registry),
            affected_endpoints=filtered_affected,
            candidate_endpoints=materialized,
            orphan_changes=orphan_changes,
            total_files_changed=len(diff_files),
            python_files_changed=len(python_files),
            analysis_duration_ms=duration_ms,
            errors=errors,
            warnings=warnings,
            effect_contract_audit=self._effect_contract_audit,
            resource_coupling_graph=self._resource_coupling_graph,
            sql_transaction_report=self._sql_transaction_report,
            sql_transaction_path_report=self._sql_transaction_path_report,
        )
        self.mypy_analyzer.release_typed_snapshot()
        return report

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
            package_path = self.app_path.parent if self.app_path.is_file() else self.app_path
            temp_analyzer = MypyAnalyzer(package_path)
            temp_analyzer.clear_cache()
