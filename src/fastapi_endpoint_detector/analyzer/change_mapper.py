"""
Change mapper - maps code changes to affected endpoints.

This module combines diff parsing, endpoint registry, and mypy-based
dependency analysis to determine which endpoints are affected by code changes.

Uses mypy for type-aware, precise dependency tracking.
"""

from __future__ import annotations

import heapq
import itertools
import os
import platform
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from fastapi_endpoint_detector.analyzer.effect_analyzer import EffectAnalyzer
from fastapi_endpoint_detector.analyzer.effect_contract_auditor import (
    audit_effect_contracts,
    build_audit_endpoint,
)
from fastapi_endpoint_detector.analyzer.endpoint_registry import EndpointRegistry
from fastapi_endpoint_detector.analyzer.evidence_graph import EvidenceGraph, source_evidence_graph
from fastapi_endpoint_detector.analyzer.framework_phase_integration import (
    collect_framework_phase_evidence,
)
from fastapi_endpoint_detector.analyzer.framework_phase_report import (
    FrameworkPhaseReport,
    phase_report_payload,
    unavailable_phase_report,
)
from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.analyzer.resource_coupling import build_resource_coupling_graph
from fastapi_endpoint_detector.analyzer.scip_analyzer import (
    SCIPAnalyzer,
    SCIPAnalyzerError,
    SCIPDefinition,
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
    SnapshotSide,
)
from fastapi_endpoint_detector.models.report import (
    AffectedEndpoint,
    AnalysisLimitationReport,
    AnalysisReport,
    CallStackFrame,
    ChangeEffectKind,
    CodeReference,
    ConfidenceLevel,
    ContractEffectEvidence,
    EffectDisposition,
    EffectEvidence,
    EndpointLifecycle,
    EndpointLifecycleKind,
    EvidenceProducer,
    EvidenceStatus,
    ExecutionEvidence,
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
    from fastapi_endpoint_detector.analyzer.mypy_analyzer import (
        EndpointDependencies,
        SourceEvidenceSpan,
    )
    from fastapi_endpoint_detector.analyzer.source_inventory import SourceFile, SourceInventory
    from fastapi_endpoint_detector.models.diff import ChangedByteSpan, DiffFile
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
EndpointResultKey = tuple[str, str, int, str, str, str]


def _endpoint_result_key(endpoint: Endpoint) -> EndpointResultKey:
    handler = endpoint.handler
    provenance = endpoint.native_provenance
    occurrence = ""
    if provenance is not None:
        registration = provenance.registration
        occurrence = ":".join(
            (
                provenance.side.value,
                str(registration.source_span.file_path.resolve()),
                str(registration.occurrence_order),
                *(
                    f"{edge.source_span.file_path.resolve()}@{edge.occurrence_order}"
                    for edge in provenance.assembly_chain
                ),
            )
        )
    return (
        endpoint.identifier,
        str(handler.file_path.resolve()),
        handler.line_number,
        handler.name,
        handler.module,
        occurrence,
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
    execution_evidence: list[ExecutionEvidence] = field(default_factory=list)

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
        for execution_evidence in candidate.execution_evidence:
            if execution_evidence not in self.execution_evidence:
                self.execution_evidence.append(execution_evidence)

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
            execution_evidence=tuple(self.execution_evidence),
        )


def _merge_affected(
    accumulated: dict[EndpointResultKey, _AffectedAccumulator],
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


@dataclass(frozen=True)
class _ExpandedSCIPDefinition:
    definition: SCIPDefinition
    depth: int
    dependency_chain: tuple[str, ...]
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class _MypySourceInventory:
    """Mypy-facing view of the canonical inventory with stable import identities."""

    root: Path
    files: tuple[SourceFile, ...]
    unresolved_imports: tuple[tuple[str, str], ...]
    excluded_files: tuple[str, ...]
    follow_imports: bool
    max_depth: int


def _mypy_inventory(inventory: SourceInventory) -> tuple[_MypySourceInventory, Path]:
    """Adapt inventory controls without changing its selected files or provenance."""
    module_root = MypyAnalyzer._infer_module_root(inventory.root)
    files = []
    for record in inventory.files:
        path = record.path.resolve()
        try:
            module = MypyAnalyzer._module_name_from_path(path, module_root)
        except ValueError:
            module = MypyAnalyzer._module_name_from_path(path, inventory.root)
        files.append(replace(record, module=module))
    return (
        _MypySourceInventory(
            root=inventory.root,
            files=tuple(files),
            unresolved_imports=inventory.unresolved_imports,
            excluded_files=inventory.excluded_files,
            follow_imports=inventory.follow_imports,
            max_depth=inventory.max_depth,
        ),
        module_root,
    )


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
    """Walk source-bound SCIP references while preserving their limitations."""
    reverse_edges = getattr(analyzer, "reverse_call_edges", None)
    if not callable(reverse_edges):
        raise SCIPAnalyzerError("SCIP analyzer lacks reference-only reverse-call evidence")

    scope_limitations: tuple[str, ...] = ()
    selected_inventory_paths: set[str] | None = None
    source_scope = getattr(analyzer, "source_scope", None)
    if callable(source_scope):
        scope = source_scope()
        index_scope = getattr(scope, "index_scope", None)
        scope_limitations = tuple(getattr(scope, "limitations", ()))
        selected_paths = getattr(scope, "selected_inventory_paths", None)
        if selected_paths is not None:
            selected_inventory_paths = {Path(item).as_posix() for item in selected_paths}
        if index_scope == "project_root":
            scope_limitations = (
                *scope_limitations,
                "SCIP indexes project_root; selected inventory paths filter returned evidence "
                "but do not restrict the index itself.",
            )
        else:
            scope_limitations = (
                *scope_limitations,
                f"SCIP index scope is {index_scope!r}; selected inventory scope is not proven.",
            )
        if warnings is not None:
            for limitation in scope_limitations:
                warning = f"SCIP source-scope limitation: {limitation}"
                if warning not in warnings:
                    warnings.append(warning)

    edge_limitations = getattr(analyzer, "reverse_call_edge_limitations", None)
    best_depth_by_symbol: dict[str, int] = {seed.symbol: 0}
    definition_by_symbol: dict[str, SCIPDefinition] = {seed.symbol: seed}
    chain_by_symbol: dict[str, tuple[str, ...]] = {seed.symbol: (seed.symbol,)}
    limitations_by_symbol: dict[str, set[str]] = {seed.symbol: set(scope_limitations)}
    queue_order = itertools.count()
    worklist: list[tuple[int, str, tuple[str, ...], int, SCIPDefinition, tuple[str, ...]]] = [
        (0, seed.symbol, (seed.symbol,), next(queue_order), seed, scope_limitations)
    ]

    def record(
        definition: SCIPDefinition,
        depth: int,
        chain: tuple[str, ...],
        limitations: tuple[str, ...],
    ) -> None:
        symbol = definition.symbol
        previous_depth = best_depth_by_symbol.get(symbol)
        previous_chain = chain_by_symbol.get(symbol)
        canonical_chain = (chain, _scip_definition_key(definition))
        old_chain = (
            (previous_chain, _scip_definition_key(definition_by_symbol[symbol]))
            if previous_chain is not None
            else None
        )
        previous_limitations = limitations_by_symbol.setdefault(symbol, set())
        limitation_count = len(previous_limitations)
        previous_limitations.update(limitations)
        if previous_depth is not None:
            if depth > previous_depth:
                return
            if depth == previous_depth and old_chain is not None:
                if canonical_chain > old_chain:
                    return
                if canonical_chain == old_chain and len(previous_limitations) == limitation_count:
                    return
        best_depth_by_symbol[symbol] = depth
        definition_by_symbol[symbol] = definition
        chain_by_symbol[symbol] = chain
        heapq.heappush(
            worklist,
            (depth, symbol, chain, next(queue_order), definition, limitations),
        )

    while worklist:
        depth, symbol, current_chain, _order, definition, current_limitations = heapq.heappop(
            worklist
        )
        if depth != best_depth_by_symbol[symbol] or current_chain != chain_by_symbol[symbol]:
            continue
        if depth >= max_depth:
            continue
        try:
            edges = reverse_edges(definition)
            limitations_for_seed = (
                tuple(edge_limitations(definition)) if callable(edge_limitations) else ()
            )
        except SCIPAnalyzerError as error:
            if warnings is not None:
                warnings.append(
                    "SCIP analysis incomplete: "
                    f"reverse references for {definition.short_name} failed: {error}"
                )
            continue
        if warnings is not None and limitations_for_seed:
            warning = f"SCIP reference limitations for {definition.short_name}: " + "; ".join(
                limitations_for_seed
            )
            if warning not in warnings:
                warnings.append(warning)
        path_limitations = tuple(
            dict.fromkeys(
                (*current_limitations, *limitations_by_symbol[symbol], *limitations_for_seed)
            )
        )
        base_resolver = getattr(analyzer, "base_method_definitions", None)
        if callable(base_resolver):
            try:
                bases = base_resolver(definition)
            except SCIPAnalyzerError as error:
                if warnings is not None:
                    warnings.append(
                        "SCIP analysis incomplete: "
                        f"override bridge from {definition.short_name} failed: {error}"
                    )
                bases = ()
            for base in sorted(bases, key=_scip_definition_key):
                record(
                    base,
                    depth + 1,
                    (*current_chain, base.symbol),
                    tuple(
                        dict.fromkeys(
                            (
                                *path_limitations,
                                "SCIP followed an explicit override-to-base bridge.",
                            )
                        )
                    ),
                )
        for edge in edges:
            edge_status = getattr(edge, "execution_status", None)
            confidence = getattr(edge, "confidence", None)
            if edge_status != "reference_only" or confidence != "LOW":
                if warnings is not None:
                    warnings.append(
                        f"SCIP discarded reverse edge for {definition.short_name}: "
                        "it lacks reference_only/LOW evidence labels."
                    )
                continue
            caller = getattr(edge, "caller", None)
            if not isinstance(caller, SCIPDefinition):
                if warnings is not None:
                    warnings.append(
                        f"SCIP discarded malformed reverse edge for {definition.short_name}."
                    )
                continue
            occurrence = getattr(edge, "occurrence", None)
            occurrence_path = getattr(occurrence, "file_path", None)
            edge_paths: tuple[str, ...] = (caller.file_path.as_posix(),)
            if isinstance(occurrence_path, Path):
                edge_paths = (*edge_paths, occurrence_path.as_posix())
            if selected_inventory_paths is not None and not set(edge_paths).issubset(
                selected_inventory_paths
            ):
                if warnings is not None:
                    warnings.append(
                        "SCIP discarded reverse reference outside the selected source inventory."
                    )
                continue
            per_edge_limitations = tuple(getattr(edge, "limitations", ()))
            combined = tuple(dict.fromkeys((*path_limitations, *per_edge_limitations)))
            record(
                caller,
                depth + 1,
                (*current_chain, caller.symbol),
                combined,
            )

    return tuple(
        _ExpandedSCIPDefinition(
            definition_by_symbol[symbol],
            best_depth_by_symbol[symbol],
            chain_by_symbol[symbol],
            tuple(sorted(limitations_by_symbol[symbol])),
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
        if not self.config.integrations.use_mypy and not use_scip:
            raise ChangeMapperError(
                "integrations.use_mypy=false requires the explicitly selected --scip backend"
            )
        if app_entry is not None and not secure_ast:
            raise ChangeMapperError("app_entry requires secure_ast=True")
        if bootstrap_entry is not None and not secure_ast:
            raise ChangeMapperError("bootstrap_entry requires secure_ast=True")
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
        self._baseline_mypy_analyzer: MypyAnalyzer | None = None
        self._effect_analyzer = EffectAnalyzer(target_project_root)
        self._baseline_effect_analyzer = (
            EffectAnalyzer(baseline_project_root) if baseline_project_root is not None else None
        )
        self._scip_analyzer: SCIPAnalyzer | None = None
        self._baseline_registry: EndpointRegistry | None = None
        self._baseline_scip_analyzer: SCIPAnalyzer | None = None
        self.source_inventory = self.config.source_inventory(self.app_path)
        self._baseline_source_inventory: SourceInventory | None = None
        self._baseline_extractor: FastAPIExtractor | SecureASTExtractor | None = None
        self._baseline_failure: str | None = None

    @property
    def baseline_mypy_analyzer(self) -> MypyAnalyzer:
        """Get an independent typed analyzer rooted at the baseline snapshot."""
        if self.baseline_app_path is None:
            raise ChangeMapperError("Mypy removals require an explicit --baseline-app snapshot")
        if self._baseline_mypy_analyzer is None:
            package_path = (
                self.baseline_app_path.parent
                if self.baseline_app_path.is_file()
                else self.baseline_app_path
            )
            effective_depth = (
                self.config.parser.max_depth if self.config.analysis.track_transitive else 1
            )
            inventory = self.baseline_source_inventory
            mypy_inventory, module_root = _mypy_inventory(inventory)
            self._baseline_mypy_analyzer = MypyAnalyzer(
                package_path,
                max_depth=effective_depth,
                module_root=module_root,
                source_inventory=mypy_inventory,
            )
        return self._baseline_mypy_analyzer

    @property
    def baseline_mypy_registry(self) -> EndpointRegistry:
        """Discover baseline endpoints independently from the target registry."""
        if self.baseline_app_path is None:
            raise ChangeMapperError("Mypy removals require an explicit --baseline-app snapshot")
        if self._baseline_registry is None:
            if self.secure_ast:
                secure_extractor = SecureASTExtractor(
                    app_path=self.baseline_app_path,
                    app_variable=self.app_variable,
                    app_entry=self.app_entry,
                    bootstrap_entry=self.bootstrap_entry,
                    snapshot_side=SnapshotSide.BASELINE,
                    source_paths=self.baseline_source_inventory.paths,
                )
                self._baseline_inventory = self._merge_surface_inventory(
                    self.baseline_app_path, secure_extractor.extract_inventory()
                )
                endpoints = self._baseline_inventory.endpoints
                extractor: FastAPIExtractor | SecureASTExtractor = secure_extractor
            else:
                extractor = FastAPIExtractor(
                    app_path=self.baseline_app_path,
                    app_variable=self.app_variable,
                    source_inventory=self.baseline_source_inventory,
                )
                endpoints = extractor.extract_endpoints()
            self._baseline_extractor = extractor
            self._baseline_registry = EndpointRegistry()
            self._baseline_registry.register_many(endpoints)
        return self._baseline_registry

    @property
    def baseline_source_inventory(self) -> SourceInventory:
        """Return the canonical source selection for the explicit baseline snapshot."""
        if self.baseline_app_path is None:
            raise ChangeMapperError("A baseline source inventory requires --baseline-app")
        if self._baseline_source_inventory is None:
            self._baseline_source_inventory = self.config.source_inventory(self.baseline_app_path)
        return self._baseline_source_inventory

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
                    source_paths=self.source_inventory.paths,
                )
            else:
                self._extractor = FastAPIExtractor(
                    app_path=self.app_path,
                    app_variable=self.app_variable,
                    source_inventory=self.source_inventory,
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
            app_variable=self.app_variable,
            app_entry=self.app_entry,
        ).extract_inventory()
        return merge_surface_inventory(native, custom)

    def _source_inventory_warnings(self) -> list[str]:
        """Report runtime source-scope caveats without changing route identity."""
        if self.secure_ast:
            return []

        warnings: list[str] = []
        snapshots = [("Target", self.source_inventory)]
        if self.baseline_app_path is not None:
            snapshots.append(("Baseline", self.baseline_source_inventory))

        for side, inventory in snapshots:
            extractor = self.extractor if side == "Target" else self._baseline_extractor
            scope_limitations = (
                extractor.source_inventory_limitations
                if isinstance(extractor, FastAPIExtractor)
                else ()
            )
            if scope_limitations:
                follow_policy = "enabled" if inventory.follow_imports else "disabled"
                warnings.append(
                    f"{side} runtime source scope selected {len(inventory.files)} file(s); "
                    f"local import following is {follow_policy}. {scope_limitations[1]}"
                )
            for limitation in inventory.limitations:
                warnings.append(f"{side} source inventory incomplete: {limitation}")
            if inventory.unresolved_imports:
                warnings.append(
                    f"{side} source inventory has {len(inventory.unresolved_imports)} "
                    "unresolved local import(s)."
                )
        return warnings

    def _endpoint_lifecycle(self) -> list[EndpointLifecycle]:
        """Reconcile endpoint inventories by public route identity, failing closed."""
        if self.baseline_app_path is None:
            return []
        try:
            if not self.baseline_app_path.exists():
                raise FileNotFoundError(
                    f"Baseline snapshot does not exist: {self.baseline_app_path}"
                )
            baseline = self.baseline_mypy_registry.get_all()
        except Exception as exc:
            self._baseline_failure = str(exc)
            return []
        target = self.registry.get_all()
        identities = sorted({item.identifier for item in baseline + target})

        baseline_root = (
            self.baseline_app_path.parent
            if self.baseline_app_path.is_file()
            else self.baseline_app_path
        )

        def snapshot_path(endpoint: Endpoint, root: Path) -> Path:
            """Compare endpoint locations inside each snapshot, not temp roots."""
            path = endpoint.handler.file_path.resolve()
            try:
                return path.relative_to(root.resolve())
            except ValueError:
                return path

        records: list[EndpointLifecycle] = []
        for identity in identities:
            old = [item for item in baseline if item.identifier == identity]
            new = [item for item in target if item.identifier == identity]
            if len(old) > 1 or len(new) > 1:
                records.append(
                    EndpointLifecycle(
                        identity=identity,
                        lifecycle=EndpointLifecycleKind.AMBIGUOUS,
                    )
                )
            elif not old:
                records.append(
                    EndpointLifecycle(
                        identity=identity,
                        lifecycle=EndpointLifecycleKind.TARGET,
                        target_endpoint=new[0],
                    )
                )
            elif not new:
                records.append(
                    EndpointLifecycle(
                        identity=identity,
                        lifecycle=EndpointLifecycleKind.REMOVED,
                        baseline_endpoint=old[0],
                    )
                )
            else:
                previous, current = old[0], new[0]
                prior, present = previous.handler, current.handler
                lifecycle = EndpointLifecycleKind.TARGET
                if snapshot_path(previous, baseline_root) != snapshot_path(
                    current, self.target_project_root
                ):
                    lifecycle = EndpointLifecycleKind.MOVED
                elif prior.name != present.name:
                    lifecycle = EndpointLifecycleKind.RENAMED
                records.append(
                    EndpointLifecycle(
                        identity=identity,
                        lifecycle=lifecycle,
                        baseline_endpoint=previous,
                        target_endpoint=current,
                    )
                )
        return records

    def _target_equivalent_endpoint(self, endpoint: Endpoint) -> Endpoint:
        """Map baseline evidence onto a unique public target identity only."""
        matches = [item for item in self.registry if item.identifier == endpoint.identifier]
        return matches[0] if len(matches) == 1 else endpoint

    @property
    def inventory(self) -> EndpointInventory:
        """Return the exact execution-free inventory used to populate the registry."""
        _registry = self.registry
        if self._inventory is None:
            raise ChangeMapperError("endpoint inventory is unavailable outside secure AST mode")
        return self._inventory

    def map_framework_phase_report(  # noqa: PLR0911
        self,
        *,
        snapshot_side: SnapshotSide = SnapshotSide.TARGET,
    ) -> FrameworkPhaseReport | None:
        """Map the explicitly selected framework-v1 catalog to a report payload.

        This report-only hook does not affect endpoint candidates or confidence.
        The current mapper retains mypy's full build result rather than the
        explicit TypedBuild receipt required for typed phase authority, so phase
        records are deliberately unavailable until that provider is connected.
        """
        if self.config.analysis.surface_preset != "framework-v1":
            return None
        if snapshot_side == SnapshotSide.BASELINE:
            return unavailable_phase_report(
                snapshot_side=snapshot_side.value,
                limitation=(
                    "the public mapper hook has only the target source inventory; "
                    "baseline phase evidence is unavailable"
                ),
            )
        if self.use_scip:
            return unavailable_phase_report(
                snapshot_side=snapshot_side.value,
                limitation=(
                    "framework phase evidence requires the bounded mypy callback frontend; "
                    "the selected SCIP mapper does not provide it"
                ),
            )
        if self._surface_contracts is None:
            return unavailable_phase_report(
                snapshot_side=snapshot_side.value,
                limitation="the selected framework-v1 contract snapshot is unavailable",
            )
        analyzer = self._mypy_analyzer
        if analyzer is None:
            return unavailable_phase_report(
                snapshot_side=snapshot_side.value,
                limitation="the target mypy source snapshot has not been initialized",
            )
        try:
            inventory = self.inventory
        except ChangeMapperError as exc:
            return unavailable_phase_report(
                snapshot_side=snapshot_side.value,
                limitation=f"the selected framework inventory is unavailable: {exc}",
            )
        source_root = Path(analyzer.source_root).resolve()
        selected_sources = {
            path.resolve()
            for endpoint in inventory.endpoints
            if endpoint.surface is not None
            for path in (endpoint.handler.file_path, endpoint.surface.registration_file)
        }
        if any(not path.is_relative_to(source_root) for path in selected_sources):
            return unavailable_phase_report(
                snapshot_side=snapshot_side.value,
                limitation=(
                    "selected framework inventory contains callback or registration sources "
                    "outside the mapper's target project root"
                ),
            )
        evidence = collect_framework_phase_evidence(
            inventory,
            self._surface_contracts,
            analyzer,
            None,
            snapshot_side=snapshot_side,
            app_variable=self.app_variable,
            app_entry=self.app_entry,
            bootstrap_entry=self.bootstrap_entry,
        )
        return phase_report_payload(evidence)

    @property
    def scip_analyzer(self) -> SCIPAnalyzer:
        """Get the SCIP analyzer, initializing if needed."""
        if self._scip_analyzer is None:
            package_path = self.app_path.parent if self.app_path.is_file() else self.app_path
            self._scip_analyzer = SCIPAnalyzer(
                package_path,
                use_cache=self.use_cache,
                source_inventory=cast("Any", self.source_inventory),
            )
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
                snapshot_side=SnapshotSide.BASELINE,
                source_paths=self.baseline_source_inventory.paths,
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
            baseline_inventory = self.baseline_source_inventory
            self._baseline_scip_analyzer = SCIPAnalyzer(
                package_path,
                use_cache=self.use_cache,
                source_inventory=cast("Any", baseline_inventory),
            )
        return self._baseline_scip_analyzer

    @property
    def mypy_analyzer(self) -> MypyAnalyzer:
        """Get the mypy analyzer, initializing if needed (does NOT pre-analyze)."""
        if self._mypy_analyzer is None:
            package_path = self.app_path.parent if self.app_path.is_file() else self.app_path

            effective_depth = (
                self.config.parser.max_depth if self.config.analysis.track_transitive else 1
            )
            mypy_inventory, module_root = _mypy_inventory(self.source_inventory)
            self._mypy_analyzer = MypyAnalyzer(
                package_path,
                max_depth=effective_depth,
                module_root=module_root,
                source_inventory=mypy_inventory,
            )
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
        analyzer: MypyAnalyzer | None = None,
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
        snapshot_analyzer = analyzer or self.mypy_analyzer
        deps = snapshot_analyzer.get_endpoint_dependencies(endpoint)

        if not deps:
            return None

        file_path = str(diff_file.path)
        snapshot_root = snapshot_analyzer.source_root.resolve()
        candidate_path = Path(file_path)
        if not candidate_path.is_absolute():
            candidate_path = snapshot_root / candidate_path
        snapshot_file_path: Path | None = None
        try:
            resolved_path = candidate_path.resolve()
            resolved_path.relative_to(snapshot_root)
        except (OSError, RuntimeError, ValueError):
            pass
        else:
            snapshot_file_path = resolved_path
        changed_lines = set(added_lines) | set(removed_lines)

        # Dependency ranges already cover complete callable definitions. Expanding
        # by nearby physical lines lets a new sibling definition inherit evidence
        # from the preceding unchanged function and creates massive false fanout.
        overlap = deps.references_lines(file_path, changed_lines)

        if overlap:
            side = "source" if analyzer is not None else "target"
            if self._change_is_deferred_lambda_only(deps, diff_file, overlap, side=side):
                return None
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
                        file_path_obj = snapshot_file_path
                        if file_path_obj is not None and file_path_obj.is_file():
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
                            symbol_paths = deps._matching_paths(
                                file_path,
                                (item.file_path for item in deps.referenced_symbols),
                                "referenced_symbols",
                            )
                            containing_symbols = [
                                sym_ref
                                for sym_ref in deps.referenced_symbols
                                if sym_ref.file_path in symbol_paths
                                and sym_ref.contains_line(first_line)
                            ]
                            if containing_symbols:
                                # Mypy may report both a module/class range and a
                                # nested callable range. Attribute a changed line to
                                # the most specific definition containing it.
                                function_name = min(
                                    containing_symbols,
                                    key=lambda ref: (
                                        ref.end_line - ref.start_line,
                                        -ref.start_line,
                                        ref.symbol_name,
                                    ),
                                ).symbol_name

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
                                    file_path=str(snapshot_file_path)
                                    if snapshot_file_path is not None
                                    else file_path,
                                    line_number=first_line,
                                    function_name=function_name,
                                    code_context=code_context,
                                )
                            )

                # Add this completed call stack to the list
                all_call_stacks.append(call_stack)

            effect_analyzer = self._effect_analyzer
            if analyzer is not None:
                if self._baseline_effect_analyzer is None:
                    raise ChangeMapperError("Baseline effect analysis requires a baseline snapshot")
                effect_analyzer = self._baseline_effect_analyzer
            effect_result = (
                effect_analyzer.analyze(
                    str(snapshot_file_path),
                    set(display_lines),
                    all_call_stacks,
                )
                if snapshot_file_path is not None
                else None
            )
            low_only_points_to = deps.references_lines_low_only(file_path, changed_lines)
            limited_call_locations = {
                (str(Path(item.file_path).resolve()), item.call_line, item.call_column)
                for item in deps.analysis_limitations
                if item.call_column is not None
            }
            limited_path_relevant = any(
                (
                    str(Path(frame.caller_file_path).resolve()),
                    frame.caller_line_number,
                    frame.caller_column_number,
                )
                in limited_call_locations
                for stack in raw_stacks
                for frame in stack
                if frame.caller_file_path is not None and frame.caller_line_number is not None
            )
            confidence = (
                ConfidenceLevel.LOW
                if low_only_points_to or limited_path_relevant
                else effect_result.confidence
                if effect_result
                else ConfidenceLevel.MEDIUM
            )
            effect_summary = (
                f"; effect analysis: {effect_result.evidence[0].summary}" if effect_result else ""
            )
            changed_byte_spans = DiffParser.get_changed_byte_spans(diff_file, side=side)
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
                execution_evidence=tuple(
                    ExecutionEvidence(
                        file_path=span.file_path,
                        start_line=span.start_line,
                        start_column=span.start_column,
                        end_line=span.end_line,
                        end_column=span.end_column,
                        execution_state=span.execution_state,
                        provenance=span.provenance,
                    )
                    for span in deps.get_source_evidence_spans(file_path)
                    if any(
                        self._source_span_overlaps_change(span, change)
                        for change in changed_byte_spans
                        if change.line_number in display_lines
                    )
                ),
            )

        return None

    @staticmethod
    def _source_span_overlaps_change(span: SourceEvidenceSpan, change: ChangedByteSpan) -> bool:
        """Match side-qualified UTF-8 edits to the actual execution span."""
        if not span.start_line <= change.line_number <= span.end_line:
            return False
        if not change.exact:
            return True
        span_start = (span.start_line, span.start_column)
        span_end = (span.end_line, span.end_column)
        change_start = (change.line_number, change.start_column)
        change_end = (change.line_number, change.end_column)
        if change_start == change_end:
            return span_start <= change_start < span_end
        return change_start < span_end and span_start < change_end

    @staticmethod
    def _change_is_deferred_lambda_only(
        deps: EndpointDependencies,
        diff_file: DiffFile,
        overlap_lines: set[int],
        *,
        side: str,
    ) -> bool:
        """Suppress only exact edits wholly inside deferred lambda bodies.

        Side-qualified diff spans and CPython UTF-8 AST columns must both be
        available. Missing or inexact source alignment fails closed to the
        existing dependency candidate.
        """
        changes = DiffParser.get_changed_byte_spans(diff_file, side=side)
        expected_lines = set(
            DiffParser.get_changed_line_numbers(diff_file)[0 if side == "target" else 1]
        )
        content_lines = {
            line.line_number
            for hunk in diff_file.hunks
            for line in (hunk.added_content if side == "target" else hunk.removed_content)
        }
        if not expected_lines <= content_lines:
            return False
        relevant_changes = [change for change in changes if change.line_number in overlap_lines]
        if any(not change.exact for change in relevant_changes):
            return False
        deferred_spans = deps.get_source_evidence_spans(
            str(diff_file.path), execution_state="deferred_execution"
        )
        if not deferred_spans:
            return False
        executed_spans = deps.get_source_evidence_spans(
            str(diff_file.path), execution_state="established_execution"
        )
        executed_spans.extend(
            deps.get_source_evidence_spans(
                str(diff_file.path), execution_state="possible_execution"
            )
        )
        if not relevant_changes:
            # This side has no changed bytes (for example, a suffix deletion
            # represented by a replacement line). The opposite side owns the
            # actual text edit; do not attribute it to this snapshot.
            return True

        def contained(change: ChangedByteSpan, span: SourceEvidenceSpan) -> bool:
            if not span.start_line <= change.line_number <= span.end_line:
                return False
            if change.line_number == span.start_line and change.start_column < span.start_column:
                return False
            return not (change.line_number == span.end_line and change.end_column > span.end_column)

        return all(
            any(contained(change, span) for span in deferred_spans)
            and not any(contained(change, span) for span in executed_spans)
            for change in relevant_changes
        )

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
        affected: dict[EndpointResultKey, _AffectedAccumulator] = {}
        processed_added_lines: set[int] = set()
        processed_removed_lines: set[int] = set()

        # Get changed lines
        added_lines, removed_lines = DiffParser.get_changed_line_numbers(diff_file)

        # Git can report a semantic file change without text hunks (pure rename,
        # move, or mode-only update). Seed endpoints by exact registered file
        # ownership so these changes cannot disappear from accounting.
        if not added_lines and not removed_lines:
            for side_registry, changed_path, side in (
                (self.registry, diff_file.path, "target"),
                (
                    self.baseline_mypy_registry
                    if self.baseline_app_path is not None and self._baseline_failure is None
                    else None,
                    diff_file.source_path or diff_file.path,
                    "baseline",
                ),
            ):
                if side_registry is None:
                    continue
                for endpoint in side_registry.get_by_file(changed_path):
                    reported_endpoint = (
                        self._target_equivalent_endpoint(endpoint)
                        if side == "baseline"
                        else endpoint
                    )
                    _merge_affected(
                        affected,
                        AffectedEndpoint(
                            endpoint=reported_endpoint,
                            confidence=ConfidenceLevel.HIGH,
                            reason=f"Line-less {side} file change affects endpoint source",
                            dependency_chain=[str(changed_path), endpoint.handler.name],
                            changed_files=[str(changed_path)],
                            effect_evidence=[
                                EffectEvidence(
                                    producer=EvidenceProducer.DIRECT,
                                    status=EvidenceStatus.ESTABLISHED,
                                    effect=ChangeEffectKind.UNKNOWN,
                                    channel=ImpactChannel.UNKNOWN,
                                    disposition=EffectDisposition.INTERNAL_EFFECT,
                                    summary=(
                                        f"Git reported a {side} file change without line hunks; "
                                        "the endpoint handler is defined by that file."
                                    ),
                                    changed_location=CodeReference(
                                        file_path=str(changed_path),
                                        line_number=endpoint.handler.line_number,
                                        symbol=endpoint.handler.name,
                                    ),
                                )
                            ],
                        ),
                    )

        # Resolve source ownership independently on each snapshot. Baseline
        # coordinates never consume target additions or substitute target ranges.
        structural_sides = [
            (self.registry, diff_file.path, added_lines, "target", processed_added_lines)
        ]
        if removed_lines and self.baseline_app_path is not None and self._baseline_failure is None:
            structural_sides.append(
                (
                    self.baseline_mypy_registry,
                    diff_file.source_path or diff_file.path,
                    removed_lines,
                    "baseline",
                    processed_removed_lines,
                )
            )
        for (
            side_registry,
            changed_path,
            structural_lines,
            side,
            processed_lines,
        ) in structural_sides:
            for endpoint, kinds, overlap in side_registry.get_structural_overlaps(
                changed_path, set(structural_lines)
            ):
                matched_kinds = ", ".join(kinds)
                changed_line = min(overlap)
                _merge_affected(
                    affected,
                    AffectedEndpoint(
                        endpoint=(
                            self._target_equivalent_endpoint(endpoint)
                            if side == "baseline"
                            else endpoint
                        ),
                        confidence=ConfidenceLevel.HIGH,
                        reason=(
                            f"Native route assembly occurrence modified ({side}: {matched_kinds}) "
                            f"in {changed_path}"
                        ),
                        dependency_chain=[str(changed_path), *kinds],
                        changed_files=[str(changed_path)],
                        effect_evidence=[
                            EffectEvidence(
                                producer=EvidenceProducer.STRUCTURAL,
                                status=EvidenceStatus.ESTABLISHED,
                                effect=ChangeEffectKind.ROUTE_ASSEMBLY,
                                channel=ImpactChannel.UNKNOWN,
                                disposition=EffectDisposition.INTERNAL_EFFECT,
                                summary=(
                                    f"Changed {side} source overlaps exact secure-AST "
                                    "route assembly "
                                    "provenance for this endpoint occurrence."
                                ),
                                changed_location=CodeReference(
                                    file_path=str(changed_path),
                                    line_number=changed_line,
                                    symbol=matched_kinds,
                                ),
                            )
                        ],
                    ),
                )
                processed_lines.update(overlap)

        # Find endpoints whose handlers are defined in the changed file.
        file_endpoints = self.registry.get_by_file(diff_file.path)

        # Check for direct handler changes
        for endpoint in file_endpoints:
            result = self._check_direct_handler_change(endpoint, diff_file, added_lines, [])
            if result:
                _merge_affected(affected, result)
                # Mark lines as processed
                handler = endpoint.handler
                handler_end = handler.end_line_number or handler.line_number + 50
                handler_lines = set(range(handler.line_number, handler_end + 1))
                processed_added_lines.update(ln for ln in added_lines if ln in handler_lines)

        # Use mypy for type-aware dependency analysis
        for endpoint in self.registry:
            result = self._check_mypy_dependency(endpoint, diff_file, added_lines, [])
            if result:
                _merge_affected(affected, result)
                # Mark lines as processed - get the actual lines that were referenced
                deps = self.mypy_analyzer.get_endpoint_dependencies(endpoint)
                if deps:
                    file_path = str(diff_file.path)
                    changed_lines = set(added_lines)
                    referenced = deps.references_lines(file_path, changed_lines)
                    if referenced:
                        # Only mark the directly changed lines as processed
                        processed_added_lines.update(ln for ln in added_lines if ln in referenced)

        # Removals are interpreted exclusively against an independently built
        # baseline graph. Without a baseline, leave them unresolved for reporting.
        if removed_lines and self.baseline_app_path is not None and self._baseline_failure is None:
            source_path = diff_file.source_path or diff_file.path
            baseline_file = diff_file.model_copy(update={"path": source_path})
            for endpoint in self.baseline_mypy_registry:
                result = self._check_mypy_dependency(
                    endpoint, baseline_file, [], removed_lines, self.baseline_mypy_analyzer
                )
                if result:
                    result = result.model_copy(
                        update={
                            "endpoint": self._target_equivalent_endpoint(result.endpoint),
                        }
                    )
                    _merge_affected(affected, result)
                    deps = self.baseline_mypy_analyzer.get_endpoint_dependencies(endpoint)
                    if deps:
                        referenced = deps.references_lines(str(source_path), set(removed_lines))
                        processed_removed_lines.update(referenced)

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

        affected: dict[EndpointResultKey, _AffectedAccumulator] = {}
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

        def analyze_structural_side(
            registry: EndpointRegistry,
            file_path: Path,
            lines: list[int],
            side: str,
        ) -> set[int]:
            processed: set[int] = set()
            for discovered, kinds, overlap in registry.get_structural_overlaps(
                file_path, set(lines)
            ):
                # Structural evidence remains attached to its source snapshot.
                # Lifecycle reconciliation is deliberately deferred rather than
                # replacing a baseline occurrence by a same-identifier target.
                endpoint = discovered
                matched_kinds = ", ".join(kinds)
                _merge_affected(
                    affected,
                    AffectedEndpoint(
                        endpoint=endpoint,
                        confidence=ConfidenceLevel.HIGH,
                        reason=(
                            f"Secure-AST {side} route assembly occurrence modified "
                            f"({matched_kinds}) in {file_path}"
                        ),
                        dependency_chain=[str(file_path), *kinds],
                        changed_files=[str(file_path)],
                        effect_evidence=[
                            EffectEvidence(
                                producer=EvidenceProducer.STRUCTURAL,
                                status=EvidenceStatus.ESTABLISHED,
                                effect=ChangeEffectKind.ROUTE_ASSEMBLY,
                                channel=ImpactChannel.UNKNOWN,
                                disposition=EffectDisposition.INTERNAL_EFFECT,
                                summary=(
                                    f"Changed {side} source overlaps exact secure-AST route "
                                    "assembly provenance for this endpoint occurrence."
                                ),
                                changed_location=CodeReference(
                                    file_path=str(file_path),
                                    line_number=min(overlap),
                                    symbol=matched_kinds,
                                ),
                            )
                        ],
                    ),
                )
                processed.update(overlap)
            return processed

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
                        confidence = ConfidenceLevel.LOW
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
                                            f"SCIP found a {side} reference-only path "
                                            f"at depth {reached.depth}; it does not establish "
                                            "execution."
                                        ),
                                        changed_location=CodeReference(
                                            file_path=str(file_path),
                                            line_number=min(seed_lines),
                                            symbol=seed.short_name,
                                        ),
                                        limitations=list(
                                            dict.fromkeys(
                                                (
                                                    "SCIP reverse references are LOW-confidence "
                                                    "reference evidence and do not establish "
                                                    "execution.",
                                                    *reached.limitations,
                                                )
                                            )
                                        ),
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
                processed_added.update(
                    analyze_structural_side(
                        self.registry,
                        diff_file.path,
                        added_lines,
                        "target",
                    )
                )
                processed_added.update(
                    analyze_side(
                        self.scip_analyzer,
                        self.registry,
                        target_root,
                        diff_file.path,
                        added_lines,
                        "target",
                    )
                )
            processed_removed: set[int] = set()
            source_path = diff_file.source_path or diff_file.path
            if removed_lines and source_path.suffix == ".py":
                assert baseline_root is not None
                processed_removed.update(
                    analyze_structural_side(
                        self.baseline_registry,
                        source_path,
                        removed_lines,
                        "baseline",
                    )
                )
                processed_removed.update(
                    analyze_side(
                        self.baseline_scip_analyzer,
                        self.baseline_registry,
                        baseline_root,
                        source_path,
                        removed_lines,
                        "baseline",
                    )
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
            verified_mypy_source_hashes=self.mypy_analyzer.verified_mypy_source_hashes,
            verified_package_source_hashes=self.mypy_analyzer.verified_package_source_hashes,
            verified_package_versions=self.mypy_analyzer.verified_package_versions,
            target_python_version=platform.python_version(),
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
                        package_applicability=audit.scope.package_applicability,
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
        # Failures describe this attempt; a recovered snapshot must be retried.
        self._baseline_failure = None

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
        unsupported_changes = [
            item.path.as_posix() for item in diff_files if item not in python_files
        ]
        if unsupported_changes:
            warnings.extend(
                f"Unresolved non-Python/configuration change: {path}; "
                "no finite dependency contract was applied"
                for path in unsupported_changes
            )
        warnings.extend(self._source_inventory_warnings())
        target_source_graph = source_evidence_graph(self.source_inventory)
        if self.baseline_app_path is not None:
            baseline_graph = source_evidence_graph(self.baseline_source_inventory, side="baseline")
            target_source_graph = EvidenceGraph(
                nodes=(*baseline_graph.nodes, *target_source_graph.nodes),
                edges=(*baseline_graph.edges, *target_source_graph.edges),
            )

        # Initialize endpoints
        report_progress(5, 100, "Extracting endpoints...")
        total_endpoints = len(self.registry)
        target_inventory = self.inventory if self.secure_ast else None

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
            endpoint_lifecycle = self._endpoint_lifecycle()
            if self._baseline_failure:
                warnings.append(
                    "SCIP baseline analysis is incomplete: "
                    "baseline endpoint lifecycle could not be reconciled "
                    f"({self._baseline_failure})."
                )
            return AnalysisReport(
                app_path=str(self.app_path),
                diff_source=diff_source_str,
                total_endpoints=total_endpoints,
                inventory_status=(
                    target_inventory.status if target_inventory is not None else None
                ),
                inventory_limitations=(
                    target_inventory.limitations if target_inventory is not None else ()
                ),
                affected_endpoints=filtered,
                candidate_endpoints=scip_affected,
                endpoint_lifecycle=endpoint_lifecycle,
                orphan_changes=scip_orphans,
                total_files_changed=len(diff_files),
                python_files_changed=len(python_files),
                analysis_duration_ms=duration_ms,
                errors=errors,
                warnings=warnings,
                framework_phase_report=self.map_framework_phase_report(),
                analysis_completeness=(
                    "partial"
                    if errors
                    or any(
                        marker in warning.lower()
                        for warning in warnings
                        for marker in ("unresolved", "incomplete", "error analyzing")
                    )
                    else "complete"
                ),
                source_evidence_graph=target_source_graph,
            )

        # Pre-analyze endpoints with mypy
        report_progress(10, 100, f"Analyzing {total_endpoints} endpoints (mypy)...")
        self._preanalyze_mypy(progress_callback)
        self._append_dependency_completeness_warnings(
            "target", self.registry, self.mypy_analyzer, warnings
        )
        analysis_limitations: list[AnalysisLimitationReport] = []
        for endpoint in self.registry.get_all():
            dependencies = self.mypy_analyzer.get_endpoint_dependencies(endpoint)
            if dependencies is None or not dependencies.analysis_limitations:
                continue
            analysis_limitations.extend(
                AnalysisLimitationReport(
                    file_path=item.file_path,
                    call_line=item.call_line,
                    cap=item.cap,
                    target_count=item.target_count,
                    limit=item.limit,
                )
                for item in dependencies.analysis_limitations
            )
        for item in analysis_limitations:
            warnings.append(
                f"Mypy bounded analysis at {item.file_path}:{item.call_line} exceeded "
                f"{item.cap} (targets={item.target_count}, limit={item.limit}); "
                "analysis is partial."
            )
        has_mypy_removals = any(
            DiffParser.get_changed_line_numbers(item)[1]
            or (item.source_path is not None and item.source_path != item.path)
            for item in python_files
        )
        if has_mypy_removals and self.baseline_app_path is None:
            warnings.append(
                "Mypy baseline analysis is incomplete: removed or renamed source requires "
                "baseline_app_path; removed lines are retained as unresolved orphan evidence."
            )
        elif has_mypy_removals and self.baseline_app_path is not None:
            try:
                if not self.baseline_app_path.exists():
                    raise FileNotFoundError(
                        f"Baseline snapshot does not exist: {self.baseline_app_path}"
                    )
                self._preanalyze_mypy_registry(
                    self.baseline_mypy_registry, self.baseline_mypy_analyzer, progress_callback
                )
                self._append_dependency_completeness_warnings(
                    "baseline", self.baseline_mypy_registry, self.baseline_mypy_analyzer, warnings
                )
            except Exception as exc:
                self._baseline_failure = str(exc)
                warnings.append(
                    "Mypy baseline analysis is incomplete: "
                    f"baseline snapshot could not be analyzed ({exc}); removed lines remain "
                    "unresolved."
                )
        if self._baseline_failure is None and self.baseline_app_path is not None:
            # Baseline bounds are reported alongside target bounds. Confidence
            # is bounded on each typed dependency candidate before accumulation,
            # preserving independent direct-handler and structural evidence.
            for endpoint in self.baseline_mypy_registry.get_all():
                dependencies = self.baseline_mypy_analyzer.get_endpoint_dependencies(endpoint)
                if dependencies is None or not dependencies.analysis_limitations:
                    continue
                analysis_limitations.extend(
                    AnalysisLimitationReport(
                        file_path=item.file_path,
                        call_line=item.call_line,
                        cap=item.cap,
                        target_count=item.target_count,
                        limit=item.limit,
                    )
                    for item in dependencies.analysis_limitations
                )
            # Keep structured limitations deterministic and avoid duplicate
            # source records when both snapshots hit the same bound.
            analysis_limitations = list(
                {
                    (item.file_path, item.call_line, item.cap, item.target_count, item.limit): item
                    for item in analysis_limitations
                }.values()
            )
            if analysis_limitations:
                warnings = [
                    warning for warning in warnings if "Mypy bounded analysis at " not in warning
                ]
                warnings.extend(
                    f"Mypy bounded analysis at {item.file_path}:{item.call_line} exceeded "
                    f"{item.cap} (targets={item.target_count}, limit={item.limit}); "
                    "analysis is partial."
                    for item in analysis_limitations
                )
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
        all_affected: dict[EndpointResultKey, _AffectedAccumulator] = {}
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
                source_path = diff_file.source_path or diff_file.path
                target_evidence = orphan_evidence.setdefault(
                    _normalized_diff_path(diff_file.path),
                    _OrphanAccumulator(
                        file_path=str(diff_file.path),
                        reason=("Target-side code changes are unrelated or could not be resolved"),
                    ),
                )
                target_evidence.added.update(added_lines)
                target_evidence.processed_added.update(processed_added)
                source_evidence = orphan_evidence.setdefault(
                    _normalized_diff_path(source_path),
                    _OrphanAccumulator(
                        file_path=str(source_path),
                        reason=(
                            "Baseline-side code changes are unrelated or could not be resolved"
                        ),
                    ),
                )
                source_evidence.removed.update(removed_lines)
                source_evidence.processed_removed.update(processed_removed)
            except Exception as e:
                warnings.append(f"Error analyzing {diff_file.path}: {e}")
                # Preserve all line evidence when an analyzer fails after parsing.
                added_lines, removed_lines = DiffParser.get_changed_line_numbers(diff_file)
                target_evidence = orphan_evidence.setdefault(
                    _normalized_diff_path(diff_file.path),
                    _OrphanAccumulator(
                        file_path=str(diff_file.path),
                        reason=f"Analysis unresolved after per-file failure: {e}",
                    ),
                )
                target_evidence.added.update(added_lines)
                source_path = diff_file.source_path or diff_file.path
                source_evidence = orphan_evidence.setdefault(
                    _normalized_diff_path(source_path),
                    _OrphanAccumulator(
                        file_path=str(source_path),
                        reason=f"Analysis unresolved after per-file failure: {e}",
                    ),
                )
                source_evidence.removed.update(removed_lines)

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

        endpoint_lifecycle = self._endpoint_lifecycle()
        if self._baseline_failure and not any(
            "baseline analysis is incomplete" in warning.lower() for warning in warnings
        ):
            warnings.append(
                "Mypy baseline analysis is incomplete: "
                f"baseline endpoint lifecycle could not be reconciled ({self._baseline_failure})."
            )
        report = AnalysisReport(
            app_path=str(self.app_path),
            diff_source=diff_source_str,
            total_endpoints=len(self.registry),
            inventory_status=(target_inventory.status if target_inventory is not None else None),
            inventory_limitations=(
                target_inventory.limitations if target_inventory is not None else ()
            ),
            affected_endpoints=filtered_affected,
            candidate_endpoints=materialized,
            endpoint_lifecycle=endpoint_lifecycle,
            orphan_changes=orphan_changes,
            total_files_changed=len(diff_files),
            python_files_changed=len(python_files),
            analysis_duration_ms=duration_ms,
            errors=errors,
            warnings=warnings,
            analysis_completeness=(
                "partial"
                if errors
                or analysis_limitations
                or any(
                    marker in warning.lower()
                    for warning in warnings
                    for marker in ("unresolved", "incomplete", "error analyzing")
                )
                else "complete"
            ),
            analysis_limitations=analysis_limitations,
            source_evidence_graph=target_source_graph,
            framework_phase_report=self.map_framework_phase_report(),
            effect_contract_audit=self._effect_contract_audit,
            resource_coupling_graph=self._resource_coupling_graph,
            sql_transaction_report=self._sql_transaction_report,
            sql_transaction_path_report=self._sql_transaction_path_report,
        )
        self.mypy_analyzer.release_typed_snapshot()
        if self._baseline_mypy_analyzer is not None:
            self._baseline_mypy_analyzer.release_typed_snapshot()
        return report

    def _preanalyze_mypy(
        self,
        progress_callback: ProgressCallback | None = None,
    ) -> None:
        """Pre-analyze all endpoints with mypy."""
        endpoints = self.registry.get_all()
        total = len(endpoints)

        if progress_callback:
            progress_callback(10, 100, f"Analyzing {total} endpoints (mypy)...")
        # The public bulk API owns cache validation, build failure tracking,
        # and guarded cache persistence. Calling analyze_endpoint in a loop
        # loses that snapshot-level failure state.
        self.mypy_analyzer.analyze_endpoints(endpoints, use_cache=self.use_cache)

    @staticmethod
    def _append_dependency_completeness_warnings(
        side: str,
        registry: EndpointRegistry,
        analyzer: MypyAnalyzer,
        warnings: list[str],
    ) -> None:
        """Keep incomplete dependency builds visible and tied to their source."""
        for endpoint in registry.get_all():
            dependencies = analyzer.get_endpoint_dependencies(endpoint)
            if dependencies is None or not dependencies.analysis_incomplete:
                continue
            source = endpoint.handler.file_path or endpoint.handler.name
            methods = ",".join(method.value for method in endpoint.methods)
            warnings.append(
                f"Mypy {side} analysis is incomplete for {methods} {endpoint.path} "
                f"({source}): dependency analysis did not resolve the full endpoint graph."
            )

    def _preanalyze_mypy_registry(
        self,
        registry: EndpointRegistry,
        analyzer: MypyAnalyzer,
        progress_callback: ProgressCallback | None = None,
    ) -> None:
        """Build typed dependencies for every endpoint in one source snapshot."""
        endpoints = registry.get_all()
        if progress_callback:
            progress_callback(10, 100, f"Analyzing {len(endpoints)} baseline endpoints (mypy)...")
        # Use the snapshot API so failed builds remain marked as failed and
        # cannot be reused from memory or persisted as complete cache entries.
        analyzer.analyze_endpoints(endpoints, use_cache=self.use_cache)

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
