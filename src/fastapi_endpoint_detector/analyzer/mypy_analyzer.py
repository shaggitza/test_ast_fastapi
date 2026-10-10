"""
Mypy-based dependency analyzer.

This module uses mypy's type analysis to determine which code paths
each endpoint handler actually uses, providing more precise dependency
tracking than import-based analysis.

It relies entirely on mypy for AST parsing and type resolution,
using mypy's internal data structures to track file/line references.
"""

from __future__ import annotations

import ast
import gc
import hashlib
import io
import json
import os
import stat
import sys
import tempfile
import tokenize
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from email.parser import BytesParser
from email.policy import compat32
from importlib.metadata import PackageNotFoundError, version
from importlib.util import find_spec
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from typing import Any, ClassVar, Literal, Protocol, cast

from packaging.utils import canonicalize_name

from fastapi_endpoint_detector.models.effect_contract import (
    CallArgumentEvidence,
    CallResolutionStatus,
    FiniteValueStatus,
    InvocationKind,
    ResolvedCallSite,
    ResourceIdentityEvidence,
)
from fastapi_endpoint_detector.models.endpoint import (
    DependencyCallableKind,
    DependencyResolutionStatus,
    Endpoint,
)
from fastapi_endpoint_detector.models.surface_contract import CallbackRangeMode

# Type alias for line-level progress callback (file_path, line_number, symbol_name)
LineProgressCallback = Callable[[str, int, str], None]
_MYPY_POSIX_FALLBACK_ROOT = "/usr/local/lib/mypy"


def _is_path_within(path: str, root: str) -> bool:
    """Check lexical path containment without crossing path-component boundaries."""
    absolute = str(Path(path).absolute())
    absolute_root = str(Path(root).absolute())
    try:
        return os.path.commonpath((absolute, absolute_root)) == absolute_root
    except ValueError:
        return False


class SourceFileRecord(Protocol):
    """Structural source record shared with offline snapshot producers."""

    @property
    def path(self) -> str | Path: ...

    @property
    def relative_path(self) -> str: ...

    @property
    def module(self) -> str: ...

    @property
    def sha256(self) -> str: ...

    @property
    def imports(self) -> Iterable[str]: ...


class SourceInventory(Protocol):
    """Optional canonical project snapshot; deliberately has no package import dependency."""

    @property
    def root(self) -> str | Path: ...

    @property
    def files(self) -> Iterable[SourceFileRecord]: ...

    @property
    def follow_imports(self) -> bool: ...

    @property
    def max_depth(self) -> int: ...

    @property
    def excluded_files(self) -> Iterable[str]: ...

    @property
    def unresolved_imports(self) -> Iterable[tuple[str, str]]: ...


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
    caller_file_path: str | None = None
    caller_line_number: int | None = None
    caller_column_number: int | None = None


@dataclass(frozen=True)
class SymbolReference:
    """A source range reached through standard or finite points-to propagation."""

    file_path: str
    symbol_name: str
    start_line: int
    end_line: int
    low_confidence: bool = False

    def contains_line(self, line: int) -> bool:
        """Check if a line number falls within this symbol's range."""
        return self.start_line <= line <= self.end_line


SourceExecutionState = Literal[
    "lexical_reference", "possible_execution", "established_execution", "deferred_execution"
]


@dataclass(frozen=True)
class SourceEvidenceSpan:
    """Exact CPython source span; columns use UTF-8 byte offsets."""

    file_path: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    execution_state: SourceExecutionState
    evidence_kind: str = "lambda_body"
    provenance: str = "mypy callable traversal"

    def __post_init__(self) -> None:
        if self.execution_state not in {
            "lexical_reference",
            "possible_execution",
            "established_execution",
            "deferred_execution",
        }:
            raise ValueError("unsupported source evidence execution state")
        if self.evidence_kind != "lambda_body":
            raise ValueError("unsupported source evidence kind")
        if self.start_line < 1 or self.end_line < self.start_line:
            raise ValueError("source evidence span lines are invalid")
        if self.start_column < 0 or self.end_column < 0:
            raise ValueError("source evidence span columns are invalid")


@dataclass(frozen=True)
class AnalysisLimitation:
    """A source-located bounded analysis path that could not be resolved."""

    file_path: str
    call_line: int
    cap: str
    target_count: int | None = None
    limit: int | None = None
    call_column: int | None = None

    def __post_init__(self) -> None:
        if self.call_line < 1 or not self.cap:
            raise ValueError("analysis limitation requires a source line and cap name")
        if self.call_column is not None and self.call_column < 0:
            raise ValueError("analysis limitation call column cannot be negative")


@dataclass
class _ProjectPathIndex:
    """Shared canonical project inventory with fail-closed query resolution."""

    source_root: str
    project_files: frozenset[str]
    _canonical_inventory: dict[str, set[str]] = field(init=False, repr=False)
    _query_cache: dict[str, str | None] = field(default_factory=dict, init=False, repr=False)
    _MAX_QUERY_CACHE: int = field(default=1024, init=False, repr=False)

    def __post_init__(self) -> None:
        canonical_inventory: dict[str, set[str]] = {}
        for item in self.project_files:
            canonical_inventory.setdefault(self.canonical(item), set()).add(item)
        self._canonical_inventory = canonical_inventory

    @staticmethod
    def parts(path: str) -> tuple[str, ...]:
        return PurePosixPath(path.replace("\\", "/")).parts

    def canonical(self, path: str) -> str:
        candidate = Path(path.replace("\\", os.sep))
        if not candidate.is_absolute() and self.source_root:
            candidate = Path(self.source_root) / candidate
        return str(candidate.resolve())

    def resolve(self, file_path: str) -> str | None:
        """Resolve once against the shared inventory, preserving ambiguity."""
        if file_path in self._query_cache:
            return self._query_cache[file_path]
        query_canonical = self.canonical(file_path)
        exact = self._canonical_inventory.get(query_canonical, set())
        if len(exact) == 1:
            selected: str | None = query_canonical
        else:
            query_parts = self.parts(file_path)
            suffixes = {
                canonical
                for canonical, originals in self._canonical_inventory.items()
                if len(originals) == 1
                and len(query_parts) <= len(self.parts(canonical))
                and self.parts(canonical)[-len(query_parts) :] == query_parts
            }
            selected = next(iter(suffixes)) if len(suffixes) == 1 else None
        if len(self._query_cache) >= self._MAX_QUERY_CACHE:
            self._query_cache.pop(next(iter(self._query_cache)))
        self._query_cache[file_path] = selected
        return selected


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
    resolved_call_sites: list[ResolvedCallSite] = field(default_factory=list)
    """Source-backed call occurrences reached from this endpoint."""
    source_evidence_spans: list[SourceEvidenceSpan] = field(default_factory=list)
    """Column-precise execution state for callable bodies sharing physical lines."""
    source_root: str = ""
    project_files: set[str] | frozenset[str] = field(default_factory=set)
    analysis_incomplete: bool = False
    build_failed: bool = False
    analysis_limitations: list[AnalysisLimitation] = field(default_factory=list)
    unresolved_imports: tuple[tuple[str, str], ...] = ()
    _path_index: _ProjectPathIndex | None = field(default=None, repr=False, compare=False)
    _canonical_key_indexes: dict[str, dict[str, frozenset[str]]] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _resolved_call_site_set: set[ResolvedCallSite] = field(
        default_factory=set, init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        self._resolved_call_site_set.update(self.resolved_call_sites)

    def add_analysis_limitation(self, limitation: AnalysisLimitation) -> None:
        if limitation not in self.analysis_limitations:
            self.analysis_limitations.append(limitation)
            self.analysis_limitations.sort(
                key=lambda item: (item.file_path, item.call_line, item.cap)
            )
        self.analysis_incomplete = True

    def add_reference(self, file_path: str, line: int, symbol_name: str = "") -> None:
        """Add a line reference to dependencies."""
        if file_path not in self.referenced_files:
            self.referenced_files[file_path] = set()
            self._canonical_key_indexes.pop("referenced_files", None)
        self.referenced_files[file_path].add(line)

    def add_symbol_reference(
        self,
        file_path: str,
        symbol_name: str,
        start_line: int,
        end_line: int,
        *,
        low_confidence: bool = False,
    ) -> None:
        """Add a symbol range while preserving finite points-to provenance."""
        ref = SymbolReference(
            file_path,
            symbol_name,
            start_line,
            end_line,
            low_confidence=low_confidence,
        )
        if ref in self.referenced_symbols:
            return
        self.referenced_symbols.append(ref)
        self._canonical_key_indexes.pop("referenced_symbols", None)

        if file_path not in self.referenced_files:
            self.referenced_files[file_path] = set()
            self._canonical_key_indexes.pop("referenced_files", None)
        self.referenced_files[file_path].update(range(start_line, end_line + 1))

    def add_call_stack(self, file_path: str, stack: list[CallFrame]) -> None:
        """Add one stack and invalidate only its lazy category index."""
        stacks = self.call_stacks.setdefault(file_path, [])
        if stack not in stacks:
            stacks.append(stack)
            self._canonical_key_indexes.pop("call_stacks", None)

    def add_resolved_call_site(self, call_site: ResolvedCallSite) -> None:
        """Add one physical call occurrence without duplicating traversal paths."""
        if call_site in self._resolved_call_site_set:
            return
        self._resolved_call_site_set.add(call_site)
        self.resolved_call_sites.append(call_site)
        self._canonical_key_indexes.pop("resolved_call_sites", None)

    def add_source_evidence_span(self, span: SourceEvidenceSpan) -> None:
        """Retain distinct proof states for one precise source-body span."""
        if span not in self.source_evidence_spans:
            self.source_evidence_spans.append(span)
            self.source_evidence_spans.sort(
                key=lambda item: (
                    item.file_path,
                    item.start_line,
                    item.start_column,
                    item.end_line,
                    item.end_column,
                    item.evidence_kind,
                    item.execution_state,
                )
            )

    def get_source_evidence_spans(
        self,
        file_path: str | None = None,
        *,
        execution_state: str | None = None,
    ) -> list[SourceEvidenceSpan]:
        """Return deterministic precise callable-body evidence."""
        selected = self.source_evidence_spans
        if file_path is not None:
            matches = self._matching_paths(
                file_path,
                (item.file_path for item in selected),
                "source_evidence_spans",
            )
            selected = [item for item in selected if item.file_path in matches]
        if execution_state is not None:
            selected = [item for item in selected if item.execution_state == execution_state]
        return sorted(
            selected,
            key=lambda item: (
                item.file_path,
                item.start_line,
                item.start_column,
                item.end_line,
                item.end_column,
                item.execution_state,
            ),
        )

    def _matching_paths(
        self,
        file_path: str,
        keys: Iterable[str],
        category: str,
    ) -> set[str]:
        """Resolve one query with one lazy canonical index per evidence category."""
        canonical_keys = self._canonical_key_indexes.get(category)
        index = self._path_index
        if canonical_keys is None:
            materialized = list(keys)
            if not materialized:
                self._canonical_key_indexes[category] = {}
                return set()
            if index is None:
                inventory = frozenset(self.project_files) or frozenset(
                    {
                        *self.referenced_files,
                        *(ref.file_path for ref in self.referenced_symbols),
                        *self.call_stacks,
                        *(site.file_path for site in self.resolved_call_sites),
                        *(span.file_path for span in self.source_evidence_spans),
                    }
                )
                index = _ProjectPathIndex(self.source_root, inventory)
                self._path_index = index
            grouped: dict[str, set[str]] = {}
            for key in materialized:
                grouped.setdefault(index.canonical(key), set()).add(key)
            canonical_keys = {
                canonical: frozenset(originals) for canonical, originals in grouped.items()
            }
            self._canonical_key_indexes[category] = canonical_keys
        elif index is None:
            index = _ProjectPathIndex(self.source_root, frozenset(self.project_files))
            self._path_index = index
        selected = index.resolve(file_path)
        return set(canonical_keys.get(selected, ())) if selected is not None else set()

    def references_symbol_at_line(self, file_path: str, line: int) -> SymbolReference | None:
        """Check if any unambiguously resolved symbol contains the given line."""
        matches = self._matching_paths(
            file_path,
            (ref.file_path for ref in self.referenced_symbols),
            "referenced_symbols",
        )
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
        return bool(self._matching_paths(file_path, self.referenced_files, "referenced_files"))

    def references_lines_low_only(self, file_path: str, lines: set[int]) -> bool:
        """Return whether every symbol path overlapping changed lines is LOW-only."""
        matches = self._matching_paths(
            file_path,
            (ref.file_path for ref in self.referenced_symbols),
            "referenced_symbols",
        )
        overlapping = [
            ref
            for ref in self.referenced_symbols
            if ref.file_path in matches and any(ref.contains_line(line) for line in lines)
        ]
        return bool(overlapping) and all(ref.low_confidence for ref in overlapping)

    def references_lines(self, file_path: str, lines: set[int]) -> set[int]:
        """Get referenced changed lines for one unambiguously resolved file."""
        matches = self._matching_paths(file_path, self.referenced_files, "referenced_files")
        return (
            set().union(*(self.referenced_files[path] & lines for path in matches))
            if matches
            else set()
        )

    def get_resolved_call_sites(
        self,
        file_path: str | None = None,
        *,
        status: CallResolutionStatus | None = None,
    ) -> list[ResolvedCallSite]:
        """Return deterministic call occurrences with fail-closed path filtering."""
        selected = self.resolved_call_sites
        if file_path is not None:
            matches = self._matching_paths(
                file_path,
                (site.file_path for site in selected),
                "resolved_call_sites",
            )
            selected = [site for site in selected if site.file_path in matches]
        if status is not None:
            selected = [site for site in selected if site.status == status]
        return sorted(
            selected,
            key=lambda site: (
                site.file_path,
                site.line,
                site.column,
                site.end_line or site.line,
                site.end_column if site.end_column is not None else site.column,
                site.source_spelling,
                site.status.value,
                site.canonical_symbol or "",
            ),
        )

    def get_call_stack(self, file_path: str) -> list[list[CallFrame]]:
        """Get all unique call stacks for one unambiguously resolved file."""
        matches = self._matching_paths(file_path, self.call_stacks, "call_stacks")
        stacks: list[list[CallFrame]] = []
        for path in self.call_stacks:
            if path in matches:
                for stack in self.call_stacks[path]:
                    if stack not in stacks:
                        stacks.append(stack)
        return stacks


@dataclass(frozen=True)
class _FinitePointsTo:
    """A bounded source-proven object set with exact constructor field values."""

    types: tuple[str, ...]
    fields: tuple[tuple[str, _FinitePointsTo], ...] = ()

    def field(self, name: str) -> _FinitePointsTo | None:
        return dict(self.fields).get(name)

    def with_field(self, name: str, value: _FinitePointsTo | None) -> _FinitePointsTo:
        fields = dict(self.fields)
        if value is None:
            fields.pop(name, None)
        else:
            fields[name] = value
        return _FinitePointsTo(self.types, tuple(sorted(fields.items())))


@dataclass(frozen=True)
class _DeferredGenerator:
    """One exact generator call whose body has not executed yet."""

    fullname: str
    receiver: _FinitePointsTo | None
    environment: tuple[tuple[str, _FinitePointsTo], ...]
    is_async: bool


@dataclass(frozen=True)
class _PartialCallable:
    """Exact finite functools.partial target and its bound source arguments."""

    declaration: tuple[str, InvocationKind]
    receiver: _FinitePointsTo | None
    args: tuple[Any, ...]
    arg_kinds: tuple[Any, ...]
    arg_names: tuple[str | None, ...]
    # Callable actuals are captured when functools.partial is constructed.  The
    # AST expressions above are retained for Python's positional/keyword merge,
    # but must never be re-evaluated in the later invocation environment.
    bound_callables: tuple[
        tuple[str, tuple[tuple[str, InvocationKind], _FinitePointsTo | None]], ...
    ] = ()
    bound_strings: tuple[tuple[str, tuple[str, ...]], ...] = ()


@dataclass(frozen=True)
class _CallableUnion:
    """Bounded set of source-proven callable targets at a control-flow join."""

    targets: tuple[tuple[tuple[str, InvocationKind], _FinitePointsTo | None], ...]


@dataclass(frozen=True)
class _ExecutorSummary:
    """Exact callback and forwarding semantics for one executor wrapper."""

    callback_index: int
    allow_callback_keyword: bool
    forwards_keyword_arguments: bool
    control_keywords: frozenset[str] = frozenset()


class MypyAnalyzer:
    """
    Analyze endpoint dependencies using mypy's type system.

    Uses mypy's build API with proper configuration to get typed ASTs
    and extract precise file/line information for all references.
    """

    # Schema 27 distinguishes typed execution evidence and creation-time partial
    # callable snapshots from the incompatible schema-26 cache formats.
    CACHE_SCHEMA_VERSION = 27
    MAX_CALL_SPAN_SOURCE_BYTES = 2_000_000
    MAX_CALL_SPAN_SOURCE_NODES = 100_000
    MAX_CALL_SPAN_SOURCE_ITEMS = 200_000
    MAX_CALL_SPAN_SOURCE_DEPTH = 128
    MAX_CALL_SPAN_MYPY_NODES = 200_000
    MAX_CALL_SPAN_MYPY_ITEMS = 400_000
    MAX_CALL_SPAN_MYPY_DEPTH = 256
    MAX_LAMBDA_SOURCE_FILE_BYTES = 1_048_576
    MAX_LAMBDA_SOURCE_SNAPSHOT_BYTES = 16_777_216
    MAX_LAMBDA_SOURCE_AST_NODES = 100_000
    MAX_POINTS_TO_TARGETS = 8
    MAX_FACTORY_RETURNS = 64
    MAX_FACTORY_STATES = 512
    MAX_POINTS_TO_EDGES = 4096
    EXECUTION_SUMMARY_VERSION = 7
    GENERATOR_CONSUMERS: ClassVar[dict[str, tuple[int, str, bool | None]]] = {
        "starlette.responses.StreamingResponse": (0, "content", None),
    }
    BACKGROUND_CALLBACK_SUMMARIES: ClassVar[dict[str, _ExecutorSummary]] = {
        "fastapi.background.BackgroundTasks.add_task": _ExecutorSummary(0, True, True),
        "starlette.background.BackgroundTasks.add_task": _ExecutorSummary(0, True, True),
    }
    EXECUTOR_SUMMARIES: ClassVar[dict[str, _ExecutorSummary]] = {
        "asyncio.threads.to_thread": _ExecutorSummary(0, False, True),
        "anyio.to_thread.run_sync": _ExecutorSummary(
            0,
            True,
            False,
            frozenset({"abandon_on_cancel", "cancellable", "limiter"}),
        ),
        "starlette.concurrency.run_in_threadpool": _ExecutorSummary(0, True, True),
    }

    def __init__(
        self,
        app_path: Path,
        *,
        max_depth: int | None = None,
        module_root: Path | None = None,
        source_inventory: SourceInventory | None = None,
        no_site_packages: bool = False,
        target_platform: str | None = None,
    ) -> None:
        """Initialize the mypy analyzer."""
        inventory_root = (
            Path(source_inventory.root).resolve() if source_inventory is not None else None
        )
        inventory_depth = getattr(source_inventory, "max_depth", None)
        effective_depth = int(
            max_depth if max_depth is not None else inventory_depth if inventory_depth else 10
        )
        if effective_depth < 1:
            raise ValueError("max_depth must be at least 1")
        self.app_path = app_path.resolve()
        self.source_root = inventory_root or (
            self.app_path.parent if self.app_path.is_file() else self.app_path
        )
        self.module_root = (module_root or self._infer_module_root(self.source_root)).resolve()
        self.source_inventory = source_inventory
        self.max_depth = effective_depth
        # Hermetic source probes can opt out of all interpreter site packages.
        # Ordinary analysis keeps mypy's historical environment discovery.
        self.no_site_packages = no_site_packages
        self.target_platform = target_platform
        self._endpoint_deps: dict[str, EndpointDependencies] = {}
        self._active_endpoint_dependencies: EndpointDependencies | None = None
        self._active_source_file = str(self.source_root)
        self._active_source_line = 0
        self._active_source_column: int | None = None
        self._analysis_build_failed = False
        self._mypy_available = self._check_mypy_available()
        self._cache_file: Path | None = None
        self._line_progress_callback: LineProgressCallback | None = None
        self._shared_path_index: _ProjectPathIndex | None = None
        self._modules_by_canonical_path: dict[str, tuple[str, ...]] = {}
        try:
            self._resolver_version = version("mypy")
        except PackageNotFoundError:
            self._resolver_version = "missing"

        # Mypy build results - stored to prevent GC
        self._build_result: Any = None
        self._trees: dict[str, Any] = {}  # module_name -> MypyFile
        self._module_to_path: dict[str, str] = {}
        self._types_map: dict[Any, Any] = {}  # AST node -> Type
        self._project_modules: set[str] = set()
        self._global_value_cache: dict[str, SymbolReference | None] = {}
        self._python_dependency_cache: dict[tuple[str, int, str], set[str]] = {}
        self._python_ast_cache: dict[str, ast.Module | None] = {}
        self._python_ast_nodes_cache: dict[str, list[ast.AST] | None] = {}
        self._python_verified_call_spans: dict[str, dict[int, tuple[int, int, int, int]]] = {}
        self._python_call_span_abstained: set[str] = set()
        self._call_source_snapshot_cache: dict[str, bytes | None] = {}
        self._source_bytes_cache: dict[str, tuple[bytes, ...] | None] = {}
        self._source_record_snapshots: dict[str, bytes | None] = {}
        self._source_record_snapshot_bytes = 0
        self._last_source_records: list[tuple[Path, str, str]] = []
        self._verified_mypy_source_hashes: dict[str, str] = {}
        self._verified_package_source_hashes: dict[str, str] = {}
        self._verified_package_versions: dict[str, str] = {}
        self._local_module_census_depth = 0
        self._local_module_census: tuple[tuple[str, bool, str, bool], ...] | None = None
        self._analysis_source_snapshots: dict[str, bytes | None] = {}
        self._lambda_source_ast_cache: dict[str, ast.Module | None] = {}
        self._lambda_source_index_cache: dict[
            str, dict[tuple[str, int, int], tuple[ast.Lambda, ...]] | None
        ] = {}
        self._resolved_call_site_cache: dict[int, ResolvedCallSite | None] = {}
        self._finite_global_value_cache: dict[str, _FinitePointsTo | None] = {}
        self._finite_global_in_progress: set[str] = set()
        self._exact_project_identity_cache: dict[str, tuple[str, str] | None] = {}
        self._built_source_fingerprint: str | None = None
        self._typed_environment_fingerprint: str | None = None
        self._cached_typed_environment_fingerprint: str | None = None
        self._expected_source_fingerprint: str | None = None
        self._fullname_resolution_cache: dict[str, tuple[str, str] | None] = {}
        self._canonical_project_fullname_cache: dict[str, str | None] = {}
        self._function_lookup_cache: dict[
            tuple[int, str, str | None, int | None], tuple[Any, str] | None
        ] = {}

    def _record_analysis_limitation(
        self, cap: str, *, target_count: int | None = None, limit: int | None = None
    ) -> None:
        deps = self._active_endpoint_dependencies
        if deps is not None and self._active_source_line > 0:
            deps.add_analysis_limitation(
                AnalysisLimitation(
                    self._active_source_file,
                    self._active_source_line,
                    cap,
                    target_count,
                    limit,
                    self._active_source_column,
                )
            )

    @property
    def cache_path(self) -> Path:
        """Path to the mypy analysis cache file."""
        if self._cache_file:
            return self._cache_file
        return self.source_root / ".endpoint_mypy_cache.json"

    @property
    def resolver_version(self) -> str:
        """Version of the typed resolver used for call-site provenance."""
        return self._resolver_version

    @property
    def verified_mypy_source_hashes(self) -> dict[str, str]:
        """Hashes of source bytes that matched mypy's parsed source digests."""
        return dict(self._verified_mypy_source_hashes)

    @property
    def verified_package_versions(self) -> dict[str, str]:
        """Versions from distribution metadata adjacent to parsed typed modules."""
        return dict(self._verified_package_versions)

    @property
    def verified_package_source_hashes(self) -> dict[str, str]:
        """Hashes of adjacent distribution metadata bytes read by the analyzer."""
        return dict(self._verified_package_source_hashes)

    def set_cache_path(self, path: Path) -> None:
        """Set a custom cache file path."""
        self._cache_file = path

    def set_line_progress_callback(self, callback: LineProgressCallback | None) -> None:
        """Set a callback for line-level progress reporting."""
        self._line_progress_callback = callback

    def _check_mypy_available(self) -> bool:
        """Check whether the two mypy APIs used by this analyzer are importable."""
        try:
            return find_spec("mypy.build") is not None and find_spec("mypy.nodes") is not None
        except (ImportError, ModuleNotFoundError, ValueError):
            return False

    def _get_source_root(self) -> Path:
        """Get the source root directory."""
        return self.source_root

    @staticmethod
    def _infer_module_root(source_root: Path) -> Path:
        """Choose a stable import root without incorporating the checkout basename."""
        if (source_root / "src").is_dir() and any((source_root / "src").rglob("*.py")):
            return source_root / "src"
        if (source_root / "__init__.py").is_file():
            return source_root.parent
        # A flat app directory is its own import root. Using its parent would
        # make analyzer module IDs inherit arbitrary checkout names such as
        # ``repo.with-hyphen``. Keep the one known stdlib collision isolated;
        # callers with a different custom package layout can pass module_root.
        return source_root.parent if (source_root / "types.py").is_file() else source_root

    @staticmethod
    def _module_name_from_path(path: Path, module_root: Path) -> str:
        """Derive a module ID relative to an explicit import root."""
        relative = path.relative_to(module_root)
        parts = list(relative.with_suffix("").parts)
        if parts and parts[-1] == "__init__":
            parts.pop()
        return ".".join(parts)

    def _read_discovered_source(self, path: Path) -> bytes | None:
        """Read one in-root regular source file without following a symlink."""
        try:
            relative = path.relative_to(self.source_root)
        except ValueError:
            return None
        if not relative.parts:
            return None
        current = self.source_root
        try:
            for part in relative.parts:
                current = current / part
                if current.is_symlink():
                    return None
            resolved = path.resolve(strict=True)
            resolved.relative_to(self.source_root)
            descriptor = os.open(
                path,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
            )
        except (OSError, ValueError):
            return None
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                return None
            with os.fdopen(descriptor, "rb") as source:
                descriptor = -1
                return source.read()
        except OSError:
            return None
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _source_records(self) -> list[tuple[Path, str, str]]:
        """Return canonical (path, module, digest) inputs from inventory or disk."""
        self._source_record_snapshots.clear()
        self._source_record_snapshot_bytes = 0
        inventory = self.source_inventory
        if inventory is not None:
            records = []
            for record in sorted(
                inventory.files,
                key=lambda item: (item.relative_path, item.module, str(item.path)),
            ):
                path = Path(record.path).resolve()
                expected = (Path(inventory.root) / record.relative_path).resolve()
                if path != expected:
                    raise MypyAnalyzerError(
                        f"source inventory path mismatch for {record.relative_path}"
                    )
                try:
                    source_bytes = path.read_bytes()
                    actual_digest = hashlib.sha256(source_bytes).hexdigest()
                except OSError as exc:
                    raise MypyAnalyzerError(
                        f"source inventory file is unavailable: {record.relative_path}"
                    ) from exc
                if actual_digest != record.sha256:
                    raise MypyAnalyzerError(f"source inventory is stale for {record.relative_path}")
                self._retain_source_record_snapshot(path, source_bytes)
                records.append((path, record.module, record.sha256))
            self._last_source_records = sorted(
                records, key=lambda record: (str(record[0]), record[1])
            )
            return self._last_source_records
        records = []
        for path in sorted(self.source_root.rglob("*.py"), key=str):
            if any(part.startswith((".", "__pycache__")) for part in path.parts):
                continue
            discovered_bytes = self._read_discovered_source(path)
            if discovered_bytes is None:
                continue
            try:
                try:
                    module = self._module_name_from_path(path, self.module_root)
                except ValueError:
                    module = self._module_name_from_path(path, self.source_root)
                digest = hashlib.sha256(discovered_bytes).hexdigest()
            except (OSError, ValueError):
                continue
            self._retain_source_record_snapshot(path, discovered_bytes)
            records.append((path, module, digest))
        self._last_source_records = sorted(records, key=lambda record: (str(record[0]), record[1]))
        return self._last_source_records

    def _retain_source_record_snapshot(self, path: Path, source_bytes: bytes) -> None:
        """Keep a bounded pre-build source snapshot for later verified reuse."""
        canonical = str(path.resolve())
        if len(source_bytes) > self.MAX_LAMBDA_SOURCE_FILE_BYTES or (
            self._source_record_snapshot_bytes + len(source_bytes)
            > self.MAX_LAMBDA_SOURCE_SNAPSHOT_BYTES
        ):
            self._source_record_snapshots[canonical] = None
            return
        self._source_record_snapshots[canonical] = source_bytes
        self._source_record_snapshot_bytes += len(source_bytes)

    def _ensure_mypy_built(self) -> None:
        """Ensure mypy has analyzed the project and we have the typed ASTs."""
        if self._trees:
            return

        if not self._mypy_available:
            raise MypyAnalyzerError("mypy is not installed")

        from mypy.build import build as mypy_build
        from mypy.build import default_data_dir
        from mypy.fscache import FileSystemCache
        from mypy.modulefinder import BuildSource
        from mypy.options import Options

        blocked_local_modules = self._unselected_local_modules()
        if self.source_inventory is not None:
            selected_modules = {record.module for record in self.source_inventory.files}
            policy_modules = {blocked[0] for blocked in blocked_local_modules}
            inventory_collisions = {
                module_name
                for module_name, _paths in getattr(self.source_inventory, "module_collisions", ())
            }
            ambiguous_modules = sorted(inventory_collisions | (selected_modules & policy_modules))
            if ambiguous_modules:
                raise MypyAnalyzerError(
                    "ambiguous local module identities in source inventory: "
                    + ", ".join(ambiguous_modules)
                )

        # Collect all Python files using a repository-independent import root.
        sources: list[BuildSource] = []
        source_records = (
            self._last_source_records
            if self._expected_source_fingerprint is not None
            else self._source_records()
        )
        for py_file, module_name, _digest in source_records:
            sources.append(BuildSource(path=str(py_file), module=module_name))
            self._module_to_path[module_name] = str(py_file)

        # Configure mypy for full analysis with AST retention
        options = Options()
        options.ignore_missing_imports = True
        if self.target_platform is not None:
            options.platform = self.target_platform
        options.no_site_packages = self.no_site_packages
        if self.no_site_packages:
            # The programmatic API defaults this to sys.executable, which makes
            # mypy add that interpreter's site-packages despite the flag.
            options.python_executable = None
        options.follow_imports = self._effective_follow_imports()
        blocked_local_paths: set[str] | None = None
        if self.source_inventory is not None:
            blocked_local_paths = set()
            for module_name, covers_children, path, is_stub in blocked_local_modules:
                blocked_local_paths.add(path)
                # Preserve normal typed imports for installed dependencies,
                # while preventing mypy from traversing local files rejected
                # by inventory include, exclude, or depth policy.
                module_options: dict[str, object] = {"follow_imports": "skip"}
                if is_stub:
                    module_options["follow_imports_for_stubs"] = True
                options.per_module_options[module_name] = module_options
                if covers_children:
                    options.per_module_options[f"{module_name}.*"] = module_options.copy()
        options.mypy_path = [str(self.module_root)]
        options.namespace_packages = True
        options.explicit_package_bases = True
        options.preserve_asts = True
        options.incremental = False
        options.check_untyped_defs = True
        options.export_types = True  # Critical for type information!

        original_path = sys.path.copy()
        original_mypypath = os.environ.pop("MYPYPATH", None) if self.no_site_packages else None
        if str(self.module_root) not in sys.path:
            sys.path.insert(0, str(self.module_root))

        try:
            fscache: FileSystemCache
            if self.no_site_packages and sys.platform != "win32":
                # mypy 1.19.1 unconditionally adds /usr/local/lib/mypy to its
                # typeshed search paths on POSIX. Hide that one ambient fallback
                # at the per-build filesystem boundary; changing modulefinder's
                # global path function would race with concurrent builds.
                class HermeticFileSystemCache(FileSystemCache):
                    def __init__(self) -> None:
                        super().__init__()
                        self._bundled_typeshed = Path(default_data_dir()).resolve() / "typeshed"

                    @staticmethod
                    def _is_fallback_path(path: str) -> bool:
                        # Check both spellings: mypy may receive the configured
                        # path while the OS resolves it through a symlink.
                        return _is_path_within(path, _MYPY_POSIX_FALLBACK_ROOT) or (
                            _is_path_within(
                                os.path.realpath(path),
                                os.path.realpath(_MYPY_POSIX_FALLBACK_ROOT),
                            )
                        )

                    def _is_blocked_fallback_path(self, path: str) -> bool:
                        if not self._is_fallback_path(path):
                            return False
                        return not _is_path_within(
                            os.path.realpath(path),
                            os.path.realpath(self._bundled_typeshed),
                        )

                    def stat_or_none(self, path: str) -> os.stat_result | None:
                        if self._is_blocked_fallback_path(path):
                            return None
                        return super().stat_or_none(path)

                    def listdir(self, path: str) -> list[str]:
                        if self._is_blocked_fallback_path(path):
                            raise FileNotFoundError(path)
                        return super().listdir(path)

                    def read(self, path: str) -> bytes:
                        if self._is_blocked_fallback_path(path):
                            raise FileNotFoundError(path)
                        return super().read(path)

                    def hash_digest(self, path: str) -> str:
                        if self._is_blocked_fallback_path(path):
                            raise FileNotFoundError(path)
                        return super().hash_digest(path)

                fscache = HermeticFileSystemCache()
            else:
                fscache = FileSystemCache()
            self._build_result = mypy_build(
                sources=sources,
                options=options,
                fscache=fscache,
                # mypy otherwise adds the process cwd even with no-site-packages.
                alt_lib_path=str(self.module_root) if self.no_site_packages else None,
            )
            self._verified_mypy_source_hashes = {}
            self._verified_package_source_hashes = {}
            self._verified_package_versions = {}
            conflicting_package_versions: set[str] = set()
            conflicting_mypy_source_paths: set[str] = set()
            conflicting_package_source_paths: set[str] = set()
            analyzed_source_hashes: dict[str, str] = {}
            scanned_metadata_roots: set[Path] = set()
            authenticated_metadata_hashes: dict[str, str] = {}

            # Store the types map
            self._types_map = self._build_result.types

            # Capture modules with trees. Followed imports may be needed for
            # typing, but only inventory-listed files belong to this snapshot's
            # semantic project identity set.
            inventory_paths = (
                {str(Path(record.path).resolve()) for record in self.source_inventory.files}
                if self.source_inventory is not None
                else None
            )
            for module_name, state in self._build_result.graph.items():
                state_path: str | None = None
                if state.path:
                    state_path = str(Path(state.path).resolve())
                    source_hash = getattr(state, "source_hash", None)
                    if isinstance(source_hash, str):
                        analyzed_source_hashes[state_path] = source_hash
                        source_file = Path(state_path)
                        try:
                            if source_file.is_file() and source_file.suffix in {".py", ".pyi"}:
                                vendor_bytes: bytes | None = source_file.read_bytes()
                            else:
                                vendor_bytes = None
                        except OSError:
                            # The module remains useful for type resolution, but
                            # unreadable bytes cannot authenticate package evidence.
                            vendor_bytes = None
                        if (
                            vendor_bytes is not None
                            and hashlib.sha1(vendor_bytes).hexdigest() == source_hash
                        ):
                            parts = module_name.split(".")
                            package_root = source_file.parent
                            while package_root.name in parts:
                                package_root = package_root.parent
                            try:
                                relative_source = source_file.relative_to(package_root).as_posix()
                            except ValueError:
                                relative_source = ""
                            if relative_source:
                                digest = "sha256:" + hashlib.sha256(vendor_bytes).hexdigest()
                                previous_digest = self._verified_mypy_source_hashes.get(
                                    relative_source
                                )
                                if previous_digest is not None and previous_digest != digest:
                                    conflicting_mypy_source_paths.add(relative_source)
                                    self._verified_mypy_source_hashes.pop(relative_source, None)
                                elif relative_source not in conflicting_mypy_source_paths:
                                    self._verified_mypy_source_hashes[relative_source] = digest
                            if relative_source and package_root not in scanned_metadata_roots:
                                scanned_metadata_roots.add(package_root)
                                metadata_candidates = sorted(
                                    package_root.glob("*.dist-info/METADATA")
                                )
                                for metadata_path in metadata_candidates:
                                    try:
                                        metadata_bytes = metadata_path.read_bytes()
                                    except OSError:
                                        # Missing evidence is deliberately absent
                                        # from the verified maps, so package pins
                                        # fail closed in the contract auditor.
                                        continue
                                    authenticated_metadata_hashes[str(metadata_path.resolve())] = (
                                        hashlib.sha256(metadata_bytes).hexdigest()
                                    )
                                    metadata = BytesParser(policy=compat32).parsebytes(
                                        metadata_bytes
                                    )
                                    metadata_distribution = canonicalize_name(
                                        str(metadata.get("Name", ""))
                                    )
                                    # Distribution and import names are not
                                    # interchangeable. Record adjacent metadata
                                    # under its own authenticated path/name;
                                    # contracts bind the exact metadata bytes.
                                    if metadata_distribution:
                                        metadata_relative = metadata_path.relative_to(
                                            package_root
                                        ).as_posix()
                                        metadata_digest = (
                                            "sha256:" + hashlib.sha256(metadata_bytes).hexdigest()
                                        )
                                        previous_metadata_digest = (
                                            self._verified_package_source_hashes.get(
                                                metadata_relative
                                            )
                                        )
                                        if (
                                            previous_metadata_digest is not None
                                            and previous_metadata_digest != metadata_digest
                                        ):
                                            conflicting_package_source_paths.add(metadata_relative)
                                            self._verified_package_source_hashes.pop(
                                                metadata_relative, None
                                            )
                                        elif (
                                            metadata_relative
                                            not in conflicting_package_source_paths
                                        ):
                                            self._verified_package_source_hashes[
                                                metadata_relative
                                            ] = metadata_digest
                                        version_text = metadata.get("Version")
                                        if (
                                            isinstance(version_text, str)
                                            and metadata_distribution
                                            not in conflicting_package_versions
                                        ):
                                            previous = self._verified_package_versions.get(
                                                metadata_distribution
                                            )
                                            if previous is not None and previous != version_text:
                                                conflicting_package_versions.add(
                                                    metadata_distribution
                                                )
                                                self._verified_package_versions.pop(
                                                    metadata_distribution, None
                                                )
                                            else:
                                                self._verified_package_versions[
                                                    metadata_distribution
                                                ] = version_text
                    if inventory_paths is None or state_path in inventory_paths:
                        self._module_to_path[module_name] = state_path
                tree = state.tree
                if tree is not None and (
                    blocked_local_paths is None
                    or state_path is None
                    or state_path not in blocked_local_paths
                ):
                    self._trees[module_name] = tree

            # State.source_hash is mypy's digest of the exact text it parsed.
            # Reuse a bounded pre-build byte snapshot only when that digest
            # matches, so a concurrent disk edit causes abstention.
            self._analysis_source_snapshots = {}
            self._lambda_source_ast_cache.clear()
            self._lambda_source_index_cache.clear()
            retained_bytes = 0
            for py_file, _module_name, _digest in source_records:
                canonical = str(py_file.resolve())
                snapshot = self._source_record_snapshots.get(canonical)
                if (
                    snapshot is None
                    or analyzed_source_hashes.get(canonical) != hashlib.sha1(snapshot).hexdigest()
                    or retained_bytes + len(snapshot) > self.MAX_LAMBDA_SOURCE_SNAPSHOT_BYTES
                    or self._decode_analysis_source(snapshot) is None
                ):
                    self._analysis_source_snapshots[canonical] = None
                    continue
                self._analysis_source_snapshots[canonical] = snapshot
                retained_bytes += len(snapshot)

            self._project_modules = set()
            modules_by_path: dict[str, list[str]] = {}
            for module_name, module_path in self._module_to_path.items():
                try:
                    canonical = str(Path(module_path).resolve())
                    Path(canonical).relative_to(self.source_root)
                except (OSError, ValueError):
                    continue
                self._project_modules.add(module_name)
                modules_by_path.setdefault(canonical, []).append(module_name)
            self._modules_by_canonical_path = {
                path: tuple(sorted(module_names)) for path, module_names in modules_by_path.items()
            }
            self._shared_path_index = None
            self._typed_environment_fingerprint = self._fingerprint_typed_environment(
                authenticated_metadata_hashes=authenticated_metadata_hashes,
                authenticated_metadata_roots=scanned_metadata_roots,
            )
            self._built_source_fingerprint = self._expected_source_fingerprint

        finally:
            sys.path = original_path
            if self.no_site_packages and original_mypypath is not None:
                os.environ["MYPYPATH"] = original_mypypath

    def _effective_follow_imports(self) -> str:
        """Translate inventory policy to mypy's string option vocabulary."""
        value = getattr(self.source_inventory, "follow_imports", True)
        if isinstance(value, bool):
            return "normal" if value else "skip"
        # Accept the protocol used by early adopters while canonical inventories
        # encode this policy as a boolean.
        if isinstance(value, str) and value in {
            "normal",
            "skip",
            "silent",
            "error",
            "error_per_module",
        }:
            return value
        raise MypyAnalyzerError(f"unsupported source inventory follow_imports policy: {value!r}")

    def _begin_analysis_cycle(self) -> None:
        """Discover local exclusions once before a bulk-analysis snapshot."""
        if self._local_module_census_depth == 0:
            self._local_module_census = self._discover_unselected_local_modules()
            self._analysis_build_failed = False
        self._local_module_census_depth += 1

    def _end_analysis_cycle(self) -> None:
        """Release the census so the next independent analysis sees new files."""
        self._local_module_census_depth -= 1
        if self._local_module_census_depth == 0:
            self._local_module_census = None

    def _unselected_local_modules(self) -> tuple[tuple[str, bool, str, bool], ...]:
        """Share a census within a bulk snapshot; otherwise discover afresh."""
        if self._local_module_census_depth:
            assert self._local_module_census is not None
            return self._local_module_census
        return self._discover_unselected_local_modules()

    def _discover_unselected_local_modules(self) -> tuple[tuple[str, bool, str, bool], ...]:
        """Return local module identities outside the canonical inventory.

        Ordinary modules block their submodule namespace. Package
        initializers are exact-only so an unselected initializer cannot
        suppress an inventory-selected child. Rejected symlinks are mapped
        from their lexical paths without reading their targets.
        """
        if self.source_inventory is None:
            return ()
        selected_paths = {
            str(Path(record.path).resolve()) for record in self.source_inventory.files
        }
        modules: dict[str, tuple[bool, set[str], bool]] = {}
        paths = sorted(
            (
                item
                for item in self.source_root.rglob("*")
                if item.is_symlink() or item.suffix in {".py", ".pyi"}
            ),
            key=str,
        )
        for path in paths:
            if path.suffix not in {".py", ".pyi"}:
                continue
            try:
                relative = path.relative_to(self.source_root)
                current = self.source_root
                for part in relative.parts:
                    current = current / part
                    if current.is_symlink():
                        raise ValueError("symlink source")
                canonical = str(path.resolve(strict=True))
                Path(canonical).relative_to(self.source_root)
                if canonical in selected_paths:
                    continue
                module = self._module_name_from_path(Path(canonical), self.module_root)
            except (OSError, ValueError):
                continue
            covers_children = path.stem != "__init__"
            previous = modules.get(module)
            modules[module] = (
                covers_children or (previous[0] if previous else False),
                ({canonical} | previous[1]) if previous else {canonical},
                path.suffix == ".pyi" or (previous[2] if previous else False),
            )

        # pathlib does not recurse through directory symlinks here; enumerate
        # the links themselves and derive module IDs from their in-root names.
        for path in paths:
            if not path.is_symlink():
                continue
            try:
                if path.is_dir():
                    covers_children = True
                    has_stubs = True
                elif path.suffix in {".py", ".pyi"}:
                    covers_children = path.stem != "__init__"
                    has_stubs = path.suffix == ".pyi"
                else:
                    continue
                module = self._module_name_from_path(path, self.module_root)
            except (OSError, ValueError):
                continue
            previous = modules.get(module)
            # Keep the link path lexical: resolving it here could mark a
            # selected target file as blocked through a second import name.
            modules[module] = (
                covers_children or (previous[0] if previous else False),
                ({str(path)} | previous[1]) if previous else {str(path)},
                has_stubs or (previous[2] if previous else False),
            )
        return tuple(
            (module, covers_children, path, has_stubs)
            for module, (covers_children, paths, has_stubs) in sorted(modules.items())
            for path in sorted(paths)
        )

    def _reset_build_state(
        self,
        *,
        clear_endpoint_dependencies: bool = True,
        clear_source_records: bool = False,
    ) -> None:
        """Discard one stale typed snapshot before an explicit bulk rebuild."""
        self._build_result = None
        self._trees.clear()
        self._module_to_path.clear()
        self._types_map.clear()
        self._project_modules.clear()
        self._global_value_cache.clear()
        self._python_dependency_cache.clear()
        self._python_ast_cache.clear()
        self._python_ast_nodes_cache.clear()
        self._python_verified_call_spans.clear()
        self._python_call_span_abstained.clear()
        self._call_source_snapshot_cache.clear()
        self._source_bytes_cache.clear()
        if clear_source_records:
            self._source_record_snapshots.clear()
            self._source_record_snapshot_bytes = 0
            self._last_source_records.clear()
        self._analysis_source_snapshots.clear()
        self._lambda_source_ast_cache.clear()
        self._lambda_source_index_cache.clear()
        self._resolved_call_site_cache.clear()
        self._finite_global_value_cache.clear()
        self._finite_global_in_progress.clear()
        self._exact_project_identity_cache.clear()
        self._modules_by_canonical_path.clear()
        self._shared_path_index = None
        self._fullname_resolution_cache.clear()
        self._canonical_project_fullname_cache.clear()
        self._function_lookup_cache.clear()
        self._built_source_fingerprint = None
        if clear_endpoint_dependencies:
            self._endpoint_deps.clear()

    def release_typed_snapshot(self) -> None:
        """Release heavy mypy AST/type graphs while retaining materialized endpoint results."""
        self._reset_build_state(clear_endpoint_dependencies=False, clear_source_records=True)
        gc.collect()

    def _find_func_in_tree(
        self,
        tree: Any,
        func_name: str,
        *,
        qualified_name: str | None = None,
        line_hint: int | None = None,
    ) -> tuple[Any, str] | None:
        """Resolve one function with snapshot-local memoization."""
        key = (id(tree), func_name, qualified_name, line_hint)
        if key not in self._function_lookup_cache:
            self._function_lookup_cache[key] = self._find_func_in_tree_uncached(
                tree,
                func_name,
                qualified_name=qualified_name,
                line_hint=line_hint,
            )
        return self._function_lookup_cache[key]

    def _find_func_in_tree_uncached(
        self,
        tree: Any,
        func_name: str,
        *,
        qualified_name: str | None = None,
        line_hint: int | None = None,
    ) -> tuple[Any, str] | None:
        """Resolve one function by qualified identity or source location."""
        from mypy.nodes import (
            Block,
            ClassDef,
            Decorator,
            ForStmt,
            FuncDef,
            IfStmt,
            MatchStmt,
            OverloadedFuncDef,
            TryStmt,
            WhileStmt,
            WithStmt,
        )

        candidates: list[tuple[Any, str]] = []
        for defn in tree.defs:
            if isinstance(defn, FuncDef) and defn.name == func_name:
                candidates.append((defn, defn.name))
            elif isinstance(defn, Decorator) and defn.func.name == func_name:
                candidates.append((defn, defn.func.name))
            elif isinstance(defn, OverloadedFuncDef) and defn.name == func_name:
                implementation = getattr(defn, "impl", None)
                if implementation is not None:
                    candidates.append((implementation, defn.name))
                elif defn.items:
                    candidates.append((defn.items[0], defn.name))
            elif isinstance(defn, ClassDef):
                for item in defn.defs.body:
                    if isinstance(item, FuncDef) and item.name == func_name:
                        candidates.append((item, f"{defn.name}.{item.name}"))
                    elif isinstance(item, Decorator) and item.func.name == func_name:
                        candidates.append((item, f"{defn.name}.{item.func.name}"))
                    elif isinstance(item, OverloadedFuncDef) and item.name == func_name:
                        implementation = getattr(item, "impl", None)
                        selected = implementation or (item.items[0] if item.items else None)
                        if selected is not None:
                            candidates.append((selected, f"{defn.name}.{item.name}"))

        if qualified_name and "." in qualified_name:
            nested_candidates: list[tuple[Any, str]] = []

            def nested_statement(statement: Any, parent: str) -> None:
                if isinstance(statement, Block):
                    for child in statement.body:
                        nested_statement(child, parent)
                elif isinstance(statement, (FuncDef, Decorator, OverloadedFuncDef)):
                    function = (
                        statement.func
                        if isinstance(statement, Decorator)
                        else getattr(statement, "impl", None) or statement
                    )
                    nested_name = getattr(function, "name", None)
                    if not isinstance(nested_name, str):
                        return
                    nested_fullname = f"{parent}.{nested_name}"
                    if nested_fullname == qualified_name:
                        nested_candidates.append((function, nested_fullname))
                    body = getattr(function, "body", None)
                    if body is not None:
                        nested_statement(body, nested_fullname)
                elif isinstance(statement, ClassDef):
                    class_fullname = f"{parent}.{statement.name}"
                    for child in statement.defs.body:
                        nested_statement(child, class_fullname)
                elif isinstance(statement, IfStmt):
                    for block in statement.body:
                        nested_statement(block, parent)
                    if statement.else_body is not None:
                        nested_statement(statement.else_body, parent)
                elif isinstance(statement, (ForStmt, WhileStmt)):
                    nested_statement(statement.body, parent)
                    if statement.else_body is not None:
                        nested_statement(statement.else_body, parent)
                elif isinstance(statement, WithStmt):
                    nested_statement(statement.body, parent)
                elif isinstance(statement, TryStmt):
                    nested_statement(statement.body, parent)
                    for handler in statement.handlers:
                        nested_statement(handler, parent)
                    if statement.else_body is not None:
                        nested_statement(statement.else_body, parent)
                    if statement.finally_body is not None:
                        nested_statement(statement.finally_body, parent)
                elif isinstance(statement, MatchStmt):
                    for body in statement.bodies:
                        nested_statement(body, parent)

            for definition in tree.defs:
                if isinstance(definition, FuncDef):
                    nested_statement(definition.body, definition.name)
                elif isinstance(definition, Decorator):
                    nested_statement(definition.func.body, definition.func.name)
                elif isinstance(definition, OverloadedFuncDef):
                    implementation = getattr(definition, "impl", None)
                    if implementation is not None:
                        nested_statement(implementation.body, definition.name)
                elif isinstance(definition, ClassDef):
                    for method in definition.defs.body:
                        if isinstance(method, FuncDef):
                            nested_statement(method.body, f"{definition.name}.{method.name}")
                        elif isinstance(method, Decorator):
                            nested_statement(
                                method.func.body,
                                f"{definition.name}.{method.func.name}",
                            )
            exact_nested = [item for item in nested_candidates if item[1] == qualified_name]
            if len(exact_nested) == 1:
                return exact_nested[0]

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

    def _callable_header_lines(self, func_node: Any, file_path: str) -> tuple[int, int]:
        """Return decorator and declaration-header lines, excluding the body."""
        import ast

        line = int(getattr(func_node, "line", 1) or 1)
        fallback = (line, line)
        try:
            module = ast.parse(Path(file_path).read_text(encoding="utf-8"))
        except (OSError, SyntaxError, UnicodeDecodeError):
            return fallback
        name = getattr(func_node, "name", None)
        matches = [
            item
            for item in ast.walk(module)
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            and item.name == name
            and (
                item.lineno == line
                or min([item.lineno, *(decorator.lineno for decorator in item.decorator_list)])
                == line
            )
        ]
        if len(matches) != 1:
            return fallback
        definition = matches[0]
        start = min(
            [definition.lineno, *(decorator.lineno for decorator in definition.decorator_list)]
        )
        # A separate first body line gives an unambiguous header boundary.
        # Inline bodies share their line with the declaration and stay
        # conservatively indivisible.
        end = definition.body[0].lineno - 1 if definition.body else definition.lineno
        return start, max(start, end)

    def _lambda_body_source_span(
        self,
        func_node: Any,
        lambda_node: Any,
        file_path: str,
        execution_state: str,
    ) -> SourceEvidenceSpan | None:
        """Map a mypy lambda to one unique CPython body span or abstain."""
        import ast

        actual = self._actual_function(func_node)
        function_name = getattr(actual, "name", None)
        function_line = int(getattr(actual, "line", 0) or 0)
        lambda_line = int(getattr(lambda_node, "line", 0) or 0)
        if not isinstance(function_name, str) or function_line < 1 or lambda_line < 1:
            return None
        canonical = str(Path(file_path).resolve())
        if canonical not in self._lambda_source_ast_cache:
            snapshot = self._analysis_source_snapshots.get(canonical)
            if snapshot is None:
                self._lambda_source_ast_cache[canonical] = None
                return None
            source = self._decode_analysis_source(snapshot)
            if source is None:
                self._lambda_source_ast_cache[canonical] = None
                return None
            try:
                self._lambda_source_ast_cache[canonical] = ast.parse(source, filename=canonical)
            except (SyntaxError, ValueError, RecursionError):
                self._lambda_source_ast_cache[canonical] = None
                return None
        module = self._lambda_source_ast_cache[canonical]
        if module is None:
            return None
        index = self._lambda_source_index(canonical, module)
        if index is None:
            return None
        lambdas = index.get((function_name, function_line, lambda_line), ())
        if len(lambdas) != 1:
            return None
        body = lambdas[0].body
        public_state = cast(
            "SourceExecutionState",
            {
                "executed": "established_execution",
                "deferred": "deferred_execution",
                "possible": "possible_execution",
                "lexical": "lexical_reference",
            }.get(execution_state, "possible_execution"),
        )
        return SourceEvidenceSpan(
            file_path=canonical,
            start_line=body.lineno,
            start_column=body.col_offset,
            end_line=body.end_lineno or body.lineno,
            end_column=body.end_col_offset or body.col_offset,
            execution_state=public_state,
            provenance=(
                "exact lambda body mapped from retained source; "
                + {
                    "lexical_reference": "lambda reference observed without body execution proof",
                    "possible_execution": "invocation occurs on a bounded conditional or loop path",
                    "established_execution": "invocation recorded by bounded callable traversal",
                    "deferred_execution": "callable body is deferred pending invocation",
                }[public_state]
            ),
        )

    def _lambda_source_index(
        self, canonical: str, module: ast.Module
    ) -> dict[tuple[str, int, int], tuple[ast.Lambda, ...]] | None:
        """Index lambda candidates by enclosing function and source line once per file."""
        if canonical in self._lambda_source_index_cache:
            return self._lambda_source_index_cache[canonical]
        from collections import defaultdict

        candidates: dict[tuple[str, int, int], list[ast.Lambda]] = defaultdict(list)
        stack: list[tuple[ast.AST, tuple[tuple[str, int], ...]]] = [(module, ())]
        visited = 0
        while stack:
            node, function_ancestors = stack.pop()
            visited += 1
            if visited > self.MAX_LAMBDA_SOURCE_AST_NODES:
                self._lambda_source_index_cache[canonical] = None
                return None
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                function_ancestors = (*function_ancestors, (node.name, node.lineno))
            if isinstance(node, ast.Lambda):
                for name, line in function_ancestors:
                    candidates[(name, line, node.lineno)].append(node)
            for child in reversed(list(ast.iter_child_nodes(node))):
                stack.append((child, function_ancestors))
        indexed = {key: tuple(values) for key, values in candidates.items()}
        self._lambda_source_index_cache[canonical] = indexed
        return indexed

    @staticmethod
    def _decode_analysis_source(source_bytes: bytes | None) -> str | None:
        """Decode one captured source snapshot using Python's source encoding rules."""
        if source_bytes is None:
            return None
        try:
            encoding, _ = tokenize.detect_encoding(io.BytesIO(source_bytes).readline)
            return source_bytes.decode(encoding)
        except (SyntaxError, UnicodeDecodeError, LookupError):
            return None

    def _resolve_fullname_to_file(self, fullname: str) -> tuple[str, str] | None:
        """Resolve one fullname with snapshot-local memoization."""
        if fullname not in self._fullname_resolution_cache:
            self._fullname_resolution_cache[fullname] = self._resolve_fullname_to_file_uncached(
                fullname
            )
        return self._fullname_resolution_cache[fullname]

    def _resolve_fullname_to_file_uncached(self, fullname: str) -> tuple[str, str] | None:
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
        suffix_matches = []
        for mod_name, module_path in self._module_to_path.items():
            if not (mod_name.endswith(f".{parts[0]}") or mod_name == parts[0]):
                continue
            try:
                Path(module_path).resolve().relative_to(self.source_root)
            except ValueError:
                continue
            suffix_matches.append(mod_name)
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

    def _add_global_value_reference(self, deps: EndpointDependencies, fullname: str) -> None:
        """Record a project global at its definition rather than its use-site."""
        first_component = fullname.split(".", maxsplit=1)[0]
        if not any(
            fullname.startswith(f"{module}.") or module.endswith(f".{first_component}")
            for module in self._project_modules
        ):
            return
        if fullname in self._global_value_cache:
            reference = self._global_value_cache[fullname]
            if reference is not None and reference not in deps.referenced_symbols:
                deps.add_symbol_reference(
                    reference.file_path,
                    reference.symbol_name,
                    reference.start_line,
                    reference.end_line,
                )
            return
        resolved = self._resolve_fullname_to_file(fullname)
        if resolved is None:
            self._global_value_cache[fullname] = None
            return
        target_path, target_module = resolved
        tree = self._trees.get(target_module)
        if tree is None:
            self._global_value_cache[fullname] = None
            return
        symbol_name = fullname.rsplit(".", maxsplit=1)[-1]
        symbol = getattr(tree, "names", {}).get(symbol_name)
        node = getattr(symbol, "node", None)
        if node is None or type(node).__name__ != "Var":
            self._global_value_cache[fullname] = None
            return
        node_fullname = getattr(node, "fullname", None)
        if node_fullname and node_fullname != fullname:
            self._global_value_cache[fullname] = None
            return
        line = getattr(node, "line", 0)
        if line <= 0:
            self._global_value_cache[fullname] = None
            return
        reference = SymbolReference(
            target_path,
            fullname,
            line,
            getattr(node, "end_line", None) or line,
        )
        self._global_value_cache[fullname] = reference
        deps.add_symbol_reference(
            reference.file_path,
            reference.symbol_name,
            reference.start_line,
            reference.end_line,
        )

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

    def _python_dependency_fullnames(self, endpoint: Endpoint) -> set[str]:
        """Resolve explicit FastAPI Depends/Security callables without execution."""
        path = endpoint.handler.file_path
        cache_key = (str(path.resolve()), endpoint.handler.line_number, endpoint.handler.name)
        cached = self._python_dependency_cache.get(cache_key)
        if cached is not None:
            return set(cached)
        path_key = str(path.resolve())
        if path_key not in self._python_ast_cache:
            try:
                self._python_ast_cache[path_key] = ast.parse(
                    path.read_text(encoding="utf-8"), filename=str(path)
                )
            except (OSError, SyntaxError, UnicodeError):
                self._python_ast_cache[path_key] = None
        tree = self._python_ast_cache[path_key]
        if tree is None:
            return set()
        imports: dict[str, str] = {}
        aliases: dict[str, ast.expr] = {}
        package = endpoint.handler.module.rpartition(".")[0]
        for statement in tree.body:
            if isinstance(statement, ast.ImportFrom):
                module = statement.module or ""
                if statement.level and package:
                    parts = package.split(".")
                    parts = parts[: len(parts) - max(statement.level - 1, 0)]
                    module = ".".join([*parts, module] if module else parts)
                for name in statement.names:
                    imports[name.asname or name.name] = f"{module}.{name.name}"
            elif isinstance(statement, ast.Import):
                for name in statement.names:
                    imports[name.asname or name.name.split(".")[0]] = name.name
            elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
                assigned = (
                    statement.target.id
                    if isinstance(statement, ast.AnnAssign)
                    and isinstance(statement.target, ast.Name)
                    else statement.targets[0].id
                    if isinstance(statement, ast.Assign)
                    and len(statement.targets) == 1
                    and isinstance(statement.targets[0], ast.Name)
                    else None
                )
                if assigned is not None and statement.value is not None:
                    aliases[assigned] = statement.value

        functions = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == endpoint.handler.name
            and (
                node.lineno <= endpoint.handler.line_number <= (node.end_lineno or node.lineno)
                or endpoint.handler.line_number
                <= node.lineno
                <= (endpoint.handler.end_line_number or endpoint.handler.line_number)
            )
        ]
        if len(functions) != 1:
            return set()
        function = functions[0]
        expressions: list[ast.expr] = [*function.decorator_list]
        expressions.extend(
            expression
            for argument in [
                *function.args.posonlyargs,
                *function.args.args,
                *function.args.kwonlyargs,
            ]
            if (expression := argument.annotation) is not None
        )
        expressions.extend(expression for expression in function.args.defaults if expression)
        expressions.extend(
            expression for expression in function.args.kw_defaults if expression is not None
        )

        def callable_fullname(expression: ast.expr) -> str | None:
            if isinstance(expression, ast.Name):
                return imports.get(expression.id, f"{endpoint.handler.module}.{expression.id}")
            if isinstance(expression, ast.Attribute) and isinstance(expression.value, ast.Name):
                owner = imports.get(expression.value.id)
                if owner:
                    return f"{owner}.{expression.attr}"
            return None

        found: set[str] = set()
        visited_aliases: set[str] = set()

        def inspect(expression: ast.expr) -> None:
            if isinstance(expression, ast.Name) and expression.id in aliases:
                if expression.id not in visited_aliases:
                    visited_aliases.add(expression.id)
                    inspect(aliases[expression.id])
                return
            for node in ast.walk(expression):
                if not isinstance(node, ast.Call):
                    continue
                registration = callable_fullname(node.func)
                if (
                    registration
                    not in {
                        "fastapi.Depends",
                        "fastapi.Security",
                        "fastapi.param_functions.Depends",
                        "fastapi.param_functions.Security",
                        "fastapi.params.Depends",
                        "fastapi.params.Security",
                    }
                    or not node.args
                ):
                    continue
                fullname = callable_fullname(node.args[0])
                if fullname is not None:
                    found.add(fullname)

        for expression in expressions:
            inspect(expression)

        def injected_type(expression: ast.expr | None, seen: set[str]) -> str | None:
            if isinstance(expression, ast.Name):
                if expression.id in aliases and expression.id not in seen:
                    return injected_type(aliases[expression.id], seen | {expression.id})
                return imports.get(expression.id, f"{endpoint.handler.module}.{expression.id}")
            if isinstance(expression, ast.Subscript):
                owner = (
                    expression.value.id
                    if isinstance(expression.value, ast.Name)
                    else expression.value.attr
                    if isinstance(expression.value, ast.Attribute)
                    else ""
                )
                if owner == "Annotated":
                    elements = (
                        expression.slice.elts
                        if isinstance(expression.slice, ast.Tuple)
                        else [expression.slice]
                    )
                    return injected_type(elements[0], seen) if elements else None
            return None

        parameter_types: dict[str, str] = {}
        for argument in [
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        ]:
            fullname = injected_type(argument.annotation, set())
            if fullname is not None:
                parameter_types[argument.arg] = fullname
        for node in ast.walk(function):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in parameter_types
            ):
                found.add(f"{parameter_types[node.func.value.id]}.{node.func.attr}")
        self._python_dependency_cache[cache_key] = set(found)
        return found

    def _runtime_dependency_seeds(self, endpoint: Endpoint) -> dict[str, int]:
        """Return only uniquely source-attested project-local runtime graph seeds."""
        graph = endpoint.dependency_graph
        if graph is None:
            return {}
        seeds: dict[str, int] = {}
        canonical_root = self.source_root.resolve()
        for occurrence in graph.occurrences:
            if (
                occurrence.resolution_status != DependencyResolutionStatus.ESTABLISHED
                or occurrence.callable_kind
                not in {DependencyCallableKind.FUNCTION, DependencyCallableKind.BOUND_METHOD}
                or occurrence.module is None
                or occurrence.qualname is None
                or occurrence.source_span is None
                or occurrence.display_name == "<lambda>"
                or "<locals>" in occurrence.qualname
            ):
                continue
            fullname = f"{occurrence.module}.{occurrence.qualname}"
            resolved = self._resolve_fullname_to_file(fullname)
            if resolved is None:
                continue
            definition_path, definition_module = resolved
            if definition_module != occurrence.module and not definition_module.endswith(
                f".{occurrence.module}"
            ):
                continue
            try:
                runtime_path = occurrence.source_span.file_path.resolve()
                mypy_path = Path(definition_path).resolve()
                runtime_path.relative_to(canonical_root)
                mypy_path.relative_to(canonical_root)
            except (OSError, ValueError):
                continue
            if runtime_path != mypy_path:
                continue
            dependency_tree = self._trees.get(definition_module)
            if dependency_tree is None:
                continue
            symbol_name = occurrence.qualname.rsplit(".", maxsplit=1)[-1]
            result = self._find_func_in_tree(
                dependency_tree,
                symbol_name,
                qualified_name=occurrence.qualname,
            )
            if result is None or result[1] != occurrence.qualname:
                continue
            definition_node = getattr(result[0], "func", result[0])
            definition_start, definition_end = self._get_func_lines(definition_node)
            if (
                occurrence.source_span.end_line < definition_start
                or occurrence.source_span.start_line > definition_end
            ):
                continue
            canonical_fullname = f"{definition_module}.{result[1]}"
            previous = seeds.get(canonical_fullname)
            if previous is None or occurrence.depth < previous:
                seeds[canonical_fullname] = occurrence.depth
        return seeds

    def _python_dependency_closure(self, endpoint: Endpoint) -> dict[str, int]:
        """Expand explicit and source-attested runtime dependencies to bounded depth."""
        depths: dict[str, int] = {}
        initial = dict.fromkeys(self._python_dependency_fullnames(endpoint), 1)
        for fullname, depth in self._runtime_dependency_seeds(endpoint).items():
            initial[fullname] = min(initial.get(fullname, depth), depth)
        queue = list(initial.items())
        while queue:
            fullname, depth = queue.pop(0)
            previous = depths.get(fullname)
            if depth > self.max_depth or (previous is not None and previous <= depth):
                continue
            depths[fullname] = depth
            if self._generator_fullname_kind(fullname) is not None:
                continue
            resolved = self._resolve_fullname_to_file(fullname)
            if resolved is None or depth >= self.max_depth:
                continue
            dependency_path, dependency_module = resolved
            dependency_tree = self._trees.get(dependency_module)
            if dependency_tree is None:
                continue
            qualified_name = (
                fullname[len(dependency_module) + 1 :]
                if fullname.startswith(f"{dependency_module}.")
                else fullname.rsplit(".", maxsplit=1)[-1]
            )
            symbol_name = qualified_name.rsplit(".", maxsplit=1)[-1]
            dependency_result = self._find_func_in_tree(
                dependency_tree,
                symbol_name,
                qualified_name=qualified_name,
            )
            if dependency_result is None:
                continue
            node, _qualified = dependency_result
            start, end = self._get_func_lines(node)
            nested_endpoint = endpoint.model_copy(
                update={
                    "handler": endpoint.handler.model_copy(
                        update={
                            "name": symbol_name,
                            "module": dependency_module,
                            "file_path": Path(dependency_path),
                            "line_number": start,
                            "end_line_number": end,
                        }
                    )
                }
            )
            queue.extend(
                (nested, depth + 1) for nested in self._python_dependency_fullnames(nested_endpoint)
            )
        return depths

    @staticmethod
    def _endpoint_key(endpoint: Endpoint) -> str:
        """Key dependency data by route, handler, and authoritative runtime graph."""
        handler = endpoint.handler
        graph_payload = (
            None
            if endpoint.dependency_graph is None
            else endpoint.dependency_graph.model_dump(mode="json")
        )
        graph_hash = hashlib.sha256(
            json.dumps(
                graph_payload,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        return json.dumps(
            [
                endpoint.identifier,
                str(handler.file_path.resolve()),
                handler.line_number,
                handler.name,
                handler.module,
                graph_hash,
            ],
            separators=(",", ":"),
        )

    def _project_path_index(self) -> _ProjectPathIndex:
        """Build one lookup inventory, reusing mypy's module paths when available."""
        if self._shared_path_index is None:
            project_files: set[str] = set()
            candidates: Iterable[Path]
            if self._module_to_path:
                candidates = (Path(path) for path in self._module_to_path.values())
            else:
                candidates = self.source_root.rglob("*.py")
            for path in candidates:
                try:
                    canonical = path.resolve()
                    canonical.relative_to(self.source_root)
                except (OSError, ValueError):
                    continue
                if canonical.suffix == ".py":
                    project_files.add(str(canonical))
            self._shared_path_index = _ProjectPathIndex(
                str(self.source_root), frozenset(project_files)
            )
        return self._shared_path_index

    def analyze_endpoint(self, endpoint: Endpoint) -> EndpointDependencies:
        """Analyze a single endpoint using mypy's typed AST."""
        if self._local_module_census_depth == 0:
            self._analysis_build_failed = False
        try:
            self._ensure_mypy_built()
        except MypyAnalyzerError:
            self._analysis_build_failed = True
        path_index = self._project_path_index()
        deps = EndpointDependencies(
            endpoint_id=endpoint.identifier,
            methods=[m.value for m in endpoint.methods],
            path=endpoint.path,
            source_root=str(self.source_root),
            project_files=path_index.project_files,
            analysis_incomplete=bool(
                self._analysis_build_failed
                or (
                    self.source_inventory is not None
                    and getattr(self.source_inventory, "unresolved_imports", ())
                )
            ),
            build_failed=self._analysis_build_failed,
            unresolved_imports=tuple(
                tuple(item)
                for item in (
                    getattr(self.source_inventory, "unresolved_imports", ())
                    if self.source_inventory is not None
                    else ()
                )
            ),
            _path_index=path_index,
        )
        self._active_endpoint_dependencies = deps

        handler = endpoint.handler
        if not handler.file_path or not self._trees:
            self._endpoint_deps[self._endpoint_key(endpoint)] = deps
            return deps

        # Find the module containing the handler through the build-time reverse index.
        handler_path = str(Path(handler.file_path).resolve())
        module_candidates = self._modules_by_canonical_path.get(handler_path, ())
        handler_module = (
            handler.module
            if handler.module in module_candidates
            else module_candidates[0]
            if module_candidates
            else None
        )

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

        function_start, function_end = self._get_func_lines(actual_func)
        callback_range = (
            endpoint.surface.callback_range
            if endpoint.surface is not None
            else CallbackRangeMode.FULL
        )
        if callback_range == CallbackRangeMode.FULL:
            start, end = function_start, function_end
        else:
            start = handler.line_number
            end = handler.end_line_number or start
        deps.add_symbol_reference(handler_path, handler.name, start, end)

        import_map = self._import_map_for_tree(tree, handler_module)

        # Trace all references in the function body.
        visited: dict[
            tuple[
                str,
                bool,
                _FinitePointsTo | None,
                tuple[tuple[str, _FinitePointsTo], ...],
                tuple[tuple[str, tuple[str, ...]], ...],
                tuple[
                    tuple[
                        str,
                        tuple[tuple[str, InvocationKind], _FinitePointsTo | None],
                    ],
                    ...,
                ],
            ],
            int,
        ] = {}
        call_stack = [CallFrame(handler_path, start, handler.name)]

        for dependency_fullname, dependency_depth in sorted(
            self._python_dependency_closure(endpoint).items()
        ):
            if self._generator_fullname_kind(dependency_fullname) is not None:
                # Typed-parameter closure is reachability-only and cannot prove
                # that a deferred generator object is consumed.
                continue
            resolved = self._resolve_fullname_to_file(dependency_fullname)
            if resolved is None:
                continue
            dependency_path, dependency_module = resolved
            dependency_tree = self._trees.get(dependency_module)
            if dependency_tree is None:
                continue
            symbol_name = (
                dependency_fullname[len(dependency_module) + 1 :]
                if dependency_fullname.startswith(f"{dependency_module}.")
                else dependency_fullname.rsplit(".", maxsplit=1)[-1]
            )
            dependency_result = self._find_func_in_tree(
                dependency_tree,
                symbol_name.rsplit(".", maxsplit=1)[-1],
                qualified_name=symbol_name,
            )
            if dependency_result is None:
                continue
            dependency_node, _qualified_name = dependency_result
            dependency_start, dependency_end = self._callable_header_lines(
                dependency_node, dependency_path
            )
            deps.add_symbol_reference(
                dependency_path,
                dependency_fullname,
                dependency_start,
                dependency_end,
            )
            visited[(dependency_fullname, False, None, (), (), ())] = dependency_depth
            if dependency_depth < self.max_depth:
                self._trace_references(
                    dependency_node,
                    deps,
                    dependency_path,
                    dependency_module,
                    [
                        *call_stack,
                        CallFrame(
                            dependency_path,
                            dependency_start,
                            dependency_fullname,
                        ),
                    ],
                    visited,
                    self._import_map_for_tree(dependency_tree, dependency_module),
                    depth=dependency_depth,
                )
            elif dependency_module in self._project_modules:
                call_site = next(
                    (
                        site
                        for site in deps.resolved_call_sites
                        if site.canonical_symbol == dependency_fullname
                        and site.file_path == handler_path
                    ),
                    None,
                )
                self._active_source_file = handler_path
                self._active_source_line = (
                    call_site.line if call_site is not None else handler.line_number
                )
                self._active_source_column = call_site.column if call_site is not None else None
                self._record_analysis_limitation("MAX_DEPTH", limit=self.max_depth)

        trace_roots: list[Any]
        if callback_range == CallbackRangeMode.FULL:
            trace_roots = [func_node]
        else:
            body = list(getattr(getattr(actual_func, "body", None), "body", ()))
            if callback_range == CallbackRangeMode.BEFORE_YIELD:
                trace_roots = [node for node in body if 0 < node.line < end]
            else:
                trace_roots = [node for node in body if node.line > start]
        for trace_root in trace_roots:
            self._trace_references(
                trace_root,
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

    def _call_source_identity(
        self,
        current_file: str,
        callee: Any,
    ) -> tuple[int, int, int | None, int | None, str] | None:
        """Return a source AST span paired to this exact mypy call occurrence."""
        canonical = str(Path(current_file).resolve())
        if canonical in self._python_call_span_abstained:
            return None
        if canonical not in self._python_verified_call_spans:
            self._python_verified_call_spans[canonical] = self._match_python_and_mypy_calls(
                canonical
            )
        if canonical in self._python_call_span_abstained:
            return None
        span = self._python_verified_call_spans[canonical].get(id(callee))
        if span is None:
            span = self._exact_coordinate_source_span(canonical, callee)
        if span is None:
            return None
        source_snapshot = self._bounded_call_source_snapshot(canonical)
        if source_snapshot is None:
            return None
        line, column, end_line, end_column = span
        self._source_bytes_cache[canonical] = tuple(source_snapshot.splitlines(keepends=True))
        lines = self._source_bytes_cache[canonical]
        spelling = ""
        if lines is not None and end_line is not None and end_line <= len(lines):
            if end_line == line:
                raw = lines[line - 1][column:end_column]
            else:
                raw = b"".join(
                    (
                        lines[line - 1][column:],
                        *lines[line : end_line - 1],
                        lines[end_line - 1][:end_column],
                    )
                )
            try:
                spelling = raw.decode("utf-8")
            except UnicodeDecodeError:
                spelling = ""
        if not spelling.strip():
            return None
        return line, column, end_line, end_column, spelling

    def _bounded_call_source_snapshot(self, canonical: str) -> bytes | None:
        """Reuse frontend-matched bytes, or capture one bounded standalone snapshot."""
        if canonical not in self._call_source_snapshot_cache:
            if canonical in self._analysis_source_snapshots:
                snapshot = self._analysis_source_snapshots[canonical]
            else:
                try:
                    with Path(canonical).open("rb") as source_file:
                        snapshot = source_file.read(self.MAX_CALL_SPAN_SOURCE_BYTES + 1)
                except OSError:
                    snapshot = None
            self._call_source_snapshot_cache[canonical] = snapshot

        snapshot = self._call_source_snapshot_cache[canonical]
        if snapshot is not None and len(snapshot) > self.MAX_CALL_SPAN_SOURCE_BYTES:
            self._python_call_span_abstained.add(canonical)
            return None
        if snapshot is None:
            self._python_call_span_abstained.add(canonical)
        return snapshot

    def _exact_coordinate_source_span(
        self,
        canonical: str,
        callee: Any,
    ) -> tuple[int, int, int, int] | None:
        """Normalize exact mypy coordinates only when a full AST span is unique."""
        line = getattr(callee, "line", 0)
        column = getattr(callee, "column", -1)
        end_line = getattr(callee, "end_line", 0)
        end_column = getattr(callee, "end_column", -1)
        if not all(isinstance(value, int) for value in (line, column, end_line, end_column)):
            return None
        if line < 1 or column < 0 or end_line < line or end_column < 0:
            return None
        source_snapshot = self._bounded_call_source_snapshot(canonical)
        if source_snapshot is None:
            return None
        if canonical not in self._python_ast_cache:
            try:
                self._python_ast_cache[canonical] = ast.parse(
                    source_snapshot.decode("utf-8"), filename=canonical
                )
            except (OSError, SyntaxError, UnicodeError, RecursionError):
                self._abstain_call_source_span(canonical)
        tree = self._python_ast_cache[canonical]
        if tree is None:
            return None
        nodes = self._python_ast_nodes(canonical, tree)
        if nodes is None:
            return None
        try:
            source_lines = source_snapshot.decode("utf-8").splitlines()

            def forms(source_line: int, byte_column: int) -> set[int]:
                raw = source_lines[source_line - 1].encode("utf-8")
                prefix = raw[:byte_column].decode("utf-8")
                codepoint_column = len(prefix)
                return {
                    byte_column,
                    codepoint_column,
                    codepoint_column - sum(not character.isascii() for character in prefix),
                }

            candidates = [
                candidate.func
                for candidate in nodes
                if isinstance(candidate, ast.Call)
                and candidate.func.lineno == line
                and candidate.func.end_lineno == end_line
                and column in forms(candidate.func.lineno, candidate.func.col_offset)
                and candidate.func.end_col_offset is not None
                and end_column
                in forms(candidate.func.end_lineno or line, candidate.func.end_col_offset)
            ]
        except (OSError, UnicodeError, IndexError):
            return None
        if len(candidates) != 1:
            return None
        function = candidates[0]
        if function.end_lineno is None or function.end_col_offset is None:
            return None
        return function.lineno, function.col_offset, function.end_lineno, function.end_col_offset

    def _python_ast_nodes(self, canonical: str, tree: ast.Module) -> list[ast.AST] | None:
        """Return a bounded, cached source AST traversal, or cache abstention."""
        if canonical in self._python_ast_nodes_cache:
            return self._python_ast_nodes_cache[canonical]

        nodes: list[ast.AST] = []
        stack: list[tuple[ast.AST, int]] = [(tree, 0)]
        item_count = 0
        while stack:
            node, depth = stack.pop()
            if (
                depth > self.MAX_CALL_SPAN_SOURCE_DEPTH
                or len(nodes) >= self.MAX_CALL_SPAN_SOURCE_NODES
            ):
                self._python_ast_nodes_cache[canonical] = None
                self._python_call_span_abstained.add(canonical)
                return None
            nodes.append(node)
            for child in ast.iter_child_nodes(node):
                item_count += 1
                if item_count > self.MAX_CALL_SPAN_SOURCE_ITEMS:
                    self._python_ast_nodes_cache[canonical] = None
                    self._python_call_span_abstained.add(canonical)
                    return None
                stack.append((child, depth + 1))

        self._python_ast_nodes_cache[canonical] = nodes
        return nodes

    def _abstain_call_source_span(self, canonical: str) -> None:
        """Discard stale source-AST state when the current snapshot is unusable."""
        self._python_ast_cache[canonical] = None
        self._python_ast_nodes_cache[canonical] = None
        self._python_verified_call_spans.pop(canonical, None)
        self._python_call_span_abstained.add(canonical)

    def _match_python_and_mypy_calls(self, canonical: str) -> dict[int, tuple[int, int, int, int]]:
        """Pair calls only when both complete per-line source sequences agree."""
        from mypy.nodes import CallExpr, FuncDef, LambdaExpr, MemberExpr, NameExpr, Node

        source_snapshot = self._bounded_call_source_snapshot(canonical)
        if source_snapshot is None:
            return {}
        try:
            source = source_snapshot.decode("utf-8")
            python_tree = ast.parse(source, filename=canonical)
        except (OSError, SyntaxError, UnicodeError, RecursionError):
            self._abstain_call_source_span(canonical)
            return {}
        self._python_ast_cache[canonical] = python_tree
        python_nodes = self._python_ast_nodes(canonical, python_tree)
        if python_nodes is None:
            return {}
        modules = self._modules_by_canonical_path.get(canonical, ())
        if len(modules) != 1:
            return {}
        mypy_tree = self._trees.get(modules[0])
        if mypy_tree is None:
            return {}

        calls: list[tuple[CallExpr, tuple[tuple[str, str, int], ...]]] = []
        seen_nodes: set[int] = set()
        seen_containers: set[int] = set()
        mypy_item_count = 0
        traversal_exhausted = False
        ignored_edges = {
            "analyzed",
            "info",
            "method_type",
            "node",
            "original_def",
            "type",
            "type_args",
            "unanalyzed_type",
        }

        stack: list[tuple[Any, tuple[tuple[str, str, int], ...], int]] = [(mypy_tree, (), 0)]
        while stack:
            value, scopes, depth = stack.pop()
            if depth > self.MAX_CALL_SPAN_MYPY_DEPTH:
                traversal_exhausted = True
                break
            if isinstance(value, Node):
                identity = id(value)
                if identity in seen_nodes:
                    continue
                if len(seen_nodes) >= self.MAX_CALL_SPAN_MYPY_NODES:
                    traversal_exhausted = True
                    break
                seen_nodes.add(identity)
                current_scopes = scopes
                if isinstance(value, FuncDef):
                    current_scopes = (*scopes, ("function", value.name, value.line))
                elif isinstance(value, LambdaExpr):
                    current_scopes = (*scopes, ("lambda", "", value.line))
                if isinstance(value, CallExpr):
                    calls.append((value, current_scopes))
                for name in dir(value):
                    if name.startswith("_") or name in ignored_edges:
                        continue
                    try:
                        child = getattr(value, name)
                    except Exception:
                        continue
                    if isinstance(child, (Node, list, tuple)):
                        stack.append((child, current_scopes, depth + 1))
            elif isinstance(value, (list, tuple)):
                identity = id(value)
                if identity in seen_containers:
                    continue
                seen_containers.add(identity)
                for item in value:
                    mypy_item_count += 1
                    if mypy_item_count > self.MAX_CALL_SPAN_MYPY_ITEMS:
                        traversal_exhausted = True
                        break
                    if isinstance(item, (Node, list, tuple)):
                        stack.append((item, scopes, depth + 1))
                if traversal_exhausted:
                    break

        if traversal_exhausted:
            self._python_call_span_abstained.add(canonical)
            return {}
        mypy_by_scope_line: dict[tuple[int, tuple[tuple[str, str, int], ...]], list[CallExpr]] = {}
        for expression, scopes in calls:
            callee_line = getattr(expression.callee, "line", 0)
            if isinstance(callee_line, int) and callee_line > 0:
                mypy_by_scope_line.setdefault((callee_line, scopes), []).append(expression)

        python_parents: dict[ast.AST, ast.AST] = {}
        for parent in python_nodes:
            for child in ast.iter_child_nodes(parent):
                python_parents[child] = parent

        def python_scope(candidate: ast.AST) -> tuple[tuple[str, str, int], ...]:
            scopes: list[tuple[str, str, int]] = []
            parent = python_parents.get(candidate)
            while parent is not None:
                if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    scopes.append(("function", parent.name, parent.lineno))
                elif isinstance(parent, ast.Lambda):
                    scopes.append(("lambda", "", parent.lineno))
                parent = python_parents.get(parent)
            return tuple(reversed(scopes))

        python_by_scope_line: dict[
            tuple[int, tuple[tuple[str, str, int], ...]], list[ast.expr]
        ] = {}
        for candidate in python_nodes:
            if not isinstance(candidate, ast.Call):
                continue
            function = candidate.func
            if function.end_lineno is None or function.end_col_offset is None:
                continue
            key = (function.lineno, python_scope(candidate))
            python_by_scope_line.setdefault(key, []).append(function)

        result: dict[int, tuple[int, int, int, int]] = {}
        source_lines = source.splitlines()

        def coordinate_forms(line: int, byte_column: int) -> set[int]:
            if line < 1 or line > len(source_lines):
                return set()
            raw = source_lines[line - 1].encode("utf-8")
            try:
                prefix = raw[:byte_column].decode("utf-8")
            except UnicodeDecodeError:
                return set()
            codepoint_column = len(prefix)
            return {
                byte_column,
                codepoint_column,
                codepoint_column - sum(not character.isascii() for character in prefix),
            }

        # Prefer independent exact coordinates when a supported mypy coordinate
        # scheme identifies one complete source AST function span.
        coordinate_assignments: dict[int, set[tuple[int, int, int, int]]] = {}
        for (line, _scopes), source_calls in python_by_scope_line.items():
            typed_calls = mypy_by_scope_line.get((line, _scopes), [])
            typed_by_coordinates: dict[tuple[int, int, int], list[CallExpr]] = {}
            for call in typed_calls:
                coordinates = (
                    getattr(call.callee, "column", -1),
                    getattr(call.callee, "end_line", -1),
                    getattr(call.callee, "end_column", -1),
                )
                typed_by_coordinates.setdefault(coordinates, []).append(call)
            for source_call in source_calls:
                if source_call.end_lineno is None or source_call.end_col_offset is None:
                    continue
                candidates: set[int] = set()
                start_forms = coordinate_forms(line, source_call.col_offset)
                end_forms = coordinate_forms(source_call.end_lineno, source_call.end_col_offset)
                for start in start_forms:
                    for end in end_forms:
                        candidates.update(
                            id(call)
                            for call in typed_by_coordinates.get(
                                (start, source_call.end_lineno, end), ()
                            )
                        )
                if len(candidates) == 1:
                    typed_call_id = next(iter(candidates))
                    coordinate_assignments.setdefault(typed_call_id, set()).add(
                        (
                            source_call.lineno,
                            source_call.col_offset,
                            source_call.end_lineno or line,
                            source_call.end_col_offset or 0,
                        )
                    )

        calls_by_identity = {
            id(call): call for typed_calls in mypy_by_scope_line.values() for call in typed_calls
        }
        for typed_call_id, spans in coordinate_assignments.items():
            if len(spans) == 1:
                span = next(iter(spans))
                result[id(calls_by_identity[typed_call_id].callee)] = span

        conflicting_calls: set[int] = set()
        for key, source_calls in python_by_scope_line.items():
            line, _scopes = key
            typed_calls = mypy_by_scope_line.get(key, [])
            if len(source_calls) != len(typed_calls):
                continue
            source_calls.sort(
                key=lambda call: (call.col_offset, call.end_lineno, call.end_col_offset)
            )
            typed_calls.sort(key=lambda call: (call.callee.column, call.callee.end_line or line))
            typed_columns = [call.callee.column for call in typed_calls]
            source_columns = [call.col_offset for call in source_calls]
            if len(set(typed_columns)) != len(typed_columns) or len(set(source_columns)) != len(
                source_columns
            ):
                continue

            source_names = [
                function.id
                if isinstance(function, ast.Name)
                else function.attr
                if isinstance(function, ast.Attribute)
                else None
                for function in source_calls
            ]
            typed_names = [
                call.callee.name if isinstance(call.callee, (NameExpr, MemberExpr)) else None
                for call in typed_calls
            ]
            if source_names != typed_names or any(name is None for name in source_names):
                continue

            for source_call, typed_call in zip(source_calls, typed_calls, strict=True):
                assert source_call.end_lineno is not None
                assert source_call.end_col_offset is not None
                identity = id(typed_call.callee)
                span = (
                    source_call.lineno,
                    source_call.col_offset,
                    source_call.end_lineno,
                    source_call.end_col_offset,
                )
                previous = result.get(identity)
                if previous is not None and previous != span:
                    result.pop(identity, None)
                    conflicting_calls.add(identity)
                elif identity not in conflicting_calls:
                    result[identity] = span
        return result

    @staticmethod
    def _callable_declaration(
        node: Any,
    ) -> tuple[str, InvocationKind] | None:
        """Return exact declaration identity only for callable definition nodes."""
        from mypy.nodes import (
            Decorator,
            FuncDef,
            OverloadedFuncDef,
            TypeInfo,
        )

        if isinstance(node, TypeInfo):
            return (node.fullname, InvocationKind.CONSTRUCTOR) if node.fullname else None
        if isinstance(node, Decorator):
            fullname = node.var.fullname or node.func.fullname
            if not fullname:
                return None
            if node.var.is_staticmethod:
                return fullname, InvocationKind.FUNCTION
            if node.var.is_classmethod:
                return fullname, InvocationKind.CLASS_METHOD
            return (
                fullname,
                (
                    InvocationKind.INSTANCE_METHOD
                    if getattr(node.func.info, "fullname", None)
                    else InvocationKind.FUNCTION
                ),
            )
        if isinstance(node, OverloadedFuncDef):
            declarations = {
                declaration
                for item in node.items
                if (declaration := MypyAnalyzer._callable_declaration(item)) is not None
            }
            return next(iter(declarations)) if len(declarations) == 1 else None
        if isinstance(node, FuncDef):
            fullname = getattr(node, "fullname", "")
            if not fullname:
                return None
            info = getattr(node, "info", None)
            return (
                fullname,
                (
                    InvocationKind.INSTANCE_METHOD
                    if getattr(info, "fullname", None)
                    else InvocationKind.FUNCTION
                ),
            )
        return None

    def _canonical_project_fullname(self, fullname: str) -> str | None:
        """Map an import spelling to one unique built project module identity."""
        if fullname not in self._canonical_project_fullname_cache:
            self._canonical_project_fullname_cache[fullname] = (
                self._canonical_project_fullname_uncached(fullname)
            )
        return self._canonical_project_fullname_cache[fullname]

    def _canonical_project_fullname_uncached(self, fullname: str) -> str | None:
        """Compute one unique project identity for an import spelling."""
        resolved = self._resolve_fullname_to_file(fullname)
        if resolved is not None:
            _path, module = resolved
            if fullname == module or fullname.startswith(f"{module}."):
                return fullname
        parts = fullname.split(".")
        candidates: set[str] = set()
        for split_at in range(1, len(parts) + 1):
            imported_module = ".".join(parts[:split_at])
            remainder = ".".join(parts[split_at:])
            for module in self._module_to_path:
                if module != imported_module and not module.endswith(f".{imported_module}"):
                    continue
                candidate = f"{module}.{remainder}" if remainder else module
                if self._resolve_fullname_to_file(candidate) is not None:
                    candidates.add(candidate)
        return next(iter(candidates)) if len(candidates) == 1 else None

    def _project_type_info(self, fullname: str) -> Any | None:
        """Resolve one exact project class through bounded explicit re-exports."""
        from mypy.nodes import TypeInfo

        visited: set[str] = set()
        current = self._canonical_project_fullname(fullname)
        if current is None:
            return None
        for _depth in range(self.max_depth + 1):
            if current in visited:
                return None
            visited.add(current)
            result = self._resolve_fullname_to_file(current)
            if result is None:
                return None
            _path, module = result
            tree = self._trees.get(module)
            if tree is None or not current.startswith(f"{module}."):
                return None
            qualified = current[len(module) + 1 :]
            if "." in qualified:
                return None
            symbol = tree.names.get(qualified)
            if symbol is not None and isinstance(symbol.node, TypeInfo):
                return symbol.node
            reexport = self._import_map_for_tree(tree, module).get(qualified)
            if reexport is None:
                return None
            current = reexport
        return None

    def _project_callable_declaration(self, fullname: str) -> tuple[str, InvocationKind] | None:
        """Resolve an exact project callable through bounded explicit re-exports."""
        from mypy.nodes import TypeInfo

        visited: set[str] = set()
        current = self._canonical_project_fullname(fullname)
        if current is None:
            return None
        for _depth in range(self.max_depth + 1):
            if current in visited:
                return None
            visited.add(current)
            result = self._resolve_fullname_to_file(current)
            if result is None:
                return None
            _path, module = result
            tree = self._trees.get(module)
            if tree is None or not current.startswith(f"{module}."):
                return None
            qualified = current[len(module) + 1 :]
            if "." in qualified:
                return None
            found = self._find_func_in_tree(
                tree,
                qualified,
                qualified_name=qualified,
            )
            if found is not None:
                return self._callable_declaration(found[0])
            symbol = tree.names.get(qualified)
            if symbol is not None and isinstance(symbol.node, TypeInfo):
                return self._callable_declaration(symbol.node)
            reexport = self._import_map_for_tree(tree, module).get(qualified)
            if reexport is None:
                return None
            current = reexport
        return None

    @staticmethod
    def _explicit_import_fullname(expression: Any, import_map: dict[str, str]) -> str | None:
        """Resolve only source-explicit, unshadowed import attribute chains."""
        from mypy.nodes import MemberExpr, MypyFile, NameExpr, TypeInfo, Var

        if isinstance(expression, NameExpr):
            imported = import_map.get(expression.name)
            if imported is None:
                return None
            node = expression.node
            if isinstance(node, Var):
                return imported if node.line < 0 and "." in (expression.fullname or "") else None
            return imported if isinstance(node, (MypyFile, TypeInfo)) else None
        if isinstance(expression, MemberExpr):
            receiver = MypyAnalyzer._explicit_import_fullname(expression.expr, import_map)
            return f"{receiver}.{expression.name}" if receiver is not None else None
        return None

    def _project_member_declaration(self, fullname: str) -> tuple[str, InvocationKind] | None:
        """Resolve a method through an exact source-proven project class export."""
        canonical = self._canonical_project_fullname(fullname)
        if canonical is None:
            return None
        fullname = canonical
        result = self._resolve_fullname_to_file(fullname)
        if result is None:
            return None
        _path, module = result
        if not fullname.startswith(f"{module}."):
            return None
        qualified = fullname[len(module) + 1 :]
        if qualified.count(".") != 1:
            return None
        class_name, member_name = qualified.split(".")
        info = self._project_type_info(f"{module}.{class_name}")
        member = info.get(member_name) if info is not None else None
        return self._callable_declaration(member.node) if member is not None else None

    def _join_finite_values(
        self, left: _FinitePointsTo | None, right: _FinitePointsTo | None
    ) -> _FinitePointsTo | None:
        """Join only complete finite values; unknown on either path fails closed."""
        if left is None or right is None:
            return None
        types = tuple(sorted(set(left.types) | set(right.types)))
        if len(types) > self.MAX_POINTS_TO_TARGETS:
            self._record_analysis_limitation(
                "MAX_POINTS_TO_TARGETS", target_count=len(types), limit=self.MAX_POINTS_TO_TARGETS
            )
            return None
        if not types:
            return None
        left_fields = dict(left.fields)
        right_fields = dict(right.fields)
        fields: list[tuple[str, _FinitePointsTo]] = []
        for name in sorted(left_fields.keys() & right_fields.keys()):
            value = self._join_finite_values(left_fields[name], right_fields[name])
            if value is not None:
                fields.append((name, value))
        return _FinitePointsTo(types, tuple(fields))

    def _join_finite_environments(
        self,
        environments: list[dict[str, _FinitePointsTo]],
    ) -> dict[str, _FinitePointsTo]:
        if not environments:
            return {}
        common = set(environments[0])
        for environment in environments[1:]:
            common &= environment.keys()
        result: dict[str, _FinitePointsTo] = {}
        for name in sorted(common):
            value: _FinitePointsTo | None = environments[0][name]
            for environment in environments[1:]:
                value = self._join_finite_values(value, environment[name])
            if value is not None:
                result[name] = value
        return result

    def _join_callable_environments(self, environments: list[dict[str, Any]]) -> dict[str, Any]:
        """Keep callable targets assigned on every path as a bounded finite union."""
        if not environments:
            return {}
        common = set(environments[0])
        for environment in environments[1:]:
            common &= environment.keys()
        joined: dict[str, Any] = {}
        for name in sorted(common):
            targets: list[Any] = []
            for environment in environments:
                value = environment[name]
                candidates = value.targets if isinstance(value, _CallableUnion) else (value,)
                for candidate in candidates:
                    if candidate not in targets:
                        targets.append(candidate)
            if len(targets) == 1:
                joined[name] = targets[0]
            elif targets and len(targets) <= self.MAX_POINTS_TO_TARGETS:
                joined[name] = _CallableUnion(tuple(targets))
            elif len(targets) > self.MAX_POINTS_TO_TARGETS:
                self._record_analysis_limitation(
                    "MAX_POINTS_TO_TARGETS",
                    target_count=len(targets),
                    limit=self.MAX_POINTS_TO_TARGETS,
                )
        return joined

    def _exact_project_identity(self, fullname: str) -> tuple[str, str] | None:
        """Split a canonical fullname at the longest exact built module prefix."""
        if fullname not in self._exact_project_identity_cache:
            modules = [
                module for module in self._project_modules if fullname.startswith(f"{module}.")
            ]
            if modules:
                longest = max(len(module) for module in modules)
                selected = [module for module in modules if len(module) == longest]
                identity = (
                    (selected[0], fullname[len(selected[0]) + 1 :]) if len(selected) == 1 else None
                )
            else:
                identity = None
            self._exact_project_identity_cache[fullname] = identity
        return self._exact_project_identity_cache[fullname]

    def _exact_finite_project_type_info(self, fullname: str) -> Any | None:
        """Resolve a class through exact module identities and explicit re-exports only."""
        from mypy.nodes import TypeInfo

        visited: set[str] = set()
        current = fullname
        for _depth in range(self.max_depth + 1):
            if current in visited:
                return None
            visited.add(current)
            identity = self._exact_project_identity(current)
            if identity is None or "." in identity[1]:
                return None
            module, name = identity
            tree = self._trees.get(module)
            if tree is None:
                return None
            symbol = tree.names.get(name)
            if symbol is not None and isinstance(symbol.node, TypeInfo):
                info = symbol.node
                return info if info.fullname == current else None
            reexport = self._import_map_for_tree(tree, module).get(name)
            if reexport is None:
                return None
            current = reexport
        return None

    def _project_constructor_info(self, callee: Any, import_map: dict[str, str]) -> Any | None:
        """Return one exact project class for a source-explicit constructor call."""
        from mypy.nodes import NameExpr, TypeInfo

        if isinstance(callee, NameExpr) and isinstance(callee.node, TypeInfo):
            info = callee.node
            return info if info.module_name in self._project_modules else None
        imported = self._explicit_import_fullname(callee, import_map)
        return self._exact_finite_project_type_info(imported) if imported is not None else None

    def _exact_finite_project_callable(self, fullname: str) -> tuple[str, InvocationKind] | None:
        """Resolve a factory through exact project modules and explicit re-exports."""
        visited: set[str] = set()
        current = fullname
        for _depth in range(self.max_depth + 1):
            if current in visited:
                return None
            visited.add(current)
            identity = self._exact_project_identity(current)
            if identity is None or identity[1].count(".") > 1:
                return None
            module, name = identity
            tree = self._trees.get(module)
            if tree is None:
                return None
            if "." in name:
                class_name, member_name = name.split(".", maxsplit=1)
                info = self._exact_finite_project_type_info(f"{module}.{class_name}")
                member = info.get(member_name) if info is not None else None
                return self._callable_declaration(member.node) if member is not None else None
            found = self._find_func_in_tree(tree, name, qualified_name=name)
            if found is not None:
                return self._callable_declaration(found[0])
            reexport = self._import_map_for_tree(tree, module).get(name)
            if reexport is None:
                return None
            current = reexport
        return None

    def _function_node_for_fullname(self, fullname: str) -> tuple[Any, str, str] | None:
        """Resolve one exact project function to its typed node, path, and module."""
        result = self._resolve_fullname_to_file(fullname)
        if result is None:
            return None
        path, module = result
        tree = self._trees.get(module)
        if tree is None or not fullname.startswith(f"{module}."):
            return None
        qualified = fullname[len(module) + 1 :]
        found = self._find_func_in_tree(
            tree,
            qualified.rsplit(".", maxsplit=1)[-1],
            qualified_name=qualified,
        )
        return (found[0], path, module) if found is not None else None

    @staticmethod
    def _actual_function(node: Any) -> Any:
        from mypy.nodes import Decorator

        return node.func if isinstance(node, Decorator) else node

    def _bind_finite_arguments(
        self,
        function: Any,
        call: Any,
        caller_environment: dict[str, _FinitePointsTo],
        caller_imports: dict[str, str],
        stack: tuple[str, ...],
        budget: list[int],
        *,
        receiver: _FinitePointsTo | None = None,
        skip_implicit_receiver: bool = False,
    ) -> dict[str, _FinitePointsTo] | None:
        """Bind a narrow valid call shape without *args/**kwargs guessing."""
        from mypy.nodes import (
            ARG_NAMED,
            ARG_NAMED_OPT,
            ARG_OPT,
            ARG_POS,
            ARG_STAR,
            ARG_STAR2,
        )

        actual = self._actual_function(function)
        arguments = list(getattr(actual, "arguments", ()))
        environment: dict[str, _FinitePointsTo] = {}
        if receiver is not None or skip_implicit_receiver:
            if not arguments:
                return None
            if receiver is not None:
                environment[arguments[0].variable.name] = receiver
            arguments = arguments[1:]
        if any(argument.kind in (ARG_STAR, ARG_STAR2) for argument in arguments):
            return None

        positional_arguments = [
            argument for argument in arguments if argument.kind in (ARG_POS, ARG_OPT)
        ]
        by_name = {
            argument.variable.name: argument for argument in arguments if not argument.pos_only
        }
        assigned: set[str] = set()
        positional = 0
        for expression, kind, name in zip(call.args, call.arg_kinds, call.arg_names, strict=True):
            if kind == ARG_POS and name is None:
                if positional >= len(positional_arguments):
                    return None
                parameter = positional_arguments[positional].variable.name
                positional += 1
            elif kind == ARG_NAMED and name in by_name:
                parameter = name
            else:
                return None
            if parameter in assigned:
                return None
            assigned.add(parameter)
            value = self._finite_expression_value(
                expression,
                caller_environment,
                caller_imports,
                stack,
                budget,
            )
            if value is not None:
                environment[parameter] = value

        required = {
            argument.variable.name
            for argument in arguments
            if argument.kind in (ARG_POS, ARG_NAMED)
        }
        if required - assigned:
            return None
        if any(
            argument.kind not in (ARG_POS, ARG_OPT, ARG_NAMED, ARG_NAMED_OPT)
            for argument in arguments
        ):
            return None
        return environment

    def _bind_finite_string_arguments(
        self,
        function: Any,
        call: Any,
        caller_environment: dict[str, tuple[str, ...]],
        *,
        receiver: tuple[str, ...] | None = None,
        skip_implicit_receiver: bool = False,
    ) -> dict[str, tuple[str, ...]] | None:
        """Bind only explicit finite string arguments to one exact callee."""
        from mypy.nodes import ARG_NAMED, ARG_NAMED_OPT, ARG_OPT, ARG_POS, ARG_STAR, ARG_STAR2

        actual = self._actual_function(function)
        arguments = list(getattr(actual, "arguments", ()))
        environment: dict[str, tuple[str, ...]] = {}
        if receiver is not None or skip_implicit_receiver:
            if not arguments:
                return None
            if receiver is not None:
                environment[arguments[0].variable.name] = receiver
            arguments = arguments[1:]
        if any(argument.kind in (ARG_STAR, ARG_STAR2) for argument in arguments):
            return None
        positional_arguments = [
            argument for argument in arguments if argument.kind in (ARG_POS, ARG_OPT)
        ]
        by_name = {
            argument.variable.name: argument for argument in arguments if not argument.pos_only
        }
        assigned: set[str] = set()
        positional = 0
        for expression, kind, name in zip(call.args, call.arg_kinds, call.arg_names, strict=True):
            if kind == ARG_POS and name is None:
                if positional >= len(positional_arguments):
                    return None
                parameter = positional_arguments[positional].variable.name
                positional += 1
            elif kind == ARG_NAMED and name in by_name:
                parameter = name
            else:
                return None
            if parameter in assigned:
                return None
            assigned.add(parameter)
            values = self._finite_string_values(expression, caller_environment)
            if values is not None:
                environment[parameter] = values
        required = {
            argument.variable.name
            for argument in arguments
            if argument.kind in (ARG_POS, ARG_NAMED)
        }
        if required - assigned or any(
            argument.kind not in (ARG_POS, ARG_OPT, ARG_NAMED, ARG_NAMED_OPT)
            for argument in arguments
        ):
            return None
        return environment

    def _bind_callable_arguments(
        self,
        function: Any,
        call: Any,
        caller_environment: dict[str, tuple[tuple[str, InvocationKind], _FinitePointsTo | None]],
        object_environment: dict[str, _FinitePointsTo],
        import_map: dict[str, str],
        stack: tuple[str, ...],
        budget: list[int],
        *,
        skip_implicit_receiver: bool = False,
    ) -> dict[str, tuple[tuple[str, InvocationKind], _FinitePointsTo | None]] | None:
        """Forward exact callable actuals to matching project parameters."""
        from mypy.nodes import (
            ARG_NAMED,
            ARG_NAMED_OPT,
            ARG_OPT,
            ARG_POS,
            ARG_STAR,
            ARG_STAR2,
            MemberExpr,
            NameExpr,
        )

        actual = self._actual_function(function)
        arguments = list(getattr(actual, "arguments", ()))
        environment: dict[str, tuple[tuple[str, InvocationKind], _FinitePointsTo | None]] = {}
        if skip_implicit_receiver:
            if not arguments:
                return None
            arguments = arguments[1:]
        if any(argument.kind in (ARG_STAR, ARG_STAR2) for argument in arguments):
            return None
        positional_arguments = [
            argument for argument in arguments if argument.kind in (ARG_POS, ARG_OPT)
        ]
        by_name = {
            argument.variable.name: argument for argument in arguments if not argument.pos_only
        }
        assigned: set[str] = set()
        positional = 0
        for expression, kind, name in zip(call.args, call.arg_kinds, call.arg_names, strict=True):
            if kind == ARG_POS and name is None:
                if positional >= len(positional_arguments):
                    return None
                parameter = positional_arguments[positional].variable.name
                positional += 1
            elif kind == ARG_NAMED and name in by_name:
                parameter = name
            else:
                return None
            if parameter in assigned:
                return None
            assigned.add(parameter)
            value: tuple[tuple[str, InvocationKind], _FinitePointsTo | None] | None = None
            if isinstance(expression, NameExpr):
                value = caller_environment.get(expression.name)
                if value is None:
                    declaration = self._callable_declaration(getattr(expression, "node", None))
                    if declaration is None:
                        imported = self._explicit_import_fullname(expression, import_map)
                        declaration = (
                            self._project_callable_declaration(imported)
                            if imported is not None
                            else None
                        )
                    if declaration is not None and self._exact_project_identity(declaration[0]):
                        value = (declaration, None)
            elif isinstance(expression, MemberExpr):
                declaration = self._callable_declaration(getattr(expression, "node", None))
                if declaration is not None and self._exact_project_identity(declaration[0]):
                    receiver = self._finite_expression_value(
                        expression.expr,
                        object_environment,
                        import_map,
                        stack,
                        budget,
                    )
                    if declaration[1] != InvocationKind.INSTANCE_METHOD or receiver is not None:
                        value = (declaration, receiver)
            if value is not None:
                environment[parameter] = value
        required = {
            argument.variable.name
            for argument in arguments
            if argument.kind in (ARG_POS, ARG_NAMED)
        }
        if required - assigned or any(
            argument.kind not in (ARG_POS, ARG_OPT, ARG_NAMED, ARG_NAMED_OPT)
            for argument in arguments
        ):
            return None
        return environment

    def _finite_global_value(
        self,
        fullname: str,
        _budget: list[int],
    ) -> _FinitePointsTo | None:
        """Summarize one exact module global from ordered source assignments."""
        from mypy.nodes import (
            AssignmentStmt,
            CallExpr,
            ClassDef,
            Decorator,
            FuncDef,
            Import,
            ImportFrom,
            NameExpr,
            PassStmt,
        )

        if fullname in self._finite_global_value_cache:
            return self._finite_global_value_cache[fullname]
        if fullname in self._finite_global_in_progress:
            return None
        identity = self._exact_project_identity(fullname)
        if identity is None or "." in identity[1]:
            self._finite_global_value_cache[fullname] = None
            return None
        module, name = identity
        tree = self._trees.get(module)
        if tree is None:
            self._finite_global_value_cache[fullname] = None
            return None
        self._finite_global_in_progress.add(fullname)
        try:
            environment: dict[str, _FinitePointsTo] = {}
            summary_budget = [0]
            import_map = self._import_map_for_tree(tree, module)
            inert_statements = (ClassDef, Decorator, FuncDef, Import, ImportFrom, PassStmt)
            for statement in tree.defs:
                if isinstance(statement, inert_statements):
                    continue
                if not isinstance(statement, AssignmentStmt):
                    self._finite_global_value_cache[fullname] = None
                    return None
                if not statement.lvalues or not all(
                    isinstance(target, NameExpr) for target in statement.lvalues
                ):
                    self._finite_global_value_cache[fullname] = None
                    return None
                value = self._finite_expression_value(
                    statement.rvalue,
                    environment,
                    import_map,
                    (fullname,),
                    summary_budget,
                )
                if value is None and isinstance(statement.rvalue, CallExpr):
                    self._finite_global_value_cache[fullname] = None
                    return None
                for target in statement.lvalues:
                    if not isinstance(target, NameExpr):
                        continue
                    if value is None:
                        environment.pop(target.name, None)
                    else:
                        environment[target.name] = value
            result = environment.get(name)
            self._finite_global_value_cache[fullname] = result
            return result
        finally:
            self._finite_global_in_progress.discard(fullname)

    def _finite_expression_value(
        self,
        expression: Any,
        environment: dict[str, _FinitePointsTo],
        import_map: dict[str, str],
        stack: tuple[str, ...],
        budget: list[int],
    ) -> _FinitePointsTo | None:
        """Evaluate the deliberately small, finite points-to expression language."""
        from mypy.nodes import CallExpr, ConditionalExpr, MemberExpr, NameExpr

        if budget[0] >= self.MAX_FACTORY_STATES:
            return None
        budget[0] += 1
        if isinstance(expression, NameExpr):
            if expression.name in environment:
                return environment[expression.name]
            imported = self._explicit_import_fullname(expression, import_map)
            raw_fullname = imported or getattr(expression, "fullname", "")
            global_fullname = raw_fullname if isinstance(raw_fullname, str) else ""
            return (
                self._finite_global_value(global_fullname, budget)
                if "." in global_fullname
                else None
            )
        if isinstance(expression, MemberExpr):
            imported = self._explicit_import_fullname(expression, import_map)
            if imported is not None:
                global_value = self._finite_global_value(imported, budget)
                if global_value is not None:
                    return global_value
            receiver = self._finite_expression_value(
                expression.expr, environment, import_map, stack, budget
            )
            return receiver.field(expression.name) if receiver is not None else None
        if isinstance(expression, ConditionalExpr):
            left = self._finite_expression_value(
                expression.if_expr, dict(environment), import_map, stack, budget
            )
            right = self._finite_expression_value(
                expression.else_expr, dict(environment), import_map, stack, budget
            )
            return self._join_finite_values(left, right)
        if not isinstance(expression, CallExpr):
            return None
        info = self._project_constructor_info(expression.callee, import_map)
        if info is not None:
            return self._finite_constructor_value(
                info, expression, environment, import_map, stack, budget
            )
        imported = self._explicit_import_fullname(expression.callee, import_map)
        declaration = (
            self._exact_finite_project_callable(imported) if imported is not None else None
        )
        if declaration is None:
            direct = self._callable_declaration(getattr(expression.callee, "node", None))
            declaration = (
                direct
                if direct is not None and self._exact_project_identity(direct[0]) is not None
                else None
            )
        if declaration is None or declaration[1] != InvocationKind.FUNCTION:
            return None
        return self._finite_factory_return(
            declaration[0], expression, environment, import_map, stack, budget
        )

    @staticmethod
    def _literal_boolean(expression: Any) -> bool | None:
        """Return the truth value of a source literal condition, when exact."""
        from mypy.nodes import IntExpr, NameExpr, StrExpr, UnaryExpr

        if isinstance(expression, NameExpr) and expression.name in {"True", "False"}:
            return expression.name == "True"
        if isinstance(expression, (IntExpr, StrExpr)):
            return bool(expression.value)
        if isinstance(expression, UnaryExpr) and expression.op == "not":
            value = MypyAnalyzer._literal_boolean(expression.expr)
            return None if value is None else not value
        return None

    @staticmethod
    def _finite_string_condition(
        expression: Any,
        environment: dict[str, tuple[str, ...]],
    ) -> bool | None:
        """Resolve exact equality tests over bounded string arguments."""
        from mypy.nodes import ComparisonExpr

        if not isinstance(expression, ComparisonExpr) or len(expression.operators) != 1:
            return None
        operator = expression.operators[0]
        if operator not in {"==", "!="}:
            return None
        left = MypyAnalyzer._finite_string_values(expression.operands[0], environment)
        right = MypyAnalyzer._finite_string_values(expression.operands[1], environment)
        if left is None or right is None:
            return None
        outcomes = {a == b for a in left for b in right}
        if len(outcomes) != 1:
            return None
        equal = next(iter(outcomes))
        return equal if operator == "==" else not equal

    @staticmethod
    def _returned_nested_function(parent: Any, nested: Any) -> bool:
        """Recognize closures returned by any branch of their defining callable."""
        from mypy.nodes import (
            Block,
            ForStmt,
            IfStmt,
            NameExpr,
            ReturnStmt,
            TryStmt,
            WhileStmt,
            WithStmt,
        )

        nested_name = getattr(nested, "name", None)

        def returned(statement: Any) -> bool:
            if isinstance(statement, ReturnStmt):
                expression = statement.expr
                return isinstance(expression, NameExpr) and (
                    expression.name == nested_name or getattr(expression, "node", None) is nested
                )
            if isinstance(statement, Block):
                return any(returned(item) for item in statement.body)
            if isinstance(statement, IfStmt):
                return any(returned(block) for block in statement.body) or (
                    statement.else_body is not None and returned(statement.else_body)
                )
            if isinstance(statement, (ForStmt, WhileStmt)):
                return returned(statement.body) or (
                    statement.else_body is not None and returned(statement.else_body)
                )
            if isinstance(statement, WithStmt):
                return returned(statement.body)
            if isinstance(statement, TryStmt):
                return (
                    returned(statement.body)
                    or any(returned(handler) for handler in statement.handlers)
                    or (statement.else_body is not None and returned(statement.else_body))
                    or (statement.finally_body is not None and returned(statement.finally_body))
                )
            return False

        return returned(getattr(parent, "body", None))

    def _returned_project_callable(self, fullname: str) -> tuple[str, InvocationKind] | None:
        """Resolve a callable returned on every explicit path of one project function."""
        from mypy.nodes import (
            Block,
            Decorator,
            ForStmt,
            FuncDef,
            IfStmt,
            LambdaExpr,
            NameExpr,
            ReturnStmt,
            TryStmt,
            WhileStmt,
            WithStmt,
        )

        resolved = self._function_node_for_fullname(fullname)
        if resolved is None:
            declaration = self._project_callable_declaration(fullname)
            if declaration is not None:
                resolved = self._function_node_for_fullname(declaration[0])
        if resolved is None:
            return None
        function = self._actual_function(resolved[0])
        returns: list[Any] = []

        def collect(statement: Any) -> None:
            if isinstance(statement, ReturnStmt):
                returns.append(statement.expr)
            elif isinstance(statement, Block):
                for item in statement.body:
                    collect(item)
                    if isinstance(item, (ReturnStmt,)):
                        break
            elif isinstance(statement, IfStmt):
                for block in statement.body:
                    collect(block)
                if statement.else_body is not None:
                    collect(statement.else_body)
            elif isinstance(statement, (ForStmt, WhileStmt)):
                collect(statement.body)
                if statement.else_body is not None:
                    collect(statement.else_body)
            elif isinstance(statement, WithStmt):
                collect(statement.body)
            elif isinstance(statement, TryStmt):
                collect(statement.body)
                for handler in statement.handlers:
                    collect(handler)
                if statement.else_body is not None:
                    collect(statement.else_body)
                if statement.finally_body is not None:
                    collect(statement.finally_body)
            elif isinstance(statement, (FuncDef, Decorator, LambdaExpr)):
                return

        collect(function.body)
        if not returns or any(not isinstance(expression, NameExpr) for expression in returns):
            return None
        declarations = [
            self._callable_declaration(getattr(expression, "node", None)) for expression in returns
        ]
        if declarations[0] is None or any(item != declarations[0] for item in declarations[1:]):
            return None
        declaration = declarations[0]
        if declaration is None:
            return None
        if self._exact_project_identity(declaration[0]) is None:
            declaration = (f"{fullname}.{declaration[0]}", declaration[1])
            if self._function_node_for_fullname(declaration[0]) is None:
                return None
        elif self._function_node_for_fullname(declaration[0]) is None:
            return None
        return declaration

    def _returned_lambda(self, fullname: str) -> tuple[Any, str, str, str] | None:
        """Return a uniquely returned lambda expression from an exact factory."""
        from mypy.nodes import Block, FuncDef, IfStmt, LambdaExpr, ReturnStmt

        resolved = self._function_node_for_fullname(fullname)
        if resolved is None:
            declaration = self._project_callable_declaration(fullname)
            if declaration is not None:
                resolved = self._function_node_for_fullname(declaration[0])
        if resolved is None:
            return None
        returns: list[Any] = []

        def collect(statement: Any) -> None:
            if isinstance(statement, ReturnStmt):
                returns.append(statement.expr)
            elif isinstance(statement, Block):
                for item in statement.body:
                    collect(item)
                    if isinstance(item, ReturnStmt):
                        break
            elif isinstance(statement, IfStmt):
                for body in statement.body:
                    collect(body)
                if statement.else_body is not None:
                    collect(statement.else_body)
            elif isinstance(statement, FuncDef):
                return

        collect(self._actual_function(resolved[0]).body)
        if len(returns) == 1 and isinstance(returns[0], LambdaExpr):
            _node, path, module = resolved
            # mypy's source-callee scope index associates lambda bodies with
            # their enclosing factory definition.
            return returns[0], path, module, fullname
        return None

    def _finite_constructor_value(
        self,
        info: Any,
        call: Any,
        environment: dict[str, _FinitePointsTo],
        import_map: dict[str, str],
        stack: tuple[str, ...],
        budget: list[int],
    ) -> _FinitePointsTo | None:
        """Construct one exact object and bind finite constructor fields."""
        fullname = getattr(info, "fullname", "")
        if not fullname or fullname in stack:
            return None
        value = _FinitePointsTo((fullname,))
        member = info.get("__init__")
        function = getattr(member, "node", None) if member is not None else None
        if function is None:
            return value
        bound = self._bind_finite_arguments(
            function,
            call,
            environment,
            import_map,
            (*stack, fullname),
            budget,
            receiver=value,
        )
        if bound is None:
            return value
        actual = self._actual_function(function)
        resolved = self._resolve_fullname_to_file(fullname)
        if resolved is None or resolved[1] not in self._trees:
            return value
        module = resolved[1]
        executed = self._execute_finite_block(
            actual.body,
            bound,
            self._import_map_for_tree(self._trees[module], module),
            (*stack, fullname),
            budget,
            collect_returns=False,
        )
        if executed is None:
            return value
        final_environment, _returns, _falls_through = executed
        self_name = actual.arguments[0].variable.name if actual.arguments else "self"
        return final_environment.get(self_name, value)

    def _finite_factory_return(
        self,
        fullname: str,
        call: Any,
        caller_environment: dict[str, _FinitePointsTo],
        caller_imports: dict[str, str],
        stack: tuple[str, ...],
        budget: list[int],
    ) -> _FinitePointsTo | None:
        """Summarize a project factory only when all normal returns are finite."""
        if fullname in stack or len(stack) >= self.max_depth:
            return None
        resolved = self._function_node_for_fullname(fullname)
        if resolved is None:
            return None
        function, _path, module = resolved
        bound = self._bind_finite_arguments(
            function,
            call,
            caller_environment,
            caller_imports,
            (*stack, fullname),
            budget,
        )
        if bound is None:
            return None
        actual = self._actual_function(function)
        executed = self._execute_finite_block(
            actual.body,
            bound,
            self._import_map_for_tree(self._trees[module], module),
            (*stack, fullname),
            budget,
            collect_returns=True,
        )
        if executed is None:
            return None
        _environment, returns, falls_through = executed
        if falls_through or not returns or len(returns) > self.MAX_FACTORY_RETURNS:
            return None
        value: _FinitePointsTo | None = returns[0]
        for returned in returns[1:]:
            value = self._join_finite_values(value, returned)
        return value

    def _execute_finite_block(
        self,
        block: Any,
        environment: dict[str, _FinitePointsTo],
        import_map: dict[str, str],
        stack: tuple[str, ...],
        budget: list[int],
        *,
        collect_returns: bool,
    ) -> tuple[dict[str, _FinitePointsTo], list[_FinitePointsTo], bool] | None:
        """Interpret assignments/branches with deterministic fail-closed joins."""
        from mypy.nodes import (
            AssignmentStmt,
            CallExpr,
            IfStmt,
            MemberExpr,
            NameExpr,
            PassStmt,
            RaiseStmt,
            ReturnStmt,
        )

        current = dict(environment)
        returns: list[_FinitePointsTo] = []
        falls_through = True
        for statement in getattr(block, "body", ()):
            if not falls_through:
                break
            if isinstance(statement, AssignmentStmt):
                value = self._finite_expression_value(
                    statement.rvalue, current, import_map, stack, budget
                )
                if value is None and isinstance(statement.rvalue, CallExpr):
                    return None
                for target in statement.lvalues:
                    if isinstance(target, NameExpr):
                        if value is None:
                            current.pop(target.name, None)
                        else:
                            current[target.name] = value
                    elif (
                        not collect_returns
                        and isinstance(target, MemberExpr)
                        and isinstance(target.expr, NameExpr)
                        and target.expr.name in current
                    ):
                        receiver = current[target.expr.name]
                        current[target.expr.name] = receiver.with_field(target.name, value)
                    else:
                        return None
                continue
            if isinstance(statement, ReturnStmt):
                if not collect_returns:
                    falls_through = False
                    continue
                value = self._finite_expression_value(
                    statement.expr, current, import_map, stack, budget
                )
                if value is None:
                    return None
                returns.append(value)
                falls_through = False
                continue
            if isinstance(statement, RaiseStmt):
                falls_through = False
                continue
            if isinstance(statement, IfStmt):
                branch_results = []
                for body in statement.body:
                    result = self._execute_finite_block(
                        body,
                        dict(current),
                        import_map,
                        stack,
                        budget,
                        collect_returns=collect_returns,
                    )
                    if result is None:
                        return None
                    branch_results.append(result)
                if statement.else_body is not None:
                    result = self._execute_finite_block(
                        statement.else_body,
                        dict(current),
                        import_map,
                        stack,
                        budget,
                        collect_returns=collect_returns,
                    )
                    if result is None:
                        return None
                    branch_results.append(result)
                else:
                    branch_results.append((dict(current), [], True))
                returns.extend(
                    returned for _branch, values, _falls in branch_results for returned in values
                )
                continuing = [branch for branch, _values, falls in branch_results if falls]
                falls_through = bool(continuing)
                current = self._join_finite_environments(continuing) if continuing else current
                continue
            if isinstance(statement, PassStmt):
                continue
            return None
        return current, returns, falls_through

    def _finite_member_declaration(
        self, receiver: _FinitePointsTo, member_name: str
    ) -> tuple[str, InvocationKind] | None:
        """Dispatch only when every finite concrete class selects one declaration."""
        if not receiver.types or len(receiver.types) > self.MAX_POINTS_TO_TARGETS:
            if len(receiver.types) > self.MAX_POINTS_TO_TARGETS:
                self._record_analysis_limitation(
                    "MAX_POINTS_TO_TARGETS",
                    target_count=len(receiver.types),
                    limit=self.MAX_POINTS_TO_TARGETS,
                )
            return None
        declarations: set[tuple[str, InvocationKind]] = set()
        for fullname in receiver.types:
            info = self._exact_finite_project_type_info(fullname)
            member = info.get(member_name) if info is not None else None
            declaration = self._callable_declaration(member.node) if member is not None else None
            if declaration is None:
                return None
            declarations.add(declaration)
        return next(iter(declarations)) if len(declarations) == 1 else None

    @staticmethod
    def _exact_call_argument(
        call: Any,
        positional_index: int,
        keyword_name: str,
    ) -> Any | None:
        """Select one exact explicit call argument without expanding stars."""
        from mypy.nodes import ARG_NAMED, ARG_POS

        for expression, kind, name in zip(
            call.args,
            call.arg_kinds,
            call.arg_names,
            strict=True,
        ):
            if kind == ARG_NAMED and name == keyword_name:
                return expression
        positional = [
            expression
            for expression, kind, name in zip(
                call.args,
                call.arg_kinds,
                call.arg_names,
                strict=True,
            )
            if kind == ARG_POS and name is None
        ]
        return positional[positional_index] if positional_index < len(positional) else None

    @staticmethod
    def _valid_builtin_generator_consumer(call: Any, fullname: str) -> bool:
        """Recognize exact eager consumer shapes from Python's documented signatures."""
        from mypy.nodes import ARG_NAMED, ARG_POS

        arguments = list(zip(call.arg_kinds, call.arg_names, strict=True))
        if any(
            kind not in {ARG_POS, ARG_NAMED}
            or (kind == ARG_POS and name is not None)
            or (kind == ARG_NAMED and name is None)
            for kind, name in arguments
        ):
            return False
        named = [name for kind, name in arguments if kind == ARG_NAMED]
        if len(named) != len(set(named)):
            return False
        positional = len([kind for kind, _name in arguments if kind == ARG_POS])
        first_is_positional = bool(arguments) and arguments[0] == (ARG_POS, None)
        if fullname == "collections.deque":
            return (
                positional <= 2
                and set(named) <= {"iterable", "maxlen"}
                and not (positional >= 1 and "iterable" in named)
                and not (positional >= 2 and "maxlen" in named)
                and (first_is_positional or "iterable" in named)
            )
        if not first_is_positional:
            return False
        if fullname == "builtins.dict":
            # Dictionary keywords are entries, never the iterable argument.
            return positional == 1
        if fullname == "builtins.sum":
            return (
                positional in {1, 2}
                and set(named) <= {"start"}
                and not (positional == 2 and "start" in named)
            )
        if fullname in {"builtins.min", "builtins.max"}:
            # The multi-argument form compares arguments without consuming them.
            return positional == 1 and set(named) <= {"key", "default"}
        if fullname == "builtins.sorted":
            return positional == 1 and set(named) <= {"key", "reverse"}
        counts = {
            "builtins.all": {1},
            "builtins.any": {1},
            "builtins.list": {1},
            "builtins.set": {1},
            "builtins.frozenset": {1},
            "builtins.tuple": {1},
            "builtins.next": {1, 2},
            "builtins.anext": {1, 2},
        }
        return positional in counts.get(fullname, set()) and not named

    def _callback_binding(
        self,
        call: Any,
        summary: _ExecutorSummary,
    ) -> tuple[Any, Any] | None:
        """Extract one callback plus its explicitly forwarded args and kwargs."""
        from mypy.nodes import ARG_NAMED, ARG_POS

        arguments = list(zip(call.args, call.arg_kinds, call.arg_names, strict=True))
        callback_offset: int | None = None
        if summary.allow_callback_keyword:
            callback_offset = next(
                (
                    offset
                    for offset, (_expression, kind, name) in enumerate(arguments)
                    if kind == ARG_NAMED and name == "func"
                ),
                None,
            )
        if callback_offset is None:
            positional_offsets = [
                offset
                for offset, (_expression, kind, name) in enumerate(arguments)
                if kind == ARG_POS and name is None
            ]
            if summary.callback_index >= len(positional_offsets):
                return None
            callback_offset = positional_offsets[summary.callback_index]

        callback_expression = arguments[callback_offset][0]
        forwarded = []
        for offset, argument in enumerate(arguments):
            if offset == callback_offset:
                continue
            _expression, kind, name = argument
            if kind == ARG_NAMED:
                if name in summary.control_keywords:
                    continue
                if not summary.forwards_keyword_arguments:
                    continue
            forwarded.append(argument)
        forwarded_call = SimpleNamespace(
            args=[argument[0] for argument in forwarded],
            arg_kinds=[argument[1] for argument in forwarded],
            arg_names=[argument[2] for argument in forwarded],
        )
        return callback_expression, forwarded_call

    def _callback_body_executes(self, fullname: str, *, allow_async: bool) -> bool:
        """Reject callbacks whose invocation creates a deferred generator object."""
        resolved = self._function_node_for_fullname(fullname)
        if resolved is None:
            return False
        function = self._actual_function(resolved[0])
        if any(
            bool(getattr(function, attribute, False))
            for attribute in ("is_generator", "is_async_generator")
        ):
            return False
        return allow_async or not bool(getattr(function, "is_coroutine", False))

    def _exact_executor_callback(
        self,
        expression: Any,
        environment: dict[str, _FinitePointsTo],
        import_map: dict[str, str],
        budget: list[int],
        *,
        allow_async: bool = False,
    ) -> tuple[tuple[str, InvocationKind], _FinitePointsTo | None] | None:
        """Resolve one source-proven project callback without callable fanout."""
        from mypy.nodes import MemberExpr

        if isinstance(expression, MemberExpr):
            receiver = self._finite_expression_value(
                expression.expr, environment, import_map, (), budget
            )
            declaration = (
                self._finite_member_declaration(receiver, expression.name)
                if receiver is not None
                else None
            )
            return (
                (declaration, receiver)
                if declaration is not None
                and self._callback_body_executes(declaration[0], allow_async=allow_async)
                else None
            )
        imported = self._explicit_import_fullname(expression, import_map)
        declaration = (
            self._exact_finite_project_callable(imported) if imported is not None else None
        )
        if declaration is None:
            direct = self._callable_declaration(getattr(expression, "node", None))
            declaration = (
                direct
                if direct is not None and self._exact_project_identity(direct[0]) is not None
                else None
            )
        if declaration is None or not self._callback_body_executes(
            declaration[0], allow_async=allow_async
        ):
            return None
        return declaration, None

    def _executor_callback_environment(
        self,
        callback_fullname: str,
        callback_receiver: _FinitePointsTo | None,
        forwarded_call: Any,
        caller_environment: dict[str, _FinitePointsTo],
        caller_imports: dict[str, str],
        budget: list[int],
    ) -> dict[str, _FinitePointsTo] | None:
        """Bind only a valid explicit callback call; unknown values stay absent."""
        resolved = self._function_node_for_fullname(callback_fullname)
        if resolved is None:
            return None
        function, _path, _module = resolved
        bound = self._bind_finite_arguments(
            function,
            forwarded_call,
            caller_environment,
            caller_imports,
            (callback_fullname,),
            budget,
            receiver=callback_receiver,
        )
        return bound

    def _generator_fullname_kind(self, fullname: str) -> bool | None:
        """Return async/sync kind for one exact project generator declaration."""
        canonical = self._canonical_project_fullname(fullname) or fullname
        resolved = self._function_node_for_fullname(canonical)
        if resolved is None:
            return None
        actual = self._actual_function(resolved[0])
        if bool(getattr(actual, "is_async_generator", False)):
            return True
        if bool(getattr(actual, "is_generator", False)):
            return False
        return None

    def _generator_function_kind(
        self,
        call_site: ResolvedCallSite | None,
    ) -> bool | None:
        """Return async/sync kind for one exact project generator call."""
        if (
            call_site is None
            or call_site.status != CallResolutionStatus.EXACT
            or call_site.canonical_symbol is None
        ):
            return None
        return self._generator_fullname_kind(call_site.canonical_symbol)

    def _deferred_generator_call(
        self,
        call: Any,
        call_site: ResolvedCallSite | None,
        environment: dict[str, _FinitePointsTo],
        import_map: dict[str, str],
        budget: list[int],
    ) -> _DeferredGenerator | None:
        """Capture one exact valid generator call without executing its body."""
        from mypy.nodes import MemberExpr

        if (
            call_site is None
            or call_site.status != CallResolutionStatus.EXACT
            or call_site.canonical_symbol is None
        ):
            return None
        is_async = self._generator_function_kind(call_site)
        if is_async is None:
            return None
        resolved = self._function_node_for_fullname(call_site.canonical_symbol)
        if resolved is None:
            return None
        function, _path, _module = resolved
        declaration = self._callable_declaration(function)
        if declaration is None:
            return None
        _fullname, invocation = declaration
        implicit_receiver = invocation in (
            InvocationKind.INSTANCE_METHOD,
            InvocationKind.CLASS_METHOD,
        )
        receiver = (
            self._finite_expression_value(
                call.callee.expr,
                environment,
                import_map,
                (),
                budget,
            )
            if implicit_receiver and isinstance(call.callee, MemberExpr)
            else None
        )
        if implicit_receiver and receiver is None:
            return None
        bound = self._bind_finite_arguments(
            function,
            call,
            environment,
            import_map,
            (call_site.canonical_symbol,),
            budget,
            receiver=receiver,
            skip_implicit_receiver=implicit_receiver,
        )
        if bound is None:
            return None
        return _DeferredGenerator(
            fullname=call_site.canonical_symbol,
            receiver=receiver,
            environment=tuple(sorted(bound.items())),
            is_async=is_async,
        )

    def _member_call_resolution(
        self,
        callee: Any,
        import_map: dict[str, str],
    ) -> tuple[
        CallResolutionStatus,
        str | None,
        InvocationKind | None,
        tuple[str, ...],
        str | None,
    ]:
        """Resolve one member call through finite nominal receiver evidence."""
        from mypy.nodes import CallExpr, Decorator, FuncDef, NameExpr, TypeInfo, Var
        from mypy.types import Instance, UnionType, get_proper_type

        if (
            isinstance(callee.expr, CallExpr)
            and isinstance(callee.expr.callee, NameExpr)
            and callee.expr.callee.name == "super"
        ):
            declaration = self._callable_declaration(getattr(callee, "node", None))
            if declaration is not None and self._resolve_fullname_to_file(declaration[0]):
                return CallResolutionStatus.EXACT, *declaration, (), None

        imported_fullname = self._explicit_import_fullname(callee, import_map)
        if imported_fullname is not None:
            declaration = self._project_callable_declaration(
                imported_fullname
            ) or self._project_member_declaration(imported_fullname)
            if declaration is not None:
                resolved_symbol, invocation = declaration
                return CallResolutionStatus.EXACT, resolved_symbol, invocation, (), None

        receiver_infos: list[TypeInfo] = []
        incomplete = False
        source_exact_receiver = False
        if isinstance(callee.expr, NameExpr):
            imported = (
                import_map.get(callee.expr.name, "")
                if isinstance(callee.expr.node, Var)
                and callee.expr.node.line < 0
                and "." in (callee.expr.fullname or "")
                else ""
            )
            direct_info = (
                callee.expr.node
                if isinstance(callee.expr.node, TypeInfo)
                else self._project_type_info(imported)
            )
            if direct_info is not None:
                receiver_infos.append(direct_info)
        elif isinstance(callee.expr, CallExpr):
            constructor = callee.expr.callee
            imported = self._explicit_import_fullname(constructor, import_map) or ""
            if isinstance(constructor, NameExpr) and not imported:
                imported = (
                    import_map.get(constructor.name, "")
                    if isinstance(constructor.node, Var)
                    and constructor.node.line < 0
                    and "." in (constructor.fullname or "")
                    else ""
                )
            constructed = self._project_type_info(imported)
            if constructed is not None:
                receiver_infos.append(constructed)
                source_exact_receiver = True
        if not receiver_infos:
            receiver_type = self._get_type_from_node(callee.expr)
            if (
                receiver_type is None
                and isinstance(callee.expr, NameExpr)
                and isinstance(callee.expr.node, Var)
            ):
                receiver_type = callee.expr.node.type
            receiver = get_proper_type(receiver_type)
            receiver_items = receiver.items if isinstance(receiver, UnionType) else (receiver,)
            for item in receiver_items:
                proper = get_proper_type(item)
                if isinstance(proper, Instance):
                    receiver_infos.append(proper.type)
                else:
                    incomplete = True

        if receiver_infos:
            candidates = tuple(sorted({item.fullname for item in receiver_infos if item.fullname}))
            resolutions: set[tuple[str, InvocationKind]] = set()
            dynamically_final = True
            for info in receiver_infos:
                member = info.get(callee.name)
                declaration = (
                    self._callable_declaration(member.node) if member is not None else None
                )
                if declaration is None:
                    incomplete = True
                else:
                    resolutions.add(declaration)
                    method = member.node if member is not None else None
                    method_final = (
                        bool(getattr(method.var, "is_final", False))
                        if isinstance(method, Decorator)
                        else bool(getattr(method, "is_final", False))
                        if isinstance(method, FuncDef)
                        else False
                    )
                    dynamically_final = dynamically_final and (
                        bool(getattr(info, "is_final", False)) or method_final
                    )
            if len(resolutions) == 1 and not incomplete:
                resolved_symbol, invocation = next(iter(resolutions))
                # Project source is subject to subclass overrides. External
                # library declarations remain exact here because this
                # analyzer has no project implementation set to fan out to.
                resolved_file = self._resolve_fullname_to_file(resolved_symbol)
                if resolved_file is None or resolved_file[1] not in self._project_modules:
                    dynamically_final = True
                if source_exact_receiver:
                    dynamically_final = True
                if invocation != InvocationKind.INSTANCE_METHOD:
                    dynamically_final = True
                if dynamically_final:
                    return (
                        CallResolutionStatus.EXACT,
                        resolved_symbol,
                        invocation,
                        candidates,
                        None,
                    )
                return (
                    CallResolutionStatus.AMBIGUOUS,
                    None,
                    None,
                    candidates,
                    "open_receiver_dispatch",
                )
            if len(receiver_infos) > 1 or len(resolutions) > 1:
                return (
                    CallResolutionStatus.AMBIGUOUS,
                    None,
                    None,
                    candidates,
                    "ambiguous_receiver",
                )
            return (
                CallResolutionStatus.UNRESOLVED,
                None,
                None,
                candidates,
                "unresolved_member",
            )

        direct = self._callable_declaration(getattr(callee, "node", None))
        if direct is not None:
            resolved_symbol, invocation = direct
            return CallResolutionStatus.EXACT, resolved_symbol, invocation, (), None
        return (
            CallResolutionStatus.UNRESOLVED,
            None,
            None,
            (),
            "dynamic_receiver",
        )

    def _resolved_call_site(
        self,
        call: Any,
        current_file: str,
        import_map: dict[str, str],
        string_environment: dict[str, tuple[str, ...]] | None = None,
        lexical_scope: str | None = None,
    ) -> ResolvedCallSite | None:
        """Classify one mypy call expression without guessing symbol identity."""
        if string_environment or lexical_scope is not None:
            # This same physical call can be reached under different endpoint
            # actual-to-formal bindings; keep each trace's argument evidence
            # separate instead of reusing the node-identity cache entry.
            site = self._resolved_call_site_uncached(
                call,
                current_file,
                import_map,
                lexical_scope=lexical_scope,
            )
            if site is None:
                return None
            return site.model_copy(
                update={"arguments": self._call_argument_evidence(call, string_environment)}
            )
        cache_key = id(call)
        if cache_key not in self._resolved_call_site_cache:
            self._resolved_call_site_cache[cache_key] = self._resolved_call_site_uncached(
                call, current_file, import_map
            )
        return self._resolved_call_site_cache[cache_key]

    @staticmethod
    def _finite_string_values(
        expression: Any,
        environment: dict[str, tuple[str, ...]] | None = None,
    ) -> tuple[str, ...] | None:
        """Resolve a bounded literal string set without evaluating application code."""
        from mypy.nodes import ConditionalExpr, NameExpr, OpExpr, StrExpr, Var

        if isinstance(expression, StrExpr):
            return (expression.value,)
        if isinstance(expression, NameExpr) and isinstance(expression.node, Var):
            if environment is not None and expression.name in environment:
                return environment[expression.name]
            value = expression.node.final_value
            return (value,) if isinstance(value, str) else None
        if isinstance(expression, ConditionalExpr):
            left = MypyAnalyzer._finite_string_values(expression.if_expr, environment)
            right = MypyAnalyzer._finite_string_values(expression.else_expr, environment)
            if left is None or right is None:
                return None
            values = tuple(sorted({*left, *right}))
            return values if len(values) <= 8 else None
        if isinstance(expression, OpExpr) and expression.op == "+":
            left = MypyAnalyzer._finite_string_values(expression.left, environment)
            right = MypyAnalyzer._finite_string_values(expression.right, environment)
            if left is None or right is None:
                return None
            values = tuple(sorted({prefix + suffix for prefix in left for suffix in right}))
            return values if len(values) <= 8 else None
        return None

    @classmethod
    def _call_argument_evidence(
        cls,
        call: Any,
        string_environment: dict[str, tuple[str, ...]] | None = None,
    ) -> tuple[CallArgumentEvidence, ...]:
        """Capture positional/keyword literal identities with strict finite bounds."""
        from mypy.nodes import ARG_NAMED, ARG_POS

        evidence: list[CallArgumentEvidence] = []
        positional_index = 0
        for source_index, (expression, kind, name) in enumerate(
            zip(call.args, call.arg_kinds, call.arg_names, strict=True)
        ):
            if kind not in {ARG_POS, ARG_NAMED}:
                continue
            values = cls._finite_string_values(expression, string_environment)
            hashes = (
                tuple(
                    sorted(
                        f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"
                        for value in values
                    )
                )
                if values is not None
                else ()
            )
            status = (
                FiniteValueStatus.EXACT
                if len(hashes) == 1
                else FiniteValueStatus.FINITE
                if hashes
                else FiniteValueStatus.UNAVAILABLE
            )
            evidence.append(
                CallArgumentEvidence(
                    source_index=source_index,
                    positional_index=positional_index if kind == ARG_POS else None,
                    keyword=name if kind == ARG_NAMED else None,
                    status=status,
                    value_hashes=hashes,
                    reason_code="dynamic_argument" if not hashes else None,
                )
            )
            if kind == ARG_POS:
                positional_index += 1
        return tuple(evidence)

    @staticmethod
    def _identity_from_argument(
        call: Any,
    ) -> ResourceIdentityEvidence:
        """Use only the first finite positional argument as a constructor resource."""
        arguments = MypyAnalyzer._call_argument_evidence(call)
        selected = next((item for item in arguments if item.positional_index == 0), None)
        if selected is None:
            return ResourceIdentityEvidence(
                status=FiniteValueStatus.UNAVAILABLE,
                reason_code="origin_argument_absent",
            )
        return ResourceIdentityEvidence(
            status=selected.status,
            value_hashes=selected.value_hashes,
            reason_code=selected.reason_code,
        )

    def _enclosing_function(self, current_file: str, line: int) -> Any | None:
        """Find one exact top-level or class function containing a source line."""
        from mypy.nodes import ClassDef, Decorator, FuncDef

        modules = self._modules_by_canonical_path.get(str(Path(current_file).resolve()), ())
        candidates: list[Any] = []
        for module in modules:
            tree = self._trees.get(module)
            if tree is None:
                continue
            definitions = list(tree.defs)
            for definition in definitions:
                nested = definition.defs.body if isinstance(definition, ClassDef) else ()
                for item in (definition, *nested):
                    function = item.func if isinstance(item, Decorator) else item
                    if not isinstance(function, FuncDef):
                        continue
                    start, end = self._get_func_lines(function)
                    if start <= line <= end:
                        candidates.append(function)
        unique = {id(item): item for item in candidates}
        return next(iter(unique.values())) if len(unique) == 1 else None

    @staticmethod
    def _origin_call_for_receiver(
        receiver: Any,
        function: Any,
        target_line: int,
    ) -> tuple[Any | None, str | None]:
        """Trace one local receiver through unconditional assignment or with binding."""
        from mypy.nodes import (
            AssignmentStmt,
            CallExpr,
            ForStmt,
            IfStmt,
            MatchStmt,
            NameExpr,
            OperatorAssignmentStmt,
            TryStmt,
            WhileStmt,
            WithStmt,
        )

        if isinstance(receiver, CallExpr):
            return receiver, None
        if not isinstance(receiver, NameExpr) or receiver.node is None:
            return None, "receiver_expression_unavailable"
        variable = receiver.node
        origin: Any | None = None

        def assign(candidate: Any) -> bool:
            nonlocal origin
            if origin is not None or not isinstance(candidate, CallExpr):
                return False
            origin = candidate
            return True

        def scan(block: Any, depth: int = 0) -> str | None:
            for statement in block.body:
                statement_line = getattr(statement, "line", -1)
                statement_end = getattr(statement, "end_line", statement_line) or statement_line
                if statement_line > target_line:
                    break
                if isinstance(statement, AssignmentStmt) and statement_line < target_line:
                    if any(
                        isinstance(target, NameExpr) and target.node is variable
                        for target in statement.lvalues
                    ) and not assign(statement.rvalue):
                        return "receiver_reassigned"
                    continue
                if (
                    isinstance(statement, OperatorAssignmentStmt)
                    and statement_line < target_line
                    and isinstance(statement.lvalue, NameExpr)
                    and statement.lvalue.node is variable
                ):
                    return "receiver_reassigned"
                if isinstance(statement, WithStmt):
                    contains_target = statement_line <= target_line <= statement_end
                    if contains_target and (len(statement.expr) != 1 or depth > 0):
                        return "receiver_context_unavailable"
                    matched = False
                    for expression, target in zip(statement.expr, statement.target, strict=True):
                        if isinstance(target, NameExpr) and target.node is variable:
                            matched = True
                            if not contains_target or not assign(expression):
                                return "receiver_context_unavailable"
                    if contains_target:
                        nested_reason = scan(statement.body, depth + 1)
                        return nested_reason
                    if matched:
                        return "receiver_context_escaped"
                    continue
                if isinstance(statement, (IfStmt, ForStmt, WhileStmt, TryStmt, MatchStmt)):
                    if statement_line <= target_line:
                        return "receiver_control_flow_unavailable"
            return None

        reason = scan(function.body)
        if reason is not None:
            return None, reason
        if origin is None:
            return None, "receiver_origin_unavailable"
        return origin, None

    def _receiver_origin_identity(
        self,
        callee: Any,
        current_file: str,
        import_map: dict[str, str],
        line: int,
    ) -> ResourceIdentityEvidence:
        """Resolve finite Path/open receiver resources without spelling fallback."""
        from mypy.nodes import MemberExpr

        if not isinstance(callee, MemberExpr):
            return ResourceIdentityEvidence(
                status=FiniteValueStatus.UNAVAILABLE,
                reason_code="receiver_expression_unavailable",
            )
        function = self._enclosing_function(current_file, line)
        if function is None:
            return ResourceIdentityEvidence(
                status=FiniteValueStatus.UNAVAILABLE,
                reason_code="receiver_scope_unavailable",
            )
        origin, reason = self._origin_call_for_receiver(callee.expr, function, line)
        if origin is None:
            return ResourceIdentityEvidence(
                status=FiniteValueStatus.UNAVAILABLE,
                reason_code=reason or "receiver_origin_unavailable",
            )
        origin_site = self._resolved_call_site(origin, current_file, import_map)
        if origin_site is None or (
            origin_site.canonical_symbol,
            origin_site.invocation,
        ) not in {
            ("builtins.open", InvocationKind.FUNCTION),
            ("pathlib.Path", InvocationKind.CONSTRUCTOR),
        }:
            return ResourceIdentityEvidence(
                status=FiniteValueStatus.UNAVAILABLE,
                reason_code="receiver_origin_unsupported",
            )
        return self._identity_from_argument(origin)

    def _resolved_call_site_uncached(
        self,
        call: Any,
        current_file: str,
        import_map: dict[str, str],
        *,
        lexical_scope: str | None = None,
    ) -> ResolvedCallSite | None:
        """Resolve one physical project-source call for the analyzer-wide cache."""
        from mypy.nodes import MemberExpr, NameExpr, SuperExpr, TypeInfo, Var

        try:
            Path(current_file).resolve().relative_to(self.source_root.resolve())
        except ValueError:
            return None
        identity = self._call_source_identity(current_file, call.callee)
        if identity is None:
            return None
        line, column, end_line, end_column, spelling = identity
        status = CallResolutionStatus.UNRESOLVED
        canonical_symbol: str | None = None
        invocation: InvocationKind | None = None
        receiver_candidates: tuple[str, ...] = ()
        reason_code: str | None = "unsupported_callee_expression"
        callee = call.callee
        if isinstance(callee, NameExpr):
            if isinstance(callee.node, TypeInfo):
                status = CallResolutionStatus.EXACT
                canonical_symbol = callee.node.fullname
                invocation = InvocationKind.CONSTRUCTOR
                reason_code = None
            elif isinstance(callee.node, Var):
                imported = (
                    import_map.get(callee.name)
                    if callee.node.line < 0 and "." in (callee.fullname or "")
                    else None
                )
                declaration = (
                    self._project_callable_declaration(imported) if imported is not None else None
                )
                if declaration is not None:
                    status = CallResolutionStatus.EXACT
                    canonical_symbol, invocation = declaration
                    reason_code = None
                else:
                    reason_code = "dynamic_callable"
            else:
                declaration = self._callable_declaration(callee.node)
                if (
                    declaration is not None
                    and lexical_scope is not None
                    and self._exact_project_identity(declaration[0]) is None
                ):
                    local_fullname = f"{lexical_scope}.{declaration[0]}"
                    if self._function_node_for_fullname(local_fullname) is not None:
                        declaration = (local_fullname, declaration[1])
                if declaration is not None:
                    status = CallResolutionStatus.EXACT
                    canonical_symbol, invocation = declaration
                    reason_code = None
                else:
                    reason_code = "dynamic_callable"
        elif isinstance(callee, MemberExpr):
            (
                status,
                canonical_symbol,
                invocation,
                receiver_candidates,
                reason_code,
            ) = self._member_call_resolution(callee, import_map)
        elif isinstance(callee, SuperExpr) and callee.info is not None:
            declarations = []
            for info in callee.info.mro[1:]:
                member = info.names.get(callee.name)
                declaration = (
                    self._callable_declaration(member.node) if member is not None else None
                )
                if declaration is not None:
                    declarations.append(declaration)
                    break
            if len(declarations) == 1 and self._resolve_fullname_to_file(declarations[0][0]):
                status = CallResolutionStatus.EXACT
                canonical_symbol, invocation = declarations[0]
                receiver_candidates = (callee.info.fullname,)
                reason_code = None
            else:
                reason_code = "unresolved_super_dispatch"
        resolver_version = self._resolver_version
        receiver_origin = (
            self._receiver_origin_identity(callee, current_file, import_map, line)
            if status == CallResolutionStatus.EXACT and invocation == InvocationKind.INSTANCE_METHOD
            else None
        )
        try:
            return ResolvedCallSite(
                file_path=str(Path(current_file).resolve()),
                line=line,
                column=column,
                end_line=end_line,
                end_column=end_column,
                source_spelling=spelling,
                canonical_symbol=canonical_symbol,
                invocation=invocation,
                status=status,
                resolver="mypy",
                resolver_version=resolver_version,
                receiver_candidates=receiver_candidates,
                reason_code=reason_code,
                arguments=self._call_argument_evidence(call),
                receiver_origin=receiver_origin,
            )
        except ValueError:
            return ResolvedCallSite(
                file_path=str(Path(current_file).resolve()),
                line=line,
                column=column,
                end_line=end_line,
                end_column=end_column,
                source_spelling=spelling,
                status=CallResolutionStatus.UNRESOLVED,
                resolver="mypy",
                resolver_version=resolver_version,
                receiver_candidates=receiver_candidates,
                reason_code="invalid_symbol_identity",
                arguments=self._call_argument_evidence(call),
            )

    def _trace_references(self, *args: Any, **kwargs: Any) -> None:
        """Keep source and endpoint context scoped across recursive traces."""
        saved = (
            self._active_endpoint_dependencies,
            self._active_source_file,
            self._active_source_line,
            self._active_source_column,
        )
        try:
            self._trace_references_impl(*args, **kwargs)
        finally:
            (
                self._active_endpoint_dependencies,
                self._active_source_file,
                self._active_source_line,
                self._active_source_column,
            ) = saved

    def _trace_references_impl(
        self,
        node: Any,
        deps: EndpointDependencies,
        current_file: str,
        current_module: str,
        call_stack: list[CallFrame],
        visited: dict[
            tuple[
                str,
                bool,
                _FinitePointsTo | None,
                tuple[tuple[str, _FinitePointsTo], ...],
                tuple[tuple[str, tuple[str, ...]], ...],
                tuple[
                    tuple[
                        str,
                        tuple[tuple[str, InvocationKind], _FinitePointsTo | None],
                    ],
                    ...,
                ],
            ],
            int,
        ],
        import_map: dict[str, str] | None = None,
        *,
        depth: int,
        low_confidence_path: bool = False,
        receiver_value: _FinitePointsTo | None = None,
        initial_environment: dict[str, _FinitePointsTo] | None = None,
        initial_string_environment: dict[str, tuple[str, ...]] | None = None,
        initial_callable_environment: dict[
            str, tuple[tuple[str, InvocationKind], _FinitePointsTo | None]
        ]
        | None = None,
        finite_edge_budget: list[int] | None = None,
    ) -> None:
        """
        Trace all references in a mypy AST node.

        Uses mypy's types map to resolve method calls when type info is available.

        Args:
            import_map: Maps local names to their actual fullnames from imports
        """
        if import_map is None:
            import_map = {}
        if finite_edge_budget is None:
            finite_edge_budget = [0]

        from mypy.nodes import (
            ARG_NAMED,
            ARG_OPT,
            ARG_POS,
            ARG_STAR,
            ARG_STAR2,
            AssertStmt,
            AssignmentStmt,
            AwaitExpr,
            Block,
            BreakStmt,
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

        flow_environment: dict[str, _FinitePointsTo] = dict(initial_environment or {})
        string_environment: dict[str, tuple[str, ...]] = dict(initial_string_environment or {})
        function_node = self._actual_function(node)
        lexical_scope = call_stack[-1].function_name if call_stack else ""
        if not lexical_scope.startswith(f"{current_module}."):
            lexical_scope = f"{current_module}.{getattr(function_node, 'name', '')}"
        if receiver_value is not None and getattr(function_node, "arguments", None):
            self_name = function_node.arguments[0].variable.name
            flow_environment[self_name] = receiver_value
        finite_budget = [0]
        awaited_call_ids: set[int] = set()
        consumed_generator_call_kinds: dict[int, bool | None] = {}
        consumed_generator_expression_ids: set[int] = set()
        eager_generator_expression_depth = [0]
        deferred_environment: dict[str, _DeferredGenerator] = {}
        # Callable aliases are kept separately from object points-to values.
        # The tuple retains a bound receiver when the source assignment proves
        # one; arbitrary callable expressions remain unresolved.
        callable_environment: dict[
            str, tuple[tuple[str, InvocationKind], _FinitePointsTo | None]
        ] = dict(initial_callable_environment or {})
        partial_environment: dict[str, _PartialCallable] = {}
        lambda_environment: dict[str, Any] = {}
        lambda_execution_states: dict[int, str] = {}
        possible_execution_depth = [0]

        def record_lambda_execution(expression: Any, state: str) -> None:
            """Attach exact source-body state when its AST identity is unique."""
            if not isinstance(expression, LambdaExpr):
                return
            if state == "executed" and possible_execution_depth[0]:
                state = "possible"
            lambda_execution_states[id(expression)] = state
            span = self._lambda_body_source_span(
                function_node,
                expression,
                current_file,
                state,
            )
            if span is not None:
                deps.add_source_evidence_span(span)
                if state in {"deferred", "possible"}:
                    lexical = self._lambda_body_source_span(
                        function_node, expression, current_file, "lexical"
                    )
                    if lexical is not None:
                        deps.add_source_evidence_span(lexical)

        def resolve_and_trace(
            fullname: str,
            call_line: int,
            *,
            call_column: int | None = None,
            low_confidence_edge: bool = False,
            target_receiver: _FinitePointsTo | None = None,
            target_environment: dict[str, _FinitePointsTo] | None = None,
            target_string_environment: dict[str, tuple[str, ...]] | None = None,
            target_callable_environment: dict[
                str, tuple[tuple[str, InvocationKind], _FinitePointsTo | None]
            ]
            | None = None,
            edge_kind: str | None = None,
        ) -> None:
            """Resolve a fullname and preserve LOW provenance through descendants."""
            self._active_source_file = current_file
            self._active_source_line = call_line
            self._active_source_column = call_column
            target_depth = depth + 1
            # External and unresolved symbols do not consume project traversal depth.
            result = self._resolve_fullname_to_file(fullname)
            if result is None or result[1] not in self._project_modules:
                return
            if target_depth >= self.max_depth:
                self._record_analysis_limitation("MAX_DEPTH", limit=self.max_depth)
            if low_confidence_edge:
                if finite_edge_budget[0] >= self.MAX_POINTS_TO_EDGES:
                    self._record_analysis_limitation(
                        "MAX_POINTS_TO_EDGES", limit=self.MAX_POINTS_TO_EDGES
                    )
                    return
                finite_edge_budget[0] += 1
            target_low_confidence = low_confidence_path or low_confidence_edge
            environment_key = tuple(sorted((target_environment or {}).items()))
            string_environment_key = tuple(sorted((target_string_environment or {}).items()))
            callable_environment_key = tuple(sorted((target_callable_environment or {}).items()))
            visit_key = (
                fullname,
                target_low_confidence,
                target_receiver,
                environment_key,
                string_environment_key,
                callable_environment_key,
            )
            previous_depth = visited.get(visit_key)
            should_recurse = previous_depth is None or target_depth < previous_depth
            if should_recurse:
                visited[visit_key] = target_depth

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
                header_start, header_end = self._callable_header_lines(target_func, target_path)
                deps.add_symbol_reference(
                    target_path,
                    fullname,
                    header_start,
                    header_end,
                    low_confidence=target_low_confidence,
                )

                # Record the edge as well as target definition provenance. The
                # caller location is required for later effect/alias analysis.
                new_frame = CallFrame(
                    target_path,
                    start,
                    fullname,
                    code_context=f"Execution summary: {edge_kind}" if edge_kind else "",
                    caller_file_path=current_file,
                    caller_line_number=call_line,
                    caller_column_number=call_column,
                )
                new_stack = [*call_stack, new_frame]
                deps.add_call_stack(target_path, new_stack)

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
                        low_confidence_path=target_low_confidence,
                        receiver_value=target_receiver,
                        initial_environment=target_environment,
                        initial_string_environment=target_string_environment,
                        initial_callable_environment=target_callable_environment,
                        finite_edge_budget=finite_edge_budget,
                    )
            else:
                class_candidates = [
                    definition
                    for definition in target_tree.defs
                    if isinstance(definition, ClassDef) and definition.name == func_name
                ]
                if len(class_candidates) == 1:
                    class_node = class_candidates[0]
                    class_line = class_node.line
                    deps.add_symbol_reference(
                        target_path,
                        fullname,
                        class_line,
                        class_line,
                        low_confidence=target_low_confidence,
                    )
                    class_stack = [
                        *call_stack,
                        CallFrame(
                            target_path,
                            class_line,
                            fullname,
                            caller_file_path=current_file,
                            caller_line_number=call_line,
                            caller_column_number=call_column,
                        ),
                    ]
                    deps.add_call_stack(target_path, class_stack)
                    initializer = self._find_func_in_tree(
                        target_tree,
                        "__init__",
                        qualified_name=f"{class_node.name}.__init__",
                    )
                    if initializer is not None:
                        initializer_node, _initializer_name = initializer
                        start, end = self._callable_header_lines(initializer_node, target_path)
                        initializer_fullname = f"{fullname}.__init__"
                        deps.add_symbol_reference(
                            target_path,
                            initializer_fullname,
                            start,
                            end,
                            low_confidence=target_low_confidence,
                        )
                        if should_recurse and target_depth < self.max_depth:
                            self._trace_references(
                                initializer_node,
                                deps,
                                target_path,
                                target_module,
                                [*call_stack, CallFrame(target_path, start, initializer_fullname)],
                                visited,
                                self._import_map_for_tree(target_tree, target_module),
                                depth=target_depth,
                                low_confidence_path=target_low_confidence,
                                receiver_value=target_receiver,
                                initial_environment=target_environment,
                                initial_string_environment=target_string_environment,
                                initial_callable_environment=target_callable_environment,
                                finite_edge_budget=finite_edge_budget,
                            )
                # Ambiguous or unresolved symbols are not converted into
                # fabricated module ranges; doing so creates unrelated impacts.

        def consume_deferred_generator(
            generator: _DeferredGenerator,
            line: int,
        ) -> None:
            """Execute one exact deferred generator body at a proven consumer."""
            deps.add_reference(current_file, line, generator.fullname)
            resolve_and_trace(
                generator.fullname,
                line,
                low_confidence_edge=True,
                target_receiver=generator.receiver,
                target_environment=dict(generator.environment),
                edge_kind=(
                    "consumed_async_generator" if generator.is_async else "consumed_generator"
                ),
            )

        def consume_generator_expression(
            expression: Any,
            line: int,
            *,
            require_async: bool | None,
        ) -> None:
            """Mark a direct generator call or consume one protocol-matched alias."""
            if isinstance(expression, CallExpr):
                consumed_generator_call_kinds[id(expression)] = require_async
            elif isinstance(expression, GeneratorExpr):
                if not require_async:
                    consumed_generator_expression_ids.add(id(expression))
            elif isinstance(expression, NameExpr):
                generator = deferred_environment.get(expression.name)
                if generator is not None and (
                    require_async is None or generator.is_async == require_async
                ):
                    consume_deferred_generator(generator, line)

        def handle_call_expr(call: CallExpr) -> None:
            """Trace exact calls, adding bounded finite receiver edges as LOW only."""
            nonlocal string_environment
            call_site = self._resolved_call_site(
                call,
                current_file,
                import_map,
                string_environment,
                lexical_scope,
            )
            if call_site is not None:
                deps.add_resolved_call_site(call_site)
            callee = call.callee
            traced = False

            if isinstance(callee, NameExpr):
                assigned_lambda = lambda_environment.get(callee.name)
                if assigned_lambda is not None:
                    lambda_expression = (
                        assigned_lambda[0]
                        if isinstance(assigned_lambda, tuple) and len(assigned_lambda) == 4
                        else assigned_lambda
                    )
                    bound_strings = self._bind_finite_string_arguments(
                        lambda_expression,
                        call,
                        string_environment,
                    )
                    original_strings = string_environment
                    if bound_strings is not None:
                        string_environment = {**string_environment, **bound_strings}
                    if (
                        isinstance(assigned_lambda, tuple)
                        and len(assigned_lambda) == 4
                        and isinstance(assigned_lambda[1], str)
                    ):
                        expression, lambda_path, lambda_module, lambda_name = assigned_lambda
                        lambda_line = int(getattr(expression, "line", call.line) or call.line)
                        lambda_stack = [
                            *call_stack,
                            CallFrame(
                                lambda_path,
                                lambda_line,
                                lambda_name,
                                caller_file_path=current_file,
                                caller_line_number=call.line,
                                caller_column_number=call.column,
                            ),
                        ]
                        deps.add_symbol_reference(
                            lambda_path,
                            lambda_name,
                            lambda_line,
                            lambda_line,
                        )
                        deps.add_call_stack(lambda_path, lambda_stack)
                        lambda_imports = self._import_map_for_tree(
                            self._trees[lambda_module], lambda_module
                        )
                        for statement in getattr(expression.body, "body", ()):
                            self._trace_references(
                                statement,
                                deps,
                                lambda_path,
                                lambda_module,
                                lambda_stack,
                                visited,
                                lambda_imports,
                                depth=depth + 1,
                                low_confidence_path=low_confidence_path,
                                finite_edge_budget=finite_edge_budget,
                            )
                    else:
                        record_lambda_execution(lambda_expression, "executed")
                        walk_node(assigned_lambda.body)
                    string_environment = original_strings
                    traced = True

                partial_alias = partial_environment.get(callee.name)
                callable_alias_value: Any = (
                    (partial_alias.declaration, partial_alias.receiver)
                    if partial_alias is not None
                    else callable_environment.get(callee.name)
                )
                callable_alias_is_possible = isinstance(callable_alias_value, _CallableUnion)
                callable_aliases = (
                    callable_alias_value.targets
                    if callable_alias_is_possible
                    else (callable_alias_value,)
                    if callable_alias_value is not None
                    else ()
                )
                if callable_aliases:
                    binding_call: Any = call
                    invocation_keywords = {
                        name
                        for kind, name in zip(call.arg_kinds, call.arg_names, strict=True)
                        if kind == ARG_NAMED and name is not None
                    }
                    partial_function = (
                        self._function_node_for_fullname(partial_alias.declaration[0])
                        if partial_alias is not None
                        else None
                    )
                    positional_formals = []
                    if partial_function is not None:
                        partial_arguments = list(
                            getattr(self._actual_function(partial_function[0]), "arguments", ())
                        )
                        if (
                            partial_alias is not None
                            and partial_alias.declaration[1] == InvocationKind.INSTANCE_METHOD
                        ):
                            partial_arguments = partial_arguments[1:]
                        positional_formals = [
                            item for item in partial_arguments if item.kind in (ARG_POS, ARG_OPT)
                        ]
                    positional_partial_parameters = (
                        {
                            positional_formals[index].variable.name
                            for index, kind in enumerate(partial_alias.arg_kinds)
                            if kind == ARG_POS and index < len(positional_formals)
                        }
                        if partial_alias is not None and partial_function is not None
                        else set()
                    )
                    invocation_positional_parameters: set[str] = set()
                    invocation_parameters = set(invocation_keywords)
                    if partial_function is not None:
                        partial_positional_count = (
                            sum(kind == ARG_POS for kind in partial_alias.arg_kinds)
                            if partial_alias is not None
                            else 0
                        )
                        positional_formals = positional_formals[partial_positional_count:]
                        invocation_positional_count = 0
                        for kind, name in zip(call.arg_kinds, call.arg_names, strict=True):
                            if kind == ARG_POS and name is None:
                                if invocation_positional_count < len(positional_formals):
                                    parameter_name = positional_formals[
                                        invocation_positional_count
                                    ].variable.name
                                    invocation_parameters.add(parameter_name)
                                    invocation_positional_parameters.add(parameter_name)
                                invocation_positional_count += 1
                    stored_keyword_parameters: set[str] = set()
                    if partial_alias is not None and partial_function is not None:
                        for kind, name in zip(
                            partial_alias.arg_kinds,
                            partial_alias.arg_names,
                            strict=True,
                        ):
                            if kind == ARG_NAMED and name is not None:
                                stored_keyword_parameters.add(name)
                    invalid_partial_duplicate = bool(
                        partial_alias is not None
                        and (
                            any(
                                parameter in invocation_keywords
                                and parameter in positional_partial_parameters
                                for parameter, _captured in partial_alias.bound_callables
                            )
                            or bool(stored_keyword_parameters & invocation_positional_parameters)
                        )
                    )
                    if partial_alias is not None:
                        from types import SimpleNamespace as _CallShape

                        kept_bound = [
                            (expression, kind, name)
                            for expression, kind, name in zip(
                                partial_alias.args,
                                partial_alias.arg_kinds,
                                partial_alias.arg_names,
                                strict=True,
                            )
                            if name is None or name not in invocation_keywords
                        ]
                        binding_call = _CallShape(
                            args=[*(item[0] for item in kept_bound), *call.args],
                            arg_kinds=[*(item[1] for item in kept_bound), *call.arg_kinds],
                            arg_names=[*(item[2] for item in kept_bound), *call.arg_names],
                        )
                    for declaration, bound_receiver in callable_aliases:
                        alias_fullname, alias_invocation = declaration
                        if (
                            call_site is not None
                            and call_site.status != CallResolutionStatus.EXACT
                            and alias_invocation == InvocationKind.FUNCTION
                            and not callable_alias_is_possible
                            and not invalid_partial_duplicate
                        ):
                            deps.add_resolved_call_site(
                                call_site.model_copy(
                                    update={
                                        "canonical_symbol": alias_fullname,
                                        "invocation": alias_invocation,
                                        "status": CallResolutionStatus.EXACT,
                                        "reason_code": None,
                                    }
                                )
                            )
                        target_strings = None
                        resolved_function = self._function_node_for_fullname(alias_fullname)
                        if resolved_function is not None:
                            target_strings = self._bind_finite_string_arguments(
                                resolved_function[0],
                                binding_call,
                                string_environment,
                                skip_implicit_receiver=(
                                    alias_invocation == InvocationKind.INSTANCE_METHOD
                                ),
                            )
                        target_callables = (
                            self._bind_callable_arguments(
                                resolved_function[0],
                                binding_call,
                                callable_environment,
                                flow_environment,
                                import_map,
                                (),
                                finite_budget,
                                skip_implicit_receiver=(
                                    alias_invocation == InvocationKind.INSTANCE_METHOD
                                ),
                            )
                            if resolved_function is not None
                            else None
                        )
                        if partial_alias is not None:
                            # Creation-time callable values win over later rebinding
                            # of the source variable used to construct the partial.
                            if target_callables is None:
                                target_callables = {}
                            for parameter, captured_value in partial_alias.bound_callables:
                                if parameter not in invocation_parameters:
                                    target_callables[parameter] = captured_value
                        if partial_alias is not None:
                            if target_strings is None:
                                target_strings = {}
                            for parameter, captured_values in partial_alias.bound_strings:
                                if parameter not in invocation_parameters:
                                    target_strings[parameter] = captured_values
                        deps.add_reference(current_file, call.line, alias_fullname)
                        alias_is_unawaited_coroutine = bool(
                            resolved_function is not None
                            and getattr(
                                self._actual_function(resolved_function[0]), "is_coroutine", False
                            )
                            and id(call) not in awaited_call_ids
                        )
                        if invalid_partial_duplicate:
                            deps.add_analysis_limitation(
                                AnalysisLimitation(
                                    file_path=current_file,
                                    call_line=call.line,
                                    cap="INVALID_PARTIAL_ARGUMENTS",
                                    call_column=call.column,
                                )
                            )
                        elif not alias_is_unawaited_coroutine:
                            resolve_and_trace(
                                alias_fullname,
                                call.line,
                                call_column=call.column,
                                low_confidence_edge=callable_alias_is_possible,
                                target_receiver=(
                                    bound_receiver
                                    if alias_invocation == InvocationKind.INSTANCE_METHOD
                                    else None
                                ),
                                target_string_environment=target_strings,
                                target_callable_environment=target_callables,
                                edge_kind="callable_alias_invocation",
                            )
                        elif resolved_function is not None:
                            header_start, header_end = self._callable_header_lines(
                                resolved_function[0], resolved_function[1]
                            )
                            deps.add_symbol_reference(
                                resolved_function[1],
                                alias_fullname,
                                header_start,
                                header_end,
                            )
                        traced = True

            canonical_symbol = (call_site.canonical_symbol if call_site is not None else None) or ""
            generator_consumer = self.GENERATOR_CONSUMERS.get(canonical_symbol)
            if generator_consumer is not None:
                positional_index, keyword_name, require_async = generator_consumer
                consumed_expression = self._exact_call_argument(
                    call,
                    positional_index,
                    keyword_name,
                )
                if consumed_expression is not None:
                    consume_generator_expression(
                        consumed_expression,
                        call.line,
                        require_async=require_async,
                    )

            builtin_consumer = {
                "builtins.anext": True,
                "builtins.next": False,
                "builtins.all": False,
                "builtins.any": False,
                "builtins.list": False,
                "builtins.set": False,
                "builtins.frozenset": False,
                "builtins.tuple": False,
                "builtins.sum": False,
                "builtins.min": False,
                "builtins.max": False,
                "builtins.sorted": False,
                "builtins.dict": False,
                "collections.deque": False,
            }.get(canonical_symbol)
            if builtin_consumer is not None and self._valid_builtin_generator_consumer(
                call,
                canonical_symbol,
            ):
                consumed = (
                    self._exact_call_argument(call, 0, "iterable")
                    if canonical_symbol == "collections.deque"
                    else call.args[0]
                )
                if consumed is not None:
                    consume_generator_expression(
                        consumed,
                        call.line,
                        require_async=builtin_consumer,
                    )
            elif builtin_consumer is not None:
                if any(kind in {ARG_STAR, ARG_STAR2} for kind in call.arg_kinds):
                    deps.add_analysis_limitation(
                        AnalysisLimitation(
                            current_file,
                            call.line,
                            "UNRESOLVED_GENERATOR_CONSUMER_ARGUMENTS",
                            call_column=call.column,
                        )
                    )

            generator_kind = self._generator_function_kind(call_site)
            if generator_kind is not None:
                generator = self._deferred_generator_call(
                    call,
                    call_site,
                    flow_environment,
                    import_map,
                    finite_budget,
                )
                if generator is not None and id(call) in consumed_generator_call_kinds:
                    consumed_kind = consumed_generator_call_kinds[id(call)]
                    if consumed_kind is None or generator.is_async == consumed_kind:
                        consume_deferred_generator(generator, call.line)
                walk_node(callee)
                for argument in call.args:
                    walk_node(argument)
                flow_environment.clear()
                string_environment.clear()
                deferred_environment.clear()
                return

            wrapper_symbol = (
                call_site.canonical_symbol
                if call_site is not None and call_site.status == CallResolutionStatus.EXACT
                else None
            )
            callback_summary: _ExecutorSummary | None = None
            callback_edge_kind: str | None = None
            allow_async_callback = False
            if wrapper_symbol in self.EXECUTOR_SUMMARIES:
                traced = True
                if id(call) in awaited_call_ids:
                    callback_summary = self.EXECUTOR_SUMMARIES[wrapper_symbol]
                    callback_edge_kind = f"executor_callback:{wrapper_symbol}"
            elif wrapper_symbol in self.BACKGROUND_CALLBACK_SUMMARIES:
                traced = True
                callback_summary = self.BACKGROUND_CALLBACK_SUMMARIES[wrapper_symbol]
                callback_edge_kind = f"background_task_callback:{wrapper_symbol}"
                allow_async_callback = True
            elif wrapper_symbol in {
                "fastapi.param_functions.Depends",
                "fastapi.param_functions.Security",
            }:
                traced = True

            callback_binding = (
                self._callback_binding(call, callback_summary)
                if callback_summary is not None
                else None
            )
            if callback_binding is not None:
                callback_expression, forwarded_call = callback_binding
                callback = self._exact_executor_callback(
                    callback_expression,
                    flow_environment,
                    import_map,
                    finite_budget,
                    allow_async=allow_async_callback,
                )
                if callback is not None:
                    declaration, callback_receiver = callback
                    callback_fullname, callback_invocation = declaration
                    if callback_invocation == InvocationKind.FUNCTION:
                        callback_receiver = None
                    callback_environment = self._executor_callback_environment(
                        callback_fullname,
                        callback_receiver,
                        forwarded_call,
                        flow_environment,
                        import_map,
                        finite_budget,
                    )
                    if callback_environment is not None:
                        deps.add_reference(current_file, call.line, callback_fullname)
                        resolve_and_trace(
                            callback_fullname,
                            call.line,
                            call_column=call.column,
                            low_confidence_edge=True,
                            target_receiver=callback_receiver,
                            target_environment=callback_environment,
                            edge_kind=callback_edge_kind,
                        )

            if isinstance(callee, MemberExpr) and (
                call_site is None or call_site.status != CallResolutionStatus.EXACT
            ):
                finite_receiver = self._finite_expression_value(
                    callee.expr,
                    flow_environment,
                    import_map,
                    (),
                    finite_budget,
                )
                finite_declaration = (
                    self._finite_member_declaration(finite_receiver, callee.name)
                    if finite_receiver is not None
                    else None
                )
                if finite_declaration is not None:
                    finite_fullname, _invocation = finite_declaration
                    deps.add_reference(current_file, call.line, finite_fullname)
                    resolve_and_trace(
                        finite_fullname,
                        call.line,
                        call_column=call.column,
                        low_confidence_edge=True,
                        target_receiver=finite_receiver,
                    )
                    traced = True

            if (
                not traced
                and call_site is not None
                and call_site.status == CallResolutionStatus.EXACT
                and call_site.canonical_symbol is not None
            ):
                deps.add_reference(current_file, call.line, call_site.canonical_symbol)
                target_strings = None
                resolved_function = self._function_node_for_fullname(call_site.canonical_symbol)
                target_callables = None
                unawaited_coroutine = bool(
                    resolved_function is not None
                    and getattr(self._actual_function(resolved_function[0]), "is_coroutine", False)
                    and id(call) not in awaited_call_ids
                )
                if resolved_function is not None:
                    target_strings = self._bind_finite_string_arguments(
                        resolved_function[0], call, string_environment
                    )
                    target_callables = self._bind_callable_arguments(
                        resolved_function[0],
                        call,
                        callable_environment,
                        flow_environment,
                        import_map,
                        (),
                        finite_budget,
                    )
                if not unawaited_coroutine:
                    resolve_and_trace(
                        call_site.canonical_symbol,
                        call.line,
                        call_column=call.column,
                        target_string_environment=target_strings,
                        target_callable_environment=target_callables,
                        low_confidence_edge=eager_generator_expression_depth[0] > 0,
                        edge_kind=(
                            "consumed_generator_expression"
                            if eager_generator_expression_depth[0] > 0
                            else None
                        ),
                    )
                elif resolved_function is not None:
                    header_start, header_end = self._callable_header_lines(
                        resolved_function[0], resolved_function[1]
                    )
                    deps.add_symbol_reference(
                        resolved_function[1],
                        call_site.canonical_symbol,
                        header_start,
                        header_end,
                    )

            # A returned lambda can retain a typed exact NameExpr while its
            # enclosing synthetic lambda scope has no stable call-site AST
            # pairing. Use that typed declaration for dependency traversal,
            # while leaving physical call identity unresolved.
            if (
                not traced
                and (call_site is None or call_site.status != CallResolutionStatus.EXACT)
                and isinstance(callee, NameExpr)
            ):
                typed_fullname = import_map.get(callee.name, callee.fullname or "")
                exact_identity = self._exact_project_identity(typed_fullname)
                exact_fullname = (
                    f"{exact_identity[0]}.{exact_identity[1]}"
                    if exact_identity is not None
                    else None
                )
                if exact_fullname is not None and self._function_node_for_fullname(exact_fullname):
                    deps.add_reference(current_file, call.line, exact_fullname)
                    resolve_and_trace(exact_fullname, call.line, call_column=call.column)
                    traced = True

            # FastAPI dependency injection passes callables as values rather
            # than invoking them in the handler body. Treat the callable given
            # to Depends() as an executable dependency, while keeping ordinary
            # NameExpr arguments isolated to avoid broad over-tracing.
            if (
                wrapper_symbol
                in {
                    "fastapi.param_functions.Depends",
                    "fastapi.param_functions.Security",
                }
                and call.args
            ):
                argument = call.args[0]
                if isinstance(argument, NameExpr) and argument.fullname:
                    dependency_fullname = import_map.get(argument.name, argument.fullname)
                    deps.add_reference(current_file, argument.line, dependency_fullname)
                    resolve_and_trace(
                        dependency_fullname,
                        argument.line,
                        call_column=argument.column,
                        edge_kind=f"fastapi_dependency:{wrapper_symbol}",
                    )

            # Walk nested calls before invalidating mutable local object state.
            if isinstance(callee, LambdaExpr):
                record_lambda_execution(callee, "executed")
                walk_node(callee.body)
            walk_node(callee)
            for arg in call.args:
                walk_node(arg)
            # A call with unrelated arguments cannot invalidate every local
            # fact. Kill only values explicitly exposed to the call; unknown
            # star expansion invalidates the bounded local state.
            exposed_names: set[str] = set()
            if isinstance(callee, MemberExpr) and isinstance(callee.expr, NameExpr):
                exposed_names.add(callee.expr.name)
            for argument, argument_kind in zip(
                call.args,
                call.arg_kinds,
                strict=True,
            ):
                if isinstance(argument, NameExpr):
                    exposed_names.add(argument.name)
                if argument_kind in (ARG_STAR, ARG_STAR2):
                    exposed_names.update(flow_environment)
                    exposed_names.update(deferred_environment)
                    exposed_names.update(callable_environment)
            for name in exposed_names:
                flow_environment.pop(name, None)
                deferred_environment.pop(name, None)
                callable_environment.pop(name, None)
                lambda_environment.pop(name, None)
                string_environment.pop(name, None)

        def walk_node(n: Any) -> None:
            """Recursively walk a mypy AST node with a bounded local environment."""
            nonlocal \
                callable_environment, \
                partial_environment, \
                deferred_environment, \
                flow_environment, \
                lambda_environment, \
                string_environment
            if n is None:
                return
            node_line = getattr(n, "line", 0)
            if isinstance(node_line, int) and node_line > 0:
                self._active_source_file = current_file
                self._active_source_line = node_line
                self._active_source_column = None

            source_line = int(getattr(n, "line", 0) or 0)
            if source_line > 0 and not isinstance(n, LambdaExpr):
                # The flow walk visits only executable statements and eager
                # expressions. Exact line evidence avoids making a reachable
                # wrapper own unreachable or deferred body lines.
                deps.add_symbol_reference(
                    current_file,
                    lexical_scope,
                    source_line,
                    source_line,
                    low_confidence=low_confidence_path,
                )

            if isinstance(n, CallExpr):
                self._active_source_file = current_file
                self._active_source_line = n.line
                self._active_source_column = n.column
                handle_call_expr(n)

            elif isinstance(n, MemberExpr):
                if n.fullname:
                    deps.add_reference(current_file, n.line, n.fullname)
                    self._add_global_value_reference(deps, n.fullname)
                walk_node(n.expr)

            elif isinstance(n, NameExpr):
                if n.fullname:
                    # Resolve using import map if available
                    actual_fullname = n.fullname
                    if n.name in import_map:
                        actual_fullname = import_map[n.name]

                    deps.add_reference(current_file, n.line, actual_fullname)
                    if n.name in import_map:
                        self._add_global_value_reference(deps, actual_fullname)
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
                # A nested function definition evaluates its signature and
                # decorators here; its body executes only through a call edge.
                if n is function_node:
                    if hasattr(n, "body"):
                        walk_node(n.body)
                elif self._returned_nested_function(function_node, n):
                    fullname = getattr(n, "fullname", None)
                    if isinstance(fullname, str):
                        if self._exact_project_identity(fullname) is None:
                            fullname = f"{lexical_scope}.{fullname}"
                        start, end = self._callable_header_lines(n, current_file)
                        deps.add_symbol_reference(
                            current_file,
                            fullname,
                            start,
                            end,
                            low_confidence=True,
                        )

            elif isinstance(n, Block):
                for stmt in n.body:
                    walk_node(stmt)
                    # Statements following an unconditional terminal cannot
                    # contribute executable references in this block.
                    if isinstance(stmt, (ReturnStmt, RaiseStmt)):
                        break

            elif isinstance(n, ExpressionStmt):
                walk_node(n.expr)

            elif isinstance(n, AssignmentStmt):
                value = self._finite_expression_value(
                    n.rvalue,
                    flow_environment,
                    import_map,
                    (),
                    finite_budget,
                )
                string_value = self._finite_string_values(n.rvalue, string_environment)
                deferred_value = (
                    self._deferred_generator_call(
                        n.rvalue,
                        self._resolved_call_site(n.rvalue, current_file, import_map),
                        flow_environment,
                        import_map,
                        finite_budget,
                    )
                    if isinstance(n.rvalue, CallExpr)
                    else (
                        deferred_environment.get(n.rvalue.name)
                        if isinstance(n.rvalue, NameExpr)
                        else None
                    )
                )
                callable_value: tuple[tuple[str, InvocationKind], _FinitePointsTo | None] | None = (
                    None
                )
                partial_value: _PartialCallable | None = (
                    partial_environment.get(n.rvalue.name)
                    if isinstance(n.rvalue, NameExpr)
                    else None
                )
                lambda_value = (
                    n.rvalue
                    if isinstance(n.rvalue, LambdaExpr)
                    else lambda_environment.get(n.rvalue.name)
                    if isinstance(n.rvalue, NameExpr)
                    else None
                )
                if isinstance(n.rvalue, NameExpr):
                    callable_value = callable_environment.get(n.rvalue.name)
                    if callable_value is None:
                        declaration = self._callable_declaration(getattr(n.rvalue, "node", None))
                        if declaration is None:
                            imported = self._explicit_import_fullname(n.rvalue, import_map)
                            declaration = (
                                self._project_callable_declaration(imported)
                                if imported is not None
                                else None
                            )
                        if declaration is not None:
                            callable_value = (declaration, None)
                elif isinstance(n.rvalue, MemberExpr):
                    declaration = self._callable_declaration(getattr(n.rvalue, "node", None))
                    receiver = self._finite_expression_value(
                        n.rvalue.expr,
                        flow_environment,
                        import_map,
                        (),
                        finite_budget,
                    )
                    if declaration is not None and (
                        declaration[1] != InvocationKind.INSTANCE_METHOD or receiver is not None
                    ):
                        callable_value = (declaration, receiver)
                elif isinstance(n.rvalue, CallExpr):
                    returned_call = self._resolved_call_site(
                        n.rvalue,
                        current_file,
                        import_map,
                        string_environment,
                        lexical_scope,
                    )
                    if (
                        returned_call is not None
                        and returned_call.status == CallResolutionStatus.EXACT
                        and returned_call.canonical_symbol is not None
                    ):
                        if returned_call.canonical_symbol == "functools.partial" and n.rvalue.args:
                            partial_target = n.rvalue.args[0]
                            target_value: (
                                tuple[tuple[str, InvocationKind], _FinitePointsTo | None] | None
                            ) = None
                            if isinstance(partial_target, NameExpr):
                                target_value = callable_environment.get(partial_target.name)
                                if target_value is None:
                                    declaration = self._callable_declaration(
                                        getattr(partial_target, "node", None)
                                    )
                                    if declaration is None:
                                        imported = self._explicit_import_fullname(
                                            partial_target, import_map
                                        )
                                        declaration = (
                                            self._project_callable_declaration(imported)
                                            if imported is not None
                                            else None
                                        )
                                    if declaration is not None and self._exact_project_identity(
                                        declaration[0]
                                    ):
                                        target_value = (declaration, None)
                            elif isinstance(partial_target, MemberExpr):
                                declaration = self._callable_declaration(
                                    getattr(partial_target, "node", None)
                                )
                                receiver = self._finite_expression_value(
                                    partial_target.expr,
                                    flow_environment,
                                    import_map,
                                    (),
                                    finite_budget,
                                )
                                if declaration is not None and self._exact_project_identity(
                                    declaration[0]
                                ):
                                    target_value = (declaration, receiver)
                            if isinstance(target_value, _CallableUnion):
                                # A partial over a branch-joined callable must not
                                # assume the union has tuple indexing semantics.
                                # Abstain until each alternative can be bound
                                # independently, and surface the lost precision.
                                self._record_analysis_limitation(
                                    "CALLABLE_UNION_PARTIAL", limit=len(target_value.targets)
                                )
                                target_value = None
                            if target_value is not None:
                                bound_callables: list[
                                    tuple[
                                        str,
                                        tuple[tuple[str, InvocationKind], _FinitePointsTo | None],
                                    ]
                                ] = []
                                bound_strings: list[tuple[str, tuple[str, ...]]] = []
                                target_node = self._function_node_for_fullname(target_value[0][0])
                                if target_node is not None:
                                    actual = self._actual_function(target_node[0])
                                    parameters = list(getattr(actual, "arguments", ()))
                                    if target_value[0][1] == InvocationKind.INSTANCE_METHOD:
                                        parameters = parameters[1:]
                                    positional_parameters = [
                                        item
                                        for item in parameters
                                        if item.kind in (ARG_POS, ARG_OPT)
                                    ]
                                    keyword_parameters = {
                                        item.variable.name: item
                                        for item in parameters
                                        if not item.pos_only
                                    }
                                    for expression, kind, name in zip(
                                        n.rvalue.args[1:],
                                        n.rvalue.arg_kinds[1:],
                                        n.rvalue.arg_names[1:],
                                        strict=True,
                                    ):
                                        parameter = None
                                        if (
                                            kind == ARG_POS
                                            and name is None
                                            and positional_parameters
                                        ):
                                            parameter = positional_parameters.pop(0)
                                        elif kind == ARG_NAMED and name in keyword_parameters:
                                            parameter = keyword_parameters[name]
                                        callable_actual: (
                                            tuple[
                                                tuple[str, InvocationKind],
                                                _FinitePointsTo | None,
                                            ]
                                            | None
                                        ) = None
                                        if isinstance(expression, NameExpr):
                                            callable_actual = callable_environment.get(
                                                expression.name
                                            )
                                            if callable_actual is None:
                                                declaration = self._callable_declaration(
                                                    getattr(expression, "node", None)
                                                )
                                                if (
                                                    declaration is not None
                                                    and self._exact_project_identity(declaration[0])
                                                ):
                                                    callable_actual = (declaration, None)
                                        elif isinstance(expression, MemberExpr):
                                            declaration = self._callable_declaration(
                                                getattr(expression, "node", None)
                                            )
                                            if (
                                                declaration is not None
                                                and self._exact_project_identity(declaration[0])
                                            ):
                                                receiver_value = self._finite_expression_value(
                                                    expression.expr,
                                                    flow_environment,
                                                    import_map,
                                                    (),
                                                    finite_budget,
                                                )
                                                if (
                                                    declaration[1] != InvocationKind.INSTANCE_METHOD
                                                    or receiver_value is not None
                                                ):
                                                    callable_actual = (declaration, receiver_value)
                                        if parameter is not None and callable_actual is not None:
                                            bound_callables.append(
                                                (parameter.variable.name, callable_actual)
                                            )
                                        if parameter is not None:
                                            string_actual = self._finite_string_values(
                                                expression, string_environment
                                            )
                                            if string_actual is not None:
                                                bound_strings.append(
                                                    (parameter.variable.name, string_actual)
                                                )
                                partial_value = _PartialCallable(
                                    declaration=target_value[0],
                                    receiver=target_value[1],
                                    args=tuple(n.rvalue.args[1:]),
                                    arg_kinds=tuple(n.rvalue.arg_kinds[1:]),
                                    arg_names=tuple(n.rvalue.arg_names[1:]),
                                    bound_callables=tuple(bound_callables),
                                    bound_strings=tuple(bound_strings),
                                )
                            callable_value = None
                        returned_declaration = self._returned_project_callable(
                            returned_call.canonical_symbol
                        )
                        if returned_declaration is not None and callable_value is None:
                            callable_value = (returned_declaration, None)
                        if lambda_value is None:
                            lambda_value = self._returned_lambda(returned_call.canonical_symbol)
                walk_node(n.rvalue)
                for lv in n.lvalues:
                    if isinstance(lv, NameExpr):
                        if value is None:
                            flow_environment.pop(lv.name, None)
                        else:
                            flow_environment[lv.name] = value
                        if string_value is None:
                            string_environment.pop(lv.name, None)
                        else:
                            string_environment[lv.name] = string_value
                        if deferred_value is None:
                            deferred_environment.pop(lv.name, None)
                        else:
                            deferred_environment[lv.name] = deferred_value
                        if callable_value is None:
                            callable_environment.pop(lv.name, None)
                        else:
                            callable_environment[lv.name] = callable_value
                        if partial_value is None:
                            partial_environment.pop(lv.name, None)
                        else:
                            partial_environment[lv.name] = partial_value
                        if lambda_value is None:
                            lambda_environment.pop(lv.name, None)
                        else:
                            lambda_environment[lv.name] = lambda_value
                    else:
                        # Arbitrary/reflection-driven member mutation invalidates all
                        # finite heap evidence outside constructor summarization.
                        flow_environment.clear()
                        string_environment.clear()
                        deferred_environment.clear()
                        callable_environment.clear()
                        lambda_environment.clear()
                    walk_node(lv)

            elif isinstance(n, ReturnStmt):
                walk_node(n.expr)

            elif isinstance(n, IfStmt):
                base_environment = dict(flow_environment)
                base_strings = dict(string_environment)
                base_deferred = dict(deferred_environment)
                base_callables = dict(callable_environment)
                base_partials = dict(partial_environment)
                base_lambdas = dict(lambda_environment)
                branch_environments: list[dict[str, _FinitePointsTo]] = []
                branch_strings: list[dict[str, tuple[str, ...]]] = []
                branch_deferred: list[dict[str, _DeferredGenerator]] = []
                branch_callables: list[
                    dict[str, tuple[tuple[str, InvocationKind], _FinitePointsTo | None]]
                ] = []
                branch_partials: list[dict[str, _PartialCallable]] = []
                branch_lambdas: list[dict[str, Any]] = []
                selected: int | None = None
                unknown_before_selection = False
                for expr, body in zip(n.expr, n.body, strict=True):
                    literal = self._literal_boolean(expr)
                    if literal is None:
                        literal = self._finite_string_condition(expr, base_strings)
                    if literal is False:
                        # Evaluating the condition is harmless; the body is
                        # statically unreachable.
                        walk_node(expr)
                        continue
                    if selected is not None:
                        continue
                    flow_environment = dict(base_environment)
                    string_environment = dict(base_strings)
                    deferred_environment = dict(base_deferred)
                    callable_environment = dict(base_callables)
                    partial_environment = dict(base_partials)
                    lambda_environment = dict(base_lambdas)
                    # An elif predicate is reached only if every preceding
                    # branch declined. Preserve that uncertainty for the
                    # predicate itself, and for even a literal-true body.
                    if unknown_before_selection:
                        possible_execution_depth[0] += 1
                    try:
                        walk_node(expr)
                    finally:
                        if unknown_before_selection:
                            possible_execution_depth[0] -= 1
                    branch_possible = literal is None or unknown_before_selection
                    if branch_possible:
                        possible_execution_depth[0] += 1
                    try:
                        walk_node(body)
                    finally:
                        if branch_possible:
                            possible_execution_depth[0] -= 1
                    branch_environments.append(dict(flow_environment))
                    branch_strings.append(dict(string_environment))
                    branch_deferred.append(dict(deferred_environment))
                    branch_callables.append(dict(callable_environment))
                    branch_partials.append(dict(partial_environment))
                    branch_lambdas.append(dict(lambda_environment))
                    if literal is True:
                        selected = len(branch_environments) - 1
                    else:
                        unknown_before_selection = True
                flow_environment = dict(base_environment)
                string_environment = dict(base_strings)
                deferred_environment = dict(base_deferred)
                callable_environment = dict(base_callables)
                partial_environment = dict(base_partials)
                lambda_environment = dict(base_lambdas)
                if n.else_body and selected is None:
                    if unknown_before_selection:
                        possible_execution_depth[0] += 1
                    try:
                        walk_node(n.else_body)
                    finally:
                        if unknown_before_selection:
                            possible_execution_depth[0] -= 1
                    branch_environments.append(dict(flow_environment))
                    branch_strings.append(dict(string_environment))
                    branch_deferred.append(dict(deferred_environment))
                    branch_callables.append(dict(callable_environment))
                    branch_partials.append(dict(partial_environment))
                    branch_lambdas.append(dict(lambda_environment))
                elif not n.else_body and selected is None:
                    branch_environments.append(base_environment)
                    branch_strings.append(base_strings)
                    branch_deferred.append(base_deferred)
                    branch_callables.append(base_callables)
                    branch_partials.append(base_partials)
                    branch_lambdas.append(base_lambdas)
                if selected is not None and not unknown_before_selection:
                    flow_environment = branch_environments[selected]
                    string_environment = branch_strings[selected]
                    deferred_environment = branch_deferred[selected]
                    callable_environment = branch_callables[selected]
                    partial_environment = branch_partials[selected]
                    lambda_environment = branch_lambdas[selected]
                else:
                    flow_environment = self._join_finite_environments(branch_environments)
                    common_string_names = (
                        set.intersection(*(set(branch) for branch in branch_strings))
                        if branch_strings
                        else set()
                    )
                    string_environment = {
                        name: branch_strings[0][name]
                        for name in common_string_names
                        if all(
                            branch_strings[0][name] == branch[name] for branch in branch_strings[1:]
                        )
                    }
                    if branch_deferred:
                        common_deferred = set.intersection(
                            *(set(branch) for branch in branch_deferred)
                        )
                        deferred_environment = {
                            name: branch_deferred[0][name]
                            for name in common_deferred
                            if all(
                                branch[name] == branch_deferred[0][name]
                                for branch in branch_deferred[1:]
                            )
                        }
                    callable_environment = self._join_callable_environments(branch_callables)
                    common_partials = (
                        set.intersection(*(set(branch) for branch in branch_partials))
                        if branch_partials
                        else set()
                    )
                    partial_environment = {
                        name: branch_partials[0][name]
                        for name in common_partials
                        if all(
                            branch[name] == branch_partials[0][name]
                            for branch in branch_partials[1:]
                        )
                    }
                    common_lambdas = (
                        set.intersection(*(set(branch) for branch in branch_lambdas))
                        if branch_lambdas
                        else set()
                    )
                    lambda_environment = {
                        name: branch_lambdas[0][name]
                        for name in common_lambdas
                        if all(
                            branch[name] is branch_lambdas[0][name] for branch in branch_lambdas[1:]
                        )
                    }

            elif isinstance(n, WhileStmt):
                walk_node(n.expr)
                if self._literal_boolean(n.expr) is False:
                    # The loop body is unreachable; only its else suite executes.
                    if n.else_body is not None:
                        walk_node(n.else_body)
                    return
                mandatory_single_pass = (
                    self._literal_boolean(n.expr) is True
                    and bool(n.body.body)
                    and isinstance(n.body.body[-1], BreakStmt)
                    and all(
                        not isinstance(item, (IfStmt, WhileStmt, ForStmt, TryStmt, BreakStmt))
                        for item in n.body.body[:-1]
                    )
                )
                before_callables = dict(callable_environment)
                before_partials = dict(partial_environment)
                before_lambdas = dict(lambda_environment)
                if not mandatory_single_pass:
                    possible_execution_depth[0] += 1
                try:
                    walk_node(n.body)
                finally:
                    if not mandatory_single_pass:
                        possible_execution_depth[0] -= 1
                after_callables = dict(callable_environment)
                after_partials = dict(partial_environment)
                after_lambdas = dict(lambda_environment)
                callable_environment = (
                    after_callables
                    if mandatory_single_pass
                    else self._join_callable_environments([before_callables, after_callables])
                )
                partial_environment = {
                    name: value
                    for name, value in (
                        after_partials.items() if mandatory_single_pass else before_partials.items()
                    )
                    if mandatory_single_pass or after_partials.get(name) == value
                }
                lambda_environment = {
                    name: value
                    for name, value in (
                        after_lambdas.items() if mandatory_single_pass else before_lambdas.items()
                    )
                    if mandatory_single_pass or after_lambdas.get(name) is value
                }
                flow_environment.clear()
                string_environment.clear()
                deferred_environment.clear()

            elif isinstance(n, ForStmt):
                consume_generator_expression(
                    n.expr,
                    n.line,
                    require_async=bool(n.is_async),
                )
                walk_node(n.expr)
                before_callables = dict(callable_environment)
                before_partials = dict(partial_environment)
                before_lambdas = dict(lambda_environment)
                possible_execution_depth[0] += 1
                try:
                    walk_node(n.body)
                finally:
                    possible_execution_depth[0] -= 1
                after_callables = dict(callable_environment)
                after_partials = dict(partial_environment)
                after_lambdas = dict(lambda_environment)
                callable_environment = self._join_callable_environments(
                    [before_callables, after_callables]
                )
                partial_environment = {
                    name: value
                    for name, value in before_partials.items()
                    if after_partials.get(name) == value
                }
                lambda_environment = {
                    name: value
                    for name, value in before_lambdas.items()
                    if after_lambdas.get(name) is value
                }
                flow_environment.clear()
                string_environment.clear()
                deferred_environment.clear()

            elif isinstance(n, WithStmt):
                for expr in n.expr:
                    walk_node(expr)
                flow_environment.clear()
                string_environment.clear()
                deferred_environment.clear()
                walk_node(n.body)
                flow_environment.clear()
                string_environment.clear()
                deferred_environment.clear()

            elif isinstance(n, TryStmt):
                # An exception may be raised before or after any assignment in the
                # protected body. Handler entry therefore joins the pre-try and
                # post-body callable state instead of inheriting one linear walk.
                before_callables = dict(callable_environment)
                before_partials = dict(partial_environment)
                before_lambdas = dict(lambda_environment)
                try_assigned_names: set[str] = set()
                try_assignment_lines: dict[str, int] = {}
                potentially_raising_lines: list[int] = []
                assignment_stack: list[Any] = [n.body]
                assignment_seen: set[int] = set()
                while assignment_stack:
                    assignment_item = assignment_stack.pop()
                    if assignment_item is None or id(assignment_item) in assignment_seen:
                        continue
                    assignment_seen.add(id(assignment_item))
                    if isinstance(assignment_item, AssignmentStmt):
                        for target in assignment_item.lvalues:
                            if isinstance(target, NameExpr):
                                try_assigned_names.add(target.name)
                                try_assignment_lines[target.name] = assignment_item.line
                    if isinstance(assignment_item, CallExpr):
                        potentially_raising_lines.append(assignment_item.line)
                    children = getattr(assignment_item, "children", None)
                    if callable(children):
                        assignment_stack.extend(child for child in children() if child is not None)
                walk_node(n.body)
                body_callables = dict(callable_environment)
                body_partials = dict(partial_environment)
                body_lambdas = dict(lambda_environment)
                normal_callables = dict(body_callables)
                normal_partials = dict(body_partials)
                normal_lambdas = dict(body_lambdas)
                handler_callables: list[
                    dict[str, tuple[tuple[str, InvocationKind], _FinitePointsTo | None]]
                ] = []
                handler_partials: list[dict[str, _PartialCallable]] = []
                handler_lambdas: list[dict[str, Any]] = []
                for handler in n.handlers:
                    exception_callables = dict(before_callables)
                    for name, assignment_line in try_assignment_lines.items():
                        if (
                            any(line > assignment_line for line in potentially_raising_lines)
                            and name in body_callables
                        ):
                            exception_callables[name] = body_callables[name]
                    callable_environment = self._join_callable_environments(
                        [before_callables, exception_callables]
                    )
                    partial_environment = {
                        key: value
                        for key, value in before_partials.items()
                        if key not in try_assigned_names and body_partials.get(key) == value
                    }
                    lambda_environment = {
                        key: value
                        for key, value in before_lambdas.items()
                        if key not in try_assigned_names and body_lambdas.get(key) is value
                    }
                    possible_execution_depth[0] += 1
                    try:
                        walk_node(handler)
                    finally:
                        possible_execution_depth[0] -= 1
                    handler_callables.append(dict(callable_environment))
                    handler_partials.append(dict(partial_environment))
                    handler_lambdas.append(dict(lambda_environment))
                if hasattr(n, "types") and n.types:
                    for exc_type in n.types:
                        if exc_type:
                            walk_node(exc_type)
                if n.else_body:
                    callable_environment = dict(body_callables)
                    partial_environment = dict(body_partials)
                    lambda_environment = dict(body_lambdas)
                    possible_execution_depth[0] += 1
                    try:
                        walk_node(n.else_body)
                    finally:
                        possible_execution_depth[0] -= 1
                    normal_callables = dict(callable_environment)
                    normal_partials = dict(partial_environment)
                    normal_lambdas = dict(lambda_environment)
                callable_paths = [normal_callables, *handler_callables]
                partial_paths = [normal_partials, *handler_partials]
                lambda_paths = [normal_lambdas, *handler_lambdas]
                if callable_paths:
                    callable_environment = self._join_callable_environments(callable_paths)
                if partial_paths:
                    common_partial = set.intersection(*(set(path) for path in partial_paths))
                    partial_environment = {
                        key: partial_paths[0][key]
                        for key in common_partial
                        if all(path[key] == partial_paths[0][key] for path in partial_paths[1:])
                    }
                if lambda_paths:
                    common_lambda = set.intersection(*(set(path) for path in lambda_paths))
                    lambda_environment = {
                        key: lambda_paths[0][key]
                        for key in common_lambda
                        if all(path[key] is lambda_paths[0][key] for path in lambda_paths[1:])
                    }
                if n.finally_body:
                    # Finally runs on every exit from an entered try. Retain
                    # enclosing uncertainty, without adding uncertainty just
                    # because control exits normally, raises, or returns.
                    walk_node(n.finally_body)
                flow_environment.clear()
                string_environment.clear()
                deferred_environment.clear()

            elif isinstance(n, AwaitExpr):
                if isinstance(n.expr, CallExpr):
                    awaited_call_ids.add(id(n.expr))
                walk_node(n.expr)

            elif isinstance(n, (RaiseStmt, AssertStmt)):
                walk_node(n.expr)

            elif isinstance(n, IndexExpr):
                walk_node(n.base)
                walk_node(n.index)

            elif isinstance(n, OpExpr):
                walk_node(n.left)
                if n.op in {"and", "or"}:
                    left_truth = self._literal_boolean(n.left)
                    if (n.op == "and" and left_truth is False) or (
                        n.op == "or" and left_truth is True
                    ):
                        return
                    if left_truth is None:
                        possible_execution_depth[0] += 1
                        try:
                            walk_node(n.right)
                        finally:
                            possible_execution_depth[0] -= 1
                    else:
                        walk_node(n.right)
                else:
                    walk_node(n.right)

            elif isinstance(n, ComparisonExpr):
                for op in n.operands:
                    walk_node(op)

            elif isinstance(n, UnaryExpr):
                walk_node(n.expr)

            elif isinstance(n, ConditionalExpr):
                walk_node(n.cond)
                condition_truth = self._literal_boolean(n.cond)
                if condition_truth is not None:
                    walk_node(n.if_expr if condition_truth else n.else_expr)
                else:
                    possible_execution_depth[0] += 1
                    try:
                        walk_node(n.if_expr)
                        walk_node(n.else_expr)
                    finally:
                        possible_execution_depth[0] -= 1

            elif isinstance(n, (ListExpr, TupleExpr, SetExpr)):
                for item in n.items:
                    walk_node(item)

            elif isinstance(n, DictExpr):
                for key, expression_value in n.items:
                    walk_node(key)
                    walk_node(expression_value)

            elif isinstance(n, (ListComprehension, SetComprehension)):
                generator = n.generator
                for sequence, is_async in zip(
                    generator.sequences,
                    generator.is_async,
                    strict=True,
                ):
                    consume_generator_expression(
                        sequence,
                        sequence.line,
                        require_async=bool(is_async),
                    )
                    walk_node(sequence)
                for conditions in generator.condlists:
                    for condition in conditions:
                        walk_node(condition)
                walk_node(generator.left_expr)

            elif isinstance(n, DictionaryComprehension):
                for sequence, is_async in zip(n.sequences, n.is_async, strict=True):
                    consume_generator_expression(
                        sequence,
                        sequence.line,
                        require_async=bool(is_async),
                    )
                    walk_node(sequence)
                for conditions in n.condlists:
                    for condition in conditions:
                        walk_node(condition)
                walk_node(n.key)
                walk_node(n.value)

            elif isinstance(n, GeneratorExpr):
                if id(n) in consumed_generator_expression_ids:
                    for sequence in n.sequences:
                        # Iterating a nested generator as an outer generator's
                        # iterable consumes that inner generator as well.
                        if isinstance(sequence, GeneratorExpr):
                            consume_generator_expression(
                                sequence,
                                sequence.line,
                                require_async=None,
                            )
                        walk_node(sequence)
                    for conditions in n.condlists:
                        for condition in conditions:
                            walk_node(condition)
                    eager_generator_expression_depth[0] += 1
                    try:
                        walk_node(n.left_expr)
                    finally:
                        eager_generator_expression_depth[0] -= 1
                elif n.sequences:
                    # Creating a generator expression evaluates only its outer iterable.
                    walk_node(n.sequences[0])

            elif isinstance(n, LambdaExpr):
                record_lambda_execution(
                    n,
                    lambda_execution_states.get(id(n), "deferred"),
                )
                # Walk lambda arguments (for default values)
                if hasattr(n, "arguments"):
                    for arg in n.arguments:
                        if hasattr(arg, "initializer") and arg.initializer:
                            walk_node(arg.initializer)
                # The body is deferred until the lambda is invoked.

            elif isinstance(n, YieldFromExpr):
                consume_generator_expression(n.expr, n.line, require_async=False)
                walk_node(n.expr)

            elif isinstance(n, YieldExpr):
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
                    resolve_and_trace(actual_fullname, decorator.line, call_column=decorator.column)
                    # Applying an exact project decorator installs its
                    # returned callable as the endpoint implementation. The
                    # decorator factory body runs at definition time, while
                    # its returned wrapper runs for each endpoint invocation.
                    returned_wrapper = self._returned_project_callable(actual_fullname)
                    if returned_wrapper is not None:
                        resolve_and_trace(
                            returned_wrapper[0],
                            decorator.line,
                            call_column=decorator.column,
                            edge_kind="decorator_wrapper_invocation",
                        )
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
        elif not isinstance(function_node, FuncDef):
            # Phase-sensitive framework callbacks pass exact body statements
            # instead of a whole function so pre/post-yield traversal cannot mix.
            walk_node(function_node)

    def analyze_endpoints(
        self,
        endpoints: list[Endpoint],
        use_cache: bool = True,
    ) -> dict[str, EndpointDependencies]:
        """Analyze multiple endpoints using one bounded exclusion census."""
        self._begin_analysis_cycle()
        try:
            return self._analyze_endpoints_in_cycle(endpoints, use_cache)
        finally:
            self._end_analysis_cycle()

    def _analyze_endpoints_in_cycle(
        self,
        endpoints: list[Endpoint],
        use_cache: bool,
    ) -> dict[str, EndpointDependencies]:
        """Analyze one snapshot while sharing its local-module policy."""
        # Try to load from cache
        if use_cache and self.cache_path.exists() and self._load_cache():
            if self._endpoint_deps:
                # Validate imported typing inputs before retaining even a
                # partial set of endpoint rows. Otherwise a request that adds
                # an endpoint can combine rows analyzed against old stubs with
                # rows analyzed against the current environment.
                try:
                    self._ensure_mypy_built()
                except MypyAnalyzerError:
                    self._verified_mypy_source_hashes = {}
                    self._verified_package_source_hashes = {}
                    self._verified_package_versions = {}
                    self._endpoint_deps.clear()
                else:
                    if (
                        not self._cached_typed_environment_fingerprint
                        or self._cached_typed_environment_fingerprint
                        != self._typed_environment_fingerprint
                    ):
                        # Call-site resolution depends on imported declarations.
                        self._endpoint_deps.clear()
            all_cached = all(self._endpoint_key(ep) in self._endpoint_deps for ep in endpoints)
            if all_cached:
                # Endpoint call sites can be reused, but package applicability
                # evidence must be derived from the current typed source tree
                # and adjacent distribution metadata. It is intentionally not
                # restored from cache JSON: those hashes and version labels
                # would be caller-editable claims unless revalidated against
                # the bytes mypy actually analyzed.
                return self._endpoint_deps
        else:
            self._endpoint_deps.clear()

        analysis_fingerprint, _sources = self._cache_fingerprint()
        if self._trees and (
            self._built_source_fingerprint is None
            or self._built_source_fingerprint != analysis_fingerprint
        ):
            self._reset_build_state()

        # Build mypy once for all endpoints
        self._expected_source_fingerprint = analysis_fingerprint
        self._analysis_build_failed = False
        try:
            self._ensure_mypy_built()
        except MypyAnalyzerError:
            self._analysis_build_failed = True
        finally:
            self._expected_source_fingerprint = None

        # Analyze uncached endpoints
        for endpoint in endpoints:
            if self._endpoint_key(endpoint) not in self._endpoint_deps:
                self.analyze_endpoint(endpoint)

        # Refresh exclusions before saving: a local alias added during the
        # build must invalidate the pre-build fingerprint. Saving itself can
        # reuse this second census without another directory walk.
        if use_cache and not self._analysis_build_failed:
            self._local_module_census = self._discover_unselected_local_modules()
            current_fingerprint, _sources = self._cache_fingerprint()
            if current_fingerprint == analysis_fingerprint:
                self._save_cache()

        return self._endpoint_deps

    def _fingerprint_typed_environment(
        self,
        *,
        authenticated_metadata_hashes: dict[str, str] | None = None,
        authenticated_metadata_roots: set[Path] | None = None,
    ) -> str:
        """Hash parsed dependency source and adjacent distribution metadata."""
        if self._build_result is None:
            return ""
        inputs: dict[str, str] = {}
        package_roots: set[Path] = set()
        for state in self._build_result.graph.values():
            state_path = getattr(state, "path", None)
            if not state_path:
                continue
            path = Path(state_path)
            try:
                if path.is_file() and path.suffix in {".py", ".pyi"}:
                    content = path.read_bytes()
                    current_digest = hashlib.sha256(content).hexdigest()
                    parsed_digest = getattr(state, "source_hash", None)
                    inputs[str(path.resolve())] = (
                        f"{current_digest}:{parsed_digest}"
                        if isinstance(parsed_digest, str)
                        else f"{current_digest}:unavailable"
                    )
                    for root in path.parents:
                        if root.name in {"site-packages", "dist-packages"} or any(
                            root.glob("*.dist-info/METADATA")
                        ):
                            package_roots.add(root)
                            break
            except OSError as exc:
                inputs[str(path.resolve())] = f"unreadable:{type(exc).__name__}"
        metadata_snapshot_hashes: dict[str, str] = {}
        if authenticated_metadata_roots is not None:
            package_roots.update(authenticated_metadata_roots)
        for root in package_roots:
            try:
                for metadata_path in root.glob("*.dist-info/METADATA"):
                    metadata_key = str(metadata_path.resolve())
                    metadata_digest = hashlib.sha256(metadata_path.read_bytes()).hexdigest()
                    inputs[metadata_key] = metadata_digest
                    metadata_snapshot_hashes[metadata_key] = metadata_digest
            except OSError as exc:
                inputs[str(root.resolve()) + "/<metadata-scan>"] = (
                    f"unreadable:{type(exc).__name__}"
                )
        if (
            authenticated_metadata_hashes is not None
            and {
                path: digest
                for path, digest in metadata_snapshot_hashes.items()
                if authenticated_metadata_roots is not None
                and Path(path).parent.parent in authenticated_metadata_roots
            }
            != authenticated_metadata_hashes
        ):
            # Authenticate evidence against the same final byte reads that
            # seal the cache. Added, changed, removed or unreadable metadata cannot
            # retain an earlier version/source pin under a new fingerprint.
            self._verified_package_source_hashes.clear()
            self._verified_package_versions.clear()
        payload = json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(payload).hexdigest()

    def _cache_fingerprint(self) -> tuple[str, dict[str, str]]:
        """Fingerprint all Python inputs and analysis semantics."""
        if self.source_inventory is not None:
            # Validate declared hashes immediately before they enter a
            # persistent cache key, as well as when they enter mypy's build.
            self._source_records()
            inventory_files = sorted(
                self.source_inventory.files,
                key=lambda record: (record.relative_path, record.module, str(record.path)),
            )
            sources = {
                Path(record.relative_path).as_posix(): record.sha256 for record in inventory_files
            }
            inventory_inputs = [
                {
                    "path": str(Path(record.path).resolve()),
                    "relative_path": Path(record.relative_path).as_posix(),
                    "module": record.module,
                    "sha256": record.sha256,
                    "imports": sorted(record.imports),
                }
                for record in inventory_files
            ]
        else:
            source_records = self._source_records()
            sources = {
                path.relative_to(self.source_root).as_posix(): digest
                for path, _module, digest in source_records
            }
            inventory_inputs = [
                {
                    "path": relative,
                    "relative_path": relative,
                    "module": module,
                    "sha256": digest,
                    "imports": [],
                }
                for path, module, digest in source_records
                for relative in (path.relative_to(self.source_root).as_posix(),)
            ]
        mypy_version = self._resolver_version
        follow_imports = self._effective_follow_imports()
        payload = json.dumps(
            {
                "schema": self.CACHE_SCHEMA_VERSION,
                "engine": "fastapi-endpoint-detector:mypy-analyzer-v2",
                "source_span_normalization": "source-call-order-verified-ast-spans-v2",
                "execution_state_policy": "conditional-elif-try-else-guaranteed-finally-v3",
                "max_depth": self.max_depth,
                "no_site_packages": self.no_site_packages,
                "hermetic_search_path_policy": (
                    "explicit-module-root-without-cwd-v1" if self.no_site_packages else None
                ),
                "target_platform": (
                    self.target_platform if self.target_platform is not None else sys.platform
                ),
                "module_root": str(self.module_root.resolve()),
                "effective_mypy_config": {
                    "follow_imports": follow_imports,
                    "blocked_local_modules": [
                        [
                            module,
                            covers_children,
                            is_stub,
                            Path(path).relative_to(self.source_root).as_posix(),
                        ]
                        for module, covers_children, path, is_stub in (
                            self._unselected_local_modules()
                        )
                    ],
                    "ignore_missing_imports": True,
                    "namespace_packages": True,
                    "explicit_package_bases": True,
                    "preserve_asts": True,
                    "incremental": False,
                    "check_untyped_defs": True,
                    "export_types": True,
                    "excluded_files": sorted(
                        self.source_inventory.excluded_files if self.source_inventory else ()
                    ),
                    "unresolved_imports": sorted(
                        [list(item) for item in self.source_inventory.unresolved_imports]
                        if self.source_inventory
                        else ()
                    ),
                },
                "inventory_root": str(self.source_root.resolve()),
                "source_inventory": inventory_inputs,
                "finite_points_to": {
                    "max_targets": self.MAX_POINTS_TO_TARGETS,
                    "max_factory_returns": self.MAX_FACTORY_RETURNS,
                    "max_factory_states": self.MAX_FACTORY_STATES,
                    "max_edges": self.MAX_POINTS_TO_EDGES,
                    "execution_summary_version": self.EXECUTION_SUMMARY_VERSION,
                    "generator_consumers": {
                        symbol: [position, keyword, require_async]
                        for symbol, (position, keyword, require_async) in sorted(
                            self.GENERATOR_CONSUMERS.items()
                        )
                    },
                    "background_callback_summaries": {
                        symbol: {
                            "callback_index": summary.callback_index,
                            "allow_callback_keyword": summary.allow_callback_keyword,
                            "forwards_keyword_arguments": summary.forwards_keyword_arguments,
                            "control_keywords": sorted(summary.control_keywords),
                        }
                        for symbol, summary in sorted(self.BACKGROUND_CALLBACK_SUMMARIES.items())
                    },
                    "executor_summaries": {
                        symbol: {
                            "callback_index": summary.callback_index,
                            "allow_callback_keyword": summary.allow_callback_keyword,
                            "forwards_keyword_arguments": summary.forwards_keyword_arguments,
                            "control_keywords": sorted(summary.control_keywords),
                        }
                        for symbol, summary in sorted(self.EXECUTOR_SUMMARIES.items())
                    },
                },
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
        # Failed builds create placeholder dependencies that must never become
        # reusable cache entries, even when callers bypass analyze_endpoints.
        if self._analysis_build_failed or any(
            deps.build_failed for deps in self._endpoint_deps.values()
        ):
            return
        endpoints_data: dict[str, Any] = {}
        for analysis_key, deps in self._endpoint_deps.items():
            endpoints_data[analysis_key] = {
                "endpoint_id": deps.endpoint_id,
                "methods": deps.methods,
                "path": deps.path,
                "analysis_incomplete": deps.analysis_incomplete,
                "analysis_limitations": [
                    {
                        "file_path": item.file_path,
                        "call_line": item.call_line,
                        "call_column": item.call_column,
                        "cap": item.cap,
                        "target_count": item.target_count,
                        "limit": item.limit,
                    }
                    for item in deps.analysis_limitations
                ],
                "build_failed": deps.build_failed,
                "unresolved_imports": [list(item) for item in deps.unresolved_imports],
                "referenced_files": {f: list(lines) for f, lines in deps.referenced_files.items()},
                "referenced_symbols": [
                    {
                        "file_path": ref.file_path,
                        "symbol_name": ref.symbol_name,
                        "start_line": ref.start_line,
                        "end_line": ref.end_line,
                        "low_confidence": ref.low_confidence,
                    }
                    for ref in deps.referenced_symbols
                ],
                "resolved_call_sites": [
                    site.model_dump(mode="json", exclude_none=True)
                    for site in deps.get_resolved_call_sites()
                ],
                "source_evidence_spans": [
                    {
                        "file_path": span.file_path,
                        "start_line": span.start_line,
                        "start_column": span.start_column,
                        "end_line": span.end_line,
                        "end_column": span.end_column,
                        "execution_state": span.execution_state,
                        "evidence_kind": span.evidence_kind,
                        "provenance": span.provenance,
                    }
                    for span in deps.get_source_evidence_spans()
                ],
                "call_stacks": {
                    f: [
                        [
                            {
                                "file_path": frame.file_path,
                                "line_number": frame.line_number,
                                "function_name": frame.function_name,
                                "code_context": frame.code_context,
                                "caller_file_path": frame.caller_file_path,
                                "caller_line_number": frame.caller_line_number,
                                "caller_column_number": frame.caller_column_number,
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
                "typed_environment_fingerprint": self._typed_environment_fingerprint,
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
            fingerprint, current_sources = self._cache_fingerprint()
            if not isinstance(data, dict):
                return False
            if data.get("schema_version") != self.CACHE_SCHEMA_VERSION:
                return False
            if data.get("fingerprint") != fingerprint:
                return False
            metadata = data.get("metadata")
            self._cached_typed_environment_fingerprint = (
                metadata.get("typed_environment_fingerprint")
                if isinstance(metadata, dict)
                and isinstance(metadata.get("typed_environment_fingerprint"), str)
                else None
            )
            endpoints_data = data.get("endpoints")
            if not isinstance(endpoints_data, dict):
                return False
            if self._shared_path_index is None:
                project_files = frozenset(
                    str((self.source_root / relative).resolve()) for relative in current_sources
                )
                self._shared_path_index = _ProjectPathIndex(str(self.source_root), project_files)
            path_index = self._shared_path_index

            for analysis_key, deps_data in endpoints_data.items():
                if not isinstance(analysis_key, str) or not isinstance(deps_data, dict):
                    self._endpoint_deps.clear()
                    return False
                # Schema changes invalidate older caches, so explicit failure
                # metadata is sufficient here. Incomplete entries can also
                # represent legitimate bounded capability limitations.
                if deps_data.get("build_failed", False):
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
                                caller_file_path=frame.get("caller_file_path"),
                                caller_line_number=frame.get("caller_line_number"),
                                caller_column_number=frame.get("caller_column_number"),
                            )
                            for frame in stack_data
                        ]
                        for stack_data in stacks_data
                    ]

                call_sites_data = deps_data.get("resolved_call_sites")
                if not isinstance(call_sites_data, list):
                    self._endpoint_deps.clear()
                    return False
                resolved_call_sites = [
                    ResolvedCallSite.model_validate(item) for item in call_sites_data
                ]
                source_span_data = deps_data.get("source_evidence_spans", [])
                if not isinstance(source_span_data, list):
                    self._endpoint_deps.clear()
                    return False
                source_evidence_spans = [
                    SourceEvidenceSpan(
                        file_path=item["file_path"],
                        start_line=item["start_line"],
                        start_column=item["start_column"],
                        end_line=item["end_line"],
                        end_column=item["end_column"],
                        execution_state=item["execution_state"],
                        evidence_kind=item.get("evidence_kind", "lambda_body"),
                        provenance=item.get("provenance", "mypy callable traversal"),
                    )
                    for item in source_span_data
                    if isinstance(item, dict)
                ]
                if len(source_evidence_spans) != len(source_span_data):
                    self._endpoint_deps.clear()
                    return False

                symbol_refs: list[SymbolReference] = []
                for ref_data in deps_data.get("referenced_symbols", []):
                    if isinstance(ref_data, dict):
                        symbol_refs.append(
                            SymbolReference(
                                file_path=ref_data["file_path"],
                                symbol_name=ref_data["symbol_name"],
                                start_line=ref_data["start_line"],
                                end_line=ref_data["end_line"],
                                low_confidence=ref_data.get("low_confidence", False),
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
                    resolved_call_sites=resolved_call_sites,
                    source_evidence_spans=source_evidence_spans,
                    source_root=str(self.source_root),
                    project_files=path_index.project_files,
                    analysis_incomplete=deps_data.get("analysis_incomplete", False),
                    build_failed=deps_data.get("build_failed", False),
                    analysis_limitations=[
                        AnalysisLimitation(**item)
                        for item in deps_data.get("analysis_limitations", ())
                        if isinstance(item, dict)
                    ],
                    unresolved_imports=tuple(
                        tuple(item) for item in deps_data.get("unresolved_imports", ())
                    ),
                    _path_index=path_index,
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

    def get_resolved_call_sites(
        self,
        endpoint: Endpoint | str,
        *,
        file_path: str | None = None,
        status: CallResolutionStatus | None = None,
    ) -> list[ResolvedCallSite]:
        """Get typed call occurrences for one endpoint analysis."""
        dependencies = self.get_endpoint_dependencies(endpoint)
        return (
            dependencies.get_resolved_call_sites(file_path, status=status)
            if dependencies is not None
            else []
        )
