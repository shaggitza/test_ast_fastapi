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
import json
import os
import sys
import tempfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from typing import Any, ClassVar

from fastapi_endpoint_detector.models.effect_contract import (
    CallArgumentEvidence,
    CallResolutionStatus,
    FiniteValueStatus,
    InvocationKind,
    ResolvedCallSite,
)
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
    caller_file_path: str | None = None
    caller_line_number: int | None = None


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
    source_root: str = ""
    project_files: set[str] | frozenset[str] = field(default_factory=set)
    _path_index: _ProjectPathIndex | None = field(default=None, repr=False, compare=False)
    _canonical_key_indexes: dict[str, dict[str, frozenset[str]]] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _resolved_call_site_set: set[ResolvedCallSite] = field(
        default_factory=set, init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        self._resolved_call_site_set.update(self.resolved_call_sites)

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

    CACHE_SCHEMA_VERSION = 14
    MAX_POINTS_TO_TARGETS = 8
    MAX_FACTORY_RETURNS = 64
    MAX_FACTORY_STATES = 512
    MAX_POINTS_TO_EDGES = 4096
    EXECUTION_SUMMARY_VERSION = 4
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
        self._python_call_span_cache: dict[str, dict[tuple[int, int], tuple[int, int]]] = {}
        self._source_bytes_cache: dict[str, tuple[bytes, ...] | None] = {}
        self._resolved_call_site_cache: dict[int, ResolvedCallSite | None] = {}
        self._finite_global_value_cache: dict[str, _FinitePointsTo | None] = {}
        self._finite_global_in_progress: set[str] = set()
        self._exact_project_identity_cache: dict[str, tuple[str, str] | None] = {}
        self._built_source_fingerprint: str | None = None
        self._expected_source_fingerprint: str | None = None
        self._fullname_resolution_cache: dict[str, tuple[str, str] | None] = {}
        self._canonical_project_fullname_cache: dict[str, str | None] = {}
        self._function_lookup_cache: dict[
            tuple[int, str, str | None, int | None], tuple[Any, str] | None
        ] = {}

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
            self._built_source_fingerprint = self._expected_source_fingerprint

        finally:
            sys.path = original_path

    def _reset_build_state(self, *, clear_endpoint_dependencies: bool = True) -> None:
        """Discard one stale typed snapshot before an explicit bulk rebuild."""
        self._build_result = None
        self._trees.clear()
        self._module_to_path.clear()
        self._types_map.clear()
        self._project_modules.clear()
        self._global_value_cache.clear()
        self._python_dependency_cache.clear()
        self._python_ast_cache.clear()
        self._python_call_span_cache.clear()
        self._source_bytes_cache.clear()
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
        self._reset_build_state(clear_endpoint_dependencies=False)
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

    def _python_dependency_closure(self, endpoint: Endpoint) -> dict[str, int]:
        """Expand explicit FastAPI dependency annotations to the configured depth."""
        depths: dict[str, int] = {}
        queue = [(fullname, 1) for fullname in self._python_dependency_fullnames(endpoint)]
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
            symbol_name = fullname.rsplit(".", maxsplit=1)[-1]
            dependency_result = self._find_func_in_tree(dependency_tree, symbol_name)
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
        try:
            self._ensure_mypy_built()
        except MypyAnalyzerError:
            pass
        path_index = self._project_path_index()
        deps = EndpointDependencies(
            endpoint_id=endpoint.identifier,
            methods=[m.value for m in endpoint.methods],
            path=endpoint.path,
            source_root=str(self.source_root),
            project_files=path_index.project_files,
            _path_index=path_index,
        )

        handler = endpoint.handler
        if not handler.file_path or not self._trees:
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

        start, end = self._get_func_lines(actual_func)
        deps.add_symbol_reference(handler_path, handler.name, start, end)

        import_map = self._import_map_for_tree(tree, handler_module)

        # Trace all references in the function body.
        visited: dict[
            tuple[
                str,
                bool,
                _FinitePointsTo | None,
                tuple[tuple[str, _FinitePointsTo], ...],
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
            dependency_start, dependency_end = self._get_func_lines(dependency_node)
            deps.add_symbol_reference(
                dependency_path,
                dependency_fullname,
                dependency_start,
                dependency_end,
            )
            visited[(dependency_fullname, False, None, ())] = dependency_depth
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

    def _call_source_identity(
        self,
        current_file: str,
        callee: Any,
    ) -> tuple[int, int, int | None, int | None, str] | None:
        """Return mypy's UTF-8 byte span and the exact source spelling."""
        line_value = getattr(callee, "line", 0)
        column_value = getattr(callee, "column", -1)
        end_line_raw = getattr(callee, "end_line", 0)
        end_column_raw = getattr(callee, "end_column", -1)
        line = int(line_value) if isinstance(line_value, int) else 0
        column = int(column_value) if isinstance(column_value, int) else -1
        end_line_value = int(end_line_raw) if isinstance(end_line_raw, int) else 0
        end_column_value = int(end_column_raw) if isinstance(end_column_raw, int) else -1
        if line < 1 or column < 0:
            return None
        end_line = end_line_value if end_line_value >= line and end_column_value >= 0 else None
        end_column = end_column_value if end_line is not None else None
        canonical = str(Path(current_file).resolve())
        if end_line is None:
            if canonical not in self._python_ast_cache:
                try:
                    self._python_ast_cache[canonical] = ast.parse(
                        Path(canonical).read_text(encoding="utf-8"), filename=canonical
                    )
                except (OSError, SyntaxError, UnicodeError):
                    self._python_ast_cache[canonical] = None
            tree = self._python_ast_cache[canonical]
            if canonical not in self._python_call_span_cache:
                spans: dict[tuple[int, int], tuple[int, int]] = {}
                if tree is not None:
                    for candidate in ast.walk(tree):
                        function = candidate.func if isinstance(candidate, ast.Call) else None
                        if (
                            function is not None
                            and function.end_lineno is not None
                            and function.end_col_offset is not None
                        ):
                            spans[(function.lineno, function.col_offset)] = (
                                function.end_lineno,
                                function.end_col_offset,
                            )
                self._python_call_span_cache[canonical] = spans
            fallback_span = self._python_call_span_cache[canonical].get((line, column))
            if fallback_span is not None:
                end_line, end_column = fallback_span
        if end_line is None or end_column is None:
            return None
        if canonical not in self._source_bytes_cache:
            try:
                self._source_bytes_cache[canonical] = tuple(
                    Path(canonical).read_bytes().splitlines(keepends=True)
                )
            except OSError:
                self._source_bytes_cache[canonical] = None
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

    @staticmethod
    def _callable_declaration(  # noqa: PLR0911
        node: Any,
    ) -> tuple[str, InvocationKind] | None:
        """Return exact declaration identity only for callable definition nodes."""
        from mypy.nodes import (  # noqa: PLC0415
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
        from mypy.nodes import TypeInfo  # noqa: PLC0415

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
        from mypy.nodes import TypeInfo  # noqa: PLC0415

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
        from mypy.nodes import MemberExpr, MypyFile, NameExpr, TypeInfo, Var  # noqa: PLC0415

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

    @classmethod
    def _join_finite_values(
        cls, left: _FinitePointsTo | None, right: _FinitePointsTo | None
    ) -> _FinitePointsTo | None:
        """Join only complete finite values; unknown on either path fails closed."""
        if left is None or right is None:
            return None
        types = tuple(sorted(set(left.types) | set(right.types)))
        if not types or len(types) > cls.MAX_POINTS_TO_TARGETS:
            return None
        left_fields = dict(left.fields)
        right_fields = dict(right.fields)
        fields: list[tuple[str, _FinitePointsTo]] = []
        for name in sorted(left_fields.keys() & right_fields.keys()):
            value = cls._join_finite_values(left_fields[name], right_fields[name])
            if value is not None:
                fields.append((name, value))
        return _FinitePointsTo(types, tuple(fields))

    @classmethod
    def _join_finite_environments(
        cls,
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
                value = cls._join_finite_values(value, environment[name])
            if value is not None:
                result[name] = value
        return result

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
        from mypy.nodes import TypeInfo  # noqa: PLC0415

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
        from mypy.nodes import NameExpr, TypeInfo  # noqa: PLC0415

        if isinstance(callee, NameExpr) and isinstance(callee.node, TypeInfo):
            info = callee.node
            return info if info.module_name in self._project_modules else None
        imported = self._explicit_import_fullname(callee, import_map)
        return self._exact_finite_project_type_info(imported) if imported is not None else None

    def _exact_finite_project_callable(  # noqa: PLR0911
        self, fullname: str
    ) -> tuple[str, InvocationKind] | None:
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
        from mypy.nodes import Decorator  # noqa: PLC0415

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
        from mypy.nodes import (  # noqa: PLC0415
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

    def _finite_global_value(  # noqa: PLR0911, PLR0912
        self,
        fullname: str,
        _budget: list[int],
    ) -> _FinitePointsTo | None:
        """Summarize one exact module global from ordered source assignments."""
        from mypy.nodes import (  # noqa: PLC0415
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

    def _finite_expression_value(  # noqa: PLR0911
        self,
        expression: Any,
        environment: dict[str, _FinitePointsTo],
        import_map: dict[str, str],
        stack: tuple[str, ...],
        budget: list[int],
    ) -> _FinitePointsTo | None:
        """Evaluate the deliberately small, finite points-to expression language."""
        from mypy.nodes import CallExpr, ConditionalExpr, MemberExpr, NameExpr  # noqa: PLC0415

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

    def _execute_finite_block(  # noqa: PLR0911, PLR0912
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
        from mypy.nodes import (  # noqa: PLC0415
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
        from mypy.nodes import ARG_NAMED, ARG_POS  # noqa: PLC0415

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
    def _valid_builtin_generator_consumer(call: Any) -> bool:
        """Accept only valid explicit `next`/`anext` positional call shapes."""
        from mypy.nodes import ARG_POS  # noqa: PLC0415

        return 1 <= len(call.args) <= 2 and all(
            kind == ARG_POS and name is None
            for kind, name in zip(call.arg_kinds, call.arg_names, strict=True)
        )

    def _callback_binding(
        self,
        call: Any,
        summary: _ExecutorSummary,
    ) -> tuple[Any, Any] | None:
        """Extract one callback plus its explicitly forwarded args and kwargs."""
        from mypy.nodes import ARG_NAMED, ARG_POS  # noqa: PLC0415

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
        from mypy.nodes import MemberExpr  # noqa: PLC0415

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
        from mypy.nodes import MemberExpr  # noqa: PLC0415

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

    def _member_call_resolution(  # noqa: PLR0911, PLR0912, PLR0915
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
        from mypy.nodes import CallExpr, NameExpr, TypeInfo, Var  # noqa: PLC0415
        from mypy.types import Instance, UnionType, get_proper_type  # noqa: PLC0415

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
            for info in receiver_infos:
                member = info.get(callee.name)
                declaration = (
                    self._callable_declaration(member.node) if member is not None else None
                )
                if declaration is None:
                    incomplete = True
                else:
                    resolutions.add(declaration)
            if len(resolutions) == 1 and not incomplete:
                resolved_symbol, invocation = next(iter(resolutions))
                return (
                    CallResolutionStatus.EXACT,
                    resolved_symbol,
                    invocation,
                    candidates,
                    None,
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
    ) -> ResolvedCallSite | None:
        """Classify one mypy call expression without guessing symbol identity."""
        cache_key = id(call)
        if cache_key not in self._resolved_call_site_cache:
            self._resolved_call_site_cache[cache_key] = self._resolved_call_site_uncached(
                call, current_file, import_map
            )
        return self._resolved_call_site_cache[cache_key]

    @staticmethod
    def _finite_string_values(  # noqa: PLR0911
        expression: Any,
    ) -> tuple[str, ...] | None:
        """Resolve a bounded literal string set without evaluating application code."""
        from mypy.nodes import ConditionalExpr, NameExpr, OpExpr, StrExpr, Var  # noqa: PLC0415

        if isinstance(expression, StrExpr):
            return (expression.value,)
        if isinstance(expression, NameExpr) and isinstance(expression.node, Var):
            value = expression.node.final_value
            return (value,) if isinstance(value, str) else None
        if isinstance(expression, ConditionalExpr):
            left = MypyAnalyzer._finite_string_values(expression.if_expr)
            right = MypyAnalyzer._finite_string_values(expression.else_expr)
            if left is None or right is None:
                return None
            values = tuple(sorted({*left, *right}))
            return values if len(values) <= 8 else None
        if isinstance(expression, OpExpr) and expression.op == "+":
            left = MypyAnalyzer._finite_string_values(expression.left)
            right = MypyAnalyzer._finite_string_values(expression.right)
            if left is None or right is None:
                return None
            values = tuple(sorted({prefix + suffix for prefix in left for suffix in right}))
            return values if len(values) <= 8 else None
        return None

    @classmethod
    def _call_argument_evidence(cls, call: Any) -> tuple[CallArgumentEvidence, ...]:
        """Capture positional/keyword literal identities with strict finite bounds."""
        from mypy.nodes import ARG_NAMED, ARG_POS  # noqa: PLC0415

        evidence: list[CallArgumentEvidence] = []
        positional_index = 0
        for source_index, (expression, kind, name) in enumerate(
            zip(call.args, call.arg_kinds, call.arg_names, strict=True)
        ):
            if kind not in {ARG_POS, ARG_NAMED}:
                continue
            values = cls._finite_string_values(expression)
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

    def _resolved_call_site_uncached(  # noqa: PLR0912, PLR0915
        self,
        call: Any,
        current_file: str,
        import_map: dict[str, str],
    ) -> ResolvedCallSite | None:
        """Resolve one physical project-source call for the analyzer-wide cache."""
        from mypy.nodes import MemberExpr, NameExpr, SuperExpr, TypeInfo, Var  # noqa: PLC0415

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

    def _trace_references(
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
            ],
            int,
        ],
        import_map: dict[str, str] | None = None,
        *,
        depth: int,
        low_confidence_path: bool = False,
        receiver_value: _FinitePointsTo | None = None,
        initial_environment: dict[str, _FinitePointsTo] | None = None,
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

        flow_environment: dict[str, _FinitePointsTo] = dict(initial_environment or {})
        function_node = self._actual_function(node)
        if receiver_value is not None and getattr(function_node, "arguments", None):
            self_name = function_node.arguments[0].variable.name
            flow_environment[self_name] = receiver_value
        finite_budget = [0]
        awaited_call_ids: set[int] = set()
        consumed_generator_call_kinds: dict[int, bool | None] = {}
        deferred_environment: dict[str, _DeferredGenerator] = {}

        def resolve_and_trace(  # noqa: PLR0912, PLR0915
            fullname: str,
            call_line: int,
            *,
            low_confidence_edge: bool = False,
            target_receiver: _FinitePointsTo | None = None,
            target_environment: dict[str, _FinitePointsTo] | None = None,
            edge_kind: str | None = None,
        ) -> None:
            """Resolve a fullname and preserve LOW provenance through descendants."""
            target_depth = depth + 1
            if target_depth > self.max_depth:
                return
            if low_confidence_edge:
                if finite_edge_budget[0] >= self.MAX_POINTS_TO_EDGES:
                    return
                finite_edge_budget[0] += 1
            target_low_confidence = low_confidence_path or low_confidence_edge
            environment_key = tuple(sorted((target_environment or {}).items()))
            visit_key = (
                fullname,
                target_low_confidence,
                target_receiver,
                environment_key,
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
                deps.add_symbol_reference(
                    target_path,
                    fullname,
                    start,
                    end,
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
                        start, end = self._get_func_lines(initializer_node)
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
            elif isinstance(expression, NameExpr):
                generator = deferred_environment.get(expression.name)
                if generator is not None and (
                    require_async is None or generator.is_async == require_async
                ):
                    consume_deferred_generator(generator, line)

        def handle_call_expr(call: CallExpr) -> None:
            """Trace exact calls, adding bounded finite receiver edges as LOW only."""
            call_site = self._resolved_call_site(call, current_file, import_map)
            if call_site is not None:
                deps.add_resolved_call_site(call_site)
            callee = call.callee
            traced = False

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
            }.get(canonical_symbol)
            if builtin_consumer is not None and self._valid_builtin_generator_consumer(call):
                consume_generator_expression(
                    call.args[0],
                    call.line,
                    require_async=builtin_consumer,
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
                resolve_and_trace(call_site.canonical_symbol, call.line)

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
                        edge_kind=f"fastapi_dependency:{wrapper_symbol}",
                    )

            # Walk nested calls before invalidating mutable local object state.
            walk_node(callee)
            for arg in call.args:
                walk_node(arg)
            flow_environment.clear()
            deferred_environment.clear()

        def walk_node(n: Any) -> None:
            """Recursively walk a mypy AST node with a bounded local environment."""
            nonlocal deferred_environment, flow_environment
            if n is None:
                return

            if isinstance(n, CallExpr):
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
                # Walk function body
                if hasattr(n, "body"):
                    walk_node(n.body)

            elif isinstance(n, Block):
                for stmt in n.body:
                    walk_node(stmt)

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
                walk_node(n.rvalue)
                for lv in n.lvalues:
                    if isinstance(lv, NameExpr):
                        if value is None:
                            flow_environment.pop(lv.name, None)
                        else:
                            flow_environment[lv.name] = value
                        if deferred_value is None:
                            deferred_environment.pop(lv.name, None)
                        else:
                            deferred_environment[lv.name] = deferred_value
                    else:
                        # Arbitrary/reflection-driven member mutation invalidates all
                        # finite heap evidence outside constructor summarization.
                        flow_environment.clear()
                        deferred_environment.clear()
                    walk_node(lv)

            elif isinstance(n, ReturnStmt):
                walk_node(n.expr)

            elif isinstance(n, IfStmt):
                base_environment = dict(flow_environment)
                base_deferred = dict(deferred_environment)
                branch_environments: list[dict[str, _FinitePointsTo]] = []
                branch_deferred: list[dict[str, _DeferredGenerator]] = []
                for expr, body in zip(n.expr, n.body, strict=True):
                    flow_environment = dict(base_environment)
                    deferred_environment = dict(base_deferred)
                    walk_node(expr)
                    walk_node(body)
                    branch_environments.append(dict(flow_environment))
                    branch_deferred.append(dict(deferred_environment))
                flow_environment = dict(base_environment)
                deferred_environment = dict(base_deferred)
                if n.else_body:
                    walk_node(n.else_body)
                    branch_environments.append(dict(flow_environment))
                    branch_deferred.append(dict(deferred_environment))
                else:
                    branch_environments.append(base_environment)
                    branch_deferred.append(base_deferred)
                flow_environment = self._join_finite_environments(branch_environments)
                common_deferred = set.intersection(*(set(branch) for branch in branch_deferred))
                deferred_environment = {
                    name: branch_deferred[0][name]
                    for name in common_deferred
                    if all(
                        branch[name] == branch_deferred[0][name] for branch in branch_deferred[1:]
                    )
                }

            elif isinstance(n, WhileStmt):
                walk_node(n.expr)
                flow_environment.clear()
                deferred_environment.clear()
                walk_node(n.body)
                flow_environment.clear()
                deferred_environment.clear()

            elif isinstance(n, ForStmt):
                consume_generator_expression(
                    n.expr,
                    n.line,
                    require_async=bool(n.is_async),
                )
                walk_node(n.expr)
                flow_environment.clear()
                deferred_environment.clear()
                walk_node(n.body)
                flow_environment.clear()
                deferred_environment.clear()

            elif isinstance(n, WithStmt):
                for expr in n.expr:
                    walk_node(expr)
                flow_environment.clear()
                deferred_environment.clear()
                walk_node(n.body)
                flow_environment.clear()
                deferred_environment.clear()

            elif isinstance(n, TryStmt):
                flow_environment.clear()
                deferred_environment.clear()
                walk_node(n.body)
                for handler in n.handlers:
                    flow_environment.clear()
                    deferred_environment.clear()
                    walk_node(handler)
                if hasattr(n, "types") and n.types:
                    for exc_type in n.types:
                        if exc_type:
                            walk_node(exc_type)
                if n.else_body:
                    flow_environment.clear()
                    deferred_environment.clear()
                    walk_node(n.else_body)
                if n.finally_body:
                    flow_environment.clear()
                    deferred_environment.clear()
                    walk_node(n.finally_body)
                flow_environment.clear()
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
                # Creating a generator expression evaluates only its outer iterable.
                if n.sequences:
                    walk_node(n.sequences[0])

            elif isinstance(n, LambdaExpr):
                # Walk lambda arguments (for default values)
                if hasattr(n, "arguments"):
                    for arg in n.arguments:
                        if hasattr(arg, "initializer") and arg.initializer:
                            walk_node(arg.initializer)
                # Walk lambda body
                walk_node(n.body)

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
        if self._trees and (
            self._built_source_fingerprint is None
            or self._built_source_fingerprint != analysis_fingerprint
        ):
            self._reset_build_state()

        # Build mypy once for all endpoints
        self._expected_source_fingerprint = analysis_fingerprint
        try:
            self._ensure_mypy_built()
        except MypyAnalyzerError:
            pass
        finally:
            self._expected_source_fingerprint = None

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
        for discovered in sorted(self.source_root.rglob("*.py")):
            try:
                path = discovered.resolve()
                relative = path.relative_to(self.source_root).as_posix()
                sources[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
            except (OSError, ValueError):
                continue
        mypy_version = self._resolver_version
        payload = json.dumps(
            {
                "schema": self.CACHE_SCHEMA_VERSION,
                "max_depth": self.max_depth,
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
                        "low_confidence": ref.low_confidence,
                    }
                    for ref in deps.referenced_symbols
                ],
                "resolved_call_sites": [
                    site.model_dump(mode="json", exclude_none=True)
                    for site in deps.get_resolved_call_sites()
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
            fingerprint, current_sources = self._cache_fingerprint()
            if not isinstance(data, dict):
                return False
            if data.get("schema_version") != self.CACHE_SCHEMA_VERSION:
                return False
            if data.get("fingerprint") != fingerprint:
                return False
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
                    source_root=str(self.source_root),
                    project_files=path_index.project_files,
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
