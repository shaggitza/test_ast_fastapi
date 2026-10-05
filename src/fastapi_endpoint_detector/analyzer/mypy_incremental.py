"""In-memory, fine-grained typed mypy build coordinator.

This deliberately stays separate from :mod:`mypy_analyzer`: it provides a
small explicit provider API for wiring a retained typed build into the
endpoint analyzer without changing its current full-build behavior.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import Path
from typing import TYPE_CHECKING, Any

from mypy.build import BuildSource, build
from mypy.config_parser import parse_config_file
from mypy.nodes import CallExpr
from mypy.options import Options
from mypy.server.update import FineGrainedBuildManager

if TYPE_CHECKING:
    from collections.abc import Mapping


class _CallTypeCollector:
    def __init__(self) -> None:
        self.calls: list[CallExpr] = []
        self.seen: set[int] = set()

    def __getattr__(self, method: str) -> Any:
        if method.startswith("visit_"):
            return self._visit
        raise AttributeError(method)

    def _visit(self, node: Any) -> None:
        if id(node) in self.seen:
            return
        self.seen.add(id(node))
        if isinstance(node, CallExpr):
            self.calls.append(node)
        ignored = {"node", "info", "type", "unanalyzed_type", "original_def",
                   "original_first_arg", "def_var", "expanded", "analyzed"}
        for cls in type(node).__mro__:
            for field in getattr(cls, "__mypyc_attrs__", ()):
                if field.startswith("_") or field in ignored:
                    continue
                try:
                    child = getattr(node, field)
                except (AttributeError, RuntimeError):
                    continue
                self._visit_value(child)

    def _visit_value(self, value: Any) -> None:
        if isinstance(value, (list, tuple)):
            for child in value:
                self._visit_value(child)
        elif hasattr(type(value), "__mypyc_attrs__"):
            self._visit(value)


class IncrementalBuildError(RuntimeError):
    """A requested typed build could not be safely updated."""


@dataclass(frozen=True)
class BuildConfig:
    """Inputs that affect module discovery and typing."""

    source_root: Path
    python_version: str = f"{sys.version_info.major}.{sys.version_info.minor}"
    mypy_options: tuple[str, ...] = ()
    config_file: Path | None = None
    engine: str = "mypy-fine-grained"


@dataclass(frozen=True)
class BuildReport:
    mode: str
    reason: str | None
    elapsed_seconds: float
    updated_modules: tuple[str, ...]
    removed_modules: tuple[str, ...]
    diagnostics: tuple[str, ...]
    inventory_fingerprint: str
    cache_fingerprint: str


@dataclass
class TypedBuild:
    """Retained mypy result. ``result`` carries ASTs, type maps and symbol tables."""

    result: Any
    manager: FineGrainedBuildManager
    report: BuildReport
    module_paths: dict[str, str]

    @property
    def modules(self) -> Mapping[str, Any]:
        return self.manager.graph

    @property
    def type_maps(self) -> Mapping[Any, Any]:
        return self.manager.manager.all_types

    def typed_snapshot(self) -> dict[str, tuple[str, ...]]:
        """Stable per-module AST and expression-type evidence for equivalence checks."""
        snapshot: dict[str, tuple[str, ...]] = {}
        for module, state in sorted(self.modules.items()):
            rows: list[str] = []
            tree = state.tree
            if tree is not None:
                rows.append("ast:" + json.dumps(tree.serialize(), sort_keys=True, default=str))
                visitor = _CallTypeCollector()
                visitor._visit(tree)
                for expr in visitor.calls:
                    typ = self.manager.manager.all_types.get(expr)
                    rows.append(
                        f"call-type:{expr.line}:{expr.column}:"
                        f"{expr!s}:{typ!r}"
                    )
            snapshot[module] = tuple(sorted(rows))
        return snapshot


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


class MypyIncrementalProvider:
    """Reusable provider for cold build, no-change reuse, and typed updates.

    Inventory keys are canonical mypy module IDs and values are source paths.
    The provider owns one in-memory mypy daemon state and fails closed when its
    engine/configuration/source-root fingerprint changes.
    """

    def __init__(self, config: BuildConfig) -> None:
        self.config = config
        self._typed: TypedBuild | None = None
        self._config_fingerprint = self._fingerprint_config()

    def _fingerprint_config(self) -> str:
        config_path = self.config.config_file
        config_hash = None
        if config_path is not None:
            config_hash = hashlib.sha256(config_path.read_bytes()).hexdigest()
        return _digest({
            "engine": self.config.engine,
            "mypy": version("mypy"),
            "python": self.config.python_version,
            "options": self.config.mypy_options,
            "config": config_hash,
            "root": str(self.config.source_root.resolve()),
        })

    def _options(self) -> Options:
        opts = Options()
        if self.config.config_file:
            parse_config_file(opts, lambda: None, str(self.config.config_file.resolve()))
        major, minor = self.config.python_version.split(".")[:2]
        opts.python_version = (int(major), int(minor))
        opts.incremental = False  # state is retained directly, not disk metadata
        opts.fine_grained_incremental = True
        opts.export_types = True
        opts.cache_dir = os.devnull
        opts.follow_imports = "normal"
        for option in self.config.mypy_options:
            if option == "ignore_missing_imports":
                opts.ignore_missing_imports = True
            elif option == "strict_optional":
                opts.strict_optional = True
            else:
                raise IncrementalBuildError(f"unsupported mypy option in provider API: {option}")
        return opts

    def build(self, inventory: Mapping[str, str | Path]) -> TypedBuild:
        """Build if cold; otherwise reuse or increment the retained typed state."""
        canonical = {module: str(Path(path).resolve()) for module, path in inventory.items()}
        if len(canonical) != len(inventory):
            raise IncrementalBuildError("module inventory contains duplicate identities")
        if len(set(canonical.values())) != len(canonical):
            raise IncrementalBuildError(
                "multiple module identities resolve to the same source path"
            )
        inventory_fp = _digest(sorted(canonical.items()))
        old = self._typed
        start = time.perf_counter()
        if old is None:
            result = build(
                [BuildSource(path, module, None, str(self.config.source_root.resolve()))
                 for module, path in sorted(canonical.items())],
                self._options(),
            )
            fg = FineGrainedBuildManager(result)
            self._source_digests = {m: _file_digest(p) for m, p in canonical.items()}
            report = self._report(
                "cold_build", None, start, tuple(sorted(canonical)), (), result.errors,
                inventory_fp,
            )
            self._typed = TypedBuild(result, fg, report, canonical)
            self._imports = _import_fingerprint(canonical)
            return self._typed

        reason = self._fallback_reason(old, canonical)
        if reason:
            self._typed = None
            current = self.build(canonical)
            current.report = BuildReport(
                "fallback_full_rebuild", reason, time.perf_counter() - start,
                current.report.updated_modules, current.report.removed_modules,
                current.report.diagnostics, inventory_fp, current.report.cache_fingerprint,
            )
            return current

        # mypy's fine-grained API consumes source paths and clears its AST cache
        # before each update; changed file contents are detected by the caller's
        # inventory snapshot below, stored independently of mypy's parse cache.
        prior_files = getattr(self, "_source_digests", {})
        changed = sorted(
            module for module, path in canonical.items()
            if old.module_paths.get(module) != path
            or prior_files.get(module) != _file_digest(path)
        )
        removed = sorted(set(old.module_paths) - set(canonical))
        if not changed and not removed:
            report = self._report(
                "no_change_reuse", None, start, (), (), old.report.diagnostics,
                inventory_fp,
            )
            reused = TypedBuild(old.result, old.manager, report, old.module_paths)
            self._typed = reused
            return reused
        fg = old.manager
        fg.flush_cache()
        fg.manager.fscache.flush()
        try:
            diagnostics = fg.update(
                [(m, canonical[m]) for m in changed],
                [(m, old.module_paths[m]) for m in removed],
            )
        except Exception as exc:
            self._typed = None
            rebuilt = self.build(canonical)
            rebuilt.report = BuildReport(
                "fallback_full_rebuild",
                f"fine-grained update failed ({type(exc).__name__}); rebuilt from source",
                time.perf_counter() - start,
                rebuilt.report.updated_modules,
                rebuilt.report.removed_modules,
                rebuilt.report.diagnostics,
                inventory_fp,
                rebuilt.report.cache_fingerprint,
            )
            return rebuilt
        result = old.result
        self._source_digests = {m: _file_digest(p) for m, p in canonical.items()}
        self._imports = _import_fingerprint(canonical)
        report = self._report(
            "incremental_update", None, start, tuple(fg.updated_modules),
            tuple(removed), diagnostics, inventory_fp,
        )
        self._typed = TypedBuild(result, fg, report, canonical)
        return self._typed

    def _fallback_reason(self, old: TypedBuild, inventory: Mapping[str, str]) -> str | None:
        if self._fingerprint_config() != self._config_fingerprint:
            return "engine/configuration/cache fingerprint changed"
        if set(old.module_paths) != set(inventory):
            return "source inventory identities changed; fine-grained root graph must be rebuilt"
        if getattr(self, "_imports", None) != _import_fingerprint(inventory):
            return "import topology changed; rebuilding to remove stale import edges"
        if any(old.module_paths[m] != path for m, path in inventory.items()):
            return "canonical module paths changed"
        if any(not module or module.startswith(".") for module in inventory):
            return "non-canonical module identity"
        return None

    def _report(self, mode: str, reason: str | None, start: float,
                updated: tuple[str, ...], removed: tuple[str, ...], diagnostics: Any,
                inventory_fp: str) -> BuildReport:
        cache_fp = _digest({"config": self._config_fingerprint, "inventory": inventory_fp,
                            "sources": getattr(self, "_source_digests", {})})
        return BuildReport(mode, reason, time.perf_counter() - start, updated, removed,
                           tuple(diagnostics), inventory_fp, cache_fp)


def _file_digest(path: str) -> str:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return "<missing>"


def _import_fingerprint(inventory: Mapping[str, str]) -> str:
    rows: list[tuple[str, tuple[str, ...]]] = []
    for module, path in sorted(inventory.items()):
        try:
            tree = ast.parse(Path(path).read_text(encoding="utf-8"))
        except (OSError, SyntaxError, UnicodeError):
            rows.append((module, ("<unreadable>",)))
            continue
        imports: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append("." * node.level + (node.module or ""))
        rows.append((module, tuple(sorted(imports))))
    return _digest(rows)
