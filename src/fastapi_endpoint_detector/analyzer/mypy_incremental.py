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
from mypy.fscache import FileSystemCache
from mypy.nodes import CallExpr
from mypy.options import Options
from mypy.server.update import FineGrainedBuildManager
from mypy.util import hash_digest

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
        ignored = {
            "node",
            "info",
            "type",
            "unanalyzed_type",
            "original_def",
            "original_first_arg",
            "def_var",
            "expanded",
            "analyzed",
        }
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


SUPPORTED_ENGINES = frozenset({"mypy-fine-grained"})
SUPPORTED_MYPY_VERSIONS = frozenset({"1.19.1"})


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
    source_digests_before: tuple[tuple[str, str], ...]
    source_digests_after: tuple[tuple[str, str], ...]


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
                    rows.append(f"call-type:{expr.line}:{expr.column}:{expr!s}:{typ!r}")
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
        if config.engine not in SUPPORTED_ENGINES:
            raise IncrementalBuildError(
                f"unsupported typed build engine {config.engine!r}; "
                f"supported engines: {', '.join(sorted(SUPPORTED_ENGINES))}"
            )
        self._mypy_version = version("mypy")
        if self._mypy_version not in SUPPORTED_MYPY_VERSIONS:
            raise IncrementalBuildError(
                f"mypy {self._mypy_version} is not validated for fine-grained updates; "
                f"supported versions: {', '.join(sorted(SUPPORTED_MYPY_VERSIONS))}"
            )
        self._typed: TypedBuild | None = None
        self._config_fingerprint = self._fingerprint_config()

    def _fingerprint_config(self) -> str:
        config_path = self.config.config_file
        config_hash = None
        if config_path is not None:
            config_hash = hashlib.sha256(config_path.read_bytes()).hexdigest()
        return _digest(
            {
                "engine": self.config.engine,
                "mypy": self._mypy_version,
                "python": self.config.python_version,
                "options": self.config.mypy_options,
                "config": config_hash,
                "root": str(self.config.source_root.resolve()),
            }
        )

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
            return self._full_rebuild(
                canonical, inventory_fp, start, mode="cold_build", reason=None
            )

        source_snapshot = _capture_sources(canonical)
        reason = self._fallback_reason(old, canonical, source_snapshot)
        if reason:
            self._typed = None
            return self._full_rebuild(
                canonical,
                inventory_fp,
                start,
                mode="fallback_full_rebuild",
                reason=reason,
            )

        # Capture and prime mypy's filesystem cache so typechecking consumes the
        # exact bytes represented by the digests and import topology below.
        source_digests = _source_digests(source_snapshot)
        prior_files = getattr(self, "_source_digests", {})
        changed = sorted(
            module
            for module, path in canonical.items()
            if old.module_paths.get(module) != path
            or prior_files.get(module) != source_digests[module]
        )
        removed = sorted(set(old.module_paths) - set(canonical))
        if not changed and not removed:
            report = self._report(
                "no_change_reuse",
                None,
                start,
                (),
                (),
                old.report.diagnostics,
                inventory_fp,
                source_digests_before=prior_files,
            )
            reused = TypedBuild(old.result, old.manager, report, old.module_paths)
            self._typed = reused
            return reused
        fg = old.manager
        fg.flush_cache()
        fg.manager.fscache.flush()
        _prime_source_snapshot(fg.manager.fscache, canonical, source_snapshot)
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
                rebuilt.report.source_digests_before,
                rebuilt.report.source_digests_after,
            )
            return rebuilt
        result = old.result
        self._source_digests = source_digests
        self._imports = _import_fingerprint_from_sources(canonical, source_snapshot)
        report = self._report(
            "incremental_update",
            None,
            start,
            tuple(fg.updated_modules),
            tuple(removed),
            diagnostics,
            inventory_fp,
            source_digests_before=prior_files,
        )
        self._typed = TypedBuild(result, fg, report, canonical)
        return self._typed

    def _full_rebuild(
        self,
        canonical: dict[str, str],
        inventory_fp: str,
        start: float,
        *,
        mode: str,
        reason: str | None,
    ) -> TypedBuild:
        """Build against one captured source snapshot and commit its fingerprint."""
        config_fp = self._fingerprint_config()
        source_snapshot = _capture_sources(canonical)
        fscache = FileSystemCache()
        _prime_source_snapshot(fscache, canonical, source_snapshot)
        result = build(
            [
                BuildSource(path, module, None, str(self.config.source_root.resolve()))
                for module, path in sorted(canonical.items())
            ],
            self._options(),
            fscache=fscache,
        )
        # The caller's configuration or files may have changed while mypy ran.
        # Do not publish a cache identity that does not describe this build.
        if self._fingerprint_config() != config_fp:
            raise IncrementalBuildError("configuration changed during full rebuild")
        if _capture_sources(canonical) != source_snapshot:
            raise IncrementalBuildError("source files changed during full rebuild")
        fg = FineGrainedBuildManager(result)
        source_digests = _source_digests(source_snapshot)
        source_digests_before = getattr(self, "_source_digests", source_digests)
        cache_fp = _cache_fingerprint(config_fp, inventory_fp, source_digests)
        report = BuildReport(
            mode,
            reason,
            time.perf_counter() - start,
            tuple(sorted(canonical)),
            (),
            tuple(result.errors),
            inventory_fp,
            cache_fp,
            tuple(sorted(source_digests_before.items())),
            tuple(sorted(source_digests.items())),
        )
        typed = TypedBuild(result, fg, report, canonical)
        # Commit state only after the build and source/config validation succeed.
        self._config_fingerprint = config_fp
        self._source_digests = source_digests
        self._imports = _import_fingerprint_from_sources(canonical, source_snapshot)
        self._typed = typed
        return typed

    def _fallback_reason(
        self,
        old: TypedBuild,
        inventory: Mapping[str, str],
        sources: Mapping[str, bytes],
    ) -> str | None:
        if self._fingerprint_config() != self._config_fingerprint:
            return "engine/configuration/cache fingerprint changed"
        if set(old.module_paths) != set(inventory):
            return "source inventory identities changed; fine-grained root graph must be rebuilt"
        if getattr(self, "_imports", None) != _import_fingerprint_from_sources(inventory, sources):
            return "import topology changed; rebuilding to remove stale import edges"
        if any(old.module_paths[m] != path for m, path in inventory.items()):
            return "canonical module paths changed"
        if any(not module or module.startswith(".") for module in inventory):
            return "non-canonical module identity"
        return None

    def _report(
        self,
        mode: str,
        reason: str | None,
        start: float,
        updated: tuple[str, ...],
        removed: tuple[str, ...],
        diagnostics: Any,
        inventory_fp: str,
        *,
        source_digests_before: Mapping[str, str] | None = None,
    ) -> BuildReport:
        source_digests_after = getattr(self, "_source_digests", {})
        if source_digests_before is None:
            source_digests_before = source_digests_after
        cache_fp = _cache_fingerprint(
            self._config_fingerprint,
            inventory_fp,
            source_digests_after,
        )
        return BuildReport(
            mode,
            reason,
            time.perf_counter() - start,
            updated,
            removed,
            tuple(diagnostics),
            inventory_fp,
            cache_fp,
            tuple(sorted(source_digests_before.items())),
            tuple(sorted(source_digests_after.items())),
        )


def _capture_sources(inventory: Mapping[str, str]) -> dict[str, bytes]:
    snapshot: dict[str, bytes] = {}
    for module, path in sorted(inventory.items()):
        try:
            snapshot[module] = Path(path).read_bytes()
        except OSError as exc:
            raise IncrementalBuildError(
                f"cannot capture source for module {module!r}: {path}"
            ) from exc
    return snapshot


def _source_digests(sources: Mapping[str, bytes]) -> dict[str, str]:
    return {module: hashlib.sha256(content).hexdigest() for module, content in sources.items()}


def _cache_fingerprint(config_fp: str, inventory_fp: str, sources: Mapping[str, str]) -> str:
    return _digest({"config": config_fp, "inventory": inventory_fp, "sources": sources})


def _prime_source_snapshot(
    fscache: FileSystemCache,
    inventory: Mapping[str, str],
    sources: Mapping[str, bytes],
) -> None:
    for module, path in inventory.items():
        content = sources[module]
        fscache.read_cache[path] = content
        fscache.hash_cache[path] = hash_digest(content)


def _import_fingerprint_from_sources(
    inventory: Mapping[str, str], sources: Mapping[str, bytes]
) -> str:
    rows: list[tuple[str, tuple[str, ...]]] = []
    for module, _path in sorted(inventory.items()):
        try:
            tree = ast.parse(sources[module].decode("utf-8"))
        except (KeyError, SyntaxError, UnicodeError):
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
