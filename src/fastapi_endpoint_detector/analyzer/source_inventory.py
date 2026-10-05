"""Deterministic project source census and bounded local import graph.

This graph describes source scope only. Import reachability is never execution evidence.
"""

from __future__ import annotations

import ast
import fnmatch
import hashlib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SourceFile:
    path: Path
    relative_path: str
    module: str
    sha256: str
    imports: tuple[str, ...]


@dataclass(frozen=True)
class SourceInventory:
    """Canonical file scope and its known import-closure limitations.

    ``files`` and :attr:`paths` are the authoritative allowlist for downstream
    analyzers. A consumer may not broaden that selection by walking ``root``
    or following an in-root import on its own. ``unresolved_imports`` records
    known local import edges whose target was not selected, and ``limitations``
    explains why parts of the discovered source scope may be incomplete.
    Consumers should preserve these limitations in analysis results when they
    affect the result.
    """

    root: Path
    files: tuple[SourceFile, ...]
    unresolved_imports: tuple[tuple[str, str], ...]
    excluded_files: tuple[str, ...]
    follow_imports: bool
    max_depth: int
    limitations: tuple[str, ...] = ()
    module_collisions: tuple[tuple[str, tuple[str, ...]], ...] = ()

    @property
    def paths(self) -> tuple[Path, ...]:
        """Return exactly the files selected by this inventory."""
        return tuple(item.path for item in self.files)


def _matches(relative: str, patterns: tuple[str, ...]) -> bool:
    return any(
        fnmatch.fnmatchcase(relative, pattern) or fnmatch.fnmatchcase(f"/{relative}", pattern)
        for pattern in patterns
    )


def _module_name(relative: Path, package_prefix: str) -> str:
    stem = relative.with_suffix("") if relative.suffix == ".py" else relative
    parts = list(stem.parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(([package_prefix] if package_prefix else []) + parts)


def build_source_inventory(  # noqa: PLR0912, PLR0915
    source: Path,
    *,
    include_patterns: tuple[str, ...] = ("**/*.py",),
    exclude_patterns: tuple[str, ...] = (
        "**/test_*.py",
        "**/*_test.py",
        "**/tests/**",
        "**/__pycache__/**",
    ),
    follow_imports: bool = True,
    max_depth: int = 10,
) -> SourceInventory:
    """Build an ordered inventory, following only resolvable project-local imports."""
    requested = Path(source).absolute()
    if any(path.is_symlink() for path in (requested, *requested.parents)):
        raise ValueError("source inventory roots and source files must not use symlink paths")
    source = requested.resolve()
    root = source.parent if source.is_file() else source
    # Do not let pathlib's file-symlink handling pull files from outside the
    # selected tree (or count the same source through an alias).
    candidates = sorted(
        path
        for path in root.rglob("*.py")
        if not path.is_symlink()
        and not any(parent.is_symlink() for parent in path.parents if parent != root.parent)
        and path.resolve().is_relative_to(root)
    )
    package_init = root / "__init__.py"
    package_prefix = root.name if not package_init.is_symlink() and package_init.is_file() else ""
    module_paths: dict[str, list[Path]] = {}
    symlink_modules: dict[str, str] = {}
    for path in root.rglob("*"):
        if not path.is_symlink():
            continue
        relative = path.relative_to(root)
        module = _module_name(relative, package_prefix)
        if module:
            symlink_modules[module] = relative.as_posix()
    by_module: dict[str, Path] = {}
    rel_by_path: dict[Path, str] = {}
    for path in candidates:
        rel = path.relative_to(root).as_posix()
        module = _module_name(Path(rel), package_prefix) or path.parent.name
        module_paths.setdefault(module, []).append(path)
        rel_by_path[path] = rel

    module_collisions = tuple(
        (
            module,
            tuple(sorted(rel_by_path[path] for path in paths)),
        )
        for module, paths in sorted(module_paths.items())
        if len(paths) > 1
    )
    ambiguous_modules = {module for module, _paths in module_collisions}
    by_module = {
        module: paths[0]
        for module, paths in module_paths.items()
        if module not in ambiguous_modules
    }

    included = {
        path
        for path in candidates
        if _matches(rel_by_path[path], include_patterns)
        and not _matches(rel_by_path[path], exclude_patterns)
    }
    excluded = {path for path in candidates if _matches(rel_by_path[path], exclude_patterns)}
    imports_by_path: dict[Path, tuple[str, ...]] = {}
    hashes_by_path: dict[Path, str] = {}
    unresolved: set[tuple[str, str]] = set()
    limitations: set[str] = set()
    for module, paths in module_collisions:
        limitations.add(
            f"Module identity {module!r} collides across source files: {', '.join(paths)}"
        )
    for path in candidates:
        try:
            raw = path.read_bytes()
            hashes_by_path[path] = hashlib.sha256(raw).hexdigest()
            source_text = raw.decode("utf-8")
            tree = ast.parse(source_text, filename=str(path))
        except (OSError, UnicodeError, SyntaxError, RecursionError) as exc:
            imports_by_path[path] = ()
            if isinstance(exc, OSError):
                reason = "could not be read"
                hashes_by_path[path] = ""
            elif isinstance(exc, UnicodeError):
                reason = "could not be decoded as UTF-8"
            else:
                reason = "could not be parsed as Python"
            limitations.add(f"{rel_by_path[path]} {reason}: {type(exc).__name__}")
            continue
        relative_path = Path(rel_by_path[path]).with_suffix("")
        parts = list(relative_path.parts)
        if parts[-1] == "__init__":
            parts.pop()
        current = ".".join(([package_prefix] if package_prefix else []) + parts)
        found: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                base = node.module or ""
                if node.level:
                    parent = current.split(".")
                    if relative_path.name != "__init__":
                        parent.pop()
                    parent = parent[: max(0, len(parent) - node.level + 1)]
                    base = ".".join([*parent, base]).strip(".")
                if base:
                    found.add(base)
                found.update(f"{base}.{alias.name}" for alias in node.names if alias.name != "*")
        imports_by_path[path] = tuple(sorted(found))

    # Seed from included sources, then optionally add local dependency modules by BFS.
    selected = set(included)
    distance = dict.fromkeys(included, 0)
    queue = sorted(included)
    while queue:
        path = queue.pop(0)
        depth = distance[path]
        for imported in imports_by_path.get(path, ()):
            local = None
            ambiguous_import = None
            parts = imported.split(".")
            for stop in range(len(parts), 0, -1):
                candidate_module = ".".join(parts[:stop])
                if candidate_module in ambiguous_modules:
                    ambiguous_import = candidate_module
                    break
                local = by_module.get(candidate_module)
                if local is not None:
                    break
            if ambiguous_import is not None:
                unresolved.add((rel_by_path[path], imported))
                limitations.add(
                    f"Local import {imported!r} from {rel_by_path[path]} is ambiguous because "
                    f"module identity {ambiguous_import!r} has multiple source files"
                )
                continue
            symlink_match = next(
                (
                    (module, relative)
                    for module, relative in sorted(symlink_modules.items())
                    if imported == module or imported.startswith(f"{module}.")
                ),
                None,
            )
            if local is None and symlink_match is not None:
                module, relative = symlink_match
                unresolved.add((rel_by_path[path], imported))
                limitations.add(
                    f"Local import {imported!r} from {rel_by_path[path]} resolves through "
                    f"rejected symlink source {relative} (module {module!r})"
                )
                continue
            if local is None:
                continue
            if local in excluded:
                unresolved.add((rel_by_path[path], imported))
                limitations.add(
                    f"Local import {imported!r} from {rel_by_path[path]} resolves to excluded "
                    f"source {rel_by_path[local]}"
                )
                continue
            if local in distance:
                continue
            if not follow_imports:
                unresolved.add((rel_by_path[path], imported))
                limitations.add(
                    f"Local import {imported!r} from {rel_by_path[path]} was not followed "
                    "because follow_imports is disabled"
                )
                continue
            if depth >= max_depth:
                unresolved.add((rel_by_path[path], imported))
                limitations.add(
                    f"Local import {imported!r} from {rel_by_path[path]} was not followed "
                    f"because the maximum import depth {max_depth} was reached"
                )
                continue
            if local not in distance:
                selected.add(local)
                distance[local] = depth + 1
                queue.append(local)
    records: list[SourceFile] = []
    for path in sorted(selected):
        relative_path = Path(rel_by_path[path]).with_suffix("")
        parts = list(relative_path.parts)
        if parts[-1] == "__init__":
            parts.pop()
        module = ".".join(([package_prefix] if package_prefix else []) + parts)
        records.append(
            SourceFile(
                path,
                rel_by_path[path],
                module,
                hashes_by_path.get(path, ""),
                imports_by_path.get(path, ()),
            )
        )
    return SourceInventory(
        root,
        tuple(records),
        tuple(sorted(unresolved)),
        tuple(sorted(rel_by_path[p] for p in excluded)),
        follow_imports,
        max_depth,
        tuple(sorted(limitations)),
        module_collisions,
    )
