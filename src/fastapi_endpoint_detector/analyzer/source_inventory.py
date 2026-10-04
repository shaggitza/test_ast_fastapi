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
    root: Path
    files: tuple[SourceFile, ...]
    unresolved_imports: tuple[tuple[str, str], ...]
    excluded_files: tuple[str, ...]
    follow_imports: bool
    max_depth: int

    @property
    def paths(self) -> tuple[Path, ...]:
        return tuple(item.path for item in self.files)


def _matches(relative: str, patterns: tuple[str, ...]) -> bool:
    return any(
        fnmatch.fnmatchcase(relative, pattern) or fnmatch.fnmatchcase(f"/{relative}", pattern)
        for pattern in patterns
    )


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
    source = source.resolve()
    root = source.parent if source.is_file() else source
    candidates = sorted(root.rglob("*.py"))
    by_module: dict[str, Path] = {}
    rel_by_path: dict[Path, str] = {}
    for path in candidates:
        rel = path.relative_to(root).as_posix()
        stem = Path(rel).with_suffix("")
        parts = list(stem.parts)
        if parts[-1] == "__init__":
            parts.pop()
        module = ".".join(parts) or path.parent.name
        by_module[module] = path
        rel_by_path[path] = rel

    included = {
        path
        for path in candidates
        if _matches(rel_by_path[path], include_patterns)
        and not _matches(rel_by_path[path], exclude_patterns)
    }
    excluded = {path for path in candidates if _matches(rel_by_path[path], exclude_patterns)}
    imports_by_path: dict[Path, tuple[str, ...]] = {}
    unresolved: set[tuple[str, str]] = set()
    for path in candidates:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeError, SyntaxError, RecursionError):
            imports_by_path[path] = ()
            continue
        relative_path = Path(rel_by_path[path]).with_suffix("")
        parts = list(relative_path.parts)
        if parts[-1] == "__init__":
            parts.pop()
        current = ".".join(parts)
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
            local = by_module.get(imported)
            if local is None and imported.rpartition(".")[0]:
                local = by_module.get(imported.rpartition(".")[0])
            if local is None:
                continue
            if local in excluded:
                unresolved.add((rel_by_path[path], imported))
                continue
            if follow_imports and depth < max_depth and local not in distance:
                selected.add(local)
                distance[local] = depth + 1
                queue.append(local)
    records: list[SourceFile] = []
    for path in sorted(selected):
        try:
            raw = path.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
        except OSError:
            digest = ""
        relative_path = Path(rel_by_path[path]).with_suffix("")
        parts = list(relative_path.parts)
        if parts[-1] == "__init__":
            parts.pop()
        records.append(
            SourceFile(
                path, rel_by_path[path], ".".join(parts), digest, imports_by_path.get(path, ())
            )
        )
    return SourceInventory(
        root,
        tuple(records),
        tuple(sorted(unresolved)),
        tuple(sorted(rel_by_path[p] for p in excluded)),
        follow_imports,
        max_depth,
    )
