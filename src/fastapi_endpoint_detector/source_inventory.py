"""Deterministic project-local source inventory shared by static providers."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import ClassVar


class SourceInventoryError(ValueError):
    """Raised when a deterministic source inventory cannot be constructed safely."""


@dataclass(frozen=True)
class SourceInventoryEntry:
    """One immutable project-local source snapshot entry."""

    relative_path: str
    path: Path
    module_name: str | None
    sha256: str
    size_bytes: int

    @property
    def is_python(self) -> bool:
        """Whether this entry is a Python implementation source."""
        return self.path.suffix == ".py"


@dataclass(frozen=True)
class SourceInventory:
    """Canonical deterministic source scope and immutable file fingerprint."""

    DEFAULT_MAX_CANDIDATES: ClassVar[int] = 100_000
    DEFAULT_MAX_FILES: ClassVar[int] = 20_000
    DEFAULT_MAX_FILE_BYTES: ClassVar[int] = 16 * 1024 * 1024
    DEFAULT_MAX_AGGREGATE_BYTES: ClassVar[int] = 256 * 1024 * 1024
    HASH_CHUNK_BYTES: ClassVar[int] = 1024 * 1024
    IMPLICIT_EXCLUSIONS: ClassVar[tuple[str, ...]] = (
        "dot-prefixed path segments",
        "__pycache__ directories",
        "symbolic links",
    )

    root: Path
    include_patterns: tuple[str, ...]
    exclude_patterns: tuple[str, ...]
    entries: tuple[SourceInventoryEntry, ...]
    fingerprint: str
    max_candidates: int
    max_files: int
    max_file_bytes: int
    max_aggregate_bytes: int

    @classmethod
    def build(
        cls,
        root: Path,
        *,
        include_patterns: tuple[str, ...] = ("**/*.py",),
        exclude_patterns: tuple[str, ...] = (
            "**/test_*.py",
            "**/*_test.py",
            "**/tests/**",
            "**/__pycache__/**",
        ),
        max_candidates: int = DEFAULT_MAX_CANDIDATES,
        max_files: int = DEFAULT_MAX_FILES,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_aggregate_bytes: int = DEFAULT_MAX_AGGREGATE_BYTES,
    ) -> SourceInventory:
        """Build one resource-bounded root-confined snapshot.

        Dot-prefixed path segments, ``__pycache__`` directories, and symbolic links
        are always excluded and cannot be re-enabled by include patterns.
        """
        try:
            canonical_root = root.expanduser().resolve(strict=True)
        except OSError as error:
            raise SourceInventoryError(
                f"source inventory root is unavailable: {root}: {error}"
            ) from error
        if not canonical_root.is_dir():
            raise SourceInventoryError(f"source inventory root is not a directory: {root}")
        if not include_patterns:
            raise SourceInventoryError("source inventory requires at least one include pattern")
        limits = {
            "max_candidates": max_candidates,
            "max_files": max_files,
            "max_file_bytes": max_file_bytes,
            "max_aggregate_bytes": max_aggregate_bytes,
        }
        for name, value in limits.items():
            if value < 0:
                raise SourceInventoryError(f"source inventory {name} must not be negative")

        entries = _collect_entries(
            canonical_root,
            include_patterns=include_patterns,
            exclude_patterns=exclude_patterns,
            max_candidates=max_candidates,
            max_files=max_files,
            max_file_bytes=max_file_bytes,
            max_aggregate_bytes=max_aggregate_bytes,
        )
        payload = json.dumps(
            {
                "schema": 2,
                "root": str(canonical_root),
                "include_patterns": list(include_patterns),
                "exclude_patterns": list(exclude_patterns),
                "implicit_exclusions": list(cls.IMPLICIT_EXCLUSIONS),
                "limits": limits,
                "entries": [
                    {
                        "path": item.relative_path,
                        "sha256": item.sha256,
                        "size_bytes": item.size_bytes,
                    }
                    for item in entries
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return cls(
            root=canonical_root,
            include_patterns=include_patterns,
            exclude_patterns=exclude_patterns,
            entries=tuple(entries),
            fingerprint=hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            max_candidates=max_candidates,
            max_files=max_files,
            max_file_bytes=max_file_bytes,
            max_aggregate_bytes=max_aggregate_bytes,
        )

    def verify(self) -> None:
        """Reject source drift after this immutable inventory was captured."""
        current = SourceInventory.build(
            self.root,
            include_patterns=self.include_patterns,
            exclude_patterns=self.exclude_patterns,
            max_candidates=self.max_candidates,
            max_files=self.max_files,
            max_file_bytes=self.max_file_bytes,
            max_aggregate_bytes=self.max_aggregate_bytes,
        )
        if current.fingerprint != self.fingerprint:
            raise SourceInventoryError("source inventory changed after snapshot construction")

    @property
    def python_entries(self) -> tuple[SourceInventoryEntry, ...]:
        """Return Python sources in canonical relative-path order."""
        return tuple(item for item in self.entries if item.is_python)

    @property
    def python_paths(self) -> tuple[Path, ...]:
        """Return Python source paths in canonical relative-path order."""
        return tuple(item.path for item in self.python_entries)

    def contains(self, path: Path) -> bool:
        """Whether an existing path is an exact member of this snapshot."""
        try:
            resolved = path.resolve(strict=True)
        except OSError:
            return False
        return any(item.path == resolved for item in self.entries)

    def allows_diff_path(self, path: Path) -> bool:
        """Whether a safe project-relative Git diff path belongs to this scope."""
        normalized = path.as_posix()
        if (
            not normalized
            or normalized == "."
            or "\\" in normalized
            or PurePosixPath(normalized).is_absolute()
            or PureWindowsPath(normalized).is_absolute()
        ):
            return False
        parts = normalized.split("/")
        if any(part in {"", ".", ".."} for part in parts):
            return False

        # DiffParser removes one exact Git side prefix. Treat this API's input only
        # as project-relative; guessing whether an ``a/`` or ``b/`` segment is a
        # side marker would be ambiguous with real directories of those names.
        relative = "/".join(parts)
        return _matches_any(relative, self.include_patterns) and not _matches_any(
            relative, self.exclude_patterns
        )


def source_root_for_app(app_path: Path) -> Path:
    """Return the shared project root used by execution-free source providers."""
    resolved = app_path.expanduser().resolve()
    if resolved.is_dir():
        return resolved
    package = resolved.parent
    while (package / "__init__.py").is_file():
        package = package.parent
    return package


def _collect_entries(
    root: Path,
    *,
    include_patterns: tuple[str, ...],
    exclude_patterns: tuple[str, ...],
    max_candidates: int,
    max_files: int,
    max_file_bytes: int,
    max_aggregate_bytes: int,
) -> list[SourceInventoryEntry]:
    """Traverse deterministically without retaining more than bounded candidates."""
    entries: list[SourceInventoryEntry] = []
    candidate_count = 0
    aggregate_bytes = 0
    pending_directories = [root]
    while pending_directories:
        directory = pending_directories.pop()
        children = _bounded_children(
            directory,
            remaining_candidates=max_candidates - candidate_count,
            max_candidates=max_candidates,
        )
        candidate_count += len(children)
        child_directories: list[Path] = []
        for child in children:
            kind = _candidate_kind(child)
            if kind == "ignored":
                continue
            if kind == "directory":
                child_directories.append(Path(child.path))
                continue
            if kind != "file":
                continue
            candidate = Path(child.path)
            relative = candidate.relative_to(root).as_posix()
            if not _matches_any(relative, include_patterns) or _matches_any(
                relative, exclude_patterns
            ):
                continue
            if len(entries) >= max_files:
                raise SourceInventoryError(
                    f"source inventory selected-file limit exceeded ({max_files})"
                )
            entry = _build_entry(
                candidate,
                root=root,
                relative=relative,
                max_file_bytes=max_file_bytes,
                remaining_aggregate_bytes=max_aggregate_bytes - aggregate_bytes,
            )
            aggregate_bytes += entry.size_bytes
            entries.append(entry)
        # Reverse push preserves deterministic ascending depth-first traversal.
        pending_directories.extend(reversed(child_directories))
    entries.sort(key=lambda item: item.relative_path)
    return entries


def _bounded_children(
    directory: Path,
    *,
    remaining_candidates: int,
    max_candidates: int,
) -> list[os.DirEntry[str]]:
    children: list[os.DirEntry[str]] = []
    try:
        with os.scandir(directory) as iterator:
            for child in iterator:
                if len(children) >= remaining_candidates:
                    raise SourceInventoryError(
                        f"source inventory candidate limit exceeded ({max_candidates})"
                    )
                children.append(child)
    except SourceInventoryError:
        raise
    except OSError as error:
        raise SourceInventoryError(
            f"source inventory enumeration failed at {directory}: {error}"
        ) from error
    children.sort(key=lambda item: item.name)
    return children


def _candidate_kind(candidate: os.DirEntry[str]) -> str:
    if candidate.name.startswith(".") or candidate.name == "__pycache__":
        return "ignored"
    try:
        if candidate.is_symlink():
            return "ignored"
        if candidate.is_dir(follow_symlinks=False):
            return "directory"
        if candidate.is_file(follow_symlinks=False):
            return "file"
    except OSError as error:
        raise SourceInventoryError(
            f"source inventory candidate is unreadable: {candidate.path}"
        ) from error
    return "other"


def _build_entry(
    candidate: Path,
    *,
    root: Path,
    relative: str,
    max_file_bytes: int,
    remaining_aggregate_bytes: int,
) -> SourceInventoryEntry:
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
        digest, size_bytes = _stream_hash(
            resolved,
            max_file_bytes=max_file_bytes,
            max_aggregate_bytes=remaining_aggregate_bytes,
        )
    except SourceInventoryError:
        raise
    except (OSError, ValueError) as error:
        raise SourceInventoryError(
            f"source inventory file is unreadable or escapes its root: {relative}"
        ) from error
    return SourceInventoryEntry(
        relative_path=relative,
        path=resolved,
        module_name=_module_name(relative) if resolved.suffix == ".py" else None,
        sha256=digest,
        size_bytes=size_bytes,
    )


def _stream_hash(
    path: Path,
    *,
    max_file_bytes: int,
    max_aggregate_bytes: int,
) -> tuple[str, int]:
    """Hash one file incrementally while enforcing exact byte boundaries."""
    digest = hashlib.sha256()
    size_bytes = 0
    with path.open("rb") as source:
        while chunk := source.read(SourceInventory.HASH_CHUNK_BYTES):
            size_bytes += len(chunk)
            if size_bytes > max_file_bytes:
                raise SourceInventoryError(
                    f"source inventory per-file byte limit exceeded ({max_file_bytes})"
                )
            if size_bytes > max_aggregate_bytes:
                raise SourceInventoryError(
                    "source inventory aggregate byte limit exceeded "
                    f"({max_aggregate_bytes})"
                )
            digest.update(chunk)
    return digest.hexdigest(), size_bytes


def _matches_any(relative_path: str, patterns: tuple[str, ...]) -> bool:
    path_segments = relative_path.split("/")
    return any(
        _match_segments(path_segments, pattern.replace("\\", "/").split("/"))
        for pattern in patterns
    )


def _match_segments(path: list[str], pattern: list[str]) -> bool:
    """Match slash-delimited globs where ``**`` spans zero or more segments."""
    matched: set[tuple[int, int]] = set()

    def visit(path_index: int, pattern_index: int) -> bool:
        state = (path_index, pattern_index)
        if state in matched:
            return False
        matched.add(state)
        if pattern_index == len(pattern):
            return path_index == len(path)
        segment = pattern[pattern_index]
        if segment == "**":
            return visit(path_index, pattern_index + 1) or (
                path_index < len(path) and visit(path_index + 1, pattern_index)
            )
        return (
            path_index < len(path)
            and fnmatchcase(path[path_index], segment)
            and visit(path_index + 1, pattern_index + 1)
        )

    return visit(0, 0)


def _module_name(relative_path: str) -> str:
    path = PurePosixPath(relative_path).with_suffix("")
    parts = list(path.parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts) or PurePosixPath(relative_path).parent.name
