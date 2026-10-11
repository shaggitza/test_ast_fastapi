"""Bounded immutable filesystem closure for a completed Mypy build graph.

The snapshot is an input to cache construction, not a trust decision. Capture
fails atomically when any graph source or required directory cannot be pinned.
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import stat
import tokenize
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType


class SourceCaptureError(RuntimeError):
    """The requested Mypy source closure could not be captured completely."""


class UnknownSnapshotPath(FileNotFoundError):
    """A cache request is outside the immutable captured closure."""


@dataclass(frozen=True)
class CaptureLimits:
    max_files: int = 20_000
    max_bytes: int = 256 * 1024 * 1024
    max_file_bytes: int = 16 * 1024 * 1024
    max_directories: int = 20_000
    max_entries_per_directory: int = 100_000
    max_total_directory_entries: int = 1_000_000

    def __post_init__(self) -> None:
        if any(type(value) is not int or value <= 0 for value in vars(self).values()):
            raise ValueError("capture limits must be positive")


_DEFAULT_LIMITS = CaptureLimits()


@dataclass(frozen=True)
class CapturedSource:
    path: str
    content: bytes
    sha256: str
    stat_result: os.stat_result


@dataclass(frozen=True)
class ImmutableTypedSource:
    """Read-only Mypy FileSystemCache-compatible view over one capture."""

    files: Mapping[str, CapturedSource]
    directories: Mapping[str, tuple[str, ...]]
    directory_stats: Mapping[str, os.stat_result]
    identity: str
    typed_paths: frozenset[str] = frozenset()

    @classmethod
    def capture_build_result(  # noqa: PLR0912, PLR0915
        cls,
        build_result: object,
        *,
        source_inventory: object | None = None,
        directory_roots: tuple[str | os.PathLike[str], ...] = (),
        trusted_files: tuple[str | os.PathLike[str], ...] = (),
        limits: CaptureLimits | None = None,
    ) -> ImmutableTypedSource:
        """Capture every Python source in ``BuildResult.graph`` plus explicit closure.

        ``trusted_files`` is an explicit same-capture closure for engine/type
        sources that are required by the consumer but absent from the graph.
        No ambient fallback is provided by the returned cache view. Graph files
        must match the completed build's recorded source hashes. Inventory and
        trusted extras are capture-only unless also present in that graph.
        """
        limits = limits or _DEFAULT_LIMITS
        graph = getattr(build_result, "graph", None)
        if not isinstance(graph, Mapping):
            raise SourceCaptureError("build result has no module graph")
        paths: set[str] = set()
        graph_hashes: dict[str, set[str]] = {}
        inventory_hashes: dict[str, str] = {}
        try:
            for state in graph.values():
                raw_path = getattr(state, "path", None)
                if raw_path and Path(str(raw_path)).suffix in {".py", ".pyi"}:
                    name = _canonical(str(raw_path))
                    digest = getattr(state, "source_hash", None)
                    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{40}", digest):
                        raise SourceCaptureError("completed Mypy build has no valid source hash")
                    paths.add(name)
                    graph_hashes.setdefault(name, set()).add(digest)
            inventory_paths = getattr(source_inventory, "paths", ())
            paths.update(_canonical(os.fspath(path)) for path in inventory_paths)
            for record in getattr(source_inventory, "files", ()):
                name = _canonical(os.fspath(record.path))
                digest = getattr(record, "sha256", None)
                if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                    raise SourceCaptureError("source inventory has no valid source hash")
                if name in inventory_hashes and inventory_hashes[name] != digest:
                    raise SourceCaptureError("source inventory has conflicting source hashes")
                inventory_hashes[name] = digest
                paths.add(name)
            paths.update(_canonical(os.fspath(path)) for path in trusted_files)
        except (OSError, ValueError) as exc:
            raise SourceCaptureError("required graph path violates source path policy") from exc
        if not paths:
            raise SourceCaptureError("build graph has no Python source paths")
        if len(paths) > limits.max_files:
            raise SourceCaptureError("source file count exceeds capture limit")

        captured: dict[str, CapturedSource] = {}
        total_bytes = 0
        for name in sorted(paths):
            try:
                remaining_bytes = limits.max_bytes - total_bytes
                data, before, after = _read_stable_regular_file(
                    name,
                    min(limits.max_file_bytes, remaining_bytes),
                    file_limit=limits.max_file_bytes,
                )
            except _FileTooLarge as exc:
                if exc.bound == "aggregate":
                    raise SourceCaptureError("aggregate source bytes exceed capture limit") from exc
                raise SourceCaptureError(f"required source could not be captured: {name}") from exc
            except (OSError, ValueError) as exc:
                raise SourceCaptureError(f"required source could not be captured: {name}") from exc
            if _stat_signature(before) != _stat_signature(after):
                raise SourceCaptureError(f"required source changed during capture: {name}")
            if any(
                not _mypy_source_sha1_matches(data, digest) for digest in graph_hashes.get(name, ())
            ):
                raise SourceCaptureError("captured source does not match completed Mypy build")
            if (
                name in inventory_hashes
                and hashlib.sha256(data).hexdigest() != inventory_hashes[name]
            ):
                raise SourceCaptureError("captured source does not match source inventory")
            total_bytes += len(data)
            if total_bytes > limits.max_bytes:
                raise SourceCaptureError("aggregate source bytes exceed capture limit")
            captured[name] = CapturedSource(name, data, hashlib.sha256(data).hexdigest(), before)

        dirs = {str(Path(name).parent) for name in paths}
        for raw_root in directory_roots:
            root = _canonical(os.fspath(raw_root))
            dirs.add(root)
        if len(dirs) > limits.max_directories:
            raise SourceCaptureError("directory count exceeds capture limit")

        listings: dict[str, tuple[str, ...]] = {}
        dir_stats: dict[str, os.stat_result] = {}
        entry_count = 0
        for name in sorted(dirs):
            descriptor = -1
            try:
                descriptor = _open_directory_nofollow(name)
                st = os.fstat(descriptor)
                if not stat.S_ISDIR(st.st_mode):
                    raise ValueError("not a directory")
                entries = []
                with os.scandir(descriptor) as iterator:
                    for entry in iterator:
                        entries.append(entry.name)
                        if len(entries) > limits.max_entries_per_directory:
                            raise ValueError("directory entry count exceeds limit")
                after = os.fstat(descriptor)
                if _stat_signature(st) != _stat_signature(after):
                    raise ValueError("directory changed during capture")
                with os.scandir(descriptor) as iterator:
                    verified_entries = sorted(entry.name for entry in iterator)
                if verified_entries != sorted(entries):
                    raise ValueError("directory entries changed during capture")
                current_directory = Path(name).stat(follow_symlinks=False)
                if _stat_signature(after) != _stat_signature(current_directory):
                    raise ValueError("directory path changed during capture")
            except (OSError, ValueError) as exc:
                raise SourceCaptureError(
                    f"required directory could not be captured: {name}"
                ) from exc
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
            entry_count += len(entries)
            if entry_count > limits.max_total_directory_entries:
                raise SourceCaptureError("aggregate directory entries exceed capture limit")
            listings[name] = tuple(sorted(entries))
            dir_stats[name] = st

        # Revisit the complete captured closure after the last source and
        # directory has been read. This bounded second pass uses one descriptor
        # at a time and detects changes to earlier paths while later paths were
        # being captured. It is a drift check, not a filesystem-wide atomic
        # snapshot: filesystems do not generally provide that primitive here.
        try:
            for name, item in captured.items():
                current = _current_file_signature(name)
                if current != _stat_signature(item.stat_result):
                    raise ValueError(f"source changed before capture completed: {name}")
            for name, captured_entries in listings.items():
                current_stat, current_entries = _current_directory_state(
                    name, limits.max_entries_per_directory
                )
                if (
                    _stat_signature(current_stat) != _stat_signature(dir_stats[name])
                    or current_entries != captured_entries
                ):
                    raise ValueError(f"directory changed before capture completed: {name}")
        except (OSError, ValueError) as exc:
            raise SourceCaptureError("captured source closure changed before completion") from exc

        identity_hash = hashlib.sha256()
        for name, digests in sorted(graph_hashes.items()):
            identity_hash.update(b"typed\0" + name.encode() + b"\0")
            for digest in sorted(digests):
                identity_hash.update(digest.encode() + b"\0")
        for name, item in sorted(captured.items()):
            identity_hash.update(name.encode() + b"\0" + item.sha256.encode() + b"\0")
            identity_hash.update(repr(_stat_signature(item.stat_result)).encode() + b"\0")
        for name, directory_entries in sorted(listings.items()):
            identity_hash.update(
                name.encode() + b"\0" + "\0".join(directory_entries).encode() + b"\0"
            )
            identity_hash.update(repr(_stat_signature(dir_stats[name])).encode() + b"\0")
        return cls(
            MappingProxyType(captured),
            MappingProxyType(listings),
            MappingProxyType(dir_stats),
            identity_hash.hexdigest(),
            frozenset(graph_hashes),
        )

    def read(self, path: str) -> bytes:
        return self._file(path).content

    def hash_digest(self, path: str) -> str:
        """Return Mypy's SHA-1 content digest from captured bytes."""
        return hashlib.sha1(self._file(path).content).hexdigest()

    def stat_or_none(self, path: str) -> os.stat_result:
        name = _canonical(path)
        item = self.files.get(name)
        if item is not None:
            return item.stat_result
        directory_stat = self.directory_stats.get(name)
        if directory_stat is not None:
            return directory_stat
        raise UnknownSnapshotPath(name)

    def listdir(self, path: str) -> list[str]:
        name = _canonical(path)
        try:
            return list(self.directories[name])
        except KeyError as exc:
            raise UnknownSnapshotPath(name) from exc

    def _file(self, path: str) -> CapturedSource:
        name = _canonical(path)
        try:
            return self.files[name]
        except KeyError as exc:
            raise UnknownSnapshotPath(name) from exc


def _mypy_source_sha1_matches(data: bytes, expected: str) -> bool:
    """Match Mypy's raw file bytes or decoded UTF-8 BuildSource.text input."""
    candidates = {hashlib.sha1(data).hexdigest()}
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
        text = data.decode(encoding)
    except (LookupError, SyntaxError, UnicodeError):
        pass
    else:
        candidates.add(hashlib.sha1(text.encode("utf-8")).hexdigest())
    return expected in candidates


def _canonical(path: str) -> str:
    candidate = Path(path)
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("captured paths must be absolute")
    # resolve(strict=True) follows symlinks, so reject each component first.
    current = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        current /= part
        if current.is_symlink():
            raise ValueError("symlink paths are not allowed in source closure")
    return str(candidate)


class _FileTooLarge(ValueError):
    def __init__(self, bound: str) -> None:
        super().__init__(f"source exceeds {bound} limit")
        self.bound = bound


def _read_stable_regular_file(
    path: str, limit: int, *, file_limit: int
) -> tuple[bytes, os.stat_result, os.stat_result]:
    target = Path(path)
    directory_fd = _open_directory_nofollow(str(target.parent))
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(target.name, flags, dir_fd=directory_fd)
    except BaseException:
        os.close(directory_fd)
        raise
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("source is not a regular file")
        if before.st_size > limit:
            bound = "file" if before.st_size > file_limit else "aggregate"
            raise _FileTooLarge(bound)
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > limit or len(data) != before.st_size:
            raise ValueError("source size changed or exceeds limit")
        after = os.fstat(fd)
        if _stat_signature(before) != _stat_signature(after):
            raise ValueError("source changed during capture")
        current = os.stat(target.name, dir_fd=directory_fd, follow_symlinks=False)
        if _stat_signature(after) != _stat_signature(current):
            raise ValueError("source path changed during capture")
        current_parent = target.parent.stat(follow_symlinks=False)
        if _stat_signature(os.fstat(directory_fd)) != _stat_signature(current_parent):
            raise ValueError("source directory path changed during capture")
        return data, before, after
    finally:
        os.close(fd)
        os.close(directory_fd)


def _open_directory_nofollow(path: str) -> int:
    """Open each directory component without following symlinks."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(os.path.sep, flags)
    try:
        for part in Path(path).parts[1:]:
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _current_file_signature(path: str) -> tuple[int, ...]:
    target = Path(path)
    parent_fd = _open_directory_nofollow(str(target.parent))
    try:
        descriptor = os.open(
            target.name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise ValueError("source is not a regular file")
            path_stat = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
            parent_stat = os.fstat(parent_fd)
            current_parent = target.parent.stat(follow_symlinks=False)
            if _stat_signature(opened) != _stat_signature(path_stat) or _stat_signature(
                parent_stat
            ) != _stat_signature(current_parent):
                raise ValueError("source path identity changed")
            return _stat_signature(opened)
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_fd)


def _current_directory_state(path: str, max_entries: int) -> tuple[os.stat_result, tuple[str, ...]]:
    descriptor = _open_directory_nofollow(path)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISDIR(before.st_mode):
            raise ValueError("not a directory")
        with os.scandir(descriptor) as iterator:
            entries = []
            for entry in iterator:
                entries.append(entry.name)
                if len(entries) > max_entries:
                    raise ValueError("directory entry count exceeds limit")
        after = os.fstat(descriptor)
        current_path = Path(path).stat(follow_symlinks=False)
        if _stat_signature(before) != _stat_signature(after) or _stat_signature(
            after
        ) != _stat_signature(current_path):
            raise ValueError("directory path identity changed")
        return after, tuple(sorted(entries))
    finally:
        os.close(descriptor)


def _stat_signature(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
