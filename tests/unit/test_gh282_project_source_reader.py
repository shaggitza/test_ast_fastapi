"""Pure filesystem-protocol controls for bounded project-source capture."""

from __future__ import annotations

import stat
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import pytest

from fastapi_endpoint_detector.analyzer import mypy_analyzer as analyzer_module
from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer

if TYPE_CHECKING:
    import os
    from collections.abc import Callable


class _ReaderFiles:
    def __init__(self) -> None:
        self.anchor = Path(Path.cwd().anchor)
        self.root = self.anchor / "synthetic" / "project"
        self.path = self.root / "source.py"
        self.contents = b"owned bytes"
        self.nodes = {
            self.anchor: self._info(stat.S_IFDIR, 1),
            self.root.parent: self._info(stat.S_IFDIR, 2),
            self.root: self._info(stat.S_IFDIR, 3),
            self.path: self._info(stat.S_IFREG, 4, len(self.contents)),
        }
        self.descriptors: dict[int, tuple[Path, SimpleNamespace]] = {}
        self.positions: dict[int, int] = {}
        self.closed: list[int] = []
        self.opens: list[tuple[Path, int]] = []
        self.reads: list[int] = []
        self.resolutions: dict[Path, Path] = {}
        self.junctions: set[Path] = set()
        self.substitute_leaf = False
        self.bad_directory_descriptor = False
        self.on_read: Callable[[], None] | None = None

    @staticmethod
    def _info(mode: int, inode: int, size: int = 0) -> SimpleNamespace:
        return SimpleNamespace(
            st_mode=mode,
            st_dev=1,
            st_ino=inode,
            st_size=size,
            st_mtime_ns=10,
            st_ctime_ns=10,
            st_file_attributes=0,
        )

    def open(self, path: str | Path, flags: int, *, dir_fd: int | None = None) -> int:
        target = Path(path)
        if dir_fd is not None:
            target = self.descriptors[dir_fd][0] / target
        info = SimpleNamespace(**vars(self.nodes[target]))
        if target == self.path and self.substitute_leaf:
            info.st_ino = 999
        if stat.S_ISDIR(info.st_mode) and self.bad_directory_descriptor:
            info.st_mode = stat.S_IFREG
        descriptor = len(self.opens) + 10
        self.opens.append((target, flags))
        self.descriptors[descriptor] = (target, info)
        self.positions[descriptor] = 0
        return descriptor

    def close(self, descriptor: int) -> None:
        self.closed.append(descriptor)

    def fstat(self, descriptor: int) -> os.stat_result:
        return cast("os.stat_result", SimpleNamespace(**vars(self.descriptors[descriptor][1])))

    def read(self, descriptor: int, requested: int) -> bytes:
        self.reads.append(requested)
        if self.on_read is not None:
            self.on_read()
        start = self.positions[descriptor]
        result = self.contents[start : start + requested]
        self.positions[descriptor] += len(result)
        return result

    def install(self, monkeypatch: pytest.MonkeyPatch, *, mode: str) -> MypyAnalyzer:
        def path_info(path: Path, **_kwargs: object) -> os.stat_result:
            return cast("os.stat_result", SimpleNamespace(**vars(self.nodes[path])))

        def resolved(path: Path, *, strict: bool = False) -> Path:
            if strict and path not in self.nodes:
                raise OSError("missing synthetic path")
            return self.resolutions.get(path, path)

        monkeypatch.setattr(Path, "lstat", path_info)
        monkeypatch.setattr(Path, "stat", path_info)
        monkeypatch.setattr(Path, "resolve", resolved)
        monkeypatch.setattr(Path, "is_junction", lambda path: path in self.junctions, raising=False)
        monkeypatch.setattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400, raising=False)
        flags: dict[str, object] = {
            "O_RDONLY": 0,
            "O_BINARY": 0x1000,
            "O_NONBLOCK": 0x2000,
            "open": self.open,
            "close": self.close,
            "fstat": self.fstat,
            "read": self.read,
            "supports_dir_fd": set() if mode == "no_dir_fd" else {self.open},
        }
        if mode != "no_nofollow":
            flags["O_NOFOLLOW"] = 0x4000
        if mode != "no_directory":
            flags["O_DIRECTORY"] = 0x8000
        monkeypatch.setattr(analyzer_module, "os", SimpleNamespace(**flags))
        analyzer = MypyAnalyzer.__new__(MypyAnalyzer)
        analyzer.source_root = self.root
        return analyzer


@pytest.mark.parametrize("mode", ["descriptor", "no_dir_fd", "no_nofollow", "no_directory"])
def test_project_source_reader_accepts_bounded_canonical_snapshot(
    mode: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = _ReaderFiles()
    analyzer = files.install(monkeypatch, mode=mode)

    assert analyzer._read_project_source(files.path, len(files.contents)) == files.contents
    assert files.reads and max(files.reads) <= len(files.contents) + 1
    assert all(flags & 0x1000 for _path, flags in files.opens)
    assert len(files.closed) == len(files.opens)
    if mode in {"no_dir_fd", "no_nofollow"}:
        assert [path for path, _flags in files.opens] == [files.path]
    else:
        assert [path for path, _flags in files.opens] == [
            files.anchor,
            files.root.parent,
            files.root,
            files.path,
        ]


@pytest.mark.parametrize("mode", ["descriptor", "no_dir_fd", "no_nofollow", "no_directory"])
def test_project_source_reader_rejects_oversize_without_reading(
    mode: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = _ReaderFiles()
    analyzer = files.install(monkeypatch, mode=mode)

    assert analyzer._read_project_source(files.path, len(files.contents) - 1) is None
    assert files.reads == []
    assert len(files.closed) == len(files.opens)


@pytest.mark.parametrize("component", ["anchor", "ancestor", "root", "leaf"])
@pytest.mark.parametrize("link_kind", ["symlink", "junction", "reparse"])
def test_project_source_reader_rejects_linked_components_before_open(
    component: str,
    link_kind: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = _ReaderFiles()
    path = {
        "anchor": files.anchor,
        "ancestor": files.root.parent,
        "root": files.root,
        "leaf": files.path,
    }[component]
    if link_kind == "symlink":
        files.nodes[path].st_mode = stat.S_IFLNK
    elif link_kind == "junction":
        files.junctions.add(path)
    else:
        files.nodes[path].st_file_attributes = 0x400
    analyzer = files.install(monkeypatch, mode="no_dir_fd")

    assert analyzer._read_project_source(files.path, 64) is None
    assert files.opens == []
    assert files.reads == []


@pytest.mark.parametrize("mode", ["descriptor", "no_dir_fd", "no_nofollow"])
def test_project_source_reader_rejects_substituted_descriptor_before_read(
    mode: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = _ReaderFiles()
    files.substitute_leaf = True
    analyzer = files.install(monkeypatch, mode=mode)

    assert analyzer._read_project_source(files.path, 64) is None
    assert files.reads == []
    assert len(files.closed) == len(files.opens)


def test_project_source_reader_requires_directory_descriptors_without_directory_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = _ReaderFiles()
    files.bad_directory_descriptor = True
    analyzer = files.install(monkeypatch, mode="no_directory")

    assert analyzer._read_project_source(files.path, 64) is None
    assert files.reads == []
    assert files.closed == [10]


@pytest.mark.parametrize("change", ["inode", "path_version", "descriptor_version", "parent_link"])
def test_project_source_reader_rejects_changes_during_read(
    change: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = _ReaderFiles()
    analyzer = files.install(monkeypatch, mode="no_dir_fd")

    def mutate() -> None:
        if change == "inode":
            files.nodes[files.path].st_ino = 999
        elif change == "path_version":
            files.nodes[files.path].st_mtime_ns = 11
        elif change == "descriptor_version":
            files.descriptors[10][1].st_ctime_ns = 11
        else:
            files.nodes[files.root].st_mode = stat.S_IFLNK

    files.on_read = mutate
    assert analyzer._read_project_source(files.path, 64) is None
    assert files.reads
    assert files.closed == [10]


@pytest.mark.parametrize(
    "invalid", ["outside", "relative", "parent", "noncanonical_root", "noncanonical_leaf"]
)
def test_project_source_reader_rejects_noncanonical_or_unconfined_paths(
    invalid: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = _ReaderFiles()
    analyzer = files.install(monkeypatch, mode="no_dir_fd")
    path = files.path
    if invalid == "outside":
        path = files.anchor / "outside" / "source.py"
    elif invalid == "relative":
        analyzer.source_root = Path("relative")
    elif invalid == "parent":
        path = files.root / ".." / "source.py"
    elif invalid == "noncanonical_root":
        files.resolutions[files.root] = files.anchor / "outside"
    else:
        files.resolutions[files.path] = files.anchor / "outside" / "source.py"

    assert analyzer._read_project_source(path, 64) is None
    assert files.opens == []
    assert files.reads == []


def test_project_source_reader_enforces_sentinel_even_with_stale_small_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = _ReaderFiles()
    files.nodes[files.path].st_size = 0
    analyzer = files.install(monkeypatch, mode="no_dir_fd")

    assert analyzer._read_project_source(files.path, 3) is None
    assert sum(files.reads) == 4
    assert files.closed == [10]
