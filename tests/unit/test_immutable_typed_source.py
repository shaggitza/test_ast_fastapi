from __future__ import annotations

import hashlib
import os
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest
from mypy.build import build
from mypy.modulefinder import BuildSource
from mypy.options import Options

from fastapi_endpoint_detector.analyzer import immutable_typed_source as source_module
from fastapi_endpoint_detector.analyzer.immutable_typed_source import (
    CaptureLimits,
    ImmutableTypedSource,
    SourceCaptureError,
    UnknownSnapshotPath,
)

if TYPE_CHECKING:
    from pathlib import Path


def _build(root: Path):
    options = Options()
    options.incremental = False
    options.ignore_missing_imports = True
    options.mypy_path = [str(root)]
    options.namespace_packages = True
    options.explicit_package_bases = True
    return build([BuildSource(str(root / "main.py"), "main")], options)


def _project(tmp_path: Path) -> tuple[Path, Path]:
    main = tmp_path / "main.py"
    helper = tmp_path / "helper.py"
    main.write_text("from helper import VALUE\nresult: int = VALUE\n")
    helper.write_text("VALUE = 1\n")
    return main, helper


def _graph(*paths: Path):
    return SimpleNamespace(
        graph={
            str(index): SimpleNamespace(
                path=str(path),
                source_hash=hashlib.sha1(path.read_bytes()).hexdigest()
                if path.is_file()
                else "0" * 40,
            )
            for index, path in enumerate(paths)
        }
    )


def test_real_build_graph_capture_freezes_sources_stats_and_directory_listing(
    tmp_path: Path,
) -> None:
    _main, helper = _project(tmp_path)
    result = _build(tmp_path)
    assert "helper" in result.graph

    snapshot = ImmutableTypedSource.capture_build_result(result, directory_roots=(tmp_path,))
    helper_key = str(helper)
    before = snapshot.stat_or_none(helper_key)
    assert snapshot.read(helper_key) == b"VALUE = 1\n"
    assert "helper.py" in snapshot.listdir(str(tmp_path))
    expected_hash = snapshot.hash_digest(helper_key)

    helper.write_text("VALUE = 2\n")
    (tmp_path / "later.py").write_text("VALUE = 3\n")
    assert snapshot.read(helper_key) == b"VALUE = 1\n"
    assert snapshot.hash_digest(helper_key) == expected_hash
    assert snapshot.stat_or_none(helper_key) == before
    assert "later.py" not in snapshot.listdir(str(tmp_path))
    with pytest.raises(UnknownSnapshotPath):
        snapshot.read(str(tmp_path / "later.py"))


@pytest.mark.parametrize(
    ("limits", "expected"),
    [
        (CaptureLimits(max_files=1), "file count"),
        (CaptureLimits(max_file_bytes=2), "required source"),
        (CaptureLimits(max_bytes=2), "aggregate source bytes"),
        (CaptureLimits(max_directories=1), "directory count"),
        (CaptureLimits(max_entries_per_directory=1), "required directory"),
    ],
)
def test_capture_fails_as_a_whole_when_a_bound_is_exceeded(
    tmp_path: Path, limits: CaptureLimits, expected: str
) -> None:
    _project(tmp_path)
    result = _build(tmp_path)
    with pytest.raises(SourceCaptureError, match=expected):
        ImmutableTypedSource.capture_build_result(
            result, directory_roots=(tmp_path,), limits=limits
        )


def test_capture_rejects_required_missing_and_symlinked_graph_sources(tmp_path: Path) -> None:
    _main, helper = _project(tmp_path)
    result = _build(tmp_path)
    helper.unlink()
    with pytest.raises(SourceCaptureError, match="required source"):
        ImmutableTypedSource.capture_build_result(result)

    helper.write_text("VALUE = 1\n")
    result = _build(tmp_path)
    target = tmp_path / "target.py"
    target.write_text("VALUE = 1\n")
    helper.unlink()
    helper.symlink_to(target)
    with pytest.raises(SourceCaptureError, match="path violates source path policy"):
        ImmutableTypedSource.capture_build_result(result)


def test_every_cache_lookup_kind_fails_closed_for_unknown_path(tmp_path: Path) -> None:
    _project(tmp_path)
    result = _build(tmp_path)
    snapshot = ImmutableTypedSource.capture_build_result(result)
    unknown = str(tmp_path / "outside.py")
    for operation in (
        snapshot.read,
        snapshot.hash_digest,
        snapshot.stat_or_none,
        snapshot.listdir,
    ):
        with pytest.raises(UnknownSnapshotPath):
            operation(unknown)


def test_source_inventory_files_join_the_same_capture(tmp_path: Path) -> None:
    main, helper = _project(tmp_path)
    excluded_lookup = tmp_path / "excluded.py"
    excluded_lookup.write_text("LOOKUP: str\n")
    result = _build(tmp_path)
    inventory = SimpleNamespace(paths=(main, helper, excluded_lookup))
    snapshot = ImmutableTypedSource.capture_build_result(result, source_inventory=inventory)
    assert snapshot.read(str(excluded_lookup)) == b"LOOKUP: str\n"


@pytest.mark.parametrize(
    ("limits", "expected"),
    [
        (CaptureLimits(max_files=1), "file count"),
        (CaptureLimits(max_file_bytes=2), "required source"),
        (CaptureLimits(max_bytes=2), "aggregate source bytes"),
    ],
)
def test_size_and_count_limits_reject_before_any_content_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, limits: CaptureLimits, expected: str
) -> None:
    _project(tmp_path)
    result = _build(tmp_path)
    reads: list[int] = []
    original_read = source_module.os.read

    def sentinel(fd: int, size: int) -> bytes:
        reads.append(size)
        return original_read(fd, size)

    monkeypatch.setattr(source_module.os, "read", sentinel)
    with pytest.raises(SourceCaptureError, match=expected):
        ImmutableTypedSource.capture_build_result(result, limits=limits)
    assert reads == []


def test_same_inode_growth_during_read_rejects_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _main, helper = _project(tmp_path)
    result = _build(tmp_path)
    original_read = source_module.os.read
    mutated = False

    def grow_after_read(fd: int, size: int) -> bytes:
        nonlocal mutated
        data = original_read(fd, size)
        if not mutated:
            with helper.open("ab") as stream:
                stream.write(b"# grew during capture\n")
            mutated = True
        return data

    monkeypatch.setattr(source_module.os, "read", grow_after_read)
    with pytest.raises(SourceCaptureError, match="required source"):
        ImmutableTypedSource.capture_build_result(result)
    assert mutated


def test_path_replacement_during_read_rejects_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _main, helper = _project(tmp_path)
    result = _build(tmp_path)
    original_read = source_module.os.read
    replaced = False

    def replace_after_read(fd: int, size: int) -> bytes:
        nonlocal replaced
        data = original_read(fd, size)
        if not replaced:
            replacement = helper.with_suffix(".replacement")
            replacement.write_bytes(b"VALUE = 7\n")
            replacement.replace(helper)
            replaced = True
        return data

    monkeypatch.setattr(source_module.os, "read", replace_after_read)
    with pytest.raises(SourceCaptureError, match="required source"):
        ImmutableTypedSource.capture_build_result(result)
    assert replaced


def test_directory_entry_drift_during_capture_rejects_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _project(tmp_path)
    result = _build(tmp_path)
    original_scandir = source_module.os.scandir
    scans = 0

    def add_entry_between_scans(path: int | str | bytes):
        nonlocal scans
        scans += 1
        if scans == 2:
            (tmp_path / "raced.py").write_text("VALUE = 2\n")
        return original_scandir(path)

    monkeypatch.setattr(source_module.os, "scandir", add_entry_between_scans)
    with pytest.raises(SourceCaptureError, match="required directory"):
        ImmutableTypedSource.capture_build_result(result, directory_roots=(tmp_path,))


def test_directory_path_replacement_during_capture_rejects_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _project(tmp_path)
    result = _build(tmp_path)
    original_scandir = source_module.os.scandir
    replaced = False

    def replace_open_directory(path: int | str | bytes):
        nonlocal replaced
        if not replaced and isinstance(path, int):
            moved = tmp_path.with_name(f"{tmp_path.name}-original")
            tmp_path.rename(moved)
            tmp_path.mkdir()
            (tmp_path / "main.py").write_text("result = 0\n")
            replaced = True
        return original_scandir(path)

    monkeypatch.setattr(source_module.os, "scandir", replace_open_directory)
    with pytest.raises(SourceCaptureError, match="required directory"):
        ImmutableTypedSource.capture_build_result(result, directory_roots=(tmp_path,))
    assert replaced


@pytest.mark.parametrize("replacement", [False, True], ids=["content", "path"])
def test_later_source_read_cannot_leave_earlier_source_stale(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, replacement: bool
) -> None:
    first = tmp_path / "a.py"
    second = tmp_path / "b.py"
    first.write_text("VALUE = 1\n")
    second.write_text("VALUE = 2\n")
    original_read = source_module.os.read
    mutated = False

    def mutate_earlier_after_later_read(fd: int, size: int) -> bytes:
        nonlocal mutated
        data = original_read(fd, size)
        if not mutated and os.fstat(fd).st_ino == second.stat().st_ino:
            if replacement:
                candidate = tmp_path / "replacement.py"
                candidate.write_text("VALUE = 9\n")
                candidate.replace(first)
            else:
                first.write_text("VALUE = 9\n")
            mutated = True
        return data

    monkeypatch.setattr(source_module.os, "read", mutate_earlier_after_later_read)
    with pytest.raises(SourceCaptureError, match="changed before completion"):
        ImmutableTypedSource.capture_build_result(_graph(first, second))
    assert mutated


@pytest.mark.parametrize("replacement", [False, True], ids=["entry", "path"])
def test_later_directory_capture_cannot_leave_earlier_listing_stale(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, replacement: bool
) -> None:
    earlier = tmp_path / "a"
    later = tmp_path / "b"
    earlier.mkdir()
    later.mkdir()
    first = earlier / "source.py"
    second = later / "source.py"
    first.write_text("VALUE = 1\n")
    second.write_text("VALUE = 2\n")
    earlier_stat = earlier.stat()
    original_scandir = source_module.os.scandir
    mutated = False

    def mutate_earlier_while_later_is_scanned(path: int | str | bytes):
        nonlocal mutated
        if not mutated and isinstance(path, int) and os.fstat(path).st_ino == later.stat().st_ino:
            if replacement:
                moved = tmp_path / "a-old"
                earlier.rename(moved)
                earlier.mkdir()
            else:
                (earlier / "late.py").write_text("VALUE = 3\n")
            mutated = True
        return original_scandir(path)

    monkeypatch.setattr(source_module.os, "scandir", mutate_earlier_while_later_is_scanned)
    with pytest.raises(SourceCaptureError, match="changed before completion"):
        ImmutableTypedSource.capture_build_result(_graph(first, second))
    assert mutated
    if replacement:
        assert earlier_stat.st_ino != earlier.stat().st_ino


def test_source_descriptor_closes_when_base_exception_interrupts_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.py"
    source.write_text("VALUE = 1\n")
    opened: list[int] = []

    def interrupt_read(fd: int, _size: int) -> bytes:
        opened.append(fd)
        raise KeyboardInterrupt

    monkeypatch.setattr(source_module.os, "read", interrupt_read)
    with pytest.raises(KeyboardInterrupt):
        ImmutableTypedSource.capture_build_result(_graph(source))
    assert len(opened) == 1
    with pytest.raises(OSError):
        os.fstat(opened[0])


def test_directory_descriptor_closes_when_base_exception_interrupts_listing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.py"
    source.write_text("VALUE = 1\n")
    original_scandir = source_module.os.scandir
    opened: list[int] = []

    def interrupt_listing(path: int | str | bytes):
        if isinstance(path, int):
            opened.append(path)
            raise KeyboardInterrupt
        return original_scandir(path)

    monkeypatch.setattr(source_module.os, "scandir", interrupt_listing)
    with pytest.raises(KeyboardInterrupt):
        ImmutableTypedSource.capture_build_result(_graph(source))
    assert len(opened) == 1
    with pytest.raises(OSError):
        os.fstat(opened[0])


@pytest.mark.parametrize(
    ("data", "decoded"),
    [
        (b"VALUE = 1\n", "VALUE = 1\n"),
        (b"\xef\xbb\xbfVALUE = 1\n", "VALUE = 1\n"),
        (b"# coding: latin-1\nVALUE = 'caf\xe9'\n", "# coding: latin-1\nVALUE = 'caf\u00e9'\n"),
    ],
)
def test_mypy_source_digest_accepts_only_recorded_raw_or_text_input(
    data: bytes, decoded: str
) -> None:
    assert source_module._mypy_source_sha1_matches(data, hashlib.sha1(data).hexdigest())
    assert source_module._mypy_source_sha1_matches(data, hashlib.sha1(decoded.encode()).hexdigest())
    assert not source_module._mypy_source_sha1_matches(data, hashlib.sha1(b"changed").hexdigest())


@pytest.mark.parametrize("digest", [None, "", "g" * 40, "a" * 39])
def test_graph_without_completed_source_hash_rejects_before_read(
    digest: object, monkeypatch
) -> None:
    graph = SimpleNamespace(
        graph={"main": SimpleNamespace(path="/__readonly_capture__/main.py", source_hash=digest)}
    )

    def unexpected_read(*_args, **_kwargs):
        raise AssertionError("source bytes must not be read without a build hash")

    monkeypatch.setattr(source_module, "_read_stable_regular_file", unexpected_read)
    with pytest.raises(SourceCaptureError, match="completed Mypy build has no valid source hash"):
        ImmutableTypedSource.capture_build_result(graph)


def test_parent_traversal_is_not_a_canonical_capture_path() -> None:
    with pytest.raises(ValueError, match="captured paths"):
        source_module._canonical("/__readonly_capture__/../main.py")


def test_changed_source_before_capture_rejects_completed_build(tmp_path: Path) -> None:
    _main, helper = _project(tmp_path)
    result = _build(tmp_path)
    helper.write_text("VALUE = 2\n")
    with pytest.raises(SourceCaptureError, match="does not match completed Mypy build"):
        ImmutableTypedSource.capture_build_result(result)


def test_text_backed_build_matches_decoded_source_hash(tmp_path: Path) -> None:
    path = tmp_path / "main.py"
    path.write_bytes(b"\xef\xbb\xbfVALUE = 1\n")
    options = Options()
    options.incremental = False
    result = build([BuildSource(str(path), "main", "VALUE = 1\n")], options)
    snapshot = ImmutableTypedSource.capture_build_result(result)
    assert str(path) in snapshot.typed_paths
    assert snapshot.read(str(path)) == path.read_bytes()


def test_inventory_digest_and_capture_only_members_are_bound(tmp_path: Path) -> None:
    main = tmp_path / "main.py"
    extra = tmp_path / "extra.py"
    main.write_text("VALUE = 1\n")
    extra.write_text("VALUE = 2\n")
    inventory = SimpleNamespace(
        paths=(extra,),
        files=(SimpleNamespace(path=extra, sha256=hashlib.sha256(extra.read_bytes()).hexdigest()),),
    )
    snapshot = ImmutableTypedSource.capture_build_result(_graph(main), source_inventory=inventory)
    assert str(main) in snapshot.typed_paths
    assert str(extra) not in snapshot.typed_paths
    extra.write_text("VALUE = 3\n")
    with pytest.raises(SourceCaptureError, match="does not match source inventory"):
        ImmutableTypedSource.capture_build_result(_graph(main), source_inventory=inventory)
