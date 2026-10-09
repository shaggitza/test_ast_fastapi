"""Observation scans reject special files and enforce opened-file byte budgets."""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from fastapi_endpoint_detector.analyzer import project_observations

if TYPE_CHECKING:
    from fastapi_endpoint_detector.analyzer.project_observations import ProjectObservationSnapshot


def _scan_clients(
    root: Path,
    *,
    max_file_bytes: int = 2_000_000,
) -> ProjectObservationSnapshot:
    return project_observations.scan_project_observations(
        root,
        client_include_patterns=("**/*.js",),
        deployment_include_patterns=(),
        max_file_bytes=max_file_bytes,
    )


def test_regular_candidate_is_scanned(tmp_path: Path) -> None:
    source = tmp_path / "client.js"
    source.write_text("fetch('/items');\n", encoding="utf-8")

    snapshot = _scan_clients(tmp_path)

    assert snapshot.complete
    assert snapshot.scanned_files == 1
    assert [(item.source_path, item.route_path) for item in snapshot.client_observations] == [
        (Path("client.js"), "/items")
    ]


def test_fifo_candidate_is_rejected_as_nonregular(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO creation is unavailable on this platform")
    fifo = tmp_path / "pipe.js"
    os.mkfifo(fifo)

    snapshot = _scan_clients(tmp_path)

    assert snapshot.scanned_files == 1
    assert len(snapshot.issues) == 1
    assert snapshot.issues[0].source_path == "pipe.js"
    assert snapshot.issues[0].reason == "source is not a regular file"
    assert not snapshot.complete
    assert not snapshot.client_observations


def test_fifo_replacement_between_stat_and_open_is_nonblocking_and_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not hasattr(os, "mkfifo") or not hasattr(os, "O_NONBLOCK"):
        pytest.skip("nonblocking FIFO creation is unavailable on this platform")
    candidate = tmp_path / "client.js"
    candidate.write_text("fetch('/items');\n", encoding="utf-8")
    original_open = os.open
    open_flags: list[int] = []

    def replace_with_fifo(path: str | bytes | os.PathLike[str], flags: int) -> int:
        assert Path(path) == candidate
        open_flags.append(flags)
        candidate.unlink()
        os.mkfifo(candidate)
        return original_open(path, flags)

    monkeypatch.setattr(project_observations.os, "open", replace_with_fifo)

    snapshot = _scan_clients(tmp_path)

    assert len(open_flags) == 1
    assert open_flags[0] & os.O_NONBLOCK
    assert len(snapshot.issues) == 1
    assert snapshot.issues[0].reason == "source is not a regular file"
    assert not snapshot.complete
    assert not snapshot.client_observations


def test_growth_after_open_is_bounded_to_budget_plus_one(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "client.js"
    source.write_text("fetch('/items');\n", encoding="utf-8")
    max_file_bytes = 32
    assert source.stat().st_size <= max_file_bytes
    original_read = os.read
    grew = False
    bytes_read = 0
    requested: list[int] = []

    def grow_before_first_read(descriptor: int, count: int) -> bytes:
        nonlocal grew, bytes_read
        requested.append(count)
        if not grew:
            with source.open("ab") as output:
                output.write(b" " * 128)
            grew = True
        chunk = original_read(descriptor, count)
        bytes_read += len(chunk)
        return chunk

    monkeypatch.setattr(project_observations.os, "read", grow_before_first_read)

    snapshot = _scan_clients(tmp_path, max_file_bytes=max_file_bytes)

    assert grew
    assert requested
    assert max(requested) <= max_file_bytes + 1
    assert bytes_read <= max_file_bytes + 1
    assert snapshot.scanned_files == 1
    assert len(snapshot.issues) == 1
    assert snapshot.issues[0].reason == "maximum source-file size exceeded"
    assert not snapshot.complete
    assert not snapshot.client_observations
