"""Offline safety tests for the lock-linked raw diff materializer."""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from typing import TYPE_CHECKING, Any, ClassVar

import pytest
from benchmarks.real_world import expansion_protocol_v2 as protocol
from benchmarks.real_world import materialize_locked_diffs_v2 as collector

if TYPE_CHECKING:
    from pathlib import Path


def _rows() -> list[dict[str, Any]]:
    return [
        {
            "pr": i,
            "diff_final_url": f"https://github.com/{collector.REPOSITORY}/pull/{i}.diff",
            "diff_bytes": 3,
            "diff_sha256": "sha256:" + "a" * 64,
        }
        for i in range(1, 51)
    ]


class _Response:
    headers: ClassVar[dict[str, str]] = {"Content-Type": "text/plain"}

    def __init__(self, body: bytes, url: str) -> None:
        self.body = body
        self.url = url

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def geturl(self) -> str:
        return self.url

    def read(self, size: int = -1) -> bytes:
        result, self.body = self.body[:size], self.body[size:]
        return result


class _BlockingResponse(_Response):
    def read(self, size: int = -1) -> bytes:
        time.sleep(1)
        return super().read(size)


class _Opener:
    def __init__(self, response: _Response) -> None:
        self.response = response

    def open(self, _request: object, timeout: float) -> _Response:
        assert timeout > 0
        return self.response


def test_row_identities_reject_duplicate_pr_url_and_bad_url() -> None:
    rows = _rows()
    rows[1]["pr"] = rows[0]["pr"]
    with pytest.raises(protocol.CorpusV2Error, match="duplicate PR"):
        collector._validate_rows(rows)
    rows = _rows()
    rows[1]["diff_final_url"] = rows[0]["diff_final_url"]
    with pytest.raises(protocol.CorpusV2Error, match="duplicate PR or diff URL"):
        collector._validate_rows(rows)
    rows = _rows()
    rows[0]["diff_final_url"] = "https://evil.example/1.diff"
    with pytest.raises(protocol.CorpusV2Error, match="invalid locked diff URL"):
        collector._validate_rows(rows)


def test_fetch_accepts_exact_redirect_and_rejects_wrong_host_or_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url = f"https://github.com/{collector.REPOSITORY}/pull/1.diff"
    final = f"https://patch-diff.githubusercontent.com/raw/{collector.REPOSITORY}/pull/1.diff"
    monkeypatch.setattr(
        urllib.request, "build_opener", lambda *_args: _Opener(_Response(b"abc", final))
    )
    body, fetched_url = collector._fetch(url, collector.REPOSITORY, 1, 3, time.monotonic() + 5, 10)
    assert body == b"abc"
    assert fetched_url == final
    monkeypatch.setattr(
        urllib.request,
        "build_opener",
        lambda *_args: _Opener(_Response(b"abc", "https://evil.example/1.diff")),
    )
    with pytest.raises(protocol.CorpusV2Error, match="redirect"):
        collector._fetch(url, collector.REPOSITORY, 1, 3, time.monotonic() + 5, 10)


def test_fetch_wall_deadline_interrupts_blocking_read_and_preserves_transport_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url = f"https://github.com/{collector.REPOSITORY}/pull/1.diff"
    monkeypatch.setattr(
        urllib.request,
        "build_opener",
        lambda *_args: _Opener(_BlockingResponse(b"abc", url)),
    )
    started = time.monotonic()
    with pytest.raises(collector.CollectionFailure) as caught:
        collector._fetch(url, collector.REPOSITORY, 1, 3, started + 0.05, 10)
    assert caught.value.failure_class == "deadline"
    assert caught.value.bytes_read == 0
    assert time.monotonic() - started < 0.5

    class _BlockingOpener:
        def open(self, _request: object, timeout: float) -> _Response:
            assert timeout > 0
            time.sleep(1)
            return _Response(b"abc", url)

    monkeypatch.setattr(urllib.request, "build_opener", lambda *_args: _BlockingOpener())
    started = time.monotonic()
    with pytest.raises(collector.CollectionFailure) as caught:
        collector._fetch(url, collector.REPOSITORY, 1, 3, started + 0.05, 10)
    assert caught.value.failure_class == "deadline"
    assert time.monotonic() - started < 0.5

    class _BrokenOpener:
        def open(self, _request: object, timeout: float) -> _Response:
            assert timeout > 0
            raise urllib.error.URLError("DNS lookup refused")

    monkeypatch.setattr(urllib.request, "build_opener", lambda *_args: _BrokenOpener())
    with pytest.raises(collector.CollectionFailure) as caught:
        collector._fetch(url, collector.REPOSITORY, 1, 3, time.monotonic() + 5, 10)
    assert caught.value.failure_class == "request_error"
    assert "DNS lookup refused" in str(caught.value)


def test_fetch_never_reads_beyond_remaining_aggregate_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url = f"https://github.com/{collector.REPOSITORY}/pull/1.diff"
    response = _Response(b"abcdefgh", url)
    monkeypatch.setattr(urllib.request, "build_opener", lambda *_args: _Opener(response))
    with pytest.raises(collector.CollectionFailure) as caught:
        collector._fetch(url, collector.REPOSITORY, 1, 8, time.monotonic() + 5, 3)
    assert caught.value.failure_class == "aggregate_limit"
    assert caught.value.bytes_read == 3
    assert response.body == b"defgh"
    monkeypatch.setattr(
        urllib.request, "build_opener", lambda *_args: _Opener(_Response(b"ab", url))
    )
    with pytest.raises(protocol.CorpusV2Error, match="size_mismatch"):
        collector._fetch(url, collector.REPOSITORY, 1, 3, time.monotonic() + 5, 10)


def test_publish_is_no_clobber_and_safe_output_rejects_symlink(tmp_path: Path) -> None:
    fd = collector._open_dir_chain(tmp_path, create=False)
    collector._publish(fd, "blob", b"abc")
    entry = tmp_path / "blob"
    original = hashlib.sha256(entry.read_bytes()).hexdigest()
    with pytest.raises(protocol.CorpusV2Error, match="overwrite"):
        collector._publish(fd, "blob", b"different")
    assert hashlib.sha256(entry.read_bytes()).hexdigest() == original
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(OSError):
        collector._open_dir_chain(link, create=False)
    parent_link = tmp_path / "parent-link"
    parent_link.symlink_to(target, target_is_directory=True)
    with pytest.raises(OSError):
        collector._open_dir_chain(parent_link / "new", create=True)
    os.close(fd)


def test_directory_fd_keeps_publish_in_opened_directory_after_path_swap(tmp_path: Path) -> None:
    output = tmp_path / "output"
    output.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    fd = collector._open_dir_chain(output, create=False)
    output.rename(tmp_path / "opened-output")
    output.symlink_to(outside, target_is_directory=True)
    collector._publish(fd, "receipt", b"pinned")
    assert (tmp_path / "opened-output" / "receipt").read_bytes() == b"pinned"
    assert list(outside.iterdir()) == []
    os.close(fd)


def test_hash_mismatch_never_creates_blob(tmp_path: Path) -> None:
    root = tmp_path / "out"
    root.mkdir()
    blob_dir = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    body = b"bad bytes"
    with pytest.raises(collector.CollectionFailure, match="hash_mismatch") as caught:
        collector._store_verified(blob_dir, body, "0" * 64)
    assert caught.value.bytes_read == len(body)
    assert list(root.iterdir()) == []
    os.close(blob_dir)


def test_capture_is_single_source_for_rows_when_paths_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock_path, manifest_path, checksums_path = (
        tmp_path / "lock.json",
        tmp_path / "manifest.json",
        tmp_path / "checksums.json",
    )
    captured = {
        lock_path: collector.LOCK.read_bytes(),
        manifest_path: collector.MANIFEST.read_bytes(),
        checksums_path: collector.CHECKSUMS.read_bytes(),
    }
    for path, data in captured.items():
        path.write_bytes(data)
    original_read = protocol._read_bounded
    calls = 0

    def capture_then_mutate(path: Path, limit: int = protocol._MAX_LOCAL_BYTES) -> bytes:
        nonlocal calls
        data = original_read(path, limit)
        calls += 1
        if calls == 1:
            # Later opens would see a different lock; the collector must never reopen it.
            lock_path.write_bytes(b'{"projects":[]}')
        return captured.get(path, data)

    monkeypatch.setattr(protocol, "_read_bounded", capture_then_mutate)

    def mocked_fetch(
        url: str, _repo: str, number: int, _size: int, _deadline: float, _budget: int
    ) -> tuple[bytes, str]:
        failure = number % 4
        if failure == 0:
            headers: Any = None
            raise urllib.error.HTTPError(url, 404, "missing", headers, None)
        labels = {1: "hash_mismatch", 2: "size_mismatch", 3: "invalid_resource"}
        error = collector.CollectionFailure(labels[failure], "mocked transport result")
        error.bytes_read = 7
        raise error

    monkeypatch.setattr(collector, "_fetch", mocked_fetch)
    result = collector.collect(
        tmp_path / "captured",
        lock_path=lock_path,
        manifest_path=manifest_path,
        checksums_path=checksums_path,
    )
    assert result["lock_sha256"] == collector.LOCK_SHA256
    project = next(
        p
        for p in json.loads(captured[lock_path])["projects"]
        if p["repository"] == collector.REPOSITORY
    )
    assert [row["pr"] for row in result["rows"]] == [row["pr"] for row in project["records"]]
    assert len(result["rows"]) == 50
    assert result["summary"] == {
        "rows": 50,
        "matched": 0,
        "missing": 10,
        "mismatch": 40,
        "bytes": 280,
    }
    assert {row["failure_class"] for row in result["rows"]} == {
        "http_error",
        "hash_mismatch",
        "size_mismatch",
        "invalid_resource",
    }
    assert all(
        row["http_status"] == 404 for row in result["rows"] if row["failure_class"] == "http_error"
    )


def test_existing_blob_read_is_bounded_and_rejects_symlink_and_growth(tmp_path: Path) -> None:
    expected = hashlib.sha256(b"abc").hexdigest()
    (tmp_path / expected).write_bytes(b"abc")
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    collector._read_blob(fd, expected, 3, expected)
    (tmp_path / expected).write_bytes(b"abcd")
    with pytest.raises(protocol.CorpusV2Error, match="collision"):
        collector._read_blob(fd, expected, 3, expected)
    (tmp_path / expected).unlink()
    (tmp_path / expected).symlink_to(tmp_path / "elsewhere")
    with pytest.raises(OSError):
        collector._read_blob(fd, expected, 3, expected)
    os.close(fd)
