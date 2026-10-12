"""Offline safety tests for the lock-linked raw diff materializer."""

from __future__ import annotations

import hashlib
import http.client
import io
import json
import os
import signal
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


def _local_http_response(payload: bytes, url: str, headers: bytes) -> http.client.HTTPResponse:
    raw = b"HTTP/1.1 200 OK\r\n" + headers + b"\r\n" + payload

    class _Socket:
        def makefile(self, _mode: str) -> io.BytesIO:
            return io.BytesIO(raw)

    response = http.client.HTTPResponse(_Socket())
    response.begin()
    response.url = url
    return response


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
    response = _local_http_response(
        b"abc", final, b"Content-Type: text/plain\r\nContent-Length: 3\r\n"
    )
    monkeypatch.setattr(urllib.request, "build_opener", lambda *_args: _Opener(response))
    body, fetched_url = collector._fetch(url, collector.REPOSITORY, 1, 3, time.monotonic() + 5, 10)
    assert body == b"abc"
    assert fetched_url == final
    monkeypatch.setattr(
        urllib.request,
        "build_opener",
        lambda *_args: _Opener(
            _local_http_response(
                b"abc",
                "https://evil.example/1.diff",
                b"Content-Type: text/plain\r\nContent-Length: 3\r\n",
            )
        ),
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


def test_active_caller_alarm_is_refused_without_changing_it() -> None:
    previous_handler = signal.getsignal(signal.SIGALRM)

    def handler(_signum: int, _frame: Any) -> None:
        return None

    signal.signal(signal.SIGALRM, handler)
    signal.setitimer(signal.ITIMER_REAL, 5, 2)
    try:
        before = signal.getitimer(signal.ITIMER_REAL)
        with (
            pytest.raises(collector.CollectionFailure, match="caller-owned active"),
            collector._wall_deadline(time.monotonic() + 1),
        ):
            pass
        after = signal.getitimer(signal.ITIMER_REAL)
        assert signal.getsignal(signal.SIGALRM) is handler
        assert after[1] == before[1]
        assert 0 < after[0] <= before[0]
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)


def test_nested_deadline_does_not_extend_outer_deadline() -> None:
    started = time.monotonic()
    with (
        pytest.raises(collector.CollectionFailure, match="wall-clock limit"),
        collector._wall_deadline(started + 0.05),
        collector._wall_deadline(started + 5),
    ):
        time.sleep(1)
    assert time.monotonic() - started < 0.5


def test_earlier_nested_deadline_shortens_outer_deadline() -> None:
    started = time.monotonic()
    with (
        pytest.raises(collector.CollectionFailure, match="wall-clock limit"),
        collector._wall_deadline(started + 5),
        collector._wall_deadline(started + 0.05),
    ):
        time.sleep(1)
    assert time.monotonic() - started < 0.5


def test_already_expired_nested_deadline_leaves_no_alarm_or_guard_state() -> None:
    with (  # noqa: SIM117
        collector._wall_deadline(time.monotonic() + 5),
        pytest.raises(collector.CollectionFailure, match="wall-clock limit"),
    ):
        with collector._wall_deadline(time.monotonic() - 1):
            pytest.fail("expired nested deadline entered its body")
    assert collector._deadline_depth == 0
    assert collector._deadline_at is None
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)


@pytest.mark.parametrize("blocked_operation", ["read", "fsync"])
def test_deadline_interrupts_blocking_cache_io(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, blocked_operation: str
) -> None:
    body = b"cached body"
    digest = hashlib.sha256(body).hexdigest()
    rootfd = collector._open_dir_chain(tmp_path, create=False)
    if blocked_operation == "read":
        collector._publish(rootfd, digest, body)
        original_read = os.read

        def blocked_read(fd: int, size: int) -> bytes:
            time.sleep(1)
            return original_read(fd, size)

        monkeypatch.setattr(os, "read", blocked_read)
    else:
        original_fsync = os.fsync

        def blocked_fsync(fd: int) -> None:
            time.sleep(1)
            original_fsync(fd)

        monkeypatch.setattr(os, "fsync", blocked_fsync)
    started = time.monotonic()
    try:
        with (
            pytest.raises(collector.CollectionFailure, match="wall-clock limit"),
            collector._wall_deadline(started + 0.05),
        ):
            collector._store_verified(rootfd, body, digest)
    finally:
        os.close(rootfd)
    assert time.monotonic() - started < 0.5


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


def test_fetch_exact_remaining_budget_fails_closed_on_unverified_eof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url = f"https://github.com/{collector.REPOSITORY}/pull/1.diff"
    response = _Response(b"abc!", url)
    monkeypatch.setattr(urllib.request, "build_opener", lambda *_args: _Opener(response))
    with pytest.raises(collector.CollectionFailure) as caught:
        collector._fetch(url, collector.REPOSITORY, 1, 3, time.monotonic() + 5, 3)
    assert caught.value.failure_class == "aggregate_budget"
    assert caught.value.bytes_read == 3
    assert response.body == b"!"


def test_fetch_exact_budget_accepts_only_completed_fixed_length_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url = f"https://github.com/{collector.REPOSITORY}/pull/1.diff"
    cases = [
        (b"abc", b"Content-Length: 3\r\n", True),
        (b"abc", b"", False),
        (b"abc", b"Content-Length: 3\r\nTransfer-Encoding: identity\r\n", False),
        (b"abc", b"Content-Length: 4\r\n", False),
        (b"ab", b"Content-Length: 3\r\n", False),
        (b"abc", b"Content-Length: 3\r\nContent-Length: 3\r\n", False),
        (b"abc", b"Content-Length: 3, 3\r\n", False),
        (b"abc", b"Content-Length: " + b"9" * 5000 + b"\r\n", False),
        (b"abc", b"Content-Length: 3\r\nTransfer-Encoding: chunked\r\n", False),
    ]
    for payload, framing, succeeds in cases:
        response = _local_http_response(payload, url, b"Content-Type: text/plain\r\n" + framing)
        monkeypatch.setattr(urllib.request, "build_opener", lambda *_args, r=response: _Opener(r))
        if succeeds:
            body, _ = collector._fetch(url, collector.REPOSITORY, 1, 3, time.monotonic() + 5, 3)
            assert body == b"abc"
            assert response.fp is None
            assert response.length == 0
        else:
            with pytest.raises(collector.CollectionFailure) as caught:
                collector._fetch(url, collector.REPOSITORY, 1, 3, time.monotonic() + 5, 3)
            assert caught.value.failure_class in {"aggregate_budget", "size_mismatch"}


def test_storage_failures_do_not_reuse_downloaded_byte_allowance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = (collector.LOCK, collector.MANIFEST, collector.CHECKSUMS)
    captured = {path: path.read_bytes() for path in paths}
    original_read = protocol._read_bounded
    monkeypatch.setattr(
        protocol,
        "_read_bounded",
        lambda path, *args: captured[path] if path in captured else original_read(path, *args),
    )
    allowances: list[int] = []

    def fetched(
        _url: str, _repo: str, _number: int, size: int, _deadline: float, budget: int
    ) -> tuple[bytes, str]:
        allowances.append(budget)
        return b"x" * size, "https://github.com/fastapi/full-stack-fastapi-template/pull/1.diff"

    def fail_store(*_args: object) -> str:
        raise OSError("mocked local disk failure")

    monkeypatch.setattr(collector, "_fetch", fetched)
    monkeypatch.setattr(collector, "_store_verified", fail_store)
    result = collector.collect(tmp_path / "out")
    assert result["summary"]["bytes"] == collector.MAX_TOTAL_BYTES
    first_size = result["rows"][0]["expected_bytes"]
    assert allowances[1] == collector.MAX_TOTAL_BYTES - first_size
    assert all(row["failure_class"] == "local_storage_error" for row in result["rows"])
    assert all(row["status"] == "missing" for row in result["rows"])
    assert result["summary"]["missing"] == 50
    assert result["summary"]["mismatch"] == 0


def test_expired_final_row_storage_fails_without_receipt_and_charges_bytes_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured = {
        path: path.read_bytes()
        for path in (collector.LOCK, collector.MANIFEST, collector.CHECKSUMS)
    }
    original_read = protocol._read_bounded
    monkeypatch.setattr(
        protocol,
        "_read_bounded",
        lambda path, *args: captured[path] if path in captured else original_read(path, *args),
    )

    allowances: list[int] = []
    sizes_fetched: list[int] = []

    def fetched(
        url: str, _repo: str, _number: int, size: int, _deadline: float, budget: int
    ) -> tuple[bytes, str]:
        allowances.append(budget)
        sizes_fetched.append(size)
        return b"x" * size, url

    store_calls = 0

    def store(_fd: int, _body: bytes, expected_hash: str) -> str:
        nonlocal store_calls
        store_calls += 1
        if store_calls == 50:
            time.sleep(1.5)
        return expected_hash

    monkeypatch.setattr(collector, "_fetch", fetched)
    monkeypatch.setattr(collector, "_store_verified", store)
    monkeypatch.setattr(collector, "MAX_SECONDS", 1)
    publish_calls: list[str] = []
    original_publish = collector._publish

    def publish_spy(fd: int, name: str, body: bytes) -> None:
        publish_calls.append(name)
        original_publish(fd, name, body)

    monkeypatch.setattr(collector, "_publish", publish_spy)
    output = tmp_path / "deadline-out"
    with pytest.raises(collector.CollectionFailure, match="wall-clock limit") as caught:
        collector.collect(output)
    assert caught.value.failure_class == "deadline"
    assert store_calls == 50  # the real alarm interrupted the final storage call
    assert sum(sizes_fetched) == collector.MAX_TOTAL_BYTES
    assert allowances == [
        collector.MAX_TOTAL_BYTES - sum(sizes_fetched[:index])
        for index in range(len(sizes_fetched))
    ]
    assert publish_calls == []
    assert not (output / "receipts.json").exists()
    assert collector._deadline_depth == 0
    assert collector._deadline_at is None
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)


@pytest.mark.parametrize("failure_stage", ["row_loop", "assembly", "publication", "cache_open"])
def test_owned_directory_descriptors_close_on_post_open_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure_stage: str
) -> None:
    captured = {
        path: path.read_bytes()
        for path in (collector.LOCK, collector.MANIFEST, collector.CHECKSUMS)
    }
    original_read_bounded = protocol._read_bounded
    monkeypatch.setattr(
        protocol,
        "_read_bounded",
        lambda path, *args: (
            captured[path] if path in captured else original_read_bounded(path, *args)
        ),
    )
    owned: set[int] = set()
    closed: set[int] = set()
    original_open_chain = collector._open_dir_chain
    original_open = os.open
    original_close = os.close

    def tracked_open_chain(path: Path, *, create: bool) -> int:
        fd = original_open_chain(path, create=create)
        owned.add(fd)
        return fd

    def tracked_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        if path == "blobs" and kwargs.get("dir_fd") in owned and failure_stage == "cache_open":
            raise OSError("mocked cache open failure")
        fd = original_open(path, flags, *args, **kwargs)
        if path == "blobs" and kwargs.get("dir_fd") in owned:
            owned.add(fd)
        return fd

    def tracked_close(fd: int) -> None:
        if fd in owned:
            closed.add(fd)
        original_close(fd)

    monkeypatch.setattr(collector, "_open_dir_chain", tracked_open_chain)
    monkeypatch.setattr(os, "open", tracked_open)
    monkeypatch.setattr(os, "close", tracked_close)
    monkeypatch.setattr(collector, "MAX_SECONDS", 10)
    monkeypatch.setattr(
        collector,
        "_fetch",
        lambda url, _repo, _number, size, _deadline, _budget: (b"x" * size, url),
    )
    monkeypatch.setattr(collector, "_store_verified", lambda _fd, _body, digest: digest)
    if failure_stage == "row_loop":

        def interrupt_fetch(*_args: object) -> tuple[bytes, str]:
            raise KeyboardInterrupt

        monkeypatch.setattr(collector, "_fetch", interrupt_fetch)
    elif failure_stage == "assembly":
        monkeypatch.setattr(
            collector.json,
            "dumps",
            lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("assembly failure")),
        )
    elif failure_stage == "publication":
        monkeypatch.setattr(
            collector,
            "_publish",
            lambda *_a: (_ for _ in ()).throw(RuntimeError("publish failure")),
        )

    with pytest.raises((KeyboardInterrupt, RuntimeError, protocol.CorpusV2Error)):
        collector.collect(tmp_path / "tracked-output")
    assert owned
    assert closed == owned


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
