#!/usr/bin/env python3
"""Materialize exact public diff bytes already bound by the frozen v2 lock."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.client
import json
import os
import signal
import stat
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from collections.abc import Iterator

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from benchmarks.real_world import expansion_protocol_v2 as protocol  # noqa: E402

LOCK = ROOT / "benchmarks/real_world/expansion/pr-lock-2500-v2.json"
MANIFEST = ROOT / "benchmarks/real_world/expansion/projects-50x50-v2.json"
CHECKSUMS = ROOT / "benchmarks/real_world/expansion/checksums-50x50-v2.json"
LOCK_SHA256 = "70496533d84a3f97db24fd41acdde416d09a2f10787e2088f802769ad8e24552"
MANIFEST_SHA256 = "abd4ee6418a70bf1963a379b26d3ddaf1fe43b2a5a5b60f4090801d1ac5dbc1c"
CHECKSUMS_SHA256 = "94e535d1d54e951c0d893652f1b5a8df95aa406390fd169938b71157516436fe"
REPOSITORY = "fastapi/full-stack-fastapi-template"
MAX_TOTAL_BYTES = 443_496
MAX_ROW_BYTES = 2_000_000
MAX_SECONDS = 180
SCHEMA = "locked-raw-diff-receipts-v1"


class CollectionFailure(protocol.CorpusV2Error):
    """A collection failure with a stable machine-readable category."""

    def __init__(self, failure_class: str, detail: str) -> None:
        super().__init__(detail)
        self.failure_class = failure_class
        self.bytes_read = 0


@contextlib.contextmanager
def _wall_deadline(deadline: float) -> Iterator[None]:
    """Interrupt a blocking urllib operation at the collector's wall deadline."""
    if (
        threading.current_thread() is not threading.main_thread()
        or not hasattr(signal, "setitimer")
        or not hasattr(signal, "SIGALRM")
    ):
        raise CollectionFailure("deadline", "exact deadline requires POSIX main-thread collection")
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    started = time.monotonic()

    def expired(_signum: int, _frame: Any) -> None:
        raise CollectionFailure("deadline", "collector wall-clock limit exceeded")

    signal.signal(signal.SIGALRM, expired)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        signal.signal(signal.SIGALRM, previous_handler)
        raise CollectionFailure("deadline", "collector wall-clock limit exceeded")
    signal.setitimer(signal.ITIMER_REAL, remaining)
    try:
        yield
    finally:
        # Account for time spent under our guard so nested operations cannot
        # postpone a timer installed by the caller.
        elapsed = time.monotonic() - started
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0]:
            signal.setitimer(
                signal.ITIMER_REAL,
                max(0.000001, previous_timer[0] - elapsed),
                previous_timer[1],
            )


def _open_dir_chain(path: Path, *, create: bool) -> int:
    """Walk/create an absolute directory using pinned directory descriptors only."""
    if ".." in path.parts:
        raise protocol.CorpusV2Error("output path may not contain parent traversal")
    absolute = path.absolute()
    parts = absolute.parts
    if ".." in parts:
        raise protocol.CorpusV2Error("output path may not contain parent traversal")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    current = os.open("/", flags)
    try:
        for part in parts[1:]:
            try:
                child = os.open(part, flags, dir_fd=current)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, 0o700, dir_fd=current)
                child = os.open(part, flags, dir_fd=current)
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _publish(dirfd: int, name: str, body: bytes) -> None:
    temp_name = f".raw-diff-{os.getpid()}-{time.monotonic_ns()}"
    fd = os.open(
        temp_name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=dirfd,
    )
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(body)
            out.flush()
            os.fsync(out.fileno())
        os.link(temp_name, name, src_dir_fd=dirfd, dst_dir_fd=dirfd, follow_symlinks=False)
        os.fsync(dirfd)
    except FileExistsError as exc:
        raise protocol.CorpusV2Error(f"refusing to overwrite existing cache entry: {name}") from exc
    finally:
        os.unlink(temp_name, dir_fd=dirfd)


def _read_blob(dirfd: int, name: str, expected_size: int, expected_hash: str) -> None:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dirfd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size != expected_size:
            raise protocol.CorpusV2Error("content-addressed cache collision")
        digest = hashlib.sha256()
        remaining = expected_size + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            remaining -= len(chunk)
            digest.update(chunk)
        if remaining == 0 or digest.hexdigest() != expected_hash:
            raise protocol.CorpusV2Error("content-addressed cache collision")
    finally:
        os.close(fd)


def _has_fixed_length_framing(response: Any, expected_size: int) -> bool:
    if type(response) is not http.client.HTTPResponse:
        return False
    lengths = response.headers.get_all("Content-Length", [])
    transfers = response.headers.get_all("Transfer-Encoding", [])
    return (
        len(lengths) == 1
        and len(lengths[0]) <= len(str(MAX_ROW_BYTES))
        and lengths[0].isascii()
        and lengths[0].isdecimal()
        and int(lengths[0]) == expected_size
        and not transfers
        and response.chunked is False
        and type(response.length) is int
        and response.length == expected_size
    )


def _completed_fixed_length_response(response: Any, framed: bool) -> bool:
    return framed and response.length == 0 and response.fp is None


def _read_response_chunk(response: Any, room: int, body: bytearray) -> bytes:
    try:
        return cast("bytes", response.read(min(64 * 1024, room)))
    except http.client.IncompleteRead as exc:
        body.extend(exc.partial)
        raise CollectionFailure(
            "size_mismatch", "diff response ended before its declared length"
        ) from exc


def _requires_unavailable_framing(
    response: Any, byte_budget: int, expected_size: int, framed: bool
) -> bool:
    return (
        type(response) is http.client.HTTPResponse and byte_budget == expected_size and not framed
    )


def _verify_budget_boundary(
    response: Any, body_size: int, expected_size: int, byte_budget: int, framed: bool
) -> None:
    if (
        body_size == expected_size
        and byte_budget == expected_size
        and not _completed_fixed_length_response(response, framed)
    ):
        raise CollectionFailure(
            "aggregate_budget", "aggregate budget prevents verifying response EOF"
        )


def _fetch(
    url: str,
    repository: str,
    number: int,
    expected_size: int,
    deadline: float,
    byte_budget: int,
) -> tuple[bytes, str]:
    redirects = protocol._SafeDiffRedirects(repository, number)
    opener = urllib.request.build_opener(redirects)
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github.v3.diff",
            "User-Agent": "fastapi-endpoint-detector-locked-diff-v2/1",
        },
    )
    body = bytearray()
    try:
        with _wall_deadline(deadline):
            response_context = opener.open(
                request, timeout=max(0.1, min(20, deadline - time.monotonic()))
            )
        with _wall_deadline(deadline), response_context as response:
            final_url = response.geturl()
            redirects._validate(final_url)
            kind = response.headers.get("Content-Type", "")
            if not (kind.startswith("text/plain") or kind.startswith("text/x-diff")):
                raise CollectionFailure("invalid_resource", "invalid diff content type")
            framed = _has_fixed_length_framing(response, expected_size)
            if _requires_unavailable_framing(response, byte_budget, expected_size, framed):
                raise CollectionFailure(
                    "aggregate_budget",
                    "aggregate budget requires unambiguous fixed-length framing",
                )
            while True:
                room = min(
                    byte_budget - len(body),
                    expected_size + 1 - len(body),
                    MAX_ROW_BYTES + 1 - len(body),
                )
                if room <= 0:
                    _verify_budget_boundary(response, len(body), expected_size, byte_budget, framed)
                    break
                chunk = _read_response_chunk(response, room, body)
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) >= byte_budget and len(body) != expected_size:
                    raise CollectionFailure("aggregate_limit", "aggregate byte ceiling exhausted")
                if len(body) > min(expected_size, MAX_ROW_BYTES):
                    raise CollectionFailure(
                        "size_mismatch", "diff exceeded locked/task byte ceiling"
                    )
    except urllib.error.HTTPError as exc:
        # The error body is deliberately not collected or included in `bytes`.
        # Close it without reading so it cannot escape the request budget.
        with contextlib.suppress(OSError):
            exc.close()
        raise
    except CollectionFailure as exc:
        exc.bytes_read = len(body)
        raise
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        failure = CollectionFailure("request_error", f"diff request failed: {exc}")
        failure.bytes_read = len(body)
        raise failure from exc
    if len(body) != expected_size:
        failure = CollectionFailure(
            "size_mismatch", f"size_mismatch: expected {expected_size} bytes, received {len(body)}"
        )
        failure.bytes_read = len(body)
        raise failure
    return bytes(body), final_url


def _validate_rows(rows: list[dict[str, Any]]) -> None:
    if len(rows) != 50:
        raise protocol.CorpusV2Error("locked repository must contain exactly 50 rows")
    seen_numbers: set[int] = set()
    seen_urls: set[str] = set()
    for row in rows:
        number, url = row.get("pr"), row.get("diff_final_url")
        if not protocol._is_int(number) or not isinstance(url, str):
            raise protocol.CorpusV2Error("malformed locked PR identity")
        canonical = f"https://github.com/{REPOSITORY}/pull/{number}.diff"
        patch = f"https://patch-diff.githubusercontent.com/raw/{REPOSITORY}/pull/{number}.diff"
        if number in seen_numbers or url in seen_urls:
            raise protocol.CorpusV2Error("duplicate PR or diff URL in selected lock rows")
        if url not in {canonical, patch}:
            raise protocol.CorpusV2Error("invalid locked diff URL")
        if (
            not protocol._is_int(row.get("diff_bytes"))
            or not 0 <= row["diff_bytes"] <= MAX_ROW_BYTES
        ):
            raise protocol.CorpusV2Error("invalid locked diff size")
        if (
            not isinstance(row.get("diff_sha256"), str)
            or protocol._DIGEST.fullmatch(row["diff_sha256"]) is None
        ):
            raise protocol.CorpusV2Error("invalid locked diff digest")
        seen_numbers.add(number)
        seen_urls.add(url)


def _store_verified(cache_fd: int, body: bytes, expected_hash: str) -> str:
    digest = hashlib.sha256(body).hexdigest()
    if digest != expected_hash:
        failure = CollectionFailure("hash_mismatch", f"hash_mismatch: received SHA-256 {digest}")
        failure.bytes_read = len(body)
        raise failure
    try:
        _read_blob(cache_fd, digest, len(body), digest)
    except FileNotFoundError:
        try:
            _publish(cache_fd, digest, body)
        except protocol.CorpusV2Error as exc:
            raise CollectionFailure(
                "local_storage_error", "content-addressed cache publication failed"
            ) from exc
    except protocol.CorpusV2Error as exc:
        raise CollectionFailure("local_storage_error", "content-addressed cache collision") from exc
    except OSError as exc:
        raise CollectionFailure(
            "local_storage_error", "content-addressed cache I/O failed"
        ) from exc
    return digest


def collect(  # noqa: PLR0912, PLR0915
    output: Path,
    *,
    lock_path: Path = LOCK,
    manifest_path: Path = MANIFEST,
    checksums_path: Path = CHECKSUMS,
) -> dict[str, Any]:
    # Capture each input once. All authentication and selection below is over these
    # immutable byte strings; no validator reopens an input path.
    raw_lock = protocol._read_bounded(lock_path)
    raw_manifest = protocol._read_bounded(manifest_path)
    raw_checksums = protocol._read_bounded(checksums_path)
    actual_lock_hash = hashlib.sha256(raw_lock).hexdigest()
    if actual_lock_hash != LOCK_SHA256:
        raise protocol.CorpusV2Error("captured lock snapshot hash mismatch")
    if hashlib.sha256(raw_manifest).hexdigest() != MANIFEST_SHA256:
        raise protocol.CorpusV2Error("captured manifest snapshot hash mismatch")
    if hashlib.sha256(raw_checksums).hexdigest() != CHECKSUMS_SHA256:
        raise protocol.CorpusV2Error("captured checksum snapshot hash mismatch")

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON value: {value}")

    try:
        manifest = json.loads(
            raw_manifest,
            object_pairs_hook=protocol._unique_object,
            parse_constant=reject_constant,
        )
        checksums = json.loads(
            raw_checksums,
            object_pairs_hook=protocol._unique_object,
            parse_constant=reject_constant,
        )
        lock = json.loads(
            raw_lock,
            object_pairs_hook=protocol._unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise protocol.CorpusV2Error("captured authentication JSON is malformed") from exc
    if not all(isinstance(value, dict) for value in (manifest, checksums, lock)):
        raise protocol.CorpusV2Error("captured authentication roots must be objects")
    protocol.validate_manifest(manifest)
    expected_profile = {
        "schema_version": 2,
        "id": "oss-expansion-50x50-checksums-v2",
        "manifest_hash": f"sha256:{MANIFEST_SHA256}",
        "collector_hash": protocol.collector_hash(),
        "lock_hash": f"sha256:{LOCK_SHA256}",
    }
    if checksums != expected_profile:
        raise protocol.CorpusV2Error("captured checksum profile identity mismatch")
    protocol.validate_lock(lock, manifest, f"sha256:{MANIFEST_SHA256}")
    project = next((p for p in lock["projects"] if p["repository"] == REPOSITORY), None)
    if project is None:
        raise protocol.CorpusV2Error("locked repository is absent")
    rows = project["records"]
    _validate_rows(rows)
    rootfd = _open_dir_chain(output, create=True)
    deadline = time.monotonic() + MAX_SECONDS
    statuses: list[dict[str, Any]] = []
    total = 0
    try:
        with contextlib.suppress(FileExistsError):
            os.mkdir("blobs", 0o700, dir_fd=rootfd)
        cachefd = os.open("blobs", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=rootfd)
    except OSError as exc:
        os.close(rootfd)
        raise protocol.CorpusV2Error("blob directory must be a real directory") from exc
    for row in rows:
        expected_hash = row["diff_sha256"].removeprefix("sha256:")
        entry: dict[str, Any] = {
            "pr": row["pr"],
            "url": row["diff_final_url"],
            "expected_sha256": expected_hash,
            "expected_bytes": row["diff_bytes"],
        }
        fetched = False
        try:
            if time.monotonic() >= deadline:
                raise CollectionFailure("deadline", "collector wall-clock limit exceeded")
            remaining = MAX_TOTAL_BYTES - total
            if remaining <= 0:
                raise CollectionFailure("aggregate_limit", "aggregate byte ceiling exhausted")
            body, final_url = _fetch(
                row["diff_final_url"],
                REPOSITORY,
                row["pr"],
                row["diff_bytes"],
                deadline,
                remaining,
            )
            fetched = True
            total += len(body)
            digest = _store_verified(cachefd, body, expected_hash)
            entry.update(
                {
                    "status": "matched",
                    "sha256": digest,
                    "bytes": len(body),
                    "final_url": final_url,
                    "blob": f"blobs/{digest}",
                }
            )
        except Exception as exc:  # retain one explicit status for every frozen row
            if not fetched:
                total += getattr(exc, "bytes_read", 0)
            classification = (
                "http_error"
                if isinstance(exc, urllib.error.HTTPError)
                else exc.failure_class
                if isinstance(exc, CollectionFailure)
                else (
                    "local_storage_error"
                    if isinstance(exc, OSError)
                    else "request_error"
                    if isinstance(exc, (urllib.error.URLError, TimeoutError))
                    else "validation_error"
                    if isinstance(exc, protocol.CorpusV2Error)
                    else "collector_error"
                )
            )
            entry.update(
                {
                    "status": "missing"
                    if classification
                    in {
                        "request_error",
                        "http_error",
                        "local_storage_error",
                        "aggregate_budget",
                        "aggregate_limit",
                        "deadline",
                    }
                    else "mismatch",
                    "failure_class": classification,
                    **(
                        {"http_status": exc.code} if isinstance(exc, urllib.error.HTTPError) else {}
                    ),
                    "failure": str(exc)[:240],
                }
            )
        statuses.append(entry)
    receipt = {
        "schema": SCHEMA,
        "lock_sha256": actual_lock_hash,
        "repository": REPOSITORY,
        "rows": statuses,
        "summary": {
            "rows": len(statuses),
            "matched": sum(r["status"] == "matched" for r in statuses),
            "missing": sum(r["status"] == "missing" for r in statuses),
            "mismatch": sum(r["status"] == "mismatch" for r in statuses),
            "bytes": total,
        },
    }
    try:
        _publish(
            rootfd,
            "receipts.json",
            (json.dumps(receipt, sort_keys=True, indent=2, allow_nan=False) + "\n").encode(),
        )
    finally:
        os.close(cachefd)
        os.close(rootfd)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = collect(args.output)
    print(json.dumps(result["summary"], sort_keys=True))
    return 0 if result["summary"]["matched"] == 50 else 2


if __name__ == "__main__":
    raise SystemExit(main())
