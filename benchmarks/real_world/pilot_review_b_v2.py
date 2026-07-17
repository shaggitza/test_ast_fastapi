#!/usr/bin/env python3
"""Capture one isolated parent Review B interval with exact private telemetry."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import math
import os
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from itertools import pairwise
from pathlib import Path, PurePosixPath
from typing import Any, Final, NoReturn

from benchmarks.real_world import pilot_run_v2
from benchmarks.real_world.ground_truth_v2.schema import ReviewArtifactV1, parse_artifact

_MAX_SESSION_BYTES: Final = 256 * 1024 * 1024
_MAX_INTERVAL_BYTES: Final = 32 * 1024 * 1024
_MAX_SAMPLES_BYTES: Final = 8 * 1024 * 1024
_MAX_FILES: Final = 400_000
_MAX_DISK_BYTES: Final = 16 * 1024 * 1024 * 1024
_MAX_INTERVAL_SECONDS: Final = 1800
_MAX_TOKENS: Final = 100_000
_MAX_TOOLS: Final = 200
_MAX_ARTIFACT_BYTES: Final = 2_097_152
_SAMPLE_TOLERANCE_MS: Final = 1500
_ALLOWED_READ_TOOLS = {"read", "grep", "find", "ls"}
_ALLOWED_TOOLS = _ALLOWED_READ_TOOLS | {"bash"}
_FORBIDDEN_TERMS = (
    "subagent",
    "intercom",
    "supervisor decision",
    "prediction",
    "route_census",
    "route census",
    "prior label",
    "review_a",
    "review a",
    "adjudication",
    "firecrawl",
    "http://",
    "https://",
)
_TOOL_SCHEMAS: dict[str, tuple[set[str], set[str]]] = {
    "read": ({"path"}, {"path", "offset", "limit"}),
    "grep": (
        {"pattern", "path"},
        {"pattern", "path", "glob", "ignoreCase", "literal", "context", "limit"},
    ),
    "find": ({"pattern", "path"}, {"pattern", "path", "limit"}),
    "ls": ({"path"}, {"path", "limit"}),
    "bash": ({"command"}, {"command"}),
}
_SAMPLERS: dict[int, subprocess.Popen[bytes]] = {}
_TELEMETRY_KEYS = {
    "attempt_id",
    "repository",
    "pr",
    "role",
    "source_kind",
    "provider",
    "model",
    "model_version",
    "client_version",
    "started_at",
    "completed_at",
    "wall_milliseconds",
    "input_tokens",
    "output_tokens",
    "cached_input_tokens",
    "tool_calls",
    "input_bytes",
    "output_bytes",
    "sampled_peak_process_tree_rss_bytes",
    "rss_sampling_interval_milliseconds",
    "disk_scope",
    "disk_bytes_before",
    "disk_bytes_after",
    "is_retry",
    "retry_of_attempt_id",
    "succeeded",
    "failure_kind",
    "status_sha256",
    "events_sha256",
    "supervisor_interval_sha256",
    "start_event_id",
    "end_event_id",
    "start_message_id",
    "end_message_id",
    "transcript_sha256",
    "artifact_sha256",
    "cost_micro_usd",
    "unavailable_reason",
}


class PilotReviewBError(ValueError):
    """Raised when a Review B interval cannot be proved isolated and complete."""


def _fail(message: str) -> NoReturn:
    raise PilotReviewBError(message)


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical(value: object) -> bytes:
    if isinstance(value, float):
        _fail("floats are forbidden in canonical private artifacts")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                _fail("canonical keys must be strings")
            _canonical(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _canonical(item)
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    _fail(f"non-finite JSON constant: {value}")


def _json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=_unique, parse_constant=_reject_constant)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, MemoryError) as exc:
        raise PilotReviewBError(f"invalid JSON: {label}") from exc
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    return value


def _reject_symlink_ancestors(path: Path) -> None:
    absolute = path.expanduser().absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            status = current.lstat()
        except FileNotFoundError:
            break
        except OSError as exc:
            raise PilotReviewBError("cannot inspect path ancestry") from exc
        if stat.S_ISLNK(status.st_mode):
            _fail("path ancestry contains a symbolic component")


def _read(path: Path, limit: int) -> bytes:
    _reject_symlink_ancestors(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PilotReviewBError(f"cannot safely read {path}") from exc
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_uid != os.getuid():
            _fail("private file is not an owned regular file")
        raw = os.read(descriptor, limit + 1)
    finally:
        os.close(descriptor)
    if len(raw) > limit:
        _fail(f"{path.name} exceeds byte limit")
    return raw


def _atomic(path: Path, raw: bytes, *, mode: int = 0o600) -> None:
    _private_directory(path.parent)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as exc:
            raise PilotReviewBError(f"refusing to overwrite {path}") from exc
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _owned_directory(path: Path) -> Path:
    _reject_symlink_ancestors(path)
    try:
        resolved = path.resolve(strict=True)
        status = path.lstat()
    except OSError as exc:
        raise PilotReviewBError("owned directory is missing") from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(status.st_mode)
        or status.st_uid != os.getuid()
        or stat.S_IMODE(status.st_mode) & 0o022
    ):
        _fail("owned directory is unsafe or group/world writable")
    return resolved


def _private_directory(path: Path) -> Path:
    _reject_symlink_ancestors(path)
    try:
        resolved = path.resolve(strict=True)
        status = path.lstat()
    except OSError as exc:
        raise PilotReviewBError("private directory is missing") from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(status.st_mode)
        or status.st_uid != os.getuid()
        or stat.S_IMODE(status.st_mode) != 0o700
    ):
        _fail("private directory must be owned mode 0700 without symlinks")
    return resolved


def _relative_child(path: Path, root: Path, *, strict: bool) -> Path:
    _reject_symlink_ancestors(root)
    _reject_symlink_ancestors(path)
    if ".." in PurePosixPath(path.as_posix()).parts:
        _fail("path contains parent traversal")
    root_resolved = _owned_directory(root)
    try:
        lexical = path.absolute().relative_to(root.absolute())
    except ValueError as exc:
        raise PilotReviewBError("path is outside assigned root") from exc
    current = root.absolute()
    for part in lexical.parts:
        current = current / part
        if current.exists() and current.is_symlink():
            _fail("assigned path contains a symbolic component")
    try:
        resolved = path.resolve(strict=strict)
        resolved.relative_to(root_resolved)
    except (OSError, ValueError) as exc:
        raise PilotReviewBError("path is outside assigned root") from exc
    return resolved


def _open_lock(path: Path) -> int:
    _reject_symlink_ancestors(path)
    _private_directory(path.parent)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise PilotReviewBError("cannot safely open private lock") from exc
    status = os.fstat(descriptor)
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_uid != os.getuid()
        or stat.S_IMODE(status.st_mode) != 0o600
    ):
        os.close(descriptor)
        _fail("private lock is not an owned mode-0600 regular file")
    return descriptor


def _allocated(root: Path) -> int:
    _owned_directory(root)
    total = 0
    count = 0
    stack = [root]
    while stack:
        path = stack.pop()
        status = path.lstat()
        count += 1
        if count > _MAX_FILES or stat.S_ISLNK(status.st_mode):
            _fail("disk scope contains excessive or symbolic entries")
        total += status.st_blocks * 512
        if total > _MAX_DISK_BYTES:
            _fail("disk scope exceeds bound")
        if stat.S_ISDIR(status.st_mode):
            stack.extend(path / entry.name for entry in os.scandir(path))
        elif not stat.S_ISREG(status.st_mode):
            _fail("disk scope contains special entry")
    return total


def _disk_scope(execution_root: Path, packet_root: Path, interval_root: Path) -> dict[str, int]:
    return {
        "execution_root": _allocated(execution_root),
        "packet_root": _allocated(packet_root),
        "interval_root": _allocated(interval_root),
    }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _proc_fields(pid: int) -> list[str]:
    try:
        raw = (Path("/proc") / str(pid) / "stat").read_text(encoding="utf-8")
    except OSError as exc:
        raise PilotReviewBError("process identity is unavailable") from exc
    close = raw.rfind(")")
    if close < 0:
        _fail("malformed proc stat")
    fields = raw[close + 2 :].split()
    if len(fields) < 20:
        _fail("malformed proc stat fields")
    return fields


def _proc_starttime(pid: int) -> int:
    try:
        value = int(_proc_fields(pid)[19])
    except ValueError as exc:
        raise PilotReviewBError("malformed proc start time") from exc
    if value <= 0:
        _fail("process start time is invalid")
    return value


def _owned_process(pid: int, expected_starttime: int | None = None) -> int:
    if pid <= 1:
        _fail("supervisor pid is invalid")
    try:
        status = (Path("/proc") / str(pid)).stat()
    except OSError as exc:
        raise PilotReviewBError("supervisor pid does not exist") from exc
    if status.st_uid != os.getuid():
        _fail("supervisor pid has wrong owner")
    starttime = _proc_starttime(pid)
    if expected_starttime is not None and starttime != expected_starttime:
        _fail("process PID was reused or start time changed")
    return starttime


def _is_ancestor(ancestor: int, descendant: int) -> bool:
    seen: set[int] = set()
    current = descendant
    while current > 1 and current not in seen:
        seen.add(current)
        if current == ancestor:
            return True
        current = _stat_parent((Path("/proc") / str(current) / "stat").read_text())
    return current == ancestor


def _declared_supervisor(pid: int) -> int:
    starttime = _owned_process(pid)
    if not _is_ancestor(pid, os.getpid()):
        _fail("declared supervisor PID is not an ancestor of the start CLI")
    try:
        command = (Path("/proc") / str(pid) / "cmdline").read_bytes().replace(b"\0", b" ")
    except OSError as exc:
        raise PilotReviewBError("cannot inspect declared supervisor command") from exc
    if re.search(rb"(?:^|/)pi(?:\s|$)", command) is None:
        _fail("declared supervisor PID is not the parent Pi process")
    return starttime


def _stat_parent(raw: str) -> int:
    close = raw.rfind(")")
    if close < 0:
        _fail("malformed proc stat")
    fields = raw[close + 2 :].split()
    if len(fields) < 2:
        _fail("malformed proc stat fields")
    try:
        return int(fields[1])
    except ValueError as exc:
        raise PilotReviewBError("malformed proc parent pid") from exc


def _process_tree(root: int) -> set[int]:
    parents: dict[int, int] = {}
    for item in Path("/proc").iterdir():
        if not item.name.isdigit():
            continue
        try:
            parents[int(item.name)] = _stat_parent((item / "stat").read_text(encoding="utf-8"))
        except (OSError, PilotReviewBError):
            continue
    selected = {root}
    changed = True
    while changed:
        changed = False
        for pid, parent in parents.items():
            if parent in selected and pid not in selected:
                selected.add(pid)
                changed = True
    return selected


def _rss(root: int) -> tuple[int, int]:
    total = 0
    count = 0
    for pid in _process_tree(root):
        try:
            for line in (Path("/proc") / str(pid) / "status").read_text().splitlines():
                if line.startswith("VmRSS:"):
                    value = int(line.split()[1])
                    if value < 0:
                        _fail("negative process RSS")
                    total += value * 1024
                    count += 1
                    break
        except (OSError, ValueError, IndexError):
            continue
    return total, count


def _write_rss_sample(handle: Any, supervisor_pid: int, supervisor_starttime: int) -> None:
    _owned_process(supervisor_pid, supervisor_starttime)
    resident, processes = _rss(supervisor_pid)
    if processes < 1:
        _fail("sampler observed no supervisor process")
    handle.write(
        _canonical(
            {
                "monotonic_ns": time.monotonic_ns(),
                "process_count": processes,
                "rss_bytes": resident,
                "unix_ms": time.time_ns() // 1_000_000,
            }
        )
    )
    handle.flush()
    os.fsync(handle.fileno())


def sample(
    samples: Path, stop: Path, ready: Path, supervisor_pid: int, supervisor_starttime: int
) -> int:
    """Private sampler subprocess entrypoint."""
    _owned_process(supervisor_pid, supervisor_starttime)
    _private_directory(samples.parent)
    with samples.open("xb") as handle:
        samples.chmod(0o600)
        started = time.monotonic()
        _write_rss_sample(handle, supervisor_pid, supervisor_starttime)
        _atomic(ready, b"ready\n")
        while time.monotonic() - started <= _MAX_INTERVAL_SECONDS:
            if stop.exists():
                # Stop is published only after finish records its end boundary. Always
                # take one final post-stop sample so coverage cannot race the poll.
                _write_rss_sample(handle, supervisor_pid, supervisor_starttime)
                break
            time.sleep(1)
            _write_rss_sample(handle, supervisor_pid, supervisor_starttime)
        else:
            _fail("Review B sampler exceeded wall-clock bound")
    return 0


def _manifest(
    manifest_path: Path, agent_config: Path, cache_root: Path, packet_root: Path
) -> tuple[dict[str, Any], str]:
    return pilot_run_v2._manifest(manifest_path, agent_config, cache_root, packet_root)


def _clean_state(
    manifest: dict[str, Any],
    manifest_path: Path,
    agent: Path,
    cache: Path,
    packet: Path,
    repository: str,
    pr: int,
) -> None:
    ledger = Path(str(manifest["custody_ledger_path"]))
    events = pilot_run_v2.validate_ledger(ledger, manifest_path, agent, cache, packet)
    if any(event["event"] == "incident" for event in events):
        _fail("custody contains no-go incident")
    stream = [
        event
        for event in events
        if str(event["repository"]).casefold() == repository.casefold() and int(event["pr"]) == pr
    ]
    if [event["event"] for event in stream] != ["source_binding_frozen", "review_a_started"]:
        _fail("Review B interval requires A-started/B-unfrozen custody state")


def _binding(manifest: dict[str, Any], repository: str, pr: int) -> dict[str, Any]:
    matches = [
        dict(item)
        for item in manifest["source_bindings"]
        if str(item["repository"]).casefold() == repository.casefold() and int(item["pr"]) == pr
    ]
    if len(matches) != 1:
        _fail("assigned PR is outside execution manifest")
    return matches[0]


def _session_snapshot(path: Path, expected: Path) -> tuple[bytes, os.stat_result]:
    _reject_symlink_ancestors(path)
    resolved = path.resolve(strict=True)
    if resolved != expected:
        _fail("supervisor session resolved path differs from manifest")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PilotReviewBError("cannot open supervisor session safely") from exc
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_uid != os.getuid():
            _fail("supervisor session is not an owned regular file")
        raw = os.read(descriptor, _MAX_SESSION_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > _MAX_SESSION_BYTES or (raw and not raw.endswith(b"\n")):
        _fail("supervisor session is oversized or incomplete")
    return raw, status


def _last_start_call(raw: bytes, expected: list[str]) -> str:
    if not raw:
        _fail("supervisor session is empty at start boundary")
    lines = raw.splitlines()
    item = _json(lines[-1] + b"\n", "start boundary message")
    message = item.get("message")
    if not isinstance(message, dict) or message.get("role") != "assistant":
        _fail("start boundary lacks assistant message")
    call_id = _single_exact_tool_call(message, expected)
    if call_id is None:
        _fail("start boundary must be the exact sole canonical start command")
    return call_id


def _verify_session_append(raw: bytes, status: os.stat_result, marker: dict[str, Any]) -> None:
    prefix_size = _strict_int(marker.get("session_prefix_bytes"), "session prefix size")
    if (
        status.st_dev != marker.get("session_device")
        or status.st_ino != marker.get("session_inode")
        or len(raw) < prefix_size
        or _sha(raw[:prefix_size]) != marker.get("session_prefix_sha256")
    ):
        _fail("supervisor session did not grow append-only from bound inode/prefix")


def _expected_start_tokens(
    manifest_path: Path,
    execution_root: Path,
    packet_root: Path,
    repository: str,
    pr: int,
    supervisor_session: Path,
    supervisor_pid: int,
    interval_root: Path,
    agent_config: Path,
    cache_root: Path,
) -> list[str]:
    return [
        sys.executable,
        "-m",
        "benchmarks.real_world.pilot_review_b_v2",
        "--start",
        "--manifest",
        str(manifest_path.resolve()),
        "--execution-root",
        str(execution_root.resolve()),
        "--packet-root",
        str(packet_root.resolve()),
        "--repository",
        repository,
        "--pr",
        str(pr),
        "--supervisor-session",
        str(supervisor_session.resolve()),
        "--supervisor-pid",
        str(supervisor_pid),
        "--interval-root",
        str(interval_root.resolve()),
        "--agent-config",
        str(agent_config.resolve()),
        "--cache-root",
        str(cache_root.resolve()),
    ]


def _expected_finish_tokens(
    manifest_path: Path,
    execution_root: Path,
    packet_root: Path,
    repository: str,
    pr: int,
    supervisor_session: Path,
    interval_root: Path,
    artifact: Path,
    agent_config: Path,
    cache_root: Path,
) -> list[str]:
    return [
        sys.executable,
        "-m",
        "benchmarks.real_world.pilot_review_b_v2",
        "--finish",
        "--manifest",
        str(manifest_path.resolve()),
        "--execution-root",
        str(execution_root.resolve()),
        "--packet-root",
        str(packet_root.resolve()),
        "--repository",
        repository,
        "--pr",
        str(pr),
        "--supervisor-session",
        str(supervisor_session.resolve()),
        "--interval-root",
        str(interval_root.resolve()),
        "--artifact",
        str(artifact.resolve()),
        "--agent-config",
        str(agent_config.resolve()),
        "--cache-root",
        str(cache_root.resolve()),
    ]


def start(
    manifest_path: Path,
    execution_root: Path,
    packet_root: Path,
    repository: str,
    pr: int,
    supervisor_session: Path,
    supervisor_pid: int,
    interval_root: Path,
    agent_config: Path,
    cache_root: Path,
) -> Path:
    manifest, _ = _manifest(manifest_path, agent_config, cache_root, packet_root)
    ledger = Path(str(manifest["custody_ledger_path"]))
    lock = _open_lock(ledger.with_suffix(ledger.suffix + ".lock"))
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return _start_locked(
            manifest_path,
            execution_root,
            packet_root,
            repository,
            pr,
            supervisor_session,
            supervisor_pid,
            interval_root,
            agent_config,
            cache_root,
        )
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)


def _start_locked(  # noqa: PLR0912,PLR0915 - fail-closed interval setup
    manifest_path: Path,
    execution_root: Path,
    packet_root: Path,
    repository: str,
    pr: int,
    supervisor_session: Path,
    supervisor_pid: int,
    interval_root: Path,
    agent_config: Path,
    cache_root: Path,
) -> Path:
    manifest, manifest_hash = _manifest(manifest_path, agent_config, cache_root, packet_root)
    execution = _private_directory(execution_root)
    if manifest_path.parent.resolve() != execution:
        _fail("execution root differs from manifest")
    _owned_directory(packet_root)
    expected_session = Path(
        str(manifest["review_b_measurement"]["supervisor_session_path"])
    ).resolve(strict=True)
    _reject_symlink_ancestors(supervisor_session)
    if supervisor_session.resolve(strict=True) != expected_session:
        _fail("supervisor session differs from manifest")
    supervisor_starttime = _declared_supervisor(supervisor_pid)
    binding = _binding(manifest, repository, pr)
    _clean_state(manifest, manifest_path, agent_config, cache_root, packet_root, repository, pr)
    if interval_root.exists():
        _private_directory(interval_root)
    else:
        if interval_root.parent.resolve(strict=True) != execution:
            _fail("interval root must be a direct execution child")
        interval_root.mkdir(mode=0o700)
    interval = _private_directory(interval_root)
    if interval.parent != execution:
        _fail("interval root must be a direct execution child")
    lock_path = interval_root / "interval.lock"
    descriptor = _open_lock(lock_path)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        active = interval_root / "active.json"
        if active.exists():
            _fail("another Review B interval is active or crashed")
        assigned = interval_root / f"{repository.replace('/', '--')}--{pr}"
        if assigned.exists():
            _fail("refusing to overwrite Review B interval")
        assigned.mkdir(mode=0o700)
        _private_directory(assigned)
        artifact = assigned / "review-b.json"
        session_raw, session_status = _session_snapshot(supervisor_session, expected_session)
        expected_start_tokens = _expected_start_tokens(
            manifest_path,
            execution_root,
            packet_root,
            repository,
            pr,
            supervisor_session,
            supervisor_pid,
            interval_root,
            agent_config,
            cache_root,
        )
        start_tool_call_id = _last_start_call(session_raw, expected_start_tokens)
        marker = {
            "schema_version": 1,
            "manifest_sha256": manifest_hash,
            "repository": binding["repository"],
            "pr": binding["pr"],
            "packet_path": next(
                item["packet_path"]
                for item in manifest["source_packet_hashes"]
                if str(item["repository"]).casefold() == repository.casefold()
                and int(item["pr"]) == pr
            ),
            "artifact_path": str(artifact.resolve()),
            "assigned_root": str(assigned.resolve()),
            "session_path": str(supervisor_session.resolve()),
            "session_device": session_status.st_dev,
            "session_inode": session_status.st_ino,
            "session_prefix_bytes": len(session_raw),
            "session_prefix_sha256": _sha(session_raw),
            "supervisor_pid": supervisor_pid,
            "supervisor_starttime": supervisor_starttime,
            "start_tool_call_id": start_tool_call_id,
            "expected_start_tokens": expected_start_tokens,
            "disk_before": _disk_scope(execution_root, packet_root, interval_root),
            "expected_finish_tokens": _expected_finish_tokens(
                manifest_path,
                execution_root,
                packet_root,
                repository,
                pr,
                supervisor_session,
                interval_root,
                artifact,
                agent_config,
                cache_root,
            ),
        }
        _atomic(assigned / "marker.json", _canonical(marker))
        samples = assigned / "rss-samples.jsonl"
        stop = assigned / "rss.stop"
        ready = assigned / "rss.ready"
        module_root = Path(__file__).resolve().parents[2]
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", ""),
            "PYTHONPATH": str(module_root),
            "LC_ALL": "C",
        }
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "benchmarks.real_world.pilot_review_b_v2",
                "--sample",
                str(samples),
                str(stop),
                str(ready),
                str(supervisor_pid),
                str(supervisor_starttime),
            ],
            cwd=module_root,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
        _SAMPLERS[process.pid] = process
        sampler_starttime = _proc_starttime(process.pid)
        deadline = time.monotonic() + 5
        while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        if not ready.exists() or process.poll() is not None:
            _fail("Review B sampler failed readiness handshake")
        boundary_raw, boundary_status = _session_snapshot(supervisor_session, expected_session)
        if (
            boundary_status.st_dev != session_status.st_dev
            or boundary_status.st_ino != session_status.st_ino
            or len(boundary_raw) < len(session_raw)
            or _sha(boundary_raw[: len(session_raw)]) != _sha(session_raw)
        ):
            _fail("supervisor session changed non-append-only during start")
        boundary = {
            "schema_version": 1,
            "session_offset": len(boundary_raw),
            "started_at": _utc_now(),
            "started_monotonic_ns": time.monotonic_ns(),
            "started_unix_ms": time.time_ns() // 1_000_000,
            "sampler_pid": process.pid,
            "sampler_starttime": sampler_starttime,
            "samples_path": str(samples.resolve()),
            "stop_path": str(stop.resolve()),
            "ready_path": str(ready.resolve()),
        }
        _atomic(assigned / "start-boundary.json", _canonical(boundary))
        _atomic(
            active,
            _canonical(
                {
                    "assigned_root": str(assigned.resolve()),
                    "marker_sha256": _sha(_canonical(marker)),
                    "boundary_sha256": _sha(_canonical(boundary)),
                }
            ),
        )
        return assigned
    except BaseException:
        if "process" in locals() and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
            _SAMPLERS.pop(process.pid, None)
        if "assigned" in locals() and assigned.exists():
            shutil.rmtree(assigned, ignore_errors=True)
        raise
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _flatten_strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for child in value.values() for item in _flatten_strings(child)]
    if isinstance(value, list):
        return [item for child in value for item in _flatten_strings(child)]
    return []


def _message_id(item: dict[str, Any]) -> str:
    identity = item.get("id")
    if not isinstance(identity, str) or not identity:
        _fail("session event/message id is missing")
    return identity


def _single_exact_tool_call(  # noqa: PLR0911 - fail-closed exact boundary parser
    message: dict[str, Any], expected: list[str]
) -> str | None:
    if message.get("role") != "assistant" or set(message) - {
        "role",
        "timestamp",
        "usage",
        "content",
        "api",
        "provider",
        "model",
        "stopReason",
        "responseId",
    }:
        return None
    content = message.get("content")
    if not isinstance(content, list) or len(content) != 1:
        return None
    part = content[0]
    if not isinstance(part, dict) or set(part) != {"type", "id", "name", "arguments"}:
        return None
    if part.get("type") != "toolCall" or part.get("name") != "bash":
        return None
    call_id = part.get("id")
    arguments = part.get("arguments")
    if not isinstance(call_id, str) or not call_id or not isinstance(arguments, dict):
        return None
    if set(arguments) != {"command"}:
        return None
    command = arguments.get("command")
    if not isinstance(command, str) or "\n" in command:
        return None
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return None
    return call_id if tokens == expected else None


def _finish_call(message: dict[str, Any], expected: list[str]) -> bool:
    return _single_exact_tool_call(message, expected) is not None


def _safe_artifact_command(command: str, artifact: str) -> None:
    first = command.splitlines()[0] if command.splitlines() else ""
    accepted = {
        f"cat > {artifact} <<'EOF'",
        f"cat > \"{artifact}\" <<'EOF'",
        f"cat > '{artifact}' <<'EOF'",
    }
    if (
        first not in accepted
        or not command.endswith("\nEOF")
        or command.splitlines().count("EOF") != 1
    ):
        _fail("Review B artifact command is not an exact no-network heredoc write")


def _contains_other_identity(text: str, repository: str, pr: int) -> bool:
    folded = text.casefold()
    if repository.casefold() in folded:
        return True
    number = re.escape(str(pr))
    patterns = (
        rf"(?<![\w/])#\s*{number}(?!\d)",
        rf"\bpr\s*#?\s*{number}(?!\d)",
        rf"\bpull\s+request\s*#?\s*{number}(?!\d)",
        rf"/pull/{number}(?!\d)",
        rf"--{number}(?!\d)",
        rf"[\"\'](?:pr|number)[\"\']\s*:\s*{number}(?!\d)",
    )
    return any(re.search(pattern, folded, flags=re.IGNORECASE) for pattern in patterns)


def _argument_path(tool: str, arguments: dict[str, Any]) -> Path | None:
    if tool in {"read", "grep", "find", "ls"}:
        value = arguments.get("path")
        if not isinstance(value, str) or not value:
            _fail("read-only tool path is invalid")
        return Path(value)
    return None


def _validate_tool_arguments(tool: str, arguments: object) -> dict[str, Any]:
    if not isinstance(arguments, dict):
        _fail("tool arguments must be an object")
    required, allowed = _TOOL_SCHEMAS[tool]
    if not required <= set(arguments) or not set(arguments) <= allowed:
        _fail("tool arguments do not match the exact schema")
    string_keys = {
        "read": {"path"},
        "grep": {"pattern", "path", "glob"},
        "find": {"pattern", "path"},
        "ls": {"path"},
        "bash": {"command"},
    }[tool]
    for key in string_keys & set(arguments):
        if not isinstance(arguments[key], str) or not arguments[key]:
            _fail("tool string argument is invalid")
    for key in {"offset", "limit", "context"} & set(arguments):
        value = arguments[key]
        minimum = 0 if key == "context" else 1
        if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
            _fail("tool numeric argument is invalid")
    for key in {"ignoreCase", "literal"} & set(arguments):
        if not isinstance(arguments[key], bool):
            _fail("tool boolean argument is invalid")
    return arguments


def _successful_tool_results(  # noqa: PLR0912 - strict tool lifecycle automaton
    objects: list[dict[str, Any]], start_call_id: str
) -> None:
    first = objects[0].get("message") if objects else None
    if (
        not isinstance(first, dict)
        or first.get("role") != "toolResult"
        or first.get("toolCallId") != start_call_id
        or first.get("toolName") != "bash"
        or first.get("isError") is not False
    ):
        _fail("interval must begin with the successful exact start toolResult")
    objects.pop(0)
    if (
        objects
        and isinstance(objects[0].get("message"), dict)
        and objects[0]["message"].get("role") == "toolResult"
    ):
        _fail("interval has multiple leading tool results")
    pending: dict[str, str] = {}
    seen: set[str] = {start_call_id}
    for item in objects:
        message = item.get("message")
        if not isinstance(message, dict):
            _fail("interval message is invalid")
        role = message.get("role")
        if role == "assistant":
            if pending:
                _fail("assistant message arrived before prior tool results")
            content = message.get("content")
            if not isinstance(content, list):
                _fail("assistant content is invalid")
            for part in content:
                if not isinstance(part, dict) or part.get("type") != "toolCall":
                    continue
                call_id = part.get("id")
                name = part.get("name")
                if not isinstance(call_id, str) or not call_id or call_id in seen:
                    _fail("tool call id is missing or duplicate")
                if not isinstance(name, str):
                    _fail("tool call name is invalid")
                seen.add(call_id)
                pending[call_id] = name
        elif role == "toolResult":
            call_id = message.get("toolCallId")
            if not isinstance(call_id, str) or call_id not in pending:
                _fail("toolResult does not match a pending toolCall")
            if message.get("toolName") != pending[call_id] or message.get("isError") is not False:
                _fail("toolResult is missing, mismatched, or failed")
            del pending[call_id]
        else:
            _fail("Review B interval contains a forbidden message role")
    if pending:
        _fail("Review B interval ended before all tool results")


def _interval(  # noqa: PLR0912,PLR0915
    raw: bytes, marker: dict[str, Any], boundary: dict[str, Any], manifest: dict[str, Any]
) -> tuple[bytes, list[dict[str, Any]]]:
    offset = boundary.get("session_offset")
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0 or offset > len(raw):
        _fail("session offset is invalid")
    suffix = raw[offset:]
    if len(suffix) > _MAX_INTERVAL_BYTES or not suffix or not suffix.endswith(b"\n"):
        _fail("session interval is empty, oversized, or incomplete")
    lines = suffix.splitlines(keepends=True)
    finish_indexes: list[int] = []
    parsed: list[dict[str, Any]] = []
    ids: set[str] = set()
    expected = marker.get("expected_finish_tokens")
    if not isinstance(expected, list) or not all(isinstance(item, str) for item in expected):
        _fail("expected finish command is invalid")
    for index, line in enumerate(lines):
        item = _json(line, "session interval line")
        identity = _message_id(item)
        if identity in ids:
            _fail("duplicate session event/message id")
        ids.add(identity)
        parsed.append(item)
        message = item.get("message")
        if (
            isinstance(message, dict)
            and message.get("role") == "assistant"
            and _finish_call(message, expected)
        ):
            finish_indexes.append(index)
    if len(finish_indexes) != 1 or finish_indexes[0] != len(lines) - 1:
        _fail("exact finish boundary must occur uniquely at session end")
    retained_lines = lines[: finish_indexes[0]]
    objects = parsed[: finish_indexes[0]]
    start_call_id = marker.get("start_tool_call_id")
    if not isinstance(start_call_id, str) or not start_call_id:
        _fail("start tool call identity is missing")
    _successful_tool_results(objects, start_call_id)
    retained_lines.pop(0)
    if not objects:
        _fail("Review B session interval has no isolated work")
    packet = Path(str(marker["packet_path"])).resolve(strict=True)
    artifact = Path(str(marker["artifact_path"])).resolve(strict=False)
    other = [
        (str(item["repository"]), int(item["pr"]))
        for item in manifest["source_bindings"]
        if not (
            str(item["repository"]).casefold() == str(marker["repository"]).casefold()
            and int(item["pr"]) == int(marker["pr"])
        )
    ]
    source_reads = writes = 0
    assistant_count = 0
    for item in objects:
        message = item.get("message")
        if not isinstance(message, dict) or message.get("role") not in {"assistant", "toolResult"}:
            _fail("Review B interval contains a forbidden message role")
        if message.get("role") != "assistant":
            continue
        assistant_count += 1
        all_text = "\n".join(_flatten_strings(message))
        folded = all_text.casefold()
        if any(term in folded for term in _FORBIDDEN_TERMS):
            _fail("Review B interval contains forbidden orchestration or benchmark material")
        if any(_contains_other_identity(all_text, repo, number) for repo, number in other):
            _fail("Review B interval references another pilot PR")
        content = message.get("content")
        if not isinstance(content, list):
            _fail("assistant content is invalid")
        for part in content:
            if not isinstance(part, dict) or part.get("type") != "toolCall":
                continue
            name = part.get("name")
            if not isinstance(name, str) or name not in _ALLOWED_TOOLS:
                _fail("Review B interval used forbidden tool")
            arguments = _validate_tool_arguments(name, part.get("arguments"))
            if name == "bash":
                command = arguments["command"]
                assert isinstance(command, str)
                _safe_artifact_command(command, str(artifact))
                writes += 1
            else:
                path = _argument_path(name, arguments)
                assert path is not None
                resolved = _relative_child(path, packet, strict=True)
                if resolved == packet:
                    _fail("source read must name a packet child")
                source_reads += 1
    if assistant_count < 1 or source_reads < 1 or writes != 1:
        _fail("Review B interval requires isolated source reads and exactly one artifact write")
    return b"".join(retained_lines), objects


def _strict_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        _fail(f"{label} must be a nonnegative integer")
    return value


def _provider_micro_usd(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail(f"{label} must be a finite nonnegative number")
    if isinstance(value, float) and (not math.isfinite(value) or value < 0):
        _fail(f"{label} must be a finite nonnegative number")
    if isinstance(value, int) and value < 0:
        _fail(f"{label} must be a finite nonnegative number")
    try:
        decimal = Decimal(str(value)) * Decimal(1_000_000)
        return int(decimal.quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    except (InvalidOperation, ValueError) as exc:
        raise PilotReviewBError(f"invalid provider cost: {label}") from exc


def _usage(
    objects: list[dict[str, Any]], pricing: dict[str, int]
) -> tuple[int, int, int, int, int]:
    input_tokens = output_tokens = cached = calls = 0
    for item in objects:
        message = item.get("message")
        if not isinstance(message, dict) or message.get("role") != "assistant":
            continue
        usage = message.get("usage")
        if not isinstance(usage, dict):
            _fail("assistant message lacks exact usage")
        for key in ("input", "output", "cacheRead"):
            if key not in usage:
                _fail("assistant usage token operand is missing")
        input_tokens += _strict_int(usage["input"], "input tokens")
        output_tokens += _strict_int(usage["output"], "output tokens")
        cached += _strict_int(usage["cacheRead"], "cached input tokens")
        cost = usage.get("cost")
        expected_cost_keys = {"input", "output", "cacheRead", "cacheWrite", "total"}
        if not isinstance(cost, dict) or set(cost) != expected_cost_keys:
            _fail("provider cost operands are incomplete or extra")
        components = {key: _provider_micro_usd(cost[key], f"provider cost {key}") for key in cost}
        if (
            abs(
                components["total"] - sum(components[key] for key in expected_cost_keys - {"total"})
            )
            > 1
        ):
            _fail("provider cost total differs from operands")
        content = message.get("content")
        if not isinstance(content, list):
            _fail("assistant content is invalid")
        calls += sum(
            1 for part in content if isinstance(part, dict) and part.get("type") == "toolCall"
        )
    if input_tokens + output_tokens + cached > _MAX_TOKENS or calls > _MAX_TOOLS:
        _fail("Review B token or tool-call bound exceeded")
    numerator = (
        input_tokens * pricing["input"]
        + cached * pricing["cached_input"]
        + output_tokens * pricing["output"]
    )
    return input_tokens, output_tokens, cached, calls, (numerator + 999_999) // 1_000_000


def _samples(
    path: Path,
    idle: int,
    start_monotonic_ns: int,
    end_monotonic_ns: int,
    start_unix_ms: int,
    end_unix_ms: int,
) -> tuple[int, int]:
    raw = _read(path, _MAX_SAMPLES_BYTES)
    rows = [_json(line + b"\n", "RSS sample") for line in raw.splitlines() if line]
    if len(rows) < 2:
        _fail("Review B requires at least two RSS samples")
    monotonic: list[int] = []
    unix: list[int] = []
    rss: list[int] = []
    for row in rows:
        if set(row) != {"monotonic_ns", "process_count", "rss_bytes", "unix_ms"}:
            _fail("RSS sample keys are invalid")
        monotonic.append(_strict_int(row["monotonic_ns"], "sample monotonic time"))
        unix.append(_strict_int(row["unix_ms"], "sample UTC time"))
        rss.append(_strict_int(row["rss_bytes"], "sample RSS"))
        if _strict_int(row["process_count"], "sample process count") < 1:
            _fail("RSS sample process count is zero")
    if any(right <= left for left, right in pairwise(monotonic)) or any(
        right < left for left, right in pairwise(unix)
    ):
        _fail("Review B RSS samples are not monotonic")
    deltas = [(right - left) // 1_000_000 for left, right in pairwise(monotonic)]
    if (
        any(delta < 500 or delta > 1500 for delta in deltas[:-1])
        or deltas[-1] > 1500
        or deltas[-1] <= 0
    ):
        _fail("Review B RSS sampling cadence escaped tolerance")
    tolerance_ns = _SAMPLE_TOLERANCE_MS * 1_000_000
    if monotonic[0] > start_monotonic_ns or start_monotonic_ns - monotonic[0] > tolerance_ns:
        _fail("RSS samples do not cover interval start")
    if monotonic[-1] < end_monotonic_ns or monotonic[-1] - end_monotonic_ns > tolerance_ns:
        _fail("RSS samples do not cover interval end")
    if unix[0] > start_unix_ms or start_unix_ms - unix[0] > _SAMPLE_TOLERANCE_MS:
        _fail("RSS UTC samples do not cover interval start")
    if unix[-1] < end_unix_ms or unix[-1] - end_unix_ms > _SAMPLE_TOLERANCE_MS:
        _fail("RSS UTC samples do not cover interval end")
    return max(0, max(rss) - idle), len(rows)


def _artifact(raw: bytes, marker: dict[str, Any], manifest: dict[str, Any]) -> ReviewArtifactV1:
    if len(raw) > _MAX_ARTIFACT_BYTES:
        _fail("Review B artifact exceeds byte limit")
    try:
        review = parse_artifact(raw, ReviewArtifactV1)
    except Exception as exc:
        raise PilotReviewBError("Review B artifact is not strict ReviewArtifactV1") from exc
    assert isinstance(review, ReviewArtifactV1)
    binding = _binding(manifest, str(marker["repository"]), int(marker["pr"]))
    hashes = manifest["policy_hashes"]
    if (
        review.lane != "B"
        or review.corpus_id != binding["corpus_id"]
        or review.repository != binding["repository"]
        or review.pr != binding["pr"]
        or review.snapshots.baseline_commit != binding["baseline_commit"]
        or review.snapshots.target_commit != binding["target_commit"]
        or review.reviewer.kind != "agent"
        or review.reviewer.name != manifest["pre_pilot_budget_approved_by"]
        or review.reviewer.version != f"{manifest['provider']}/{manifest['model']}"
        or review.run.prompt_sha256 != manifest["prompt_hashes"]["review-prompt-v1.md"]
        or review.run.model_policy_sha256 != hashes["model-policy-v1.json"]
        or review.run.tool_policy_sha256 != hashes["tool-policy-v1.json"]
        or review.run.source_policy_sha256 != hashes["source-policy-v1.json"]
        or review.run.limits.max_tokens != _MAX_TOKENS
        or review.run.limits.max_tool_calls != _MAX_TOOLS
        or review.run.limits.max_seconds != _MAX_INTERVAL_SECONDS
        or review.run.limits.max_output_bytes != _MAX_ARTIFACT_BYTES
    ):
        _fail("Review B artifact identity, policy, or limits binding mismatch")
    return review


def _validate_artifact_times(
    review: ReviewArtifactV1, boundary: dict[str, Any], end_unix_ms: int
) -> None:
    started_at = datetime.fromisoformat(str(boundary["started_at"])[:-1] + "+00:00")
    completed_at = datetime.fromtimestamp(end_unix_ms / 1000, timezone.utc)
    if (
        review.run.started_at != started_at
        or review.run.completed_at < started_at
        or review.run.completed_at > completed_at
    ):
        _fail("Review B artifact timestamps do not match the isolated interval")


def _safe_incident(interval_root: Path, repository: str, pr: int) -> None:
    try:
        _private_directory(interval_root)
        path = interval_root / f"incident-required-{repository.replace('/', '--')}--{pr}.json"
        if path.exists():
            status = path.lstat()
            if (
                path.is_symlink()
                or not stat.S_ISREG(status.st_mode)
                or status.st_uid != os.getuid()
            ):
                return
            return
        _atomic(
            path,
            _canonical(
                {
                    "repository": repository,
                    "pr": pr,
                    "incident_required": True,
                    "occurred_at": _utc_now(),
                }
            ),
        )
    except (OSError, PilotReviewBError):
        return


def finish(
    manifest_path: Path,
    execution_root: Path,
    packet_root: Path,
    repository: str,
    pr: int,
    supervisor_session: Path,
    interval_root: Path,
    artifact: Path,
    agent_config: Path,
    cache_root: Path,
) -> Path:
    manifest, _ = _manifest(manifest_path, agent_config, cache_root, packet_root)
    ledger = Path(str(manifest["custody_ledger_path"]))
    ledger_lock = _open_lock(ledger.with_suffix(ledger.suffix + ".lock"))
    try:
        fcntl.flock(ledger_lock, fcntl.LOCK_EX)
        _clean_state(manifest, manifest_path, agent_config, cache_root, packet_root, repository, pr)
        return _finish_locked(
            manifest_path,
            execution_root,
            packet_root,
            repository,
            pr,
            supervisor_session,
            interval_root,
            artifact,
            agent_config,
            cache_root,
        )
    finally:
        fcntl.flock(ledger_lock, fcntl.LOCK_UN)
        os.close(ledger_lock)


def _finish_locked(  # noqa: PLR0912,PLR0915 - fail-closed interval finalization
    manifest_path: Path,
    execution_root: Path,
    packet_root: Path,
    repository: str,
    pr: int,
    supervisor_session: Path,
    interval_root: Path,
    artifact: Path,
    agent_config: Path,
    cache_root: Path,
) -> Path:
    manifest, manifest_hash = _manifest(manifest_path, agent_config, cache_root, packet_root)
    execution = _private_directory(execution_root)
    if manifest_path.parent.resolve() != execution:
        _fail("execution root differs from manifest")
    interval = _private_directory(interval_root)
    if interval.parent != execution:
        _fail("interval root must be a direct execution child")
    lock = _open_lock(interval_root / "interval.lock")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        active_path = interval_root / "active.json"
        active = _json(_read(active_path, 4096), "active interval")
        assigned = Path(str(active.get("assigned_root")))
        _relative_child(assigned, interval_root, strict=True)
        _private_directory(assigned)
        marker_path = assigned / "marker.json"
        boundary_path = assigned / "start-boundary.json"
        marker = _json(_read(marker_path, 64 * 1024), "Review B marker")
        boundary = _json(_read(boundary_path, 64 * 1024), "Review B start boundary")
        if active.get("marker_sha256") != _sha(_canonical(marker)) or active.get(
            "boundary_sha256"
        ) != _sha(_canonical(boundary)):
            _fail("active Review B marker/boundary hash mismatch")
        if (
            marker.get("manifest_sha256") != manifest_hash
            or str(marker.get("repository")).casefold() != repository.casefold()
            or marker.get("pr") != pr
            or artifact.resolve() != Path(str(marker.get("artifact_path"))).resolve()
            or supervisor_session.resolve() != Path(str(marker.get("session_path"))).resolve()
        ):
            _fail("finish arguments differ from active Review B marker")
        supervisor_pid = _strict_int(marker.get("supervisor_pid"), "supervisor pid")
        supervisor_starttime = _strict_int(
            marker.get("supervisor_starttime"), "supervisor start time"
        )
        _owned_process(supervisor_pid, supervisor_starttime)
        if not _is_ancestor(supervisor_pid, os.getpid()):
            _fail("declared supervisor PID is not an ancestor of the finish CLI")
        expected_session = Path(
            str(manifest["review_b_measurement"]["supervisor_session_path"])
        ).resolve(strict=True)
        session_raw, session_status = _session_snapshot(supervisor_session, expected_session)
        _verify_session_append(session_raw, session_status, marker)
        interval_raw, objects = _interval(session_raw, marker, boundary, manifest)
        end_monotonic_ns = time.monotonic_ns()
        end_unix_ms = time.time_ns() // 1_000_000
        stop = Path(str(boundary["stop_path"]))
        _relative_child(stop, assigned, strict=False)
        pid = _strict_int(boundary.get("sampler_pid"), "sampler pid")
        sampler_starttime = _strict_int(boundary.get("sampler_starttime"), "sampler start time")
        _owned_process(pid, sampler_starttime)
        _atomic(stop, b"stop\n")
        deadline = time.monotonic() + 5
        sampler = _SAMPLERS.pop(pid, None)
        while time.monotonic() < deadline:
            if sampler is not None:
                if sampler.poll() is not None:
                    sampler.wait(timeout=1)
                    break
            else:
                try:
                    waited, _status = os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    waited = pid if not Path("/proc", str(pid)).exists() else 0
                if waited == pid:
                    break
            time.sleep(0.05)
        else:
            _owned_process(pid, sampler_starttime)
            os.killpg(pid, signal.SIGKILL)
            with contextlib.suppress(ChildProcessError):
                os.waitpid(pid, 0)
            _fail("Review B sampler did not stop cleanly")
        disk_after = _disk_scope(execution_root, packet_root, interval_root)
        artifact_raw = _read(artifact, _MAX_ARTIFACT_BYTES)
        review = _artifact(artifact_raw, marker, manifest)
        completed_at = datetime.fromtimestamp(end_unix_ms / 1000, timezone.utc)
        _validate_artifact_times(review, boundary, end_unix_ms)
        wall_ms = max(
            1,
            (end_monotonic_ns - _strict_int(boundary["started_monotonic_ns"], "start monotonic"))
            // 1_000_000,
        )
        if wall_ms > _MAX_INTERVAL_SECONDS * 1000:
            _fail("Review B interval exceeded wall-clock bound")
        peak, _ = _samples(
            Path(str(boundary["samples_path"])),
            _strict_int(
                manifest["resource_projection_inputs"]["idle_supervisor_rss_bytes"], "idle RSS"
            ),
            _strict_int(boundary["started_monotonic_ns"], "start monotonic"),
            end_monotonic_ns,
            _strict_int(boundary["started_unix_ms"], "start UTC"),
            end_unix_ms,
        )
        pricing = manifest["pricing_micro_usd_per_million_tokens"]
        if not isinstance(pricing, dict) or not all(
            isinstance(pricing.get(key), int) and not isinstance(pricing.get(key), bool)
            for key in ("input", "cached_input", "output")
        ):
            _fail("manifest pricing is invalid")
        input_tokens, output_tokens, cached, calls, cost = _usage(objects, pricing)
        assistant = [
            item
            for item in objects
            if isinstance(item.get("message"), dict) and item["message"].get("role") == "assistant"
        ]
        start_id = _message_id(objects[0])
        end_id = _message_id(objects[-1])
        start_message = _message_id(assistant[0])
        end_message = _message_id(assistant[-1])
        telemetry = {
            "attempt_id": f"review-b-{repository.casefold()}-{pr}-attempt-1",
            "repository": str(marker["repository"]),
            "pr": pr,
            "role": "review_b",
            "source_kind": "supervisor_session_interval_v1",
            "provider": manifest["provider"],
            "model": manifest["model"],
            "model_version": manifest["model_version"],
            "client_version": manifest["client_version"],
            "started_at": boundary["started_at"],
            "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
            "wall_milliseconds": wall_ms,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cached_input_tokens": cached,
            "tool_calls": calls,
            "input_bytes": len(interval_raw),
            "output_bytes": len(artifact_raw),
            "sampled_peak_process_tree_rss_bytes": peak,
            "rss_sampling_interval_milliseconds": 1000,
            "disk_scope": {"before": marker["disk_before"], "after": disk_after},
            "disk_bytes_before": sum(
                _strict_int(v, "disk before") for v in marker["disk_before"].values()
            ),
            "disk_bytes_after": sum(disk_after.values()),
            "is_retry": False,
            "retry_of_attempt_id": None,
            "succeeded": True,
            "failure_kind": None,
            "status_sha256": None,
            "events_sha256": None,
            "supervisor_interval_sha256": _sha(interval_raw),
            "start_event_id": start_id,
            "end_event_id": end_id,
            "start_message_id": start_message,
            "end_message_id": end_message,
            "transcript_sha256": _sha(interval_raw),
            "artifact_sha256": _sha(artifact_raw),
            "cost_micro_usd": cost,
            "unavailable_reason": None,
        }
        if set(telemetry) != _TELEMETRY_KEYS:
            _fail("Review B telemetry keys are incomplete")
        _atomic(assigned / "supervisor-interval.jsonl", interval_raw, mode=0o400)
        telemetry_path = assigned / "telemetry.json"
        _atomic(telemetry_path, _canonical(telemetry), mode=0o400)
        active_path.unlink()
        directory = os.open(interval_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return telemetry_path
    except BaseException:
        _safe_incident(interval_root, repository, pr)
        raise
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--execution-root", type=Path)
    parser.add_argument("--packet-root", type=Path)
    parser.add_argument("--repository")
    parser.add_argument("--pr", type=int)
    parser.add_argument("--supervisor-session", type=Path)
    parser.add_argument("--supervisor-pid", type=int)
    parser.add_argument("--interval-root", type=Path)
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--agent-config", type=Path)
    parser.add_argument("--cache-root", type=Path)
    parser.add_argument("--start", action="store_true")
    parser.add_argument("--finish", action="store_true")
    parser.add_argument("--print-start-command", action="store_true")
    parser.add_argument("--print-finish-command", action="store_true")
    parser.add_argument(
        "--sample", nargs=5, metavar=("SAMPLES", "STOP", "READY", "PID", "STARTTIME")
    )
    args = parser.parse_args()
    if args.sample is not None:
        return sample(
            Path(args.sample[0]),
            Path(args.sample[1]),
            Path(args.sample[2]),
            int(args.sample[3]),
            int(args.sample[4]),
        )
    required = [
        args.manifest,
        args.execution_root,
        args.packet_root,
        args.repository,
        args.pr,
        args.supervisor_session,
        args.interval_root,
        args.agent_config,
        args.cache_root,
    ]
    if (
        any(value is None for value in required)
        or sum((args.start, args.finish, args.print_start_command, args.print_finish_command)) != 1
    ):
        parser.error(
            "choose exactly one of --start, --finish, --print-start-command, "
            "or --print-finish-command "
            "with all authenticated paths/identity"
        )
    assert (
        args.manifest and args.execution_root and args.packet_root and args.repository and args.pr
    )
    assert args.supervisor_session and args.interval_root and args.agent_config and args.cache_root
    if args.print_start_command:
        if args.supervisor_pid is None:
            parser.error("--print-start-command requires --supervisor-pid")
        print(
            shlex.join(
                _expected_start_tokens(
                    args.manifest,
                    args.execution_root,
                    args.packet_root,
                    args.repository,
                    args.pr,
                    args.supervisor_session,
                    args.supervisor_pid,
                    args.interval_root,
                    args.agent_config,
                    args.cache_root,
                )
            )
        )
        return 0
    if args.print_finish_command:
        if args.artifact is None:
            parser.error("--print-finish-command requires --artifact")
        print(
            shlex.join(
                _expected_finish_tokens(
                    args.manifest,
                    args.execution_root,
                    args.packet_root,
                    args.repository,
                    args.pr,
                    args.supervisor_session,
                    args.interval_root,
                    args.artifact,
                    args.agent_config,
                    args.cache_root,
                )
            )
        )
        return 0
    if args.start:
        if args.supervisor_pid is None:
            parser.error("--start requires --supervisor-pid")
        assigned = start(
            args.manifest,
            args.execution_root,
            args.packet_root,
            args.repository,
            args.pr,
            args.supervisor_session,
            args.supervisor_pid,
            args.interval_root,
            args.agent_config,
            args.cache_root,
        )
        boundary_raw = _read(assigned / "start-boundary.json", 64 * 1024)
        boundary = _json(boundary_raw, "Review B start boundary")
        print(
            json.dumps(
                {
                    "assigned_root": str(assigned),
                    "boundary_sha256": _sha(boundary_raw),
                    "started_at": boundary["started_at"],
                },
                sort_keys=True,
            )
        )
        return 0
    if args.artifact is None:
        parser.error("--finish requires --artifact")
    telemetry = finish(
        args.manifest,
        args.execution_root,
        args.packet_root,
        args.repository,
        args.pr,
        args.supervisor_session,
        args.interval_root,
        args.artifact,
        args.agent_config,
        args.cache_root,
    )
    print(json.dumps({"telemetry": str(telemetry)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
