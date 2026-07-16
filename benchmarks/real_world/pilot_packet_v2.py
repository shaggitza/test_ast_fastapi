#!/usr/bin/env python3
"""Prepare and validate immutable bare caches and read-only pilot review packets."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import resource
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
from contextlib import contextmanager, suppress
from functools import partial
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, NoReturn, cast

from benchmarks.real_world import pilot_protocol_v2, pilot_source_v2
from benchmarks.real_world.ground_truth_v2.evidence import collision_resistant_cache_name

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

_MAX_COMMANDS = 100
_MAX_WALL_SECONDS = 1800
_MAX_TREE_BYTES = 64 * 1024 * 1024
_MAX_BATCH_BYTES = 256 * 1024 * 1024 + 4 * 1024 * 1024
_MAX_DIFF_BYTES = 32 * 1024 * 1024
_MAX_STDERR_BYTES = 1024 * 1024
_MAX_MANIFEST_BYTES = 16 * 1024 * 1024
_MAX_FILES = 200_000
_MAX_FILE_BYTES = 32 * 1024 * 1024
_MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024
_MAX_TOTAL_BYTES = 512 * 1024 * 1024
# 3 packets * 512 MiB + one 260 MiB cat-file spool + 64 MiB tree + 32 MiB diff
# is 1,892 MiB, leaving 156 MiB inside this hard aggregate staging cap.
_MAX_PACKET_STAGING_BYTES = 2 * 1024 * 1024 * 1024
_MAX_CACHE_BYTES = 2 * 1024 * 1024 * 1024
# Three complete caches at the per-cache cap consume at most 6 GiB, leaving
# 2 GiB for bounded fetch output/index staging inside this aggregate ceiling.
_MAX_CACHE_STAGING_BYTES = 8 * 1024 * 1024 * 1024
_MIN_DISK_HEADROOM_BYTES = 256 * 1024 * 1024
_MAX_PATH_BYTES = 2048
_PACKET_ID = "blind-review-pilot-packet-v1"
_PACKET_KEYS = {
    "schema_version",
    "id",
    "repository",
    "pr",
    "source_bindings_sha256",
    "baseline_commit",
    "baseline_tree",
    "target_commit",
    "target_tree",
    "remote_diff_sha256",
    "remote_diff_bytes",
    "local_diff_sha256",
    "local_diff_bytes",
    "snapshots",
    "payload_files",
    "payload_bytes",
    "packet_root_sha256",
}
_CONTROL_FILES = (
    "checksums-v1.json",
    "review-prompt-v1.md",
    "adjudication-prompt-v1.md",
    "model-policy-v1.json",
    "tool-policy-v1.json",
    "source-policy-v1.json",
    "scope-policy-v1.json",
)


class PilotPacketError(ValueError):
    """Raised when cache or packet provenance cannot be proved."""


def _fail(message: str) -> NoReturn:
    raise PilotPacketError(message)


def _sha(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    _fail(f"non-finite JSON constant is forbidden: {value}")


def _read_bounded(path: Path, limit: int) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            os.close(descriptor)
            _fail(f"bounded file is not regular: {path.name}")
        with os.fdopen(descriptor, "rb") as handle:
            raw = handle.read(limit + 1)
    except OSError as exc:
        raise PilotPacketError(f"cannot read bounded file: {path.name}") from exc
    if len(raw) > limit:
        _fail(f"bounded file exceeds limit: {path.name}")
    return raw


def _load_json_bounded(path: Path) -> dict[str, Any]:
    raw = _read_bounded(path, _MAX_MANIFEST_BYTES)
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, MemoryError) as exc:
        raise PilotPacketError("invalid packet manifest JSON") from exc
    if not isinstance(value, dict):
        _fail("packet manifest root must be an object")
    return value


def _binding_inputs(root: Path) -> tuple[list[dict[str, Any]], str]:
    pilot_protocol_v2.validate_preregistration(root)
    base = root / "benchmarks/real_world/pilot_v2"
    payload = pilot_source_v2.validate_authenticated(
        root,
        base / "source-bindings-v1.json",
        base / "source-bindings-checksums-v1.json",
    )
    raw = _read_bounded(base / "source-bindings-v1.json", 2 * 1024 * 1024)
    records = payload["records"]
    if not isinstance(records, list) or len(records) != 3:
        _fail("authenticated source bindings must contain three records")
    return records, _sha(raw)


def _git_env() -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.devnull,
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES": "",
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": "maintenance.auto",
        "GIT_CONFIG_VALUE_0": "false",
        "GIT_CONFIG_KEY_1": "gc.auto",
        "GIT_CONFIG_VALUE_1": "0",
    }


def _child_limits(max_file_bytes: int) -> None:
    """Apply inherited hard limits to Git and every child it spawns."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (_MAX_WALL_SECONDS, _MAX_WALL_SECONDS))
    resource.setrlimit(resource.RLIMIT_AS, (3 * 1024**3, 3 * 1024**3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (max_file_bytes, max_file_bytes))
    with suppress(ValueError):
        resource.setrlimit(resource.RLIMIT_NPROC, (1024, 1024))


def _kill_wait(process: subprocess.Popen[bytes]) -> None:
    with suppress(OSError):
        os.killpg(process.pid, signal.SIGKILL)
    with suppress(OSError, subprocess.TimeoutExpired):
        process.wait(timeout=5)


def _lstat_inventory(root: Path, *, byte_limit: int) -> tuple[set[str], set[str], int]:
    if not root.is_dir() or root.is_symlink():
        _fail("filesystem inventory root is unsafe")
    directories: set[str] = set()
    files: set[str] = set()
    total = 0
    pending = [root]
    count = 0
    while pending:
        current = pending.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    count += 1
                    if count > _MAX_FILES:
                        _fail("filesystem inventory file count exceeded")
                    relative = Path(entry.path).relative_to(root).as_posix()
                    metadata = entry.stat(follow_symlinks=False)
                    mode = metadata.st_mode
                    if stat.S_ISDIR(mode):
                        directories.add(relative)
                        pending.append(Path(entry.path))
                    elif stat.S_ISREG(mode):
                        total += metadata.st_size
                        if total > byte_limit:
                            _fail("filesystem inventory byte bound exceeded")
                        files.add(relative)
                    else:
                        _fail("filesystem inventory contains symlink or special entry")
        except OSError as exc:
            raise PilotPacketError("cannot inventory filesystem") from exc
    return directories, files, total


class GitRunner:
    """Run argv-only Git commands with temp-file output and active bounds."""

    def __init__(self, *, deadline: float | None = None) -> None:
        self.deadline = time.monotonic() + _MAX_WALL_SECONDS if deadline is None else deadline
        self.commands = 0

    def _command(self, cache: Path, args: Sequence[str]) -> list[str]:
        return [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "filter.lfs.smudge=",
            "-c",
            "core.useReplaceRefs=false",
            "-c",
            "maintenance.auto=false",
            "-c",
            "gc.auto=0",
            "-C",
            str(cache),
            *args,
        ]

    def run_to_path(  # noqa: PLR0912 - fail-closed process lifecycle
        self,
        cache: Path,
        args: Sequence[str],
        output: Path,
        *,
        limit: int,
        disk_root: Path | None = None,
        disk_limit: int = _MAX_CACHE_STAGING_BYTES,
        input_path: Path | None = None,
    ) -> None:
        self.commands += 1
        if self.commands > _MAX_COMMANDS:
            _fail("Git command budget exceeded")
        if self.deadline <= time.monotonic():
            _fail("Git wall-clock budget exceeded")
        if threading.active_count() != 1:
            _fail("bounded Git runner requires a single-threaded process")
        stderr_path = output.with_name(f".{output.name}.stderr")
        process: subprocess.Popen[bytes] | None = None
        stdin_handle = None
        try:
            stdin_handle = input_path.open("rb") if input_path is not None else None
            with output.open("xb") as stdout, stderr_path.open("xb") as stderr:
                process = subprocess.Popen(
                    self._command(cache, args),
                    stdin=stdin_handle if stdin_handle is not None else subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    env=_git_env(),
                    shell=False,
                    start_new_session=True,
                    preexec_fn=partial(  # noqa: PLW1509 - single-threaded bounded child
                        _child_limits,
                        _MAX_CACHE_BYTES if args[0] == "fetch" else max(limit, _MAX_STDERR_BYTES),
                    ),
                )
                while process.poll() is None:
                    if time.monotonic() >= self.deadline:
                        _kill_wait(process)
                        _fail("Git command exceeded wall-clock budget")
                    if (
                        output.stat().st_size > limit
                        or stderr_path.stat().st_size > _MAX_STDERR_BYTES
                    ):
                        _kill_wait(process)
                        _fail("Git command output exceeded bound")
                    if disk_root is not None:
                        _lstat_inventory(disk_root, byte_limit=disk_limit)
                    time.sleep(0.05)
                code = process.wait(timeout=5)
                _kill_wait(process)
            if output.stat().st_size > limit or stderr_path.stat().st_size > _MAX_STDERR_BYTES:
                _fail("Git command output exceeded bound")
            if disk_root is not None:
                _lstat_inventory(disk_root, byte_limit=disk_limit)
            if code != 0:
                _fail(f"Git command failed: {args[0]}")
        except BaseException as exc:
            if process is not None:
                _kill_wait(process)
            output.unlink(missing_ok=True)
            if isinstance(exc, PilotPacketError):
                raise
            raise PilotPacketError("bounded Git command failed") from exc
        finally:
            if stdin_handle is not None:
                stdin_handle.close()
            stderr_path.unlink(missing_ok=True)
            if process is not None and process.poll() is None:
                _kill_wait(process)

    def run(
        self,
        cache: Path,
        *args: str,
        limit: int = 1024 * 1024,
        disk_root: Path | None = None,
        disk_limit: int = _MAX_CACHE_STAGING_BYTES,
    ) -> bytes:
        descriptor, name = tempfile.mkstemp(prefix="pilot-git-output-")
        os.close(descriptor)
        output = Path(name)
        output.unlink()
        try:
            self.run_to_path(
                cache,
                args,
                output,
                limit=limit,
                disk_root=disk_root,
                disk_limit=disk_limit,
            )
            return _read_bounded(output, limit)
        finally:
            output.unlink(missing_ok=True)


def _require_private_parent(path: Path) -> None:
    parent = path.parent
    try:
        metadata = parent.lstat()
    except OSError as exc:
        raise PilotPacketError("cannot inspect private root parent") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        _fail("cache/packet parent must be private and owned by current uid")


def _preflight_disk(parent: Path, required: int) -> None:
    try:
        free = shutil.disk_usage(parent).free
    except OSError as exc:
        raise PilotPacketError("cannot inspect staging disk capacity") from exc
    if free < required + _MIN_DISK_HEADROOM_BYTES:
        _fail("insufficient free space for bounded staging")


@contextmanager
def _validation_lock(root: Path) -> Iterator[None]:
    """Serialize validation/regeneration through a private sibling lock."""
    _require_private_parent(root)
    lock = root.with_name(f".{root.name}.validation.lock")
    descriptor = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
            _fail("validation lock ownership or permissions are unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        with suppress(OSError):
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


@contextmanager
def _publication_lock(final: Path) -> Iterator[None]:
    lock = final.with_name(f".{final.name}.publication.lock")
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise PilotPacketError(f"publication is already in progress: {final}") from exc
    try:
        if final.exists():
            _fail(f"refusing to overwrite output: {final}")
        yield
    finally:
        os.close(descriptor)
        lock.unlink(missing_ok=True)


def _require_separate_roots(first: Path, second: Path) -> None:
    first_absolute = first.resolve()
    second_absolute = second.resolve()
    if (
        first_absolute == second_absolute
        or first_absolute.is_relative_to(second_absolute)
        or second_absolute.is_relative_to(first_absolute)
    ):
        _fail("cache and packet roots must be separate non-nested paths")


def _directory_identity(path: Path) -> tuple[int, int]:
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        _fail("cache directory identity or ownership is unsafe")
    return metadata.st_dev, metadata.st_ino


def _cache_path(root: Path, repository: str) -> Path:
    return root / collision_resistant_cache_name(repository)


def _verify_cache_config(runner: GitRunner, cache: Path) -> None:
    forbidden_files = (
        cache / "objects/info/alternates",
        cache / "objects/info/http-alternates",
    )
    if any(path.exists() or path.is_symlink() for path in forbidden_files):
        _fail("Git alternate object database is forbidden")
    references = runner.run(cache, "for-each-ref", "--format=%(refname)")
    if references.strip():
        _fail("Git cache refs are forbidden")
    config = runner.run(cache, "config", "--local", "--list", "--null").decode(errors="strict")
    entries = [item for item in config.split("\0") if item]
    forbidden = ("promisor", "partialclone", "alternate")
    if any(any(token in item.casefold() for token in forbidden) for item in entries):
        _fail("partial/promisor/alternate Git cache is forbidden")


def _check_readonly_tree(root: Path, *, byte_limit: int = _MAX_CACHE_BYTES) -> None:
    if stat.S_IMODE(root.lstat().st_mode) & 0o222:
        _fail("published cache or packet is writable")
    directories, files, _total = _lstat_inventory(root, byte_limit=byte_limit)
    for relative in directories | files:
        if stat.S_IMODE((root / relative).lstat().st_mode) & 0o222:
            _fail("published cache or packet is writable")


def _validate_one_cache(  # noqa: PLR0912,PLR0915 - fail-closed cache validation
    runner: GitRunner,
    cache: Path,
    record: dict[str, Any],
    *,
    require_readonly: bool,
) -> None:
    if not cache.is_dir() or cache.is_symlink():
        _fail("bare cache is missing or unsafe")
    _lstat_inventory(cache, byte_limit=_MAX_CACHE_BYTES)
    if require_readonly:
        _check_readonly_tree(cache)
    if runner.run(cache, "rev-parse", "--is-bare-repository").strip() != b"true":
        _fail("cache is not bare")
    expected_remote = f"https://github.com/{record['repository']}.git"
    if (
        runner.run(cache, "config", "--get", "remote.origin.url").decode().strip()
        != expected_remote
    ):
        _fail("cache remote mismatch")
    _verify_cache_config(runner, cache)
    if runner.run(cache, "rev-parse", "--is-shallow-repository").strip() != b"true":
        _fail("Git cache must be shallow")
    shallow_path = cache / "shallow"
    shallow_raw = _read_bounded(shallow_path, 4096)
    try:
        shallow_commits = {line for line in shallow_raw.decode("ascii").splitlines() if line}
    except UnicodeDecodeError as exc:
        raise PilotPacketError("Git shallow boundary is malformed") from exc
    expected_shallow = {
        str(record["baseline_commit"]),
        str(record["target_commit"]),
    }
    if shallow_commits != expected_shallow or any(
        re.fullmatch(r"[0-9a-f]{40}", item) is None for item in shallow_commits
    ):
        _fail("Git shallow boundary contains missing or extra history")
    object_lines = (
        runner.run(
            cache,
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname) %(objecttype)",
            limit=_MAX_TREE_BYTES,
        )
        .decode("ascii")
        .splitlines()
    )
    commit_objects: set[str] = set()
    object_ids: set[str] = set()
    for line in object_lines:
        try:
            oid, kind = line.split(" ")
        except ValueError as exc:
            raise PilotPacketError("Git object inventory is malformed") from exc
        if re.fullmatch(r"[0-9a-f]{40}", oid) is None:
            _fail("Git object inventory contains invalid identity")
        object_ids.add(oid)
        if kind not in {"blob", "tree", "commit"}:
            _fail("Git cache contains unsupported extra object type")
        if kind == "commit":
            commit_objects.add(oid)
    if commit_objects != expected_shallow:
        _fail("Git cache contains extra commit history")
    reachable_raw = runner.run(
        cache,
        "rev-list",
        "--objects",
        "--no-object-names",
        *sorted(expected_shallow),
        limit=_MAX_TREE_BYTES,
    ).decode("ascii")
    reachable = {line for line in reachable_raw.splitlines() if line}
    if any(re.fullmatch(r"[0-9a-f]{40}", oid) is None for oid in reachable):
        _fail("Git reachable object inventory is malformed")
    if reachable != object_ids:
        _fail("Git cache contains unreachable or missing objects")
    for side in ("baseline", "target"):
        commit = str(record[f"{side}_commit"])
        tree = str(record[f"{side}_tree"])
        resolved = runner.run(
            cache, "rev-parse", "--verify", "--end-of-options", f"{commit}^{{commit}}"
        )
        if resolved.decode().strip() != commit:
            _fail("cache commit mismatch")
        resolved_tree = runner.run(
            cache, "rev-parse", "--verify", "--end-of-options", f"{commit}^{{tree}}"
        )
        if resolved_tree.decode().strip() != tree:
            _fail("cache tree mismatch")
        runner.run(cache, "cat-file", "-e", f"{tree}^{{tree}}")


def _validate_cache_unlocked(cache_root: Path, records: list[dict[str, Any]]) -> None:
    identity = _directory_identity(cache_root)
    _check_readonly_tree(cache_root, byte_limit=3 * _MAX_CACHE_BYTES)
    expected = {_cache_path(cache_root, str(record["repository"])).name for record in records}
    _dirs, files, _total = _lstat_inventory(cache_root, byte_limit=3 * _MAX_CACHE_BYTES)
    actual = {entry.name for entry in os.scandir(cache_root) if entry.is_dir(follow_symlinks=False)}
    top_files = {name for name in files if "/" not in name}
    if actual != expected or top_files:
        _fail("cache root contains missing or extra entries")
    runner = GitRunner()
    for record in records:
        cache = _cache_path(cache_root, str(record["repository"]))
        cache_identity = _directory_identity(cache)
        _validate_one_cache(runner, cache, record, require_readonly=True)
        if _directory_identity(cache) != cache_identity:
            _fail("cache directory changed during validation")
    if _directory_identity(cache_root) != identity:
        _fail("cache root changed during validation")


def validate_cache(cache_root: Path, records: list[dict[str, Any]]) -> None:
    with _validation_lock(cache_root):
        _validate_cache_unlocked(cache_root, records)


def _readonly(root: Path) -> None:
    directories, files, _total = _lstat_inventory(root, byte_limit=3 * _MAX_CACHE_BYTES)
    for relative in sorted(files, key=lambda value: len(PurePosixPath(value).parts), reverse=True):
        (root / relative).chmod(0o444)
    for relative in sorted(
        directories, key=lambda value: len(PurePosixPath(value).parts), reverse=True
    ):
        (root / relative).chmod(0o555)
    root.chmod(0o555)


def _make_writable_for_cleanup(root: Path) -> None:
    if not root.exists() or root.is_symlink():
        return
    pending = [root]
    directories: list[Path] = []
    while pending:
        current = pending.pop()
        directories.append(current)
        with suppress(OSError), os.scandir(current) as entries:
            for entry in entries:
                try:
                    metadata = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                path = Path(entry.path)
                if stat.S_ISDIR(metadata.st_mode):
                    pending.append(path)
                elif stat.S_ISREG(metadata.st_mode):
                    with suppress(OSError):
                        path.chmod(0o600, follow_symlinks=False)
    for directory in directories:
        with suppress(OSError):
            directory.chmod(0o700, follow_symlinks=False)


def prepare_cache(cache_root: Path, records: list[dict[str, Any]]) -> None:
    if cache_root.exists():
        _fail(f"refusing to overwrite cache root: {cache_root}")
    cache_root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _require_private_parent(cache_root)
    _preflight_disk(cache_root.parent, _MAX_CACHE_STAGING_BYTES)
    staging = Path(tempfile.mkdtemp(prefix=f".{cache_root.name}.", dir=cache_root.parent))
    staging.chmod(0o700)
    runner = GitRunner()
    try:
        for record in records:
            cache = _cache_path(staging, str(record["repository"]))
            cache.mkdir()
            runner.run(cache, "init", "--bare", disk_root=staging)
            runner.run(
                cache,
                "remote",
                "add",
                "origin",
                f"https://github.com/{record['repository']}.git",
                disk_root=staging,
            )
            for side in ("baseline", "target"):
                runner.run(
                    cache,
                    "fetch",
                    "--no-tags",
                    "--depth=1",
                    "--no-recurse-submodules",
                    "origin",
                    str(record[f"{side}_commit"]),
                    limit=8 * 1024 * 1024,
                    disk_root=staging,
                )
            _validate_one_cache(runner, cache, record, require_readonly=False)
        _lstat_inventory(staging, byte_limit=_MAX_CACHE_STAGING_BYTES)
        _readonly(staging)
        _validate_cache_unlocked(staging, records)
        with _publication_lock(cache_root):
            staging.rename(cache_root)
    except BaseException:
        _make_writable_for_cleanup(staging)
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _safe_name(raw: bytes) -> PurePosixPath:
    if not raw or b"\\" in raw or b"\x00" in raw or len(raw) > _MAX_PATH_BYTES:
        _fail("Git tree path is invalid")
    try:
        name = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise PilotPacketError("Git tree path is not UTF-8") from exc
    raw_parts = name.split("/")
    if (
        name.startswith("/")
        or name.endswith("/")
        or any(part in {"", ".", "..", ".git"} for part in raw_parts)
        or len(raw_parts) > 100
    ):
        _fail("Git tree path escapes or conflicts with packet")
    path = PurePosixPath(name)
    if path.is_absolute() or path.as_posix() != name:
        _fail("Git tree path is not canonical POSIX")
    return path


def _hash_file(path: Path, limit: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            os.close(descriptor)
            _fail("packet payload is not a regular file")
        with os.fdopen(descriptor, "rb") as handle:
            while chunk := handle.read(64 * 1024):
                size += len(chunk)
                if size > limit:
                    _fail("packet payload file exceeds bound")
                digest.update(chunk)
    except OSError as exc:
        raise PilotPacketError("cannot hash packet payload") from exc
    return f"sha256:{digest.hexdigest()}", size


def _record_payload_files(root: Path, *, exclude: set[str]) -> list[dict[str, object]]:
    _directories, files, total = _lstat_inventory(root, byte_limit=_MAX_TOTAL_BYTES)
    result: list[dict[str, object]] = []
    for relative in sorted(files):
        if relative in exclude:
            continue
        digest, size = _hash_file(
            root / relative, _MAX_FILE_BYTES if "/" in relative else _MAX_MANIFEST_BYTES
        )
        result.append({"path": relative, "sha256": digest, "bytes": size})
    if total > _MAX_TOTAL_BYTES:
        _fail("packet payload total exceeded")
    return result


def _packet_name(record: dict[str, Any]) -> str:
    identity = f"{record['repository'].casefold()}#{record['pr']}"
    slug = str(record["repository"]).replace("/", "--")
    return f"{slug}--{record['pr']}--{hashlib.sha256(identity.encode()).hexdigest()[:16]}"


def _manifest_root(manifest: dict[str, Any]) -> str:
    payload = {key: value for key, value in manifest.items() if key != "packet_root_sha256"}
    return _sha(b"blind-review-pilot-packet-root-v1\0" + _canonical(payload))


def _parse_tree(raw: bytes) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    blobs: list[dict[str, str]] = []
    gitlinks: list[dict[str, str]] = []
    seen: set[str] = set()
    records = raw.split(b"\0")
    if records[-1] != b"":
        _fail("Git ls-tree output is not NUL terminated")
    for record in records[:-1]:
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, kind, oid = metadata.decode("ascii").split(" ")
        except (ValueError, UnicodeDecodeError) as exc:
            raise PilotPacketError("malformed Git ls-tree record") from exc
        path = _safe_name(raw_path).as_posix()
        if path in seen:
            _fail("Git tree contains duplicate path")
        seen.add(path)
        if re.fullmatch(r"[0-9a-f]{40}", oid) is None:
            _fail("Git tree object id is invalid")
        if mode in {"100644", "100755", "120000"} and kind == "blob":
            blobs.append({"path": path, "mode": mode, "oid": oid})
        elif mode == "160000" and kind == "commit":
            gitlinks.append({"path": path, "commit": oid})
        else:
            _fail("Git tree contains unsupported mode/type")
    return blobs, gitlinks


def _copy_exact(source: Path, target: Path, expected: int, staging_root: Path) -> str:
    digest = hashlib.sha256()
    written = 0
    target.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as input_handle, target.open("xb") as output_handle:
        while chunk := input_handle.read(64 * 1024):
            written += len(chunk)
            if written > expected or written > _MAX_FILE_BYTES:
                _fail("Git blob changed size")
            digest.update(chunk)
            output_handle.write(chunk)
            _lstat_inventory(staging_root, byte_limit=_MAX_PACKET_STAGING_BYTES)
    if written != expected:
        _fail("Git blob size mismatch")
    target.chmod(0o444)
    return f"sha256:{digest.hexdigest()}"


def _materialize_blobs(  # noqa: PLR0912,PLR0915 - bounded batch protocol parser
    runner: GitRunner,
    cache: Path,
    destination: Path,
    entries: list[dict[str, str]],
    staging_root: Path,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    by_oid: dict[str, list[dict[str, str]]] = {}
    for entry in entries:
        by_oid.setdefault(entry["oid"], []).append(entry)
    input_file = destination.parent / f".{destination.name}.batch-input"
    output_file = destination.parent / f".{destination.name}.batch-output"
    input_file.write_bytes(b"".join(f"{oid}\n".encode() for oid in by_oid))
    try:
        runner.run_to_path(
            cache,
            ("cat-file", "--batch"),
            output_file,
            limit=_MAX_BATCH_BYTES,
            disk_root=staging_root,
            disk_limit=_MAX_PACKET_STAGING_BYTES,
            input_path=input_file,
        )
        files: list[dict[str, object]] = []
        symlinks: list[dict[str, object]] = []
        logical_total = 0
        with output_file.open("rb") as stream:
            for oid, oid_entries in by_oid.items():
                header = stream.readline(201)
                if not header.endswith(b"\n") or len(header) > 200:
                    _fail("Git cat-file batch header exceeded bound")
                try:
                    returned, kind, raw_size = header[:-1].decode("ascii").split(" ")
                    size = int(raw_size)
                except (ValueError, UnicodeDecodeError) as exc:
                    raise PilotPacketError("malformed Git cat-file batch header") from exc
                if returned != oid or kind != "blob" or size < 0 or size > _MAX_FILE_BYTES:
                    _fail("Git cat-file batch identity/type/size mismatch")
                descriptor, blob_name = tempfile.mkstemp(
                    prefix="pilot-blob-", dir=destination.parent
                )
                blob = Path(blob_name)
                digest = hashlib.sha256()
                try:
                    with os.fdopen(descriptor, "wb") as target:
                        remaining = size
                        while remaining:
                            chunk = stream.read(min(64 * 1024, remaining))
                            if not chunk:
                                _fail("Git cat-file batch blob truncated")
                            digest.update(chunk)
                            target.write(chunk)
                            remaining -= len(chunk)
                            _lstat_inventory(staging_root, byte_limit=_MAX_PACKET_STAGING_BYTES)
                    if stream.read(1) != b"\n":
                        _fail("Git cat-file batch blob delimiter missing")
                    blob_hash = f"sha256:{digest.hexdigest()}"
                    for entry in oid_entries:
                        logical_total += size
                        if logical_total > _MAX_SNAPSHOT_BYTES:
                            _fail("snapshot total bytes exceeded")
                        if entry["mode"] == "120000":
                            raw_target = _read_bounded(blob, _MAX_PATH_BYTES)
                            symlinks.append(
                                {
                                    "path": entry["path"],
                                    "oid": oid,
                                    "target_hex": raw_target.hex(),
                                    "sha256": blob_hash,
                                    "bytes": size,
                                }
                            )
                        else:
                            path = destination.joinpath(*PurePosixPath(entry["path"]).parts)
                            actual_hash = _copy_exact(blob, path, size, staging_root)
                            if actual_hash != blob_hash:
                                _fail("Git blob copy hash changed")
                            files.append(
                                {
                                    "path": entry["path"],
                                    "mode": entry["mode"],
                                    "oid": oid,
                                    "sha256": blob_hash,
                                    "bytes": size,
                                }
                            )
                finally:
                    blob.unlink(missing_ok=True)
            if stream.read(1):
                _fail("Git cat-file batch emitted trailing bytes")
        return sorted(files, key=lambda item: str(item["path"])), sorted(
            symlinks, key=lambda item: str(item["path"])
        )
    finally:
        input_file.unlink(missing_ok=True)
        output_file.unlink(missing_ok=True)


def _snapshot_from_cache(
    runner: GitRunner,
    cache: Path,
    tree: str,
    destination: Path,
    staging_root: Path,
) -> dict[str, object]:
    destination.mkdir()
    listing_path = destination.parent / f".{destination.name}.ls-tree"
    try:
        runner.run_to_path(
            cache,
            ("ls-tree", "-rz", "--full-tree", "-r", tree),
            listing_path,
            limit=_MAX_TREE_BYTES,
            disk_root=staging_root,
            disk_limit=_MAX_PACKET_STAGING_BYTES,
        )
        blobs, gitlinks = _parse_tree(_read_bounded(listing_path, _MAX_TREE_BYTES))
        if len(blobs) + len(gitlinks) > _MAX_FILES:
            _fail("snapshot file count exceeded")
        files, symlinks = _materialize_blobs(runner, cache, destination, blobs, staging_root)
    finally:
        listing_path.unlink(missing_ok=True)
    return {"files": files, "symlinks": symlinks, "gitlinks": gitlinks}


def _expected_packet_manifest(
    root: Path,
    cache_root: Path,
    packet: Path,
    record: dict[str, Any],
    bindings_hash: str,
    runner: GitRunner,
) -> dict[str, Any]:
    policy_root = root / "benchmarks/real_world/pilot_v2"
    (packet / "policies").mkdir()
    for name in _CONTROL_FILES:
        shutil.copyfile(policy_root / name, packet / "policies" / name)
    (packet / "binding.json").write_bytes(_canonical(record))
    cache = _cache_path(cache_root, str(record["repository"]))
    snapshots: dict[str, object] = {}
    for side in ("baseline", "target"):
        snapshot = _snapshot_from_cache(
            runner,
            cache,
            str(record[f"{side}_tree"]),
            packet / side,
            packet.parent,
        )
        snapshots[side] = {"tree": record[f"{side}_tree"], **snapshot}
    diff_path = packet / "snapshot.diff"
    runner.run_to_path(
        cache,
        (
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            str(record["baseline_commit"]),
            str(record["target_commit"]),
        ),
        diff_path,
        limit=_MAX_DIFF_BYTES,
        disk_root=packet.parent,
        disk_limit=_MAX_PACKET_STAGING_BYTES,
    )
    diff_hash, diff_bytes = _hash_file(diff_path, _MAX_DIFF_BYTES)
    payload_files = _record_payload_files(packet, exclude={"packet-manifest.json"})
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "id": _PACKET_ID,
        "repository": record["repository"],
        "pr": record["pr"],
        "source_bindings_sha256": bindings_hash,
        "baseline_commit": record["baseline_commit"],
        "baseline_tree": record["baseline_tree"],
        "target_commit": record["target_commit"],
        "target_tree": record["target_tree"],
        "remote_diff_sha256": record["diff_sha256"],
        "remote_diff_bytes": record["diff_bytes"],
        "local_diff_sha256": diff_hash,
        "local_diff_bytes": diff_bytes,
        "snapshots": snapshots,
        "payload_files": payload_files,
        "payload_bytes": sum(cast("int", item["bytes"]) for item in payload_files),
        "packet_root_sha256": "",
    }
    manifest["packet_root_sha256"] = _manifest_root(manifest)
    return manifest


def _expected_packet_paths(manifest: dict[str, Any]) -> tuple[set[str], set[str]]:
    payload = manifest["payload_files"]
    if not isinstance(payload, list):
        _fail("packet payload inventory is invalid")
    files = {"packet-manifest.json"}
    for item in payload:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            _fail("packet payload item is invalid")
        files.add(cast("str", item["path"]))
    directories = {"baseline", "target", "policies"}
    for filename in files:
        for parent in PurePosixPath(filename).parents:
            if parent.as_posix() != ".":
                directories.add(parent.as_posix())
    return directories, files


def _validate_manifest_shape(
    manifest: dict[str, Any], record: dict[str, Any], bindings_hash: str
) -> None:
    if (
        set(manifest) != _PACKET_KEYS
        or manifest.get("schema_version") != 1
        or manifest.get("id") != _PACKET_ID
    ):
        _fail("packet manifest schema/id/keys mismatch")
    expected = {
        "repository": record["repository"],
        "pr": record["pr"],
        "source_bindings_sha256": bindings_hash,
        "baseline_commit": record["baseline_commit"],
        "baseline_tree": record["baseline_tree"],
        "target_commit": record["target_commit"],
        "target_tree": record["target_tree"],
        "remote_diff_sha256": record["diff_sha256"],
        "remote_diff_bytes": record["diff_bytes"],
    }
    if any(manifest.get(key) != value for key, value in expected.items()):
        _fail("packet semantic binding mismatch")
    if manifest.get("packet_root_sha256") != _manifest_root(manifest):
        _fail("packet semantic root hash mismatch")


def prepare_packets(
    root: Path,
    cache_root: Path,
    packet_root: Path,
    records: list[dict[str, Any]],
    bindings_hash: str,
) -> None:
    _require_separate_roots(cache_root, packet_root)
    if packet_root.exists():
        _fail("refusing to overwrite packet root")
    packet_root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _require_private_parent(packet_root)
    _preflight_disk(packet_root.parent, _MAX_PACKET_STAGING_BYTES)
    staging = Path(tempfile.mkdtemp(prefix=f".{packet_root.name}.", dir=packet_root.parent))
    staging.chmod(0o700)
    runner = GitRunner()
    try:
        with _validation_lock(cache_root):
            cache_identity = _directory_identity(cache_root)
            _validate_cache_unlocked(cache_root, records)
            for record in records:
                packet = staging / _packet_name(record)
                packet.mkdir()
                manifest = _expected_packet_manifest(
                    root, cache_root, packet, record, bindings_hash, runner
                )
                (packet / "packet-manifest.json").write_bytes(_canonical(manifest))
                _lstat_inventory(staging, byte_limit=_MAX_PACKET_STAGING_BYTES)
            if _directory_identity(cache_root) != cache_identity:
                _fail("cache root changed during packet preparation")
        _readonly(staging)
        with _validation_lock(cache_root):
            cache_identity = _directory_identity(cache_root)
            _validate_cache_unlocked(cache_root, records)
            _validate_packets_unlocked(
                staging,
                records,
                bindings_hash,
                source_root=root,
                cache_root=cache_root,
            )
            if _directory_identity(cache_root) != cache_identity:
                _fail("cache root changed during staged packet validation")
        with _publication_lock(packet_root):
            staging.rename(packet_root)
    except BaseException:
        _make_writable_for_cleanup(staging)
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _validate_packets_unlocked(  # noqa: PLR0912 - fail-closed packet reconciliation
    packet_root: Path,
    records: list[dict[str, Any]],
    bindings_hash: str,
    *,
    source_root: Path,
    cache_root: Path,
) -> None:
    _check_readonly_tree(packet_root)
    expected_names = {_packet_name(record) for record in records}
    root_dirs, root_files, _total = _lstat_inventory(
        packet_root, byte_limit=len(records) * _MAX_TOTAL_BYTES
    )
    top_dirs = {name for name in root_dirs if "/" not in name}
    top_files = {name for name in root_files if "/" not in name}
    if top_dirs != expected_names or top_files:
        _fail("packet root contains missing or extra entries")
    by_name = {_packet_name(record): record for record in records}
    for name in sorted(expected_names):
        packet = packet_root / name
        _check_readonly_tree(packet)
        manifest = _load_json_bounded(packet / "packet-manifest.json")
        record = by_name[name]
        _validate_manifest_shape(manifest, record, bindings_hash)
        if _read_bounded(packet / "binding.json", _MAX_MANIFEST_BYTES) != _canonical(record):
            _fail("packet binding bytes mismatch")
        files = _record_payload_files(packet, exclude={"packet-manifest.json"})
        if files != manifest.get("payload_files"):
            _fail("packet payload inventory mismatch")
        if sum(cast("int", item["bytes"]) for item in files) != manifest.get("payload_bytes"):
            _fail("packet payload total mismatch")
        expected_dirs, expected_files = _expected_packet_paths(manifest)
        actual_dirs, actual_files, _bytes = _lstat_inventory(packet, byte_limit=_MAX_TOTAL_BYTES)
        if actual_dirs != expected_dirs or actual_files != expected_files:
            _fail("packet contains unmanifested or missing entries")
        for relative in actual_dirs | actual_files:
            mode = (packet / relative).lstat().st_mode
            if stat.S_IMODE(mode) & 0o222 or (stat.S_ISREG(mode) and stat.S_IMODE(mode) & 0o111):
                _fail("packet permissions are not read-only/non-executable")
        policy_root = source_root / "benchmarks/real_world/pilot_v2"
        for policy_name in _CONTROL_FILES:
            if _read_bounded(packet / "policies" / policy_name, _MAX_MANIFEST_BYTES) != (
                _read_bounded(policy_root / policy_name, _MAX_MANIFEST_BYTES)
            ):
                _fail("packet policy bytes mismatch")
        _preflight_disk(packet_root.parent, 3 * 1024 * 1024 * 1024)
        with tempfile.TemporaryDirectory(
            prefix="pilot-packet-regenerate-", dir=packet_root.parent
        ) as name_temp:
            regenerated = Path(name_temp) / "packet"
            regenerated.mkdir()
            expected_manifest = _expected_packet_manifest(
                source_root,
                cache_root,
                regenerated,
                record,
                bindings_hash,
                GitRunner(),
            )
            if manifest != expected_manifest:
                _fail("packet differs from locked Git object regeneration")
        if _record_payload_files(packet, exclude={"packet-manifest.json"}) != files:
            _fail("packet changed during locked Git regeneration")
        if any(part == ".git" for item in files for part in PurePosixPath(str(item["path"])).parts):
            _fail("packet exposes Git control data")


def validate_packets(
    packet_root: Path,
    records: list[dict[str, Any]],
    bindings_hash: str,
    *,
    source_root: Path,
    cache_root: Path,
) -> None:
    _require_separate_roots(cache_root, packet_root)
    _require_private_parent(packet_root)
    with _validation_lock(cache_root), _validation_lock(packet_root):
        cache_identity = _directory_identity(cache_root)
        packet_identity = _directory_identity(packet_root)
        _validate_cache_unlocked(cache_root, records)
        _validate_packets_unlocked(
            packet_root,
            records,
            bindings_hash,
            source_root=source_root,
            cache_root=cache_root,
        )
        if _directory_identity(cache_root) != cache_identity:
            _fail("cache root changed during packet validation")
        if _directory_identity(packet_root) != packet_identity:
            _fail("packet root changed during validation")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--cache-root", required=True, type=Path)
    parser.add_argument("--packet-root", type=Path)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--prepare-cache", action="store_true")
    group.add_argument("--validate-cache", action="store_true")
    group.add_argument("--prepare-packets", action="store_true")
    group.add_argument("--validate-packets", action="store_true")
    args = parser.parse_args()
    records, bindings_hash = _binding_inputs(args.root)
    if args.prepare_cache:
        prepare_cache(args.cache_root, records)
    elif args.validate_cache:
        validate_cache(args.cache_root, records)
    elif args.prepare_packets:
        if args.packet_root is None:
            parser.error("--prepare-packets requires --packet-root")
        prepare_packets(args.root, args.cache_root, args.packet_root, records, bindings_hash)
    else:
        if args.packet_root is None:
            parser.error("--validate-packets requires --packet-root")
        validate_packets(
            args.packet_root,
            records,
            bindings_hash,
            source_root=args.root,
            cache_root=args.cache_root,
        )
    print(
        json.dumps(
            {
                "records": len(records),
                "cache_root": str(args.cache_root),
                "packet_root": str(args.packet_root) if args.packet_root else None,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
