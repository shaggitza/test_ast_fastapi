#!/usr/bin/env python3
"""Prepare and authenticate exact offline Git source for production-v1 campaigns."""

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, NoReturn, cast

from benchmarks.real_world import ground_truth_campaign_v1
from benchmarks.real_world.ground_truth_v2.schema import canonical_json

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Sequence
    from typing import IO

_PROFILE_DIR: Final = "benchmarks/real_world/production_v1"
_CHECKSUMS: Final = f"{_PROFILE_DIR}/checksums-v1.json"
_POLICY: Final = f"{_PROFILE_DIR}/source-policy-v1.json"
_SCHEMA: Final = f"{_PROFILE_DIR}/source-bindings-schema-v1.json"
_MODULE: Final = "benchmarks/real_world/ground_truth_source_v1.py"
_MAX_JSON: Final = 64 * 1024 * 1024
_MAX_COMMITS: Final = 100
_VALIDATION_COMMANDS_PER_COMMIT: Final = 3
_VALIDATION_FIXED_COMMANDS: Final = 13
_MAX_VALIDATION_COMMANDS: Final = (
    _VALIDATION_COMMANDS_PER_COMMIT * _MAX_COMMITS + _VALIDATION_FIXED_COMMANDS
)
_MAX_PREPARATION_COMMANDS: Final = 2 * _MAX_COMMITS + 2 + _MAX_VALIDATION_COMMANDS
_MAX_OUTPUT: Final = 8 * 1024 * 1024
_MAX_DISK: Final = 5 * 1024 * 1024 * 1024
_MAX_FILES: Final = 2_000_000
_MAX_PROCESSES: Final = 512
_COMMAND_TIMEOUT: Final = 180
_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class SourceV1Error(RuntimeError):
    """Raised when production source custody or identity is invalid."""


def _fail(message: str) -> NoReturn:
    raise SourceV1Error(message)


def _sha(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            _fail(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _constant(value: str) -> NoReturn:
    _fail(f"non-finite JSON is forbidden: {value}")


def _read_json(path: Path, *, modes: set[int]) -> tuple[dict[str, Any], bytes, os.stat_result]:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise SourceV1Error(f"cannot open {path}") from exc
    try:
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_uid != os.getuid()
            or stat.S_IMODE(status.st_mode) not in modes
        ):
            _fail(f"invalid JSON owner, type, or mode: {path}")
        raw = b""
        while len(raw) <= _MAX_JSON:
            chunk = os.read(descriptor, min(64 * 1024, _MAX_JSON + 1 - len(raw)))
            if not chunk:
                break
            raw += chunk
    finally:
        os.close(descriptor)
    if len(raw) > _MAX_JSON:
        _fail(f"JSON exceeds bound: {path}")
    try:
        value = json.loads(raw, object_pairs_hook=_unique, parse_constant=_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SourceV1Error(f"invalid JSON: {path}") from exc
    if not isinstance(value, dict):
        _fail(f"JSON root is not an object: {path}")
    return value, raw, status


def _strict(value: dict[str, Any], keys: set[str], label: str) -> None:
    if set(value) != keys:
        _fail(f"invalid {label} keys")


def _read_profile_file(path: Path) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise SourceV1Error(f"cannot open profile file: {path}") from exc
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_uid != os.getuid():
            _fail(f"invalid profile file: {path}")
        chunks: list[bytes] = []
        total = 0
        while total <= _MAX_JSON:
            chunk = os.read(descriptor, min(64 * 1024, _MAX_JSON + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    if len(raw) > _MAX_JSON:
        _fail(f"profile file exceeds bound: {path}")
    return raw


def _profile(root: Path) -> None:
    profile, _, _ = _read_json(root / _CHECKSUMS, modes={0o444, 0o644})
    _strict(profile, {"schema_version", "id", "files"}, "checksum profile")
    files = profile.get("files")
    required = {_MODULE, _POLICY, _SCHEMA}
    if (
        profile.get("schema_version") != 1
        or profile.get("id") != "ground-truth-production-checksums-v1"
        or not isinstance(files, dict)
        or not required <= set(files)
    ):
        _fail("unsupported source checksum profile")
    for relative in required:
        expected = files.get(relative)
        if not isinstance(expected, str) or not _DIGEST.fullmatch(expected):
            _fail("invalid source checksum")
        if _sha(_read_profile_file(root / relative)) != expected:
            _fail(f"source profile checksum mismatch: {relative}")


def _file_identity(status: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_uid,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def _campaign(root: Path, path: Path) -> tuple[dict[str, Any], bytes]:
    value, raw, opened = _read_json(path, modes={0o400})
    try:
        current = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise SourceV1Error("cannot restat campaign manifest") from exc
    if _file_identity(opened) != _file_identity(current):
        _fail("campaign manifest drifted while opening")
    try:
        ground_truth_campaign_v1.validate_manifest(root, value)
    except ground_truth_campaign_v1.CampaignV1Error as exc:
        raise SourceV1Error("campaign manifest authentication failed") from exc
    if canonical_json(value) != raw:
        _fail("campaign manifest is not canonical JSON")
    authorization = value.get("authorization")
    records = value.get("records")
    lanes = value.get("lanes")
    corpus = value.get("corpus")
    if (
        authorization
        != {
            "canonical_import_authorized": False,
            "live_launch_authorized": False,
            "source_packet_materialization_authorized": False,
        }
        or not isinstance(records, list)
        or len(records) != 50
        or not isinstance(lanes, list)
        or len(lanes) != 100
        or not isinstance(corpus, dict)
        or corpus.get("id") != "oss-expansion-50x50-lock-v2"
    ):
        _fail("campaign is not the canonical offline production slice")
    return value, raw


def _remote(repository: str) -> str:
    if not _REPOSITORY.fullmatch(repository):
        _fail("invalid repository")
    return f"https://github.com/{repository}.git"


def _expected_commits(campaign: dict[str, Any]) -> list[str]:
    records = campaign["records"]
    commits = {
        commit for row in records for commit in (row["baseline_commit"], row["target_commit"])
    }
    if not commits or len(commits) > 100 or any(not _SHA.fullmatch(item) for item in commits):
        _fail("campaign commit set is invalid")
    return sorted(commits)


_TEST_TRANSPORT_CAPABILITY = object()


class GitRunner:
    """Bounded argv-only Git runner with streaming output and disk enforcement."""

    def __init__(self, *, command_limit: int = _MAX_VALIDATION_COMMANDS) -> None:
        if command_limit < 1 or command_limit > _MAX_PREPARATION_COMMANDS:
            _fail("Git command limit is invalid")
        self.command_limit = command_limit
        self.commands = 0
        self.output_bytes = 0

    def run(
        self,
        git_dir: Path,
        args: Sequence[str],
        *,
        check: bool = True,
        network: bool = False,
        test_file_transport: bool = False,
        monitor_root: Path | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        self.commands += 1
        if self.commands > self.command_limit:
            _fail("Git command bound exceeded")
        argv = [
            "/usr/bin/prlimit",
            "--core=0",
            "--cpu=150",
            f"--fsize={_MAX_DISK}",
            "--nofile=256",
            f"--nproc={_MAX_PROCESSES}",
            "--",
            "git",
            "-c",
            "credential.helper=",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "protocol.allow=never",
            "-c",
            (
                "protocol.file.allow=always"
                if test_file_transport
                else "protocol.https.allow=always"
                if network
                else "protocol.file.allow=never"
            ),
            "--git-dir",
            str(git_dir),
            *args,
        ]
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": "/nonexistent",
            "LANG": "C",
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "/bin/false",
            "SSH_ASKPASS": "/bin/false",
            "GIT_SSH_COMMAND": "false",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_LFS_SKIP_SMUDGE": "1",
            "NO_PROXY": "github.com",
            "no_proxy": "github.com",
        }
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            start_new_session=True,
        )
        stdout, stderr = self._collect(process, monitor_root=monitor_root)
        result = subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)
        if check and result.returncode != 0:
            detail = result.stderr.decode("utf-8", "replace")[:500]
            raise SourceV1Error(f"Git command failed ({result.returncode}): {detail}")
        return result

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes]) -> None:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()

    def _collect(  # noqa: PLR0912,PLR0915
        self, process: subprocess.Popen[bytes], *, monitor_root: Path | None
    ) -> tuple[bytes, bytes]:
        if process.stdout is None or process.stderr is None:
            self._terminate(process)
            _fail("Git process pipes are unavailable")
        stdout = bytearray()
        stderr = bytearray()
        selector = selectors.DefaultSelector()
        started = time.monotonic()
        last_disk_check = 0.0
        for stream, label in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        try:
            while selector.get_map():
                now = time.monotonic()
                if now - started > _COMMAND_TIMEOUT:
                    self._terminate(process)
                    _fail("Git command timed out and process group was reaped")
                if monitor_root is not None and now - last_disk_check >= 0.05:
                    try:
                        _tree_bounds(monitor_root)
                    except SourceV1Error:
                        self._terminate(process)
                        raise
                    except OSError as exc:
                        self._terminate(process)
                        raise SourceV1Error(
                            "Git staging disk monitor failed and process group was reaped"
                        ) from exc
                    last_disk_check = now
                for key, _ in selector.select(timeout=0.05):
                    stream = cast("IO[bytes]", key.fileobj)
                    try:
                        chunk = os.read(stream.fileno(), 64 * 1024)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(stream)
                        stream.close()
                        continue
                    if len(chunk) > _MAX_OUTPUT - self.output_bytes:
                        self._terminate(process)
                        _fail("Git output bound exceeded and process group was reaped")
                    target = stdout if key.data == "stdout" else stderr
                    target.extend(chunk)
                    self.output_bytes += len(chunk)
            while process.poll() is None:
                now = time.monotonic()
                if now - started > _COMMAND_TIMEOUT:
                    self._terminate(process)
                    _fail("Git command timed out and process group was reaped")
                if monitor_root is not None:
                    try:
                        _tree_bounds(monitor_root)
                    except SourceV1Error:
                        self._terminate(process)
                        raise
                    except OSError as exc:
                        self._terminate(process)
                        raise SourceV1Error(
                            "Git staging disk monitor failed and process group was reaped"
                        ) from exc
                time.sleep(0.01)
            if monitor_root is not None:
                try:
                    _tree_bounds(monitor_root)
                except OSError as exc:
                    raise SourceV1Error("Git staging disk validation failed") from exc
        finally:
            selector.close()
            for stream in (process.stdout, process.stderr):
                if not stream.closed:
                    stream.close()
        return bytes(stdout), bytes(stderr)


def _tree_bounds(root: Path) -> tuple[int, int]:
    total = 0
    files = 0
    for directory, names, filenames in os.walk(root, followlinks=False):
        files += len(names) + len(filenames)
        if files > _MAX_FILES:
            _fail("cache file bound exceeded")
        for name in [*names, *filenames]:
            path = Path(directory, name)
            status = path.lstat()
            if stat.S_ISLNK(status.st_mode):
                _fail("cache contains a symlink")
            if stat.S_ISREG(status.st_mode):
                total += status.st_size
                if total > _MAX_DISK:
                    _fail("cache disk bound exceeded")
            elif not stat.S_ISDIR(status.st_mode):
                _fail("cache contains unsupported filesystem object")
    return total, files


def _file_digest(path: Path, expected: os.stat_result) -> str:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if _file_identity(opened) != _file_identity(expected):
            _fail("cache file drifted before inventory read")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_DISK:
                _fail("cache file exceeds disk bound")
            digest.update(chunk)
        after = os.fstat(descriptor)
        if _file_identity(opened) != _file_identity(after):
            _fail("cache file drifted during inventory read")
    finally:
        os.close(descriptor)
    return f"sha256:{digest.hexdigest()}"


def _inventory(cache: Path) -> dict[str, Any]:
    root_before = cache.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(root_before.st_mode)
        or root_before.st_uid != os.getuid()
        or stat.S_IMODE(root_before.st_mode) != 0o500
    ):
        _fail("cache root owner, type, or mode is invalid")
    digest = hashlib.sha256()
    file_count = 0
    disk_bytes = 0
    path_count = 1
    digest.update(canonical_json({"path": ".", "type": "directory", "mode": "0500"}))
    for directory, names, filenames in os.walk(cache, topdown=True, followlinks=False):
        names.sort()
        filenames.sort()
        base = Path(directory)
        for name in names:
            path = base / name
            status = path.lstat()
            if (
                not stat.S_ISDIR(status.st_mode)
                or status.st_uid != os.getuid()
                or stat.S_IMODE(status.st_mode) != 0o500
            ):
                _fail("cache directory owner, type, or mode is invalid")
            relative = path.relative_to(cache).as_posix()
            digest.update(canonical_json({"path": relative, "type": "directory", "mode": "0500"}))
            path_count += 1
            if path_count > _MAX_FILES:
                _fail("cache inventory path bound exceeded")
        for name in filenames:
            path = base / name
            status = path.lstat()
            if (
                not stat.S_ISREG(status.st_mode)
                or status.st_uid != os.getuid()
                or stat.S_IMODE(status.st_mode) != 0o400
            ):
                _fail("cache file owner, type, or mode is invalid")
            disk_bytes += status.st_size
            file_count += 1
            path_count += 1
            if path_count > _MAX_FILES or disk_bytes > _MAX_DISK:
                _fail("cache inventory bound exceeded")
            relative = path.relative_to(cache).as_posix()
            digest.update(
                canonical_json(
                    {
                        "path": relative,
                        "type": "file",
                        "mode": "0400",
                        "size": status.st_size,
                        "sha256": _file_digest(path, status),
                    }
                )
            )
    root_after = cache.stat(follow_symlinks=False)
    if _file_identity(root_before) != _file_identity(root_after):
        _fail("cache root drifted during inventory")
    return {
        "inventory_sha256": f"sha256:{digest.hexdigest()}",
        "inventory_path_count": path_count,
        "file_count": file_count,
        "disk_bytes": disk_bytes,
        "root_identity": list(_file_identity(root_after)),
    }


def _lines(raw: bytes) -> list[str]:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SourceV1Error("Git emitted non-ASCII identity output") from exc
    return [line for line in text.splitlines() if line]


def _git_text(runner: GitRunner, cache: Path, args: Sequence[str], *, check: bool = True) -> str:
    result = runner.run(cache, args, check=check)
    try:
        return result.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SourceV1Error("Git emitted invalid UTF-8") from exc


def _config(runner: GitRunner, cache: Path, key: str) -> str | None:
    result = runner.run(cache, ["config", "--local", "--get", key], check=False)
    if result.returncode == 1:
        return None
    if result.returncode != 0:
        _fail(f"cannot read Git config: {key}")
    return result.stdout.decode("utf-8", "strict").strip()


def _derive(runner: GitRunner, cache: Path, commits: list[str]) -> tuple[dict[str, str], set[str]]:
    trees: dict[str, str] = {}
    for commit in commits:
        kind = _git_text(runner, cache, ["cat-file", "-t", commit]).strip()
        if kind != "commit":
            _fail("expected commit is not a commit object")
        tree = _git_text(runner, cache, ["show", "-s", "--format=%T", commit]).strip()
        if not _SHA.fullmatch(tree):
            _fail("commit tree identity is invalid")
        if _git_text(runner, cache, ["cat-file", "-t", tree]).strip() != "tree":
            _fail("commit tree is unavailable")
        trees[commit] = tree
    expected_objects = set(
        _lines(
            runner.run(
                cache,
                ["rev-list", "--objects", "--no-object-names", *commits],
            ).stdout
        )
    )
    expected_objects.update(commits)
    actual_rows = _lines(
        runner.run(
            cache,
            ["cat-file", "--batch-all-objects", "--batch-check=%(objectname)"],
        ).stdout
    )
    actual_objects = set(actual_rows)
    if actual_objects != expected_objects:
        _fail("cache contains missing or unreachable extra Git objects")
    return trees, expected_objects


def _cache_summary(
    campaign: dict[str, Any],
    campaign_raw: bytes,
    cache: Path,
    runner: GitRunner,
    inventory: dict[str, Any],
) -> dict[str, Any]:
    assignment = campaign["assignment"]
    repository = assignment["repository"]
    commits = _expected_commits(campaign)
    expected_remote = _remote(repository)
    if _config(runner, cache, "core.bare") != "true":
        _fail("cache is not bare")
    if _config(runner, cache, "remote.origin.url") != expected_remote:
        _fail("cache remote differs from canonical HTTPS remote")
    forbidden_keys = (
        "remote.origin.promisor",
        "remote.origin.partialclonefilter",
        "extensions.partialclone",
        "core.alternateRefsCommand",
        "protocol.version",
    )
    if any(_config(runner, cache, key) is not None for key in forbidden_keys):
        _fail("cache contains forbidden promisor, partial, alternate, or protocol config")
    config_dump = _git_text(runner, cache, ["config", "--local", "--list"]).splitlines()
    allowed_prefixes = {
        "core.repositoryformatversion=0",
        "core.filemode=true",
        "core.bare=true",
        f"remote.origin.url={expected_remote}",
    }
    if set(config_dump) != allowed_prefixes:
        _fail("cache local config is not exact")
    refs = _git_text(runner, cache, ["for-each-ref", "--format=%(refname)"])
    if refs:
        _fail("cache contains refs")
    forbidden_paths = [
        "FETCH_HEAD",
        "ORIG_HEAD",
        "MERGE_HEAD",
        "CHERRY_PICK_HEAD",
        "REVERT_HEAD",
        "commondir",
        "gitdir",
        "objects/info/alternates",
    ]
    if any(
        (cache / relative).exists() or (cache / relative).is_symlink()
        for relative in forbidden_paths
    ):
        _fail("cache contains forbidden Git control file")
    replace = _git_text(runner, cache, ["replace", "-l"])
    if replace:
        _fail("cache contains replacement objects")
    shallow_path = cache / "shallow"
    try:
        shallow_rows = shallow_path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as exc:
        raise SourceV1Error("cache shallow boundary is unavailable") from exc
    if shallow_rows != sorted(set(shallow_rows)) or shallow_rows != commits:
        _fail("cache shallow boundary is not the exact canonical commit list")
    trees, objects = _derive(runner, cache, commits)
    fsck = runner.run(cache, ["fsck", "--strict", "--no-dangling"], check=False)
    if fsck.returncode != 0:
        detail = fsck.stderr.decode("utf-8", "replace")[:500]
        raise SourceV1Error(f"cache object closure failed fsck: {detail}")
    content = {
        "schema_version": 1,
        "repository": repository,
        "remote": expected_remote,
        "campaign_manifest_sha256": _sha(campaign_raw),
        "commits": [{"commit": commit, "tree": trees[commit]} for commit in commits],
        "object_count": len(objects),
        "inventory_sha256": inventory["inventory_sha256"],
        "inventory_path_count": inventory["inventory_path_count"],
        "disk_bytes": inventory["disk_bytes"],
        "file_count": inventory["file_count"],
    }
    return {**content, "content_sha256": _sha(canonical_json(content))}


def _validate_modes(cache: Path) -> None:
    root_status = cache.lstat()
    if (
        not stat.S_ISDIR(root_status.st_mode)
        or root_status.st_uid != os.getuid()
        or stat.S_IMODE(root_status.st_mode) != 0o500
    ):
        _fail("cache root owner, type, or mode is invalid")
    for directory, names, filenames in os.walk(cache, followlinks=False):
        directory_path = Path(directory)
        for name in names:
            status = (directory_path / name).lstat()
            if (
                not stat.S_ISDIR(status.st_mode)
                or status.st_uid != os.getuid()
                or stat.S_IMODE(status.st_mode) != 0o500
            ):
                _fail("cache directory owner, type, or mode is invalid")
        for name in filenames:
            status = (directory_path / name).lstat()
            if (
                not stat.S_ISREG(status.st_mode)
                or status.st_uid != os.getuid()
                or stat.S_IMODE(status.st_mode) != 0o400
            ):
                _fail("cache file owner, type, or mode is invalid")


def _directory_identity(path: Path) -> tuple[int, int, int, int]:
    status = path.stat(follow_symlinks=False)
    return status.st_dev, status.st_ino, status.st_mode, status.st_uid


def _root_identity(path: Path) -> tuple[int, int, int, int, int, int]:
    status = path.stat(follow_symlinks=False)
    return (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_uid,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def validate_cache(root: Path, campaign_path: Path, cache: Path) -> dict[str, Any]:
    _profile(root)
    campaign, campaign_raw = _campaign(root, campaign_path)
    if not cache.is_absolute():
        _fail("cache path must be absolute")
    _private_existing_parent(cache.parent)
    before = _root_identity(cache)
    inventory_before = _inventory(cache)
    runner = GitRunner(command_limit=_MAX_VALIDATION_COMMANDS)
    summary = _cache_summary(campaign, campaign_raw, cache, runner, inventory_before)
    inventory_after = _inventory(cache)
    after = _root_identity(cache)
    if before != after or inventory_before != inventory_after:
        _fail("cache identity or complete inventory drifted during validation")
    return {
        **summary,
        "cache_device": before[0],
        "cache_inode": before[1],
        "validated_offline": True,
        "commands": runner.commands,
    }


def _freeze(root: Path) -> None:
    paths: list[Path] = []
    for directory, names, filenames in os.walk(root, topdown=False, followlinks=False):
        base = Path(directory)
        for name in filenames:
            path = base / name
            if path.is_symlink() or not path.is_file():
                _fail("staging cache contains unsupported file")
            path.chmod(0o400, follow_symlinks=False)
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        for name in names:
            path = base / name
            if path.is_symlink() or not path.is_dir():
                _fail("staging cache contains unsupported directory")
            paths.append(path)
    for path in paths:
        path.chmod(0o500, follow_symlinks=False)
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    root.chmod(0o500, follow_symlinks=False)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _reject_symlink_ancestors(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            status = current.lstat()
        except OSError as exc:
            raise SourceV1Error(f"cannot inspect path ancestor: {current}") from exc
        if stat.S_ISLNK(status.st_mode):
            _fail(f"path ancestor is a symlink: {current}")


def _private_existing_parent(parent: Path) -> Path:
    if not parent.is_absolute():
        _fail("cache parent must be absolute")
    _reject_symlink_ancestors(parent)
    status = parent.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(status.st_mode)
        or status.st_uid != os.getuid()
        or stat.S_IMODE(status.st_mode) != 0o700
    ):
        _fail("cache parent must be private current-UID mode 0700")
    return parent


def _private_parent(path: Path) -> Path:
    if not path.is_absolute() or path.exists() or path.is_symlink():
        _fail("cache output must be an absent absolute path")
    return _private_existing_parent(path.parent)


@contextmanager
def _lock(parent: Path) -> Iterator[None]:
    lock_path = parent / ".source-cache.lock"
    descriptor = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_uid != os.getuid():
            _fail("invalid source cache lock")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _rename_noreplace(source: Path, target: Path, parent_descriptor: int | None = None) -> None:
    if source.parent != target.parent:
        _fail("atomic cache publication requires one parent directory")
    owned_descriptor = parent_descriptor is None
    descriptor = (
        os.open(
            target.parent,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
        )
        if owned_descriptor
        else parent_descriptor
    )
    assert descriptor is not None
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = libc.renameat2
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            descriptor,
            os.fsencode(source.name),
            descriptor,
            os.fsencode(target.name),
            1,
        )
        if result == 0:
            return
        error = ctypes.get_errno()
        if error in {errno.EEXIST, errno.ENOTEMPTY}:
            _fail("cache output already exists at atomic publication")
        raise SourceV1Error(f"atomic no-replace cache publication failed: errno {error}")
    finally:
        if owned_descriptor:
            os.close(descriptor)


def _remove_init_extras(cache: Path) -> None:
    for relative in ("hooks", "branches"):
        path = cache / relative
        if path.exists():
            shutil.rmtree(path)
    exclude = cache / "info" / "exclude"
    if exclude.exists():
        exclude.unlink()


def _clear_failed_fetch_locks(staging: Path) -> None:
    for relative in ("shallow.lock", "FETCH_HEAD.lock", "packed-refs.lock", "config.lock"):
        path = staging / relative
        try:
            status = path.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(status.st_mode) or status.st_uid != os.getuid():
            _fail("failed fetch left an unsafe lock file")
        path.unlink()


def _fetch_commit(
    runner: GitRunner,
    staging: Path,
    transport: str,
    commit: str,
    *,
    test_transport: bool,
) -> None:
    last_error: SourceV1Error | None = None
    for retry in range(2):
        try:
            runner.run(
                staging,
                ["fetch", "--depth=1", "--no-tags", transport, commit],
                network=not test_transport,
                test_file_transport=test_transport,
                monitor_root=staging,
            )
            last_error = None
            break
        except SourceV1Error as exc:
            last_error = exc
            if retry == 0:
                _clear_failed_fetch_locks(staging)
                time.sleep(1)
    if last_error is not None:
        raise last_error
    fetch_head = staging / "FETCH_HEAD"
    if fetch_head.exists():
        fetch_head.unlink()
    _tree_bounds(staging)


def _populate_staging(
    staging: Path,
    campaign: dict[str, Any],
    campaign_raw: bytes,
    commits: list[str],
    transport: str,
    canonical_remote: str,
    runner: GitRunner,
    *,
    test_transport: bool,
) -> dict[str, Any]:
    runner.run(staging, ["init", "--bare"], monitor_root=staging)
    for commit in commits:
        _fetch_commit(runner, staging, transport, commit, test_transport=test_transport)
    runner.run(
        staging,
        ["config", "--local", "remote.origin.url", canonical_remote],
        monitor_root=staging,
    )
    _remove_init_extras(staging)
    _freeze(staging)
    inventory_before = _inventory(staging)
    summary = _cache_summary(campaign, campaign_raw, staging, runner, inventory_before)
    inventory_after = _inventory(staging)
    if inventory_before != inventory_after:
        _fail("staging cache inventory drifted during validation")
    return summary


def _remove_tree(path: Path) -> None:
    for directory, names, _ in os.walk(path, topdown=False, followlinks=False):
        base = Path(directory)
        for name in names:
            with suppress(OSError):
                (base / name).chmod(0o700, follow_symlinks=False)
        with suppress(OSError):
            base.chmod(0o700, follow_symlinks=False)
    shutil.rmtree(path, ignore_errors=True)


def prepare_cache(
    root: Path,
    campaign_path: Path,
    cache: Path,
    *,
    runner_factory: Callable[[], GitRunner] | None = None,
    _test_transport: tuple[str, object] | None = None,
) -> dict[str, Any]:
    _profile(root)
    campaign, campaign_raw = _campaign(root, campaign_path)
    parent = _private_parent(cache)
    repository = campaign["assignment"]["repository"]
    canonical_remote = _remote(repository)
    if _test_transport is None:
        transport = canonical_remote
        test_transport = False
    else:
        transport, capability = _test_transport
        if capability is not _TEST_TRANSPORT_CAPABILITY or not transport:
            _fail("invalid test-only transport capability")
        test_transport = True
    commits = _expected_commits(campaign)
    parent_identity = _directory_identity(parent)
    with _lock(parent):
        parent_descriptor = os.open(
            parent,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            opened_parent = os.fstat(parent_descriptor)
            if (
                _directory_identity(parent) != parent_identity
                or (
                    opened_parent.st_dev,
                    opened_parent.st_ino,
                    opened_parent.st_mode,
                    opened_parent.st_uid,
                )
                != parent_identity
            ):
                _fail("cache parent identity drifted before preparation")
            if cache.exists() or cache.is_symlink():
                _fail("cache output already exists")
            staging = Path(tempfile.mkdtemp(prefix=f".{cache.name}.", dir=parent))
            runner = (
                GitRunner(command_limit=_MAX_PREPARATION_COMMANDS)
                if runner_factory is None
                else runner_factory()
            )
            if runner.command_limit < _MAX_PREPARATION_COMMANDS:
                _fail("preparation runner command limit is insufficient")
            try:
                summary = _populate_staging(
                    staging,
                    campaign,
                    campaign_raw,
                    commits,
                    transport,
                    canonical_remote,
                    runner,
                    test_transport=test_transport,
                )
                _rename_noreplace(staging, cache, parent_descriptor)
                os.fsync(parent_descriptor)
                if _directory_identity(parent) != parent_identity:
                    _fail("cache parent identity drifted during publication")
            except BaseException:
                if staging.exists():
                    _remove_tree(staging)
                raise
        finally:
            os.close(parent_descriptor)
    validated = validate_cache(root, campaign_path, cache)
    if validated["content_sha256"] != summary["content_sha256"]:
        _fail("published cache differs from staged cache")
    return validated


def _binding_payload(
    campaign: dict[str, Any], campaign_raw: bytes, cache: dict[str, Any]
) -> dict[str, Any]:
    trees = {row["commit"]: row["tree"] for row in cache["commits"]}
    records = []
    for row in campaign["records"]:
        records.append(
            {
                "rank": row["rank"],
                "repository": row["repository"],
                "pr": row["pr"],
                "baseline_commit": row["baseline_commit"],
                "baseline_tree": trees[row["baseline_commit"]],
                "target_commit": row["target_commit"],
                "target_tree": trees[row["target_commit"]],
                "diff_sha256": row["diff_sha256"],
                "diff_bytes": row["diff_bytes"],
                "diff_final_url": row["diff_final_url"],
                "diff_content_type": row["diff_content_type"],
                "source_state": "cache_validated_packets_pending",
                "review_state": "pending",
            }
        )
    return {
        "schema_version": 1,
        "id": f"{campaign['id']}-source-bindings-v1",
        "authorization": {
            "packet_materialization_authorized": False,
            "live_launch_authorized": False,
            "canonical_import_authorized": False,
        },
        "campaign_manifest_sha256": _sha(campaign_raw),
        "campaign_id": campaign["id"],
        "corpus_id": campaign["corpus"]["id"],
        "repository": campaign["assignment"]["repository"],
        "cache": {
            "logical_id": f"{campaign['id']}-exact-git-cache-v1",
            "device": cache["cache_device"],
            "inode": cache["cache_inode"],
            "content_sha256": cache["content_sha256"],
            "remote": cache["remote"],
            "commit_count": len(cache["commits"]),
            "object_count": cache["object_count"],
            "inventory_sha256": cache["inventory_sha256"],
            "inventory_path_count": cache["inventory_path_count"],
            "file_count": cache["file_count"],
            "disk_bytes": cache["disk_bytes"],
        },
        "records": records,
    }


def _publish(path: Path, value: dict[str, Any]) -> None:
    if not path.is_absolute() or path.exists() or path.is_symlink():
        _fail("binding output must be an absent absolute path")
    _reject_symlink_ancestors(path.parent)
    parent_before = _directory_identity(path.parent)
    status = path.parent.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(status.st_mode)
        or status.st_uid != os.getuid()
        or stat.S_IMODE(status.st_mode) != 0o700
    ):
        _fail("binding parent must be private mode 0700")
    raw = canonical_json(value)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o400,
    )
    try:
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if _directory_identity(path.parent) != parent_before:
        _fail("binding parent identity drifted during publication")


def _require_bound_inventory(cache: dict[str, Any], inventory: dict[str, Any]) -> None:
    for key in ("inventory_sha256", "inventory_path_count", "file_count", "disk_bytes"):
        if cache.get(key) != inventory.get(key):
            _fail("cache inventory differs from authenticated cache summary")
    root = inventory["root_identity"]
    if cache.get("cache_device") != root[0] or cache.get("cache_inode") != root[1]:
        _fail("cache root identity differs from authenticated cache summary")


def build_source_bindings(
    root: Path, campaign_path: Path, cache_path: Path, output: Path
) -> dict[str, Any]:
    cache = validate_cache(root, campaign_path, cache_path)
    campaign, campaign_raw = _campaign(root, campaign_path)
    if _sha(campaign_raw) != cache["campaign_manifest_sha256"]:
        _fail("campaign drifted between cache validation and binding publication")
    inventory_before = _inventory(cache_path)
    _require_bound_inventory(cache, inventory_before)
    value = _binding_payload(campaign, campaign_raw, cache)
    _publish(output, value)
    inventory_after = _inventory(cache_path)
    if inventory_before != inventory_after:
        _fail("cache inventory drifted around source binding publication")
    _require_bound_inventory(cache, inventory_after)
    return {"output": str(output), "sha256": _sha(canonical_json(value)), "records": 50}


def validate_source_bindings(
    root: Path, campaign_path: Path, cache_path: Path, binding_path: Path
) -> dict[str, Any]:
    cache = validate_cache(root, campaign_path, cache_path)
    inventory_before = _inventory(cache_path)
    _require_bound_inventory(cache, inventory_before)
    campaign, campaign_raw = _campaign(root, campaign_path)
    if _sha(campaign_raw) != cache["campaign_manifest_sha256"]:
        _fail("campaign drifted between cache and binding validation")
    value, raw, opened = _read_json(binding_path, modes={0o400})
    expected = _binding_payload(campaign, campaign_raw, cache)
    if value != expected or raw != canonical_json(expected):
        _fail("source bindings differ from authenticated campaign and cache")
    current = binding_path.stat(follow_symlinks=False)
    if (opened.st_dev, opened.st_ino, opened.st_ctime_ns) != (
        current.st_dev,
        current.st_ino,
        current.st_ctime_ns,
    ):
        _fail("source bindings drifted while validating")
    inventory_after = _inventory(cache_path)
    if inventory_before != inventory_after:
        _fail("cache inventory drifted around source binding validation")
    _require_bound_inventory(cache, inventory_after)
    return {
        "valid": True,
        "sha256": _sha(raw),
        "records": len(value["records"]),
        "commit_count": value["cache"]["commit_count"],
        "live_launch_authorized": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    sub = parser.add_subparsers(dest="command", required=True)
    for name in (
        "prepare-cache",
        "validate-cache",
        "build-source-bindings",
        "validate-source-bindings",
    ):
        command = sub.add_parser(name)
        command.add_argument("--campaign", type=Path, required=True)
        command.add_argument("--cache", type=Path, required=True)
        if name == "build-source-bindings":
            command.add_argument("--output", type=Path, required=True)
        if name == "validate-source-bindings":
            command.add_argument("--bindings", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = args.root.resolve(strict=True)
    if args.command == "prepare-cache":
        result = prepare_cache(root, args.campaign, args.cache)
    elif args.command == "validate-cache":
        result = validate_cache(root, args.campaign, args.cache)
    elif args.command == "build-source-bindings":
        result = build_source_bindings(root, args.campaign, args.cache, args.output)
    else:
        result = validate_source_bindings(root, args.campaign, args.cache, args.bindings)
    print(canonical_json(result).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
