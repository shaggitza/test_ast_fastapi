#!/usr/bin/env python3
"""Immutable, false-authority broker-bundle governance for a new lineage."""

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import threading
from contextlib import contextmanager, suppress
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, Final, Literal, NoReturn, cast

from benchmarks.real_world import ground_truth_run_v1 as run_v1
from benchmarks.real_world import ground_truth_submit_v1 as submit_v1
from benchmarks.real_world.ground_truth_v2.schema import canonical_json

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

_MAX_FILE: Final = 8 * 1024 * 1024
_MAX_FILES: Final = 64
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_LINEAGE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
_BUNDLE_PROTOCOL: Final = "ground-truth-broker-bundle-v1"
_RECEIPT_PROTOCOL: Final = "ground-truth-broker-bundle-receipt-v1"
_FREEZE_PROTOCOL: Final = "ground-truth-broker-prepare-freeze-v1"
_PHASE_PROTOCOL: Final = "ground-truth-broker-freeze-phase-v1"
_ROOT_PROTOCOL: Final = "ground-truth-broker-new-lineage-root-v1"
_LAUNCH_PROFILE_PROTOCOL: Final = "ground-truth-broker-launch-profile-v1"
_BUNDLE_DOMAIN: Final = b"ground-truth-broker-bundle-v1\0"
_RUNTIME_DOMAINS: Final = {
    "ground-truth-runtime-attestation-v1": b"ground-truth-runtime-attestation-v1\0",
    "ground-truth-runtime-attestation-supersession-v1": (
        b"ground-truth-runtime-attestation-supersession-v1\0"
    ),
}
_FREEZE_PHASES: Final = ("prepared", "launch_claimed", "pre_escrow")
_ROOT_MARKER: Final = ".broker-new-lineage-root-v1.json"
_ROOT_LOCK: Final = ".broker-new-lineage-root-v1.lock"
_RECEIPT_NAME: Final = ".bundle-receipt-v1.json"
_ACTIVE_LOCKS = threading.local()
_PROTECTED_PARTS: Final = {
    "production_v1",
    "ledger-v7",
    "ledger_v7",
    "escrow",
    "reviews",
    "labels",
}


class BrokerBundleError(RuntimeError):
    """Fail-closed immutable broker-bundle error."""


def _fail(message: str) -> NoReturn:
    raise BrokerBundleError(message)


def _sha(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _strict_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        _fail(f"{label} keys are invalid")


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate JSON key")
        result[key] = value
    return result


def _constant(value: str) -> NoReturn:
    _fail(f"non-finite JSON value: {value}")


def _root_identity(value: os.stat_result) -> tuple[int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid)


def _identity(value: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _normalized_absolute(path: Path, label: str) -> None:
    if not path.is_absolute() or os.path.normpath(str(path)) != str(path) or ".." in path.parts:
        _fail(f"{label} must be normalized absolute")


def _descriptor_walk(path: Path) -> tuple[int, os.stat_result]:
    """Open every path component without following aliases and return the leaf fd."""
    _normalized_absolute(path, "path")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            following = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = following
        return descriptor, os.fstat(descriptor)
    except OSError as error:
        os.close(descriptor)
        raise BrokerBundleError(f"descriptor walk rejected {path}: {error}") from error


def _open_file(path: Path, *, modes: set[int]) -> tuple[int, os.stat_result]:
    _normalized_absolute(path, "input path")
    parent_fd, _ = _descriptor_walk(path.parent)
    try:
        descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=parent_fd,
        )
    except OSError as error:
        raise BrokerBundleError(f"cannot read exact input {path}: {error}") from error
    finally:
        os.close(parent_fd)
    status = os.fstat(descriptor)
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_uid != os.getuid()
        or status.st_nlink != 1
        or stat.S_IMODE(status.st_mode) not in modes
        or status.st_size > _MAX_FILE
    ):
        os.close(descriptor)
        _fail(f"input is not an exact owned regular file: {path}")
    return descriptor, status


def _read_fd(descriptor: int, status: os.stat_result, label: str) -> bytes:
    chunks: list[bytes] = []
    os.lseek(descriptor, 0, os.SEEK_SET)
    remaining = _MAX_FILE + 1
    while remaining:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    if len(raw) != status.st_size or _identity(os.fstat(descriptor)) != _identity(status):
        _fail(f"{label} changed while reading")
    return raw


def _owned_bytes(path: Path, *, modes: set[int] | None = None) -> bytes:
    descriptor, status = _open_file(path, modes=modes or {0o400, 0o444, 0o600, 0o644})
    try:
        raw = _read_fd(descriptor, status, str(path))
        parent_fd, _ = _descriptor_walk(path.parent)
        try:
            current = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        finally:
            os.close(parent_fd)
        if _identity(current) != _identity(status):
            _fail(f"input changed while reading: {path}")
        return raw
    except OSError as error:
        raise BrokerBundleError(f"cannot read exact input {path}: {error}") from error
    finally:
        os.close(descriptor)


def _json_raw(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=_unique, parse_constant=_constant)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, RecursionError) as error:
        raise BrokerBundleError(f"invalid JSON: {label}") from error
    if not isinstance(value, dict) or canonical_json(value) != raw:
        _fail(f"JSON is not a canonical object: {label}")
    return cast("dict[str, Any]", value)


def _json_file(path: Path, *, modes: set[int] | None = None) -> tuple[dict[str, Any], bytes]:
    raw = _owned_bytes(path, modes=modes)
    return _json_raw(raw, str(path)), raw


def _safe_relative(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or "\x00" in value
        or value.startswith("/")
    ):
        _fail("bundle source path is unsafe")
    normalized = PurePosixPath(value)
    if normalized.as_posix() != value or any(part in {"", ".", ".."} for part in normalized.parts):
        _fail("bundle source path is unsafe")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        _fail(f"{label} is not a SHA-256 digest")
    return value


def _false_authority_map() -> dict[str, bool]:
    """Return a fresh, non-authorizing map; callers never share mutable authority state."""
    return {
        "review_launch": False,
        "escrow": False,
        "adjudication": False,
        "canonical_import": False,
    }


def _false_authority(value: object, label: str) -> None:
    if (
        not isinstance(value, dict)
        or frozenset(value)
        != frozenset(("review_launch", "escrow", "adjudication", "canonical_import"))
        or any(item is not False for item in value.values())
    ):
        _fail(f"{label} authority map is invalid")


def _lineage(value: object) -> str:
    if not isinstance(value, str) or not _LINEAGE.fullmatch(value):
        _fail("lineage_id is invalid")
    return value


def _absolute_string(value: object, label: str) -> str:
    if not isinstance(value, str):
        _fail(f"{label} is invalid")
    _normalized_absolute(Path(value), label)
    return value


def _exact_int(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        _fail(f"{label} is invalid")
    return value


def _launch_profile(value: dict[str, Any]) -> None:
    _strict_keys(
        value,
        {
            "schema_version",
            "protocol",
            "provider",
            "model",
            "model_version",
            "client_version",
            "decoding",
            "tools",
            "agent_sha256",
            "broker_entrypoint",
            "broker_entrypoint_sha256",
        },
        "launch profile",
    )
    _exact_int(value["schema_version"], "launch profile schema", minimum=1)
    if value["schema_version"] != 1 or value["protocol"] != _LAUNCH_PROFILE_PROTOCOL:
        _fail("launch profile protocol is invalid")
    for field in ("provider", "model", "model_version", "client_version"):
        if not isinstance(value[field], str) or not value[field] or len(value[field]) > 256:
            _fail(f"launch profile {field} is invalid")
    if not isinstance(value["decoding"], dict):
        _fail("launch profile decoding is invalid")
    canonical_json(value["decoding"])
    tools = value["tools"]
    if (
        not isinstance(tools, list)
        or not tools
        or len(tools) > 32
        or any(not isinstance(item, str) or not item or len(item) > 128 for item in tools)
        or len(set(tools)) != len(tools)
    ):
        _fail("launch profile tools are invalid")
    _digest(value["agent_sha256"], "launch profile agent_sha256")
    _safe_relative(value["broker_entrypoint"])
    _digest(value["broker_entrypoint_sha256"], "launch profile broker entrypoint")


def _production_profile(value: dict[str, Any], raw: bytes) -> tuple[str, str]:
    _strict_keys(value, {"schema_version", "id", "files"}, "production profile")
    files = value["files"]
    _exact_int(value["schema_version"], "production profile schema", minimum=1)
    if (
        value["schema_version"] != 1
        or value["id"] != "ground-truth-production-checksums-v1"
        or not isinstance(files, dict)
        or not files
        or len(files) > 512
    ):
        _fail("production profile is invalid")
    for path, digest in files.items():
        _safe_relative(path)
        _digest(digest, "production profile file")
    return _sha(raw), _sha(canonical_json(files))


def _runtime_attestation(value: dict[str, Any], raw: bytes) -> None:
    protocol = value.get("protocol")
    if value.get("schema_version") != 2 or protocol not in _RUNTIME_DOMAINS:
        _fail("runtime attestation version is unsupported")
    expected = {
        "schema_version",
        "protocol",
        "campaign_id",
        "campaign_manifest_sha256",
        "campaign_lanes_sha256",
        "source_bindings_sha256",
        "packet_publication_entry_hash",
        "runtime_custody_receipt_path",
        "runtime_custody_receipt_sha256",
        "production_profile_sha256",
        "production_files_sha256",
        "runtime_identity",
        "extension_sha256",
        "extension_schema_sha256",
        "agent_source_sha256",
        "execution_root",
        "execution_device",
        "execution_inode",
        "attested_at",
        "authorizations",
        "previous_hash",
        "entry_hash",
    }
    if protocol == "ground-truth-runtime-attestation-supersession-v1":
        expected.add("supersedes_entry_hash")
    _strict_keys(value, expected, "runtime attestation")
    try:
        run_v1._validate_runtime_identity(value["runtime_identity"])
    except run_v1.GroundTruthRunError as error:
        raise BrokerBundleError("runtime attestation identity is invalid") from error
    for field in (
        "campaign_manifest_sha256",
        "campaign_lanes_sha256",
        "source_bindings_sha256",
        "packet_publication_entry_hash",
        "runtime_custody_receipt_sha256",
        "production_profile_sha256",
        "production_files_sha256",
        "extension_sha256",
        "extension_schema_sha256",
        "agent_source_sha256",
        "previous_hash",
        "entry_hash",
    ):
        _digest(value[field], f"runtime {field}")
    if "supersedes_entry_hash" in value:
        _digest(value["supersedes_entry_hash"], "runtime supersedes")
    _exact_int(value["execution_device"], "runtime execution device")
    _exact_int(value["execution_inode"], "runtime execution inode", minimum=1)
    if (
        not isinstance(value["campaign_id"], str)
        or not value["campaign_id"]
        or not isinstance(value["attested_at"], str)
        or not _TIMESTAMP.fullmatch(value["attested_at"])
    ):
        _fail("runtime attestation metadata is invalid")
    try:
        datetime.fromisoformat(value["attested_at"].replace("Z", "+00:00"))
    except ValueError as error:
        raise BrokerBundleError("runtime attestation timestamp is invalid") from error
    _absolute_string(value["runtime_custody_receipt_path"], "runtime custody path")
    _absolute_string(value["execution_root"], "runtime execution root")
    if value["authorizations"] != {
        "review_launch": False,
        "adjudication": False,
        "canonical_import": False,
    }:
        _fail("runtime attestation authority is invalid")
    body = {key: item for key, item in value.items() if key != "entry_hash"}
    if value["entry_hash"] != _sha(_RUNTIME_DOMAINS[cast("str", protocol)] + canonical_json(body)):
        _fail("runtime attestation entry hash is invalid")
    if canonical_json(value) != raw:
        _fail("runtime attestation is not canonical")


def _control_snapshot(
    runtime_attestation: Path, binding: Path, production_profile: Path, launch_profile: Path
) -> dict[str, Any]:
    runtime, runtime_raw = _json_file(runtime_attestation)
    bindings, binding_raw = _json_file(binding)
    production, profile_raw = _json_file(production_profile)
    launch, launch_raw = _json_file(launch_profile)
    _runtime_attestation(runtime, runtime_raw)
    profile_checksum, profile_files = _production_profile(production, profile_raw)
    _launch_profile(launch)
    try:
        parsed = submit_v1.SubmissionBindings.model_validate(bindings)
    except (ValueError, RecursionError, MemoryError) as error:
        raise BrokerBundleError("submission binding is invalid") from error
    record = parsed.records[0]
    if (
        record.runtime_attestation_entry_hash != runtime["entry_hash"]
        or record.profile_checksum_sha256 != profile_checksum
        or record.profile_files_sha256 != profile_files
        or runtime["production_profile_sha256"] != profile_checksum
        or runtime["production_files_sha256"] != profile_files
    ):
        _fail("runtime, binding, and production profile are not exactly coupled")
    return {
        "runtime_attestation_entry_hash": runtime["entry_hash"],
        "runtime_attestation_sha256": _sha(runtime_raw),
        "binding_sha256": _sha(binding_raw),
        "production_profile_sha256": profile_checksum,
        "launch_profile_sha256": _sha(launch_raw),
        "launch_profile": launch,
        "raw": {
            "runtime-attestation.json": runtime_raw,
            "binding.json": binding_raw,
            "production-profile.json": profile_raw,
            "launch-profile.json": launch_raw,
        },
    }


def _reject_protected_destination(path: Path, label: str) -> None:
    _normalized_absolute(path, label)
    if any(part.casefold() in _PROTECTED_PARTS for part in path.parts):
        _fail("protected historical destination is forbidden")


def _fsync(descriptor: int, _label: str) -> None:
    """Durability seam used by focused order-injection tests."""
    os.fsync(descriptor)


def _write_all(descriptor: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            _fail("staged file write failed")
        view = view[written:]


def _exists_at(parent_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def _rename_noreplace_at(parent_fd: int, source: str, target: str) -> None:
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
    if renameat2(parent_fd, os.fsencode(source), parent_fd, os.fsencode(target), 1) == 0:
        return
    error = ctypes.get_errno()
    if error in {errno.EEXIST, errno.ENOTEMPTY}:
        _fail("output already exists at atomic publication")
    _fail(f"atomic no-replace publication failed: errno {error}")


def _verify_live_root(root: Path, root_fd: int, expected: os.stat_result) -> None:
    live_fd, live_status = _descriptor_walk(root)
    try:
        if (
            _root_identity(live_status) != _root_identity(expected)
            or _root_identity(os.fstat(root_fd)) != _root_identity(expected)
        ):
            _fail("lineage root changed during operation")
    finally:
        os.close(live_fd)


def _atomic_at(
    root: Path,
    root_fd: int,
    root_status: os.stat_result,
    name: str,
    value: dict[str, Any],
    *,
    mode: int = 0o400,
) -> None:
    temporary = f".{name}.{secrets.token_hex(12)}"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=root_fd,
        )
        _write_all(descriptor, canonical_json(value))
        os.fchmod(descriptor, mode)
        _fsync(descriptor, f"file:{name}")
        os.close(descriptor)
        descriptor = None
        _verify_live_root(root, root_fd, root_status)
        _rename_noreplace_at(root_fd, temporary, name)
        _fsync(root_fd, f"directory:{root}")
    except OSError as error:
        raise BrokerBundleError(f"cannot publish {name}: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with suppress(FileNotFoundError):
            os.unlink(temporary, dir_fd=root_fd)


def _relative_bytes(root_fd: int, name: str, *, modes: set[int]) -> bytes:
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        dir_fd=root_fd,
    )
    try:
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_uid != os.getuid()
            or status.st_nlink != 1
            or stat.S_IMODE(status.st_mode) not in modes
            or status.st_size > _MAX_FILE
        ):
            _fail(f"input is not an exact owned regular file: {name}")
        raw = _read_fd(descriptor, status, name)
        if _identity(os.stat(name, dir_fd=root_fd, follow_symlinks=False)) != _identity(status):
            _fail(f"input changed while reading: {name}")
        return raw
    finally:
        os.close(descriptor)


def _root_marker_body(root: Path, status: os.stat_result, lineage_id: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "protocol": _ROOT_PROTOCOL,
        "lineage_id": lineage_id,
        "root_path": str(root),
        "root_device": status.st_dev,
        "root_inode": status.st_ino,
        "authorizations": _false_authority_map(),
    }


def _validate_marker(value: dict[str, Any], raw: bytes, root: Path, status: os.stat_result) -> None:
    expected = {
        "schema_version",
        "protocol",
        "lineage_id",
        "root_path",
        "root_device",
        "root_inode",
        "authorizations",
        "marker_sha256",
    }
    _strict_keys(value, expected, "lineage root marker")
    body = {key: item for key, item in value.items() if key != "marker_sha256"}
    _exact_int(value["schema_version"], "lineage root schema", minimum=1)
    _exact_int(value["root_device"], "lineage root device")
    _exact_int(value["root_inode"], "lineage root inode", minimum=1)
    _lineage(value["lineage_id"])
    _false_authority(value["authorizations"], "lineage root")
    if (
        value["schema_version"] != 1
        or value["protocol"] != _ROOT_PROTOCOL
        or value["root_path"] != str(root)
        or value["root_device"] != status.st_dev
        or value["root_inode"] != status.st_ino
        or value["marker_sha256"] != _sha(canonical_json(body))
        or canonical_json(value) != raw
    ):
        _fail("lineage root marker is invalid")


def _inspect_root_at(
    root: Path, root_fd: int
) -> tuple[os.stat_result, dict[str, Any], bytes]:
    _reject_protected_destination(root, "lineage root")
    status = os.fstat(root_fd)
    if (
        not stat.S_ISDIR(status.st_mode)
        or status.st_uid != os.getuid()
        or stat.S_IMODE(status.st_mode) != 0o700
    ):
        _fail("lineage root must be an owned mode-0700 directory")
    raw = _relative_bytes(root_fd, _ROOT_MARKER, modes={0o400})
    marker = _json_raw(raw, str(root / _ROOT_MARKER))
    _validate_marker(marker, raw, root, status)
    return status, marker, raw


@contextmanager
def _lineage_lock(
    root: Path, *, lineage_id: str | None = None, create: bool = False
) -> Iterator[tuple[int, os.stat_result, dict[str, Any], bytes]]:
    active = cast(
        "dict[str, tuple[int, os.stat_result, dict[str, Any], bytes]]",
        getattr(_ACTIVE_LOCKS, "roots", {}),
    )
    key = str(root)
    if key in active:
        root_fd, status, marker, raw = active[key]
        _verify_live_root(root, root_fd, status)
        if lineage_id is not None and marker["lineage_id"] != _lineage(lineage_id):
            _fail("lineage root belongs to another lineage")
        yield root_fd, status, marker, raw
        return
    _reject_protected_destination(root, "lineage root")
    root_fd, initial = _descriptor_walk(root)
    if (
        not stat.S_ISDIR(initial.st_mode)
        or initial.st_uid != os.getuid()
        or stat.S_IMODE(initial.st_mode) != 0o700
    ):
        os.close(root_fd)
        _fail("lineage root must be an owned mode-0700 directory")
    lock_fd: int | None = None
    try:
        lock_fd = os.open(
            _ROOT_LOCK,
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=root_fd,
        )
        lock_status = os.fstat(lock_fd)
        if (
            not stat.S_ISREG(lock_status.st_mode)
            or lock_status.st_uid != os.getuid()
            or lock_status.st_nlink != 1
            or stat.S_IMODE(lock_status.st_mode) != 0o600
        ):
            _fail("lineage root lock identity is invalid")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        if create and not _exists_at(root_fd, _ROOT_MARKER):
            if lineage_id is None:
                _fail("lineage_id is required")
            body = _root_marker_body(root, initial, _lineage(lineage_id))
            _atomic_at(
                root,
                root_fd,
                initial,
                _ROOT_MARKER,
                {**body, "marker_sha256": _sha(canonical_json(body))},
            )
        status, marker, raw = _inspect_root_at(root, root_fd)
        if _root_identity(status) != _root_identity(initial):
            _fail("lineage root identity changed")
        if lineage_id is not None and marker["lineage_id"] != _lineage(lineage_id):
            _fail("lineage root belongs to another lineage")
        active[key] = (root_fd, status, marker, raw)
        _ACTIVE_LOCKS.roots = active
        yield root_fd, status, marker, raw
        _verify_live_root(root, root_fd, status)
    except OSError as error:
        raise BrokerBundleError(f"cannot lock lineage root: {error}") from error
    finally:
        active.pop(key, None)
        _ACTIVE_LOCKS.roots = active
        if lock_fd is not None:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
        os.close(root_fd)


def _entry(path: str, raw: bytes, category: str) -> dict[str, Any]:
    return {
        "path": path,
        "category": category,
        "bytes": len(raw),
        "mode": "0400",
        "sha256": _sha(raw),
    }


def _root_binding(root: Path, status: os.stat_result, marker_raw: bytes) -> dict[str, Any]:
    return {
        "lineage_root_path": str(root),
        "lineage_root_device": status.st_dev,
        "lineage_root_inode": status.st_ino,
        "lineage_root_marker_sha256": _sha(marker_raw),
    }


def _open_directory_at(parent_fd: int, name: str) -> int:
    return os.open(
        name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=parent_fd,
    )


def _remove_tree_at(parent_fd: int, name: str) -> None:
    try:
        descriptor = _open_directory_at(parent_fd, name)
    except FileNotFoundError:
        return
    try:
        os.fchmod(descriptor, 0o700)
        for child in os.listdir(descriptor):  # noqa: PTH208 -- descriptor-relative traversal
            status = os.stat(child, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISDIR(status.st_mode):
                _remove_tree_at(descriptor, child)
            else:
                os.chmod(child, 0o600, dir_fd=descriptor, follow_symlinks=False)
                os.unlink(child, dir_fd=descriptor)
    finally:
        os.close(descriptor)
    os.rmdir(name, dir_fd=parent_fd)


def _stage_file(
    staging_fd: int,
    relative: str,
    raw: bytes,
    directories: set[str],
) -> None:
    parts = PurePosixPath(relative).parts
    current = os.dup(staging_fd)
    prefix: list[str] = []
    try:
        for part in parts[:-1]:
            prefix.append(part)
            directory = "/".join(prefix)
            with suppress(FileExistsError):
                os.mkdir(part, mode=0o700, dir_fd=current)
            following = _open_directory_at(current, part)
            os.close(current)
            current = following
            directories.add(directory)
        descriptor = os.open(
            parts[-1],
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=current,
        )
        try:
            _write_all(descriptor, raw)
            os.fchmod(descriptor, 0o400)
            _fsync(descriptor, f"staged-file:{relative}")
        finally:
            os.close(descriptor)
    finally:
        os.close(current)


def _sync_staged_directories(staging_fd: int, directories: set[str]) -> None:
    for relative in sorted(directories, key=lambda item: (-item.count("/"), item)):
        descriptor, _ = _open_relative(staging_fd, relative, directory=True)
        try:
            os.fchmod(descriptor, 0o500)
            _fsync(descriptor, f"staged-directory:{relative}")
        finally:
            os.close(descriptor)
    os.fchmod(staging_fd, 0o500)
    _fsync(staging_fd, "staged-directory:.")


def materialize_bundle(
    runtime_attestation: Path,
    binding: Path,
    production_profile: Path,
    launch_profile: Path,
    sources: Mapping[str, Path],
    output: Path,
    *,
    lineage_id: str,
) -> dict[str, Any]:
    """Atomically publish one enclosing object containing bundle and receipt."""
    _reject_protected_destination(output, "output path")
    if output.name in {"", ".", ".."}:
        _fail("output path is invalid")
    lineage_id = _lineage(lineage_id)
    if not sources or len(sources) > _MAX_FILES:
        _fail("bundle source cardinality is invalid")
    with _lineage_lock(output.parent, lineage_id=lineage_id, create=True) as (
        root_fd,
        root_status,
        _marker,
        marker_raw,
    ):
        if _exists_at(root_fd, output.name):
            _fail(f"output already exists: {output}")
        snapshot = _control_snapshot(
            runtime_attestation, binding, production_profile, launch_profile
        )
        source_rows: list[tuple[str, bytes]] = []
        for relative, path in sorted(sources.items()):
            source_rows.append((f"broker/{_safe_relative(relative)}", _owned_bytes(path)))
        launch = cast("dict[str, Any]", snapshot["launch_profile"])
        entrypoint = f"broker/{launch['broker_entrypoint']}"
        source_by_path = dict(source_rows)
        if (
            entrypoint not in source_by_path
            or _sha(source_by_path[entrypoint]) != launch["broker_entrypoint_sha256"]
        ):
            _fail("launch profile broker entrypoint is not exactly bundled")
        control_rows = [
            (f"control/{name}", raw)
            for name, raw in sorted(cast("dict[str, bytes]", snapshot["raw"]).items())
        ]
        rows = sorted(
            [
                *(_entry(path, raw, "control") for path, raw in control_rows),
                *(_entry(path, raw, "broker") for path, raw in source_rows),
            ],
            key=lambda row: cast("str", row["path"]),
        )
        manifest_body = {
            "schema_version": 1,
            "protocol": _BUNDLE_PROTOCOL,
            "lineage_id": lineage_id,
            **_root_binding(output.parent, root_status, marker_raw),
            "runtime_attestation_entry_hash": snapshot["runtime_attestation_entry_hash"],
            "runtime_attestation_sha256": snapshot["runtime_attestation_sha256"],
            "binding_sha256": snapshot["binding_sha256"],
            "production_profile_sha256": snapshot["production_profile_sha256"],
            "launch_profile_sha256": snapshot["launch_profile_sha256"],
            "files": rows,
            "inventory_sha256": _sha(canonical_json(rows)),
            "authorizations": _false_authority_map(),
        }
        bundle_id = _sha(_BUNDLE_DOMAIN + canonical_json(manifest_body))
        manifest = {**manifest_body, "bundle_id": bundle_id}
        staging_name = f".{output.name}.{secrets.token_hex(12)}"
        os.mkdir(staging_name, mode=0o700, dir_fd=root_fd)
        staging_fd = _open_directory_at(root_fd, staging_name)
        directories: set[str] = set()
        try:
            for relative, raw in (*control_rows, *source_rows):
                _stage_file(staging_fd, relative, raw, directories)
            manifest_raw = canonical_json(manifest)
            _stage_file(staging_fd, "manifest.json", manifest_raw, directories)
            stage_status = os.fstat(staging_fd)
            receipt_body = {
                "schema_version": 1,
                "protocol": _RECEIPT_PROTOCOL,
                "lineage_id": lineage_id,
                **_root_binding(output.parent, root_status, marker_raw),
                "bundle_id": bundle_id,
                "bundle_path": str(output),
                "bundle_device": stage_status.st_dev,
                "bundle_inode": stage_status.st_ino,
                "manifest_sha256": _sha(manifest_raw),
                "inventory_sha256": manifest["inventory_sha256"],
                "runtime_attestation_entry_hash": snapshot["runtime_attestation_entry_hash"],
                "runtime_attestation_sha256": snapshot["runtime_attestation_sha256"],
                "binding_sha256": snapshot["binding_sha256"],
                "production_profile_sha256": snapshot["production_profile_sha256"],
                "launch_profile_sha256": snapshot["launch_profile_sha256"],
                "authorizations": _false_authority_map(),
            }
            receipt = {**receipt_body, "receipt_sha256": _sha(canonical_json(receipt_body))}
            _stage_file(staging_fd, _RECEIPT_NAME, canonical_json(receipt), directories)
            _sync_staged_directories(staging_fd, directories)
            _verify_live_root(output.parent, root_fd, root_status)
            _rename_noreplace_at(root_fd, staging_name, output.name)
            _fsync(root_fd, f"directory:{output.parent}")
        except BaseException:
            _remove_tree_at(root_fd, staging_name)
            raise
        finally:
            os.close(staging_fd)
    receipt_path = output / _RECEIPT_NAME
    return verify_bundle(receipt_path)


def _manifest(value: dict[str, Any], raw: bytes) -> list[dict[str, Any]]:
    expected = {
        "schema_version",
        "protocol",
        "lineage_id",
        "lineage_root_path",
        "lineage_root_device",
        "lineage_root_inode",
        "lineage_root_marker_sha256",
        "runtime_attestation_entry_hash",
        "runtime_attestation_sha256",
        "binding_sha256",
        "production_profile_sha256",
        "launch_profile_sha256",
        "files",
        "inventory_sha256",
        "authorizations",
        "bundle_id",
    }
    _strict_keys(value, expected, "bundle manifest")
    _lineage(value["lineage_id"])
    _absolute_string(value["lineage_root_path"], "lineage root path")
    for field in (
        "lineage_root_marker_sha256",
        "runtime_attestation_entry_hash",
        "runtime_attestation_sha256",
        "binding_sha256",
        "production_profile_sha256",
        "launch_profile_sha256",
        "inventory_sha256",
        "bundle_id",
    ):
        _digest(value[field], f"manifest {field}")
    _false_authority(value["authorizations"], "manifest")
    rows = value["files"]
    if not isinstance(rows, list) or not rows or len(rows) > _MAX_FILES + 4:
        _fail("bundle inventory is invalid")
    seen: set[str] = set()
    previous = ""
    for row in rows:
        if not isinstance(row, dict):
            _fail("bundle inventory row is invalid")
        _strict_keys(row, {"path", "category", "bytes", "mode", "sha256"}, "bundle row")
        relative = _safe_relative(row["path"])
        if (
            relative in seen
            or relative <= previous
            or row["category"] not in {"control", "broker"}
            or not relative.startswith(f"{row['category']}/")
            or row["mode"] != "0400"
            or not isinstance(row["bytes"], int)
            or isinstance(row["bytes"], bool)
            or row["bytes"] < 0
            or row["bytes"] > _MAX_FILE
        ):
            _fail("bundle inventory row is invalid")
        _digest(row["sha256"], "bundle row")
        seen.add(relative)
        previous = relative
    _exact_int(value["schema_version"], "manifest schema", minimum=1)
    _exact_int(value["lineage_root_device"], "manifest root device")
    _exact_int(value["lineage_root_inode"], "manifest root inode", minimum=1)
    body = {key: item for key, item in value.items() if key != "bundle_id"}
    if (
        value["schema_version"] != 1
        or value["protocol"] != _BUNDLE_PROTOCOL
        or value["inventory_sha256"] != _sha(canonical_json(rows))
        or value["bundle_id"] != _sha(_BUNDLE_DOMAIN + canonical_json(body))
        or canonical_json(value) != raw
    ):
        _fail("bundle manifest is invalid")
    return cast("list[dict[str, Any]]", rows)


def _receipt(value: dict[str, Any], raw: bytes) -> None:
    expected = {
        "schema_version",
        "protocol",
        "lineage_id",
        "lineage_root_path",
        "lineage_root_device",
        "lineage_root_inode",
        "lineage_root_marker_sha256",
        "bundle_id",
        "bundle_path",
        "bundle_device",
        "bundle_inode",
        "manifest_sha256",
        "inventory_sha256",
        "runtime_attestation_entry_hash",
        "runtime_attestation_sha256",
        "binding_sha256",
        "production_profile_sha256",
        "launch_profile_sha256",
        "authorizations",
        "receipt_sha256",
    }
    _strict_keys(value, expected, "bundle receipt")
    _lineage(value["lineage_id"])
    _absolute_string(value["lineage_root_path"], "lineage root path")
    _absolute_string(value["bundle_path"], "bundle path")
    for field in (
        "lineage_root_marker_sha256",
        "bundle_id",
        "manifest_sha256",
        "inventory_sha256",
        "runtime_attestation_entry_hash",
        "runtime_attestation_sha256",
        "binding_sha256",
        "production_profile_sha256",
        "launch_profile_sha256",
        "receipt_sha256",
    ):
        _digest(value[field], f"receipt {field}")
    _exact_int(value["schema_version"], "receipt schema", minimum=1)
    for field in ("lineage_root_device", "bundle_device"):
        _exact_int(value[field], f"receipt {field}")
    for field in ("lineage_root_inode", "bundle_inode"):
        _exact_int(value[field], f"receipt {field}", minimum=1)
    _false_authority(value["authorizations"], "receipt")
    body = {key: item for key, item in value.items() if key != "receipt_sha256"}
    if (
        value["schema_version"] != 1
        or value["protocol"] != _RECEIPT_PROTOCOL
        or value["receipt_sha256"] != _sha(canonical_json(body))
        or canonical_json(value) != raw
    ):
        _fail("bundle receipt is invalid")


def _open_relative(root_fd: int, relative: str, *, directory: bool) -> tuple[int, os.stat_result]:
    parts = PurePosixPath(relative).parts
    current = os.dup(root_fd)
    try:
        for index, part in enumerate(parts):
            final = index == len(parts) - 1
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
            if directory or not final:
                flags |= os.O_DIRECTORY
            following = os.open(part, flags, dir_fd=current)
            os.close(current)
            current = following
        return current, os.fstat(current)
    except OSError as error:
        os.close(current)
        raise BrokerBundleError(f"bundle descriptor traversal failed: {relative}") from error


def _census(root_fd: int) -> tuple[set[str], set[str], list[tuple[int, os.stat_result, str]]]:
    files: set[str] = set()
    directories: set[str] = set()
    retained: list[tuple[int, os.stat_result, str]] = []

    def visit(fd: int, prefix: str) -> None:
        for name in sorted(os.listdir(fd)):
            relative = f"{prefix}/{name}" if prefix else name
            child_fd, child_status = _open_relative(root_fd, relative, directory=False)
            if stat.S_ISDIR(child_status.st_mode):
                os.close(child_fd)
                child_fd, child_status = _open_relative(root_fd, relative, directory=True)
                if (
                    stat.S_IMODE(child_status.st_mode) != 0o500
                    or child_status.st_uid != os.getuid()
                ):
                    os.close(child_fd)
                    _fail("bundle directory identity changed")
                directories.add(relative)
                retained.append((child_fd, child_status, relative))
                visit(child_fd, relative)
            elif stat.S_ISREG(child_status.st_mode):
                files.add(relative)
                retained.append((child_fd, child_status, relative))
            else:
                os.close(child_fd)
                _fail("bundle contains a special file")

    try:
        visit(root_fd, "")
    except BaseException:
        for descriptor, _, _ in retained:
            os.close(descriptor)
        raise
    return files, directories, retained


def verify_bundle(receipt_path: Path) -> dict[str, Any]:  # noqa: PLR0912, PLR0915
    """Descriptor-scan and revalidate the exact bundle while holding its root lock."""
    _normalized_absolute(receipt_path, "receipt path")
    if receipt_path.name != _RECEIPT_NAME:
        _fail("receipt must be inside its atomic bundle object")
    root = receipt_path.parent.parent
    with _lineage_lock(root) as (_root_fd, root_status, marker, marker_raw):
        receipt_fd, receipt_status = _open_file(receipt_path, modes={0o400})
        try:
            receipt_raw = _read_fd(receipt_fd, receipt_status, "bundle receipt")
            receipt = _json_raw(receipt_raw, "bundle receipt")
            _receipt(receipt, receipt_raw)
        except BaseException:
            os.close(receipt_fd)
            raise
        bundle = Path(cast("str", receipt["bundle_path"]))
        if bundle != receipt_path.parent or bundle.parent != root:
            os.close(receipt_fd)
            _fail("bundle receipt path binding is invalid")
        if (
            receipt["lineage_id"] != marker["lineage_id"]
            or receipt["lineage_root_path"] != str(root)
            or receipt["lineage_root_device"] != root_status.st_dev
            or receipt["lineage_root_inode"] != root_status.st_ino
            or receipt["lineage_root_marker_sha256"] != _sha(marker_raw)
        ):
            os.close(receipt_fd)
            _fail("bundle lineage root binding changed")
        try:
            root_fd, bundle_status = _descriptor_walk(bundle)
        except BaseException:
            os.close(receipt_fd)
            raise
        retained: list[tuple[int, os.stat_result, str]] = [
            (receipt_fd, receipt_status, _RECEIPT_NAME)
        ]
        try:
            if (
                not stat.S_ISDIR(bundle_status.st_mode)
                or bundle_status.st_uid != os.getuid()
                or stat.S_IMODE(bundle_status.st_mode) != 0o500
                or bundle_status.st_dev != receipt["bundle_device"]
                or bundle_status.st_ino != receipt["bundle_inode"]
            ):
                _fail("bundle directory identity changed")
            files, directories, census_retained = _census(root_fd)
            retained.extend(census_retained)
            census_identities = {
                relative: _identity(status) for _, status, relative in census_retained
            }
            if census_identities.get(_RECEIPT_NAME) != _identity(receipt_status):
                _fail("bundle receipt identity changed during scan")
            expected_files = {"manifest.json", _RECEIPT_NAME}
            expected_directories = {"control", "broker"}
            manifest_fd, manifest_status = _open_relative(root_fd, "manifest.json", directory=False)
            retained.append((manifest_fd, manifest_status, "manifest.json"))
            if census_identities.get("manifest.json") != _identity(manifest_status):
                _fail("bundle manifest identity changed during scan")
            manifest_raw = _read_fd(manifest_fd, manifest_status, "manifest")
            manifest = _json_raw(manifest_raw, "manifest")
            rows = _manifest(manifest, manifest_raw)
            for field in (
                "lineage_id",
                "lineage_root_path",
                "lineage_root_device",
                "lineage_root_inode",
                "lineage_root_marker_sha256",
                "bundle_id",
                "inventory_sha256",
                "runtime_attestation_entry_hash",
                "runtime_attestation_sha256",
                "binding_sha256",
                "production_profile_sha256",
                "launch_profile_sha256",
                "authorizations",
            ):
                if manifest[field] != receipt[field]:
                    _fail("manifest and receipt identity differ")
            if _sha(manifest_raw) != receipt["manifest_sha256"]:
                _fail("bundle manifest identity changed")
            for row in rows:
                relative = cast("str", row["path"])
                expected_files.add(relative)
                parent = PurePosixPath(relative).parent
                while parent.as_posix() not in {".", ""}:
                    expected_directories.add(parent.as_posix())
                    parent = parent.parent
                fd, status = _open_relative(root_fd, relative, directory=False)
                retained.append((fd, status, relative))
                if census_identities.get(relative) != _identity(status):
                    _fail(f"bundle file identity changed during scan: {relative}")
                raw = _read_fd(fd, status, relative)
                if (
                    not stat.S_ISREG(status.st_mode)
                    or status.st_uid != os.getuid()
                    or status.st_nlink != 1
                    or stat.S_IMODE(status.st_mode) != 0o400
                    or row["bytes"] != len(raw)
                    or row["sha256"] != _sha(raw)
                ):
                    _fail("bundle file identity changed")
            if files != expected_files or directories != expected_directories:
                _fail("bundle inventory changed")
            snapshot = _control_snapshot(
                bundle / "control/runtime-attestation.json",
                bundle / "control/binding.json",
                bundle / "control/production-profile.json",
                bundle / "control/launch-profile.json",
            )
            for field in (
                "runtime_attestation_entry_hash",
                "runtime_attestation_sha256",
                "binding_sha256",
                "production_profile_sha256",
                "launch_profile_sha256",
            ):
                if snapshot[field] != receipt[field]:
                    _fail("bundle control identity changed")
            for descriptor, initial, relative in retained:
                if _identity(os.fstat(descriptor)) != _identity(initial):
                    _fail(f"bundle identity changed during scan: {relative}")
            current = os.fstat(root_fd)
            if _identity(current) != _identity(bundle_status):
                _fail("bundle root changed during scan")
        finally:
            for descriptor, _, _ in retained:
                os.close(descriptor)
            os.close(root_fd)
        return receipt


def _phase_path(freeze_path: Path, phase: str) -> Path:
    return freeze_path.with_name(f"{freeze_path.name}.{phase}.json")


def _freeze_document(value: dict[str, Any], raw: bytes) -> None:
    expected = {
        "schema_version",
        "protocol",
        "lineage_id",
        "lineage_root_path",
        "lineage_root_device",
        "lineage_root_inode",
        "lineage_root_marker_sha256",
        "bundle_id",
        "bundle_receipt_path",
        "bundle_receipt_sha256",
        "runtime_attestation_entry_hash",
        "runtime_attestation_sha256",
        "binding_sha256",
        "production_profile_sha256",
        "launch_profile_sha256",
        "bundle_inventory_sha256",
        "phase_scope",
        "prepared_at",
        "authorizations",
        "freeze_sha256",
    }
    _strict_keys(value, expected, "prepare freeze")
    _lineage(value["lineage_id"])
    _absolute_string(value["lineage_root_path"], "freeze root path")
    _absolute_string(value["bundle_receipt_path"], "freeze receipt path")
    for field in (
        "lineage_root_marker_sha256",
        "bundle_id",
        "bundle_receipt_sha256",
        "runtime_attestation_entry_hash",
        "runtime_attestation_sha256",
        "binding_sha256",
        "production_profile_sha256",
        "launch_profile_sha256",
        "bundle_inventory_sha256",
        "freeze_sha256",
    ):
        _digest(value[field], f"freeze {field}")
    _false_authority(value["authorizations"], "freeze")
    _exact_int(value["schema_version"], "freeze schema", minimum=1)
    _exact_int(value["lineage_root_device"], "freeze root device")
    _exact_int(value["lineage_root_inode"], "freeze root inode", minimum=1)
    body = {key: item for key, item in value.items() if key != "freeze_sha256"}
    if (
        value["schema_version"] != 1
        or value["protocol"] != _FREEZE_PROTOCOL
        or value["phase_scope"] != list(_FREEZE_PHASES)
        or not isinstance(value["prepared_at"], str)
        or not _TIMESTAMP.fullmatch(value["prepared_at"])
        or value["freeze_sha256"] != _sha(canonical_json(body))
        or canonical_json(value) != raw
    ):
        _fail("prepare freeze is invalid")
    try:
        parsed = datetime.fromisoformat(value["prepared_at"].replace("Z", "+00:00"))
    except ValueError as error:
        raise BrokerBundleError("prepare freeze timestamp is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        _fail("prepare freeze timestamp is invalid")


def _completed_phases(freeze_path: Path, freeze: dict[str, Any]) -> list[dict[str, Any]]:
    completed: list[dict[str, Any]] = []
    previous = freeze["freeze_sha256"]
    for index, phase in enumerate(_FREEZE_PHASES):
        path = _phase_path(freeze_path, phase)
        if not path.exists():
            if any(
                _phase_path(freeze_path, later).exists() for later in _FREEZE_PHASES[index + 1 :]
            ):
                _fail("freeze phase state is out of order")
            break
        value, raw = _json_file(path, modes={0o400})
        _strict_keys(
            value,
            {
                "schema_version",
                "protocol",
                "lineage_id",
                "bundle_id",
                "freeze_sha256",
                "phase",
                "ordinal",
                "previous_phase_sha256",
                "authorizations",
                "phase_sha256",
            },
            "freeze phase receipt",
        )
        _exact_int(value["schema_version"], "phase schema", minimum=1)
        _exact_int(value["ordinal"], "phase ordinal")
        body = {key: item for key, item in value.items() if key != "phase_sha256"}
        _false_authority(value["authorizations"], "phase")
        if (
            value["schema_version"] != 1
            or value["protocol"] != _PHASE_PROTOCOL
            or value["lineage_id"] != freeze["lineage_id"]
            or value["bundle_id"] != freeze["bundle_id"]
            or value["freeze_sha256"] != freeze["freeze_sha256"]
            or value["phase"] != phase
            or value["ordinal"] != index
            or value["previous_phase_sha256"] != previous
            or value["phase_sha256"] != _sha(canonical_json(body))
            or canonical_json(value) != raw
        ):
            _fail("freeze phase state is invalid")
        previous = value["phase_sha256"]
        completed.append(value)
    return completed


def prepare_freeze(
    receipt_path: Path,
    runtime_attestation: Path,
    binding: Path,
    production_profile: Path,
    launch_profile: Path,
    output: Path,
    *,
    clock: datetime | None = None,
) -> dict[str, Any]:
    """Publish a false-authority freeze and durably claim its prepared phase."""
    _reject_protected_destination(output, "freeze output")
    for phase_name in _FREEZE_PHASES:
        _reject_protected_destination(_phase_path(output, phase_name), "freeze phase output")
    receipt = verify_bundle(receipt_path)
    root = Path(cast("str", receipt["lineage_root_path"]))
    if output.parent != root:
        _fail("freeze must be published in the bound lineage root")
    with _lineage_lock(root, lineage_id=cast("str", receipt["lineage_id"])) as (
        root_fd,
        root_status,
        _marker,
        marker_raw,
    ):
        if _exists_at(root_fd, output.name):
            _fail(f"output already exists: {output}")
        if any(_exists_at(root_fd, _phase_path(output, phase).name) for phase in _FREEZE_PHASES):
            _fail("orphan freeze phase state exists")
        snapshot = _control_snapshot(
            runtime_attestation, binding, production_profile, launch_profile
        )
        for field in (
            "runtime_attestation_entry_hash",
            "runtime_attestation_sha256",
            "binding_sha256",
            "production_profile_sha256",
            "launch_profile_sha256",
        ):
            if snapshot[field] != receipt[field]:
                _fail("prepare inputs differ from the receipt-bound bundle")
        now = (clock or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
        body = {
            "schema_version": 1,
            "protocol": _FREEZE_PROTOCOL,
            "lineage_id": receipt["lineage_id"],
            **_root_binding(root, root_status, marker_raw),
            "bundle_id": receipt["bundle_id"],
            "bundle_receipt_path": str(receipt_path),
            "bundle_receipt_sha256": _sha(canonical_json(receipt)),
            "runtime_attestation_entry_hash": snapshot["runtime_attestation_entry_hash"],
            "runtime_attestation_sha256": snapshot["runtime_attestation_sha256"],
            "binding_sha256": snapshot["binding_sha256"],
            "production_profile_sha256": snapshot["production_profile_sha256"],
            "launch_profile_sha256": snapshot["launch_profile_sha256"],
            "bundle_inventory_sha256": receipt["inventory_sha256"],
            "phase_scope": list(_FREEZE_PHASES),
            "prepared_at": now.isoformat().replace("+00:00", "Z"),
            "authorizations": _false_authority_map(),
        }
        freeze = {**body, "freeze_sha256": _sha(canonical_json(body))}
        _atomic_at(root, root_fd, root_status, output.name, freeze)
    verify_freeze(
        output, runtime_attestation, binding, production_profile, launch_profile, phase="prepared"
    )
    return freeze


def verify_freeze(
    freeze_path: Path,
    runtime_attestation: Path,
    binding: Path,
    production_profile: Path,
    launch_profile: Path,
    *,
    phase: Literal["prepared", "launch_claimed", "pre_escrow"],
) -> dict[str, Any]:
    """Validate and consume exactly the next durable, no-clobber freeze phase."""
    if phase not in _FREEZE_PHASES:
        _fail("freeze phase is invalid")
    _reject_protected_destination(freeze_path, "freeze path")
    phase_path = _phase_path(freeze_path, phase)
    _reject_protected_destination(phase_path, "freeze phase path")
    root = freeze_path.parent
    with _lineage_lock(root) as (root_fd, root_status, marker, marker_raw):
        freeze, freeze_raw = _json_file(freeze_path, modes={0o400})
        _freeze_document(freeze, freeze_raw)
        if (
            freeze["lineage_id"] != marker["lineage_id"]
            or freeze["lineage_root_path"] != str(root)
            or freeze["lineage_root_device"] != root_status.st_dev
            or freeze["lineage_root_inode"] != root_status.st_ino
            or freeze["lineage_root_marker_sha256"] != _sha(marker_raw)
        ):
            _fail("freeze lineage root binding changed")
        completed = _completed_phases(freeze_path, freeze)
        expected_phase = (
            _FREEZE_PHASES[len(completed)] if len(completed) < len(_FREEZE_PHASES) else None
        )
        if phase != expected_phase:
            _fail("freeze phase replay or out-of-order transition")
        receipt_path = Path(cast("str", freeze["bundle_receipt_path"]))
        receipt = verify_bundle(receipt_path)
        for freeze_field, receipt_field in (
            ("lineage_id", "lineage_id"),
            ("bundle_id", "bundle_id"),
            ("bundle_inventory_sha256", "inventory_sha256"),
            ("lineage_root_path", "lineage_root_path"),
            ("lineage_root_device", "lineage_root_device"),
            ("lineage_root_inode", "lineage_root_inode"),
            ("lineage_root_marker_sha256", "lineage_root_marker_sha256"),
        ):
            if freeze[freeze_field] != receipt[receipt_field]:
                _fail("prepare freeze bundle lineage changed")
        if freeze["bundle_receipt_sha256"] != _sha(canonical_json(receipt)):
            _fail("prepare freeze receipt identity changed")
        snapshot = _control_snapshot(
            runtime_attestation, binding, production_profile, launch_profile
        )
        for field in (
            "runtime_attestation_entry_hash",
            "runtime_attestation_sha256",
            "binding_sha256",
            "production_profile_sha256",
            "launch_profile_sha256",
        ):
            if freeze[field] != snapshot[field] or freeze[field] != receipt[field]:
                _fail(f"{phase} control identity changed")
        previous = freeze["freeze_sha256"] if not completed else completed[-1]["phase_sha256"]
        ordinal = _FREEZE_PHASES.index(phase)
        body = {
            "schema_version": 1,
            "protocol": _PHASE_PROTOCOL,
            "lineage_id": freeze["lineage_id"],
            "bundle_id": freeze["bundle_id"],
            "freeze_sha256": freeze["freeze_sha256"],
            "phase": phase,
            "ordinal": ordinal,
            "previous_phase_sha256": previous,
            "authorizations": _false_authority_map(),
        }
        _atomic_at(
            root,
            root_fd,
            root_status,
            phase_path.name,
            {**body, "phase_sha256": _sha(canonical_json(body))},
        )
        return freeze


def _sources(values: list[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            _fail("--source must be RELATIVE=ABSOLUTE")
        relative, raw_path = value.split("=", 1)
        relative = _safe_relative(relative)
        if relative in result:
            _fail("duplicate --source path")
        result[relative] = Path(raw_path)
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--runtime-attestation", type=Path, required=True)
    common.add_argument("--binding", type=Path, required=True)
    common.add_argument("--production-profile", type=Path, required=True)
    common.add_argument("--launch-profile", type=Path, required=True)
    build = sub.add_parser("build-bundle", parents=[common])
    build.add_argument("--source", action="append", required=True)
    build.add_argument("--lineage-id", required=True)
    build.add_argument("--output", type=Path, required=True)
    verify = sub.add_parser("verify-bundle")
    verify.add_argument("--receipt", type=Path, required=True)
    freeze = sub.add_parser("prepare-freeze", parents=[common])
    freeze.add_argument("--receipt", type=Path, required=True)
    freeze.add_argument("--output", type=Path, required=True)
    verify_freeze_parser = sub.add_parser("verify-freeze", parents=[common])
    verify_freeze_parser.add_argument("--freeze", type=Path, required=True)
    verify_freeze_parser.add_argument("--phase", choices=_FREEZE_PHASES, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "build-bundle":
            result = materialize_bundle(
                args.runtime_attestation,
                args.binding,
                args.production_profile,
                args.launch_profile,
                _sources(args.source),
                args.output,
                lineage_id=args.lineage_id,
            )
        elif args.command == "verify-bundle":
            result = verify_bundle(args.receipt)
        elif args.command == "prepare-freeze":
            result = prepare_freeze(
                args.receipt,
                args.runtime_attestation,
                args.binding,
                args.production_profile,
                args.launch_profile,
                args.output,
            )
        else:
            result = verify_freeze(
                args.freeze,
                args.runtime_attestation,
                args.binding,
                args.production_profile,
                args.launch_profile,
                phase=args.phase,
            )
    except BrokerBundleError as error:
        _parser().error(str(error))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
