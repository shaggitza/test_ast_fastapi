#!/usr/bin/env python3
"""Prepare and finalize broker-bound reviews launched by the native subagent tool."""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import errno
import fcntl
import hashlib
import json
import math
import os
import re
import resource
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, Literal, NoReturn, cast

from benchmarks.real_world import pilot_packet_v2, pilot_submit_v3
from benchmarks.real_world.ground_truth_v2 import GroundTruthError
from benchmarks.real_world.ground_truth_v2.evidence import GitEvidenceValidator
from benchmarks.real_world.ground_truth_v2.schema import (
    Actor,
    ResourceLimits,
    SnapshotBinding,
    artifact_sha256,
    canonical_json,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_PACKET_BYTES = 512 * 1024 * 1024
_MAX_PACKET_FILES = 100_000
_MAX_STDIO_BYTES = 64 * 1024 * 1024
_MAX_RESULT_BYTES = 2 * 1024 * 1024
_MAX_WALL_SECONDS = 1800
_MAX_RSS_BYTES = 4 * 1024 * 1024 * 1024
_ATTEMPT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_AGENT_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_REJECTION_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,99}$")
_CORRECTABLE_REJECTION_CODES = {"DRAFT_INVALID", "EVIDENCE_INVALID"}
_NATIVE_AGENT_NAME = "pilot-blind-reviewer-luna-medium-v3"
_MAX_AGENT_FILES = 5_000
_MAX_AGENT_CENSUS_BYTES = 64 * 1024 * 1024
_POLICY_FILES = {
    "review_prompt": "review-prompt-v1.md",
    "model_policy": "model-policy-v1.json",
    "tool_policy": "tool-policy-v1.json",
    "source_policy": "source-policy-v1.json",
}
_PACKET_ID = "blind-review-pilot-packet-v3"


class PilotTypedRunError(RuntimeError):
    """Fail-closed typed-run error."""


def _fail(message: str) -> NoReturn:
    raise PilotTypedRunError(message)


def _sha(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _safe_relative(value: str) -> str:
    if "\\" in value or "\x00" in value or value.startswith("/"):
        _fail("unsafe packet path")
    parts = PurePosixPath(value).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        _fail("unsafe packet path")
    return value


def _read(path: Path, limit: int, *, modes: set[int] | None = None) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise PilotTypedRunError(f"cannot open {path.name}") from exc
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_uid != os.getuid():
            _fail("file owner or type is invalid")
        if modes is not None and stat.S_IMODE(status.st_mode) not in modes:
            _fail("file mode is invalid")
        chunks: list[bytes] = []
        total = 0
        while total <= limit:
            chunk = os.read(descriptor, min(64 * 1024, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(raw) > limit:
        _fail("file exceeds byte limit")
    return raw


def _json(path: Path, limit: int, *, modes: set[int] | None = None) -> dict[str, Any]:
    raw = _read(path, limit, modes=modes)
    try:
        value = json.loads(raw, object_pairs_hook=_unique, parse_constant=_constant)
    except (
        json.JSONDecodeError,
        UnicodeDecodeError,
        ValueError,
        RecursionError,
        MemoryError,
    ) as exc:
        raise PilotTypedRunError(f"invalid JSON: {path.name}") from exc
    if not isinstance(value, dict):
        _fail("JSON root must be an object")
    canonical_json(value)
    return cast("dict[str, Any]", value)


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate JSON key")
        result[key] = value
    return result


def _constant(value: str) -> NoReturn:
    _fail(f"non-finite JSON value: {value}")


def _atomic(path: Path, raw: bytes, *, mode: int) -> None:
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise PilotTypedRunError(f"refusing to overwrite {path}") from exc
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _rename_noreplace(source: Path, target: Path) -> None:
    """Atomically publish one directory without replacing any extant destination."""
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
    if renameat2(-100, os.fsencode(source), -100, os.fsencode(target), 1) == 0:
        return
    code = ctypes.get_errno()
    if code in {errno.EEXIST, errno.ENOTEMPTY}:
        raise PilotTypedRunError(f"refusing to overwrite {target}")
    raise OSError(code, os.strerror(code), target)


def _inventory(root: Path, *, byte_limit: int = _MAX_PACKET_BYTES) -> tuple[list[Path], int]:
    if not root.is_dir() or root.is_symlink():
        _fail("packet root is unsafe")
    files: list[Path] = []
    total = 0
    pending = [root]
    while pending:
        current = pending.pop()
        try:
            entries = list(os.scandir(current))
        except OSError as exc:
            raise PilotTypedRunError("cannot inventory packet") from exc
        for entry in entries:
            status = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(status.st_mode):
                pending.append(Path(entry.path))
            elif stat.S_ISREG(status.st_mode):
                if status.st_size > _MAX_FILE_BYTES:
                    _fail("packet file exceeds byte limit")
                total += status.st_size
                if total > byte_limit:
                    _fail("packet exceeds byte limit")
                files.append(Path(entry.path))
                if len(files) > _MAX_PACKET_FILES:
                    _fail("packet file count exceeded")
            else:
                _fail("packet contains symlink or special entry")
    files.sort(key=lambda item: item.relative_to(root).as_posix())
    return files, total


def _copy_exact(source: Path, target: Path) -> None:
    files, _ = _inventory(source)
    target.mkdir(mode=0o700)
    for source_file in files:
        relative = source_file.relative_to(source)
        destination = target / relative
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        raw = _read(source_file, _MAX_FILE_BYTES, modes={0o400, 0o444})
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            offset = 0
            while offset < len(raw):
                written = os.write(descriptor, raw[offset:])
                if written <= 0:
                    _fail("packet copy short write")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _payload_files(packet: Path) -> tuple[list[dict[str, object]], int]:
    files, _total = _inventory(packet)
    payload: list[dict[str, object]] = []
    payload_total = 0
    for path in files:
        relative = path.relative_to(packet).as_posix()
        if relative == "packet-manifest.json":
            continue
        raw = _read(path, _MAX_FILE_BYTES)
        payload.append({"path": _safe_relative(relative), "bytes": len(raw), "sha256": _sha(raw)})
        payload_total += len(raw)
    return payload, payload_total


def _freeze_tree(root: Path) -> None:
    files, _ = _inventory(root)
    directories: set[Path] = {root}
    for path in files:
        path.chmod(0o444)
        directories.update(
            parent for parent in path.parents if parent == root or root in parent.parents
        )
    for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        directory.chmod(0o555)


def _packet_map(root: Path) -> dict[tuple[str, int], Path]:
    result: dict[tuple[str, int], Path] = {}
    for packet in root.iterdir():
        if not packet.is_dir() or packet.is_symlink():
            _fail("packet root contains an unsafe entry")
        manifest = _json(packet / "packet-manifest.json", 16 * 1024 * 1024, modes={0o444})
        repository, pr = manifest.get("repository"), manifest.get("pr")
        if not isinstance(repository, str) or not isinstance(pr, int) or isinstance(pr, bool):
            _fail("packet identity is invalid")
        key = (repository, pr)
        if key in result:
            _fail("duplicate packet identity")
        result[key] = packet.resolve(strict=True)
    return result


def prepare_packets(  # noqa: PLR0915
    source_root: Path,
    cache_root: Path,
    v2_packet_root: Path,
    v3_packet_root: Path,
) -> list[Path]:
    """Validate v2 packets, copy them safely, add v3 policy bytes, and freeze v3 packets."""
    source_root = source_root.resolve(strict=True)
    cache_root = cache_root.resolve(strict=True)
    v2_packet_root = v2_packet_root.resolve(strict=True)
    records, bindings_hash = pilot_packet_v2._binding_inputs(source_root)
    pilot_packet_v2.validate_packets(
        v2_packet_root,
        records,
        bindings_hash,
        source_root=source_root,
        cache_root=cache_root,
    )
    if v3_packet_root.exists() or v3_packet_root.is_symlink():
        _fail("v3 packet root already exists")
    parent = v3_packet_root.parent.resolve(strict=True)
    if stat.S_IMODE(parent.stat().st_mode) & 0o077:
        _fail("v3 packet parent is not private")
    staging = Path(tempfile.mkdtemp(prefix=f".{v3_packet_root.name}.", dir=parent))
    try:
        source_packets = _packet_map(v2_packet_root)
        prepared: list[Path] = []
        for record in records:
            key = (str(record["repository"]), int(record["pr"]))
            source_packet = source_packets.get(key)
            if source_packet is None:
                _fail("validated v2 packet is missing")
            destination = staging / source_packet.name
            _copy_exact(source_packet, destination)
            manifest_path = destination / "packet-manifest.json"
            manifest_path.chmod(0o600)
            original = _json(manifest_path, 16 * 1024 * 1024)
            original_root = original.get("packet_root_sha256")
            if not isinstance(original_root, str) or not _SHA.fullmatch(original_root):
                _fail("source packet root digest is invalid")
            policies = destination / "policies-v3"
            policies.mkdir(mode=0o700)
            for name in _POLICY_FILES.values():
                raw = _read(source_root / "benchmarks/real_world/pilot_v3" / name, 8 * 1024 * 1024)
                target = policies / name
                target.write_bytes(raw)
                target.chmod(0o600)
            payload, payload_bytes = _payload_files(destination)
            manifest = dict(original)
            manifest.update(
                {
                    "id": _PACKET_ID,
                    "source_packet_root_sha256": original_root,
                    "payload_files": payload,
                    "payload_bytes": payload_bytes,
                    "packet_root_sha256": "",
                }
            )
            manifest["packet_root_sha256"] = pilot_submit_v3._manifest_root(manifest)
            raw = canonical_json(manifest)
            manifest_path.write_bytes(raw)
            manifest_path.chmod(0o444)
            _freeze_tree(destination)
            check = _json(manifest_path, 16 * 1024 * 1024, modes={0o444})
            if check.get("packet_root_sha256") != pilot_submit_v3._manifest_root(check):
                _fail("prepared v3 packet root mismatch")
            pilot_submit_v3._verify_payload(destination, check)
            prepared.append(destination)
        _rename_noreplace(staging, v3_packet_root)
        directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return [v3_packet_root / item.name for item in prepared]
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _source_runtime_bytes(source_root: Path) -> dict[str, bytes]:
    return {
        "index.ts": _read(
            source_root / ".pi/extensions/blind-review-submit/index.ts", 2 * 1024 * 1024
        ),
        "review-schema.ts": _read(
            source_root / ".pi/extensions/blind-review-submit/review-schema.ts", 2 * 1024 * 1024
        ),
        "review-prompt-v1.md": _read(
            source_root / "benchmarks/real_world/pilot_v3/review-prompt-v1.md",
            8 * 1024 * 1024,
        ),
        "checksums-v1.json": _read(
            source_root / "benchmarks/real_world/pilot_v3/checksums-v1.json", 256 * 1024
        ),
    }


def _agent_bytes(extension: Path, prompt: bytes) -> bytes:
    try:
        prompt_text = prompt.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PilotTypedRunError("review prompt is not UTF-8") from exc
    return (
        "---\nname: pilot-blind-reviewer-luna-medium-v3\n"
        "description: Typed blind reviewer launched only by the parent subagent tool\n"
        "model: openai-codex/gpt-5.6-luna\nthinking: medium\n"
        "tools: read, grep, find, ls, submit_blind_review\nextensions:\n"
        f"subagentOnlyExtensions: {extension}\nsystemPromptMode: replace\n"
        "inheritProjectContext: false\ninheritSkills: false\ndefaultContext: fresh\n"
        "defaultProgress: false\n---\n\n" + prompt_text.rstrip() + "\n"
    ).encode()


def _materialize_execution_runtime(
    execution_root: Path, source_root: Path, model: str, thinking: str
) -> dict[str, object]:
    raw = _source_runtime_bytes(source_root)
    runtime = execution_root / "runtime"
    runtime.mkdir(mode=0o700)
    for name, content in raw.items():
        _atomic(runtime / name, content, mode=0o400)
    extension = (runtime / "index.ts").resolve(strict=True)
    agent_raw = _agent_bytes(extension, raw["review-prompt-v1.md"])
    agent = runtime / "pilot-blind-reviewer-luna-medium-v3.md"
    _atomic(agent, agent_raw, mode=0o400)
    return {
        "schema_version": 1,
        "protocol": "blind-review-typed-run-v3",
        "source_root": str(source_root),
        "execution_root": str(execution_root),
        "model": model,
        "thinking": thinking,
        "runtime_files": {
            name: {"path": str(runtime / name), "sha256": _sha(content), "bytes": len(content)}
            for name, content in raw.items()
        },
        "agent": {
            "runtime_name": "pilot-blind-reviewer-luna-medium-v3",
            "path": str(agent),
            "sha256": _sha(agent_raw),
            "bytes": len(agent_raw),
            "extension_path": str(extension),
        },
    }


def _reauthenticate_execution(execution_root: Path) -> dict[str, Any]:
    if not execution_root.is_absolute():
        _fail("execution root must be absolute")
    root = execution_root.resolve(strict=True)
    identity = _json(root / "execution.json", 512 * 1024, modes={0o400})
    if set(identity) != {
        "schema_version",
        "protocol",
        "source_root",
        "execution_root",
        "model",
        "thinking",
        "runtime_files",
        "agent",
    }:
        _fail("execution identity fields are invalid")
    if identity.get("execution_root") != str(root):
        _fail("execution identity root mismatch")
    runtime_files = identity.get("runtime_files")
    agent = identity.get("agent")
    if not isinstance(runtime_files, dict) or not isinstance(agent, dict):
        _fail("execution runtime identity is invalid")
    if set(runtime_files) != {
        "index.ts",
        "review-schema.ts",
        "review-prompt-v1.md",
        "checksums-v1.json",
    }:
        _fail("execution runtime identity is invalid")
    for value in [*runtime_files.values(), agent]:
        if not isinstance(value, dict):
            _fail("execution runtime identity is invalid")
        path_value, digest, size = value.get("path"), value.get("sha256"), value.get("bytes")
        if (
            not isinstance(path_value, str)
            or not isinstance(digest, str)
            or not isinstance(size, int)
        ):
            _fail("execution runtime identity is invalid")
        path = Path(path_value)
        if path.parent.resolve(strict=True) != (root / "runtime").resolve(strict=True):
            _fail("execution runtime path escaped")
        raw = _read(path, size, modes={0o400})
        if len(raw) != size or _sha(raw) != digest:
            _fail("execution runtime bytes changed")
    extension_path = agent.get("extension_path")
    index = runtime_files.get("index.ts")
    if not isinstance(index, dict) or extension_path != index.get("path"):
        _fail("execution agent extension binding mismatch")
    return identity


def _source_record(source_root: Path, repository: str, pr: int) -> dict[str, Any]:
    payload = _json(
        source_root / "benchmarks/real_world/pilot_v2/source-bindings-v1.json", 2 * 1024 * 1024
    )
    records = payload.get("records")
    if not isinstance(records, list):
        _fail("source binding records are invalid")
    matches = [
        item
        for item in records
        if isinstance(item, dict) and item.get("repository") == repository and item.get("pr") == pr
    ]
    if len(matches) != 1:
        _fail("source binding identity is not unique")
    return cast("dict[str, Any]", matches[0])


def _find_packet(packet_root: Path, repository: str, pr: int) -> Path:
    packet = _packet_map(packet_root).get((repository, pr))
    if packet is None:
        _fail("v3 packet is missing")
    return packet


def _open_execution(source_root: Path, execution_root: Path, model: str, thinking: str) -> Path:
    if not execution_root.is_absolute():
        _fail("execution root must be absolute")
    execution_root = execution_root.resolve(strict=False)
    parent = execution_root.parent.resolve(strict=True)
    parent_status = parent.stat()
    if (
        not stat.S_ISDIR(parent_status.st_mode)
        or parent_status.st_uid != os.getuid()
        or stat.S_IMODE(parent_status.st_mode) & 0o077
    ):
        _fail("execution parent is not private")
    lock_path = parent / f".{execution_root.name}.initialize.lock"
    descriptor = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_uid != os.getuid()
            or stat.S_IMODE(status.st_mode) != 0o600
        ):
            _fail("execution initialization lock is invalid")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        if not execution_root.exists():
            execution_root.mkdir(mode=0o700)
            (execution_root / "attempts").mkdir(mode=0o700)
            (execution_root / "leases").mkdir(mode=0o700)
            identity = _materialize_execution_runtime(execution_root, source_root, model, thinking)
            _atomic(execution_root / "execution.json", canonical_json(identity), mode=0o400)
            _reauthenticate_execution(execution_root)
            return execution_root
        root_status = execution_root.stat()
        if (
            not stat.S_ISDIR(root_status.st_mode)
            or root_status.st_uid != os.getuid()
            or stat.S_IMODE(root_status.st_mode) & 0o077
        ):
            _fail("execution root is not private")
        identity = _reauthenticate_execution(execution_root)
        if (
            identity.get("source_root") != str(source_root)
            or identity.get("model") != model
            or identity.get("thinking") != thinking
        ):
            _fail("execution identity mismatch")
        attempts = execution_root / "attempts"
        leases = execution_root / "leases"
        if (
            not attempts.is_dir()
            or attempts.is_symlink()
            or not leases.is_dir()
            or leases.is_symlink()
        ):
            _fail("execution state roots are invalid")
        return execution_root
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _authenticated_inputs(
    packet: Path, run_hashes: dict[str, str]
) -> tuple[pilot_submit_v3.AuthenticatedInput, ...]:
    paths: dict[str, Path] = {"packet_manifest": packet / "packet-manifest.json"}
    paths.update({key: packet / "policies-v3" / value for key, value in _POLICY_FILES.items()})
    inputs: list[pilot_submit_v3.AuthenticatedInput] = []
    for name in (
        "packet_manifest",
        "review_prompt",
        "model_policy",
        "tool_policy",
        "source_policy",
    ):
        path = paths[name]
        raw = _read(path, 8 * 1024 * 1024, modes={0o444})
        digest = _sha(raw)
        if name in run_hashes and run_hashes[name] != digest:
            _fail("packet policy does not match bound run")
        inputs.append(
            pilot_submit_v3.AuthenticatedInput(
                name=cast("Any", name), path=str(path), sha256=digest, bytes=len(raw), mode=0o444
            )
        )
    return tuple(inputs)


def create_binding(
    *,
    source_root: Path,
    cache_root: Path,
    packet: Path,
    attempt_dir: Path,
    attempt_id: str,
    repository: str,
    pr: int,
    lane: Literal["A", "B"],
    reviewer_name: str,
    reviewer_version: str,
    started_at: datetime,
    max_seconds: int = _MAX_WALL_SECONDS,
) -> tuple[pilot_submit_v3.SubmissionBinding, Path]:
    if not _ATTEMPT.fullmatch(attempt_id):
        _fail("attempt id is invalid")
    source = _source_record(source_root, repository, pr)
    manifest_path = packet / "packet-manifest.json"
    manifest_raw = _read(manifest_path, 16 * 1024 * 1024, modes={0o444})
    manifest = _json(manifest_path, 16 * 1024 * 1024, modes={0o444})
    expected = {
        "repository": repository,
        "pr": pr,
        "baseline_commit": source["baseline_commit"],
        "target_commit": source["target_commit"],
        "baseline_tree": source["baseline_tree"],
        "target_tree": source["target_tree"],
    }
    if any(manifest.get(key) != value for key, value in expected.items()):
        _fail("packet and source binding disagree")
    _, inventory_hash = pilot_submit_v3._inventory(manifest)
    policy_paths = {key: packet / "policies-v3" / name for key, name in _POLICY_FILES.items()}
    policy_hashes = {
        key: _sha(_read(path, 8 * 1024 * 1024, modes={0o444})) for key, path in policy_paths.items()
    }
    status = packet.stat()
    escrow_path = attempt_dir / "escrow" / "review.json"
    record = pilot_submit_v3.SubmissionBinding(
        schema_version=1,
        attempt_id=attempt_id,
        capability=secrets.token_hex(32),
        packet_path=str(packet),
        packet_device=status.st_dev,
        packet_inode=status.st_ino,
        packet_manifest_sha256=_sha(manifest_raw),
        packet_root_sha256=cast("str", manifest["packet_root_sha256"]),
        blob_inventory_sha256=inventory_hash,
        authenticated_inputs=_authenticated_inputs(packet, policy_hashes),
        escrow_path=str(escrow_path),
        cache_root=str(cache_root),
        corpus_id="blind-review-pilot-typed-v3",
        repository=repository,
        pr=pr,
        lane=lane,
        snapshots=SnapshotBinding(
            baseline_commit=cast("str", source["baseline_commit"]),
            target_commit=cast("str", source["target_commit"]),
        ),
        baseline_tree=cast("str", source["baseline_tree"]),
        target_tree=cast("str", source["target_tree"]),
        reviewer=Actor(kind="agent", name=reviewer_name, version=reviewer_version),
        run=pilot_submit_v3.BoundRun(
            prompt_sha256=policy_hashes["review_prompt"],
            model_policy_sha256=policy_hashes["model_policy"],
            tool_policy_sha256=policy_hashes["tool_policy"],
            source_policy_sha256=policy_hashes["source_policy"],
            started_at=started_at,
            limits=ResourceLimits(
                max_tokens=100_000,
                max_tool_calls=203,
                max_seconds=max_seconds,
                max_output_bytes=2_097_152,
            ),
        ),
        max_validation_attempts=3,
    )
    bindings = pilot_submit_v3.SubmissionBindings(
        schema_version=1, protocol="blind-review-submit-v3", records=(record,)
    )
    binding_path = attempt_dir / "binding.json"
    _atomic(binding_path, canonical_json(bindings.model_dump(mode="json")), mode=0o600)
    pilot_submit_v3.load_bindings(binding_path)
    return record, binding_path


def _runtime_root() -> Path:
    root = Path("/tmp") / f"pilot-review-v3-{os.getuid()}"
    for path in (root, root / "registry", root / "sockets"):
        path.mkdir(mode=0o700, exist_ok=True)
        status = path.lstat()
        if (
            stat.S_ISLNK(status.st_mode)
            or not stat.S_ISDIR(status.st_mode)
            or status.st_uid != os.getuid()
            or stat.S_IMODE(status.st_mode) != 0o700
        ):
            _fail("native runtime directory is unsafe")
    return root


def _registry_key(status: os.stat_result) -> str:
    return hashlib.sha256(f"{status.st_dev}:{status.st_ino}".encode()).hexdigest()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _lease_payload(execution_root: Path, attempt_id: str, slot: int) -> dict[str, object]:
    pid = os.getpid()
    return {
        "schema_version": 1,
        "slot": slot,
        "attempt_id": attempt_id,
        "phase": "preparing",
        "owner_pid": pid,
        "owner_start_identity": _proc_start_identity(pid),
        "created_at": _utc_text(_utc_now()),
        "state_path": str(execution_root / "attempts" / attempt_id / "native-state.json"),
        "broker_pid": None,
        "broker_start_identity": None,
        "registry": None,
        "socket_dir": None,
    }


def _replace_private_json(path: Path, value: dict[str, object]) -> None:
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_json(value))
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _reconcile_orphan_lease(path: Path) -> bool:
    """Remove only a dead preparation whose durable state was never published."""
    lease = _json(path, 128 * 1024, modes={0o600})
    if lease.get("phase") != "preparing" or Path(str(lease.get("state_path"))).exists():
        return False
    pid, identity = lease.get("owner_pid"), lease.get("owner_start_identity")
    if not isinstance(pid, int) or not isinstance(identity, str) or _same_process(pid, identity):
        return False
    broker_pid, broker_identity = lease.get("broker_pid"), lease.get("broker_start_identity")
    if isinstance(broker_pid, int) and isinstance(broker_identity, str):
        _terminate_process(broker_pid, broker_identity)
    registry = lease.get("registry")
    if isinstance(registry, str):
        Path(registry).unlink(missing_ok=True)
    socket_dir = lease.get("socket_dir")
    if isinstance(socket_dir, str):
        shutil.rmtree(socket_dir, ignore_errors=True)
    attempt = Path(str(lease["state_path"])).parent
    if attempt.is_dir() and not attempt.is_symlink():
        marker = attempt / "native-failure.json"
        if not marker.exists():
            _atomic(
                marker,
                canonical_json(
                    {
                        "schema_version": 1,
                        "attempt_id": lease.get("attempt_id"),
                        "diagnostic": "orphaned_preparation",
                        "failed_at": _utc_text(_utc_now()),
                    }
                ),
                mode=0o400,
            )
    path.unlink()
    _fsync_directory(path.parent)
    return True


def _claim_lease(execution_root: Path, attempt_id: str) -> tuple[int, Path]:
    for slot in range(3):
        path = execution_root / "leases" / f"slot-{slot}.json"
        if path.exists() and not _reconcile_orphan_lease(path):
            continue
        try:
            descriptor = os.open(
                path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
            )
        except FileExistsError:
            continue
        try:
            os.write(descriptor, canonical_json(_lease_payload(execution_root, attempt_id, slot)))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _fsync_directory(path.parent)
        return slot, path
    _fail("maximum three active native attempts reached")


def _update_lease(path: Path, attempt_id: str, **updates: object) -> None:
    value = _json(path, 128 * 1024, modes={0o600})
    if value.get("attempt_id") != attempt_id:
        _fail("native lease ownership mismatch")
    value.update(updates)
    _replace_private_json(path, cast("dict[str, object]", value))


def _release_lease(path: Path, attempt_id: str) -> None:
    if _json(path, 64 * 1024, modes={0o600}).get("attempt_id") != attempt_id:
        _fail("native lease ownership mismatch")
    path.unlink()
    _fsync_directory(path.parent)


def _limits() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (_MAX_WALL_SECONDS, _MAX_WALL_SECONDS))
    resource.setrlimit(resource.RLIMIT_AS, (_MAX_RSS_BYTES, _MAX_RSS_BYTES))
    resource.setrlimit(resource.RLIMIT_FSIZE, (_MAX_STDIO_BYTES, _MAX_STDIO_BYTES))


def _proc_start_identity(pid: int) -> str:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
    except (OSError, UnicodeDecodeError) as exc:
        raise PilotTypedRunError("cannot authenticate broker process") from exc
    closing = raw.rfind(")")
    fields = raw[closing + 2 :].split() if closing >= 0 else []
    if len(fields) < 20 or not fields[19].isdigit():
        _fail("broker process identity is invalid")
    return fields[19]


def _same_process(pid: int, identity: str) -> bool:
    try:
        return _proc_start_identity(pid) == identity
    except PilotTypedRunError:
        return False


def _reap_process(pid: int) -> None:
    with contextlib.suppress(ChildProcessError, ProcessLookupError):
        os.waitpid(pid, os.WNOHANG)


def _terminate_process(pid: int, identity: str) -> None:
    if not _same_process(pid, identity):
        _reap_process(pid)
        return
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pid, signal.SIGTERM)
    deadline = time.monotonic() + 2
    while _same_process(pid, identity) and time.monotonic() < deadline:
        _reap_process(pid)
        time.sleep(0.02)
    if _same_process(pid, identity):
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(pid, signal.SIGKILL)
        deadline = time.monotonic() + 2
        while _same_process(pid, identity) and time.monotonic() < deadline:
            _reap_process(pid)
            time.sleep(0.02)
    _reap_process(pid)


def _serve_native_broker(
    socket_path: Path, binding_path: Path, status_path: Path, deadline_unix_ms: int
) -> int:
    outcome, diagnostic, code = "success", "", 0
    try:
        _limits()
        pilot_submit_v3.serve(
            socket_path,
            binding_path,
            timeout_seconds=_MAX_WALL_SECONDS,
            deadline_unix_ms=deadline_unix_ms,
        )
    except BaseException as exc:
        outcome, diagnostic, code = "failure", type(exc).__name__, 1
    _atomic(
        status_path,
        canonical_json(
            {
                "schema_version": 1,
                "outcome": outcome,
                "diagnostic": diagnostic,
                "completed_at": _utc_text(_utc_now()),
            }
        ),
        mode=0o400,
    )
    return code


def _validate_registry_descriptor(path: Path, packet: Path) -> dict[str, Any]:
    status = path.lstat()
    if (
        stat.S_ISLNK(status.st_mode)
        or not stat.S_ISREG(status.st_mode)
        or status.st_uid != os.getuid()
        or stat.S_IMODE(status.st_mode) != 0o600
    ):
        _fail("native registry descriptor is unsafe")
    value = _json(path, 128 * 1024, modes={0o600})
    packet_status = packet.stat()
    expected_keys = {
        "schema_version",
        "protocol",
        "attempt_id",
        "cwd",
        "cwd_device",
        "cwd_inode",
        "socket_path",
        "capability",
    }
    if (
        set(value) != expected_keys
        or value.get("schema_version") != 1
        or value.get("protocol") != "blind-review-native-registry-v3"
        or value.get("cwd") != str(packet)
        or value.get("cwd_device") != str(packet_status.st_dev)
        or value.get("cwd_inode") != str(packet_status.st_ino)
        or not isinstance(value.get("attempt_id"), str)
        or not isinstance(value.get("socket_path"), str)
        or not isinstance(value.get("capability"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", cast("str", value.get("capability")))
    ):
        _fail("native registry descriptor fields are invalid")
    return value


def _write_registry(
    runtime_root: Path, packet: Path, record: pilot_submit_v3.SubmissionBinding, socket_path: Path
) -> Path:
    status = packet.stat()
    path = runtime_root / "registry" / f"{_registry_key(status)}.json"
    _atomic(
        path,
        canonical_json(
            {
                "schema_version": 1,
                "protocol": "blind-review-native-registry-v3",
                "attempt_id": record.attempt_id,
                "cwd": str(packet),
                "cwd_device": str(status.st_dev),
                "cwd_inode": str(status.st_ino),
                "socket_path": str(socket_path),
                "capability": record.capability,
            }
        ),
        mode=0o600,
    )
    _validate_registry_descriptor(path, packet)
    return path


def _wait_socket(path: Path, pid: int, identity: str, timeout: int = 30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            status = path.lstat()
            if (
                stat.S_ISSOCK(status.st_mode)
                and status.st_uid == os.getuid()
                and stat.S_IMODE(status.st_mode) == 0o600
            ):
                return
            _fail("native broker socket is unsafe")
        if not _same_process(pid, identity):
            _fail("native broker failed before readiness")
        time.sleep(0.01)
    _fail("native broker readiness timeout")


def prepare_native_attempt(  # noqa: PLR0915
    *,
    source_root: Path,
    cache_root: Path,
    packet_root: Path,
    execution_root: Path,
    repository: str,
    pr: int,
    lane: Literal["A", "B"],
    attempt_id: str,
    model: str = "openai-codex/gpt-5.6-luna",
    thinking: str = "medium",
    reviewer_name: str = "pilot-blind-reviewer-luna-medium-v3",
    timeout_seconds: int = _MAX_WALL_SECONDS,
) -> dict[str, object]:
    """Prepare one broker-bound cwd for a later parent-native subagent tool call."""
    if not _ATTEMPT.fullmatch(attempt_id):
        _fail("attempt id is invalid")
    if timeout_seconds <= 0 or timeout_seconds > _MAX_WALL_SECONDS:
        _fail("timeout is out of range")
    source_root, cache_root = source_root.resolve(strict=True), cache_root.resolve(strict=True)
    packet_root = packet_root.resolve(strict=True)
    execution_root = _open_execution(source_root, execution_root, model, thinking)
    slot, lease = _claim_lease(execution_root, attempt_id)
    attempt = execution_root / "attempts" / attempt_id
    broker_pid: int | None = None
    broker_identity: str | None = None
    socket_dir: Path | None = None
    registry: Path | None = None
    attempt_created = False
    try:
        attempt.mkdir(mode=0o700)
        attempt_created = True
        (attempt / "escrow").mkdir(mode=0o700)
        (attempt / "logs").mkdir(mode=0o700)
        packet = attempt / "packet"
        _copy_exact(_find_packet(packet_root, repository, pr), packet)
        _freeze_tree(packet)
        started = _utc_now()
        record, binding = create_binding(
            source_root=source_root,
            cache_root=cache_root,
            packet=packet,
            attempt_dir=attempt,
            attempt_id=attempt_id,
            repository=repository,
            pr=pr,
            lane=lane,
            reviewer_name=reviewer_name,
            reviewer_version=f"{model}:{thinking}",
            started_at=started,
            max_seconds=timeout_seconds,
        )
        runtime = _runtime_root()
        socket_dir = Path(tempfile.mkdtemp(prefix=f"{attempt_id[:20]}-", dir=runtime / "sockets"))
        socket_path = socket_dir / "submit.sock"
        registry = _write_registry(runtime, packet, record, socket_path)
        broker_status = attempt / "broker-status.json"
        deadline_unix_ms = int(started.timestamp() * 1000) + timeout_seconds * 1000
        if deadline_unix_ms <= int(time.time() * 1000):
            _fail("native preparation exhausted attempt deadline")
        _update_lease(
            lease,
            attempt_id,
            registry=str(registry),
            socket_dir=str(socket_dir),
        )
        argv = [
            sys.executable,
            "-m",
            "benchmarks.real_world.pilot_typed_run_v3",
            "serve-native-broker",
            "--socket",
            str(socket_path),
            "--binding",
            str(binding),
            "--status",
            str(broker_status),
            "--deadline-unix-ms",
            str(deadline_unix_ms),
        ]
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", os.devnull),
            "LC_ALL": "C",
            "PYTHONPATH": str(source_root),
        }
        stdout_fd = os.open(attempt / "logs/broker.stdout", os.O_WRONLY | os.O_CREAT, 0o600)
        stderr_fd = os.open(attempt / "logs/broker.stderr", os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            actions = [
                (os.POSIX_SPAWN_DUP2, stdout_fd, 1),
                (os.POSIX_SPAWN_DUP2, stderr_fd, 2),
                (os.POSIX_SPAWN_CLOSE, stdout_fd),
                (os.POSIX_SPAWN_CLOSE, stderr_fd),
            ]
            broker_pid = os.posix_spawn(
                sys.executable, argv, env, file_actions=actions, setsid=True
            )
        finally:
            os.close(stdout_fd)
            os.close(stderr_fd)
        broker_identity = _proc_start_identity(broker_pid)
        _update_lease(
            lease,
            attempt_id,
            broker_pid=broker_pid,
            broker_start_identity=broker_identity,
        )
        _wait_socket(socket_path, broker_pid, broker_identity)
        launch: dict[str, object] = {
            "agent": reviewer_name,
            "cwd": str(packet),
            "model": model,
            "thinking": thinking,
            "attempt": attempt_id,
        }
        state = {
            "schema_version": 1,
            "attempt_id": attempt_id,
            "repository": repository,
            "pr": pr,
            "lane": lane,
            "packet": str(packet),
            "binding": str(binding),
            "registry": str(registry),
            "socket_dir": str(socket_dir),
            "broker_pid": broker_pid,
            "broker_start_identity": broker_identity,
            "broker_status": str(broker_status),
            "deadline_unix_ms": deadline_unix_ms,
            "lease_slot": slot,
            "lease": str(lease),
            "prepared_at": _utc_text(started),
        }
        _atomic(attempt / "native-state.json", canonical_json(state), mode=0o600)
        _update_lease(
            lease,
            attempt_id,
            phase="active",
            owner_pid=broker_pid,
            owner_start_identity=broker_identity,
        )
        _atomic(attempt / "native-launch.json", canonical_json(launch), mode=0o400)
        return launch
    except BaseException:
        if broker_pid is not None and broker_identity is not None:
            _terminate_process(broker_pid, broker_identity)
        if registry is not None:
            registry.unlink(missing_ok=True)
        if socket_dir is not None:
            shutil.rmtree(socket_dir, ignore_errors=True)
        with contextlib.suppress(Exception):
            _release_lease(lease, attempt_id)
        if attempt_created:
            with contextlib.suppress(Exception):
                _atomic(
                    attempt / "native-failure.json",
                    canonical_json(
                        {
                            "schema_version": 1,
                            "attempt_id": attempt_id,
                            "failed_at": _utc_text(_utc_now()),
                        }
                    ),
                    mode=0o400,
                )
        raise


def _load_native_state(execution_root: Path, attempt_id: str) -> tuple[Path, dict[str, Any]]:
    if not execution_root.is_absolute():
        _fail("execution root must be absolute")
    if not _ATTEMPT.fullmatch(attempt_id):
        _fail("attempt id is invalid")
    attempt = execution_root.resolve(strict=True) / "attempts" / attempt_id
    if not attempt.is_dir() or attempt.is_symlink():
        _fail("native attempt is missing")
    return attempt, _json(attempt / "native-state.json", 512 * 1024, modes={0o600})


def _cleanup_native(state: dict[str, Any]) -> None:
    registry = Path(str(state["registry"]))
    if registry.exists() or registry.is_symlink():
        registry.unlink()
        _fsync_directory(registry.parent)
    shutil.rmtree(Path(str(state["socket_dir"])), ignore_errors=True)
    lease = Path(str(state["lease"]))
    if lease.exists() or lease.is_symlink():
        _release_lease(lease, str(state["attempt_id"]))


def _run_git(cache: Path, args: Sequence[str]) -> bytes:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.devnull,
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_LAZY_FETCH": "1",
    }
    try:
        result = subprocess.run(
            ["git", *args], cwd=cache, env=env, check=False, capture_output=True, timeout=30
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise GroundTruthError("offline Git evidence command failed") from exc
    if result.returncode != 0 or len(result.stdout) > 4 * 1024 * 1024:
        raise GroundTruthError("offline Git evidence command failed")
    return result.stdout


def _validator_for(binding: pilot_submit_v3.SubmissionBinding) -> GitEvidenceValidator:
    return GitEvidenceValidator(
        Path(binding.cache_root),
        binding.repository,
        binding.snapshots.baseline_commit,
        binding.snapshots.target_commit,
        binding.baseline_tree,
        binding.target_tree,
        runner=_run_git,
    )


def _authenticated_result(path: Path, binding: pilot_submit_v3.SubmissionBinding) -> dict[str, Any]:
    result = _json(path, _MAX_RESULT_BYTES, modes={0o400})
    receipt = pilot_submit_v3.recover_submission(binding, validator=_validator_for(binding))
    artifact = _read(Path(binding.escrow_path), binding.run.limits.max_output_bytes, modes={0o400})
    expected = {
        "schema_version": 1,
        "attempt_id": binding.attempt_id,
        "repository": binding.repository,
        "pr": binding.pr,
        "lane": binding.lane,
        "receipt": receipt.model_dump(mode="json"),
        "artifact_sha256": artifact_sha256(artifact),
    }
    if (
        set(result) != {*expected, "finalized_at"}
        or any(result.get(key) != value for key, value in expected.items())
        or not isinstance(result.get("finalized_at"), str)
    ):
        _fail("existing native result failed authentication")
    return result


def finalize_native_attempt(  # noqa: PLR0912,PLR0915 - terminal transaction is linear
    *, execution_root: Path, attempt_id: str, wait_seconds: int | None = None
) -> dict[str, object]:
    """Accept escrow independently of native tool prose, then clean every capability."""
    if not execution_root.is_absolute():
        _fail("execution root must be absolute")
    if not _ATTEMPT.fullmatch(attempt_id):
        _fail("attempt id is invalid")
    root = execution_root.resolve(strict=True)
    attempt = root / "attempts" / attempt_id
    if not attempt.is_dir() or attempt.is_symlink():
        _fail("native attempt is missing")
    lock = os.open(
        attempt / "finalize.lock",
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        lock_status = os.fstat(lock)
        if (
            not stat.S_ISREG(lock_status.st_mode)
            or lock_status.st_uid != os.getuid()
            or stat.S_IMODE(lock_status.st_mode) != 0o600
        ):
            _fail("native finalize lock is unsafe")
        fcntl.flock(lock, fcntl.LOCK_EX)
        attempt, state = _load_native_state(root, attempt_id)
        result_path, failure_path = attempt / "native-result.json", attempt / "native-failure.json"
        if result_path.exists() and failure_path.exists():
            _fail("native attempt has conflicting terminal markers")
        binding = pilot_submit_v3.load_bindings(Path(str(state["binding"]))).records[0]
        if result_path.exists():
            existing_result = _authenticated_result(result_path, binding)
            _cleanup_native(state)
            return existing_result
        if failure_path.exists():
            _cleanup_native(state)
            _fail("native attempt already finalized as failure")
        pid, identity = int(state["broker_pid"]), str(state["broker_start_identity"])
        status_path = Path(str(state["broker_status"]))
        try:
            absolute_deadline = int(state["deadline_unix_ms"]) / 1000
            wait_deadline = absolute_deadline
            if wait_seconds is not None:
                wait_deadline = min(wait_deadline, time.time() + max(0, wait_seconds))
            receipt: pilot_submit_v3.SubmissionReceipt | None = None
            broker: dict[str, Any] | None = None
            while True:
                if status_path.exists():
                    broker = _json(status_path, 256 * 1024, modes={0o400})
                    if broker.get("outcome") == "failure":
                        _fail("native broker did not report success")
                try:
                    receipt = pilot_submit_v3.recover_submission(
                        binding, validator=_validator_for(binding)
                    )
                except pilot_submit_v3.SubmissionRejected as exc:
                    if exc.code != "NOT_SUBMITTED":
                        raise
                if receipt is not None and broker is not None:
                    break
                if time.time() >= wait_deadline:
                    break
                if not _same_process(pid, identity) and broker is None:
                    _fail("native broker exited without terminal status")
                time.sleep(0.02)
            if receipt is None or broker is None or broker.get("outcome") != "success":
                _fail("native attempt did not complete before deadline")
            _reap_process(pid)
            artifact = _read(
                Path(binding.escrow_path), binding.run.limits.max_output_bytes, modes={0o400}
            )
            result: dict[str, object] = {
                "schema_version": 1,
                "attempt_id": binding.attempt_id,
                "repository": binding.repository,
                "pr": binding.pr,
                "lane": binding.lane,
                "receipt": receipt.model_dump(mode="json"),
                "artifact_sha256": artifact_sha256(artifact),
                "finalized_at": _utc_text(_utc_now()),
            }
            _atomic(result_path, canonical_json(result), mode=0o400)
            _cleanup_native(state)
            return result
        except BaseException as exc:
            _terminate_process(pid, identity)
            if not result_path.exists() and not failure_path.exists():
                _atomic(
                    failure_path,
                    canonical_json(
                        {
                            "schema_version": 1,
                            "attempt_id": attempt_id,
                            "diagnostic": type(exc).__name__,
                            "failed_at": _utc_text(_utc_now()),
                        }
                    ),
                    mode=0o400,
                )
            with contextlib.suppress(Exception):
                _cleanup_native(state)
            raise
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)


def _frontmatter_runtime_name(path: Path, raw: bytes) -> str | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PilotTypedRunError(f"agent definition is not UTF-8: {path.name}") from exc
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None
    fields: dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            break
        key, separator, value = line.partition(":")
        if not separator or key.strip() not in {"name", "package"}:
            continue
        key = key.strip()
        if key in fields:
            _fail("agent definition has duplicate identity field")
        fields[key] = value.strip().strip("\"'")
    else:
        _fail("agent definition frontmatter is unterminated")
    name = fields.get("name")
    package = fields.get("package")
    if name is None:
        return None
    if not _AGENT_COMPONENT.fullmatch(name) or (
        package is not None and not _AGENT_COMPONENT.fullmatch(package)
    ):
        _fail("agent definition runtime identity is invalid")
    return f"{package}.{name}" if package else name


def _normalized_discovery_root(path: Path, field: str) -> Path:
    if not path.is_absolute():
        _fail(f"{field} agent discovery root must be absolute")
    normalized = Path(os.path.abspath(path))  # noqa: PTH100 - resolving would hide symlinks
    current = Path(normalized.anchor)
    for part in normalized.parts[1:]:
        current /= part
        if (current.exists() or current.is_symlink()) and stat.S_ISLNK(current.lstat().st_mode):
            _fail(f"{field} agent discovery root has a symlink ancestor")
    return normalized


def _pi_config_dir_name() -> str:
    package_root = os.environ.get("PI_SUBAGENTS_PI_CODING_AGENT_PACKAGE_ROOT")
    if not package_root:
        return ".pi"
    root = _normalized_discovery_root(Path(package_root), "Pi coding-agent package")
    payload = _json(root / "package.json", 1024 * 1024)
    config = payload.get("piConfig")
    value = config.get("configDir") if isinstance(config, dict) else None
    if payload.get("name") != "@earendil-works/pi-coding-agent" or not isinstance(value, str):
        _fail("Pi coding-agent package config is invalid")
    if not value.strip() or "/" in value or "\\" in value or value in {".", ".."}:
        _fail("Pi coding-agent config directory is unsafe")
    return value


def _pi_agent_dir() -> Path:
    configured = os.environ.get("PI_CODING_AGENT_DIR")
    if configured == "~":
        path = Path.home()
    elif configured and configured.startswith("~/"):
        path = Path.home() / configured[2:]
    elif configured:
        path = Path(configured)
        if not path.is_absolute():
            _fail("relative PI_CODING_AGENT_DIR is unsupported for native review")
    else:
        path = Path.home() / _pi_config_dir_name() / "agent"
    return _normalized_discovery_root(path, "Pi agent")


def _pi_subagents_agents_module() -> Path:
    override = os.environ.get("PILOT_PI_SUBAGENTS_AGENTS_MODULE")
    module = (
        Path(override)
        if override
        else _pi_agent_dir() / "npm/node_modules/pi-subagents/src/agents/agents.ts"
    )
    module = _normalized_discovery_root(module, "pi-subagents module")
    package = module.parents[2]
    payload = _json(package / "package.json", 1024 * 1024)
    if payload.get("name") != "pi-subagents" or payload.get("version") != "0.34.0":
        _fail("pinned pi-subagents 0.34.0 is unavailable")
    _read(module, 8 * 1024 * 1024)
    return module


def _runtime_agent_discovery(identity: dict[str, Any]) -> dict[str, object]:
    """Ask the pinned resolver for its exact builtin/package/user/project candidates."""
    if os.environ.get("PI_SUBAGENT_EXTRA_AGENT_DIRS", "").strip():
        _fail("PI_SUBAGENT_EXTRA_AGENT_DIRS is unsupported for native review")
    module = _pi_subagents_agents_module()
    jiti = module.parents[3] / "jiti/lib/jiti.mjs"
    _read(jiti, 8 * 1024 * 1024)
    source_root = Path(cast("str", identity["source_root"])).resolve(strict=True)
    script = """
import { pathToFileURL } from 'node:url';
const { createJiti } = await import(pathToFileURL(process.argv[1]).href);
const modulePath = process.argv[2];
const cwd = process.argv[3];
const api = await createJiti(import.meta.url).import(modulePath);
const all = api.discoverAgentsAll(cwd);
const effective = api.discoverAgents(cwd, 'both').agents;
const row = (agent) => ({
  name: agent.name,
  filePath: agent.filePath,
  source: agent.source,
  disabled: agent.disabled === true,
});
const payload = {
  schema_version: 1,
  roots: {
    userDir: all.userDir,
    projectDir: all.projectDir,
    userSettingsPath: all.userSettingsPath,
    projectSettingsPath: all.projectSettingsPath,
  },
  definitions: {
    builtin: all.builtin.map(row),
    package: all.package.map(row),
    user: all.user.map(row),
    project: all.project.map(row),
  },
  effective: effective.map(row),
};
process.stdout.write(JSON.stringify(payload));
"""
    node = shutil.which("node")
    if node is None:
        _fail("Node is unavailable for exact agent discovery")
    try:
        result = subprocess.run(
            [
                node,
                "--input-type=module",
                "-e",
                script,
                str(jiti),
                str(module),
                str(source_root),
            ],
            cwd=source_root,
            env=dict(os.environ),
            check=False,
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise PilotTypedRunError("pinned agent discovery failed") from exc
    if result.returncode != 0 or result.stderr or len(result.stdout) > 8 * 1024 * 1024:
        _fail("pinned agent discovery failed")
    try:
        payload = json.loads(result.stdout, object_pairs_hook=_unique, parse_constant=_constant)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise PilotTypedRunError("pinned agent discovery output is invalid") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        _fail("pinned agent discovery output is invalid")
    package_path = module.parents[2] / "package.json"
    module_raw = _read(module, 8 * 1024 * 1024)
    package_raw = _read(package_path, 1024 * 1024)
    payload["resolver"] = {
        "module_path": str(module),
        "module_sha256": _sha(module_raw),
        "package_path": str(package_path),
        "package_sha256": _sha(package_raw),
        "package_version": "0.34.0",
    }
    canonical_json(payload)
    return cast("dict[str, object]", payload)


def _discovery_roots(
    identity: dict[str, Any],
    *,
    user_agent_root: Path | None = None,
    builtin_agent_root: Path | None = None,
) -> list[tuple[str, Path]]:
    if os.environ.get("PI_SUBAGENT_EXTRA_AGENT_DIRS", "").strip():
        _fail("PI_SUBAGENT_EXTRA_AGENT_DIRS is unsupported for native review")
    source_root = Path(cast("str", identity["source_root"])).resolve(strict=True)
    configured_user = user_agent_root
    if configured_user is None:
        override = os.environ.get("PILOT_PI_USER_AGENT_ROOT")
        configured_user = Path(override) if override else _pi_agent_dir() / "agents"
    user = _normalized_discovery_root(configured_user, "user")
    roots: list[tuple[str, Path]] = [
        ("project", source_root / ".pi/agents"),
        ("legacy_project", source_root / ".agents"),
        ("user", user),
        ("legacy_user", Path.home() / ".agents"),
    ]
    if builtin_agent_root is not None:
        roots.append(("builtin", _normalized_discovery_root(builtin_agent_root, "builtin")))
    else:
        override = os.environ.get("PILOT_PI_BUILTIN_AGENT_ROOT")
        if override:
            candidate = Path(override)
            roots.append(("builtin", _normalized_discovery_root(candidate, "builtin")))
        else:
            roots.append(
                (
                    "builtin",
                    _normalized_discovery_root(
                        _pi_subagents_agents_module().parents[2] / "agents", "builtin"
                    ),
                )
            )
    paths = [path for _kind, path in roots]
    if len(paths) != len(set(paths)):
        _fail("agent discovery roots overlap")
    return roots


def _agent_discovery_census(  # noqa: PLR0912,PLR0915
    identity: dict[str, Any],
    *,
    user_agent_root: Path | None = None,
    builtin_agent_root: Path | None = None,
) -> dict[str, object]:
    roots = _discovery_roots(
        identity,
        user_agent_root=user_agent_root,
        builtin_agent_root=builtin_agent_root,
    )
    root_rows: list[dict[str, object]] = []
    definitions: list[dict[str, object]] = []
    total_bytes = 0
    for kind, root in roots:
        if not root.exists():
            root_rows.append({"kind": kind, "path": str(root), "exists": False})
            continue
        root_status = root.lstat()
        if stat.S_ISLNK(root_status.st_mode) or not stat.S_ISDIR(root_status.st_mode):
            _fail("agent discovery root is unsafe")
        root_rows.append({"kind": kind, "path": str(root), "exists": True})
        pending = [root]
        while pending:
            current = pending.pop()
            for entry in sorted(os.scandir(current), key=lambda item: item.name):
                status = entry.stat(follow_symlinks=False)
                entry_path = Path(entry.path)
                if stat.S_ISDIR(status.st_mode):
                    pending.append(entry_path)
                    continue
                if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
                    _fail("agent discovery tree contains unsafe entry")
                if entry_path.suffix != ".md":
                    continue
                if len(definitions) >= _MAX_AGENT_FILES:
                    _fail("agent discovery file bound exceeded")
                raw = _read(entry_path, _MAX_FILE_BYTES)
                total_bytes += len(raw)
                if total_bytes > _MAX_AGENT_CENSUS_BYTES:
                    _fail("agent discovery byte bound exceeded")
                definitions.append(
                    {
                        "root_kind": kind,
                        "path": str(entry_path.resolve(strict=True)),
                        "sha256": _sha(raw),
                        "bytes": len(raw),
                        "runtime_name": _frontmatter_runtime_name(entry_path, raw),
                    }
                )
    definitions.sort(key=lambda item: (str(item["path"]), str(item["root_kind"])))
    target_paths = [
        cast("str", item["path"])
        for item in definitions
        if item["runtime_name"] == _NATIVE_AGENT_NAME
    ]
    runtime = _runtime_agent_discovery(identity)
    runtime_definitions = runtime.get("definitions")
    effective = runtime.get("effective")
    if not isinstance(runtime_definitions, dict) or not isinstance(effective, list):
        _fail("pinned agent discovery output fields are invalid")
    runtime_candidates: list[str] = []
    for source in ("builtin", "package", "user", "project"):
        rows = runtime_definitions.get(source)
        if not isinstance(rows, list):
            _fail("pinned agent discovery definition rows are invalid")
        for row in rows:
            if not isinstance(row, dict):
                _fail("pinned agent discovery definition is invalid")
            if row.get("name") == _NATIVE_AGENT_NAME:
                path = row.get("filePath")
                if not isinstance(path, str):
                    _fail("pinned agent discovery target path is invalid")
                runtime_candidates.append(str(Path(path).resolve(strict=True)))
    effective_targets = [
        str(Path(cast("str", row["filePath"])).resolve(strict=True))
        for row in effective
        if isinstance(row, dict)
        and row.get("name") == _NATIVE_AGENT_NAME
        and isinstance(row.get("filePath"), str)
    ]
    runtime_candidates.sort()
    effective_targets.sort()
    target_paths = sorted(set(target_paths) | set(runtime_candidates))
    payload = {
        "roots": root_rows,
        "definitions": definitions,
        "runtime_discovery": runtime,
    }
    return {
        "roots": root_rows,
        "definitions": len(definitions),
        "census_sha256": _sha(canonical_json(payload)),
        "target_paths": target_paths,
        "runtime_effective_paths": effective_targets,
        "runtime_discovery_sha256": _sha(canonical_json(runtime)),
    }


def _installed_agent(
    execution_root: Path,
    identity: dict[str, Any],
    *,
    user_agent_root: Path | None = None,
    builtin_agent_root: Path | None = None,
) -> dict[str, Any]:
    receipt = _json(execution_root / "agent-installation.json", 256 * 1024, modes={0o400})
    if set(receipt) != {
        "schema_version",
        "runtime_name",
        "path",
        "sha256",
        "bytes",
        "source_agent_sha256",
        "discovery",
    }:
        _fail("agent installation receipt fields are invalid")
    agent = cast("dict[str, Any]", identity["agent"])
    if (
        receipt.get("schema_version") != 1
        or receipt.get("runtime_name") != agent.get("runtime_name")
        or receipt.get("runtime_name") != _NATIVE_AGENT_NAME
        or receipt.get("sha256") != agent.get("sha256")
        or receipt.get("source_agent_sha256") != agent.get("sha256")
        or not isinstance(receipt.get("path"), str)
        or not isinstance(receipt.get("bytes"), int)
        or not isinstance(receipt.get("discovery"), dict)
    ):
        _fail("agent installation receipt binding is invalid")
    installed = Path(cast("str", receipt["path"]))
    if not installed.is_absolute() or installed.resolve(strict=True) != installed:
        _fail("installed agent path is invalid")
    raw = _read(installed, cast("int", receipt["bytes"]), modes={0o400})
    if len(raw) != receipt["bytes"] or _sha(raw) != receipt["sha256"]:
        _fail("installed agent bytes changed")
    discovery = _agent_discovery_census(
        identity,
        user_agent_root=user_agent_root,
        builtin_agent_root=builtin_agent_root,
    )
    if discovery != receipt["discovery"]:
        _fail("agent discovery census changed")
    if discovery["target_paths"] != [str(installed)] or discovery.get(
        "runtime_effective_paths"
    ) != [str(installed)]:
        _fail("native runtime agent is not the unique resolver definition")
    return receipt


def native_launch_plan(
    execution_root: Path,
    attempt_ids: Sequence[str],
    *,
    user_agent_root: Path | None = None,
    builtin_agent_root: Path | None = None,
) -> dict[str, object]:
    if not execution_root.is_absolute():
        _fail("execution root must be absolute")
    if not attempt_ids or len(attempt_ids) > 6 or len(set(attempt_ids)) != len(attempt_ids):
        _fail("native launch attempt list is invalid")
    root = execution_root.resolve(strict=True)
    identity = _reauthenticate_execution(root)
    agent = cast("dict[str, Any]", identity["agent"])
    installation = _installed_agent(
        root,
        identity,
        user_agent_root=user_agent_root,
        builtin_agent_root=builtin_agent_root,
    )
    tasks: list[dict[str, object]] = []
    remaining: list[int] = []
    now_ms = int(time.time() * 1000)
    for attempt_id in sorted(attempt_ids):
        attempt, state = _load_native_state(root, attempt_id)
        if (attempt / "native-result.json").exists() or (attempt / "native-failure.json").exists():
            _fail("native launch attempt is already terminal")
        launch = _json(attempt / "native-launch.json", 128 * 1024, modes={0o400})
        if (
            launch.get("attempt") != state.get("attempt_id")
            or launch.get("cwd") != state.get("packet")
            or launch.get("agent") != agent.get("runtime_name")
            or launch.get("model") != identity.get("model")
            or launch.get("thinking") != identity.get("thinking")
        ):
            _fail("native launch and state disagree")
        binding = pilot_submit_v3.load_bindings(Path(str(state["binding"]))).records[0]
        if (
            binding.attempt_id != attempt_id
            or binding.packet_path != state.get("packet")
            or binding.repository != state.get("repository")
            or binding.pr != state.get("pr")
            or binding.lane != state.get("lane")
        ):
            _fail("native binding and state disagree")
        registry = _validate_registry_descriptor(
            Path(str(state["registry"])), Path(binding.packet_path)
        )
        if (
            registry.get("attempt_id") != attempt_id
            or registry.get("capability") != binding.capability
            or registry.get("socket_path") != str(Path(str(state["socket_dir"])) / "submit.sock")
        ):
            _fail("native registry and binding disagree")
        pid, process_identity = int(state["broker_pid"]), str(state["broker_start_identity"])
        if not _same_process(pid, process_identity):
            _fail("native broker is not live")
        deadline_ms = state.get("deadline_unix_ms")
        if not isinstance(deadline_ms, int) or deadline_ms <= now_ms:
            _fail("native launch deadline expired")
        remaining.append(deadline_ms - now_ms)
        tasks.append(
            {
                "agent": launch["agent"],
                "task": (
                    "Perform the assigned blind review. Follow your exact system policy and "
                    "terminate through submit_blind_review."
                ),
                "cwd": launch["cwd"],
                "model": launch["model"],
                "output": False,
                "progress": False,
                "toolBudget": {"soft": 200, "hard": 203, "block": ["read", "grep", "find", "ls"]},
                "acceptance": False,
            }
        )
    remaining_ms = min(remaining)
    if remaining_ms < 1_000:
        _fail("native launch has less than one second remaining")
    execution_raw = _read(root / "execution.json", 512 * 1024, modes={0o400})
    return {
        "authentication": {
            "execution_sha256": _sha(execution_raw),
            "agent_file": installation["path"],
            "agent_sha256": installation["sha256"],
            "extension_path": agent["extension_path"],
        },
        "subagent_call": {
            "tasks": tasks,
            "concurrency": 3,
            "context": "fresh",
            "artifacts": False,
            "includeProgress": False,
            "async": False,
            "timeoutMs": remaining_ms // 1_000 * 1_000,
        },
    }


def create_native_agent(
    execution_root: Path,
    output: Path,
    *,
    user_agent_root: Path | None = None,
    builtin_agent_root: Path | None = None,
) -> dict[str, str]:
    root = execution_root.resolve(strict=True)
    identity = _reauthenticate_execution(root)
    agent = cast("dict[str, Any]", identity["agent"])
    source = Path(cast("str", agent["path"]))
    body = _read(source, int(agent["bytes"]), modes={0o400})
    if _sha(body) != agent["sha256"]:
        _fail("execution agent bytes changed")
    if not output.is_absolute():
        _fail("native agent output must be absolute")
    output = output.resolve(strict=False)
    roots = _discovery_roots(
        identity,
        user_agent_root=user_agent_root,
        builtin_agent_root=builtin_agent_root,
    )
    user_roots = [path for kind, path in roots if kind == "user"]
    if len(user_roots) != 1:
        _fail("user agent discovery root is invalid")
    user_root = user_roots[0]
    user_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        output.relative_to(user_root)
    except ValueError as exc:
        raise PilotTypedRunError("native agent output is outside Pi user discovery") from exc
    receipt_path = root / "agent-installation.json"
    if receipt_path.exists() or receipt_path.is_symlink():
        _fail("native agent installation already exists")
    if output.exists() or output.is_symlink():
        _fail("native agent output already exists")
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    status = output.parent.stat()
    if status.st_uid != os.getuid() or stat.S_IMODE(status.st_mode) & 0o077:
        _fail("native agent parent is not private")
    before = _agent_discovery_census(
        identity,
        user_agent_root=user_agent_root,
        builtin_agent_root=builtin_agent_root,
    )
    if before["target_paths"]:
        _fail("native runtime agent already has a resolver definition")
    _atomic(output, body, mode=0o400)
    try:
        discovery = _agent_discovery_census(
            identity,
            user_agent_root=user_agent_root,
            builtin_agent_root=builtin_agent_root,
        )
        if discovery["target_paths"] != [str(output)] or discovery.get(
            "runtime_effective_paths"
        ) != [str(output)]:
            _fail("native runtime agent is not the unique resolver definition")
        receipt: dict[str, object] = {
            "schema_version": 1,
            "runtime_name": agent["runtime_name"],
            "path": str(output),
            "sha256": _sha(body),
            "bytes": len(body),
            "source_agent_sha256": agent["sha256"],
            "discovery": discovery,
        }
        _atomic(receipt_path, canonical_json(receipt), mode=0o400)
        _installed_agent(
            root,
            identity,
            user_agent_root=user_agent_root,
            builtin_agent_root=builtin_agent_root,
        )
    except BaseException:
        receipt_path.unlink(missing_ok=True)
        output.unlink(missing_ok=True)
        raise
    return {
        "runtime_name": cast("str", agent["runtime_name"]),
        "agent_file": str(output),
        "extension": cast("str", agent["extension_path"]),
        "sha256": cast("str", agent["sha256"]),
    }


def _session_integer(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        _fail(f"session usage {field} is invalid")
    return value


def _session_cost(value: object) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        or value < 0
    ):
        _fail("session usage cost.total is invalid")
    return float(value)


def _session_tool_path(packet: Path, value: object) -> None:
    if not isinstance(value, str) or not value or "\x00" in value:
        _fail("session source tool path is invalid")
    candidate = Path(value)
    try:
        resolved = (
            candidate.resolve(strict=False)
            if candidate.is_absolute()
            else (packet / candidate).resolve(strict=False)
        )
        resolved.relative_to(packet)
    except (OSError, RuntimeError, ValueError) as exc:
        raise PilotTypedRunError("session source tool escaped assigned packet") from exc


def _session_submission_rejection(message: dict[str, Any]) -> bool:
    details = message.get("details")
    if not isinstance(details, dict):
        return False
    expected_keys = {"protocol_version", "ok", "code"}
    diagnostic = details.get("diagnostic")
    if diagnostic is not None:
        expected_keys.add("diagnostic")
    code = details.get("code")
    if (
        set(details) != expected_keys
        or details.get("protocol_version") != 3
        or details.get("ok") is not False
        or not isinstance(code, str)
        or code not in _CORRECTABLE_REJECTION_CODES
        or not _REJECTION_CODE.fullmatch(code)
        or (diagnostic is not None and (not isinstance(diagnostic, str) or len(diagnostic) > 500))
    ):
        return False
    compact_diagnostic = "" if diagnostic is None else re.sub(r"\s+", " ", diagnostic).strip()
    compact = "" if diagnostic is None else f" diagnostic={compact_diagnostic}"
    content = message.get("content")
    return content == [{"type": "text", "text": f"SUBMISSION_REJECTED code={code}{compact}"}]


def audit_native_session(  # noqa: PLR0912,PLR0915
    execution_root: Path, attempt_id: str, session_path: Path
) -> dict[str, object]:
    """Audit one pinned Pi session while treating validated escrow as authority."""
    root = execution_root.resolve(strict=True)
    identity = _reauthenticate_execution(root)
    attempt, state = _load_native_state(root, attempt_id)
    result_path = attempt / "native-result.json"
    if not result_path.exists() or (attempt / "native-failure.json").exists():
        _fail("session audit requires one successful finalized escrow")
    binding = pilot_submit_v3.load_bindings(Path(str(state["binding"]))).records[0]
    result = _authenticated_result(result_path, binding)
    receipt = cast("dict[str, Any]", result["receipt"])
    packet = Path(str(state["packet"])).resolve(strict=True)
    raw = _read(session_path.resolve(strict=True), _MAX_STDIO_BYTES)
    if not raw or not raw.endswith(b"\n"):
        _fail("session JSONL framing is invalid")

    allowed_event_types = {
        "session",
        "model_change",
        "thinking_level_change",
        "session_info",
        "message",
    }
    allowed_tools = {"read", "grep", "find", "ls", "submit_blind_review"}
    source_tools = allowed_tools - {"submit_blind_review"}
    session_events = 0
    model_events = 0
    thinking_events = 0
    assistant_messages = 0
    calls: dict[str, str] = {}
    result_ids: set[str] = set()
    tool_errors = 0
    submit_errors = 0
    semantic_rejections = 0
    submit_successes = 0
    input_tokens = 0
    output_tokens = 0
    cache_read_tokens = 0
    cost_usd = 0.0
    terminal_success_seen = False
    identity_ready = False

    for line in raw.splitlines():
        if terminal_success_seen:
            _fail("successful submission was not the terminal session event")
        try:
            event = json.loads(
                line,
                object_pairs_hook=_unique,
                parse_constant=_constant,
            )
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise PilotTypedRunError("session JSONL contains invalid JSON") from exc
        if not isinstance(event, dict) or event.get("type") not in allowed_event_types:
            _fail("session event is invalid")
        event_type = event["type"]
        if event_type == "session":
            session_events += 1
            if event.get("cwd") != str(packet):
                _fail("session cwd does not match assigned packet")
        elif event_type == "model_change":
            model_events += 1
            expected = str(identity["model"])
            expected_provider, _, expected_model = expected.partition("/")
            if event.get("provider") != expected_provider or event.get("modelId") != expected_model:
                _fail("session model does not match execution")
        elif event_type == "thinking_level_change":
            thinking_events += 1
            if event.get("thinkingLevel") != identity["thinking"]:
                _fail("session thinking does not match execution")
        identity_ready = model_events == 1 and thinking_events == 1
        if event_type != "message":
            continue

        message = event.get("message")
        if not isinstance(message, dict):
            _fail("session message is invalid")
        role = message.get("role")
        if role == "assistant":
            if not identity_ready:
                _fail("assistant activity preceded model/thinking binding")
            assistant_messages += 1
            content = message.get("content")
            usage = message.get("usage")
            if not isinstance(content, list) or not isinstance(usage, dict):
                _fail("session assistant message is invalid")
            for part in content:
                if not isinstance(part, dict):
                    _fail("session assistant content is invalid")
                kind = part.get("type")
                if kind == "thinking":
                    continue
                if kind == "text":
                    if str(part.get("text", "")).strip():
                        _fail("session assistant emitted forbidden prose")
                    continue
                if kind != "toolCall":
                    _fail("session assistant content type is invalid")
                call_id, name, arguments = part.get("id"), part.get("name"), part.get("arguments")
                if (
                    not isinstance(call_id, str)
                    or not call_id
                    or call_id in calls
                    or name not in allowed_tools
                    or not isinstance(arguments, dict)
                ):
                    _fail("session tool call is invalid")
                calls[call_id] = cast("str", name)
                if name in source_tools:
                    _session_tool_path(packet, arguments.get("path", "."))
            input_tokens += _session_integer(usage.get("input"), "input")
            output_tokens += _session_integer(usage.get("output"), "output")
            cache_read_tokens += _session_integer(usage.get("cacheRead"), "cacheRead")
            cost = usage.get("cost")
            if not isinstance(cost, dict):
                _fail("session usage cost is invalid")
            cost_usd += _session_cost(cost.get("total"))
        elif role == "toolResult":
            call_id = message.get("toolCallId")
            name = message.get("toolName")
            if (
                not isinstance(call_id, str)
                or call_id not in calls
                or call_id in result_ids
                or name != calls[call_id]
                or not isinstance(message.get("isError"), bool)
            ):
                _fail("session tool result is invalid")
            result_ids.add(call_id)
            if message["isError"]:
                tool_errors += 1
                if name == "submit_blind_review":
                    submit_errors += 1
                    _fail("submission transport, security, or protocol tool error is terminal")
            elif name == "submit_blind_review":
                details = message.get("details")
                if isinstance(details, dict) and details == receipt:
                    submit_successes += 1
                    terminal_success_seen = True
                elif _session_submission_rejection(message):
                    semantic_rejections += 1
                else:
                    _fail("submission result is neither rejection nor authenticated escrow")
        elif role not in {"user", "system"}:
            _fail("session message role is invalid")

    if session_events != 1 or model_events != 1 or thinking_events != 1:
        _fail("session identity event cardinality is invalid")
    if not assistant_messages or len(calls) > 203 or set(calls) != result_ids:
        _fail("session tool/result cardinality is invalid")
    submit_calls = sum(name == "submit_blind_review" for name in calls.values())
    if (
        not 1 <= submit_calls <= 3
        or submit_successes != 1
        or semantic_rejections != submit_calls - 1
        or submit_errors != 0
        or not terminal_success_seen
    ):
        _fail("session submission result is invalid")
    return {
        "schema_version": 1,
        "attempt_id": attempt_id,
        "repository": state["repository"],
        "pr": state["pr"],
        "lane": state["lane"],
        "session_sha256": _sha(raw),
        "assistant_messages": assistant_messages,
        "tool_calls": len(calls),
        "source_tool_calls": len(calls) - submit_calls,
        "submit_calls": submit_calls,
        "correction_submissions": submit_calls - 1,
        "tool_errors": tool_errors,
        "submit_errors": submit_errors,
        "semantic_rejections": semantic_rejections,
        "parent_success_compatible": True,
        "eventual_escrow_accepted": True,
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cache_read_tokens": cache_read_tokens,
            "cost_usd_observed": cost_usd,
            "cost_micro_usd": round(cost_usd * 1_000_000),
        },
    }


def audit_native_sessions(
    execution_root: Path, pairs: Sequence[tuple[str, Path]]
) -> dict[str, object]:
    if not pairs or len(pairs) > 6 or len({attempt for attempt, _ in pairs}) != len(pairs):
        _fail("session audit pair list is invalid")
    rows = [
        audit_native_session(execution_root, attempt, session)
        for attempt, session in sorted(pairs, key=lambda item: item[0])
    ]
    usage_rows = [cast("dict[str, Any]", row["usage"]) for row in rows]
    return {
        "schema_version": 1,
        "protocol": "blind-review-native-session-audit-v3",
        "results": rows,
        "totals": {
            "sessions": len(rows),
            "submit_calls": sum(cast("int", row["submit_calls"]) for row in rows),
            "correction_submissions": sum(
                cast("int", row["correction_submissions"]) for row in rows
            ),
            "tool_errors": sum(cast("int", row["tool_errors"]) for row in rows),
            "input_tokens": sum(row["input_tokens"] for row in usage_rows),
            "output_tokens": sum(row["output_tokens"] for row in usage_rows),
            "cache_read_tokens": sum(row["cache_read_tokens"] for row in usage_rows),
            "cost_usd_observed": sum(float(row["cost_usd_observed"]) for row in usage_rows),
            "cost_micro_usd": sum(int(row["cost_micro_usd"]) for row in usage_rows),
        },
    }


def _audit_pair(value: str) -> tuple[str, Path]:
    attempt, separator, path = value.partition("=")
    if not separator or not _ATTEMPT.fullmatch(attempt) or not path:
        raise argparse.ArgumentTypeError("session pair must be ATTEMPT_ID=/absolute/session.jsonl")
    session = Path(path)
    if not session.is_absolute():
        raise argparse.ArgumentTypeError("session path must be absolute")
    return attempt, session


def summarize(execution_root: Path) -> dict[str, object]:
    results: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for attempt in sorted(
        (execution_root.resolve(strict=True) / "attempts").iterdir(), key=lambda item: item.name
    ):
        if (attempt / "native-result.json").exists():
            results.append(_json(attempt / "native-result.json", _MAX_RESULT_BYTES, modes={0o400}))
        elif (attempt / "native-failure.json").exists():
            failures.append(
                _json(attempt / "native-failure.json", _MAX_RESULT_BYTES, modes={0o400})
            )
    return {
        "schema_version": 1,
        "protocol": "blind-review-native-subagent-v3",
        "results": results,
        "failures": failures,
        "totals": {"successful": len(results), "failed": len(failures)},
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    sub = parser.add_subparsers(dest="command", required=True)
    packets = sub.add_parser("prepare-packets")
    packets.add_argument("--cache-root", required=True, type=Path)
    packets.add_argument("--v2-packet-root", required=True, type=Path)
    packets.add_argument("--v3-packet-root", required=True, type=Path)
    prepare = sub.add_parser("prepare-native-attempt")
    prepare.add_argument("--cache-root", required=True, type=Path)
    prepare.add_argument("--packet-root", required=True, type=Path)
    prepare.add_argument("--execution-root", required=True, type=Path)
    prepare.add_argument("--repository", required=True)
    prepare.add_argument("--pr", required=True, type=int)
    prepare.add_argument("--lane", required=True, choices=("A", "B"))
    prepare.add_argument("--attempt-id", required=True)
    prepare.add_argument("--timeout-seconds", type=int, default=_MAX_WALL_SECONDS)
    finalize = sub.add_parser("finalize-native-attempt")
    finalize.add_argument("--execution-root", required=True, type=Path)
    finalize.add_argument("--attempt-id", required=True)
    plan = sub.add_parser("native-launch-plan")
    plan.add_argument("--execution-root", required=True, type=Path)
    plan.add_argument("--attempt-id", action="append", required=True)
    plan.add_argument("--user-agent-root", type=Path)
    plan.add_argument("--builtin-agent-root", type=Path)
    agent = sub.add_parser("create-native-agent")
    agent.add_argument("--execution-root", required=True, type=Path)
    agent.add_argument("--output", required=True, type=Path)
    agent.add_argument("--user-agent-root", type=Path)
    agent.add_argument("--builtin-agent-root", type=Path)
    audit = sub.add_parser("audit-native-sessions")
    audit.add_argument("--execution-root", required=True, type=Path)
    audit.add_argument("--session", action="append", required=True, type=_audit_pair)
    audit.add_argument("--output", type=Path)
    summary = sub.add_parser("summarize")
    summary.add_argument("--execution-root", required=True, type=Path)
    summary.add_argument("--output", type=Path)
    serve_parser = sub.add_parser("serve-native-broker", help=argparse.SUPPRESS)
    serve_parser.add_argument("--socket", required=True, type=Path)
    serve_parser.add_argument("--binding", required=True, type=Path)
    serve_parser.add_argument("--status", required=True, type=Path)
    serve_parser.add_argument("--deadline-unix-ms", required=True, type=int)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = args.root.resolve(strict=True)
    if args.command == "prepare-packets":
        result: object = {
            "packets": [
                str(path)
                for path in prepare_packets(
                    root, args.cache_root, args.v2_packet_root, args.v3_packet_root
                )
            ]
        }
    elif args.command == "prepare-native-attempt":
        result = prepare_native_attempt(
            source_root=root,
            cache_root=args.cache_root,
            packet_root=args.packet_root,
            execution_root=args.execution_root,
            repository=args.repository,
            pr=args.pr,
            lane=cast("Literal['A', 'B']", args.lane),
            attempt_id=args.attempt_id,
            timeout_seconds=args.timeout_seconds,
        )
    elif args.command == "finalize-native-attempt":
        result = finalize_native_attempt(
            execution_root=args.execution_root, attempt_id=args.attempt_id
        )
    elif args.command == "native-launch-plan":
        result = native_launch_plan(
            args.execution_root,
            args.attempt_id,
            user_agent_root=args.user_agent_root,
            builtin_agent_root=args.builtin_agent_root,
        )
    elif args.command == "create-native-agent":
        result = create_native_agent(
            args.execution_root,
            args.output,
            user_agent_root=args.user_agent_root,
            builtin_agent_root=args.builtin_agent_root,
        )
    elif args.command == "serve-native-broker":
        return _serve_native_broker(args.socket, args.binding, args.status, args.deadline_unix_ms)
    elif args.command == "audit-native-sessions":
        result = audit_native_sessions(args.execution_root, args.session)
        raw = canonical_json(result)
        if args.output:
            _atomic(args.output, raw, mode=0o400)
        print(raw.decode(), end="")
        return 0
    else:
        result = summarize(args.execution_root)
        raw = canonical_json(result)
        if args.output:
            _atomic(args.output, raw, mode=0o400)
        print(raw.decode(), end="")
        return 0
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
