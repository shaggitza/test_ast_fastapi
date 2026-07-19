#!/usr/bin/env python3
"""Custody and native launch plans for production-v1 blind reviews.

This module may start only the deterministic local submission broker. It never
starts Pi, a model, or a provider process. Native model launches are emitted as
data for the supervisor-owned native subagent tool.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import math
import os
import re
import resource
import shutil
import signal
import stat
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Literal, NoReturn, cast

from benchmarks.real_world import ground_truth_campaign_v1 as campaign_v1
from benchmarks.real_world import ground_truth_packet_v1 as packet_v1
from benchmarks.real_world import ground_truth_source_v1 as source_v1
from benchmarks.real_world import ground_truth_submit_v1 as submit_v1
from benchmarks.real_world.ground_truth_v2.schema import artifact_sha256, canonical_json

if TYPE_CHECKING:
    from collections.abc import Sequence

_PROFILE: Final = "benchmarks/real_world/production_v1"
_RUNTIME_POLICY: Final = f"{_PROFILE}/runtime-policy-v1.json"
_RUNTIME_SCHEMA: Final = f"{_PROFILE}/runtime-attestation-schema-v1.json"
_AUTH_SCHEMA: Final = f"{_PROFILE}/review-canary-authorization-schema-v1.json"
_EVENT_SCHEMA: Final = f"{_PROFILE}/lane-event-schema-v1.json"
_AUDIT_SCHEMA: Final = f"{_PROFILE}/session-audit-schema-v1.json"
_MODULE: Final = "benchmarks/real_world/ground_truth_run_v1.py"
_EXTENSION: Final = f"{_PROFILE}/extensions/ground-truth-review-submit/index.ts"
_EXTENSION_SCHEMA: Final = f"{_PROFILE}/extensions/ground-truth-review-submit/review-schema.ts"
_AGENT_NAME: Final = "ground-truth-production-reviewer-v1"
_MODEL: Final = "openai-codex/gpt-5.6-luna"
_THINKING: Final = "medium"
_TOOLS: Final = ("read", "grep", "find", "ls", "submit_blind_review")
_MAX_ACTIVE: Final = 3
_MAX_WALL: Final = 1800
_MAX_FILE: Final = 64 * 1024 * 1024
_MAX_SESSION: Final = 64 * 1024 * 1024
_MAX_RSS: Final = 4 * 1024 * 1024 * 1024
_MAX_OUTPUT: Final = 2 * 1024 * 1024
_RUNTIME_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_ATTEMPT = re.compile(r"^prod-v1-i[0-9]{3}-rank[0-9]{3}-pr[0-9]+-[AB]$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVENT_FILE = re.compile(
    r"^([0-9]{6})-(prepared|launch_claimed|native_result|pending|completed|operational_failed)-([A-Za-z0-9_-]+)\.json$"
)
_NATIVE_RUN = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$|^[0-9a-f]{8,64}$")
_SESSION_ID = re.compile(r"^[0-9A-Za-z_-]{8,128}$")
_EVENT_ID = re.compile(r"^[0-9A-Za-z_-]{1,128}$")
_TASK_TEXT: Final = (
    "Perform the assigned blind review. Follow the exact packet policy, submit through "
    "submit_blind_review, then emit only SUBMISSION_COMPLETE."
)
_CORRECTABLE = {"DRAFT_INVALID", "EVIDENCE_INVALID"}
_ZERO = "sha256:" + "0" * 64
_RUNTIME_FILE: Final = "runtime-attestation.json"
_RUNTIME_SUPERSESSION_FILE: Final = "runtime-attestation-supersession-001.json"
_RUNTIME_PROTOCOL: Final = "ground-truth-runtime-attestation-v1"
_RUNTIME_SUPERSESSION_PROTOCOL: Final = "ground-truth-runtime-attestation-supersession-v1"
_RUNTIME_DOMAIN: Final = b"ground-truth-runtime-attestation-v1\0"
_RUNTIME_SUPERSESSION_DOMAIN: Final = b"ground-truth-runtime-attestation-supersession-v1\0"


class GroundTruthRunError(RuntimeError):
    """Fail-closed native runtime error."""


def _fail(message: str) -> NoReturn:
    raise GroundTruthRunError(message)


def _sha(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _strict_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        _fail(f"{label} keys are invalid")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> str:
    normalized = value.astimezone(timezone.utc).replace(microsecond=0)
    return normalized.isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail("timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise GroundTruthRunError("timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.microsecond:
        _fail("timestamp is invalid")
    return parsed.astimezone(timezone.utc)


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            _fail("duplicate JSON key")
        value[key] = item
    return value


def _constant(value: str) -> NoReturn:
    _fail(f"non-finite JSON value: {value}")


def _json_raw(
    path: Path, *, modes: set[int] | None = None, limit: int = _MAX_FILE
) -> tuple[dict[str, Any], bytes]:
    raw = submit_v1._owned_file(
        path,
        max_bytes=limit,
        allowed_modes=modes or {0o400, 0o600, 0o644},
    )
    try:
        value = json.loads(raw, object_pairs_hook=_unique, parse_constant=_constant)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise GroundTruthRunError(f"invalid JSON: {path.name}") from exc
    if not isinstance(value, dict):
        _fail("JSON root is invalid")
    canonical_json(value)
    return cast("dict[str, Any]", value), raw


def _atomic(path: Path, value: dict[str, Any], *, mode: int = 0o400) -> None:
    submit_v1._atomic_no_clobber(path, canonical_json(value), mode=mode)


def _private_directory(path: Path, *, create: bool = False) -> os.stat_result:
    if not path.is_absolute():
        _fail("private path must be absolute")
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        status = current.lstat()
        if stat.S_ISLNK(status.st_mode):
            _fail("private path has a symlink ancestor")
    status = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(status.st_mode)
        or status.st_uid != os.getuid()
        or stat.S_IMODE(status.st_mode) != 0o700
    ):
        _fail("private directory owner or mode is invalid")
    return status


def _profile(root: Path) -> submit_v1.ProfileSnapshot:
    try:
        return submit_v1._profile_snapshot(root)
    except submit_v1.GroundTruthSubmitError as exc:
        raise GroundTruthRunError("production profile authentication failed") from exc


def _campaign(root: Path, path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        value, raw = campaign_v1._json(path, modes={0o400})
        campaign_v1.validate_manifest(root, value)
    except campaign_v1.CampaignV1Error as exc:
        raise GroundTruthRunError("campaign authentication failed") from exc
    return value, raw


def _custody(
    root: Path,
    campaign_path: Path,
    bindings: Path,
    cache: Path,
    ledger: Path,
    packets: Path,
) -> tuple[dict[str, Any], bytes, dict[str, Any], submit_v1.ProfileSnapshot]:
    campaign, campaign_raw = _campaign(root, campaign_path)
    try:
        packet = packet_v1.validate_packets(root, campaign_path, bindings, cache, ledger, packets)
        source = source_v1.validate_source_bindings(root, campaign_path, cache, bindings)
    except (packet_v1.PacketV1Error, source_v1.SourceV1Error) as exc:
        raise GroundTruthRunError("production packet or source custody failed") from exc
    if (
        packet.get("live_launch_authorized") is not False
        or packet.get("canonical_import_authorized") is not False
    ):
        _fail("base packet gates are not false")
    profile = _profile(root)
    return campaign, campaign_raw, {"packet": packet, "source": source}, profile


def _package_paths() -> tuple[Path, Path, Path, Path]:
    agent_dir = Path(os.environ.get("PI_CODING_AGENT_DIR", str(Path.home() / ".pi/agent")))
    subagents = agent_dir / "npm/node_modules/pi-subagents"
    resolver = subagents / "src/agents/agents.ts"
    pi_package = (
        Path.home() / ".local/lib/node_modules/@earendil-works/pi-coding-agent/package.json"
    )
    config = agent_dir / "extensions/subagent/config.json"
    return subagents, resolver, pi_package, config


def _read_immutable_system_file(path: Path, *, max_bytes: int) -> bytes:
    status = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_uid not in {0, os.getuid()}
        or stat.S_IMODE(status.st_mode) & 0o022
        or status.st_size <= 0
        or status.st_size > max_bytes
    ):
        _fail("system runtime file identity is invalid")
    raw = path.read_bytes()
    after = path.stat(follow_symlinks=False)
    if len(raw) != status.st_size or (
        status.st_dev,
        status.st_ino,
        status.st_ctime_ns,
        status.st_size,
    ) != (after.st_dev, after.st_ino, after.st_ctime_ns, after.st_size):
        _fail("system runtime file drifted while reading")
    return raw


def _read_package(
    path: Path, expected_name: str, expected_version: str
) -> tuple[dict[str, Any], bytes]:
    value, raw = _json_raw(path, modes={0o644})
    if value.get("name") != expected_name or value.get("version") != expected_version:
        _fail(f"pinned {expected_name} {expected_version} is unavailable")
    return value, raw


def _bounded_node_attestation(
    argv: list[str], root: Path, env: dict[str, str], *, timeout: int = 30
) -> subprocess.CompletedProcess[bytes]:
    """Run only a checksum-bound local Node attestation script; no shell or network."""
    try:
        return subprocess.run(
            argv,
            cwd=root,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=timeout,
            env=env,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise GroundTruthRunError("pinned Node attestation failed") from exc


def _resolver_census(root: Path, resolver: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    if os.environ.get("PI_SUBAGENT_EXTRA_AGENT_DIRS", "").strip():
        _fail("extra agent roots are forbidden")
    jiti = resolver.parents[3] / "jiti/lib/jiti.mjs"
    submit_v1._owned_file(jiti, max_bytes=8 * 1024 * 1024, allowed_modes={0o644})
    script = """
import { pathToFileURL } from 'node:url';
const { createJiti } = await import(pathToFileURL(process.argv[1]).href);
const api = await createJiti(import.meta.url).import(process.argv[2]);
const cwd = process.argv[3];
const found = api.discoverAgentsAll(cwd);
const effective = api.discoverAgents(cwd, 'both').agents;
const row = (a, source) => ({
  name:a.name, filePath:a.filePath ?? null, source:a.source ?? source,
  model:a.model ?? null, thinking:a.thinking ?? null,
  tools:a.tools ?? null, extensions:a.extensions ?? null,
  subagentOnlyExtensions:a.subagentOnlyExtensions ?? null,
  disabled:a.disabled === true
});
const clean = {
  roots: {userDir:found.userDir, projectDir:found.projectDir,
          userSettingsPath:found.userSettingsPath, projectSettingsPath:found.projectSettingsPath},
  effective: effective.map((a) => row(a,a.source)).sort((a,b) =>
    `${a.name}:${a.filePath}`.localeCompare(`${b.name}:${b.filePath}`))
};
for (const key of ['builtin','package','user','project']) {
  clean[key] = (found[key] ?? []).map((a) => row(a,key)).sort((a,b) =>
    `${a.name}:${a.filePath}`.localeCompare(`${b.name}:${b.filePath}`));
}
process.stdout.write(JSON.stringify(clean));
"""
    node = shutil.which("node")
    if node is None:
        _fail("Node is unavailable")
    node_path = Path(node).resolve(strict=True)
    node_raw = _read_immutable_system_file(node_path, max_bytes=128 * 1024 * 1024)
    argv = [
        str(node_path),
        "--input-type=module",
        "-e",
        script,
        str(jiti),
        str(resolver),
        str(root),
    ]
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(Path.home()),
        "LANG": "C",
        "LC_ALL": "C",
        "PI_CODING_AGENT_DIR": os.environ.get(
            "PI_CODING_AGENT_DIR", str(Path.home() / ".pi/agent")
        ),
    }
    result = _bounded_node_attestation(argv, root, env)
    if result.returncode or result.stderr or len(result.stdout) > 8 * 1024 * 1024:
        _fail("pinned resolver execution failed")
    try:
        value = json.loads(result.stdout, object_pairs_hook=_unique, parse_constant=_constant)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise GroundTruthRunError("resolver output is invalid") from exc
    expected = {"builtin", "package", "user", "project", "effective", "roots"}
    if not isinstance(value, dict) or set(value) != expected:
        _fail("resolver output is invalid")
    execution = {
        "node_path": str(node_path),
        "node_sha256": _sha(node_raw),
        "script_sha256": _sha(script.encode()),
        "argv_sha256": _sha(canonical_json(argv)),
        "timeout_seconds": 30,
        "network_authorized": False,
        "shell": False,
    }
    return cast("dict[str, Any]", value), execution


def _manual_roots(root: Path, subagents: Path) -> list[dict[str, Any]]:
    agent_dir = Path(os.environ.get("PI_CODING_AGENT_DIR", str(Path.home() / ".pi/agent")))
    roots = [
        ("project-old", root / ".pi/agents"),
        ("project-new", root / ".agents"),
        ("user-old", agent_dir / "agents"),
        ("user-new", Path.home() / ".agents"),
        ("builtin", subagents / "agents"),
    ]
    rows: list[dict[str, Any]] = []
    for kind, path in roots:
        absolute = path.absolute()
        exists = absolute.exists()
        if exists and (absolute.is_symlink() or not absolute.is_dir()):
            _fail("agent discovery root is unsafe")
        rows.append({"kind": kind, "path": str(absolute), "exists": exists})
    if len({row["path"] for row in rows}) != len(rows):
        _fail("agent discovery roots overlap")
    return rows


def _config(config_path: Path) -> tuple[dict[str, Any], bytes]:
    value, raw = _json_raw(config_path, modes={0o644})
    _strict_keys(value, {"maxSubagentSpawnsPerSession", "intercomBridge"}, "runtime config")
    bridge = value.get("intercomBridge")
    if (
        not isinstance(bridge, dict)
        or set(bridge) != {"mode", "instructionFile"}
        or bridge.get("mode") not in {"fork-only", "off"}
        or bridge.get("instructionFile") != ""
    ):
        _fail("intercom bridge must be exact fork-only/off with no instruction file")
    if value.get("maxSubagentSpawnsPerSession") != 500:
        _fail("subagent spawn bound is not pinned")
    return value, raw


def _runtime_identity(root: Path) -> dict[str, Any]:
    subagents, resolver, pi_package, config_path = _package_paths()
    package_path = subagents / "package.json"
    _read_package(package_path, "pi-subagents", "0.35.1")
    _, pi_raw = _read_package(pi_package, "@earendil-works/pi-coding-agent", "0.80.10")
    required = {
        "package": package_path,
        "agents": subagents / "src/agents/agents.ts",
        "schemas": subagents / "src/extension/schemas.ts",
        "pi_args": subagents / "src/runs/shared/pi-args.ts",
        "foreground_execution": subagents / "src/runs/foreground/execution.ts",
        "foreground_executor": subagents / "src/runs/foreground/subagent-executor.ts",
    }
    files: dict[str, dict[str, object]] = {}
    for name, path in required.items():
        raw = submit_v1._owned_file(path, max_bytes=8 * 1024 * 1024, allowed_modes={0o644})
        files[name] = {"path": str(path), "sha256": _sha(raw), "bytes": len(raw)}
    config, config_raw = _config(config_path)
    census, resolver_execution = _resolver_census(root, resolver)
    roots = _manual_roots(root, subagents)
    return {
        "schema_version": 1,
        "pi_subagents_version": "0.35.1",
        "pi_version": "0.80.10",
        "pi_package": {"path": str(pi_package), "sha256": _sha(pi_raw), "bytes": len(pi_raw)},
        "runtime_files": files,
        "config": {
            "path": str(config_path),
            "sha256": _sha(config_raw),
            "bytes": len(config_raw),
            "intercom_mode": config["intercomBridge"]["mode"],
        },
        "roots": roots,
        "resolver_census": census,
        "resolver_census_sha256": _sha(canonical_json(census)),
        "resolver_execution": resolver_execution,
    }


def _immutable_runtime_identity(value: dict[str, Any]) -> dict[str, Any]:
    return {
        key: item
        for key, item in value.items()
        if key not in {"resolver_census", "resolver_census_sha256"}
    }


def _validate_file_identity(value: object, label: str) -> None:
    if not isinstance(value, dict):
        _fail(f"{label} identity is invalid")
    _strict_keys(value, {"path", "sha256", "bytes"}, label)
    if (
        not isinstance(value["path"], str)
        or not Path(value["path"]).is_absolute()
        or not isinstance(value["sha256"], str)
        or not _DIGEST.fullmatch(value["sha256"])
        or not isinstance(value["bytes"], int)
        or isinstance(value["bytes"], bool)
        or value["bytes"] <= 0
    ):
        _fail(f"{label} identity is invalid")


def _validate_agent_census_row(value: object) -> None:
    if not isinstance(value, dict):
        _fail("resolver census agent row is invalid")
    _strict_keys(
        value,
        {
            "name",
            "filePath",
            "source",
            "model",
            "thinking",
            "tools",
            "extensions",
            "subagentOnlyExtensions",
            "disabled",
        },
        "resolver census agent row",
    )
    nullable_strings = ("model", "thinking")
    nullable_lists = ("extensions", "subagentOnlyExtensions")
    if (
        not isinstance(value["name"], str)
        or not value["name"]
        or not isinstance(value["filePath"], str)
        or not Path(value["filePath"]).is_absolute()
        or value["source"] not in {"builtin", "package", "user", "project"}
        or any(
            value[key] is not None and not isinstance(value[key], str) for key in nullable_strings
        )
        or not isinstance(value["tools"], list)
        or any(not isinstance(item, str) or not item for item in value["tools"])
        or any(
            value[key] is not None
            and (
                not isinstance(value[key], list)
                or any(not isinstance(item, str) or not item for item in value[key])
            )
            for key in nullable_lists
        )
        or not isinstance(value["disabled"], bool)
    ):
        _fail("resolver census agent row is invalid")


def _validate_runtime_identity(value: object) -> dict[str, Any]:  # noqa: PLR0912
    if not isinstance(value, dict):
        _fail("runtime identity is invalid")
    _strict_keys(
        value,
        {
            "schema_version",
            "pi_subagents_version",
            "pi_version",
            "pi_package",
            "runtime_files",
            "config",
            "roots",
            "resolver_census",
            "resolver_census_sha256",
            "resolver_execution",
        },
        "runtime identity",
    )
    if (
        value["schema_version"] != 1
        or value["pi_subagents_version"] != "0.35.1"
        or value["pi_version"] != "0.80.10"
    ):
        _fail("runtime identity version is invalid")
    _validate_file_identity(value["pi_package"], "Pi package")
    files = value["runtime_files"]
    expected_files = {
        "package",
        "agents",
        "schemas",
        "pi_args",
        "foreground_execution",
        "foreground_executor",
    }
    if not isinstance(files, dict) or set(files) != expected_files:
        _fail("runtime file census is invalid")
    for name in sorted(expected_files):
        _validate_file_identity(files[name], f"runtime file {name}")
    config = value["config"]
    if not isinstance(config, dict):
        _fail("runtime config identity is invalid")
    _strict_keys(config, {"path", "sha256", "bytes", "intercom_mode"}, "runtime config identity")
    _validate_file_identity(
        {key: config[key] for key in ("path", "sha256", "bytes")}, "runtime config"
    )
    if config["intercom_mode"] not in {"fork-only", "off"}:
        _fail("runtime config intercom mode is invalid")
    roots = value["roots"]
    expected_root_kinds = ["project-old", "project-new", "user-old", "user-new", "builtin"]
    if not isinstance(roots, list) or len(roots) != len(expected_root_kinds):
        _fail("runtime discovery roots are invalid")
    for row, expected_kind in zip(roots, expected_root_kinds, strict=True):
        if not isinstance(row, dict):
            _fail("runtime discovery root is invalid")
        _strict_keys(row, {"kind", "path", "exists"}, "runtime discovery root")
        if (
            row["kind"] != expected_kind
            or not isinstance(row["path"], str)
            or not Path(row["path"]).is_absolute()
            or not isinstance(row["exists"], bool)
        ):
            _fail("runtime discovery root is invalid")
    census = value["resolver_census"]
    if not isinstance(census, dict):
        _fail("resolver census is invalid")
    _strict_keys(
        census,
        {"roots", "effective", "builtin", "package", "user", "project"},
        "resolver census",
    )
    census_roots = census["roots"]
    if not isinstance(census_roots, dict):
        _fail("resolver census roots are invalid")
    _strict_keys(
        census_roots,
        {"userDir", "projectDir", "userSettingsPath", "projectSettingsPath"},
        "resolver census roots",
    )
    if any(
        not isinstance(item, str) or not Path(item).is_absolute() for item in census_roots.values()
    ):
        _fail("resolver census roots are invalid")
    for source in ("effective", "builtin", "package", "user", "project"):
        rows = census[source]
        if not isinstance(rows, list):
            _fail("resolver census source is invalid")
        for row in rows:
            _validate_agent_census_row(row)
    if (
        not isinstance(value["resolver_census_sha256"], str)
        or not _DIGEST.fullmatch(value["resolver_census_sha256"])
        or value["resolver_census_sha256"] != _sha(canonical_json(census))
    ):
        _fail("resolver census digest is invalid")
    execution = value["resolver_execution"]
    if not isinstance(execution, dict):
        _fail("resolver execution identity is invalid")
    _strict_keys(
        execution,
        {
            "node_path",
            "node_sha256",
            "script_sha256",
            "argv_sha256",
            "timeout_seconds",
            "network_authorized",
            "shell",
        },
        "resolver execution identity",
    )
    if (
        not isinstance(execution["node_path"], str)
        or not Path(execution["node_path"]).is_absolute()
        or any(
            not isinstance(execution[key], str) or not _DIGEST.fullmatch(execution[key])
            for key in ("node_sha256", "script_sha256", "argv_sha256")
        )
        or execution["timeout_seconds"] != 30
        or execution["network_authorized"] is not False
        or execution["shell"] is not False
    ):
        _fail("resolver execution identity is invalid")
    return value


def _entry_hash(domain: bytes, value: dict[str, Any]) -> str:
    return _sha(domain + canonical_json(value))


def _authorized_attempts(authorization: dict[str, Any] | None) -> set[str]:
    if authorization is None:
        return set()
    lanes = authorization.get("lanes")
    if not isinstance(lanes, list):
        _fail("authorization lanes are invalid")
    attempts: set[str] = set()
    seen_lanes: set[str] = set()
    for row in lanes:
        if not isinstance(row, dict):
            _fail("authorization lane is invalid")
        _strict_keys(row, {"lane_key", "attempt_id", "reviewer"}, "authorization lane")
        attempt = row.get("attempt_id")
        reviewer = row.get("reviewer")
        if (
            not isinstance(attempt, str)
            or not _ATTEMPT.fullmatch(attempt)
            or "-rank001-" not in attempt
            or not isinstance(reviewer, dict)
            or set(reviewer) != {"name", "version"}
            or reviewer.get("name")
            != f"production-blind-reviewer-{attempt.removeprefix('prod-v1-')}"
            or reviewer.get("version")
            != f"ground-truth-production-v1-{attempt.removeprefix('prod-v1-')}"
            or not isinstance(row.get("lane_key"), str)
            or attempt in attempts
        ):
            _fail("authorization lane identity is invalid")
        attempts.add(attempt)
        seen_lanes.add(attempt[-1])
    if len(attempts) != 2 or seen_lanes != {"A", "B"}:
        _fail("authorization must contain exact rank-1 A/B lanes")
    return attempts


def _event_expected_keys(kind: str) -> set[str]:
    common = {"schema_version", "protocol", "sequence", "kind", "previous_hash", "entry_hash"}
    specific = {
        "prepared": {
            "attempt_id",
            "rank",
            "lane",
            "lane_key",
            "binding_sha256",
            "runtime_attestation_entry_hash",
            "packet_root_sha256",
            "broker_pid",
            "broker_start_identity",
            "prepared_at",
        },
        "launch_claimed": {
            "batch_id",
            "attempt_ids",
            "task_indices",
            "runtime_attestation_entry_hash",
            "plan_sha256",
            "claimed_at",
        },
        "native_result": {
            "attempt_id",
            "batch_id",
            "native_run_id",
            "task_index",
            "runtime_attestation_entry_hash",
            "session_path",
            "session_device",
            "session_inode",
            "session_uid",
            "session_mode",
            "session_sha256",
            "parent_status",
            "bound_at",
        },
        "pending": {
            "attempt_id",
            "review_sha256",
            "escrow_sha256",
            "receipt_sha256",
            "binding_sha256",
            "pending_at",
        },
        "completed": {
            "attempt_id",
            "review_sha256",
            "receipt_sha256",
            "session_sha256",
            "audit_sha256",
            "runtime_attestation_entry_hash",
            "packet_root_sha256",
            "binding_sha256",
            "completed_at",
            "eligible",
        },
        "operational_failed": {"attempt_id", "reason", "failed_at", "relaunch_authorized"},
    }
    try:
        return common | specific[kind]
    except KeyError as exc:
        raise GroundTruthRunError("lane event kind is invalid") from exc


def _validate_runtime_ledger_entry(
    value: dict[str, Any],
    raw: bytes,
    base: dict[str, Any],
    previous_hash: str,
    *,
    supersedes_entry_hash: str | None,
) -> None:
    expected_keys = {
        "schema_version",
        "protocol",
        "campaign_id",
        "campaign_manifest_sha256",
        "campaign_lanes_sha256",
        "source_bindings_sha256",
        "packet_publication_entry_hash",
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
    protocol = _RUNTIME_PROTOCOL
    domain = _RUNTIME_DOMAIN
    if supersedes_entry_hash is not None:
        expected_keys.add("supersedes_entry_hash")
        protocol = _RUNTIME_SUPERSESSION_PROTOCOL
        domain = _RUNTIME_SUPERSESSION_DOMAIN
    _strict_keys(value, expected_keys, "runtime attestation")
    body = {key: item for key, item in value.items() if key != "entry_hash"}
    if (
        canonical_json(value) != raw
        or value["schema_version"] != 1
        or value["protocol"] != protocol
        or value["campaign_id"] != base["campaign_id"]
        or value["campaign_manifest_sha256"] != base["campaign_manifest_sha256"]
        or value["campaign_lanes_sha256"] != base["campaign_canary_lanes_sha256"]
        or value["packet_publication_entry_hash"] != base["packet_publication_entry_hash"]
        or value["authorizations"]
        != {"review_launch": False, "adjudication": False, "canonical_import": False}
        or value["previous_hash"] != previous_hash
        or (
            supersedes_entry_hash is not None
            and value["supersedes_entry_hash"] != supersedes_entry_hash
        )
        or value["entry_hash"] != _entry_hash(domain, body)
    ):
        _fail("runtime attestation ledger entry is invalid")
    _parse_timestamp(value["attested_at"])
    for key in (
        "source_bindings_sha256",
        "production_profile_sha256",
        "production_files_sha256",
        "extension_sha256",
        "extension_schema_sha256",
        "agent_source_sha256",
    ):
        if not isinstance(value[key], str) or not _DIGEST.fullmatch(value[key]):
            _fail("runtime attestation digest is invalid")
    _validate_runtime_identity(value["runtime_identity"])


def _extended_ledger(root: Path, repository_root: Path) -> dict[str, Any]:  # noqa: PLR0912,PLR0915
    base = campaign_v1._validate_ledger_unlocked(root, repository_root)
    if not base.get("packet_publication_present"):
        _fail("runtime requires packet publication")
    head = cast("str", base["entry_hash"])
    runtime_path = root / _RUNTIME_FILE
    runtime: dict[str, Any] | None = None
    first_runtime: dict[str, Any] | None = None
    if runtime_path.exists() or runtime_path.is_symlink():
        first_runtime, raw = _json_raw(runtime_path, modes={0o400})
        _validate_runtime_ledger_entry(
            first_runtime,
            raw,
            base,
            head,
            supersedes_entry_hash=None,
        )
        runtime = first_runtime
        head = cast("str", runtime["entry_hash"])
    supersession_path = root / _RUNTIME_SUPERSESSION_FILE
    supersession_files = sorted(root.glob("runtime-attestation-supersession-*.json"))
    if [path.name for path in supersession_files] not in ([], [_RUNTIME_SUPERSESSION_FILE]):
        _fail("runtime attestation supersession cardinality is invalid")
    runtime_superseded = False
    if supersession_path.exists() or supersession_path.is_symlink():
        if first_runtime is None:
            _fail("runtime supersession exists without an initial attestation")
        supersession, raw = _json_raw(supersession_path, modes={0o400})
        _validate_runtime_ledger_entry(
            supersession,
            raw,
            base,
            head,
            supersedes_entry_hash=cast("str", first_runtime["entry_hash"]),
        )
        runtime = supersession
        head = cast("str", runtime["entry_hash"])
        runtime_superseded = True
    auth_path = root / "review-canary-authorization.json"
    authorization: dict[str, Any] | None = None
    if auth_path.exists() or auth_path.is_symlink():
        if runtime is None:
            _fail("canary authorization exists without runtime attestation")
        authorization, raw = _json_raw(auth_path, modes={0o400})
        _strict_keys(
            authorization,
            {
                "schema_version",
                "protocol",
                "campaign_id",
                "campaign_manifest_sha256",
                "runtime_attestation_entry_hash",
                "agent_installation_sha256",
                "production_profile_sha256",
                "lanes",
                "limits",
                "issued_at",
                "expires_at",
                "authorizations",
                "previous_hash",
                "entry_hash",
            },
            "canary authorization",
        )
        body = {key: value for key, value in authorization.items() if key != "entry_hash"}
        issued = _parse_timestamp(authorization["issued_at"])
        expires = _parse_timestamp(authorization["expires_at"])
        if (
            canonical_json(authorization) != raw
            or authorization["schema_version"] != 1
            or authorization["protocol"] != "ground-truth-review-canary-authorization-v1"
            or authorization["campaign_id"] != base["campaign_id"]
            or authorization["campaign_manifest_sha256"] != base["campaign_manifest_sha256"]
            or authorization["runtime_attestation_entry_hash"] != runtime["entry_hash"]
            or authorization["production_profile_sha256"] != runtime["production_profile_sha256"]
            or not isinstance(authorization["agent_installation_sha256"], str)
            or not _DIGEST.fullmatch(authorization["agent_installation_sha256"])
            or authorization["limits"]
            != {"max_global_active": 3, "max_processes_per_lane": 1, "replacement_attempts": 0}
            or expires - issued != timedelta(hours=24)
            or authorization["authorizations"]
            != {"review_launch": True, "adjudication": False, "canonical_import": False}
            or authorization["previous_hash"] != head
            or authorization["entry_hash"]
            != _entry_hash(b"ground-truth-review-canary-authorization-v1\0", body)
        ):
            _fail("canary authorization ledger entry is invalid")
        _authorized_attempts(authorization)
        if (
            authorization["lanes"] != base["campaign_canary_lanes"]
            or _sha(canonical_json(authorization["lanes"])) != base["campaign_canary_lanes_sha256"]
            or runtime["campaign_lanes_sha256"] != base["campaign_canary_lanes_sha256"]
        ):
            _fail("authorization lanes differ from authenticated campaign lanes")
        head = cast("str", authorization["entry_hash"])
    authorized = _authorized_attempts(authorization)
    authorized_rows = {
        cast("str", row["attempt_id"]): row
        for row in (authorization or {}).get("lanes", [])
        if isinstance(row, dict)
    }
    runtime_entry_hash = runtime.get("entry_hash") if runtime is not None else None
    if authorized and (
        not isinstance(runtime_entry_hash, str) or not _DIGEST.fullmatch(runtime_entry_hash)
    ):
        _fail("authorized lanes lack an authenticated runtime head")
    events_dir = root / "lane-events"
    states: dict[str, str] = {}
    batches: dict[str, dict[str, int]] = {}
    batch_events: dict[str, dict[str, Any]] = {}
    batch_native_runs: dict[str, str] = {}
    prepared_events: dict[str, dict[str, Any]] = {}
    pending_events: dict[str, dict[str, Any]] = {}
    native_results: dict[str, dict[str, Any]] = {}
    events: list[dict[str, Any]] = []
    if events_dir.exists():
        _private_directory(events_dir)
        paths = sorted(events_dir.iterdir(), key=lambda item: item.name)
        for expected_sequence, path in enumerate(paths, 1):
            match = _EVENT_FILE.fullmatch(path.name)
            if match is None or int(match.group(1)) != expected_sequence:
                _fail("lane event sequence is invalid")
            event, raw = _json_raw(path, modes={0o400})
            kind = cast("str", event.get("kind"))
            _strict_keys(event, _event_expected_keys(kind), "lane event")
            body = {key: value for key, value in event.items() if key != "entry_hash"}
            identifier = match.group(3)
            if (
                canonical_json(event) != raw
                or event["schema_version"] != 1
                or event["protocol"] != "ground-truth-review-lane-event-v1"
                or event["sequence"] != expected_sequence
                or event["kind"] != match.group(2)
                or event["previous_hash"] != head
                or event["entry_hash"] != _entry_hash(b"ground-truth-review-lane-event-v1\0", body)
            ):
                _fail("lane event hash chain is invalid")
            if kind == "launch_claimed":
                batch = event["batch_id"]
                attempts = event["attempt_ids"]
                task_indices = event["task_indices"]
                if (
                    identifier != batch
                    or not isinstance(batch, str)
                    or not _RUNTIME_NAME.fullmatch(batch)
                    or not isinstance(attempts, list)
                    or not 1 <= len(attempts) <= _MAX_ACTIVE
                    or len(set(attempts)) != len(attempts)
                    or not isinstance(task_indices, list)
                    or task_indices != list(range(len(attempts)))
                    or any(
                        item not in authorized or states.get(item) != "prepared"
                        for item in attempts
                    )
                    or event["runtime_attestation_entry_hash"] != runtime_entry_hash
                    or not isinstance(event["plan_sha256"], str)
                    or not _DIGEST.fullmatch(event["plan_sha256"])
                ):
                    _fail("batch launch claim is invalid")
                _parse_timestamp(event["claimed_at"])
                batches[batch] = dict(zip(attempts, task_indices, strict=True))
                batch_events[batch] = event
                for attempt in attempts:
                    states[attempt] = "launch_claimed"
            else:
                attempt = event["attempt_id"]
                if identifier != attempt or attempt not in authorized:
                    _fail("lane event is outside exact authorization")
                previous = states.get(attempt)
                if kind == "prepared":
                    if (
                        previous is not None
                        or event["rank"] != 1
                        or event["lane"] != attempt[-1]
                        or event["lane_key"] != authorized_rows[attempt]["lane_key"]
                        or event["runtime_attestation_entry_hash"] != runtime_entry_hash
                        or not isinstance(event["broker_pid"], int)
                        or event["broker_pid"] <= 0
                        or not isinstance(event["broker_start_identity"], str)
                        or any(
                            not isinstance(event[key], str) or not _DIGEST.fullmatch(event[key])
                            for key in (
                                "binding_sha256",
                                "runtime_attestation_entry_hash",
                                "packet_root_sha256",
                            )
                        )
                    ):
                        _fail("prepared event transition is invalid")
                    _parse_timestamp(event["prepared_at"])
                    prepared_events[attempt] = event
                    states[attempt] = "prepared"
                elif kind == "native_result":
                    if (
                        previous != "launch_claimed"
                        or event["batch_id"] not in batches
                        or attempt not in batches[event["batch_id"]]
                        or event["task_index"] != batches[event["batch_id"]][attempt]
                        or event["runtime_attestation_entry_hash"] != runtime_entry_hash
                        or event["runtime_attestation_entry_hash"]
                        != prepared_events[attempt]["runtime_attestation_entry_hash"]
                        or not isinstance(event["native_run_id"], str)
                        or not _NATIVE_RUN.fullmatch(event["native_run_id"])
                        or not isinstance(event["session_path"], str)
                        or not Path(event["session_path"]).is_absolute()
                        or not isinstance(event["session_device"], int)
                        or not isinstance(event["session_inode"], int)
                        or event["session_uid"] != os.getuid()
                        or event["session_mode"] not in {0o600, 0o644}
                        or not isinstance(event["session_sha256"], str)
                        or not _DIGEST.fullmatch(event["session_sha256"])
                    ):
                        _fail("native result transition is invalid")
                    _validate_session_layout(
                        Path(event["session_path"]), event["native_run_id"], event["task_index"]
                    )
                    if event["parent_status"] not in {"success", "failure"}:
                        _fail("native parent status is invalid")
                    prior_run = batch_native_runs.get(event["batch_id"])
                    if prior_run is not None and prior_run != event["native_run_id"]:
                        _fail("native run id differs within claimed batch")
                    batch_native_runs[event["batch_id"]] = event["native_run_id"]
                    _parse_timestamp(event["bound_at"])
                    native_results[attempt] = event
                    states[attempt] = (
                        "native_bound"
                        if event["parent_status"] == "success"
                        else "operational_failed"
                    )
                elif kind == "pending":
                    if (
                        previous != "native_bound"
                        or event["binding_sha256"] != prepared_events[attempt]["binding_sha256"]
                        or any(
                            not isinstance(event[key], str) or not _DIGEST.fullmatch(event[key])
                            for key in (
                                "review_sha256",
                                "escrow_sha256",
                                "receipt_sha256",
                                "binding_sha256",
                            )
                        )
                    ):
                        _fail("pending event transition is invalid")
                    _parse_timestamp(event["pending_at"])
                    pending_events[attempt] = event
                    states[attempt] = "pending"
                elif kind == "completed":
                    if (
                        previous != "pending"
                        or event["eligible"] is not True
                        or event["runtime_attestation_entry_hash"] != runtime_entry_hash
                        or event["runtime_attestation_entry_hash"]
                        != prepared_events[attempt]["runtime_attestation_entry_hash"]
                        or event["packet_root_sha256"]
                        != prepared_events[attempt]["packet_root_sha256"]
                        or event["binding_sha256"] != prepared_events[attempt]["binding_sha256"]
                        or event["binding_sha256"] != pending_events[attempt]["binding_sha256"]
                        or event["review_sha256"] != pending_events[attempt]["review_sha256"]
                        or event["receipt_sha256"] != pending_events[attempt]["receipt_sha256"]
                        or event["session_sha256"] != native_results[attempt]["session_sha256"]
                        or any(
                            not isinstance(event[key], str) or not _DIGEST.fullmatch(event[key])
                            for key in (
                                "review_sha256",
                                "receipt_sha256",
                                "session_sha256",
                                "audit_sha256",
                                "runtime_attestation_entry_hash",
                                "packet_root_sha256",
                                "binding_sha256",
                            )
                        )
                    ):
                        _fail("completed event transition is invalid")
                    _parse_timestamp(event["completed_at"])
                    states[attempt] = "completed"
                elif kind == "operational_failed":
                    if (
                        previous
                        not in {None, "prepared", "launch_claimed", "native_bound", "pending"}
                        or event["relaunch_authorized"] is not False
                    ):
                        _fail("operational failure transition is invalid")
                    _parse_timestamp(event["failed_at"])
                    states[attempt] = "operational_failed"
            events.append(event)
            head = cast("str", event["entry_hash"])
    active = sum(
        state in {"prepared", "launch_claimed", "native_bound", "pending"}
        for state in states.values()
    )
    if active > _MAX_ACTIVE:
        _fail("global active lane bound exceeded")
    return {
        "base": base,
        "runtime": runtime,
        "first_runtime": first_runtime,
        "runtime_superseded": runtime_superseded,
        "authorization": authorization,
        "events": events,
        "states": states,
        "batches": batches,
        "batch_events": batch_events,
        "batch_native_runs": batch_native_runs,
        "native_results": native_results,
        "active": active,
        "head": head,
    }


def validate_runtime_ledger(ledger: Path, root: Path) -> dict[str, Any]:
    private = campaign_v1._private_root(ledger)
    with campaign_v1._ledger_lock(private):
        value = _extended_ledger(private, root)
    return {
        "entry_hash": value["head"],
        "runtime_attested": value["runtime"] is not None,
        "canary_authorized": value["authorization"] is not None,
        "active": value["active"],
        "states": value["states"],
    }


def _runtime_attestation_publication(
    current: dict[str, Any],
) -> tuple[str, str, bytes, dict[str, str]]:
    if current["runtime"] is None:
        return _RUNTIME_FILE, _RUNTIME_PROTOCOL, _RUNTIME_DOMAIN, {}
    if (
        current["authorization"] is None
        and not current["events"]
        and not current["runtime_superseded"]
    ):
        return (
            _RUNTIME_SUPERSESSION_FILE,
            _RUNTIME_SUPERSESSION_PROTOCOL,
            _RUNTIME_SUPERSESSION_DOMAIN,
            {"supersedes_entry_hash": cast("str", current["runtime"]["entry_hash"])},
        )
    _fail("runtime attestation cannot be superseded after authorization or lane activity")


def attest_runtime(
    root: Path,
    campaign_path: Path,
    bindings: Path,
    cache: Path,
    ledger: Path,
    packets: Path,
    execution_root: Path,
) -> dict[str, Any]:
    campaign, campaign_raw, custody, profile = _custody(
        root, campaign_path, bindings, cache, ledger, packets
    )
    status = _private_directory(execution_root, create=True)
    if any(execution_root.iterdir()):
        _fail("execution root must be empty before attestation")
    identity = _runtime_identity(root)
    runtime = execution_root / "runtime"
    runtime.mkdir(mode=0o700)
    extension_dir = runtime / "extension"
    extension_dir.mkdir(mode=0o700)
    source_extension = profile.files[_EXTENSION]
    source_schema = profile.files[_EXTENSION_SCHEMA]
    (extension_dir / "index.ts").write_bytes(source_extension)
    (extension_dir / "review-schema.ts").write_bytes(source_schema)
    (extension_dir / "index.ts").chmod(0o400)
    (extension_dir / "review-schema.ts").chmod(0o400)
    agent_source = runtime / "agent-source.md"
    prompt = profile.files[f"{_PROFILE}/review-prompt-v1.md"].decode("utf-8")
    body = _agent_body(extension_dir / "index.ts", prompt)
    agent_source.write_bytes(body)
    agent_source.chmod(0o400)
    runtime.chmod(0o500)
    entry_body = {
        "schema_version": 1,
        "campaign_id": campaign["id"],
        "campaign_manifest_sha256": _sha(campaign_raw),
        "campaign_lanes_sha256": _sha(
            canonical_json(
                [
                    {
                        "lane_key": row["lane_key"],
                        "attempt_id": row["attempt_id"],
                        "reviewer": row["reviewer"],
                    }
                    for row in campaign["lanes"]
                    if row["rank"] == 1 and row["lane"] in {"A", "B"}
                ]
            )
        ),
        "source_bindings_sha256": custody["source"]["sha256"],
        "packet_publication_entry_hash": custody["packet"]["publication_entry_hash"],
        "production_profile_sha256": profile.checksum_sha256,
        "production_files_sha256": profile.files_sha256,
        "runtime_identity": identity,
        "extension_sha256": _sha(source_extension),
        "extension_schema_sha256": _sha(source_schema),
        "agent_source_sha256": _sha(body),
        "execution_root": str(execution_root),
        "execution_device": status.st_dev,
        "execution_inode": status.st_ino,
        "attested_at": _timestamp(_now()),
        "authorizations": {
            "review_launch": False,
            "adjudication": False,
            "canonical_import": False,
        },
    }
    private = campaign_v1._private_root(ledger)
    with campaign_v1._ledger_lock(private):
        current = _extended_ledger(private, root)
        filename, protocol, domain, supersedes = _runtime_attestation_publication(current)
        body_with_chain = {
            **entry_body,
            "protocol": protocol,
            **supersedes,
            "previous_hash": current["head"],
        }
        entry = {
            **body_with_chain,
            "entry_hash": _entry_hash(domain, body_with_chain),
        }
        campaign_v1._publish(private / filename, entry)
        verified = _extended_ledger(private, root)
        if verified["runtime"] != entry:
            _fail("runtime attestation publication did not become the ledger head")
    _atomic(execution_root / "runtime-attestation.json", entry)
    return {
        "runtime_attestation_entry_hash": entry["entry_hash"],
        "execution_root": str(execution_root),
        "pi_subagents_version": "0.35.1",
        "pi_version": "0.80.10",
        "live_launch_authorized": False,
    }


def _agent_body(extension: Path, prompt: str) -> bytes:
    text = f"""---
name: {_AGENT_NAME}
description: Production-v1 blind ground-truth reviewer
model: {_MODEL}
thinking: {_THINKING}
tools:
  - read
  - grep
  - find
  - ls
  - submit_blind_review
extensions:
subagentOnlyExtensions:
  - {extension}
---
{prompt.rstrip()}
"""
    return text.encode()


def _runtime_attestation(root: Path, execution_root: Path) -> dict[str, Any]:
    value, raw = _json_raw(execution_root / "runtime-attestation.json", modes={0o400})
    expected_keys = {
        "schema_version",
        "protocol",
        "campaign_id",
        "campaign_manifest_sha256",
        "campaign_lanes_sha256",
        "source_bindings_sha256",
        "packet_publication_entry_hash",
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
    protocol = value.get("protocol")
    domain = _RUNTIME_DOMAIN
    if protocol == _RUNTIME_SUPERSESSION_PROTOCOL:
        expected_keys.add("supersedes_entry_hash")
        domain = _RUNTIME_SUPERSESSION_DOMAIN
    elif protocol != _RUNTIME_PROTOCOL:
        _fail("runtime attestation protocol is invalid")
    _strict_keys(value, expected_keys, "runtime attestation")
    status = execution_root.stat(follow_symlinks=False)
    profile = _profile(root)
    extension = submit_v1._owned_file(
        execution_root / "runtime/extension/index.ts", max_bytes=_MAX_FILE, allowed_modes={0o400}
    )
    extension_schema = submit_v1._owned_file(
        execution_root / "runtime/extension/review-schema.ts",
        max_bytes=_MAX_FILE,
        allowed_modes={0o400},
    )
    agent = submit_v1._owned_file(
        execution_root / "runtime/agent-source.md", max_bytes=_MAX_FILE, allowed_modes={0o400}
    )
    body = {key: item for key, item in value.items() if key != "entry_hash"}
    if (
        canonical_json(value) != raw
        or value.get("schema_version") != 1
        or value.get("protocol") != protocol
        or value.get("execution_root") != str(execution_root)
        or value.get("execution_device") != status.st_dev
        or value.get("execution_inode") != status.st_ino
        or _immutable_runtime_identity(_validate_runtime_identity(value.get("runtime_identity")))
        != _immutable_runtime_identity(_runtime_identity(root))
        or value.get("production_profile_sha256") != profile.checksum_sha256
        or value.get("production_files_sha256") != profile.files_sha256
        or extension != profile.files[_EXTENSION]
        or extension_schema != profile.files[_EXTENSION_SCHEMA]
        or value.get("extension_sha256") != _sha(extension)
        or value.get("extension_schema_sha256") != _sha(extension_schema)
        or value.get("agent_source_sha256") != _sha(agent)
        or not isinstance(value.get("campaign_lanes_sha256"), str)
        or not _DIGEST.fullmatch(cast("str", value["campaign_lanes_sha256"]))
        or value.get("entry_hash") != _entry_hash(domain, body)
        or (
            protocol == _RUNTIME_SUPERSESSION_PROTOCOL
            and not _DIGEST.fullmatch(str(value.get("supersedes_entry_hash", "")))
        )
        or value.get("authorizations")
        != {"review_launch": False, "adjudication": False, "canonical_import": False}
        or not _DIGEST.fullmatch(str(value.get("previous_hash", "")))
        or not _DIGEST.fullmatch(str(value.get("entry_hash", "")))
    ):
        _fail("runtime attestation identity changed")
    return value


def _agent_candidates(census: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for source in ("builtin", "package", "user", "project"):
        source_rows = census.get(source)
        if not isinstance(source_rows, list):
            _fail("resolver census is invalid")
        rows.extend(
            row for row in source_rows if isinstance(row, dict) and row.get("name") == _AGENT_NAME
        )
    return rows


def create_native_agent(root: Path, execution_root: Path, output: Path) -> dict[str, Any]:
    attestation = _runtime_attestation(root, execution_root)
    identity = _runtime_identity(root)
    if identity != attestation.get("runtime_identity"):
        _fail("runtime identity drifted")
    if _agent_candidates(identity["resolver_census"]):
        _fail("production agent already has a resolver definition")
    user_rows = [row for row in identity["roots"] if row.get("kind") == "user-old"]
    if len(user_rows) != 1:
        _fail("user agent discovery root is invalid")
    user_root = Path(cast("str", user_rows[0]["path"]))
    user_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    user_status = user_root.stat(follow_symlinks=False)
    if (
        user_root.is_symlink()
        or not stat.S_ISDIR(user_status.st_mode)
        or user_status.st_uid != os.getuid()
        or stat.S_IMODE(user_status.st_mode) & 0o022
    ):
        _fail("user agent discovery root is unsafe")
    expected_output = user_root / "ground-truth-production-reviewer-v1.md"
    output = output.absolute()
    if output != expected_output:
        _fail("agent output is not the exact flat user discovery path")
    if output.exists() or output.is_symlink():
        _fail("agent output already exists")
    body = submit_v1._owned_file(
        execution_root / "runtime/agent-source.md", max_bytes=_MAX_FILE, allowed_modes={0o400}
    )
    submit_v1._atomic_no_clobber(output, body, mode=0o400)
    after = _runtime_identity(root)
    if _immutable_runtime_identity(after) != _immutable_runtime_identity(identity):
        output.unlink(missing_ok=True)
        _fail("immutable runtime identity drifted during agent installation")
    candidates = _agent_candidates(after["resolver_census"])
    resolved = [
        str(Path(cast("str", row["filePath"])).resolve(strict=True))
        for row in candidates
        if row.get("filePath")
    ]
    effective = [
        row
        for row in after["resolver_census"]["effective"]
        if isinstance(row, dict) and row.get("name") == _AGENT_NAME
    ]
    expected_extension = str(execution_root / "runtime/extension/index.ts")
    if (
        resolved != [str(output.resolve(strict=True))]
        or len(effective) != 1
        or effective[0].get("model") != _MODEL
        or effective[0].get("thinking") != _THINKING
        or effective[0].get("tools") != list(_TOOLS)
        or effective[0].get("extensions") != []
        or effective[0].get("subagentOnlyExtensions") != [expected_extension]
    ):
        output.unlink(missing_ok=True)
        _fail("production agent is not the unique resolver definition")
    receipt = {
        "schema_version": 1,
        "protocol": "ground-truth-native-agent-installation-v1",
        "runtime_attestation_entry_hash": attestation["entry_hash"],
        "agent_name": _AGENT_NAME,
        "path": str(output),
        "sha256": _sha(body),
        "bytes": len(body),
        "resolver_census_sha256": after["resolver_census_sha256"],
        "runtime_identity": after,
    }
    _atomic(execution_root / "agent-installation.json", receipt)
    return receipt


def _installed_agent(root: Path, execution_root: Path) -> dict[str, Any]:
    attestation = _runtime_attestation(root, execution_root)
    receipt, raw_receipt = _json_raw(execution_root / "agent-installation.json", modes={0o400})
    _strict_keys(
        receipt,
        {
            "schema_version",
            "protocol",
            "runtime_attestation_entry_hash",
            "agent_name",
            "path",
            "sha256",
            "bytes",
            "resolver_census_sha256",
            "runtime_identity",
        },
        "agent installation",
    )
    if (
        canonical_json(receipt) != raw_receipt
        or receipt.get("schema_version") != 1
        or receipt.get("protocol") != "ground-truth-native-agent-installation-v1"
        or receipt.get("runtime_attestation_entry_hash") != attestation.get("entry_hash")
        or receipt.get("agent_name") != _AGENT_NAME
    ):
        _fail("agent installation attestation differs")
    path = Path(cast("str", receipt.get("path")))
    raw = submit_v1._owned_file(path, max_bytes=_MAX_FILE, allowed_modes={0o400})
    identity = _runtime_identity(root)
    resolved = [
        str(Path(cast("str", row["filePath"])).resolve(strict=True))
        for row in _agent_candidates(identity["resolver_census"])
        if row.get("filePath")
    ]
    effective = [
        row
        for row in identity["resolver_census"]["effective"]
        if isinstance(row, dict) and row.get("name") == _AGENT_NAME
    ]
    expected_extension = str(execution_root / "runtime/extension/index.ts")
    if (
        identity != receipt.get("runtime_identity")
        or _immutable_runtime_identity(identity)
        != _immutable_runtime_identity(cast("dict[str, Any]", attestation["runtime_identity"]))
        or identity.get("resolver_census_sha256") != receipt.get("resolver_census_sha256")
        or _sha(raw) != receipt.get("sha256")
        or len(raw) != receipt.get("bytes")
        or resolved != [str(path.resolve(strict=True))]
        or len(effective) != 1
        or effective[0].get("model") != _MODEL
        or effective[0].get("thinking") != _THINKING
        or effective[0].get("tools") != list(_TOOLS)
        or effective[0].get("extensions") != []
        or effective[0].get("subagentOnlyExtensions") != [expected_extension]
    ):
        _fail("installed agent identity or discovery changed")
    return receipt


def authorize_canary(
    root: Path,
    campaign_path: Path,
    bindings: Path,
    cache: Path,
    ledger: Path,
    packets: Path,
    execution_root: Path,
    *,
    ranks: Sequence[int],
    lanes: Sequence[str],
    now: datetime | None = None,
) -> dict[str, Any]:
    if list(ranks) != [1] or list(lanes) != ["A", "B"]:
        _fail("only the exact rank-1 A/B canary may be authorized")
    campaign, campaign_raw, _, profile = _custody(
        root, campaign_path, bindings, cache, ledger, packets
    )
    attestation = _runtime_attestation(root, execution_root)
    installed = _installed_agent(root, execution_root)
    private = campaign_v1._private_root(ledger)
    with campaign_v1._ledger_lock(private):
        current = _extended_ledger(private, root)
        fresh_attestation = _runtime_attestation(root, execution_root)
        fresh_installed = _installed_agent(root, execution_root)
        if (
            fresh_attestation != attestation
            or fresh_installed != installed
            or current["runtime"] is None
            or current["runtime"] != fresh_attestation
        ):
            _fail("runtime attestation is not the fresh current campaign runtime")
        attestation = fresh_attestation
        installed = fresh_installed
        if current["authorization"] is not None:
            _fail("canary authorization already exists")
        selected = [
            lane for lane in campaign["lanes"] if lane["rank"] == 1 and lane["lane"] in {"A", "B"}
        ]
        if len(selected) != 2:
            _fail("campaign canary lanes are invalid")
        issued = (now or _now()).astimezone(timezone.utc).replace(microsecond=0)
        body = {
            "schema_version": 1,
            "protocol": "ground-truth-review-canary-authorization-v1",
            "campaign_id": campaign["id"],
            "campaign_manifest_sha256": _sha(campaign_raw),
            "runtime_attestation_entry_hash": attestation["entry_hash"],
            "agent_installation_sha256": _sha(canonical_json(installed)),
            "production_profile_sha256": profile.checksum_sha256,
            "lanes": [
                {
                    "lane_key": row["lane_key"],
                    "attempt_id": row["attempt_id"],
                    "reviewer": row["reviewer"],
                }
                for row in selected
            ],
            "limits": {
                "max_global_active": 3,
                "max_processes_per_lane": 1,
                "replacement_attempts": 0,
            },
            "issued_at": _timestamp(issued),
            "expires_at": _timestamp(issued + timedelta(hours=24)),
            "authorizations": {
                "review_launch": True,
                "adjudication": False,
                "canonical_import": False,
            },
            "previous_hash": current["head"],
        }
        value = {
            **body,
            "entry_hash": _entry_hash(b"ground-truth-review-canary-authorization-v1\0", body),
        }
        campaign_v1._publish(private / "review-canary-authorization.json", value)
        _extended_ledger(private, root)
    return {
        "entry_hash": value["entry_hash"],
        "lanes": value["lanes"],
        "expires_at": value["expires_at"],
    }


def _authorization(current: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    value = current.get("authorization")
    if not isinstance(value, dict):
        _fail("review canary is not authorized")
    reference = (now or _now()).astimezone(timezone.utc)
    if reference < _parse_timestamp(value.get("issued_at")) or reference > _parse_timestamp(
        value.get("expires_at")
    ):
        _fail("review canary authorization expired")
    return value


def _runtime_boundary(
    root: Path,
    execution_root: Path,
    current: dict[str, Any],
    expected_attestation: dict[str, Any],
    expected_installation: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    fresh_attestation = _runtime_attestation(root, execution_root)
    fresh_installation = _installed_agent(root, execution_root)
    runtime = current.get("runtime")
    authorization = current.get("authorization")
    if (
        fresh_attestation != expected_attestation
        or fresh_installation != expected_installation
        or not isinstance(runtime, dict)
        or runtime != fresh_attestation
        or not isinstance(authorization, dict)
        or authorization.get("runtime_attestation_entry_hash")
        != fresh_attestation.get("entry_hash")
        or fresh_installation.get("runtime_attestation_entry_hash")
        != fresh_attestation.get("entry_hash")
    ):
        _fail("runtime or installation drifted at lane boundary")
    return fresh_attestation, fresh_installation


def _append_event_locked(
    private: Path,
    root: Path,
    current: dict[str, Any],
    identifier: str,
    kind: str,
    fields: dict[str, Any],
) -> dict[str, Any]:
    events_dir = private / "lane-events"
    if not events_dir.exists():
        events_dir.mkdir(mode=0o700)
        directory = os.open(private, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    sequence = len(current["events"]) + 1
    body = {
        "schema_version": 1,
        "protocol": "ground-truth-review-lane-event-v1",
        "sequence": sequence,
        "kind": kind,
        **fields,
        "previous_hash": current["head"],
    }
    value = {**body, "entry_hash": _entry_hash(b"ground-truth-review-lane-event-v1\0", body)}
    campaign_v1._publish(events_dir / f"{sequence:06d}-{kind}-{identifier}.json", value)
    _extended_ledger(private, root)
    return value


def _proc_identity(pid: int) -> str:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
    except (OSError, UnicodeDecodeError) as exc:
        raise GroundTruthRunError("broker process identity is unavailable") from exc
    closing = raw.rfind(")")
    fields = raw[closing + 2 :].split() if closing >= 0 else []
    if len(fields) < 20 or not fields[19].isdigit():
        _fail("broker process identity is invalid")
    return fields[19]


def _same_process(pid: int, identity: str) -> bool:
    try:
        return _proc_identity(pid) == identity
    except GroundTruthRunError:
        return False


def _terminate(pid: int, identity: str) -> None:
    if not _same_process(pid, identity):
        return
    with contextlib.suppress(ProcessLookupError):
        os.killpg(pid, signal.SIGTERM)
    deadline = time.monotonic() + 1
    while _same_process(pid, identity) and time.monotonic() < deadline:
        time.sleep(0.01)
    if _same_process(pid, identity):
        with contextlib.suppress(ProcessLookupError):
            os.killpg(pid, signal.SIGKILL)


def _broker_socket_path(attempt_id: str) -> Path:
    runtime = Path(f"/tmp/ground-truth-review-v1-{os.getuid()}")
    _private_directory(runtime, create=True)
    sockets = runtime / "sockets"
    _private_directory(sockets, create=True)
    name = hashlib.sha256(attempt_id.encode()).hexdigest()[:24] + ".sock"
    path = sockets / name
    if len(os.fsencode(path)) >= 100:
        _fail("broker socket path exceeds conservative AF_UNIX bound")
    if path.exists() or path.is_symlink():
        _fail("broker socket path already exists")
    return path


def _registry(packet: Path, record: submit_v1.SubmissionBinding, socket_path: Path) -> Path:
    runtime = Path(f"/tmp/ground-truth-review-v1-{os.getuid()}")
    _private_directory(runtime, create=True)
    registry = runtime / "registry"
    _private_directory(registry, create=True)
    status = packet.stat(follow_symlinks=False)
    key = hashlib.sha256(f"{status.st_dev}:{status.st_ino}".encode()).hexdigest()
    path = registry / f"{key}.json"
    value = {
        "schema_version": 1,
        "protocol": "ground-truth-review-native-registry-v1",
        "attempt_id": record.attempt_id,
        "capability": record.capability,
        "cwd": str(packet),
        "cwd_device": str(status.st_dev),
        "cwd_inode": str(status.st_ino),
        "socket_path": str(socket_path),
    }
    _atomic(path, value, mode=0o600)
    return path


def _broker_limits() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (_MAX_RSS, _MAX_RSS))
    # The broker performs nested, independently bounded source/cache evidence
    # validation. Its ceiling must not be lower than those child prlimit values.
    resource.setrlimit(resource.RLIMIT_FSIZE, (5 * 1024 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    # RLIMIT_NPROC is UID-wide and counts threads, including the parent Pi.
    resource.setrlimit(resource.RLIMIT_NPROC, (512, 512))


def serve_broker(socket_path: Path, binding: Path, deadline_ms: int) -> int:
    _broker_limits()
    return submit_v1.serve(
        socket_path, binding, timeout_seconds=_MAX_WALL, deadline_unix_ms=deadline_ms
    )


def _wait_socket(path: Path, pid: int, identity: str) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if path.exists():
            status = path.lstat()
            if (
                stat.S_ISSOCK(status.st_mode)
                and status.st_uid == os.getuid()
                and stat.S_IMODE(status.st_mode) == 0o600
            ):
                return
            _fail("broker socket is unsafe")
        if not _same_process(pid, identity):
            _fail("broker failed before readiness")
        time.sleep(0.01)
    _fail("broker readiness timeout")


def _slot_claim(execution_root: Path, attempt_id: str, rank: int, lane: Literal["A", "B"]) -> Path:
    slots = execution_root / "slots"
    _private_directory(slots, create=True)
    lock_path = slots / ".lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        claims = [
            path for path in slots.iterdir() if path.name != ".lock" and path.suffix == ".json"
        ]
        if len(claims) >= _MAX_ACTIVE:
            _fail("global active lane bound exceeded")
        claim = slots / f"{attempt_id}.json"
        try:
            _atomic(
                claim,
                {
                    "schema_version": 1,
                    "attempt_id": attempt_id,
                    "owner_pid": os.getpid(),
                    "owner_start_identity": _proc_identity(os.getpid()),
                    "rank": rank,
                    "lane": lane,
                    "broker_pid": None,
                    "broker_start_identity": None,
                    "claimed_at": _timestamp(_now()),
                },
            )
        except submit_v1.SubmissionRejected as exc:
            raise GroundTruthRunError("slot is already claimed") from exc
        return claim
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _slot_update_broker(execution_root: Path, attempt_id: str, pid: int, identity: str) -> None:
    slot = execution_root / "slots" / f"{attempt_id}.json"
    value, _ = _json_raw(slot, modes={0o400})
    value["broker_pid"] = pid
    value["broker_start_identity"] = identity
    temporary = slot.with_name(f".{slot.name}.{os.getpid()}.tmp")
    submit_v1._atomic_no_clobber(temporary, canonical_json(value), mode=0o400)
    temporary.replace(slot)
    directory = os.open(slot.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _slot_release(execution_root: Path, attempt_id: str) -> None:
    slots = execution_root / "slots"
    if not slots.exists():
        return
    descriptor = os.open(slots / ".lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        claim = slots / f"{attempt_id}.json"
        if claim.exists():
            status = claim.lstat()
            if not stat.S_ISREG(status.st_mode) or status.st_uid != os.getuid():
                _fail("slot claim is unsafe")
            claim.unlink()
            directory = os.open(slots, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def prepare_attempt(  # noqa: PLR0915
    root: Path,
    campaign_path: Path,
    bindings: Path,
    cache: Path,
    ledger: Path,
    packets: Path,
    execution_root: Path,
    *,
    rank: int,
    lane: Literal["A", "B"],
    attempt_id: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    if not _ATTEMPT.fullmatch(attempt_id):
        _fail("attempt id is invalid")
    _custody(root, campaign_path, bindings, cache, ledger, packets)
    attestation = _runtime_attestation(root, execution_root)
    installation = _installed_agent(root, execution_root)
    private = campaign_v1._private_root(ledger)
    with campaign_v1._ledger_lock(private):
        current = _extended_ledger(private, root)
        auth = _authorization(current, now)
        fresh_attestation, _ = _runtime_boundary(
            root, execution_root, current, attestation, installation
        )
        allowed = [row for row in auth["lanes"] if row.get("attempt_id") == attempt_id]
        if len(allowed) != 1 or current["states"].get(attempt_id) is not None:
            _fail("lane is not uniquely authorized or was already claimed")
        campaign, _ = _campaign(root, campaign_path)
        lanes = [
            row
            for row in campaign["lanes"]
            if row["attempt_id"] == attempt_id and row["rank"] == rank and row["lane"] == lane
        ]
        if len(lanes) != 1:
            _fail("attempt differs from campaign lane")
    _slot_claim(execution_root, attempt_id, rank, lane)
    pid: int | None = None
    identity: str | None = None
    registry: Path | None = None
    try:
        attempts = execution_root / "attempts"
        _private_directory(attempts, create=True)
        attempt = attempts / attempt_id
        submit_v1.prepare_binding(
            root,
            campaign_path,
            bindings,
            cache,
            ledger,
            packets,
            rank,
            lane,
            attempt_id,
            attempt,
            started_at=(now or _now()),
        )
        record = submit_v1.load_bindings(attempt / "binding.json").records[0]
        with campaign_v1._ledger_lock(private):
            before_spawn = _extended_ledger(private, root)
            _authorization(before_spawn, now)
            fresh_attestation, _ = _runtime_boundary(
                root, execution_root, before_spawn, attestation, installation
            )
            if before_spawn["states"].get(attempt_id) is not None:
                _fail("lane changed before broker spawn")
        logs = attempt / "logs"
        logs.mkdir(mode=0o700)
        socket_path = _broker_socket_path(attempt_id)
        registry = _registry(attempt / "packet", record, socket_path)
        deadline_ms = int((now or _now()).timestamp() * 1000) + _MAX_WALL * 1000
        stdout = os.open(logs / "broker.stdout", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        stderr = os.open(logs / "broker.stderr", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        argv = [
            sys.executable,
            "-m",
            "benchmarks.real_world.ground_truth_run_v1",
            "serve-broker",
            "--socket",
            str(socket_path),
            "--binding",
            str(attempt / "binding.json"),
            "--deadline-unix-ms",
            str(deadline_ms),
        ]
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(Path.home()),
            "PYTHONPATH": str(root),
            "LANG": "C",
            "LC_ALL": "C",
        }
        actions = [
            (os.POSIX_SPAWN_DUP2, stdout, 1),
            (os.POSIX_SPAWN_DUP2, stderr, 2),
            (os.POSIX_SPAWN_CLOSE, stdout),
            (os.POSIX_SPAWN_CLOSE, stderr),
        ]
        try:
            pid = os.posix_spawn(sys.executable, argv, env, file_actions=actions, setsid=True)
        finally:
            os.close(stdout)
            os.close(stderr)
        identity = _proc_identity(pid)
        _slot_update_broker(execution_root, attempt_id, pid, identity)
        _wait_socket(socket_path, pid, identity)
        state = {
            "schema_version": 1,
            "attempt_id": attempt_id,
            "rank": rank,
            "lane": lane,
            "packet": str(attempt / "packet"),
            "binding": str(attempt / "binding.json"),
            "binding_sha256": _sha(
                submit_v1._owned_file(
                    attempt / "binding.json", max_bytes=_MAX_FILE, allowed_modes={0o400}
                )
            ),
            "broker_pid": pid,
            "broker_start_identity": identity,
            "socket": str(socket_path),
            "registry": str(registry),
            "deadline_unix_ms": deadline_ms,
            "runtime_attestation_entry_hash": fresh_attestation["entry_hash"],
            "packet_root_sha256": record.packet_root_sha256,
            "reviewer": record.reviewer.model_dump(mode="json"),
        }
        _atomic(attempt / "native-state.json", state)
        with campaign_v1._ledger_lock(private):
            current = _extended_ledger(private, root)
            _authorization(current, now)
            fresh_attestation, _ = _runtime_boundary(
                root, execution_root, current, attestation, installation
            )
            if current["states"].get(attempt_id) is not None:
                _fail("lane was claimed while preparing")
            event = _append_event_locked(
                private,
                root,
                current,
                attempt_id,
                "prepared",
                {
                    "attempt_id": attempt_id,
                    "rank": rank,
                    "lane": lane,
                    "lane_key": allowed[0]["lane_key"],
                    "binding_sha256": state["binding_sha256"],
                    "runtime_attestation_entry_hash": fresh_attestation["entry_hash"],
                    "packet_root_sha256": record.packet_root_sha256,
                    "broker_pid": pid,
                    "broker_start_identity": identity,
                    "prepared_at": _timestamp(now or _now()),
                },
            )
    except BaseException as exc:
        if pid is not None and identity is not None:
            _terminate(pid, identity)
        if registry is not None:
            registry.unlink(missing_ok=True)
        with contextlib.suppress(Exception), campaign_v1._ledger_lock(private):
            current = _extended_ledger(private, root)
            if current["states"].get(attempt_id) is None:
                _operational_failure(private, root, current, attempt_id, str(exc))
        _slot_release(execution_root, attempt_id)
        raise
    return {
        "attempt_id": attempt_id,
        "event_hash": event["entry_hash"],
        "cwd": state["packet"],
        "live_launch_authorized": True,
    }


def _state(execution_root: Path, attempt_id: str) -> dict[str, Any]:
    if not _ATTEMPT.fullmatch(attempt_id):
        _fail("attempt id is invalid")
    value, raw = _json_raw(
        execution_root / "attempts" / attempt_id / "native-state.json", modes={0o400}
    )
    _strict_keys(
        value,
        {
            "schema_version",
            "attempt_id",
            "rank",
            "lane",
            "packet",
            "binding",
            "binding_sha256",
            "broker_pid",
            "broker_start_identity",
            "socket",
            "registry",
            "deadline_unix_ms",
            "runtime_attestation_entry_hash",
            "packet_root_sha256",
            "reviewer",
        },
        "native state",
    )
    if (
        canonical_json(value) != raw
        or value["schema_version"] != 1
        or value["attempt_id"] != attempt_id
        or value["lane"] != attempt_id[-1]
        or not isinstance(value["broker_pid"], int)
        or not isinstance(value["broker_start_identity"], str)
        or not isinstance(value["deadline_unix_ms"], int)
        or not _DIGEST.fullmatch(str(value["binding_sha256"]))
        or not _DIGEST.fullmatch(str(value["packet_root_sha256"]))
    ):
        _fail("native state identity is invalid")
    return value


def _validate_native_plan_schema(root: Path, plan: dict[str, Any]) -> str:
    subagents, _, _, _ = _package_paths()
    jiti = subagents / "node_modules/jiti/lib/jiti.mjs"
    if not jiti.exists():
        jiti = subagents.parent / "jiti/lib/jiti.mjs"
    schemas = subagents / "src/extension/schemas.ts"
    submit_v1._owned_file(jiti, max_bytes=8 * 1024 * 1024, allowed_modes={0o644})
    submit_v1._owned_file(schemas, max_bytes=8 * 1024 * 1024, allowed_modes={0o644})
    script = """
import { pathToFileURL } from 'node:url';
const { createJiti } = await import(pathToFileURL(process.argv[1]).href);
const jiti = createJiti(import.meta.url);
const api = await jiti.import(process.argv[2]);
const valueApi = await import(pathToFileURL(process.argv[3]).href);
const value = JSON.parse(process.argv[4]);
if (!valueApi.Value.Check(api.SubagentParams, value)) process.exit(9);
process.stdout.write('VALID');
"""
    node = shutil.which("node")
    if node is None:
        _fail("Node is unavailable")
    node_path = Path(node).resolve(strict=True)
    value_module = subagents.parent / "typebox/build/value/index.mjs"
    submit_v1._owned_file(value_module, max_bytes=8 * 1024 * 1024, allowed_modes={0o644})
    argv = [
        str(node_path),
        "--input-type=module",
        "-e",
        script,
        str(jiti),
        str(schemas),
        str(value_module),
        canonical_json(plan).decode(),
    ]
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(Path.home()),
        "LANG": "C",
        "LC_ALL": "C",
        "PI_CODING_AGENT_DIR": os.environ.get(
            "PI_CODING_AGENT_DIR", str(Path.home() / ".pi/agent")
        ),
    }
    result = _bounded_node_attestation(argv, root, env, timeout=15)
    if result.returncode != 0 or result.stdout != b"VALID" or result.stderr:
        _fail("native launch plan fails pinned SubagentParams Value.Check")
    return _sha(canonical_json(plan))


def native_launch_plan(
    root: Path, ledger: Path, execution_root: Path, attempt_ids: Sequence[str]
) -> dict[str, Any]:
    if (
        not attempt_ids
        or len(attempt_ids) > _MAX_ACTIVE
        or len(set(attempt_ids)) != len(attempt_ids)
        or any(not _ATTEMPT.fullmatch(item) for item in attempt_ids)
    ):
        _fail("launch attempt list is invalid")
    _installed_agent(root, execution_root)
    private = campaign_v1._private_root(ledger)
    states: dict[str, dict[str, Any]] = {}
    tasks: list[dict[str, Any]] = []
    with campaign_v1._ledger_lock(private):
        snapshot = _extended_ledger(private, root)
        _authorization(snapshot)
        for attempt_id in attempt_ids:
            if snapshot["states"].get(attempt_id) != "prepared":
                _fail("launch requires an exact prepared lane")
            state = _state(execution_root, attempt_id)
            pid, identity = int(state["broker_pid"]), cast("str", state["broker_start_identity"])
            if not _same_process(pid, identity) or int(state["deadline_unix_ms"]) <= int(
                time.time() * 1000
            ):
                _fail("prepared broker is not live")
            packet = Path(cast("str", state["packet"])).resolve(strict=True)
            status = packet.stat(follow_symlinks=False)
            record = submit_v1.load_bindings(Path(cast("str", state["binding"]))).records[0]
            if status.st_dev != record.packet_device or status.st_ino != record.packet_inode:
                _fail("prepared cwd identity changed")
            states[attempt_id] = state
            tasks.append(
                {
                    "agent": _AGENT_NAME,
                    "task": _TASK_TEXT,
                    "cwd": str(packet),
                    "model": _MODEL,
                    "output": False,
                    "progress": False,
                    "acceptance": False,
                    "toolBudget": {
                        "soft": 200,
                        "hard": 203,
                        "block": ["read", "grep", "find", "ls"],
                    },
                }
            )
    plan = {
        "tasks": tasks,
        "context": "fresh",
        "concurrency": 3,
        "artifacts": False,
        "includeProgress": False,
        "async": False,
        "timeoutMs": 1_798_000,
    }
    plan_hash = _validate_native_plan_schema(root, plan)
    with campaign_v1._ledger_lock(private):
        current = _extended_ledger(private, root)
        _authorization(current)
        _installed_agent(root, execution_root)
        for attempt_id, state in states.items():
            if current["states"].get(attempt_id) != "prepared":
                _fail("lane changed before atomic launch claim")
            pid, identity = int(state["broker_pid"]), cast("str", state["broker_start_identity"])
            if not _same_process(pid, identity):
                _fail("broker changed before atomic launch claim")
        batch_id = hashlib.sha256(
            canonical_json({"plan": plan_hash, "previous": current["head"]})
        ).hexdigest()[:24]
        event = _append_event_locked(
            private,
            root,
            current,
            batch_id,
            "launch_claimed",
            {
                "batch_id": batch_id,
                "attempt_ids": list(attempt_ids),
                "task_indices": list(range(len(attempt_ids))),
                "runtime_attestation_entry_hash": current["runtime"]["entry_hash"],
                "plan_sha256": plan_hash,
                "claimed_at": _timestamp(_now()),
            },
        )
    return {
        "batch_id": batch_id,
        "launch_claim_event_hash": event["entry_hash"],
        "plan_sha256": plan_hash,
        "subagent_call": plan,
    }


def _authenticated_session_file(session: Path) -> tuple[bytes, os.stat_result]:
    _, _, _, config_path = _package_paths()
    session_root = config_path.parents[2] / "sessions"
    session_root = session_root.resolve(strict=True)
    if not session.is_absolute():
        _fail("session path must be absolute")
    resolved = session.resolve(strict=True)
    try:
        resolved.relative_to(session_root)
    except ValueError as exc:
        raise GroundTruthRunError("session path is outside authenticated Pi session root") from exc
    current = Path(resolved.anchor)
    for part in resolved.parts[1:]:
        current /= part
        if current.is_symlink():
            _fail("session path has a symlink ancestor")
    before = resolved.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or stat.S_IMODE(before.st_mode) not in {0o600, 0o644}
    ):
        _fail("session file identity is invalid")
    raw = submit_v1._owned_file(resolved, max_bytes=_MAX_SESSION, allowed_modes={0o600, 0o644})
    after = resolved.stat(follow_symlinks=False)
    if (before.st_dev, before.st_ino, before.st_ctime_ns, before.st_size) != (
        after.st_dev,
        after.st_ino,
        after.st_ctime_ns,
        after.st_size,
    ):
        _fail("session file drifted while binding")
    return raw, before


def _validate_session_layout(session: Path, native_run_id: str, task_index: int) -> None:
    _, _, _, config_path = _package_paths()
    session_root = (config_path.parents[2] / "sessions").resolve(strict=True)
    resolved = session.resolve(strict=True)
    try:
        relative = resolved.relative_to(session_root)
    except ValueError as exc:
        raise GroundTruthRunError("session path is outside authenticated Pi session root") from exc
    if (
        len(relative.parts) != 4
        or relative.parts[1] != native_run_id
        or relative.parts[2] != f"run-{task_index}"
        or relative.parts[3] != "session.jsonl"
        or not relative.parts[0]
    ):
        _fail("session path does not match claimed native batch task")


def _session_start(raw: bytes) -> datetime:
    try:
        first = json.loads(raw.splitlines()[0], object_pairs_hook=_unique)
    except (IndexError, json.JSONDecodeError, ValueError, UnicodeDecodeError) as exc:
        raise GroundTruthRunError("session header is invalid") from exc
    if not isinstance(first, dict) or first.get("type") != "session":
        _fail("session header is invalid")
    _event_timestamp(first.get("timestamp"))
    return datetime.fromisoformat(cast("str", first["timestamp"])[:-1] + "+00:00")


def bind_native_result(
    root: Path,
    ledger: Path,
    execution_root: Path,
    attempt_id: str,
    batch_id: str,
    native_run_id: str,
    session: Path,
    parent_status: Literal["success", "failure"],
) -> dict[str, Any]:
    if (
        not _ATTEMPT.fullmatch(attempt_id)
        or not _RUNTIME_NAME.fullmatch(batch_id)
        or not _NATIVE_RUN.fullmatch(native_run_id)
        or parent_status not in {"success", "failure"}
    ):
        _fail("native result identity is invalid")
    _installed_agent(root, execution_root)
    private = campaign_v1._private_root(ledger)
    state = _state(execution_root, attempt_id)
    with campaign_v1._ledger_lock(private):
        current = _extended_ledger(private, root)
        batch = current["batches"].get(batch_id)
        if (
            current["states"].get(attempt_id) != "launch_claimed"
            or not isinstance(batch, dict)
            or attempt_id not in batch
        ):
            _fail("native result does not match one claimed launch batch")
        task_index = batch[attempt_id]
        prior_run = current["batch_native_runs"].get(batch_id)
        if prior_run is not None and prior_run != native_run_id:
            _fail("native run id differs from claimed batch")
        _validate_session_layout(session, native_run_id, task_index)
        raw, status = _authenticated_session_file(session)
        claim = current["batch_events"].get(batch_id)
        if not isinstance(claim, dict) or _session_start(raw) < _parse_timestamp(
            claim["claimed_at"]
        ):
            _fail("session predates claimed native launch batch")
        event = _append_event_locked(
            private,
            root,
            current,
            attempt_id,
            "native_result",
            {
                "attempt_id": attempt_id,
                "batch_id": batch_id,
                "native_run_id": native_run_id,
                "task_index": task_index,
                "runtime_attestation_entry_hash": current["runtime"]["entry_hash"],
                "session_path": str(session.resolve(strict=True)),
                "session_device": status.st_dev,
                "session_inode": status.st_ino,
                "session_uid": status.st_uid,
                "session_mode": stat.S_IMODE(status.st_mode),
                "session_sha256": _sha(raw),
                "parent_status": parent_status,
                "bound_at": _timestamp(_now()),
            },
        )
    if parent_status == "failure":
        _cleanup_attempt(state)
        _slot_release(execution_root, attempt_id)
    return {
        "attempt_id": attempt_id,
        "parent_status": parent_status,
        "event_hash": event["entry_hash"],
        "eligible": False,
    }


def finalize_attempt(
    root: Path, ledger: Path, execution_root: Path, attempt_id: str
) -> dict[str, Any]:
    _installed_agent(root, execution_root)
    state = _state(execution_root, attempt_id)
    private = campaign_v1._private_root(ledger)
    with campaign_v1._ledger_lock(private):
        current = _extended_ledger(private, root)
        if current["states"].get(attempt_id) != "native_bound":
            _fail("finalization requires a successful bound native result")
    try:
        record = submit_v1.load_bindings(Path(cast("str", state["binding"]))).records[0]
        receipt = submit_v1.recover_submission(record)
        review_raw = submit_v1._owned_file(
            Path(record.escrow_path), max_bytes=_MAX_OUTPUT, allowed_modes={0o400}
        )
        pending = {
            "schema_version": 1,
            "attempt_id": attempt_id,
            "review_sha256": artifact_sha256(json.loads(review_raw)),
            "escrow_sha256": _sha(review_raw),
            "receipt": receipt.model_dump(mode="json"),
            "binding_sha256": state["binding_sha256"],
            "eligible": False,
        }
        _atomic(execution_root / "attempts" / attempt_id / "pending-result.json", pending)
        with campaign_v1._ledger_lock(private):
            current = _extended_ledger(private, root)
            if current["states"].get(attempt_id) != "native_bound":
                _fail("lane changed while finalizing escrow")
            event = _append_event_locked(
                private,
                root,
                current,
                attempt_id,
                "pending",
                {
                    "attempt_id": attempt_id,
                    "review_sha256": pending["review_sha256"],
                    "escrow_sha256": pending["escrow_sha256"],
                    "receipt_sha256": _sha(canonical_json(pending["receipt"])),
                    "binding_sha256": state["binding_sha256"],
                    "pending_at": _timestamp(_now()),
                },
            )
    except BaseException as exc:
        with contextlib.suppress(Exception), campaign_v1._ledger_lock(private):
            current = _extended_ledger(private, root)
            if current["states"].get(attempt_id) == "native_bound":
                _operational_failure(private, root, current, attempt_id, str(exc))
        _cleanup_attempt(state)
        _slot_release(execution_root, attempt_id)
        raise
    return {
        "attempt_id": attempt_id,
        "pending_event_hash": event["entry_hash"],
        "eligible": False,
    }


def _session_integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        _fail(f"session {label} usage is invalid")
    return value


def _session_cost(value: object) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        or value < 0
    ):
        _fail("session cost is invalid")
    return float(value)


def _session_source_path(packet: Path, value: object) -> None:
    if not isinstance(value, str) or not value or "\x00" in value:
        _fail("session source path is invalid")
    candidate = Path(value)
    resolved = (
        candidate.resolve(strict=False)
        if candidate.is_absolute()
        else (packet / candidate).resolve(strict=False)
    )
    try:
        resolved.relative_to(packet)
    except ValueError as exc:
        raise GroundTruthRunError("session source path escaped packet") from exc


def _event_timestamp(value: object) -> None:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail("session event timestamp is invalid")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise GroundTruthRunError("session event timestamp is invalid") from exc


def _audit_session_data(  # noqa: PLR0912,PLR0915
    session: Path, packet: Path, receipt: dict[str, Any], bound: dict[str, Any]
) -> dict[str, Any]:
    raw, status = _authenticated_session_file(session)
    if (
        str(session.resolve(strict=True)) != bound["session_path"]
        or status.st_dev != bound["session_device"]
        or status.st_ino != bound["session_inode"]
        or status.st_uid != bound["session_uid"]
        or stat.S_IMODE(status.st_mode) != bound["session_mode"]
        or _sha(raw) != bound["session_sha256"]
        or bound["parent_status"] != "success"
    ):
        _fail("session differs from bound native result")
    if not raw.endswith(b"\n"):
        _fail("session JSONL framing is invalid")
    calls: dict[str, str] = {}
    results: set[str] = set()
    session_count = model_count = thinking_count = user_count = 0
    submit_success = submit_rejections = 0
    terminal_success = terminal_ack = False
    input_tokens = output_tokens = cache_tokens = 0
    cost = 0.0
    previous_event_id: str | None = None
    event_ids: set[str] = set()
    identity_ready = False
    for ordinal, line in enumerate(raw.splitlines()):
        if terminal_ack:
            _fail("terminal acknowledgement was not the final event")
        try:
            event = json.loads(line, object_pairs_hook=_unique, parse_constant=_constant)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
            raise GroundTruthRunError("session JSONL is invalid") from exc
        if not isinstance(event, dict):
            _fail("session event is invalid")
        kind = event.get("type")
        if ordinal == 0:
            _strict_keys(event, {"type", "version", "id", "timestamp", "cwd"}, "session header")
            if (
                kind != "session"
                or event["version"] != 3
                or not isinstance(event["id"], str)
                or not _SESSION_ID.fullmatch(event["id"])
                or event["cwd"] != str(packet)
            ):
                _fail("session header identity is invalid")
            _event_timestamp(event["timestamp"])
            event_ids.add(event["id"])
            session_count += 1
            continue
        if kind not in {"model_change", "thinking_level_change", "message"}:
            _fail("session event type is invalid")
        if (
            not isinstance(event.get("id"), str)
            or not _EVENT_ID.fullmatch(event["id"])
            or event["id"] in event_ids
            or event.get("parentId") == event["id"]
        ):
            _fail("session event id is invalid or duplicated")
        expected_parent = previous_event_id
        if ordinal == 1:
            expected_parent = None
        if event.get("parentId") != expected_parent:
            _fail("session event parent chain is invalid")
        previous_event_id = cast("str", event["id"])
        event_ids.add(previous_event_id)
        _event_timestamp(event.get("timestamp"))
        if kind == "model_change":
            _strict_keys(
                event, {"type", "id", "parentId", "timestamp", "provider", "modelId"}, "model event"
            )
            model_count += 1
            if (
                ordinal != 1
                or event["provider"] != "openai-codex"
                or event["modelId"] != "gpt-5.6-luna"
            ):
                _fail("session model differs")
            continue
        if kind == "thinking_level_change":
            _strict_keys(
                event, {"type", "id", "parentId", "timestamp", "thinkingLevel"}, "thinking event"
            )
            thinking_count += 1
            if ordinal != 2 or event["thinkingLevel"] != _THINKING:
                _fail("session thinking differs")
            identity_ready = model_count == 1 and thinking_count == 1
            continue
        _strict_keys(event, {"type", "id", "parentId", "timestamp", "message"}, "message event")
        message = event["message"]
        if not isinstance(message, dict) or not identity_ready:
            _fail("session message is invalid")
        role = message.get("role")
        if role == "user":
            _strict_keys(message, {"role", "content", "timestamp"}, "user message")
            user_count += 1
            if (
                user_count != 1
                or calls
                or message["content"] != [{"type": "text", "text": _TASK_TEXT}]
                or not isinstance(message["timestamp"], int)
            ):
                _fail("initial user task is invalid")
            continue
        if user_count != 1:
            _fail("assistant/tool activity preceded exact user task")
        if terminal_success and role != "assistant":
            _fail("successful submission was not followed directly by acknowledgement")
        if role == "assistant":
            _strict_keys(
                message,
                {
                    "role",
                    "content",
                    "api",
                    "provider",
                    "model",
                    "usage",
                    "stopReason",
                    "timestamp",
                    "responseId",
                },
                "assistant message",
            )
            content, usage = message["content"], message["usage"]
            if (
                not isinstance(content, list)
                or not isinstance(usage, dict)
                or message["api"] != "openai-codex-responses"
                or message["provider"] != "openai-codex"
                or message["model"] != "gpt-5.6-luna"
                or not isinstance(message["timestamp"], int)
                or not isinstance(message["responseId"], str)
            ):
                _fail("assistant identity is invalid")
            _strict_keys(
                usage,
                {"input", "output", "cacheRead", "cacheWrite", "reasoning", "totalTokens", "cost"},
                "assistant usage",
            )
            components = [
                _session_integer(usage[key], key)
                for key in ("input", "output", "cacheRead", "cacheWrite", "reasoning")
            ]
            if _session_integer(usage["totalTokens"], "totalTokens") != sum(components[:4]):
                _fail("assistant total token count is invalid")
            costs = usage["cost"]
            if not isinstance(costs, dict):
                _fail("session cost is invalid")
            _strict_keys(
                costs, {"input", "output", "cacheRead", "cacheWrite", "total"}, "usage cost"
            )
            for key in ("input", "output", "cacheRead", "cacheWrite"):
                _session_cost(costs[key])
            cost += _session_cost(costs["total"])
            input_tokens += components[0]
            output_tokens += components[1]
            cache_tokens += components[2]
            if terminal_success:
                texts = [
                    item
                    for item in content
                    if isinstance(item, dict) and item.get("type") == "text"
                ]
                if (
                    message["stopReason"] != "stop"
                    or len(texts) != 1
                    or texts[0].get("text") != "SUBMISSION_COMPLETE"
                    or set(texts[0]) - {"type", "text", "textSignature"}
                    or any(
                        not isinstance(item, dict) or item.get("type") not in {"thinking", "text"}
                        for item in content
                    )
                ):
                    _fail("terminal acknowledgement is invalid")
                terminal_ack = True
            else:
                if message["stopReason"] != "toolUse":
                    _fail("nonterminal assistant stop reason is invalid")
                for item in content:
                    if not isinstance(item, dict):
                        _fail("assistant content is invalid")
                    if item.get("type") == "thinking":
                        continue
                    if item.get("type") == "text":
                        if str(item.get("text", "")).strip():
                            _fail("assistant emitted forbidden prose")
                        continue
                    if item.get("type") != "toolCall" or set(item) != {
                        "type",
                        "id",
                        "name",
                        "arguments",
                    }:
                        _fail("assistant tool call is invalid")
                    call_id, name, arguments = item["id"], item["name"], item["arguments"]
                    if (
                        not isinstance(call_id, str)
                        or not call_id
                        or call_id in calls
                        or name not in _TOOLS
                        or not isinstance(arguments, dict)
                    ):
                        _fail("tool call is invalid")
                    calls[call_id] = cast("str", name)
                    if name in {"read", "grep", "find", "ls"}:
                        _session_source_path(packet, arguments.get("path", "."))
        elif role == "toolResult":
            allowed = {"role", "toolCallId", "toolName", "content", "isError", "timestamp"}
            if "details" in message:
                allowed.add("details")
            _strict_keys(message, allowed, "tool result")
            call_id, name = message["toolCallId"], message["toolName"]
            if (
                not isinstance(call_id, str)
                or calls.get(call_id) != name
                or call_id in results
                or message["isError"] is not False
                or not isinstance(message["timestamp"], int)
                or not isinstance(message["content"], list)
                or any(
                    not isinstance(item, dict)
                    or set(item) != {"type", "text"}
                    or item["type"] != "text"
                    or not isinstance(item["text"], str)
                    for item in message["content"]
                )
            ):
                _fail("tool result is invalid")
            results.add(call_id)
            if name == "submit_blind_review":
                details = message.get("details")
                if isinstance(details, dict) and details == receipt:
                    submit_success += 1
                    terminal_success = True
                elif (
                    isinstance(details, dict)
                    and details.get("ok") is False
                    and details.get("code") in _CORRECTABLE
                    and set(details) <= {"protocol_version", "ok", "code", "diagnostic"}
                ):
                    submit_rejections += 1
                else:
                    _fail("submission result is invalid")
        else:
            _fail("session role is invalid")
    submit_calls = sum(name == "submit_blind_review" for name in calls.values())
    if (
        session_count != 1
        or model_count != 1
        or thinking_count != 1
        or user_count != 1
        or set(calls) != results
        or not 1 <= submit_calls <= 3
        or submit_success != 1
        or submit_rejections != submit_calls - 1
        or not terminal_success
        or not terminal_ack
        or len(calls) > 203
    ):
        _fail("session grammar or cardinality is invalid")
    after = session.stat(follow_symlinks=False)
    if (status.st_dev, status.st_ino, status.st_ctime_ns, status.st_size) != (
        after.st_dev,
        after.st_ino,
        after.st_ctime_ns,
        after.st_size,
    ):
        _fail("session file drifted during audit")
    return {
        "session_sha256": _sha(raw),
        "tool_calls": len(calls),
        "submit_calls": submit_calls,
        "correction_submissions": submit_rejections,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cache_read_tokens": cache_tokens,
        "cost_micro_usd": round(cost * 1_000_000),
        "terminal_acknowledgement": "SUBMISSION_COMPLETE",
        "native_parent_success": True,
    }


def _cleanup_attempt(state: dict[str, Any]) -> None:
    registry = Path(cast("str", state["registry"]))
    registry.unlink(missing_ok=True)
    socket_path = Path(cast("str", state["socket"]))
    socket_path.unlink(missing_ok=True)
    pid, identity = int(state["broker_pid"]), cast("str", state["broker_start_identity"])
    _terminate(pid, identity)


def _operational_failure(
    private: Path, root: Path, current: dict[str, Any], attempt_id: str, reason: str
) -> dict[str, Any]:
    return _append_event_locked(
        private,
        root,
        current,
        attempt_id,
        "operational_failed",
        {
            "attempt_id": attempt_id,
            "reason": reason[:500],
            "failed_at": _timestamp(_now()),
            "relaunch_authorized": False,
        },
    )


def audit_session(
    root: Path,
    ledger: Path,
    execution_root: Path,
    attempt_id: str,
) -> dict[str, Any]:
    _installed_agent(root, execution_root)
    state = _state(execution_root, attempt_id)
    private = campaign_v1._private_root(ledger)
    with campaign_v1._ledger_lock(private):
        current = _extended_ledger(private, root)
        if current["states"].get(attempt_id) != "pending":
            _fail("session audit requires pending escrow")
        bound = current["native_results"].get(attempt_id)
        if not isinstance(bound, dict) or bound.get("parent_status") != "success":
            _fail("session audit requires one successful bound native result")
    try:
        pending, pending_raw = _json_raw(
            execution_root / "attempts" / attempt_id / "pending-result.json", modes={0o400}
        )
        record = submit_v1.load_bindings(Path(cast("str", state["binding"]))).records[0]
        recovered = submit_v1.recover_submission(record)
        receipt = recovered.model_dump(mode="json")
        if receipt != pending.get("receipt"):
            _fail("pending receipt differs from fresh recovery")
        audit = _audit_session_data(
            Path(cast("str", bound["session_path"])),
            Path(cast("str", state["packet"])),
            receipt,
            bound,
        )
        review_raw = submit_v1._owned_file(
            Path(record.escrow_path), max_bytes=_MAX_OUTPUT, allowed_modes={0o400}
        )
        audit.update(
            {
                "schema_version": 1,
                "protocol": "ground-truth-review-session-audit-v1",
                "attempt_id": attempt_id,
                "binding_sha256": state["binding_sha256"],
                "pending_sha256": _sha(pending_raw),
                "review_sha256": artifact_sha256(json.loads(review_raw)),
                "receipt_sha256": _sha(canonical_json(receipt)),
                "runtime_attestation_entry_hash": state["runtime_attestation_entry_hash"],
                "packet_root_sha256": state["packet_root_sha256"],
                "reviewer": state["reviewer"],
                "eligible": True,
            }
        )
        audit_path = execution_root / "attempts" / attempt_id / "session-audit.json"
        _atomic(audit_path, audit)
        with campaign_v1._ledger_lock(private):
            current = _extended_ledger(private, root)
            if current["states"].get(attempt_id) != "pending":
                _fail("lane changed while auditing session")
            event = _append_event_locked(
                private,
                root,
                current,
                attempt_id,
                "completed",
                {
                    "attempt_id": attempt_id,
                    "review_sha256": audit["review_sha256"],
                    "receipt_sha256": audit["receipt_sha256"],
                    "session_sha256": audit["session_sha256"],
                    "audit_sha256": _sha(canonical_json(audit)),
                    "runtime_attestation_entry_hash": audit["runtime_attestation_entry_hash"],
                    "packet_root_sha256": audit["packet_root_sha256"],
                    "binding_sha256": audit["binding_sha256"],
                    "completed_at": _timestamp(_now()),
                    "eligible": True,
                },
            )
    except BaseException as exc:
        with contextlib.suppress(Exception), campaign_v1._ledger_lock(private):
            current = _extended_ledger(private, root)
            if current["states"].get(attempt_id) == "pending":
                _operational_failure(private, root, current, attempt_id, str(exc))
        _cleanup_attempt(state)
        _slot_release(execution_root, attempt_id)
        raise
    _cleanup_attempt(state)
    _slot_release(execution_root, attempt_id)
    return {
        "attempt_id": attempt_id,
        "completed_event_hash": event["entry_hash"],
        "eligible": True,
    }


def reconcile(root: Path, ledger: Path, execution_root: Path) -> dict[str, Any]:
    private = campaign_v1._private_root(ledger)
    released: list[str] = []
    needs_attention: list[str] = []
    slots = execution_root / "slots"
    _private_directory(slots, create=True)
    with campaign_v1._ledger_lock(private):
        current = _extended_ledger(private, root)
        slot_paths = sorted(
            path for path in slots.iterdir() if path.name != ".lock" and path.suffix == ".json"
        )
        for path in slot_paths:
            slot, _ = _json_raw(path, modes={0o400})
            _strict_keys(
                slot,
                {
                    "schema_version",
                    "attempt_id",
                    "owner_pid",
                    "owner_start_identity",
                    "rank",
                    "lane",
                    "broker_pid",
                    "broker_start_identity",
                    "claimed_at",
                },
                "slot claim",
            )
            attempt = slot.get("attempt_id")
            if (
                not isinstance(attempt, str)
                or path.name != f"{attempt}.json"
                or not _ATTEMPT.fullmatch(attempt)
            ):
                _fail("slot attempt identity is invalid")
            state_name = current["states"].get(attempt)
            owner_alive = _same_process(
                int(slot["owner_pid"]), cast("str", slot["owner_start_identity"])
            )
            broker_pid = slot.get("broker_pid")
            broker_identity = slot.get("broker_start_identity")
            broker_alive = (
                isinstance(broker_pid, int)
                and isinstance(broker_identity, str)
                and _same_process(broker_pid, broker_identity)
            )
            if state_name is None and not owner_alive:
                if broker_alive:
                    _terminate(cast("int", broker_pid), cast("str", broker_identity))
                attempt_root = execution_root / "attempts" / attempt
                if attempt_root.exists():
                    with contextlib.suppress(GroundTruthRunError):
                        state = _state(execution_root, attempt)
                        Path(cast("str", state.get("registry", "/nonexistent"))).unlink(
                            missing_ok=True
                        )
                        Path(cast("str", state.get("socket", "/nonexistent"))).unlink(
                            missing_ok=True
                        )
                    packet_v1._thaw_remove(attempt_root)
                _slot_release(execution_root, attempt)
                released.append(attempt)
                continue
            if state_name == "prepared" and not broker_alive:
                _operational_failure(
                    private, root, current, attempt, "never-launched broker exited"
                )
                _slot_release(execution_root, attempt)
                released.append(attempt)
                current = _extended_ledger(private, root)
            elif state_name in {"launch_claimed", "native_bound", "pending"}:
                if not broker_alive:
                    needs_attention.append(attempt)
            elif state_name in {"completed", "operational_failed"}:
                _slot_release(execution_root, attempt)
                released.append(attempt)
    return {"released_orphaned": released, "claimed_needs_attention": needs_attention}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    sub = parser.add_subparsers(dest="command", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--campaign", type=Path, required=True)
    common.add_argument("--bindings", type=Path, required=True)
    common.add_argument("--cache", type=Path, required=True)
    common.add_argument("--ledger-root", type=Path, required=True)
    common.add_argument("--packets", type=Path, required=True)
    common.add_argument("--execution-root", type=Path, required=True)
    sub.add_parser("attest-runtime", parents=[common])
    create = sub.add_parser("create-native-agent")
    create.add_argument("--execution-root", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    auth = sub.add_parser("authorize-canary", parents=[common])
    auth.add_argument("--ranks", type=int, nargs="+", required=True)
    auth.add_argument("--lanes", nargs="+", required=True)
    prepare = sub.add_parser("prepare-attempt", parents=[common])
    prepare.add_argument("--rank", type=int, required=True)
    prepare.add_argument("--lane", choices=("A", "B"), required=True)
    prepare.add_argument("--attempt-id", required=True)
    launch = sub.add_parser("native-launch-plan")
    launch.add_argument("--ledger-root", type=Path, required=True)
    launch.add_argument("--execution-root", type=Path, required=True)
    launch.add_argument("--attempt-id", action="append", required=True)
    bind_result = sub.add_parser("bind-native-result")
    bind_result.add_argument("--ledger-root", type=Path, required=True)
    bind_result.add_argument("--execution-root", type=Path, required=True)
    bind_result.add_argument("--attempt-id", required=True)
    bind_result.add_argument("--batch-id", required=True)
    bind_result.add_argument("--native-run-id", required=True)
    bind_result.add_argument("--session", type=Path, required=True)
    bind_result.add_argument("--parent-status", choices=("success", "failure"), required=True)
    finalize = sub.add_parser("finalize-attempt")
    finalize.add_argument("--ledger-root", type=Path, required=True)
    finalize.add_argument("--execution-root", type=Path, required=True)
    finalize.add_argument("--attempt-id", required=True)
    audit = sub.add_parser("audit-session")
    audit.add_argument("--ledger-root", type=Path, required=True)
    audit.add_argument("--execution-root", type=Path, required=True)
    audit.add_argument("--attempt-id", required=True)
    reconcile_parser = sub.add_parser("reconcile")
    reconcile_parser.add_argument("--ledger-root", type=Path, required=True)
    reconcile_parser.add_argument("--execution-root", type=Path, required=True)
    validate = sub.add_parser("validate-ledger")
    validate.add_argument("--ledger-root", type=Path, required=True)
    broker = sub.add_parser("serve-broker", help=argparse.SUPPRESS)
    broker.add_argument("--socket", type=Path, required=True)
    broker.add_argument("--binding", type=Path, required=True)
    broker.add_argument("--deadline-unix-ms", type=int, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = args.root
    if args.command == "attest-runtime":
        result = attest_runtime(
            root,
            args.campaign,
            args.bindings,
            args.cache,
            args.ledger_root,
            args.packets,
            args.execution_root,
        )
    elif args.command == "create-native-agent":
        result = create_native_agent(root, args.execution_root, args.output)
    elif args.command == "authorize-canary":
        result = authorize_canary(
            root,
            args.campaign,
            args.bindings,
            args.cache,
            args.ledger_root,
            args.packets,
            args.execution_root,
            ranks=args.ranks,
            lanes=args.lanes,
        )
    elif args.command == "prepare-attempt":
        result = prepare_attempt(
            root,
            args.campaign,
            args.bindings,
            args.cache,
            args.ledger_root,
            args.packets,
            args.execution_root,
            rank=args.rank,
            lane=args.lane,
            attempt_id=args.attempt_id,
        )
    elif args.command == "native-launch-plan":
        result = native_launch_plan(root, args.ledger_root, args.execution_root, args.attempt_id)
    elif args.command == "bind-native-result":
        result = bind_native_result(
            root,
            args.ledger_root,
            args.execution_root,
            args.attempt_id,
            args.batch_id,
            args.native_run_id,
            args.session,
            args.parent_status,
        )
    elif args.command == "finalize-attempt":
        result = finalize_attempt(root, args.ledger_root, args.execution_root, args.attempt_id)
    elif args.command == "audit-session":
        result = audit_session(
            root,
            args.ledger_root,
            args.execution_root,
            args.attempt_id,
        )
    elif args.command == "reconcile":
        result = reconcile(root, args.ledger_root, args.execution_root)
    elif args.command == "validate-ledger":
        result = validate_runtime_ledger(args.ledger_root, root)
    elif args.command == "serve-broker":
        return serve_broker(args.socket, args.binding, args.deadline_unix_ms)
    else:  # pragma: no cover
        _fail("unsupported command")
    print(canonical_json(result).decode())
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
