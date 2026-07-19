#!/usr/bin/env python3
"""Custody and native launch plans for production-v1 blind reviews.

This module may start only the deterministic local submission broker. It never
starts Pi, a model, or a provider process. Native model launches are emitted as
data for the supervisor-owned native subagent tool.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
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
import tempfile
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
    from collections.abc import Iterator, Sequence

_PROFILE: Final = "benchmarks/real_world/production_v1"
_RUNTIME_POLICY: Final = f"{_PROFILE}/runtime-policy-v1.json"
_RUNTIME_MIGRATION_CHECKSUMS: Final = f"{_PROFILE}/checksums-runtime-migration-v1.json"
_RUNTIME_REPAIR_CHECKSUMS: Final = f"{_PROFILE}/checksums-runtime-repair-v1.json"
_FINAL_RECOVERY_CHECKSUMS: Final = f"{_PROFILE}/checksums-final-prelaunch-recovery-v1.json"
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
_BROKER_READY_SECONDS: Final = 900
_MAX_FILE: Final = 64 * 1024 * 1024
_MAX_SESSION: Final = 64 * 1024 * 1024
_MAX_RSS: Final = 4 * 1024 * 1024 * 1024
_MAX_OUTPUT: Final = 2 * 1024 * 1024
_RUNTIME_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_ATTEMPT = re.compile(r"^prod-v1-i[0-9]{3}-rank[0-9]{3}-pr[0-9]+-[AB]$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ZERO_HASH: Final = "sha256:" + "0" * 64
_EVENT_FILE = re.compile(
    r"^([0-9]{6})-(prepared|launch_claimed|native_result|pending|completed|operational_failed|prelaunch_migration|runtime_migrated|runtime_migrated_repair|canary_reauthorized|canary_prelaunch_recovery|canary_final_prelaunch_recovery)-([A-Za-z0-9_-]+)\.json$"
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
_MIGRATION_PROTOCOL: Final = "ground-truth-prelaunch-custody-migration-v1"
_MIGRATION_RUNTIME_PROTOCOL: Final = "ground-truth-runtime-attestation-migration-v1"
_MIGRATED_AUTH_PROTOCOL: Final = "ground-truth-review-canary-authorization-generation2-v1"
_MIGRATION_REPAIR_PROTOCOL: Final = "ground-truth-runtime-attestation-migration-repair-v1"
_PRELAUNCH_RECOVERY_PROTOCOL: Final = "ground-truth-review-canary-prelaunch-recovery-v1"
_FINAL_PRELAUNCH_RECOVERY_PROTOCOL: Final = "ground-truth-review-canary-final-prelaunch-recovery-v1"
_MIGRATION_DOMAIN: Final = b"ground-truth-prelaunch-custody-migration-v1\0"
_MIGRATION_RUNTIME_DOMAIN: Final = b"ground-truth-runtime-attestation-migration-v1\0"
_MIGRATED_AUTH_DOMAIN: Final = b"ground-truth-review-canary-authorization-generation2-v1\0"
_MIGRATION_REPAIR_DOMAIN: Final = b"ground-truth-runtime-attestation-migration-repair-v1\0"
_PRELAUNCH_RECOVERY_DOMAIN: Final = b"ground-truth-review-canary-prelaunch-recovery-v1\0"
_FINAL_PRELAUNCH_RECOVERY_DOMAIN: Final = (
    b"ground-truth-review-canary-final-prelaunch-recovery-v1\0"
)


class GroundTruthRunError(RuntimeError):
    """Fail-closed native runtime error."""


class _LaneAuthorityChanged(GroundTruthRunError):
    """Raised when a prepare attempt crosses an authorization generation."""


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
    try:
        submit_v1._atomic_no_clobber(path, canonical_json(value), mode=mode)
    except submit_v1.SubmissionRejected as exc:
        raise GroundTruthRunError(f"publication already exists: {path.name}") from exc


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


def _custody_receipt_payload(
    campaign_path: Path,
    campaign: dict[str, Any],
    campaign_raw: bytes,
    bindings: Path,
    cache: Path,
    ledger: Path,
    packets: Path,
    custody: dict[str, Any],
    profile: submit_v1.ProfileSnapshot,
    source_inventory: dict[str, Any],
    packet_inventory: dict[str, Any],
) -> dict[str, Any]:
    source_value, source_raw, _ = source_v1._read_json(bindings, modes={0o400})
    cache_summary = source_value.get("cache")
    aggregate, aggregate_raw, _ = packet_v1._json(
        packets / "aggregate-manifest.json", modes={0o400}
    )
    cache_status = cache.stat(follow_symlinks=False)
    packet_status = packets.stat(follow_symlinks=False)
    if not isinstance(cache_summary, dict) or _sha(source_raw) != custody["source"]["sha256"]:
        _fail("source binding changed around custody receipt")
    return {
        "schema_version": 1,
        "protocol": "ground-truth-runtime-custody-receipt-v1",
        "campaign_id": campaign["id"],
        "campaign_path": str(campaign_path),
        "campaign_manifest_sha256": _sha(campaign_raw),
        "source_bindings_path": str(bindings),
        "source_bindings_sha256": _sha(source_raw),
        "cache": {
            "cache_root": str(cache),
            "cache_device": cache_status.st_dev,
            "cache_inode": cache_status.st_ino,
            "inventory_sha256": source_inventory["inventory_sha256"],
            "inventory_path_count": source_inventory["inventory_path_count"],
            "file_count": source_inventory["file_count"],
            "disk_bytes": source_inventory["disk_bytes"],
            "content_sha256": cache_summary["content_sha256"],
        },
        "ledger_root": str(ledger),
        "packets": {
            "packets_root": str(packets),
            "packets_device": packet_status.st_dev,
            "packets_inode": packet_status.st_ino,
            "inventory_sha256": packet_inventory["sha256"],
            "inventory_entries": packet_inventory["entries"],
            "inventory_bytes": packet_inventory["bytes"],
            "aggregate_manifest_sha256": _sha(aggregate_raw),
            "aggregate_root_sha256": aggregate["aggregate_root_sha256"],
            "publication_entry_hash": custody["packet"]["publication_entry_hash"],
            "packet_count": 50,
        },
        "production_profile_sha256": profile.checksum_sha256,
        "production_files_sha256": profile.files_sha256,
        "authorizations": {
            "review_launch": False,
            "adjudication": False,
            "canonical_import": False,
        },
    }


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
        "prelaunch_migration": {
            "prior_runtime_entry_hash",
            "prior_execution_root",
            "prior_execution_device",
            "prior_execution_inode",
            "prior_authorization_entry_hash",
            "prior_events_sha256",
            "prior_event_count",
            "campaign_manifest_sha256",
            "source_bindings_sha256",
            "packet_publication_entry_hash",
            "production_profile_sha256",
            "attempt_ids",
            "model_launch_count",
            "migrated_at",
            "authorizations",
        },
        "runtime_migrated": {
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
            "supersedes_entry_hash",
            "migration_entry_hash",
        },
        "runtime_migrated_repair": {
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
            "supersedes_entry_hash",
            "migration_entry_hash",
            "bad_execution_root",
            "bad_production_profile_sha256",
            "bad_agent_source_sha256",
        },
        "canary_reauthorized": {
            "campaign_id",
            "campaign_manifest_sha256",
            "runtime_attestation_entry_hash",
            "agent_installation_sha256",
            "production_profile_sha256",
            "lanes",
            "attempt_ids",
            "limits",
            "issued_at",
            "expires_at",
            "authorizations",
            "migration_entry_hash",
            "generation",
        },
        "canary_prelaunch_recovery": {
            "campaign_id",
            "campaign_manifest_sha256",
            "runtime_attestation_entry_hash",
            "prior_authorization_entry_hash",
            "agent_installation_sha256",
            "production_profile_sha256",
            "lanes",
            "attempt_ids",
            "failed_attempt_id",
            "prepared_entry_hash",
            "failure_entry_hash",
            "prior_events_sha256",
            "prior_event_count",
            "archive_path",
            "archive_device",
            "archive_inode",
            "archive_inventory_sha256",
            "archive_entries",
            "archive_bytes",
            "binding_sha256",
            "broker_pid",
            "broker_start_identity",
            "broker_stdout_sha256",
            "broker_stdout_bytes",
            "broker_stderr_sha256",
            "broker_stderr_bytes",
            "limits",
            "model_launch_count",
            "issued_at",
            "expires_at",
            "recovered_at",
            "authorizations",
            "generation",
        },
        "canary_final_prelaunch_recovery": {
            "campaign_id",
            "campaign_manifest_sha256",
            "runtime_attestation_entry_hash",
            "prior_authorization_entry_hash",
            "agent_installation_sha256",
            "production_profile_sha256",
            "lanes",
            "attempt_ids",
            "failed_attempt_id",
            "prepared_entry_hash",
            "failure_entry_hash",
            "prior_events_sha256",
            "prior_event_count",
            "archive_path",
            "archive_device",
            "archive_inode",
            "archive_inventory_sha256",
            "archive_entries",
            "archive_bytes",
            "binding_sha256",
            "broker_pid",
            "broker_start_identity",
            "broker_stdout_sha256",
            "broker_stdout_bytes",
            "broker_stderr_sha256",
            "broker_stderr_bytes",
            "limits",
            "model_launch_count",
            "issued_at",
            "expires_at",
            "recovered_at",
            "authorizations",
            "generation",
        },
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
    current_profile_sha256: str,
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
    del current_profile_sha256
    receipt_version = value.get("schema_version") == 2
    if receipt_version:
        expected_keys.update({"runtime_custody_receipt_path", "runtime_custody_receipt_sha256"})
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
        or value["schema_version"] not in {1, 2}
        or value["protocol"] != protocol
        or value["campaign_id"] != base["campaign_id"]
        or value["campaign_manifest_sha256"] != base["campaign_manifest_sha256"]
        or value["campaign_lanes_sha256"] != base["campaign_canary_lanes_sha256"]
        or value["packet_publication_entry_hash"] != base["packet_publication_entry_hash"]
        or (
            receipt_version
            and (
                not isinstance(value.get("runtime_custody_receipt_path"), str)
                or not Path(cast("str", value["runtime_custody_receipt_path"])).is_absolute()
                or not _DIGEST.fullmatch(str(value.get("runtime_custody_receipt_sha256", "")))
            )
        )
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


def _rename_directory_noreplace(source: Path, target: Path) -> None:
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
    if renameat2(-100, os.fsencode(source), -100, os.fsencode(target), 1) != 0:
        error = ctypes.get_errno()
        raise GroundTruthRunError(f"prelaunch archive rename failed: {os.strerror(error)}")


def _native_state_at(path: Path, attempt_id: str) -> dict[str, Any]:
    if not _ATTEMPT.fullmatch(attempt_id):
        _fail("attempt id is invalid")
    value, raw = _json_raw(path, modes={0o400})
    state_keys = {
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
    }
    if "generation" in value:
        state_keys.add("generation")
    _strict_keys(value, state_keys, "native state")
    if (
        canonical_json(value) != raw
        or value["schema_version"] != 1
        or value.get("generation", 1) not in {1, 2, 3, 4}
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


def _require_no_live_broker_for_binding(binding: Path) -> None:
    needle = os.fsencode(str(binding))
    for process in Path("/proc").iterdir():
        if not process.name.isdigit():
            continue
        try:
            status = process.stat(follow_symlinks=False)
            if status.st_uid != os.getuid():
                continue
            command = (process / "cmdline").read_bytes().split(b"\0")
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if (
            needle in command
            and b"serve-broker" in command
            and any(part.endswith(b"ground_truth_run_v1.py") or part == b"-m" for part in command)
        ):
            _fail("pre-readiness broker process is still alive")


def _recovery_archive_summary(
    path: Path,
    attempt_id: str,
    *,
    allow_missing_state: bool = False,
    historical_replay: bool = False,
) -> dict[str, Any]:
    status = _private_directory(path)
    expected_entries = {"binding.json", "escrow", "logs", "packet"}
    state_path = path / "native-state.json"
    if state_path.exists():
        expected_entries.add("native-state.json")
    elif not allow_missing_state:
        _fail("prelaunch recovery native state is absent")
    if {item.name for item in path.iterdir()} != expected_entries:
        _fail("prelaunch recovery archive inventory is not exact")
    escrow = path / "escrow"
    logs = path / "logs"
    _private_directory(escrow)
    _private_directory(logs)
    if any(escrow.iterdir()) or {item.name for item in logs.iterdir()} != {
        "broker.stderr",
        "broker.stdout",
    }:
        _fail("prelaunch recovery archive escrow or logs are invalid")
    packet_status = (path / "packet").stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(packet_status.st_mode)
        or packet_status.st_uid != os.getuid()
        or stat.S_IMODE(packet_status.st_mode) != 0o500
    ):
        _fail("prelaunch recovery packet identity is invalid")
    binding_raw = submit_v1._owned_file(
        path / "binding.json", max_bytes=_MAX_FILE, allowed_modes={0o400}
    )
    if state_path.exists():
        state = _native_state_at(state_path, attempt_id)
        socket_path = Path(cast("str", state["socket"]))
        registry_path = Path(cast("str", state["registry"]))
        if (
            not isinstance(state["broker_pid"], int)
            or state["broker_pid"] <= 0
            or not isinstance(state["broker_start_identity"], str)
            or (
                not historical_replay
                and (
                    _same_process(state["broker_pid"], state["broker_start_identity"])
                    or socket_path.exists()
                    or socket_path.is_symlink()
                    or registry_path.exists()
                    or registry_path.is_symlink()
                )
            )
        ):
            _fail("prelaunch recovery broker is not exactly dead")
    else:
        binding_path = path / "binding.json"
        if not historical_replay:
            _require_no_live_broker_for_binding(binding_path)
        runtime_root = Path(f"/tmp/ground-truth-review-v1-{os.getuid()}")
        socket_path = (
            runtime_root
            / "sockets"
            / (hashlib.sha256(attempt_id.encode()).hexdigest()[:24] + ".sock")
        )
        packet_identity = (path / "packet").stat(follow_symlinks=False)
        registry_path = (
            runtime_root
            / "registry"
            / (
                hashlib.sha256(
                    f"{packet_identity.st_dev}:{packet_identity.st_ino}".encode()
                ).hexdigest()
                + ".json"
            )
        )
        if not historical_replay and (
            socket_path.exists()
            or socket_path.is_symlink()
            or registry_path.exists()
            or registry_path.is_symlink()
        ):
            _fail("pre-readiness broker socket or registry remains")
        state = {"broker_pid": 0, "broker_start_identity": "pre-readiness-unpublished"}
    stdout = submit_v1._owned_file(
        logs / "broker.stdout", max_bytes=_MAX_FILE, allowed_modes={0o600}
    )
    stderr = submit_v1._owned_file(
        logs / "broker.stderr", max_bytes=_MAX_FILE, allowed_modes={0o600}
    )
    inventory = packet_v1._inventory(
        path,
        limit=packet_v1._MAX_AGGREGATE_PAYLOAD,
        max_entries=packet_v1._MAX_AGGREGATE_ENTRIES,
    )
    return {
        "archive_device": status.st_dev,
        "archive_inode": status.st_ino,
        "archive_inventory_sha256": inventory["sha256"],
        "archive_entries": inventory["entries"],
        "archive_bytes": inventory["bytes"],
        "binding_sha256": _sha(binding_raw),
        "broker_pid": state["broker_pid"],
        "broker_start_identity": state["broker_start_identity"],
        "broker_stdout_sha256": _sha(stdout),
        "broker_stdout_bytes": len(stdout),
        "broker_stderr_sha256": _sha(stderr),
        "broker_stderr_bytes": len(stderr),
    }


def _final_recovery_profile_identity(root: Path) -> tuple[str, str]:
    current = _profile(root)
    try:
        raw = current.files[_FINAL_RECOVERY_CHECKSUMS]
        expected = current.digests[_FINAL_RECOVERY_CHECKSUMS]
    except KeyError as exc:
        raise GroundTruthRunError(
            "final recovery profile is not current-profile authenticated"
        ) from exc
    value = submit_v1._strict_json(raw, "final prelaunch recovery checksum profile")
    files = value.get("files")
    if (
        _sha(raw) != expected
        or not isinstance(files, dict)
        or not files
        or any(
            not isinstance(relative, str)
            or not isinstance(digest, str)
            or not _DIGEST.fullmatch(digest)
            for relative, digest in files.items()
        )
    ):
        _fail("final recovery profile is invalid")
    return _sha(raw), _sha(canonical_json(dict(sorted(files.items()))))


def _validate_final_recovery_binding(
    root: Path,
    archive: Path,
    attempt_id: str,
    runtime_entry_hash: str,
    binding_sha256: str,
) -> None:
    binding = archive / "binding.json"
    raw_before = submit_v1._owned_file(binding, max_bytes=_MAX_FILE, allowed_modes={0o400})
    try:
        document = submit_v1.SubmissionBindings.model_validate_json(raw_before)
        canonical = canonical_json(document.model_dump(mode="json"))
        if len(document.records) != 1:
            _fail("final prelaunch recovery binding document cardinality is invalid")
        record = document.records[0]
    except (ValueError, TypeError, UnicodeError, RecursionError, MemoryError) as exc:
        raise GroundTruthRunError("final prelaunch recovery binding is invalid") from exc
    raw_after = submit_v1._owned_file(binding, max_bytes=_MAX_FILE, allowed_modes={0o400})
    profile_checksum, profile_files = _final_recovery_profile_identity(root)
    if (
        raw_before != raw_after
        or canonical != raw_after
        or record.generation != 3
        or record.attempt_id != attempt_id
        or record.runtime_attestation_entry_hash != runtime_entry_hash
        or record.profile_checksum_sha256 != profile_checksum
        or record.profile_files_sha256 != profile_files
        or _sha(raw_after) != binding_sha256
    ):
        _fail("final prelaunch recovery binding is not the exact generation3 lane")


def _extended_ledger(root: Path, repository_root: Path) -> dict[str, Any]:  # noqa: PLR0912,PLR0915
    base = campaign_v1._validate_ledger_unlocked(root, repository_root)
    if not base.get("packet_publication_present"):
        _fail("runtime requires packet publication")
    head = cast("str", base["entry_hash"])
    current_profile_sha256 = _profile(repository_root).checksum_sha256
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
            current_profile_sha256,
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
            current_profile_sha256,
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
    migration: dict[str, Any] | None = None
    repair: dict[str, Any] | None = None
    prelaunch_recovery: dict[str, Any] | None = None
    final_prelaunch_recovery: dict[str, Any] | None = None
    generation = 1
    generation2_attempts: set[str] = set()
    generation3_attempts: set[str] = set()
    generation4_attempts: set[str] = set()
    launched_attempts: set[str] = set()
    if events_dir.exists():
        _private_directory(events_dir)
        paths = sorted(events_dir.iterdir(), key=lambda item: item.name)
        for expected_sequence, path in enumerate(paths, 1):
            match = _EVENT_FILE.fullmatch(path.name)
            if match is None or int(match.group(1)) != expected_sequence:
                _fail("lane event sequence is invalid")
            event, raw = _json_raw(path, modes={0o400})
            kind = cast("str", event.get("kind"))
            expected_event_keys = _event_expected_keys(kind)
            if kind not in {
                "canary_reauthorized",
                "canary_prelaunch_recovery",
                "canary_final_prelaunch_recovery",
            } and event.get("generation") in {2, 3, 4}:
                expected_event_keys.add("generation")
            _strict_keys(event, expected_event_keys, "lane event")
            body = {key: value for key, value in event.items() if key != "entry_hash"}
            identifier = match.group(3)
            special = {
                "prelaunch_migration": (_MIGRATION_PROTOCOL, _MIGRATION_DOMAIN),
                "runtime_migrated": (_MIGRATION_RUNTIME_PROTOCOL, _MIGRATION_RUNTIME_DOMAIN),
                "runtime_migrated_repair": (
                    _MIGRATION_REPAIR_PROTOCOL,
                    _MIGRATION_REPAIR_DOMAIN,
                ),
                "canary_reauthorized": (_MIGRATED_AUTH_PROTOCOL, _MIGRATED_AUTH_DOMAIN),
                "canary_prelaunch_recovery": (
                    _PRELAUNCH_RECOVERY_PROTOCOL,
                    _PRELAUNCH_RECOVERY_DOMAIN,
                ),
                "canary_final_prelaunch_recovery": (
                    _FINAL_PRELAUNCH_RECOVERY_PROTOCOL,
                    _FINAL_PRELAUNCH_RECOVERY_DOMAIN,
                ),
            }
            event_protocol, event_domain = special.get(
                kind, ("ground-truth-review-lane-event-v1", b"ground-truth-review-lane-event-v1\0")
            )
            if (
                canonical_json(event) != raw
                or event["schema_version"]
                not in ({2} if kind in {"runtime_migrated", "runtime_migrated_repair"} else {1})
                or event["protocol"] != event_protocol
                or event["sequence"] != expected_sequence
                or event["kind"] != match.group(2)
                or event["previous_hash"] != head
                or event["entry_hash"] != _entry_hash(event_domain, body)
            ):
                _fail("lane event hash chain is invalid")
            if (
                kind
                in {
                    "prepared",
                    "launch_claimed",
                    "native_result",
                    "pending",
                    "completed",
                    "operational_failed",
                }
                and event.get("generation", 1) != generation
            ):
                _fail("lane event generation is invalid")
            if kind == "prelaunch_migration":
                attempts = sorted(authorized)
                prior_kinds = {
                    attempt: [row["kind"] for row in events if row.get("attempt_id") == attempt]
                    for attempt in attempts
                }
                if (
                    identifier != "prelaunch"
                    or migration is not None
                    or runtime is None
                    or runtime.get("schema_version") != 1
                    or runtime_superseded
                    or authorization is None
                    or attempts != sorted(event["attempt_ids"])
                    or any(states.get(item) != "operational_failed" for item in attempts)
                    or any(
                        prior_kinds[item] != ["prepared", "operational_failed"] for item in attempts
                    )
                    or launched_attempts
                    or native_results
                    or pending_events
                    or event["prior_runtime_entry_hash"] != runtime["entry_hash"]
                    or event["prior_execution_root"] != runtime["execution_root"]
                    or event["prior_execution_device"] != runtime["execution_device"]
                    or event["prior_execution_inode"] != runtime["execution_inode"]
                    or event["prior_authorization_entry_hash"] != authorization["entry_hash"]
                    or event["prior_events_sha256"] != _sha(canonical_json(events))
                    or event["prior_event_count"] != len(events)
                    or event["campaign_manifest_sha256"] != base["campaign_manifest_sha256"]
                    or event["source_bindings_sha256"] != runtime["source_bindings_sha256"]
                    or not _DIGEST.fullmatch(str(event["production_profile_sha256"]))
                    or event["packet_publication_entry_hash"]
                    != base["packet_publication_entry_hash"]
                    or event["model_launch_count"] != 0
                    or event["authorizations"]
                    != {"review_launch": False, "adjudication": False, "canonical_import": False}
                ):
                    _fail("prelaunch custody migration is invalid")
                _parse_timestamp(event["migrated_at"])
                migration = event
                authorization = None
                authorized = set()
                authorized_rows = {}
            elif kind == "runtime_migrated":
                if identifier != "runtime":
                    _fail("migrated runtime attestation identifier is invalid")
                _validate_migrated_event_candidate(
                    {
                        "events": events,
                        "head": head,
                        "migration": migration,
                        "generation": generation,
                        "runtime": runtime,
                        "authorization": authorization,
                        "base": base,
                    },
                    event,
                )
                runtime = event
                runtime_entry_hash = event["entry_hash"]
            elif kind == "runtime_migrated_repair":
                if identifier != "runtime-repair" or repair is not None:
                    _fail("migrated runtime repair identifier is invalid")
                _validate_repaired_event_candidate(
                    {
                        "events": events,
                        "head": head,
                        "migration": migration,
                        "generation": generation,
                        "runtime": runtime,
                        "authorization": authorization,
                        "base": base,
                    },
                    event,
                )
                repair = event
                runtime = event
                runtime_entry_hash = event["entry_hash"]
            elif kind == "canary_reauthorized":
                if (
                    identifier != "canary"
                    or migration is None
                    or generation != 1
                    or authorization is not None
                    or runtime is None
                    or runtime.get("kind") not in {"runtime_migrated", "runtime_migrated_repair"}
                    or event["generation"] != 2
                    or event["migration_entry_hash"] != migration["entry_hash"]
                    or event["runtime_attestation_entry_hash"] != runtime["entry_hash"]
                    or event["production_profile_sha256"] != runtime["production_profile_sha256"]
                    or not _DIGEST.fullmatch(str(event["agent_installation_sha256"]))
                    or event["campaign_id"] != base["campaign_id"]
                    or event["campaign_manifest_sha256"] != base["campaign_manifest_sha256"]
                    or event["lanes"] != base["campaign_canary_lanes"]
                    or event["limits"]
                    != {
                        "max_global_active": 3,
                        "max_processes_per_lane": 1,
                        "replacement_attempts": 0,
                    }
                    or event["authorizations"]
                    != {"review_launch": True, "adjudication": False, "canonical_import": False}
                    or any(
                        states.get(item) != "operational_failed" for item in event["attempt_ids"]
                    )
                    or set(event["attempt_ids"]) != _authorized_attempts(event)
                    or any(item in launched_attempts for item in event["attempt_ids"])
                ):
                    _fail("migrated canary authorization is invalid")
                issued = _parse_timestamp(event["issued_at"])
                expires = _parse_timestamp(event["expires_at"])
                if expires - issued != timedelta(hours=24):
                    _fail("migrated canary interval is invalid")
                authorization = event
                authorized = _authorized_attempts(event)
                authorized_rows = {row["attempt_id"]: row for row in event["lanes"]}
                generation2_attempts.update(authorized)
                for attempt in authorized:
                    states[attempt] = "authorized"
                generation = 2
            elif kind == "canary_prelaunch_recovery":
                if not isinstance(runtime, dict):
                    _fail("generation3 prelaunch recovery lacks runtime")
                failed = event["failed_attempt_id"]
                failed_rows = [row for row in events if row.get("attempt_id") == failed]
                generation2_failed_rows = [row for row in failed_rows if row.get("generation") == 2]
                pre_readiness_failure = [row["kind"] for row in generation2_failed_rows] == [
                    "operational_failed"
                ] and generation2_failed_rows[-1].get("reason") == "broker failed before readiness"
                post_readiness_failure = [row["kind"] for row in generation2_failed_rows] == [
                    "prepared",
                    "operational_failed",
                ] and generation2_failed_rows[-1].get("reason") == "never-launched broker exited"
                operational = [
                    item for item, state in states.items() if state == "operational_failed"
                ]
                archive = Path(cast("str", event["archive_path"]))
                expected_archive = (
                    Path(cast("str", runtime["execution_root"]))
                    / "prelaunch-failures"
                    / "generation2"
                    / failed
                )
                if archive != expected_archive:
                    _fail("generation3 prelaunch recovery archive path is invalid")
                summary = _recovery_archive_summary(
                    archive,
                    failed,
                    allow_missing_state=event["prepared_entry_hash"] == _ZERO_HASH,
                    historical_replay=True,
                )
                if (
                    identifier != "canary-recovery"
                    or prelaunch_recovery is not None
                    or generation != 2
                    or migration is None
                    or runtime is None
                    or runtime.get("kind") != "runtime_migrated_repair"
                    or authorization is None
                    or authorization.get("kind") != "canary_reauthorized"
                    or event["generation"] != 3
                    or event["runtime_attestation_entry_hash"] != runtime["entry_hash"]
                    or event["prior_authorization_entry_hash"] != authorization["entry_hash"]
                    or event["campaign_id"] != base["campaign_id"]
                    or event["campaign_manifest_sha256"] != base["campaign_manifest_sha256"]
                    or event["production_profile_sha256"] != runtime["production_profile_sha256"]
                    or event["agent_installation_sha256"]
                    != authorization["agent_installation_sha256"]
                    or event["lanes"] != base["campaign_canary_lanes"]
                    or event["attempt_ids"] != sorted(authorized)
                    or set(event["attempt_ids"]) != _authorized_attempts(event)
                    or operational != [failed]
                    or states.get(failed) != "operational_failed"
                    or any(
                        states.get(item) != "authorized" for item in authorized if item != failed
                    )
                    or not (pre_readiness_failure or post_readiness_failure)
                    or generation2_failed_rows[-1].get("relaunch_authorized") is not False
                    or event["prepared_entry_hash"]
                    != (
                        generation2_failed_rows[0]["entry_hash"]
                        if post_readiness_failure
                        else _ZERO_HASH
                    )
                    or event["failure_entry_hash"] != generation2_failed_rows[-1]["entry_hash"]
                    or event["prior_events_sha256"] != _sha(canonical_json(events))
                    or event["prior_event_count"] != len(events)
                    or launched_attempts
                    or native_results
                    or pending_events
                    or event["model_launch_count"] != 0
                    or any(event[key] != summary[key] for key in summary)
                    or (
                        post_readiness_failure
                        and (
                            event["binding_sha256"] != generation2_failed_rows[0]["binding_sha256"]
                            or event["broker_pid"] != generation2_failed_rows[0]["broker_pid"]
                            or event["broker_start_identity"]
                            != generation2_failed_rows[0]["broker_start_identity"]
                        )
                    )
                    or event["limits"]
                    != {
                        "max_global_active": 3,
                        "max_processes_per_lane": 1,
                        "replacement_attempts": 0,
                    }
                    or event["authorizations"]
                    != {"review_launch": True, "adjudication": False, "canonical_import": False}
                ):
                    _fail("generation3 prelaunch recovery is invalid")
                issued = _parse_timestamp(event["issued_at"])
                expires = _parse_timestamp(event["expires_at"])
                recovered_at = _parse_timestamp(event["recovered_at"])
                if expires - issued != timedelta(hours=24) or not issued <= recovered_at <= expires:
                    _fail("generation3 prelaunch recovery interval is invalid")
                authorization = event
                authorized = _authorized_attempts(event)
                authorized_rows = {row["attempt_id"]: row for row in event["lanes"]}
                generation3_attempts.update(authorized)
                for attempt in authorized:
                    states[attempt] = "authorized"
                prelaunch_recovery = event
                generation = 3
            elif kind == "canary_final_prelaunch_recovery":
                if not isinstance(runtime, dict):
                    _fail("generation4 final prelaunch recovery lacks runtime")
                failed = event["failed_attempt_id"]
                generation3_rows = [
                    row
                    for row in events
                    if row.get("attempt_id") == failed and row.get("generation") == 3
                ]
                pre_readiness_failure = [row["kind"] for row in generation3_rows] == [
                    "operational_failed"
                ] and generation3_rows[-1].get("reason") == "broker failed before readiness"
                operational = [
                    item for item, state in states.items() if state == "operational_failed"
                ]
                archive = Path(cast("str", event["archive_path"]))
                expected_archive = (
                    Path(cast("str", runtime["execution_root"]))
                    / "prelaunch-failures"
                    / "generation3"
                    / failed
                )
                if archive != expected_archive:
                    _fail("generation4 final prelaunch recovery archive path is invalid")
                summary = _recovery_archive_summary(
                    archive,
                    failed,
                    allow_missing_state=True,
                    historical_replay=True,
                )
                _validate_final_recovery_binding(
                    repository_root,
                    archive,
                    failed,
                    cast("str", runtime["entry_hash"]),
                    summary["binding_sha256"],
                )
                if (
                    identifier != "canary-final-recovery"
                    or final_prelaunch_recovery is not None
                    or generation != 3
                    or prelaunch_recovery is None
                    or runtime.get("kind") != "runtime_migrated_repair"
                    or authorization is None
                    or authorization.get("kind") != "canary_prelaunch_recovery"
                    or event["generation"] != 4
                    or event["runtime_attestation_entry_hash"] != runtime["entry_hash"]
                    or event["prior_authorization_entry_hash"] != authorization["entry_hash"]
                    or event["campaign_id"] != base["campaign_id"]
                    or event["campaign_manifest_sha256"] != base["campaign_manifest_sha256"]
                    or event["production_profile_sha256"] != runtime["production_profile_sha256"]
                    or event["agent_installation_sha256"]
                    != authorization["agent_installation_sha256"]
                    or event["lanes"] != base["campaign_canary_lanes"]
                    or event["attempt_ids"] != sorted(authorized)
                    or set(event["attempt_ids"]) != _authorized_attempts(event)
                    or operational != [failed]
                    or states.get(failed) != "operational_failed"
                    or any(
                        states.get(item) != "authorized" for item in authorized if item != failed
                    )
                    or not pre_readiness_failure
                    or generation3_rows[-1].get("relaunch_authorized") is not False
                    or event["prepared_entry_hash"] != _ZERO_HASH
                    or event["failure_entry_hash"] != generation3_rows[-1]["entry_hash"]
                    or event["prior_events_sha256"] != _sha(canonical_json(events))
                    or event["prior_event_count"] != len(events)
                    or launched_attempts
                    or native_results
                    or pending_events
                    or event["model_launch_count"] != 0
                    or any(event[key] != summary[key] for key in summary)
                    or event["broker_pid"] != 0
                    or event["broker_start_identity"] != "pre-readiness-unpublished"
                    or event["limits"]
                    != {
                        "max_global_active": 3,
                        "max_processes_per_lane": 1,
                        "replacement_attempts": 0,
                    }
                    or event["authorizations"]
                    != {"review_launch": True, "adjudication": False, "canonical_import": False}
                ):
                    _fail("generation4 final prelaunch recovery is invalid")
                issued = _parse_timestamp(event["issued_at"])
                expires = _parse_timestamp(event["expires_at"])
                recovered_at = _parse_timestamp(event["recovered_at"])
                if expires - issued != timedelta(hours=24) or not issued <= recovered_at <= expires:
                    _fail("generation4 final prelaunch recovery interval is invalid")
                authorization = event
                authorized = _authorized_attempts(event)
                authorized_rows = {row["attempt_id"]: row for row in event["lanes"]}
                generation4_attempts.update(authorized)
                for attempt in authorized:
                    states[attempt] = "authorized"
                final_prelaunch_recovery = event
                generation = 4
            elif kind == "launch_claimed":
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
                    launched_attempts.add(attempt)
                    states[attempt] = "launch_claimed"
            else:
                attempt = event["attempt_id"]
                if identifier != attempt or attempt not in authorized:
                    _fail("lane event is outside exact authorization")
                previous = states.get(attempt)
                if kind == "prepared":
                    if (
                        (generation == 1 and previous is not None)
                        or (generation in {2, 3, 4} and previous != "authorized")
                        or event.get("generation", 1) != generation
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
                        not in {
                            None,
                            "authorized",
                            "prepared",
                            "launch_claimed",
                            "native_bound",
                            "pending",
                        }
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
        "migration": migration,
        "repair": repair,
        "prelaunch_recovery": prelaunch_recovery,
        "final_prelaunch_recovery": final_prelaunch_recovery,
        "generation": generation,
        "generation2_attempts": generation2_attempts,
        "generation3_attempts": generation3_attempts,
        "generation4_attempts": generation4_attempts,
        "authorization": authorization,
        "events": events,
        "states": states,
        "batches": batches,
        "batch_events": batch_events,
        "batch_native_runs": batch_native_runs,
        "native_results": native_results,
        "launched_attempts": launched_attempts,
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


def _prepare_runtime_staging(execution_root: Path) -> Path:
    """Create an inert random sibling; crashed partial trees are never reused or deleted."""
    _private_directory(execution_root.parent)
    if execution_root.exists() or execution_root.is_symlink():
        _fail("migrated execution root already exists")
    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{execution_root.name}.runtime-staging-", dir=execution_root.parent
        )
    )
    status = _private_directory(staging)
    _atomic(
        staging / ".runtime-staging-owner.json",
        {
            "protocol": "ground-truth-runtime-staging-owner-v1",
            "final_root": str(execution_root),
            "device": status.st_dev,
            "inode": status.st_ino,
            "uid": os.getuid(),
        },
    )
    return staging


def _fsync_tree(root: Path) -> None:
    for directory, _names, filenames in os.walk(root, topdown=False, followlinks=False):
        base = Path(directory)
        for name in filenames:
            descriptor = os.open(base / name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        descriptor = os.open(base, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _migrated_candidate_files(root: Path, execution_root: Path, value: dict[str, Any]) -> None:
    status = _private_directory(execution_root)
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
    custody = submit_v1._owned_file(
        execution_root / "runtime/custody-receipt.json",
        max_bytes=_MAX_FILE,
        allowed_modes={0o400},
    )
    if (
        value.get("schema_version") != 2
        or value.get("kind") not in {"runtime_migrated", "runtime_migrated_repair"}
        or value.get("execution_root") != str(execution_root)
        or value.get("execution_device") != status.st_dev
        or value.get("execution_inode") != status.st_ino
        or value.get("runtime_custody_receipt_path")
        != str(execution_root / "runtime/custody-receipt.json")
        or value.get("runtime_custody_receipt_sha256") != _sha(custody)
        or value.get("production_profile_sha256") != profile.checksum_sha256
        or value.get("production_files_sha256") != profile.files_sha256
        or extension != profile.files[_EXTENSION]
        or extension_schema != profile.files[_EXTENSION_SCHEMA]
        or value.get("extension_sha256") != _sha(extension)
        or value.get("extension_schema_sha256") != _sha(extension_schema)
        or value.get("agent_source_sha256") != _sha(agent)
    ):
        _fail("migrated runtime candidate files are invalid")


def _validate_migration_roots(
    current: dict[str, Any], execution_root: Path, *, repair: bool = False
) -> None:
    migration = current.get("migration")
    if not isinstance(migration, dict):
        _fail("prelaunch migration is absent")
    prior = Path(cast("str", migration.get("prior_execution_root")))
    if execution_root == prior:
        _fail("migrated execution root must differ from preserved prior root")
    runtime = current.get("runtime")
    if repair:
        if not isinstance(runtime, dict) or runtime.get("kind") not in {
            "runtime_migrated",
            "runtime_migrated_repair",
        }:
            _fail("repair lacks a migrated runtime")
        bad_root = (
            runtime.get("execution_root")
            if runtime.get("kind") == "runtime_migrated"
            else runtime.get("bad_execution_root")
        )
        if execution_root == Path(cast("str", bad_root)):
            _fail("repaired execution root must differ from bad migrated root")
    status = _private_directory(prior)
    if status.st_dev != migration.get("prior_execution_device") or status.st_ino != migration.get(
        "prior_execution_inode"
    ):
        _fail("preserved prior execution root identity changed")


def _validate_repair_incident(  # noqa: PLR0912, PLR0915
    current: dict[str, Any],
) -> dict[str, Any]:
    migration = current.get("migration")
    bad = current.get("runtime")
    events = current.get("events")
    if (
        not isinstance(migration, dict)
        or not isinstance(bad, dict)
        or bad.get("kind") != "runtime_migrated"
        or current.get("generation") != 1
        or current.get("authorization") is not None
        or not isinstance(events, list)
        or not events
        or events[-1].get("entry_hash") != bad.get("entry_hash")
    ):
        _fail("runtime repair is outside the exact incident state")
    bad_root = Path(cast("str", bad.get("execution_root")))
    if _runtime_attestation(Path(__file__).resolve().parents[2], bad_root) != bad:
        _fail("bad migrated runtime local attestation changed")
    _private_directory(bad_root)
    if (bad_root / "agent-installation.json").exists():
        _fail("bad migrated runtime already has an installation receipt")
    if {path.name for path in bad_root.iterdir()} != {
        "prior-agent-source.md",
        "runtime",
        "runtime-attestation.json",
    }:
        _fail("bad migrated runtime inventory is not exact")
    runtime_dir = bad_root / "runtime"
    extension_dir = runtime_dir / "extension"
    if {path.name for path in runtime_dir.iterdir()} != {
        "agent-source.md",
        "custody-receipt.json",
        "extension",
    } or {path.name for path in extension_dir.iterdir()} != {"index.ts", "review-schema.ts"}:
        _fail("bad migrated runtime nested inventory is not exact")
    runtime_status = runtime_dir.stat(follow_symlinks=False)
    extension_status = extension_dir.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(runtime_status.st_mode)
        or runtime_status.st_uid != os.getuid()
        or stat.S_IMODE(runtime_status.st_mode) != 0o500
        or not stat.S_ISDIR(extension_status.st_mode)
        or extension_status.st_uid != os.getuid()
        or stat.S_IMODE(extension_status.st_mode) != 0o700
    ):
        _fail("bad migrated runtime nested identity changed")
    bad_body = submit_v1._owned_file(
        runtime_dir / "agent-source.md", max_bytes=_MAX_FILE, allowed_modes={0o400}
    )
    if _sha(bad_body) != bad.get("agent_source_sha256"):
        _fail("bad migrated agent source changed")
    marker = b"subagentOnlyExtensions:\n  - "
    if bad_body.count(marker) != 1:
        _fail("bad migrated agent extension marker is invalid")
    extension_raw = bad_body.split(marker, 1)[1].split(b"\n", 1)[0]
    try:
        bad_extension = Path(extension_raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise GroundTruthRunError("bad migrated extension path is invalid") from exc
    project_root = Path(__file__).resolve().parents[2]
    historical_files, _profile_hash, _files_hash = _historical_runtime_profile(
        project_root, cast("str", bad.get("production_profile_sha256"))
    )
    prompt = historical_files[f"{_PROFILE}/review-prompt-v1.md"].decode("utf-8")
    if bad_body != _agent_body(bad_extension, prompt):
        _fail("bad migrated agent body is not the exact staging-path incident")
    expected_prefix = f".{bad_root.name}.runtime-staging-"
    try:
        staging_root = bad_extension.parents[2]
    except IndexError as exc:
        raise GroundTruthRunError("bad migrated staging path is invalid") from exc
    if (
        not bad_extension.is_absolute()
        or bad_extension.name != "index.ts"
        or bad_extension.parent.name != "extension"
        or bad_extension.parent.parent.name != "runtime"
        or staging_root.parent != bad_root.parent
        or not staging_root.name.startswith(expected_prefix)
        or not re.fullmatch(r"[a-z0-9_]{8}", staging_root.name.removeprefix(expected_prefix))
        or staging_root.exists()
        or staging_root.is_symlink()
    ):
        _fail("bad migrated staging path is not the exact absent owned prefix")
    prior_root = Path(cast("str", migration.get("prior_execution_root")))
    if _runtime_attestation(Path(__file__).resolve().parents[2], prior_root, allow_legacy=True).get(
        "entry_hash"
    ) != migration.get("prior_runtime_entry_hash"):
        _fail("prior runtime attestation changed during repair")
    prior_receipt, prior_raw = _json_raw(prior_root / "agent-installation.json", modes={0o400})
    prior_archive = submit_v1._owned_file(
        bad_root / "prior-agent-source.md", max_bytes=_MAX_FILE, allowed_modes={0o400}
    )
    output = Path(cast("str", prior_receipt.get("path")))
    global_body = submit_v1._owned_file(output, max_bytes=_MAX_FILE, allowed_modes={0o400})
    if (
        set(prior_receipt)
        != {
            "schema_version",
            "protocol",
            "runtime_attestation_entry_hash",
            "agent_name",
            "path",
            "sha256",
            "bytes",
            "resolver_census_sha256",
            "runtime_identity",
        }
        or canonical_json(prior_receipt) != prior_raw
        or prior_receipt.get("schema_version") != 1
        or prior_receipt.get("protocol") != "ground-truth-native-agent-installation-v1"
        or prior_receipt.get("agent_name") != _AGENT_NAME
        or prior_receipt.get("runtime_attestation_entry_hash")
        != migration.get("prior_runtime_entry_hash")
        or _sha(prior_archive) != prior_receipt.get("sha256")
        or global_body != bad_body
    ):
        _fail("runtime repair agent custody is not exact")
    return {
        "bad_root": bad_root,
        "bad_body": bad_body,
        "prior_root": prior_root,
        "prior_receipt": prior_receipt,
        "prior_archive": prior_archive,
        "output": output,
    }


def _recover_migrated_runtime(
    root: Path, ledger: Path, execution_root: Path, *, repair: bool = False
) -> dict[str, Any] | None:
    if not execution_root.exists():
        return None
    pending = execution_root / "runtime-attestation.pending.json"
    local = execution_root / "runtime-attestation.json"
    if pending.exists() and local.exists():
        _fail("migrated runtime has duplicate local attestations")
    candidate_path = local if local.exists() else pending
    if not candidate_path.exists():
        _fail("migrated runtime final root is incomplete")
    candidate, candidate_raw = _json_raw(candidate_path, modes={0o400})
    if canonical_json(candidate) != candidate_raw:
        _fail("migrated runtime candidate is not canonical")
    _migrated_candidate_files(root, execution_root, candidate)
    private = campaign_v1._private_root(ledger)
    with campaign_v1._ledger_lock(private):
        current = _extended_ledger(private, root)
        _validate_migration_roots(current, execution_root, repair=repair)
        if current.get("runtime") != candidate:
            migration = current.get("migration")
            if (
                not isinstance(migration, dict)
                or current.get("generation") != 1
                or current.get("authorization") is not None
                or (not repair and current.get("runtime", {}).get("schema_version") != 1)
                or (repair and current.get("runtime", {}).get("kind") != "runtime_migrated")
            ):
                _fail("migrated runtime candidate has no exact ledger transition")
            if repair:
                _validate_repaired_event_candidate(current, candidate)
            else:
                _validate_migrated_event_candidate(current, candidate)
            events = private / "lane-events"
            if not events.exists():
                events.mkdir(mode=0o700)
            kind = "runtime_migrated_repair" if repair else "runtime_migrated"
            identifier = "runtime-repair" if repair else "runtime"
            campaign_v1._publish(
                events / f"{candidate['sequence']:06d}-{kind}-{identifier}.json", candidate
            )
            verified = _extended_ledger(private, root)
            if verified.get("runtime") != candidate:
                _fail("migrated runtime recovery did not become ledger head")
        elif (
            current.get("head") != candidate.get("entry_hash")
            or current.get("generation") != 1
            or current.get("authorization") is not None
        ):
            _fail("migrated runtime recovery is not the exact ledger head")
    if pending.exists():
        packet_v1._rename_noreplace(pending, local)
    return {
        "runtime_attestation_entry_hash": candidate["entry_hash"],
        "execution_root": str(execution_root),
        "pi_subagents_version": "0.35.1",
        "pi_version": "0.80.10",
        "live_launch_authorized": False,
    }


def attest_runtime(  # noqa: PLR0912, PLR0915
    root: Path,
    campaign_path: Path,
    bindings: Path,
    cache: Path,
    ledger: Path,
    packets: Path,
    execution_root: Path,
    *,
    migrated: bool = False,
    repair: bool = False,
) -> dict[str, Any]:
    if migrated and repair:
        _fail("runtime migration modes are mutually exclusive")
    migrated_like = migrated or repair
    if migrated_like:
        private = campaign_v1._private_root(ledger)
        with campaign_v1._ledger_lock(private):
            current_for_root = _extended_ledger(private, root)
            _validate_migration_roots(current_for_root, execution_root, repair=repair)
            if repair and current_for_root.get("runtime", {}).get("kind") == "runtime_migrated":
                _validate_repair_incident(current_for_root)
        recovered = _recover_migrated_runtime(root, ledger, execution_root, repair=repair)
        if recovered is not None:
            return recovered
        build_root = _prepare_runtime_staging(execution_root)
    else:
        build_root = execution_root
    source_inventory_before = source_v1._inventory(cache)
    packet_inventory_before = packet_v1._inventory(
        packets,
        limit=packet_v1._MAX_AGGREGATE_PAYLOAD,
        max_entries=packet_v1._MAX_AGGREGATE_ENTRIES,
    )
    campaign, campaign_raw, custody, profile = _custody(
        root, campaign_path, bindings, cache, ledger, packets
    )
    source_inventory_after = source_v1._inventory(cache)
    packet_inventory_after = packet_v1._inventory(
        packets,
        limit=packet_v1._MAX_AGGREGATE_PAYLOAD,
        max_entries=packet_v1._MAX_AGGREGATE_ENTRIES,
    )
    if (
        source_inventory_before != source_inventory_after
        or packet_inventory_before != packet_inventory_after
    ):
        _fail("custody inventories drifted around runtime attestation")
    status = _private_directory(build_root, create=True)
    initial_entries = {path.name for path in build_root.iterdir()}
    if (migrated_like and initial_entries != {".runtime-staging-owner.json"}) or (
        not migrated_like and initial_entries
    ):
        _fail("execution root must be empty before attestation")
    identity = _runtime_identity(root)
    runtime = build_root / "runtime"
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
    agent_extension = (
        execution_root / "runtime/extension/index.ts"
        if migrated_like
        else extension_dir / "index.ts"
    )
    body = _agent_body(agent_extension, prompt)
    agent_source.write_bytes(body)
    agent_source.chmod(0o400)
    custody_receipt = _custody_receipt_payload(
        campaign_path,
        campaign,
        campaign_raw,
        bindings,
        cache,
        ledger,
        packets,
        custody,
        profile,
        source_inventory_after,
        packet_inventory_after,
    )
    custody_path = runtime / "custody-receipt.json"
    _atomic(custody_path, custody_receipt)
    custody_raw = submit_v1._owned_file(custody_path, max_bytes=_MAX_FILE, allowed_modes={0o400})
    final_campaign, final_campaign_raw = _campaign(root, campaign_path)
    _final_source, final_source_raw, _ = source_v1._read_json(bindings, modes={0o400})
    source_inventory_final = source_v1._inventory(cache)
    packet_inventory_final = packet_v1._inventory(
        packets,
        limit=packet_v1._MAX_AGGREGATE_PAYLOAD,
        max_entries=packet_v1._MAX_AGGREGATE_ENTRIES,
    )
    if (
        final_campaign != campaign
        or final_campaign_raw != campaign_raw
        or _sha(final_source_raw) != custody["source"]["sha256"]
        or source_inventory_after != source_inventory_final
        or packet_inventory_after != packet_inventory_final
    ):
        _fail("custody inventories drifted around receipt publication")
    runtime.chmod(0o500)
    entry_body = {
        "schema_version": 2,
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
        "runtime_custody_receipt_path": str(execution_root / "runtime/custody-receipt.json"),
        "runtime_custody_receipt_sha256": _sha(custody_raw),
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
        if migrated_like:
            _validate_migration_roots(current, execution_root, repair=repair)
            if repair:
                _validate_repair_incident(current)
            migration = current.get("migration")
            current_runtime = current.get("runtime")
            if (
                not isinstance(migration, dict)
                or not isinstance(current_runtime, dict)
                or current.get("generation") != 1
                or current.get("authorization") is not None
                or execution_root.exists()
                or (not repair and current_runtime.get("schema_version") != 1)
                or (repair and current_runtime.get("kind") != "runtime_migrated")
            ):
                _fail("prelaunch migration is not ready for runtime attestation")
            fields = {
                **entry_body,
                "supersedes_entry_hash": (
                    current_runtime["entry_hash"]
                    if repair
                    else migration["prior_runtime_entry_hash"]
                ),
                "migration_entry_hash": migration["entry_hash"],
            }
            if repair:
                fields.update(
                    {
                        "bad_execution_root": current_runtime["execution_root"],
                        "bad_production_profile_sha256": current_runtime[
                            "production_profile_sha256"
                        ],
                        "bad_agent_source_sha256": current_runtime["agent_source_sha256"],
                    }
                )
            kind = "runtime_migrated_repair" if repair else "runtime_migrated"
            entry = _event_value(current, kind, fields)
            if repair:
                _validate_repaired_event_candidate(current, entry)
            else:
                _validate_migrated_event_candidate(current, entry)
            pending = build_root / "runtime-attestation.pending.json"
            _atomic(pending, entry)
            owner = build_root / ".runtime-staging-owner.json"
            owner_raw = submit_v1._owned_file(owner, max_bytes=_MAX_FILE, allowed_modes={0o400})
            owner_value = json.loads(owner_raw)
            build_status = build_root.stat(follow_symlinks=False)
            if (
                not isinstance(owner_value, dict)
                or canonical_json(owner_value) != owner_raw
                or set(owner_value) != {"protocol", "final_root", "device", "inode", "uid"}
                or owner_value.get("protocol") != "ground-truth-runtime-staging-owner-v1"
                or owner_value.get("final_root") != str(execution_root)
                or owner_value.get("device") != build_status.st_dev
                or owner_value.get("inode") != build_status.st_ino
                or owner_value.get("uid") != os.getuid()
            ):
                _fail("runtime staging owner changed")
            owner.unlink()
            _fsync_tree(build_root)
            packet_v1._rename_noreplace(build_root, execution_root)
            local = execution_root / "runtime-attestation.json"
            packet_v1._rename_noreplace(execution_root / "runtime-attestation.pending.json", local)
            events = private / "lane-events"
            if not events.exists():
                events.mkdir(mode=0o700)
            identifier = "runtime-repair" if repair else "runtime"
            campaign_v1._publish(
                events / f"{entry['sequence']:06d}-{kind}-{identifier}.json", entry
            )
            verified = _extended_ledger(private, root)
            if verified.get("runtime") != entry:
                _fail("migrated runtime publication did not become ledger head")
        else:
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
    if not migrated_like:
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


def _historical_runtime_profile(
    root: Path, expected_sha256: str
) -> tuple[dict[str, bytes], str, str]:
    current = _profile(root)
    matches = [
        raw
        for relative in (
            packet_v1._SELECTION_CHECKSUMS,
            _RUNTIME_MIGRATION_CHECKSUMS,
            _RUNTIME_REPAIR_CHECKSUMS,
        )
        if (raw := current.files.get(relative)) is not None and _sha(raw) == expected_sha256
    ]
    if len(matches) != 1:
        _fail("historical runtime profile is not uniquely current-profile authenticated")
    raw = matches[0]
    try:
        value = json.loads(raw, object_pairs_hook=_unique, parse_constant=_constant)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise GroundTruthRunError("historical runtime profile is invalid") from exc
    files = value.get("files") if isinstance(value, dict) else None
    if not isinstance(files, dict):
        _fail("historical runtime profile shape is invalid")
    captured: dict[str, bytes] = {}
    for required in (_EXTENSION, _EXTENSION_SCHEMA, f"{_PROFILE}/review-prompt-v1.md"):
        expected = files.get(required)
        actual = submit_v1._owned_file(root / required, max_bytes=_MAX_FILE, allowed_modes={0o644})
        if not isinstance(expected, str) or _sha(actual) != expected:
            _fail("historical runtime dependency changed")
        captured[required] = actual
    return captured, _sha(raw), _sha(canonical_json(cast("dict[str, str]", files)))


def _runtime_attestation(
    root: Path, execution_root: Path, *, allow_legacy: bool = False
) -> dict[str, Any]:
    value, raw = _json_raw(execution_root / "runtime-attestation.json", modes={0o400})
    legacy = allow_legacy and value.get("schema_version") == 1
    expected_keys = {
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
    if legacy:
        expected_keys.remove("runtime_custody_receipt_path")
        expected_keys.remove("runtime_custody_receipt_sha256")
    protocol = value.get("protocol")
    domain = _RUNTIME_DOMAIN
    if protocol == _RUNTIME_SUPERSESSION_PROTOCOL:
        expected_keys.add("supersedes_entry_hash")
        domain = _RUNTIME_SUPERSESSION_DOMAIN
    elif protocol == _MIGRATION_RUNTIME_PROTOCOL:
        expected_keys.update({"sequence", "kind", "supersedes_entry_hash", "migration_entry_hash"})
        domain = _MIGRATION_RUNTIME_DOMAIN
    elif protocol == _MIGRATION_REPAIR_PROTOCOL:
        expected_keys.update(
            {
                "sequence",
                "kind",
                "supersedes_entry_hash",
                "migration_entry_hash",
                "bad_execution_root",
                "bad_production_profile_sha256",
                "bad_agent_source_sha256",
            }
        )
        domain = _MIGRATION_REPAIR_DOMAIN
    elif protocol != _RUNTIME_PROTOCOL:
        _fail("runtime attestation protocol is invalid")
    _strict_keys(value, expected_keys, "runtime attestation")
    status = execution_root.stat(follow_symlinks=False)
    current_profile = _profile(root)
    expected_profile = cast("str", value.get("production_profile_sha256"))
    historical = expected_profile != current_profile.checksum_sha256
    if historical:
        if not legacy and protocol not in {
            _MIGRATION_RUNTIME_PROTOCOL,
            _MIGRATION_REPAIR_PROTOCOL,
        }:
            _fail("historical runtime protocol is not eligible")
        profile_files, profile_checksum_sha256, profile_files_sha256 = _historical_runtime_profile(
            root, expected_profile
        )
    else:
        profile_files = current_profile.files
        profile_checksum_sha256 = current_profile.checksum_sha256
        profile_files_sha256 = current_profile.files_sha256
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
    custody_path = execution_root / "runtime/custody-receipt.json"
    custody_raw = (
        b""
        if legacy
        else submit_v1._owned_file(custody_path, max_bytes=_MAX_FILE, allowed_modes={0o400})
    )
    body = {key: item for key, item in value.items() if key != "entry_hash"}
    if (
        canonical_json(value) != raw
        or value.get("schema_version") != (1 if legacy else 2)
        or value.get("protocol") != protocol
        or value.get("execution_root") != str(execution_root)
        or value.get("execution_device") != status.st_dev
        or value.get("execution_inode") != status.st_ino
        or _immutable_runtime_identity(_validate_runtime_identity(value.get("runtime_identity")))
        != _immutable_runtime_identity(_runtime_identity(root))
        or value.get("production_profile_sha256") != profile_checksum_sha256
        or value.get("production_files_sha256") != profile_files_sha256
        or extension != profile_files[_EXTENSION]
        or extension_schema != profile_files[_EXTENSION_SCHEMA]
        or value.get("extension_sha256") != _sha(extension)
        or value.get("extension_schema_sha256") != _sha(extension_schema)
        or value.get("agent_source_sha256") != _sha(agent)
        or (
            not legacy
            and (
                value.get("runtime_custody_receipt_path") != str(custody_path)
                or value.get("runtime_custody_receipt_sha256") != _sha(custody_raw)
            )
        )
        or not isinstance(value.get("campaign_lanes_sha256"), str)
        or not _DIGEST.fullmatch(cast("str", value["campaign_lanes_sha256"]))
        or value.get("entry_hash") != _entry_hash(domain, body)
        or (
            protocol
            in {
                _RUNTIME_SUPERSESSION_PROTOCOL,
                _MIGRATION_RUNTIME_PROTOCOL,
                _MIGRATION_REPAIR_PROTOCOL,
            }
            and not _DIGEST.fullmatch(str(value.get("supersedes_entry_hash", "")))
        )
        or (
            protocol in {_MIGRATION_RUNTIME_PROTOCOL, _MIGRATION_REPAIR_PROTOCOL}
            and (
                value.get("kind")
                != (
                    "runtime_migrated"
                    if protocol == _MIGRATION_RUNTIME_PROTOCOL
                    else "runtime_migrated_repair"
                )
                or not isinstance(value.get("sequence"), int)
                or not _DIGEST.fullmatch(str(value.get("migration_entry_hash", "")))
            )
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


def _migrated_native_agent(  # noqa: PLR0912, PLR0915
    root: Path,
    ledger: Path,
    execution_root: Path,
    output: Path,
    attestation: dict[str, Any],
    body: bytes,
) -> dict[str, Any]:
    private = campaign_v1._private_root(ledger)
    with campaign_v1._ledger_lock(private):
        current = _extended_ledger(private, root)
        migration = current.get("migration")
        if (
            not isinstance(migration, dict)
            or current.get("runtime") != attestation
            or attestation.get("kind") != "runtime_migrated"
            or current.get("generation") != 1
            or current.get("authorization") is not None
        ):
            _fail("migrated agent installation lacks exact migration custody")
        _validate_migration_roots(current, execution_root)
        prior_root = Path(cast("str", migration["prior_execution_root"]))
        prior_attestation = _runtime_attestation(root, prior_root, allow_legacy=True)
        prior_receipt, prior_raw = _json_raw(prior_root / "agent-installation.json", modes={0o400})
        if (
            set(prior_receipt)
            != {
                "schema_version",
                "protocol",
                "runtime_attestation_entry_hash",
                "agent_name",
                "path",
                "sha256",
                "bytes",
                "resolver_census_sha256",
                "runtime_identity",
            }
            or canonical_json(prior_receipt) != prior_raw
            or prior_receipt.get("schema_version") != 1
            or prior_receipt.get("protocol") != "ground-truth-native-agent-installation-v1"
            or prior_attestation.get("entry_hash") != migration["prior_runtime_entry_hash"]
            or prior_receipt.get("runtime_attestation_entry_hash")
            != migration["prior_runtime_entry_hash"]
            or prior_receipt.get("agent_name") != _AGENT_NAME
            or prior_receipt.get("path") != str(output)
        ):
            _fail("prior agent installation is not migration-bound")
        archive = execution_root / "prior-agent-source.md"
        old_expected = cast("str", prior_receipt.get("sha256"))
        new_expected = _sha(body)
        output_raw = submit_v1._owned_file(output, max_bytes=_MAX_FILE, allowed_modes={0o400})
        if _sha(output_raw) == old_expected:
            prior_identity = _runtime_identity(root)
            prior_candidates = _agent_candidates(prior_identity["resolver_census"])
            prior_effective = [
                row
                for row in prior_identity["resolver_census"]["effective"]
                if isinstance(row, dict) and row.get("name") == _AGENT_NAME
            ]
            if (
                prior_identity.get("resolver_census_sha256")
                != prior_receipt.get("resolver_census_sha256")
                or [row.get("filePath") for row in prior_candidates] != [str(output)]
                or len(prior_effective) != 1
                or prior_effective[0].get("subagentOnlyExtensions")
                != [str(prior_root / "runtime/extension/index.ts")]
            ):
                _fail("prior agent resolver identity changed")
            with contextlib.suppress(FileExistsError):
                os.link(output, archive)
            archive_directory = os.open(archive.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(archive_directory)
            finally:
                os.close(archive_directory)
        elif _sha(output_raw) != new_expected:
            _fail("global agent is neither exact prior nor exact migrated bytes")
        archive_raw = submit_v1._owned_file(archive, max_bytes=_MAX_FILE, allowed_modes={0o400})
        if _sha(archive_raw) != old_expected or len(archive_raw) != prior_receipt.get("bytes"):
            _fail("archived prior agent bytes changed")
        output_raw = submit_v1._owned_file(output, max_bytes=_MAX_FILE, allowed_modes={0o400})
        if _sha(output_raw) == old_expected:
            temporary = output.parent / ".ground-truth-production-reviewer-v1.migrating"
            try:
                submit_v1._atomic_no_clobber(temporary, body, mode=0o400)
            except submit_v1.SubmissionRejected:
                existing = submit_v1._owned_file(
                    temporary, max_bytes=_MAX_FILE, allowed_modes={0o400}
                )
                if existing != body:
                    _fail("migrated agent temporary bytes changed")
            if (
                submit_v1._owned_file(output, max_bytes=_MAX_FILE, allowed_modes={0o400})
                != output_raw
            ):
                _fail("prior agent changed during migrated replacement")
            temporary.replace(output)
            descriptor = os.open(output.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        elif output_raw != body:
            _fail("migrated global agent bytes changed")
    after = _runtime_identity(root)
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
        _fail("migrated production agent is not the unique resolver definition")
    receipt = {
        "schema_version": 2,
        "protocol": "ground-truth-native-agent-installation-migration-v1",
        "runtime_attestation_entry_hash": attestation["entry_hash"],
        "agent_name": _AGENT_NAME,
        "path": str(output),
        "sha256": new_expected,
        "bytes": len(body),
        "resolver_census_sha256": after["resolver_census_sha256"],
        "runtime_identity": after,
        "prior_runtime_attestation_entry_hash": migration["prior_runtime_entry_hash"],
        "prior_archive_path": str(archive),
        "prior_archive_sha256": old_expected,
    }
    receipt_path = execution_root / "agent-installation.json"
    if receipt_path.exists():
        receipt_existing, _raw = _json_raw(receipt_path, modes={0o400})
        if receipt_existing != receipt:
            _fail("migrated agent installation receipt changed")
    else:
        _atomic(receipt_path, receipt)
    return receipt


def _repaired_native_agent(  # noqa: PLR0912, PLR0915
    root: Path,
    ledger: Path,
    execution_root: Path,
    output: Path,
    attestation: dict[str, Any],
    body: bytes,
) -> dict[str, Any]:
    private = campaign_v1._private_root(ledger)
    with campaign_v1._ledger_lock(private):
        current = _extended_ledger(private, root)
        migration = current.get("migration")
        if (
            not isinstance(migration, dict)
            or current.get("runtime") != attestation
            or attestation.get("kind") != "runtime_migrated_repair"
            or current.get("generation") != 1
            or current.get("authorization") is not None
        ):
            _fail("repaired agent installation lacks exact ledger custody")
        _validate_migration_roots(current, execution_root, repair=True)
        bad_root = Path(cast("str", attestation.get("bad_execution_root")))
        bad_body = submit_v1._owned_file(
            bad_root / "runtime/agent-source.md", max_bytes=_MAX_FILE, allowed_modes={0o400}
        )
        if (
            _sha(bad_body) != attestation.get("bad_agent_source_sha256")
            or (bad_root / "agent-installation.json").exists()
        ):
            _fail("superseded migrated agent custody changed")
        prior_root = Path(cast("str", migration["prior_execution_root"]))
        prior_receipt, prior_raw = _json_raw(prior_root / "agent-installation.json", modes={0o400})
        old = submit_v1._owned_file(
            bad_root / "prior-agent-source.md", max_bytes=_MAX_FILE, allowed_modes={0o400}
        )
        if (
            canonical_json(prior_receipt) != prior_raw
            or _sha(old) != prior_receipt.get("sha256")
            or prior_receipt.get("runtime_attestation_entry_hash")
            != migration["prior_runtime_entry_hash"]
            or prior_receipt.get("path") != str(output)
        ):
            _fail("original agent archive is not repair-bound")
        new_expected = _sha(body)
        bad_expected = _sha(bad_body)
        global_body = submit_v1._owned_file(output, max_bytes=_MAX_FILE, allowed_modes={0o400})
        if _sha(global_body) not in {bad_expected, new_expected}:
            _fail("global agent is outside exact repair states")
        archives = {
            execution_root / "prior-agent-source.md": old,
            execution_root / "superseded-agent-source.md": bad_body,
        }
        for path, expected in archives.items():
            if not path.exists():
                source = (
                    bad_root / "prior-agent-source.md"
                    if path.name == "prior-agent-source.md"
                    else bad_root / "runtime/agent-source.md"
                )
                os.link(source, path)
            archived = submit_v1._owned_file(path, max_bytes=_MAX_FILE, allowed_modes={0o400})
            if archived != expected:
                _fail("repaired agent archive changed")
        archive_directory = os.open(execution_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(archive_directory)
        finally:
            os.close(archive_directory)
        if global_body == bad_body:
            temporary = output.parent / ".ground-truth-production-reviewer-v1.repairing"
            try:
                submit_v1._atomic_no_clobber(temporary, body, mode=0o400)
            except submit_v1.SubmissionRejected:
                if (
                    submit_v1._owned_file(temporary, max_bytes=_MAX_FILE, allowed_modes={0o400})
                    != body
                ):
                    _fail("repaired agent temporary bytes changed")
            if (
                submit_v1._owned_file(output, max_bytes=_MAX_FILE, allowed_modes={0o400})
                != bad_body
            ):
                _fail("bad global agent changed during repair")
            temporary.replace(output)
            descriptor = os.open(output.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    after = _runtime_identity(root)
    candidates = _agent_candidates(after["resolver_census"])
    effective = [
        row
        for row in after["resolver_census"]["effective"]
        if isinstance(row, dict) and row.get("name") == _AGENT_NAME
    ]
    expected_extension = str(execution_root / "runtime/extension/index.ts")
    if (
        [row.get("filePath") for row in candidates] != [str(output)]
        or len(effective) != 1
        or effective[0].get("model") != _MODEL
        or effective[0].get("thinking") != _THINKING
        or effective[0].get("tools") != list(_TOOLS)
        or effective[0].get("extensions") != []
        or effective[0].get("subagentOnlyExtensions") != [expected_extension]
    ):
        _fail("repaired production agent is not the unique resolver definition")
    receipt = {
        "schema_version": 3,
        "protocol": "ground-truth-native-agent-installation-migration-repair-v1",
        "runtime_attestation_entry_hash": attestation["entry_hash"],
        "agent_name": _AGENT_NAME,
        "path": str(output),
        "sha256": _sha(body),
        "bytes": len(body),
        "resolver_census_sha256": after["resolver_census_sha256"],
        "runtime_identity": after,
        "prior_runtime_attestation_entry_hash": migration["prior_runtime_entry_hash"],
        "bad_runtime_attestation_entry_hash": attestation["supersedes_entry_hash"],
        "prior_archive_path": str(execution_root / "prior-agent-source.md"),
        "prior_archive_sha256": _sha(old),
        "superseded_archive_path": str(execution_root / "superseded-agent-source.md"),
        "superseded_archive_sha256": _sha(bad_body),
    }
    receipt_path = execution_root / "agent-installation.json"
    if receipt_path.exists():
        existing, _raw = _json_raw(receipt_path, modes={0o400})
        if existing != receipt:
            _fail("repaired agent installation receipt changed")
    else:
        _atomic(receipt_path, receipt)
    return receipt


def create_native_agent(
    root: Path,
    execution_root: Path,
    output: Path,
    *,
    ledger: Path | None = None,
) -> dict[str, Any]:
    attestation = _runtime_attestation(root, execution_root)
    identity = _runtime_identity(root)
    migrated = attestation.get("kind") in {
        "runtime_migrated",
        "runtime_migrated_repair",
    }
    repaired = attestation.get("kind") == "runtime_migrated_repair"
    if (not migrated and identity != attestation.get("runtime_identity")) or (
        migrated
        and _immutable_runtime_identity(identity)
        != _immutable_runtime_identity(cast("dict[str, Any]", attestation["runtime_identity"]))
    ):
        _fail("runtime identity drifted")
    if not migrated and _agent_candidates(identity["resolver_census"]):
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
    body = submit_v1._owned_file(
        execution_root / "runtime/agent-source.md", max_bytes=_MAX_FILE, allowed_modes={0o400}
    )
    if migrated:
        if ledger is None:
            _fail("migrated agent installation requires the exact ledger")
        if repaired:
            return _repaired_native_agent(root, ledger, execution_root, output, attestation, body)
        return _migrated_native_agent(root, ledger, execution_root, output, attestation, body)
    if output.exists() or output.is_symlink():
        _fail("agent output already exists")
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
    migrated = receipt.get("schema_version") in {2, 3}
    repaired = receipt.get("schema_version") == 3
    expected_keys = {
        "schema_version",
        "protocol",
        "runtime_attestation_entry_hash",
        "agent_name",
        "path",
        "sha256",
        "bytes",
        "resolver_census_sha256",
        "runtime_identity",
    }
    if migrated:
        expected_keys.update(
            {
                "prior_runtime_attestation_entry_hash",
                "prior_archive_path",
                "prior_archive_sha256",
            }
        )
    if repaired:
        expected_keys.update(
            {
                "bad_runtime_attestation_entry_hash",
                "superseded_archive_path",
                "superseded_archive_sha256",
            }
        )
    _strict_keys(receipt, expected_keys, "agent installation")
    if (
        canonical_json(receipt) != raw_receipt
        or (
            migrated
            and receipt.get("protocol")
            != (
                "ground-truth-native-agent-installation-migration-repair-v1"
                if repaired
                else "ground-truth-native-agent-installation-migration-v1"
            )
        )
        or (
            not migrated
            and (
                receipt.get("schema_version") != 1
                or receipt.get("protocol") != "ground-truth-native-agent-installation-v1"
            )
        )
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
        _immutable_runtime_identity(identity)
        != _immutable_runtime_identity(cast("dict[str, Any]", attestation["runtime_identity"]))
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
    if migrated:
        archive = Path(cast("str", receipt.get("prior_archive_path")))
        archive_raw = submit_v1._owned_file(archive, max_bytes=_MAX_FILE, allowed_modes={0o400})
        if (
            archive != execution_root / "prior-agent-source.md"
            or _sha(archive_raw) != receipt.get("prior_archive_sha256")
            or not _DIGEST.fullmatch(str(receipt.get("prior_runtime_attestation_entry_hash", "")))
        ):
            _fail("migrated prior agent archive changed")
    if repaired:
        superseded = Path(cast("str", receipt.get("superseded_archive_path")))
        superseded_raw = submit_v1._owned_file(
            superseded, max_bytes=_MAX_FILE, allowed_modes={0o400}
        )
        if (
            superseded != execution_root / "superseded-agent-source.md"
            or _sha(superseded_raw) != receipt.get("superseded_archive_sha256")
            or not _DIGEST.fullmatch(str(receipt.get("bad_runtime_attestation_entry_hash", "")))
        ):
            _fail("repaired superseded agent archive changed")
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


def authorize_prelaunch_migration(  # noqa: PLR0912, PLR0915
    root: Path,
    campaign_path: Path,
    bindings: Path,
    cache: Path,
    ledger: Path,
    packets: Path,
    execution_root: Path,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    source_inventory_before = source_v1._inventory(cache)
    packet_inventory_before = packet_v1._inventory(
        packets,
        limit=packet_v1._MAX_AGGREGATE_PAYLOAD,
        max_entries=packet_v1._MAX_AGGREGATE_ENTRIES,
    )
    campaign, campaign_raw, custody, profile = _custody(
        root, campaign_path, bindings, cache, ledger, packets
    )
    source_inventory = source_v1._inventory(cache)
    packet_inventory = packet_v1._inventory(
        packets,
        limit=packet_v1._MAX_AGGREGATE_PAYLOAD,
        max_entries=packet_v1._MAX_AGGREGATE_ENTRIES,
    )
    if source_inventory_before != source_inventory or packet_inventory_before != packet_inventory:
        _fail("custody drifted around prelaunch migration validation")
    source_raw = submit_v1._owned_file(bindings, max_bytes=_MAX_FILE, allowed_modes={0o400})
    private = campaign_v1._private_root(ledger)
    with campaign_v1._ledger_lock(private):
        fresh_source_raw = submit_v1._owned_file(
            bindings, max_bytes=_MAX_FILE, allowed_modes={0o400}
        )
        if (
            fresh_source_raw != source_raw
            or source_v1._inventory(cache) != source_inventory
            or packet_v1._inventory(
                packets,
                limit=packet_v1._MAX_AGGREGATE_PAYLOAD,
                max_entries=packet_v1._MAX_AGGREGATE_ENTRIES,
            )
            != packet_inventory
        ):
            _fail("custody drifted before prelaunch migration publication")
        current = _extended_ledger(private, root)
        authorization = current.get("authorization")
        runtime = current.get("runtime")
        attempts = sorted(_authorized_attempts(authorization))
        if (
            current.get("migration") is not None
            or current.get("runtime_superseded")
            or not isinstance(runtime, dict)
            or runtime.get("schema_version") != 1
            or not isinstance(authorization, dict)
            or attempts
            != sorted(row["attempt_id"] for row in campaign["lanes"] if row["rank"] == 1)
            or current.get("active") != 0
            or _sha(source_raw) != runtime.get("source_bindings_sha256")
            or custody["source"].get("sha256") != runtime.get("source_bindings_sha256")
            or custody["packet"].get("publication_entry_hash")
            != current.get("base", {}).get("packet_publication_entry_hash")
        ):
            _fail("ledger is not eligible for prelaunch migration")
        execution_status = _private_directory(execution_root)
        if (
            str(execution_root) != runtime.get("execution_root")
            or execution_status.st_dev != runtime.get("execution_device")
            or execution_status.st_ino != runtime.get("execution_inode")
        ):
            _fail("prelaunch execution root differs from prior runtime")
        _private_directory(execution_root / "attempts")
        for attempt in attempts:
            rows = [row for row in current["events"] if row.get("attempt_id") == attempt]
            if (
                [row["kind"] for row in rows] != ["prepared", "operational_failed"]
                or rows[-1].get("reason") != "never-launched broker exited"
                or current["states"].get(attempt) != "operational_failed"
            ):
                _fail("prelaunch lane history is not exact")
            prepared = rows[0]
            state = _state(execution_root, attempt)
            if state["broker_pid"] != prepared.get("broker_pid") or state[
                "broker_start_identity"
            ] != prepared.get("broker_start_identity"):
                _fail("prelaunch broker state differs from prepared event")
            if _same_process(state["broker_pid"], state["broker_start_identity"]):
                _fail("prelaunch broker is still alive")
            socket = Path(state["socket"])
            registry = Path(state["registry"])
            if socket.exists() or socket.is_symlink() or registry.exists() or registry.is_symlink():
                _fail("prelaunch socket or registry remains")
            attempt_root = execution_root / "attempts" / attempt
            _private_directory(attempt_root)
            if {path.name for path in attempt_root.iterdir()} != {
                "binding.json",
                "escrow",
                "logs",
                "native-state.json",
                "packet",
            }:
                _fail("prelaunch attempt inventory is not exact")
            logs = attempt_root / "logs"
            _private_directory(logs)
            _private_directory(attempt_root / "escrow")
            packet_status = (attempt_root / "packet").stat(follow_symlinks=False)
            if (
                not stat.S_ISDIR(packet_status.st_mode)
                or packet_status.st_uid != os.getuid()
                or stat.S_IMODE(packet_status.st_mode) != 0o500
            ):
                _fail("prelaunch packet identity is invalid")
            if {path.name for path in logs.iterdir()} != {"broker.stderr", "broker.stdout"}:
                _fail("prelaunch broker log inventory is not exact")
            for log in logs.iterdir():
                status = log.stat(follow_symlinks=False)
                if (
                    not stat.S_ISREG(status.st_mode)
                    or status.st_uid != os.getuid()
                    or stat.S_IMODE(status.st_mode) != 0o600
                ):
                    _fail("prelaunch broker log identity is invalid")
            forbidden = {
                "review.json",
                "receipt.json",
                "pending-result.json",
                "session-audit.json",
                "native-result.json",
                "native-plan.json",
            }
            if any(path.name in forbidden for path in attempt_root.rglob("*")):
                _fail("prelaunch semantic or native artifacts exist")
            escrow = attempt_root / "escrow"
            if escrow.exists() and any(escrow.iterdir()):
                _fail("prelaunch escrow is not empty")
        slots = execution_root / "slots"
        if slots.exists() or slots.is_symlink():
            _private_directory(slots)
            if {path.name for path in slots.iterdir()} != {".lock"}:
                _fail("prelaunch slots inventory is invalid")
            lock_status = (slots / ".lock").stat(follow_symlinks=False)
            if (
                not stat.S_ISREG(lock_status.st_mode)
                or lock_status.st_uid != os.getuid()
                or stat.S_IMODE(lock_status.st_mode) != 0o600
                or lock_status.st_size != 0
            ):
                _fail("prelaunch slots lock identity is invalid")
        migration = _append_event_locked(
            private,
            root,
            current,
            "prelaunch",
            "prelaunch_migration",
            {
                "prior_runtime_entry_hash": runtime["entry_hash"],
                "prior_execution_root": runtime["execution_root"],
                "prior_execution_device": runtime["execution_device"],
                "prior_execution_inode": runtime["execution_inode"],
                "prior_authorization_entry_hash": authorization["entry_hash"],
                "prior_events_sha256": _sha(canonical_json(current["events"])),
                "prior_event_count": len(current["events"]),
                "campaign_manifest_sha256": _sha(campaign_raw),
                "source_bindings_sha256": _sha(source_raw),
                "packet_publication_entry_hash": current["base"]["packet_publication_entry_hash"],
                "production_profile_sha256": profile.checksum_sha256,
                "attempt_ids": attempts,
                "model_launch_count": 0,
                "migrated_at": _timestamp(now or _now()),
                "authorizations": {
                    "review_launch": False,
                    "adjudication": False,
                    "canonical_import": False,
                },
            },
        )
    return {"entry_hash": migration["entry_hash"], "model_launch_count": 0}


def authorize_migrated_canary(
    root: Path,
    campaign_path: Path,
    ledger: Path,
    execution_root: Path,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    campaign, campaign_raw = _campaign(root, campaign_path)
    attestation = _runtime_attestation(root, execution_root)
    installed = _installed_agent(root, execution_root)
    private = campaign_v1._private_root(ledger)
    with campaign_v1._ledger_lock(private):
        current = _extended_ledger(private, root)
        migration = current.get("migration")
        if (
            not isinstance(migration, dict)
            or current.get("runtime") != attestation
            or attestation.get("kind") not in {"runtime_migrated", "runtime_migrated_repair"}
            or current.get("authorization") is not None
            or current.get("generation") != 1
        ):
            _fail("migrated runtime is not ready for canary authorization")
        selected = [
            {
                "lane_key": row["lane_key"],
                "attempt_id": row["attempt_id"],
                "reviewer": row["reviewer"],
            }
            for row in campaign["lanes"]
            if row["rank"] == 1 and row["lane"] in {"A", "B"}
        ]
        issued = (now or _now()).astimezone(timezone.utc).replace(microsecond=0)
        auth = _append_event_locked(
            private,
            root,
            current,
            "canary",
            "canary_reauthorized",
            {
                "campaign_id": campaign["id"],
                "campaign_manifest_sha256": _sha(campaign_raw),
                "runtime_attestation_entry_hash": attestation["entry_hash"],
                "agent_installation_sha256": _sha(canonical_json(installed)),
                "production_profile_sha256": _profile(root).checksum_sha256,
                "lanes": selected,
                "attempt_ids": sorted(row["attempt_id"] for row in selected),
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
                "migration_entry_hash": migration["entry_hash"],
                "generation": 2,
            },
        )
        _extended_ledger(private, root)
    return {"entry_hash": auth["entry_hash"], "generation": 2, "lanes": selected}


def authorize_prelaunch_canary_recovery(  # noqa: PLR0912, PLR0915
    root: Path,
    campaign_path: Path,
    ledger: Path,
    execution_root: Path,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    campaign, campaign_raw = _campaign(root, campaign_path)
    attestation = _runtime_attestation(root, execution_root)
    installation = _installed_agent(root, execution_root)
    private = campaign_v1._private_root(ledger)
    with campaign_v1._ledger_lock(private):
        current = _extended_ledger(private, root)
        fresh_attestation = _runtime_attestation(root, execution_root)
        fresh_installation = _installed_agent(root, execution_root)
        if fresh_attestation != attestation or fresh_installation != installation:
            _fail("runtime or agent drifted before generation3 recovery")
        authorization = current.get("authorization")
        states = current.get("states")
        if (
            current.get("generation") != 2
            or current.get("prelaunch_recovery") is not None
            or current.get("runtime") != attestation
            or attestation.get("kind") != "runtime_migrated_repair"
            or not isinstance(authorization, dict)
            or authorization.get("kind") != "canary_reauthorized"
            or current.get("active") != 0
            or current.get("launched_attempts")
            or current.get("native_results")
            or not isinstance(states, dict)
        ):
            _fail("ledger is not eligible for generation3 prelaunch recovery")
        authorized = sorted(_authorized_attempts(authorization))
        failed = [item for item in authorized if states.get(item) == "operational_failed"]
        untouched = [item for item in authorized if states.get(item) == "authorized"]
        if len(failed) != 1 or len(untouched) != 1:
            _fail("generation2 lane states are not the exact recoverable pair")
        failed_attempt = failed[0]
        rows = [row for row in current["events"] if row.get("attempt_id") == failed_attempt]
        generation2_rows = [row for row in rows if row.get("generation") == 2]
        pre_readiness_failure = [row["kind"] for row in generation2_rows] == [
            "operational_failed"
        ] and generation2_rows[-1].get("reason") == "broker failed before readiness"
        post_readiness_failure = [row["kind"] for row in generation2_rows] == [
            "prepared",
            "operational_failed",
        ] and generation2_rows[-1].get("reason") == "never-launched broker exited"
        if (
            not (pre_readiness_failure or post_readiness_failure)
            or generation2_rows[-1].get("relaunch_authorized") is not False
            or any(row.get("generation") != 2 for row in generation2_rows)
            or installation.get("runtime_attestation_entry_hash") != attestation["entry_hash"]
            or authorization.get("agent_installation_sha256") != _sha(canonical_json(installation))
        ):
            _fail("generation2 failure evidence is not exact")
        slots = execution_root / "slots"
        _private_directory(slots)
        if {item.name for item in slots.iterdir()} != {".lock"}:
            _fail("generation2 recovery slots are not empty")
        lock_status = (slots / ".lock").stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(lock_status.st_mode)
            or lock_status.st_uid != os.getuid()
            or stat.S_IMODE(lock_status.st_mode) != 0o600
            or lock_status.st_size != 0
        ):
            _fail("generation2 recovery slot lock is invalid")
        attempts_root = execution_root / "attempts"
        _private_directory(attempts_root)
        source_attempt = attempts_root / failed_attempt
        untouched_attempt = attempts_root / untouched[0]
        if untouched_attempt.exists() or untouched_attempt.is_symlink():
            _fail("untouched generation2 lane unexpectedly has an attempt directory")
        failures = execution_root / "prelaunch-failures"
        generation_dir = failures / "generation2"
        archive = generation_dir / failed_attempt
        if not failures.exists():
            failures.mkdir(mode=0o700)
            descriptor = os.open(execution_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        _private_directory(failures)
        if {item.name for item in failures.iterdir()} not in (set(), {"generation2"}):
            _fail("prelaunch failure archive root is invalid")
        if not generation_dir.exists():
            generation_dir.mkdir(mode=0o700)
            descriptor = os.open(failures, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        _private_directory(generation_dir)
        if {item.name for item in generation_dir.iterdir()} not in (set(), {failed_attempt}):
            _fail("generation2 failure archive inventory is invalid")
        if source_attempt.exists() and not archive.exists():
            _recovery_archive_summary(
                source_attempt, failed_attempt, allow_missing_state=pre_readiness_failure
            )
            _fsync_tree(source_attempt)
            _rename_directory_noreplace(source_attempt, archive)
            for directory_path in (attempts_root, generation_dir):
                descriptor = os.open(directory_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        elif source_attempt.exists() or not archive.exists():
            _fail("generation2 attempt archive recovery state is invalid")
        summary = _recovery_archive_summary(
            archive, failed_attempt, allow_missing_state=pre_readiness_failure
        )
        _fsync_tree(archive)
        native_state = (
            _native_state_at(archive / "native-state.json", failed_attempt)
            if post_readiness_failure
            else None
        )
        if (
            post_readiness_failure
            and (
                not isinstance(native_state, dict)
                or native_state.get("generation") != 2
                or native_state.get("runtime_attestation_entry_hash") != attestation["entry_hash"]
                or summary["binding_sha256"] != native_state.get("binding_sha256")
                or summary["binding_sha256"] != generation2_rows[0]["binding_sha256"]
                or summary["broker_pid"] != generation2_rows[0]["broker_pid"]
                or summary["broker_start_identity"] != generation2_rows[0]["broker_start_identity"]
            )
        ) or (pre_readiness_failure and (summary["broker_pid"] != 0 or native_state is not None)):
            _fail("archived generation2 attempt differs from ledger")
        selected = [
            {
                "lane_key": row["lane_key"],
                "attempt_id": row["attempt_id"],
                "reviewer": row["reviewer"],
            }
            for row in campaign["lanes"]
            if row["rank"] == 1 and row["lane"] in {"A", "B"}
        ]
        if selected != authorization.get("lanes"):
            _fail("recovered canary lanes differ from generation2 authorization")
        issued = (now or _now()).astimezone(timezone.utc).replace(microsecond=0)
        event = _append_event_locked(
            private,
            root,
            current,
            "canary-recovery",
            "canary_prelaunch_recovery",
            {
                "campaign_id": campaign["id"],
                "campaign_manifest_sha256": _sha(campaign_raw),
                "runtime_attestation_entry_hash": attestation["entry_hash"],
                "prior_authorization_entry_hash": authorization["entry_hash"],
                "agent_installation_sha256": _sha(canonical_json(installation)),
                "production_profile_sha256": attestation["production_profile_sha256"],
                "lanes": selected,
                "attempt_ids": authorized,
                "failed_attempt_id": failed_attempt,
                "prepared_entry_hash": (
                    generation2_rows[0]["entry_hash"] if post_readiness_failure else _ZERO_HASH
                ),
                "failure_entry_hash": generation2_rows[-1]["entry_hash"],
                "prior_events_sha256": _sha(canonical_json(current["events"])),
                "prior_event_count": len(current["events"]),
                "archive_path": str(archive),
                **summary,
                "limits": {
                    "max_global_active": 3,
                    "max_processes_per_lane": 1,
                    "replacement_attempts": 0,
                },
                "model_launch_count": 0,
                "issued_at": _timestamp(issued),
                "expires_at": _timestamp(issued + timedelta(hours=24)),
                "recovered_at": _timestamp(issued),
                "authorizations": {
                    "review_launch": True,
                    "adjudication": False,
                    "canonical_import": False,
                },
                "generation": 3,
            },
        )
        verified = _extended_ledger(private, root)
        if verified.get("generation") != 3 or any(
            verified["states"].get(item) != "authorized" for item in authorized
        ):
            _fail("generation3 prelaunch recovery did not become atomic ledger state")
    return {"entry_hash": event["entry_hash"], "generation": 3, "lanes": selected}


def authorize_final_prelaunch_canary_recovery(  # noqa: PLR0912, PLR0915
    root: Path,
    campaign_path: Path,
    ledger: Path,
    execution_root: Path,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    campaign, campaign_raw = _campaign(root, campaign_path)
    attestation = _runtime_attestation(root, execution_root)
    installation = _installed_agent(root, execution_root)
    private = campaign_v1._private_root(ledger)
    with campaign_v1._ledger_lock(private), _locked_slots(execution_root) as slots:
        current = _extended_ledger(private, root)
        if (
            _runtime_attestation(root, execution_root) != attestation
            or _installed_agent(root, execution_root) != installation
        ):
            _fail("runtime or agent drifted before final generation4 recovery")
        authorization = current.get("authorization")
        states = current.get("states")
        if (
            current.get("generation") != 3
            or current.get("prelaunch_recovery") is None
            or current.get("final_prelaunch_recovery") is not None
            or current.get("runtime") != attestation
            or attestation.get("kind") != "runtime_migrated_repair"
            or not isinstance(authorization, dict)
            or authorization.get("kind") != "canary_prelaunch_recovery"
            or current.get("active") != 0
            or current.get("launched_attempts")
            or current.get("native_results")
            or not isinstance(states, dict)
        ):
            _fail("ledger is not eligible for terminal generation4 prelaunch recovery")
        authorized = sorted(_authorized_attempts(authorization))
        failed = [item for item in authorized if states.get(item) == "operational_failed"]
        untouched = [item for item in authorized if states.get(item) == "authorized"]
        if len(failed) != 1 or len(untouched) != 1:
            _fail("generation3 lane states are not the exact recoverable pair")
        failed_attempt = failed[0]
        generation3_rows = [
            row
            for row in current["events"]
            if row.get("attempt_id") == failed_attempt and row.get("generation") == 3
        ]
        if (
            [row["kind"] for row in generation3_rows] != ["operational_failed"]
            or generation3_rows[-1].get("reason") != "broker failed before readiness"
            or generation3_rows[-1].get("relaunch_authorized") is not False
            or installation.get("runtime_attestation_entry_hash") != attestation["entry_hash"]
            or authorization.get("agent_installation_sha256") != _sha(canonical_json(installation))
        ):
            _fail("generation3 pre-readiness failure evidence is not exact")
        if {item.name for item in slots.iterdir()} != {".lock"}:
            _fail("generation3 final recovery slots are not empty")
        attempts_root = execution_root / "attempts"
        _private_directory(attempts_root)
        source_attempt = attempts_root / failed_attempt
        untouched_attempt = attempts_root / untouched[0]
        if (
            {item.name for item in attempts_root.iterdir()} not in ({failed_attempt}, set())
            or untouched_attempt.exists()
            or untouched_attempt.is_symlink()
        ):
            _fail("generation3 attempt inventory is not the exact failed/untouched pair")
        failures = execution_root / "prelaunch-failures"
        _private_directory(failures)
        if {item.name for item in failures.iterdir()} not in (
            {"generation2"},
            {"generation2", "generation3"},
        ):
            _fail("terminal prelaunch failure archive root is invalid")
        generation_dir = failures / "generation3"
        archive = generation_dir / failed_attempt
        if not generation_dir.exists():
            generation_dir.mkdir(mode=0o700)
            descriptor = os.open(failures, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        _private_directory(generation_dir)
        if {item.name for item in generation_dir.iterdir()} not in (set(), {failed_attempt}):
            _fail("generation3 failure archive inventory is invalid")
        if source_attempt.exists() and not archive.exists():
            source_binding = source_attempt / "binding.json"
            _require_no_live_broker_for_binding(source_binding)
            source_summary = _recovery_archive_summary(
                source_attempt, failed_attempt, allow_missing_state=True
            )
            _validate_final_recovery_binding(
                root,
                source_attempt,
                failed_attempt,
                cast("str", attestation["entry_hash"]),
                source_summary["binding_sha256"],
            )
            _fsync_tree(source_attempt)
            _rename_directory_noreplace(source_attempt, archive)
            _require_no_live_broker_for_binding(source_binding)
            for directory_path in (attempts_root, generation_dir):
                descriptor = os.open(directory_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        elif source_attempt.exists() or not archive.exists():
            _fail("generation3 attempt archive recovery state is invalid")
        summary = _recovery_archive_summary(archive, failed_attempt, allow_missing_state=True)
        _validate_final_recovery_binding(
            root,
            archive,
            failed_attempt,
            cast("str", attestation["entry_hash"]),
            summary["binding_sha256"],
        )
        _fsync_tree(archive)
        if (
            summary["broker_pid"] != 0
            or summary["broker_start_identity"] != "pre-readiness-unpublished"
        ):
            _fail("archived generation3 attempt has a published broker identity")
        selected = [
            {
                "lane_key": row["lane_key"],
                "attempt_id": row["attempt_id"],
                "reviewer": row["reviewer"],
            }
            for row in campaign["lanes"]
            if row["rank"] == 1 and row["lane"] in {"A", "B"}
        ]
        if selected != authorization.get("lanes"):
            _fail("final recovered canary lanes differ from generation3 authorization")
        final_attestation = _runtime_attestation(root, execution_root)
        final_installation = _installed_agent(root, execution_root)
        if (
            final_attestation != attestation
            or final_installation != installation
            or authorization.get("agent_installation_sha256")
            != _sha(canonical_json(final_installation))
        ):
            _fail("runtime or agent drifted before final recovery publication")
        issued = (now or _now()).astimezone(timezone.utc).replace(microsecond=0)
        event = _append_event_locked(
            private,
            root,
            current,
            "canary-final-recovery",
            "canary_final_prelaunch_recovery",
            {
                "campaign_id": campaign["id"],
                "campaign_manifest_sha256": _sha(campaign_raw),
                "runtime_attestation_entry_hash": attestation["entry_hash"],
                "prior_authorization_entry_hash": authorization["entry_hash"],
                "agent_installation_sha256": _sha(canonical_json(installation)),
                "production_profile_sha256": attestation["production_profile_sha256"],
                "lanes": selected,
                "attempt_ids": authorized,
                "failed_attempt_id": failed_attempt,
                "prepared_entry_hash": _ZERO_HASH,
                "failure_entry_hash": generation3_rows[-1]["entry_hash"],
                "prior_events_sha256": _sha(canonical_json(current["events"])),
                "prior_event_count": len(current["events"]),
                "archive_path": str(archive),
                **summary,
                "limits": {
                    "max_global_active": 3,
                    "max_processes_per_lane": 1,
                    "replacement_attempts": 0,
                },
                "model_launch_count": 0,
                "issued_at": _timestamp(issued),
                "expires_at": _timestamp(issued + timedelta(hours=24)),
                "recovered_at": _timestamp(issued),
                "authorizations": {
                    "review_launch": True,
                    "adjudication": False,
                    "canonical_import": False,
                },
                "generation": 4,
            },
        )
        verified = _extended_ledger(private, root)
        if verified.get("generation") != 4 or any(
            verified["states"].get(item) != "authorized" for item in authorized
        ):
            _fail("generation4 final prelaunch recovery did not become atomic ledger state")
    return {"entry_hash": event["entry_hash"], "generation": 4, "lanes": selected}


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
        or authorization.get("agent_installation_sha256")
        != _sha(canonical_json(fresh_installation))
    ):
        _fail("runtime or installation drifted at lane boundary")
    return fresh_attestation, fresh_installation


def _event_value(current: dict[str, Any], kind: str, fields: dict[str, Any]) -> dict[str, Any]:
    sequence = len(current["events"]) + 1
    protocols = {
        "prelaunch_migration": (_MIGRATION_PROTOCOL, _MIGRATION_DOMAIN, 1),
        "runtime_migrated": (_MIGRATION_RUNTIME_PROTOCOL, _MIGRATION_RUNTIME_DOMAIN, 2),
        "runtime_migrated_repair": (
            _MIGRATION_REPAIR_PROTOCOL,
            _MIGRATION_REPAIR_DOMAIN,
            2,
        ),
        "canary_reauthorized": (_MIGRATED_AUTH_PROTOCOL, _MIGRATED_AUTH_DOMAIN, 1),
        "canary_prelaunch_recovery": (
            _PRELAUNCH_RECOVERY_PROTOCOL,
            _PRELAUNCH_RECOVERY_DOMAIN,
            1,
        ),
        "canary_final_prelaunch_recovery": (
            _FINAL_PRELAUNCH_RECOVERY_PROTOCOL,
            _FINAL_PRELAUNCH_RECOVERY_DOMAIN,
            1,
        ),
    }
    protocol, domain, schema_version = protocols.get(
        kind, ("ground-truth-review-lane-event-v1", b"ground-truth-review-lane-event-v1\0", 1)
    )
    generation_field = (
        {"generation": current["generation"]}
        if current.get("generation") in {2, 3, 4}
        and kind
        in {
            "prepared",
            "launch_claimed",
            "native_result",
            "pending",
            "completed",
            "operational_failed",
        }
        else {}
    )
    body = {
        "schema_version": schema_version,
        "protocol": protocol,
        "sequence": sequence,
        "kind": kind,
        **generation_field,
        **fields,
        "previous_hash": current["head"],
    }
    return {**body, "entry_hash": _entry_hash(domain, body)}


def _validate_migrated_event_candidate(current: dict[str, Any], candidate: dict[str, Any]) -> None:
    migration = current.get("migration")
    runtime = current.get("runtime")
    base = current.get("base")
    fields = {
        key: item
        for key, item in candidate.items()
        if key
        not in {
            "schema_version",
            "protocol",
            "sequence",
            "kind",
            "previous_hash",
            "entry_hash",
        }
    }
    if (
        not isinstance(migration, dict)
        or not isinstance(runtime, dict)
        or not isinstance(base, dict)
        or current.get("generation") != 1
        or current.get("authorization") is not None
        or runtime.get("schema_version") != 1
        or candidate != _event_value(current, "runtime_migrated", fields)
        or set(candidate) != _event_expected_keys("runtime_migrated")
        or candidate.get("migration_entry_hash") != migration.get("entry_hash")
        or candidate.get("supersedes_entry_hash") != migration.get("prior_runtime_entry_hash")
        or candidate.get("campaign_id") != base.get("campaign_id")
        or candidate.get("campaign_manifest_sha256") != base.get("campaign_manifest_sha256")
        or candidate.get("campaign_lanes_sha256") != base.get("campaign_canary_lanes_sha256")
        or candidate.get("source_bindings_sha256") != migration.get("source_bindings_sha256")
        or candidate.get("production_profile_sha256") != migration.get("production_profile_sha256")
        or candidate.get("packet_publication_entry_hash")
        != base.get("packet_publication_entry_hash")
        or candidate.get("execution_root") == migration.get("prior_execution_root")
        or candidate.get("authorizations")
        != {"review_launch": False, "adjudication": False, "canonical_import": False}
    ):
        _fail("migrated runtime candidate is invalid")
    _parse_timestamp(candidate.get("attested_at"))
    _validate_runtime_identity(candidate.get("runtime_identity"))


def _validate_repaired_event_candidate(current: dict[str, Any], candidate: dict[str, Any]) -> None:
    migration = current.get("migration")
    runtime = current.get("runtime")
    base = current.get("base")
    fields = {
        key: item
        for key, item in candidate.items()
        if key
        not in {
            "schema_version",
            "protocol",
            "sequence",
            "kind",
            "previous_hash",
            "entry_hash",
        }
    }
    if (
        not isinstance(migration, dict)
        or not isinstance(runtime, dict)
        or not isinstance(base, dict)
        or current.get("generation") != 1
        or current.get("authorization") is not None
        or runtime.get("kind") != "runtime_migrated"
        or not current.get("events")
        or current["events"][-1].get("entry_hash") != runtime.get("entry_hash")
        or candidate != _event_value(current, "runtime_migrated_repair", fields)
        or set(candidate) != _event_expected_keys("runtime_migrated_repair")
        or candidate.get("migration_entry_hash") != migration.get("entry_hash")
        or candidate.get("supersedes_entry_hash") != runtime.get("entry_hash")
        or candidate.get("bad_execution_root") != runtime.get("execution_root")
        or candidate.get("bad_production_profile_sha256")
        != runtime.get("production_profile_sha256")
        or candidate.get("bad_agent_source_sha256") != runtime.get("agent_source_sha256")
        or candidate.get("campaign_id") != base.get("campaign_id")
        or candidate.get("campaign_manifest_sha256") != base.get("campaign_manifest_sha256")
        or candidate.get("campaign_lanes_sha256") != base.get("campaign_canary_lanes_sha256")
        or candidate.get("source_bindings_sha256") != migration.get("source_bindings_sha256")
        or candidate.get("packet_publication_entry_hash")
        != base.get("packet_publication_entry_hash")
        or candidate.get("execution_root")
        in {migration.get("prior_execution_root"), runtime.get("execution_root")}
        or candidate.get("authorizations")
        != {"review_launch": False, "adjudication": False, "canonical_import": False}
    ):
        _fail("migrated runtime repair candidate is invalid")
    _parse_timestamp(candidate.get("attested_at"))
    _validate_runtime_identity(candidate.get("runtime_identity"))


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
    value = _event_value(current, kind, fields)
    sequence = value["sequence"]
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
    if len(fields) < 20 or fields[0] in {"Z", "X", "x"} or not fields[19].isdigit():
        _fail("broker process identity is invalid or terminal")
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


def serve_broker(
    root: Path,
    socket_path: Path,
    binding: Path,
    deadline_ms: int,
    ledger: Path,
    execution_root: Path,
) -> int:
    _broker_limits()
    attestation = _runtime_attestation(root, execution_root)
    records = submit_v1.load_bindings(binding)
    record = records.records[0]
    private = campaign_v1._private_root(ledger)
    with campaign_v1._ledger_lock(private):
        current = _extended_ledger(private, root)
        if (
            current.get("runtime") != attestation
            or record.runtime_attestation_entry_hash != attestation.get("entry_hash")
            or record.runtime_custody_receipt_path
            != attestation.get("runtime_custody_receipt_path")
            or record.runtime_custody_receipt_sha256
            != attestation.get("runtime_custody_receipt_sha256")
        ):
            _fail("broker binding differs from current runtime custody")
    return submit_v1.serve(
        socket_path, binding, timeout_seconds=_MAX_WALL, deadline_unix_ms=deadline_ms
    )


def _wait_socket(path: Path, pid: int, identity: str) -> None:
    # Broker readiness includes full offline reauthentication of the 50-packet
    # publication and exact cache before exposing the socket.
    deadline = time.monotonic() + _BROKER_READY_SECONDS
    while time.monotonic() < deadline:
        if not _same_process(pid, identity):
            _fail("broker failed before readiness")
        if path.exists():
            status = path.lstat()
            if (
                stat.S_ISSOCK(status.st_mode)
                and status.st_uid == os.getuid()
                and stat.S_IMODE(status.st_mode) == 0o600
            ):
                if not _same_process(pid, identity):
                    _fail("broker failed after socket publication")
                return
            _fail("broker socket is unsafe")
        time.sleep(0.01)
    _fail("broker readiness timeout")


@contextlib.contextmanager
def _locked_slots(execution_root: Path) -> Iterator[Path]:
    slots = execution_root / "slots"
    _private_directory(slots)
    descriptor = os.open(slots / ".lock", os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
    try:
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_uid != os.getuid()
            or stat.S_IMODE(status.st_mode) != 0o600
            or status.st_size != 0
        ):
            _fail("slot lock is invalid")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield slots
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


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


def _lane_authority_matches(
    current: dict[str, Any],
    attempt_id: str,
    generation: int,
    authorization_hash: str,
    state: str | None,
) -> bool:
    authorization = current.get("authorization")
    states = current.get("states")
    return (
        current.get("generation") == generation
        and isinstance(authorization, dict)
        and authorization.get("entry_hash") == authorization_hash
        and isinstance(states, dict)
        and states.get(attempt_id) == state
    )


def _require_lane_authority(
    current: dict[str, Any],
    attempt_id: str,
    generation: int,
    authorization_hash: str,
    state: str | None,
    now: datetime | None = None,
) -> dict[str, Any]:
    if not _lane_authority_matches(current, attempt_id, generation, authorization_hash, state):
        raise _LaneAuthorityChanged("lane authorization changed while preparing")
    return _authorization(current, now)


def _remove_stale_attempt(attempt: Path, attempts_root: Path) -> None:
    if attempt.parent != attempts_root or not attempt.name or attempt.is_symlink():
        _fail("stale attempt cleanup path is unsafe")
    status = attempt.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(status.st_mode)
        or status.st_uid != os.getuid()
        or stat.S_IMODE(status.st_mode) != 0o700
    ):
        _fail("stale attempt cleanup identity is unsafe")
    packet_v1._inventory(
        attempt,
        limit=packet_v1._MAX_AGGREGATE_PAYLOAD,
        max_entries=packet_v1._MAX_AGGREGATE_ENTRIES,
    )
    shutil.rmtree(attempt)
    descriptor = os.open(attempts_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _attested_broker_path(attestation: dict[str, Any]) -> str:
    try:
        node_path = cast("str", attestation["runtime_identity"]["resolver_execution"]["node_path"])
    except (KeyError, TypeError) as exc:
        raise GroundTruthRunError("attested broker Node path is absent") from exc
    node_parent = str(Path(node_path).parent)
    if not Path(node_path).is_absolute() or node_parent not in {"/usr/local/bin", "/usr/bin"}:
        _fail("attested broker Node path is invalid")
    return f"{node_parent}:/usr/bin:/bin"


def prepare_attempt(  # noqa: PLR0912,PLR0915
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
        generation = cast("int", current.get("generation", 1))
        authorization_hash = cast("str", auth["entry_hash"])
        expected_state = None if generation == 1 else "authorized"
        if len(allowed) != 1 or current["states"].get(attempt_id) != expected_state:
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
    attempt_created = False
    attempts = execution_root / "attempts"
    attempt = attempts / attempt_id
    try:
        with campaign_v1._ledger_lock(private):
            after_claim = _extended_ledger(private, root)
            _require_lane_authority(
                after_claim,
                attempt_id,
                generation,
                authorization_hash,
                expected_state,
                now,
            )
            _runtime_boundary(root, execution_root, after_claim, attestation, installation)
        _private_directory(attempts, create=True)
        if attempt.exists() or attempt.is_symlink():
            _fail("attempt path already exists")
        attempt_created = True
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
            runtime_attestation_entry_hash=cast("str", attestation["entry_hash"]),
            runtime_custody_receipt_path=Path(
                cast("str", attestation["runtime_custody_receipt_path"])
            ),
            runtime_custody_receipt_sha256=cast(
                "str", attestation["runtime_custody_receipt_sha256"]
            ),
            generation=cast("Literal[1, 2, 3, 4]", generation),
            started_at=(now or _now()),
        )
        record = submit_v1.load_bindings(attempt / "binding.json").records[0]
        if record.generation != generation:
            _fail("submission binding generation changed")
        with campaign_v1._ledger_lock(private):
            before_spawn = _extended_ledger(private, root)
            _require_lane_authority(
                before_spawn,
                attempt_id,
                generation,
                authorization_hash,
                expected_state,
                now,
            )
            fresh_attestation, _ = _runtime_boundary(
                root, execution_root, before_spawn, attestation, installation
            )
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
            "--ledger-root",
            str(ledger),
            "--execution-root",
            str(execution_root),
            "--deadline-unix-ms",
            str(deadline_ms),
        ]
        env = {
            "PATH": _attested_broker_path(fresh_attestation),
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
            "generation": generation,
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
            _require_lane_authority(
                current,
                attempt_id,
                generation,
                authorization_hash,
                expected_state,
                now,
            )
            fresh_attestation, _ = _runtime_boundary(
                root, execution_root, current, attestation, installation
            )
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
        authority_changed = isinstance(exc, _LaneAuthorityChanged)
        with contextlib.suppress(Exception), campaign_v1._ledger_lock(private):
            failed_current = _extended_ledger(private, root)
            same_authority = _lane_authority_matches(
                failed_current,
                attempt_id,
                generation,
                authorization_hash,
                expected_state,
            )
            if same_authority and not authority_changed:
                _operational_failure(private, root, failed_current, attempt_id, str(exc))
            else:
                authority_changed = True
        try:
            if authority_changed and attempt_created and attempt.exists():
                _remove_stale_attempt(attempt, attempts)
        finally:
            _slot_release(execution_root, attempt_id)
        raise
    return {
        "attempt_id": attempt_id,
        "event_hash": event["entry_hash"],
        "cwd": state["packet"],
        "live_launch_authorized": True,
    }


def _state(execution_root: Path, attempt_id: str) -> dict[str, Any]:
    return _native_state_at(
        execution_root / "attempts" / attempt_id / "native-state.json", attempt_id
    )


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


def _parser() -> argparse.ArgumentParser:  # noqa: PLR0915
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
    sub.add_parser("attest-migrated-runtime", parents=[common])
    sub.add_parser("attest-repaired-runtime", parents=[common])
    migration = sub.add_parser("authorize-prelaunch-migration")
    migration.add_argument("--campaign", type=Path, required=True)
    migration.add_argument("--bindings", type=Path, required=True)
    migration.add_argument("--cache", type=Path, required=True)
    migration.add_argument("--ledger-root", type=Path, required=True)
    migration.add_argument("--packets", type=Path, required=True)
    migration.add_argument("--execution-root", type=Path, required=True)
    migrated_auth = sub.add_parser("authorize-migrated-canary")
    migrated_auth.add_argument("--campaign", type=Path, required=True)
    migrated_auth.add_argument("--ledger-root", type=Path, required=True)
    migrated_auth.add_argument("--execution-root", type=Path, required=True)
    recovery = sub.add_parser("authorize-prelaunch-canary-recovery")
    recovery.add_argument("--campaign", type=Path, required=True)
    recovery.add_argument("--ledger-root", type=Path, required=True)
    recovery.add_argument("--execution-root", type=Path, required=True)
    final_recovery = sub.add_parser("authorize-final-prelaunch-canary-recovery")
    final_recovery.add_argument("--campaign", type=Path, required=True)
    final_recovery.add_argument("--ledger-root", type=Path, required=True)
    final_recovery.add_argument("--execution-root", type=Path, required=True)
    create = sub.add_parser("create-native-agent")
    create.add_argument("--execution-root", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--ledger-root", type=Path)
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
    broker.add_argument("--ledger-root", type=Path, required=True)
    broker.add_argument("--execution-root", type=Path, required=True)
    broker.add_argument("--deadline-unix-ms", type=int, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:  # noqa: PLR0912
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
    elif args.command == "attest-migrated-runtime":
        result = attest_runtime(
            root,
            args.campaign,
            args.bindings,
            args.cache,
            args.ledger_root,
            args.packets,
            args.execution_root,
            migrated=True,
        )
    elif args.command == "attest-repaired-runtime":
        result = attest_runtime(
            root,
            args.campaign,
            args.bindings,
            args.cache,
            args.ledger_root,
            args.packets,
            args.execution_root,
            repair=True,
        )
    elif args.command == "authorize-prelaunch-migration":
        result = authorize_prelaunch_migration(
            root,
            args.campaign,
            args.bindings,
            args.cache,
            args.ledger_root,
            args.packets,
            args.execution_root,
        )
    elif args.command == "authorize-migrated-canary":
        result = authorize_migrated_canary(
            root,
            args.campaign,
            args.ledger_root,
            args.execution_root,
        )
    elif args.command == "authorize-prelaunch-canary-recovery":
        result = authorize_prelaunch_canary_recovery(
            root,
            args.campaign,
            args.ledger_root,
            args.execution_root,
        )
    elif args.command == "authorize-final-prelaunch-canary-recovery":
        result = authorize_final_prelaunch_canary_recovery(
            root,
            args.campaign,
            args.ledger_root,
            args.execution_root,
        )
    elif args.command == "create-native-agent":
        result = create_native_agent(
            root, args.execution_root, args.output, ledger=args.ledger_root
        )
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
        return serve_broker(
            root,
            args.socket,
            args.binding,
            args.deadline_unix_ms,
            args.ledger_root,
            args.execution_root,
        )
    else:  # pragma: no cover
        _fail("unsupported command")
    print(canonical_json(result).decode())
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
