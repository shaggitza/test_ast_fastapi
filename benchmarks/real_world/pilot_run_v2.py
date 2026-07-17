#!/usr/bin/env python3
"""Freeze and validate private execution/custody artifacts for pilot v1."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final, NoReturn

from benchmarks.real_world import pilot_packet_v2, pilot_protocol_v2, pilot_source_v2

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_MAX_JSON_BYTES: Final = 8 * 1024 * 1024
_MAX_LEDGER_BYTES: Final = 8 * 1024 * 1024
_GENESIS = "sha256:" + "0" * 64
_EXECUTION_ID = "blind-review-pilot-execution-v1"
_CORPUS_ID = "blind-review-pilot-v1"
_AGENT_NAME = "pilot-blind-reviewer-v1"
_AGENT_PACKAGE = "benchmark-pilot"
_AGENT_BODY_SHA256 = "sha256:4714e79ecbe8993cf9a81a522584392d8b8a72854877f4882112f9de02516ed3"
_AGENT_TOOLS = ["read", "grep", "find", "ls"]
_PROVIDER = "openai-codex"
_MODEL = "gpt-5.6-sol"
_PI_VERSION = "0.34.0"
_PRICING = {"input": 5_000_000, "cached_input": 500_000, "output": 30_000_000}
_MAX_RUNS = 18
_MAX_TOKENS = 100_000
_BUDGET_MICRO_USD = _MAX_RUNS * _MAX_TOKENS * max(_PRICING.values()) // 1_000_000
_APPROVAL_MODE = "protocol_resource_ceiling_no_separate_hard_cap"
_APPROVAL_TEXT = (
    "nu e nevoie de hard cap- ca avem ai destul de eficient din punct de vedere cost, dai inainte"
)
_SCOPE_POLICY_NAME = "scope-policy-v1.json"
_REQUIRED_STAGES = [
    "source_binding_frozen",
    "review_a_started",
    "review_b_frozen",
    "review_a_escrow_frozen",
    "review_a_first_opened",
    "reviews_validated",
    "adjudication_started",
    "adjudication_frozen",
    "terminal_imported",
]
_AUXILIARY_EVENTS = {"attempt_failed", "incident"}
_EVENT_KEYS = {
    "schema_version",
    "repository",
    "pr",
    "sequence",
    "event",
    "occurred_at",
    "supervisor_actor",
    "attempt_id",
    "input_sha256",
    "output_sha256",
    "transcript_sha256",
    "telemetry_sha256",
    "incident_kind",
    "retry_of_attempt_id",
    "previous_event_sha256",
    "event_sha256",
}


class PilotRunError(ValueError):
    """Raised when private execution or custody provenance is invalid."""


def _fail(message: str) -> NoReturn:
    raise PilotRunError(message)


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical(value: object) -> bytes:
    def reject_float(item: object) -> None:
        if isinstance(item, float):
            _fail("floats are forbidden in canonical pilot artifacts")
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                _fail("canonical object keys must be strings")
            for child in item.values():
                reject_float(child)
        elif isinstance(item, (list, tuple)):
            for child in item:
                reject_float(child)

    reject_float(value)
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    _fail(f"non-finite JSON constant: {value}")


def _read(path: Path, limit: int = _MAX_JSON_BYTES) -> bytes:
    try:
        with path.open("rb") as handle:
            raw = handle.read(limit + 1)
    except OSError as exc:
        raise PilotRunError(f"cannot read {path}") from exc
    if len(raw) > limit:
        _fail(f"{path.name} exceeds byte limit")
    return raw


def _json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, MemoryError) as exc:
        raise PilotRunError(f"invalid JSON: {label}") from exc
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    _canonical(value)
    return value


def _utc(value: str) -> str:
    if not value.endswith("Z"):
        _fail("timestamp must use canonical UTC Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise PilotRunError("invalid timestamp") from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        _fail("timestamp must be UTC")
    if parsed.isoformat().replace("+00:00", "Z") != value:
        _fail("timestamp is not canonical UTC")
    return value


def _atomic_no_clobber(path: Path, raw: bytes, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
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
            raise PilotRunError(f"refusing to overwrite {path}") from exc
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _write_all(fd: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        try:
            written = os.write(fd, raw[offset:])
        except InterruptedError:
            continue
        if written <= 0:
            _fail("custody ledger short write")
        offset += written


def _parse_agent(path: Path) -> dict[str, object]:
    raw = _read(path, 64 * 1024)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PilotRunError("agent config is not UTF-8") from exc
    if not text.startswith("---\n") or "\n---\n" not in text[4:]:
        _fail("agent frontmatter is invalid")
    front, body = text[4:].split("\n---\n", 1)
    values: dict[str, str] = {}
    for line in front.splitlines():
        if ": " not in line:
            _fail("agent frontmatter line is invalid")
        key, value = line.split(": ", 1)
        if key in values:
            _fail("duplicate agent frontmatter key")
        values[key] = value
    expected = {
        "name": _AGENT_NAME,
        "package": _AGENT_PACKAGE,
        "description": (
            "Read-only isolated reviewer/adjudicator for the preregistered issue #147 pilot"
        ),
        "tools": ", ".join(_AGENT_TOOLS),
        "thinking": "high",
        "systemPromptMode": "replace",
        "inheritProjectContext": "false",
        "inheritSkills": "false",
        "defaultContext": "fresh",
    }
    if values != expected:
        _fail("custom agent semantics changed")
    body_hash = _sha(body.encode())
    if body_hash != _AGENT_BODY_SHA256:
        _fail("custom agent system prompt changed")
    return {
        "path": str(path.resolve()),
        "name": _AGENT_NAME,
        "package": _AGENT_PACKAGE,
        "system_prompt_sha256": body_hash,
        "tools": _AGENT_TOOLS,
    }


def _directory_allocated_bytes(root: Path) -> int:
    total = 0
    for current, directories, files in os.walk(root, followlinks=False):
        for name in [*directories, *files]:
            path = Path(current) / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                _fail("private execution roots must not contain symlinks")
            total += info.st_blocks * 512
    return total


def _packet_records(packet_root: Path, bindings: list[dict[str, Any]]) -> list[dict[str, object]]:
    manifests: dict[tuple[str, int], tuple[Path, dict[str, Any], bytes]] = {}
    for manifest_path in sorted(packet_root.glob("*/packet-manifest.json")):
        raw = _read(manifest_path)
        manifest = _json(raw, str(manifest_path))
        key = str(manifest.get("repository")).casefold(), int(manifest.get("pr", 0))
        if key in manifests:
            _fail("duplicate packet identity")
        manifests[key] = manifest_path, manifest, raw
    result: list[dict[str, object]] = []
    for binding in bindings:
        key = str(binding["repository"]).casefold(), int(binding["pr"])
        if key not in manifests:
            _fail("packet missing for source binding")
        path, manifest, raw = manifests.pop(key)
        result.append(
            {
                "repository": binding["repository"],
                "pr": binding["pr"],
                "packet_path": str(path.parent.resolve()),
                "packet_root_sha256": manifest["packet_root_sha256"],
                "packet_manifest_sha256": _sha(raw),
            }
        )
    if manifests:
        _fail("unexpected packet identity")
    return result


def authenticate_inputs(
    root: Path, cache_root: Path, packet_root: Path
) -> tuple[list[dict[str, Any]], str, list[dict[str, object]]]:
    pilot_protocol_v2.validate_preregistration(root)
    bindings_path = root / "benchmarks/real_world/pilot_v2/source-bindings-v1.json"
    checksums_path = root / "benchmarks/real_world/pilot_v2/source-bindings-checksums-v1.json"
    payload = pilot_source_v2.validate_authenticated(root, bindings_path, checksums_path)
    records = payload["records"]
    if not isinstance(records, list) or len(records) != 3:
        _fail("authenticated source binding count changed")
    bindings_hash = _sha(_read(bindings_path))
    pilot_packet_v2.validate_packets(
        packet_root,
        records,
        bindings_hash,
        source_root=root,
        cache_root=cache_root,
    )
    return records, bindings_hash, _packet_records(packet_root, records)


def _policy_hashes(root: Path) -> tuple[dict[str, str], dict[str, str]]:
    pilot_protocol_v2.validate_preregistration(root)
    profile = _json(_read(root / "benchmarks/real_world/pilot_v2/checksums-v1.json"), "profile")
    files = profile.get("files")
    if not isinstance(files, dict):
        _fail("pilot checksum profile is invalid")
    prompts = {key: value for key, value in files.items() if "prompt" in key}
    policies = {key: value for key, value in files.items() if "prompt" not in key}
    if not all(isinstance(value, str) and _DIGEST.fullmatch(value) for value in files.values()):
        _fail("pilot checksum profile digest is invalid")
    return dict(sorted(policies.items())), dict(sorted(prompts.items()))


def _execution_keys(root: Path) -> set[str]:
    schema = _json(
        _read(root / "benchmarks/real_world/pilot_v2/execution-manifest-schema-v1.json"),
        "execution schema",
    )
    fields = schema.get("required_fields")
    if not isinstance(fields, list) or not all(isinstance(item, str) for item in fields):
        _fail("execution schema required fields are invalid")
    return set(fields) | {"approval"}


def _validated_supervisor_session_path(value: str) -> str:
    path = Path(value).expanduser().resolve(strict=True)
    status = path.stat()
    if not path.is_file() or path.is_symlink() or status.st_uid != os.getuid():
        _fail("supervisor session path is not an owned regular file")
    if status.st_size > 256 * 1024 * 1024:
        _fail("supervisor session exceeds private telemetry bound")
    return str(path)


def build_execution_manifest(
    root: Path,
    cache_root: Path,
    packet_root: Path,
    agent_config: Path,
    execution_root: Path,
    *,
    created_at: str,
    approval_at: str,
    supervisor_actor: str,
    supervisor_session_path: str,
) -> dict[str, object]:
    records, bindings_hash, packets = authenticate_inputs(root, cache_root, packet_root)
    agent = _parse_agent(agent_config)
    supervisor_session_path = _validated_supervisor_session_path(supervisor_session_path)
    policies, prompts = _policy_hashes(root)
    decoding = {"thinking": "high", "temperature": "provider_default", "top_p": "provider_default"}
    approval = {
        "schema_version": 1,
        "budget_mode": _APPROVAL_MODE,
        "approval_text": _APPROVAL_TEXT,
        "approval_text_sha256": _sha(_APPROVAL_TEXT.encode()),
        "approved_by": supervisor_actor,
        "approved_at": _utc(approval_at),
        "derived_ceiling_formula": "18*100000*30000000//1000000",
        "separate_monetary_hard_cap": False,
        "execution_runner_sha256": _sha(Path(__file__).read_bytes()),
        "packet_validator_sha256": _sha(Path(pilot_packet_v2.__file__).read_bytes()),
    }
    source_bindings = [
        {
            "corpus_id": _CORPUS_ID,
            "repository": record["repository"],
            "pr": record["pr"],
            "baseline_commit": record["baseline_commit"],
            "baseline_tree": record["baseline_tree"],
            "target_commit": record["target_commit"],
            "target_tree": record["target_tree"],
            "diff_sha256": record["diff_sha256"],
            "diff_bytes": record["diff_bytes"],
        }
        for record in records
    ]
    available_ram = int(os.sysconf("SC_AVPHYS_PAGES")) * int(os.sysconf("SC_PAGE_SIZE"))
    disk = os.statvfs(execution_root.parent)
    disk_free = disk.f_bavail * disk.f_frsize
    cache_bytes = _directory_allocated_bytes(cache_root)
    manifest: dict[str, object] = {
        "schema_version": 1,
        "execution_id": _EXECUTION_ID,
        "created_at": _utc(created_at),
        "provider": _PROVIDER,
        "model": _MODEL,
        "model_version": _MODEL,
        "client_name": "pi-subagents",
        "client_version": _PI_VERSION,
        "decoding_configuration": decoding,
        "decoding_configuration_sha256": _sha(_canonical(decoding)),
        "pi_subagents_version": _PI_VERSION,
        "pricing_micro_usd_per_million_tokens": _PRICING,
        "budget_micro_usd": _BUDGET_MICRO_USD,
        "pre_pilot_budget_approved_by": supervisor_actor,
        "pre_pilot_budget_approved_at": approval_at,
        "custom_agent_config": agent,
        "custom_agent_config_sha256": _sha(_read(agent_config, 64 * 1024)),
        "inherit_project_context": False,
        "allowed_tools": _AGENT_TOOLS,
        "review_b_measurement": {
            "source_kind": "supervisor_session_interval_v1",
            "supervisor_session_path": supervisor_session_path,
            "start_event_id_policy": "unique boundary immediately before Review B",
            "end_event_id_policy": "unique boundary immediately after artifact freeze",
            "start_message_id_policy": "first isolated Review B message",
            "end_message_id_policy": "last isolated Review B message",
            "interval_usage_rule": "exact provider usage events inside inclusive boundaries",
            "interval_tool_event_rule": "only assigned PR Review B tools inside interval",
            "interval_source_hash_rule": "hash exact bounded session event/message bytes",
        },
        "resource_projection_inputs": {
            "available_ram_bytes": available_ram,
            "idle_supervisor_rss_bytes": 0,
            "provider_concurrency_cap": 3,
            "disk_free_bytes": disk_free,
            "immutable_cache_bytes": cache_bytes,
            "review_a_concurrency_cap": 3,
            "review_b_concurrency_cap": 1,
            "adjudication_concurrency_cap": 3,
        },
        "policy_hashes": policies,
        "prompt_hashes": prompts,
        "source_bindings": source_bindings,
        "source_packet_hashes": packets,
        "scope_binding": {
            "scope_id": "fastapi-adapter-v1",
            "scope_version": 1,
            "product": "fastapi-endpoint-detector",
            "definition_sha256": policies[_SCOPE_POLICY_NAME],
        },
        "custody_ledger_path": str((execution_root / "custody.jsonl").resolve()),
        "telemetry_path": str((execution_root / "telemetry.jsonl").resolve()),
        "approval": approval,
    }
    if set(manifest) != _execution_keys(root):
        _fail("execution manifest keys differ from frozen schema")
    validate_execution_manifest(
        root,
        manifest,
        agent_config=agent_config,
        cache_root=cache_root,
        packet_root=packet_root,
    )
    if bindings_hash != _sha(
        _read(root / "benchmarks/real_world/pilot_v2/source-bindings-v1.json")
    ):
        _fail("source binding hash changed during manifest construction")
    return manifest


def validate_execution_manifest(  # noqa: PLR0912,PLR0915 - strict cross-artifact validation
    root: Path,
    manifest: dict[str, Any],
    *,
    agent_config: Path,
    cache_root: Path,
    packet_root: Path,
) -> None:
    _canonical(manifest)
    if set(manifest) != _execution_keys(root):
        _fail("execution manifest keys are invalid")
    decoding = {"thinking": "high", "temperature": "provider_default", "top_p": "provider_default"}
    if (
        manifest["schema_version"] != 1
        or manifest["execution_id"] != _EXECUTION_ID
        or manifest["provider"] != _PROVIDER
        or manifest["model"] != _MODEL
        or manifest["model_version"] != _MODEL
        or manifest["client_name"] != "pi-subagents"
        or manifest["client_version"] != _PI_VERSION
        or manifest["pi_subagents_version"] != _PI_VERSION
        or manifest["decoding_configuration"] != decoding
        or manifest["decoding_configuration_sha256"] != _sha(_canonical(decoding))
        or manifest["pricing_micro_usd_per_million_tokens"] != _PRICING
        or manifest["budget_micro_usd"] != _BUDGET_MICRO_USD
        or manifest["inherit_project_context"] is not False
        or manifest["allowed_tools"] != _AGENT_TOOLS
    ):
        _fail("execution manifest frozen identity changed")
    if manifest["custom_agent_config"] != _parse_agent(agent_config):
        _fail("execution manifest agent binding changed")
    if manifest["custom_agent_config_sha256"] != _sha(_read(agent_config, 64 * 1024)):
        _fail("execution manifest agent hash changed")
    created_at = _utc(str(manifest["created_at"]))
    approval_at = _utc(str(manifest["pre_pilot_budget_approved_at"]))
    actor = manifest["pre_pilot_budget_approved_by"]
    if not isinstance(actor, str) or not actor or approval_at > created_at:
        _fail("execution approval actor/timestamp is invalid")
    approval = manifest.get("approval")
    expected_approval = {
        "schema_version": 1,
        "budget_mode": _APPROVAL_MODE,
        "approval_text": _APPROVAL_TEXT,
        "approval_text_sha256": _sha(_APPROVAL_TEXT.encode()),
        "approved_by": actor,
        "approved_at": approval_at,
        "derived_ceiling_formula": "18*100000*30000000//1000000",
        "separate_monetary_hard_cap": False,
        "execution_runner_sha256": _sha(Path(__file__).read_bytes()),
        "packet_validator_sha256": _sha(Path(pilot_packet_v2.__file__).read_bytes()),
    }
    if approval != expected_approval:
        _fail("execution approval receipt changed")
    review_b = manifest.get("review_b_measurement")
    expected_review_b_keys = {
        "source_kind",
        "supervisor_session_path",
        "start_event_id_policy",
        "end_event_id_policy",
        "start_message_id_policy",
        "end_message_id_policy",
        "interval_usage_rule",
        "interval_tool_event_rule",
        "interval_source_hash_rule",
    }
    if not isinstance(review_b, dict) or set(review_b) != expected_review_b_keys:
        _fail("Review B measurement contract changed")
    if (
        review_b.get("source_kind") != "supervisor_session_interval_v1"
        or not isinstance(review_b.get("supervisor_session_path"), str)
        or not review_b["supervisor_session_path"]
        or review_b["supervisor_session_path"]
        != _validated_supervisor_session_path(str(review_b["supervisor_session_path"]))
    ):
        _fail("Review B measurement identity changed")
    fixed_measurements = {
        "start_event_id_policy": "unique boundary immediately before Review B",
        "end_event_id_policy": "unique boundary immediately after artifact freeze",
        "start_message_id_policy": "first isolated Review B message",
        "end_message_id_policy": "last isolated Review B message",
        "interval_usage_rule": "exact provider usage events inside inclusive boundaries",
        "interval_tool_event_rule": "only assigned PR Review B tools inside interval",
        "interval_source_hash_rule": "hash exact bounded session event/message bytes",
    }
    if any(review_b.get(key) != value for key, value in fixed_measurements.items()):
        _fail("Review B measurement policy changed")
    resources = manifest.get("resource_projection_inputs")
    resource_keys = {
        "available_ram_bytes",
        "idle_supervisor_rss_bytes",
        "provider_concurrency_cap",
        "disk_free_bytes",
        "immutable_cache_bytes",
        "review_a_concurrency_cap",
        "review_b_concurrency_cap",
        "adjudication_concurrency_cap",
    }
    if not isinstance(resources, dict) or set(resources) != resource_keys:
        _fail("execution resource projection keys changed")
    for key, value in resources.items():
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            _fail("execution resource projection value is invalid")
        if key not in {"idle_supervisor_rss_bytes", "immutable_cache_bytes"} and value == 0:
            _fail("execution resource projection value must be positive")
    if (
        resources["provider_concurrency_cap"] != 3
        or resources["review_a_concurrency_cap"] != 3
        or resources["review_b_concurrency_cap"] != 1
        or resources["adjudication_concurrency_cap"] != 3
    ):
        _fail("execution concurrency caps changed")
    policies, prompts = _policy_hashes(root)
    if manifest.get("policy_hashes") != policies or manifest.get("prompt_hashes") != prompts:
        _fail("execution policy/prompt hashes changed")
    source_payload = pilot_source_v2.validate_authenticated(
        root,
        root / "benchmarks/real_world/pilot_v2/source-bindings-v1.json",
        root / "benchmarks/real_world/pilot_v2/source-bindings-checksums-v1.json",
    )
    records = source_payload["records"]
    if not isinstance(records, list) or len(records) != 3:
        _fail("authenticated source binding count changed")
    bindings_hash = _sha(_read(root / "benchmarks/real_world/pilot_v2/source-bindings-v1.json"))
    pilot_packet_v2.validate_cache(cache_root, records)
    pilot_packet_v2.validate_packets(
        packet_root, records, bindings_hash, source_root=root, cache_root=cache_root
    )
    expected_bindings = [
        {
            "corpus_id": _CORPUS_ID,
            "repository": record["repository"],
            "pr": record["pr"],
            "baseline_commit": record["baseline_commit"],
            "baseline_tree": record["baseline_tree"],
            "target_commit": record["target_commit"],
            "target_tree": record["target_tree"],
            "diff_sha256": record["diff_sha256"],
            "diff_bytes": record["diff_bytes"],
        }
        for record in records
    ]
    bindings = manifest.get("source_bindings")
    packets = manifest.get("source_packet_hashes")
    expected_packets = _packet_records(packet_root, records)
    if bindings != expected_bindings or packets != expected_packets:
        _fail("execution source/packet bindings changed")
    binding_keys = [
        (str(item["repository"]).casefold(), int(item["pr"])) for item in expected_bindings
    ]
    packet_keys = [
        (str(item["repository"]).casefold(), int(str(item["pr"]))) for item in expected_packets
    ]
    if len(set(binding_keys)) != 3 or set(binding_keys) != set(packet_keys):
        _fail("execution source/packet identities are duplicate or mismatched")
    if manifest.get("scope_binding") != {
        "scope_id": "fastapi-adapter-v1",
        "scope_version": 1,
        "product": "fastapi-endpoint-detector",
        "definition_sha256": policies[_SCOPE_POLICY_NAME],
    }:
        _fail("execution scope binding changed")
    for field in ("custody_ledger_path", "telemetry_path"):
        value = manifest.get(field)
        if not isinstance(value, str) or not Path(value).is_absolute():
            _fail("execution private artifact path is invalid")


def freeze_execution(
    root: Path,
    cache_root: Path,
    packet_root: Path,
    agent_config: Path,
    execution_root: Path,
    *,
    created_at: str,
    approval_at: str,
    supervisor_actor: str,
    supervisor_session_path: str,
) -> tuple[Path, str]:
    if execution_root.exists():
        _fail("refusing to overwrite private execution root")
    execution_root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if stat.S_IMODE(execution_root.parent.stat().st_mode) & 0o077:
        _fail("execution parent must be private mode 0700")
    manifest = build_execution_manifest(
        root,
        cache_root,
        packet_root,
        agent_config,
        execution_root,
        created_at=created_at,
        approval_at=approval_at,
        supervisor_actor=supervisor_actor,
        supervisor_session_path=supervisor_session_path,
    )
    execution_root.mkdir(mode=0o700)
    manifest_path = execution_root / "execution-manifest.json"
    _atomic_no_clobber(manifest_path, _canonical(manifest))
    return manifest_path, _sha(_read(manifest_path))


def _manifest(
    path: Path, agent_config: Path, cache_root: Path, packet_root: Path
) -> tuple[dict[str, Any], str]:
    raw = _read(path)
    manifest = _json(raw, str(path))
    if raw != _canonical(manifest):
        _fail("execution manifest is not canonically encoded")
    validate_execution_manifest(
        Path(__file__).resolve().parents[2],
        manifest,
        agent_config=agent_config,
        cache_root=cache_root,
        packet_root=packet_root,
    )
    private_parent = path.resolve().parent
    if (
        Path(str(manifest["custody_ledger_path"])).parent != private_parent
        or Path(str(manifest["telemetry_path"])).parent != private_parent
    ):
        _fail("execution private artifact paths changed")
    return manifest, _sha(raw)


def _event_hash(event: dict[str, Any]) -> str:
    payload = {key: value for key, value in event.items() if key != "event_sha256"}
    return _sha(_canonical(payload))


def _parse_ledger(raw: bytes) -> list[dict[str, Any]]:
    if len(raw) > _MAX_LEDGER_BYTES:
        _fail("custody ledger exceeds byte limit")
    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(raw.splitlines(keepends=True), 1):
        if not line.endswith(b"\n"):
            _fail("custody ledger line lacks LF")
        event = _json(line, f"custody line {line_number}")
        if line != _canonical(event):
            _fail("custody ledger line is not canonical")
        if set(event) != _EVENT_KEYS:
            _fail("custody event keys are invalid")
        events.append(event)
    return events


def _event_shape(  # noqa: PLR0912 - exact per-event null/evidence contracts
    event: dict[str, Any],
) -> None:
    if event["schema_version"] != 1 or not isinstance(event["pr"], int) or event["pr"] <= 0:
        _fail("custody event identity is invalid")
    if not isinstance(event["sequence"], int) or event["sequence"] < 0:
        _fail("custody sequence is invalid")
    _utc(str(event["occurred_at"]))
    for field in (
        "input_sha256",
        "output_sha256",
        "transcript_sha256",
        "telemetry_sha256",
        "previous_event_sha256",
        "event_sha256",
    ):
        value = event[field]
        if value is not None and _DIGEST.fullmatch(str(value)) is None:
            _fail(f"custody {field} is invalid")
    if event["event_sha256"] != _event_hash(event):
        _fail("custody event hash mismatch")
    name = event["event"]
    if not isinstance(event["repository"], str) or not event["repository"]:
        _fail("custody repository is invalid")
    if not isinstance(event["supervisor_actor"], str) or not event["supervisor_actor"]:
        _fail("custody supervisor actor is invalid")
    rules: dict[str, tuple[set[str], set[str]]] = {
        "source_binding_frozen": (
            {"input_sha256", "output_sha256"},
            {"attempt_id", "transcript_sha256", "telemetry_sha256", "retry_of_attempt_id"},
        ),
        "review_a_started": (
            {"attempt_id", "input_sha256"},
            {"output_sha256", "transcript_sha256", "telemetry_sha256"},
        ),
        "review_b_frozen": (
            {
                "attempt_id",
                "input_sha256",
                "output_sha256",
                "transcript_sha256",
                "telemetry_sha256",
            },
            {"retry_of_attempt_id"},
        ),
        "review_a_escrow_frozen": (
            {
                "attempt_id",
                "input_sha256",
                "output_sha256",
                "transcript_sha256",
                "telemetry_sha256",
            },
            {"retry_of_attempt_id"},
        ),
        "review_a_first_opened": (
            {"attempt_id", "input_sha256"},
            {"output_sha256", "transcript_sha256", "telemetry_sha256", "retry_of_attempt_id"},
        ),
        "reviews_validated": (
            {"input_sha256", "output_sha256"},
            {"attempt_id", "transcript_sha256", "telemetry_sha256", "retry_of_attempt_id"},
        ),
        "adjudication_started": (
            {"attempt_id", "input_sha256"},
            {"output_sha256", "transcript_sha256", "telemetry_sha256"},
        ),
        "adjudication_frozen": (
            {
                "attempt_id",
                "input_sha256",
                "output_sha256",
                "transcript_sha256",
                "telemetry_sha256",
            },
            {"retry_of_attempt_id"},
        ),
        "terminal_imported": (
            {"input_sha256", "output_sha256"},
            {"attempt_id", "transcript_sha256", "telemetry_sha256", "retry_of_attempt_id"},
        ),
        "attempt_failed": (
            {"attempt_id", "transcript_sha256", "telemetry_sha256"},
            {"output_sha256", "retry_of_attempt_id"},
        ),
    }
    if name in rules:
        required, forbidden = rules[name]
        if any(event[field] is None for field in required) or any(
            event[field] is not None for field in forbidden
        ):
            _fail("custody event required/null field shape is invalid")
    started = name in {"review_a_started", "adjudication_started"}
    frozen = name in {"review_b_frozen", "review_a_escrow_frozen", "adjudication_frozen"}
    if started and (
        not event["attempt_id"]
        or event["input_sha256"] is None
        or any(
            event[field] is not None
            for field in ("output_sha256", "transcript_sha256", "telemetry_sha256")
        )
    ):
        _fail("custody started-event hash/null shape is invalid")
    if frozen and (
        not event["attempt_id"]
        or any(
            event[field] is None
            for field in ("input_sha256", "output_sha256", "transcript_sha256", "telemetry_sha256")
        )
    ):
        _fail("custody frozen-event evidence is incomplete")
    if name == "incident":
        if not event["incident_kind"]:
            _fail("custody incident requires incident_kind")
    elif event["incident_kind"] is not None:
        _fail("incident_kind is allowed only on incident")
    if name == "attempt_failed" and (not event["attempt_id"] or event["telemetry_sha256"] is None):
        _fail("failed attempt requires attempt and telemetry")


def _declared_ledger_path(manifest: dict[str, Any], supplied: Path | None) -> Path:
    declared = Path(str(manifest["custody_ledger_path"])).resolve()
    if supplied is not None and supplied.resolve() != declared:
        _fail("CLI ledger path differs from execution manifest custody ledger")
    return declared


def _validate_ledger(  # noqa: PLR0912,PLR0915 - strict append-only state machine
    ledger_path: Path,
    manifest_path: Path,
    agent_config: Path,
    cache_root: Path,
    packet_root: Path,
    *,
    enforce_declared_path: bool,
) -> list[dict[str, Any]]:
    manifest, manifest_hash = _manifest(manifest_path, agent_config, cache_root, packet_root)
    if enforce_declared_path:
        ledger_path = _declared_ledger_path(manifest, ledger_path)
    events = _parse_ledger(_read(ledger_path, _MAX_LEDGER_BYTES))
    allowed = {
        (str(item["repository"]).casefold(), int(item["pr"]))
        for item in manifest["source_bindings"]
    }
    packet_hashes = {
        (str(item["repository"]).casefold(), int(item["pr"])): item["packet_manifest_sha256"]
        for item in manifest["source_packet_hashes"]
    }
    streams: dict[tuple[str, int], list[dict[str, Any]]] = {}
    global_incident = False
    global_attempts: set[str] = set()
    expected_actor = str(manifest["pre_pilot_budget_approved_by"])
    for event in events:
        _event_shape(event)
        if event["supervisor_actor"] != expected_actor:
            _fail("custody supervisor actor changed")
        if global_incident and event["event"] != "incident":
            _fail("custody ledger continued after global no-go incident")
        if event["event"] == "incident":
            global_incident = True
        if event["event"] in {"review_a_started", "review_b_frozen", "adjudication_started"}:
            attempt = str(event["attempt_id"])
            if attempt in global_attempts:
                _fail("duplicate global custody attempt id")
            global_attempts.add(attempt)
            if len(global_attempts) > _MAX_RUNS:
                _fail("custody total started-attempt bound exceeded")
        key = str(event["repository"]).casefold(), int(event["pr"])
        if key not in allowed:
            _fail("custody identity is outside execution manifest")
        streams.setdefault(key, []).append(event)
    if set(streams) != allowed:
        _fail("custody ledger does not cover all execution PRs")
    for key, stream in streams.items():
        previous = _GENESIS
        stage_index = 0
        attempts: set[str] = set()
        failed_attempts: set[str] = set()
        active_review_a: str | None = None
        active_adjudication: str | None = None
        previous_time: datetime | None = None
        incident_seen = False
        retries = {"review_a_started": 0, "adjudication_started": 0}
        review_b_attempts = 0
        for sequence, event in enumerate(stream):
            if event["sequence"] != sequence or event["previous_event_sha256"] != previous:
                _fail("custody sequence/hash chain is broken")
            previous = event["event_sha256"]
            current_time = datetime.fromisoformat(str(event["occurred_at"])[:-1] + "+00:00")
            if previous_time is not None and current_time < previous_time:
                _fail("custody timestamps are not monotonic")
            previous_time = current_time
            name = event["event"]
            if incident_seen and name != "incident":
                _fail("custody stream continued after no-go incident")
            if name == "incident":
                incident_seen = True
                continue
            if name == "attempt_failed":
                attempt = str(event["attempt_id"])
                if attempt not in attempts or attempt in failed_attempts:
                    _fail("custody failed attempt reference is invalid")
                prior = stream[sequence - 1]["event"] if sequence else None
                if prior not in {"review_a_started", "adjudication_started"}:
                    _fail("custody attempt_failed must immediately follow its started event")
                failed_attempts.add(attempt)
                if prior == "review_a_started":
                    active_review_a = None
                else:
                    active_adjudication = None
                stage_index -= 1
                continue
            if stage_index >= len(_REQUIRED_STAGES) or name != _REQUIRED_STAGES[stage_index]:
                _fail("custody event stage order is invalid")
            if name == "source_binding_frozen" and (
                event["input_sha256"] != manifest_hash
                or event["output_sha256"] != packet_hashes[key]
            ):
                _fail("custody genesis is not bound to execution manifest/packet")
            if name in {"review_a_started", "adjudication_started"}:
                attempt = str(event["attempt_id"])
                if attempt in attempts:
                    _fail("duplicate custody attempt id")
                retry = event["retry_of_attempt_id"]
                if retry is None:
                    if any(item["event"] == name for item in stream[:sequence]):
                        _fail("repeated attempt requires retry_of_attempt_id")
                elif str(retry) not in failed_attempts:
                    _fail("custody retry does not reference failed attempt")
                else:
                    retries[name] += 1
                    if retries[name] > 1:
                        _fail("custody stream exceeds one retry")
                attempts.add(attempt)
                if name == "review_a_started":
                    active_review_a = attempt
                else:
                    active_adjudication = attempt
            elif event["retry_of_attempt_id"] is not None:
                _fail("retry_of_attempt_id is allowed only on started events")
            if name in {"review_a_escrow_frozen", "review_a_first_opened"} and (
                event["attempt_id"] != active_review_a
            ):
                _fail("Review A custody event is bound to the wrong attempt")
            if name == "adjudication_frozen" and event["attempt_id"] != active_adjudication:
                _fail("adjudication custody event is bound to the wrong attempt")
            if name == "review_b_frozen":
                review_b_attempts += 1
                if review_b_attempts > 1 or event["retry_of_attempt_id"] is not None:
                    _fail("Review B permits exactly one non-retry attempt")
                attempt_b = str(event["attempt_id"])
                if attempt_b in attempts:
                    _fail("duplicate custody attempt id")
                attempts.add(attempt_b)
            stage_index += 1
        if not incident_seen and stage_index == 0:
            _fail("empty custody stream")
    return events


def validate_ledger(
    ledger_path: Path,
    manifest_path: Path,
    agent_config: Path,
    cache_root: Path,
    packet_root: Path,
) -> list[dict[str, Any]]:
    """Validate only the manifest-declared canonical custody ledger."""
    return _validate_ledger(
        ledger_path,
        manifest_path,
        agent_config,
        cache_root,
        packet_root,
        enforce_declared_path=True,
    )


def initialize_ledger(
    ledger_path: Path,
    manifest_path: Path,
    agent_config: Path,
    cache_root: Path,
    packet_root: Path,
    *,
    occurred_at: str,
    supervisor_actor: str,
) -> None:
    manifest, manifest_hash = _manifest(manifest_path, agent_config, cache_root, packet_root)
    ledger_path = _declared_ledger_path(manifest, ledger_path)
    events: list[dict[str, Any]] = []
    packets = {
        (str(item["repository"]).casefold(), int(item["pr"])): item
        for item in manifest["source_packet_hashes"]
    }
    for binding in manifest["source_bindings"]:
        key = str(binding["repository"]).casefold(), int(binding["pr"])
        event: dict[str, Any] = {
            "schema_version": 1,
            "repository": binding["repository"],
            "pr": binding["pr"],
            "sequence": 0,
            "event": "source_binding_frozen",
            "occurred_at": _utc(occurred_at),
            "supervisor_actor": supervisor_actor,
            "attempt_id": None,
            "input_sha256": manifest_hash,
            "output_sha256": packets[key]["packet_manifest_sha256"],
            "transcript_sha256": None,
            "telemetry_sha256": None,
            "incident_kind": None,
            "retry_of_attempt_id": None,
            "previous_event_sha256": _GENESIS,
            "event_sha256": None,
        }
        event["event_sha256"] = _event_hash(event)
        events.append(event)
    _atomic_no_clobber(ledger_path, b"".join(_canonical(event) for event in events))
    validate_ledger(ledger_path, manifest_path, agent_config, cache_root, packet_root)


def append_event(
    ledger_path: Path,
    manifest_path: Path,
    agent_config: Path,
    cache_root: Path,
    packet_root: Path,
    *,
    repository: str,
    pr: int,
    event_name: str,
    occurred_at: str,
    supervisor_actor: str,
    attempt_id: str | None,
    input_sha256: str | None,
    output_sha256: str | None,
    transcript_sha256: str | None,
    telemetry_sha256: str | None,
    incident_kind: str | None,
    retry_of_attempt_id: str | None,
) -> dict[str, Any]:
    if event_name not in set(_REQUIRED_STAGES) | _AUXILIARY_EVENTS:
        _fail("unknown custody event")
    manifest, _manifest_hash = _manifest(manifest_path, agent_config, cache_root, packet_root)
    ledger_path = _declared_ledger_path(manifest, ledger_path)
    lock_path = ledger_path.with_suffix(ledger_path.suffix + ".lock")
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        events = validate_ledger(ledger_path, manifest_path, agent_config, cache_root, packet_root)
        stream = [
            item
            for item in events
            if str(item["repository"]).casefold() == repository.casefold() and item["pr"] == pr
        ]
        if not stream:
            _fail("custody append identity is not initialized")
        created: dict[str, Any] = {
            "schema_version": 1,
            "repository": stream[0]["repository"],
            "pr": pr,
            "sequence": len(stream),
            "event": event_name,
            "occurred_at": _utc(occurred_at),
            "supervisor_actor": supervisor_actor,
            "attempt_id": attempt_id,
            "input_sha256": input_sha256,
            "output_sha256": output_sha256,
            "transcript_sha256": transcript_sha256,
            "telemetry_sha256": telemetry_sha256,
            "incident_kind": incident_kind,
            "retry_of_attempt_id": retry_of_attempt_id,
            "previous_event_sha256": stream[-1]["event_sha256"],
            "event_sha256": None,
        }
        created["event_sha256"] = _event_hash(created)
        _event_shape(created)
        existing = _read(ledger_path, _MAX_LEDGER_BYTES)
        descriptor_test, name_test = tempfile.mkstemp(
            prefix=".custody-prospective.", dir=ledger_path.parent
        )
        prospective = Path(name_test)
        try:
            os.fchmod(descriptor_test, 0o600)
            with os.fdopen(descriptor_test, "wb") as handle:
                handle.write(existing)
                handle.write(_canonical(created))
                handle.flush()
                os.fsync(handle.fileno())
            _validate_ledger(
                prospective,
                manifest_path,
                agent_config,
                cache_root,
                packet_root,
                enforce_declared_path=False,
            )
        finally:
            prospective.unlink(missing_ok=True)
        fd = os.open(ledger_path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
        try:
            if stat.S_IMODE(os.fstat(fd).st_mode) != 0o600:
                _fail("custody ledger permissions changed")
            _write_all(fd, _canonical(created))
            os.fsync(fd)
        finally:
            os.close(fd)
        return created
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def write_review_a_tasks(
    task_root: Path,
    manifest_path: Path,
    agent_config: Path,
    cache_root: Path,
    packet_root: Path,
) -> list[Path]:
    manifest, _manifest_hash = _manifest(manifest_path, agent_config, cache_root, packet_root)
    ledger_path = _declared_ledger_path(manifest, None)
    lock_path = ledger_path.with_suffix(ledger_path.suffix + ".lock")
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return _write_review_a_tasks_locked(
            task_root, manifest_path, agent_config, cache_root, packet_root
        )
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _write_review_a_tasks_locked(
    task_root: Path,
    manifest_path: Path,
    agent_config: Path,
    cache_root: Path,
    packet_root: Path,
) -> list[Path]:
    manifest, manifest_hash = _manifest(manifest_path, agent_config, cache_root, packet_root)
    ledger_path = _declared_ledger_path(manifest, None)
    events = validate_ledger(ledger_path, manifest_path, agent_config, cache_root, packet_root)
    if len(events) != len(manifest["source_bindings"]) or any(
        event["sequence"] != 0 or event["event"] != "source_binding_frozen" for event in events
    ):
        _fail("Review A tasks require exact initialized pre-start custody state")
    if task_root.exists():
        _fail("refusing to overwrite reviewer task root")
    task_root.mkdir(parents=True, mode=0o700)
    packets = {
        (str(item["repository"]).casefold(), int(item["pr"])): item
        for item in manifest["source_packet_hashes"]
    }
    outputs: list[Path] = []
    for binding in manifest["source_bindings"]:
        key = str(binding["repository"]).casefold(), int(binding["pr"])
        task = {
            "schema_version": 1,
            "task_type": "blind_ground_truth_review",
            "lane": "A",
            "execution_manifest_sha256": manifest_hash,
            "packet_path": packets[key]["packet_path"],
            "packet_manifest_sha256": packets[key]["packet_manifest_sha256"],
            "corpus_id": binding["corpus_id"],
            "repository": binding["repository"],
            "pr": binding["pr"],
            "snapshots": {
                "baseline_commit": binding["baseline_commit"],
                "target_commit": binding["target_commit"],
            },
            "prompt_sha256": manifest["prompt_hashes"]["review-prompt-v1.md"],
            "model_policy_sha256": manifest["policy_hashes"]["model-policy-v1.json"],
            "tool_policy_sha256": manifest["policy_hashes"]["tool-policy-v1.json"],
            "source_policy_sha256": manifest["policy_hashes"]["source-policy-v1.json"],
            "reviewer": {
                "kind": "agent",
                "name": _AGENT_NAME,
                "version": f"{_PROVIDER}/{_MODEL}",
            },
            "model": {"provider": _PROVIDER, "id": _MODEL, "thinking": "high"},
            "limits": {
                "max_tokens": 100_000,
                "max_tool_calls": 200,
                "max_seconds": 1800,
                "max_output_bytes": 2_097_152,
            },
            "forbidden_inputs": [
                "predictions",
                "scores",
                "route_census",
                "vendor_output",
                "prior_labels",
                "review_b",
                "adjudications",
            ],
        }
        output = (
            task_root / f"{str(binding['repository']).replace('/', '--')}--{binding['pr']}.json"
        )
        _atomic_no_clobber(output, _canonical(task))
        outputs.append(output)
    return outputs


def _optional_digest(value: str | None) -> str | None:
    if value is None:
        return None
    if _DIGEST.fullmatch(value) is None:
        _fail("CLI digest is invalid")
    return value


def main() -> int:  # noqa: PLR0915 - explicit private custody CLI
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--agent-config", required=True, type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--ledger", type=Path)
    parser.add_argument("--cache-root", type=Path)
    parser.add_argument("--packet-root", type=Path)
    parser.add_argument("--execution-root", type=Path)
    parser.add_argument("--occurred-at")
    parser.add_argument("--supervisor-actor", default="benchmark-parent-supervisor")
    parser.add_argument("--supervisor-session-path")
    parser.add_argument("--repository")
    parser.add_argument("--pr", type=int)
    parser.add_argument("--event")
    parser.add_argument("--attempt-id")
    parser.add_argument("--input-sha256")
    parser.add_argument("--output-sha256")
    parser.add_argument("--transcript-sha256")
    parser.add_argument("--telemetry-sha256")
    parser.add_argument("--incident-kind")
    parser.add_argument("--retry-of-attempt-id")
    parser.add_argument("--task-root", type=Path)
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--freeze-execution", action="store_true")
    actions.add_argument("--initialize-ledger", action="store_true")
    actions.add_argument("--append-event", action="store_true")
    actions.add_argument("--validate", action="store_true")
    actions.add_argument("--write-review-a-tasks", action="store_true")
    args = parser.parse_args()
    if args.freeze_execution:
        if not all((args.cache_root, args.packet_root, args.execution_root, args.occurred_at)):
            parser.error("freeze execution requires private roots and --occurred-at")
        if args.supervisor_session_path is None:
            parser.error("--freeze-execution requires --supervisor-session-path")
        path, digest = freeze_execution(
            args.root,
            args.cache_root,
            args.packet_root,
            args.agent_config,
            args.execution_root,
            created_at=args.occurred_at,
            approval_at=args.occurred_at,
            supervisor_actor=args.supervisor_actor,
            supervisor_session_path=args.supervisor_session_path,
        )
        print(json.dumps({"manifest": str(path), "sha256": digest}, sort_keys=True))
        return 0
    if args.manifest is None:
        parser.error("action requires --manifest")
    if args.cache_root is None or args.packet_root is None:
        parser.error("action requires --cache-root and --packet-root")
    manifest_data, _manifest_digest = _manifest(
        args.manifest, args.agent_config, args.cache_root, args.packet_root
    )
    canonical_ledger = _declared_ledger_path(manifest_data, args.ledger)
    if args.initialize_ledger:
        if args.occurred_at is None:
            parser.error("initialize ledger requires --occurred-at")
        initialize_ledger(
            canonical_ledger,
            args.manifest,
            args.agent_config,
            args.cache_root,
            args.packet_root,
            occurred_at=args.occurred_at,
            supervisor_actor=args.supervisor_actor,
        )
        print(json.dumps({"ledger": str(canonical_ledger), "events": 3}, sort_keys=True))
        return 0
    if args.append_event:
        if None in (args.repository, args.pr, args.event, args.occurred_at):
            parser.error("append requires identity, event, and timestamp")
        event = append_event(
            canonical_ledger,
            args.manifest,
            args.agent_config,
            args.cache_root,
            args.packet_root,
            repository=args.repository,
            pr=args.pr,
            event_name=args.event,
            occurred_at=args.occurred_at,
            supervisor_actor=args.supervisor_actor,
            attempt_id=args.attempt_id,
            input_sha256=_optional_digest(args.input_sha256),
            output_sha256=_optional_digest(args.output_sha256),
            transcript_sha256=_optional_digest(args.transcript_sha256),
            telemetry_sha256=_optional_digest(args.telemetry_sha256),
            incident_kind=args.incident_kind,
            retry_of_attempt_id=args.retry_of_attempt_id,
        )
        print(json.dumps({"event_sha256": event["event_sha256"]}, sort_keys=True))
        return 0
    if args.write_review_a_tasks:
        if args.task_root is None:
            parser.error("task generation requires --task-root")
        outputs = write_review_a_tasks(
            args.task_root,
            args.manifest,
            args.agent_config,
            args.cache_root,
            args.packet_root,
        )
        print(json.dumps({"tasks": [str(path) for path in outputs]}, sort_keys=True))
        return 0
    events = validate_ledger(
        canonical_ledger,
        args.manifest,
        args.agent_config,
        args.cache_root,
        args.packet_root,
    )
    print(json.dumps({"events": len(events)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
