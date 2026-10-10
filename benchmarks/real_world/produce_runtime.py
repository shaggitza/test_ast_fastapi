#!/usr/bin/env python3
"""Produce no-clobber paired secure/runtime artifacts for one frozen snapshot.

Runtime imports remain fail-closed: a caller must provide a matching trusted host
receipt before the runtime adapter can launch. This module produces comparison
inputs only and never writes benchmark truth or aggregate results.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Protocol

if __package__ in {None, ""}:
    checkout_root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(checkout_root / "src"))
    sys.path.insert(1, str(checkout_root))

from benchmarks.real_world._secure_publish import (
    SecurePathError,
    ensure_publishable,
    publish_exclusive_batch,
)
from benchmarks.real_world.benchmark_schema import BenchmarkSchemaError, strict_json_loads
from benchmarks.real_world.compare_runtime import (
    ComparisonError,
    _validate,
    compare_target_baseline,
)

from fastapi_endpoint_detector.analyzer.framework_phase_runtime import PhaseManifest
from fastapi_endpoint_detector.analyzer.runtime_custody import (
    CustodyBinding,
    RuntimeCustodyError,
    custody_digest,
    runtime_custody_authority_from_environment,
    runtime_record_request_digest,
    verify_runtime_custody,
)
from fastapi_endpoint_detector.executor.vm_executor import VMExecutor, VMExecutorError

if TYPE_CHECKING:
    from collections.abc import Iterator

Mode = Literal["secure", "runtime"]
Snapshot = Literal["target", "baseline"]
MODES: tuple[Mode, ...] = ("secure", "runtime")
IMAGE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")
PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROTECTED_ROOTS = (PROJECT_ROOT / "benchmarks",)


class ProducerError(ValueError):
    """Invalid pinned input, unsafe publication request, or rejected runtime gate."""


@dataclass(frozen=True)
class SnapshotInput:
    """An already materialized immutable target or baseline checkout."""

    side: Snapshot
    app_path: Path
    diff_path: Path
    source_revision: str
    dependency_lock: Path
    source_snapshot_lock: Path
    runtime_image: str
    sbom: Path
    diff_path_sha256: str = ""


@dataclass(frozen=True)
class EntryConfiguration:
    app_entry: str | None
    bootstrap_entry: str | None
    app_variable: str
    backend: str


@dataclass(frozen=True)
class TrustedRuntimeEvidence:
    """Signed host receipt; the signing key is configured outside the receipt."""

    status: str
    host_boundary: str
    runtime_version: str
    image_digest: str
    dependency_lock_sha256: str
    snapshot_lock_sha256: str
    sbom_sha256: str
    seccomp_sha256: str
    policy_sha256: str
    canary_receipt_sha256: str
    key_id: str = ""
    issued_at: int = 0
    expires_at: int = 0
    request_sha256: str = ""
    signature: str = ""


@dataclass(frozen=True)
class InvocationResult:
    inventory: dict[str, Any] | None = None
    impact: dict[str, Any] | None = None
    seconds: float | None = None
    peak_rss_bytes: int | None = None
    custody_receipt: dict[str, Any] | None = None
    phase_manifest: dict[str, Any] | None = None
    phase_observation: dict[str, Any] | None = None


class ArtifactRunner(Protocol):
    def __call__(
        self,
        mode: Mode,
        phase: Literal["list", "impact"],
        request: RunRequest,
    ) -> InvocationResult: ...


@dataclass(frozen=True)
class RunRequest:
    snapshot: SnapshotInput
    configuration: EntryConfiguration
    dependency_lock_sha256: str
    snapshot_lock_sha256: str
    runtime_image: str
    sbom_sha256: str
    seccomp_sha256: str
    runtime_policy_sha256: str
    custody_binding: CustodyBinding | None = None
    phase_manifest_state: dict[str, Any] | None = None
    phase_manifest_source_root: Path | None = None


def _run_runtime_phase(phase: Literal["list", "impact"], request: RunRequest) -> InvocationResult:
    config = request.configuration
    executor = VMExecutor(
        image=request.runtime_image,
        dependency_lock_hash=request.dependency_lock_sha256,
        snapshot_lock_hash=request.snapshot_lock_sha256,
        sbom_hash=request.sbom_sha256,
        seccomp_hash=request.seccomp_sha256,
        expected_policy_sha256=request.runtime_policy_sha256,
    )
    started = time.monotonic()
    try:
        phase_manifest = request.phase_manifest_state
        if not isinstance(phase_manifest, dict):
            raise PhaseFailure("unavailable", "static runtime phase manifest is unavailable")
        try:
            PhaseManifest.model_validate(phase_manifest)
        except (ImportError, TypeError, ValueError) as error:
            raise PhaseFailure(
                "unavailable", "static runtime phase coverage is conditional"
            ) from error
        payload = executor.analyze_in_vm(
            app_path=request.snapshot.app_path,
            diff_path=request.snapshot.diff_path if phase == "impact" else None,
            app_variable=config.app_variable,
            output_format="json",
            app_entry=config.app_entry,
            bootstrap_entry=config.bootstrap_entry,
            phase_manifest=phase_manifest,
            phase_manifest_source_root=request.phase_manifest_source_root,
        )
    except VMExecutorError as error:
        raise PhaseFailure(_failure_phase(str(error)), str(error)) from error
    elapsed = time.monotonic() - started
    if not isinstance(payload, dict):
        raise PhaseFailure("extraction", f"runtime {phase} output must be an object")
    worker_phase = "list" if phase == "list" else "analyze"
    if payload.get("status") != "ok" or payload.get("phase") != worker_phase:
        message = payload.get("message")
        raise PhaseFailure(
            _failure_phase(message if isinstance(message, str) else "runtime worker error"),
            message if isinstance(message, str) else "runtime worker returned an error",
        )
    telemetry = payload.get("telemetry")
    peak = (
        telemetry.get("container_peak_rss_bytes")
        if isinstance(telemetry, dict)
        and telemetry.get("container_peak_rss_status") == "measured"
        and telemetry.get("source") == "sampled-/proc/[pid]/statm"
        else None
    )
    peak_rss = peak if isinstance(peak, int) and not isinstance(peak, bool) and peak >= 0 else None
    if phase == "list":
        endpoints = payload.get("endpoints")
        if not isinstance(endpoints, list):
            raise PhaseFailure("extraction", "runtime list output lacks endpoints")
        return InvocationResult(
            inventory={"inventory_status": "runtime_observed", "endpoints": endpoints},
            seconds=elapsed,
            peak_rss_bytes=peak_rss,
            phase_manifest=phase_manifest,
            phase_observation=payload.get("phase_observation"),
        )
    candidates = payload.get("candidate_endpoints")
    if not isinstance(candidates, list):
        raise PhaseFailure("extraction", "runtime impact output lacks candidate_endpoints")
    return InvocationResult(
        impact={"candidate_endpoints": candidates},
        seconds=elapsed,
        peak_rss_bytes=peak_rss,
        phase_manifest=phase_manifest,
        phase_observation=payload.get("phase_observation"),
    )


def _invocation_payload(result: InvocationResult) -> dict[str, Any]:
    payload = {
        "inventory": result.inventory,
        "impact": result.impact,
        "seconds": result.seconds,
        "peak_rss_bytes": result.peak_rss_bytes,
    }
    if result.phase_manifest is not None:
        payload["phase_manifest"] = result.phase_manifest
    if result.phase_observation is not None:
        payload["phase_observation"] = result.phase_observation
    return payload


def _broker_runtime_invocation(
    phase: Literal["list", "impact"], request: RunRequest
) -> InvocationResult:
    """Issue custody only after this host broker owns the gated VM invocation.

    Signing material stays in the trusted host process; it is never sent to
    the worker. This path cannot attest an arbitrary caller-supplied result.
    """
    binding = request.custody_binding
    if binding is None:
        raise ProducerError("runtime broker requires a fresh host challenge")
    authority = runtime_custody_authority_from_environment()
    if binding.runtime_version != authority.runtime_version or binding.phase != phase:
        raise ProducerError("runtime broker challenge conflicts with operator pins")
    result = _run_runtime_phase(phase, request)
    issued_at = int(time.time())
    receipt = {
        "binding": binding.model_dump(mode="json"),
        "result_sha256": custody_digest(_invocation_payload(result)),
        "key_id": authority.key_id,
        "issued_at": issued_at,
        "expires_at": issued_at + authority.max_validity_seconds,
    }
    signature = hmac.new(
        authority.secret,
        json.dumps(receipt, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(),
        hashlib.sha256,
    ).hexdigest()
    return replace(result, custody_receipt={**receipt, "signature": signature})


class CommandRunner:
    """Run the installed CLI in secure AST or gated VM mode."""

    def __init__(self, *, timeout_seconds: float = 600) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.timeout_seconds = timeout_seconds

    def __call__(  # noqa: PLR0912, PLR0915
        self,
        mode: Mode,
        phase: Literal["list", "impact"],
        request: RunRequest,
    ) -> InvocationResult:
        config = request.configuration
        app = request.snapshot.app_path
        if mode == "runtime":
            return _broker_runtime_invocation(phase, request)

        args = [
            sys.executable,
            "-m",
            "fastapi_endpoint_detector",
            "list" if phase == "list" else "analyze",
            "--app",
            str(app),
            "--format",
            "json",
            "--app-var",
            config.app_variable,
        ]
        if phase == "impact":
            args.extend(["--diff", str(request.snapshot.diff_path), "--no-cache"])
            if config.backend == "scip":
                args.append("--scip")
        args.append("--secure-ast")
        if config.app_entry:
            args.extend(["--app-entry", config.app_entry])
        if config.bootstrap_entry:
            args.extend(["--bootstrap-entry", config.bootstrap_entry])
        environment = os.environ.copy()
        started = time.monotonic()
        try:
            # This producer compares the canonical framework catalog explicitly;
            # project-controlled configuration files never select its authority.
            with tempfile.TemporaryDirectory(prefix="framework-phase-config-") as directory:
                config_path = Path(directory) / "config.json"
                config_path.write_text(
                    json.dumps({"analysis": {"surface_preset": "framework-v1"}}),
                    encoding="utf-8",
                )
                args[3:3] = ["--config", str(config_path)]
                completed = subprocess.run(
                    args,
                    cwd=app if app.is_dir() else app.parent,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=self.timeout_seconds,
                    env=environment,
                )
        except subprocess.TimeoutExpired as error:
            raise PhaseFailure("timeout", f"{phase} command timed out") from error
        except OSError as error:
            raise PhaseFailure(
                "unavailable", f"could not start {phase} command: {error}"
            ) from error
        elapsed = time.monotonic() - started
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()[:1000] or "no diagnostic output"
            raise PhaseFailure(_failure_phase(detail), detail)
        payload = _decode_cli_json(completed.stdout, phase)
        if not isinstance(payload, dict):
            raise PhaseFailure("extraction", f"{phase} output must be an object")
        if phase == "list":
            if mode == "secure":
                if not isinstance(payload.get("inventory_status"), str):
                    raise PhaseFailure("extraction", "secure list lacks inventory status")
                inventory = {
                    "inventory_status": payload["inventory_status"],
                    "endpoints": payload.get("endpoints"),
                }
            else:
                inventory = {
                    "inventory_status": "runtime_observed",
                    "endpoints": payload.get("endpoints"),
                }
            return InvocationResult(inventory=inventory, seconds=elapsed)
        candidates = payload.get("candidate_endpoints")
        if not isinstance(candidates, list):
            raise PhaseFailure("extraction", "impact output lacks candidate_endpoints")
        phase_report = payload.get("framework_phase_report")
        if isinstance(phase_report, dict) and isinstance(
            phase_report.get("runtime_manifest"), dict
        ):
            try:
                manifest = PhaseManifest.model_validate(phase_report["runtime_manifest"])
            except (ImportError, TypeError, ValueError) as error:
                raise PhaseFailure(
                    "extraction", "secure phase manifest failed validation"
                ) from error
            if request.phase_manifest_state is not None:
                manifest_value = manifest.model_dump(mode="json")
                if phase_report.get("backend") == "unavailable" or phase_report.get(
                    "lifecycle_conditional_surfaces"
                ):
                    request.phase_manifest_state.clear()
                    request.phase_manifest_state.update({"conditional": True})
                    return InvocationResult(
                        impact={"candidate_endpoints": candidates}, seconds=elapsed
                    )
                source_root = request.phase_manifest_source_root
                if source_root is None:
                    raise PhaseFailure("extraction", "phase manifest source root is unavailable")
                for entry in manifest_value["entries"]:
                    for identity_name in ("callback", "registration"):
                        identity = entry[identity_name]
                        staged_file = Path(identity["file"]).resolve(strict=True)
                        try:
                            relative = staged_file.relative_to(app.resolve(strict=True))
                            original_file = (
                                source_root.resolve(strict=True)
                                if not source_root.is_dir()
                                else (source_root / relative).resolve(strict=True)
                            )
                        except (OSError, ValueError) as error:
                            raise PhaseFailure(
                                "extraction", "phase manifest source is outside staged app"
                            ) from error
                        identity["file"] = str(original_file)
                request.phase_manifest_state.clear()
                request.phase_manifest_state.update(manifest_value)
        return InvocationResult(impact={"candidate_endpoints": candidates}, seconds=elapsed)


def _decode_cli_json(output: str, phase: Literal["list", "impact"]) -> dict[str, Any]:
    decoder = json.JSONDecoder()
    start = output.find("{")
    while start >= 0:
        try:
            value, end = decoder.raw_decode(output[start:])
        except json.JSONDecodeError:
            start = output.find("{", start + 1)
            continue
        if isinstance(value, dict):
            expected = {"candidate_endpoints"} if phase == "impact" else {"endpoints"}
            if expected <= value.keys():
                return value
        start = output.find("{", start + max(end, 1))
    raise PhaseFailure("extraction", f"{phase} returned no recognized JSON object")


class PhaseFailure(Exception):
    def __init__(self, phase: str, message: str) -> None:
        self.phase = phase
        super().__init__(message or phase)


def _failure_phase(message: str) -> str:
    lowered = message.lower()
    if any(word in lowered for word in ("dependency", "mypy", "scip", "lock file", "package")):
        return "dependency"
    if "import" in lowered or ("module" in lowered and "not found" in lowered):
        return "import"
    if any(word in lowered for word in ("app", "factory", "bootstrap", "entry")):
        return "app_resolution"
    if "timeout" in lowered or "timed out" in lowered:
        return "timeout"
    if any(word in lowered for word in ("docker", "image", "runtime", "sandbox", "gvisor", "kata")):
        return "unavailable"
    return "extraction"


def _sha256_bytes(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _hash_file(path: Path, label: str) -> str:
    try:
        if path.is_symlink() or not path.is_file():
            raise ProducerError(f"{label} must be a regular, non-symlinked file: {path}")
        return _sha256_bytes(path.read_bytes())
    except OSError as error:
        raise ProducerError(f"cannot read {label} {path}: {error}") from error


def _source_digest(root: Path) -> str:
    """Hash regular source files deterministically without following symlinks."""
    digest = hashlib.sha256()
    ignored = {".git", ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache"}
    try:
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root)
            if any(part in ignored for part in relative.parts):
                continue
            mode = path.lstat().st_mode
            if path.is_symlink():
                raise ProducerError(f"snapshot source contains symlink: {relative}")
            if path.is_file():
                encoded = relative.as_posix().encode("utf-8")
                content = path.read_bytes()
                digest.update(len(encoded).to_bytes(8, "big"))
                digest.update(encoded)
                digest.update(len(content).to_bytes(8, "big"))
                digest.update(content)
            elif not stat.S_ISDIR(mode):
                raise ProducerError(f"snapshot source contains special file: {relative}")
    except OSError as error:
        raise ProducerError(f"cannot hash snapshot source {root}: {error}") from error
    return f"sha256:{digest.hexdigest()}"


def _verify_source_revision(app_path: Path, expected: str) -> Path:
    """Require the materialized snapshot checkout to be exactly the declared commit."""
    try:
        completed = subprocess.run(
            ["git", "-C", str(app_path), "rev-parse", "--show-toplevel", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ProducerError("cannot verify pinned snapshot git revision") from error
    fields = completed.stdout.strip().splitlines()
    if completed.returncode or len(fields) != 2 or fields[1].lower() != expected:
        raise ProducerError(f"materialized source revision does not match pin {expected}")
    root = Path(fields[0]).resolve(strict=True)
    try:
        status = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=all"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ProducerError("cannot verify snapshot checkout cleanliness") from error
    if status.returncode or status.stdout.strip():
        raise ProducerError("materialized snapshot checkout has uncommitted or untracked files")
    return root


def _tool_digest() -> str:
    package = PROJECT_ROOT / "src" / "fastapi_endpoint_detector"
    digest = hashlib.sha256()
    inputs = [
        package,
        PROJECT_ROOT / "benchmarks/real_world/produce_runtime.py",
        PROJECT_ROOT / "benchmarks/real_world/compare_runtime.py",
        PROJECT_ROOT / "benchmarks/real_world/benchmark_schema.py",
        PROJECT_ROOT / "benchmarks/real_world/_secure_publish.py",
        PROJECT_ROOT / "pyproject.toml",
        PROJECT_ROOT / "uv.lock",
    ]
    for path in inputs:
        if path.is_dir():
            content = _source_digest(path).encode()
            name = path.relative_to(PROJECT_ROOT).as_posix()
        else:
            content = path.read_bytes()
            name = path.relative_to(PROJECT_ROOT).as_posix()
        encoded = name.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return f"sha256:{digest.hexdigest()}"


def _revalidate_lane(request: RunRequest, source_hash: str, tool_hash: str) -> None:
    """Recheck every pinned input immediately before each list/impact invocation."""
    source_root = _verify_source_revision(
        request.snapshot.app_path, request.snapshot.source_revision
    )
    if _source_digest(source_root) != source_hash:
        raise ProducerError("snapshot source changed after producer preflight")
    if _tool_digest() != tool_hash:
        raise ProducerError("producer tool changed after producer preflight")
    if _hash_file(request.snapshot.diff_path, "impact diff") != request.snapshot.diff_path_sha256:
        raise ProducerError("impact diff changed after producer preflight")
    if (
        _hash_file(request.snapshot.dependency_lock, "dependency lock")
        != request.dependency_lock_sha256
    ):
        raise ProducerError("dependency lock changed after producer preflight")
    if (
        _hash_file(request.snapshot.source_snapshot_lock, "source snapshot lock")
        != request.snapshot_lock_sha256
    ):
        raise ProducerError("source snapshot lock changed after producer preflight")
    if _hash_file(request.snapshot.sbom, "snapshot SBOM") != request.sbom_sha256:
        raise ProducerError("snapshot SBOM changed after producer preflight")
    seccomp = (
        PROJECT_ROOT / "src/fastapi_endpoint_detector/executor/policies/runtime-seccomp-v1.json"
    )
    if _hash_file(seccomp, "packaged seccomp policy") != request.seccomp_sha256:
        raise ProducerError("packaged seccomp policy changed after producer preflight")


@contextmanager
def _frozen_lane_request(
    request: RunRequest, source_hash: str, tool_hash: str
) -> Iterator[RunRequest]:
    """Run each phase against a private read-only copy and recheck all pins around it."""
    _revalidate_lane(request, source_hash, tool_hash)
    source_root = _verify_source_revision(
        request.snapshot.app_path, request.snapshot.source_revision
    )
    ignored = {".git", ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache"}
    with tempfile.TemporaryDirectory(prefix="secure-runtime-lane-") as temporary_name:
        temporary = Path(temporary_name)
        staged_root = temporary / "source"
        shutil.copytree(
            source_root,
            staged_root,
            ignore=lambda _directory, names: {name for name in names if name in ignored},
        )
        if _source_digest(staged_root) != source_hash:
            raise ProducerError("snapshot source changed while staging the pinned lane")
        try:
            app_relative = request.snapshot.app_path.relative_to(source_root)
        except ValueError as error:
            raise ProducerError("application path is outside the pinned source checkout") from error
        staged_app = staged_root / app_relative
        staged_diff = temporary / "change.diff"
        shutil.copyfile(request.snapshot.diff_path, staged_diff)
        if _hash_file(staged_diff, "staged impact diff") != request.snapshot.diff_path_sha256:
            raise ProducerError("impact diff changed while staging the pinned lane")
        for path in sorted((*staged_root.rglob("*"), staged_root), reverse=True):
            current_mode = path.stat(follow_symlinks=False).st_mode
            path.chmod(stat.S_IMODE(current_mode) & ~0o222)
        staged_diff.chmod(0o444)
        staged_snapshot = replace(
            request.snapshot,
            app_path=staged_app,
            diff_path=staged_diff,
        )
        staged_request = replace(request, snapshot=staged_snapshot)
        _revalidate_lane(request, source_hash, tool_hash)
        try:
            yield staged_request
        finally:
            manifest_state = staged_request.phase_manifest_state
            if (
                isinstance(manifest_state, dict)
                and manifest_state
                and (
                    set(manifest_state) != {"conditional"}
                    or manifest_state["conditional"] is not True
                )
            ):
                PhaseManifest.model_validate(manifest_state)
            if _source_digest(staged_root) != source_hash:
                raise ProducerError("read-only staged source changed during lane execution")
            if _hash_file(staged_diff, "staged impact diff") != request.snapshot.diff_path_sha256:
                raise ProducerError("staged impact diff changed during lane execution")
            _revalidate_lane(request, source_hash, tool_hash)


def _runtime_policy_digest(request_values: dict[str, str]) -> str:
    """Match VMExecutor.policy_provenance() for its exact default launch policy."""
    policy = {
        "version": 1,
        "runtime": "runsc",
        "user": "65532:65532",
        "memory_limit": "512m",
        "memory_swap": "512m",
        "cpu_quota": 50000,
        "cpu_period": 100000,
        "pids_limit": 128,
        "nofile_limit": 256,
        "nproc_limit": 128,
        "fsize_limit_kib": 16384,
        "tmpfs_size": "64m",
        "output_limit_bytes": 4 * 1024 * 1024,
    }
    clean_env = {
        "HOME": "/tmp/home",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "TMPDIR": "/tmp",
    }
    payload = {
        "policy": policy,
        "image": request_values["image"],
        "seccomp_sha256": request_values["seccomp_sha256"],
        "environment": dict(sorted(clean_env.items())),
        "dependency_lock_hash": request_values["dependency_lock_sha256"],
        "snapshot_lock_hash": request_values["snapshot_lock_sha256"],
        "sbom_hash": request_values["sbom_sha256"],
    }
    return _sha256_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())


def _request_digest(request: RunRequest) -> str:
    payload = {
        "source_sha256": _source_digest(request.snapshot.app_path),
        "source_revision": request.snapshot.source_revision,
        "snapshot": request.snapshot.side,
        "diff_sha256": _hash_file(request.snapshot.diff_path, "diff"),
        "app_entry": request.configuration.app_entry,
        "bootstrap_entry": request.configuration.bootstrap_entry,
        "app_variable": request.configuration.app_variable,
        "backend": request.configuration.backend,
        "dependency_lock_sha256": request.dependency_lock_sha256,
        "snapshot_lock_sha256": request.snapshot_lock_sha256,
        "image_digest": request.runtime_image,
        "sbom_sha256": request.sbom_sha256,
        "seccomp_sha256": request.seccomp_sha256,
        "policy_sha256": request.runtime_policy_sha256,
    }
    return (
        "sha256:"
        + hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )


def _evidence_payload(evidence: TrustedRuntimeEvidence) -> dict[str, Any]:
    return {
        "status": evidence.status,
        "host_boundary": evidence.host_boundary,
        "runtime_version": evidence.runtime_version,
        "image_digest": evidence.image_digest,
        "dependency_lock_sha256": evidence.dependency_lock_sha256,
        "snapshot_lock_sha256": evidence.snapshot_lock_sha256,
        "sbom_sha256": evidence.sbom_sha256,
        "seccomp_sha256": evidence.seccomp_sha256,
        "policy_sha256": evidence.policy_sha256,
        "canary_receipt_sha256": evidence.canary_receipt_sha256,
        "key_id": evidence.key_id,
        "issued_at": evidence.issued_at,
        "expires_at": evidence.expires_at,
        "request_sha256": evidence.request_sha256,
    }


def _validate_evidence(evidence: TrustedRuntimeEvidence | None, request: RunRequest) -> None:
    """Authenticate a fresh host receipt against an out-of-band HMAC trust anchor."""
    key = os.environ.get("FASTAPI_DETECTOR_RUNTIME_TRUST_KEY")
    configured_key_id = os.environ.get("FASTAPI_DETECTOR_RUNTIME_TRUST_KEY_ID")
    configured_runtime_version = os.environ.get("FASTAPI_DETECTOR_RUNTIME_TRUST_VERSION")
    if not key or not configured_key_id or not configured_runtime_version:
        raise ProducerError("runtime gate closed: no independently trusted authority is configured")
    if evidence is None:
        raise ProducerError("runtime gate closed: signed host receipt is missing")
    expected = {
        "status": "passed",
        "host_boundary": "gvisor",
        "runtime_version": configured_runtime_version,
        "image_digest": request.runtime_image,
        "dependency_lock_sha256": request.dependency_lock_sha256,
        "snapshot_lock_sha256": request.snapshot_lock_sha256,
        "sbom_sha256": request.sbom_sha256,
        "seccomp_sha256": request.seccomp_sha256,
        "policy_sha256": request.runtime_policy_sha256,
        "request_sha256": _request_digest(request),
        "key_id": configured_key_id,
    }
    payload = _evidence_payload(evidence)
    for field, value in expected.items():
        if payload[field] != value:
            raise ProducerError(f"runtime receipt pin mismatch: {field}")
    if any(
        not isinstance(value, str) or not value
        for name, value in payload.items()
        if name not in {"issued_at", "expires_at"}
    ) or not isinstance(evidence.signature, str):
        raise ProducerError("runtime receipt has invalid field types")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", evidence.canary_receipt_sha256):
        raise ProducerError("runtime receipt canary digest is malformed")
    now = int(time.time())
    if (
        type(evidence.issued_at) is not int
        or type(evidence.expires_at) is not int
        or evidence.issued_at <= 0
        or evidence.issued_at >= evidence.expires_at
        or evidence.expires_at <= now
        or evidence.issued_at > now + 60
        or evidence.expires_at - evidence.issued_at > 3600
    ):
        raise ProducerError("runtime receipt is stale, expired, or has an invalid validity window")
    signature = evidence.signature
    if not re.fullmatch(r"[0-9a-f]{64}", signature):
        raise ProducerError("runtime receipt signature is malformed")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    expected_signature = hmac.new(key.encode(), canonical, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected_signature):
        raise ProducerError("runtime receipt signature authentication failed")


def _measured(seconds: float | None) -> dict[str, Any]:
    if seconds is None:
        return {"status": "not_measured", "reason": "phase_not_completed"}
    return {"status": "measured", "seconds": seconds}


def _invoke_record_phase(
    mode: Mode,
    phase: Literal["list", "impact"],
    request: RunRequest,
    record: dict[str, Any],
    runner: ArtifactRunner,
    evidence: TrustedRuntimeEvidence | None,
) -> InvocationResult:
    if mode == "secure":
        return runner(mode, phase, request)
    authority = runtime_custody_authority_from_environment()
    assert evidence is not None
    binding = CustodyBinding(
        snapshot=request.snapshot.side,
        phase=phase,
        nonce=secrets.token_hex(16),
        request_sha256=runtime_record_request_digest(record),
        canary_receipt_sha256=evidence.canary_receipt_sha256,
        runtime_version=authority.runtime_version,
    )
    result = runner(mode, phase, replace(request, custody_binding=binding))
    receipt = verify_runtime_custody(
        result.custody_receipt,
        expected=binding,
        result=_invocation_payload(result),
        authority=authority,
        now=int(time.time()),
    )
    record.setdefault("runtime_custody", {})[phase] = {
        "binding": binding.model_dump(mode="json"),
        "result": _invocation_payload(result),
        "receipt": receipt.model_dump(mode="json"),
    }
    return result


def _record(  # noqa: PLR0911, PLR0912
    *,
    mode: Mode,
    snapshot: SnapshotInput,
    config: EntryConfiguration,
    request: RunRequest,
    source_hash: str,
    tool_hash: str,
    invocation_spec: dict[str, Any],
    runner: ArtifactRunner,
    evidence: TrustedRuntimeEvidence | None,
) -> dict[str, Any]:
    configuration = {
        "app_entry": config.app_entry,
        "bootstrap_entry": config.bootstrap_entry,
        "app_variable": config.app_variable,
        "backend": config.backend,
        "dependency_lock_sha256": request.dependency_lock_sha256,
    }
    provenance: dict[str, Any] = {
        "source_sha256": source_hash,
        "tool_sha256": tool_hash,
        "effective_invocation_sha256": _sha256_bytes(
            json.dumps(
                {**invocation_spec, "mode": mode},
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ),
        "dependency_lock_sha256": request.dependency_lock_sha256,
        "runtime_image_digest": request.runtime_image,
        "runtime_sbom_sha256": request.sbom_sha256,
    }
    if mode == "runtime":
        provenance.update(
            runtime_seccomp_sha256=request.seccomp_sha256,
            runtime_policy_sha256=request.runtime_policy_sha256,
            runtime_canary_receipt_sha256=(
                evidence.canary_receipt_sha256 if evidence is not None else "sha256:" + "0" * 64
            ),
            runtime_attestation_sha256=(
                "sha256:"
                + hashlib.sha256(
                    json.dumps(
                        {**_evidence_payload(evidence), "signature": evidence.signature},
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode()
                ).hexdigest()
                if evidence is not None
                else "sha256:" + "0" * 64
            ),
        )
    record: dict[str, Any] = {
        "schema_version": 1,
        "mode": mode,
        "snapshot": snapshot.side,
        "status": "failure",
        "configuration": configuration,
        "timing": {"list": _measured(None), "impact": _measured(None)},
        "resources": {
            "peak_rss_bytes": {
                "status": "not_measured",
                "reason": (
                    "phase_not_completed"
                    if mode == "runtime"
                    else "secure_host_process_rss_not_collected"
                ),
            }
        },
        "failure": {"phase": "unavailable", "message": "run not started"},
        "inventory": None,
        "impact": None,
        "provenance": provenance,
    }
    if isinstance(request.phase_manifest_state, dict) and "entries" in request.phase_manifest_state:
        record["framework_phase_manifest"] = request.phase_manifest_state
    if mode == "runtime":
        try:
            _validate_evidence(evidence, request)
        except ProducerError as error:
            record["failure"] = {"phase": "unavailable", "message": str(error)}
            return record
    results: dict[str, InvocationResult] = {}
    for phase in ("list", "impact"):
        try:
            with _frozen_lane_request(request, source_hash, tool_hash) as lane_request:
                result = _invoke_record_phase(mode, phase, lane_request, record, runner, evidence)
            if result.seconds is not None:
                record["timing"][phase] = _measured(result.seconds)
            results[phase] = result
        except PhaseFailure as error:
            record.pop("runtime_custody", None)
            record["failure"] = {"phase": error.phase, "message": str(error)[:4096]}
            return record
        except (ProducerError, RuntimeCustodyError) as error:
            record.pop("runtime_custody", None)
            record["failure"] = {"phase": "unavailable", "message": str(error)[:4096]}
            return record
        except (OSError, TimeoutError) as error:
            record.pop("runtime_custody", None)
            phase_name = "timeout" if isinstance(error, TimeoutError) else "unavailable"
            record["failure"] = {"phase": phase_name, "message": str(error)[:4096] or phase_name}
            return record
        except Exception as error:  # adapters classify; unknown errors are extraction abstentions
            record.pop("runtime_custody", None)
            record["failure"] = {
                "phase": "extraction",
                "message": str(error)[:4096] or type(error).__name__,
            }
            return record
    inventory = results["list"].inventory
    impact = results["impact"].impact
    if (
        not isinstance(inventory, dict)
        or not isinstance(inventory.get("endpoints"), list)
        or not isinstance(inventory.get("inventory_status"), str)
        or not isinstance(impact, dict)
        or not isinstance(impact.get("candidate_endpoints"), list)
    ):
        record.pop("runtime_custody", None)
        record["failure"] = {
            "phase": "extraction",
            "message": "runner omitted complete list or impact output",
        }
        return record
    rss_values = [results[phase].peak_rss_bytes for phase in ("list", "impact")]
    if all(value is not None for value in rss_values):
        record["resources"]["peak_rss_bytes"] = {
            "status": "measured",
            "bytes": max(value for value in rss_values if value is not None),
        }
    record.update(status="success", failure=None, inventory=inventory, impact=impact)
    static_manifest = request.phase_manifest_state
    if isinstance(static_manifest, dict) and "entries" in static_manifest:
        record["framework_phase_manifest"] = static_manifest
    if mode == "runtime":
        manifest = results["list"].phase_manifest
        observations = {phase: results[phase].phase_observation for phase in ("list", "impact")}
        if isinstance(manifest, dict) and all(
            isinstance(item, dict) for item in observations.values()
        ):
            record["framework_phase"] = {
                "manifest": manifest,
                "observations": observations,
                "role": "positive_observation_only",
            }
    return record


def produce_snapshot_pair(
    snapshot: SnapshotInput,
    configuration: EntryConfiguration,
    output_directory: Path,
    *,
    runner: ArtifactRunner | None = None,
    runtime_evidence: TrustedRuntimeEvidence | None = None,
) -> dict[Mode, Path]:
    """Produce secure/runtime schema-v1 files for one pinned target/baseline snapshot."""
    if snapshot.app_path.is_symlink():
        raise ProducerError("app_path cannot be a symlink")
    app_path = snapshot.app_path.resolve(strict=True)
    if not (app_path.is_dir() or app_path.is_file()):
        raise ProducerError("app_path must resolve to a regular file or directory")
    if snapshot.diff_path.is_symlink():
        raise ProducerError("diff_path cannot be a symlink")
    diff_path = snapshot.diff_path.resolve(strict=True)
    if not diff_path.is_file():
        raise ProducerError("diff_path must be a regular non-symlinked file")
    if not re.fullmatch(r"[0-9a-f]{40,64}", snapshot.source_revision):
        raise ProducerError("source_revision must be a full lowercase git object id")
    lock_hash = _hash_file(snapshot.dependency_lock, "snapshot dependency lock")
    source_snapshot_lock_hash = _hash_file(snapshot.source_snapshot_lock, "source snapshot lock")
    sbom_hash = _hash_file(snapshot.sbom, "snapshot SBOM")
    if not IMAGE.fullmatch(snapshot.runtime_image):
        raise ProducerError("runtime_image must be an immutable registry image digest")
    if not configuration.app_variable.strip() or configuration.backend not in {"mypy", "scip"}:
        raise ProducerError("app_variable and supported backend are required")
    source_root = _verify_source_revision(app_path, snapshot.source_revision)
    source_hash = _source_digest(source_root)
    tool_hash = _tool_digest()
    seccomp_path = (
        PROJECT_ROOT / "src/fastapi_endpoint_detector/executor/policies/runtime-seccomp-v1.json"
    )
    seccomp_hash = _hash_file(seccomp_path, "packaged seccomp policy")
    policy_hash = _runtime_policy_digest(
        {
            "image": snapshot.runtime_image,
            "dependency_lock_sha256": lock_hash,
            "snapshot_lock_sha256": source_snapshot_lock_hash,
            "sbom_sha256": sbom_hash,
            "seccomp_sha256": seccomp_hash,
        }
    )
    diff_hash = _hash_file(diff_path, "impact diff")
    request = RunRequest(
        snapshot=replace(
            snapshot,
            app_path=app_path,
            diff_path=diff_path,
            diff_path_sha256=diff_hash,
        ),
        configuration=configuration,
        dependency_lock_sha256=lock_hash,
        snapshot_lock_sha256=source_snapshot_lock_hash,
        runtime_image=snapshot.runtime_image,
        sbom_sha256=sbom_hash,
        seccomp_sha256=seccomp_hash,
        runtime_policy_sha256=policy_hash,
        phase_manifest_state={},
        phase_manifest_source_root=app_path,
    )
    invocation = {
        "program": "fastapi-endpoint-detector",
        "list_and_impact": True,
        "mode_options": {
            "secure": ["--secure-ast"],
            "runtime": ["runtime-worker-protocol-v3"],
        },
        "runtime_worker": {
            "module": "fastapi_endpoint_detector.parser.runtime_worker",
            "protocol_version": 3,
            "phases": ["list", "analyze"],
            "bounded_source_config": {
                "dependency_max_depth": 10,
                "dependency_max_nodes": 4096,
                "dependency_max_work": 65536,
            },
            "peak_rss_source": "container sampled /proc/[pid]/statm resident pages",
        },
        "app_path": str(app_path),
        "diff_path": str(diff_path),
        "diff_sha256": diff_hash,
        "configuration": {
            "app_entry": configuration.app_entry,
            "bootstrap_entry": configuration.bootstrap_entry,
            "app_variable": configuration.app_variable,
            "backend": configuration.backend,
            "surface_preset": "framework-v1",
        },
        "backend": configuration.backend,
        "no_cache": True,
        "source_revision": snapshot.source_revision,
        "dependency_lock_sha256": lock_hash,
        "source_snapshot_lock_sha256": source_snapshot_lock_hash,
        "runtime_image_digest": snapshot.runtime_image,
        "sbom_sha256": sbom_hash,
    }
    active_runner = runner or CommandRunner()
    artifacts: dict[Mode, dict[str, Any]] = {
        mode: _record(
            mode=mode,
            snapshot=snapshot,
            config=configuration,
            request=request,
            source_hash=source_hash,
            tool_hash=tool_hash,
            invocation_spec=invocation,
            runner=active_runner,
            evidence=runtime_evidence,
        )
        for mode in MODES
    }
    for mode, record in artifacts.items():
        try:
            _validate(record, mode)
        except ComparisonError as error:
            raise ProducerError(f"producer emitted invalid {mode} artifact: {error}") from error
    output_directory = output_directory.expanduser().absolute()
    if output_directory == PROJECT_ROOT or output_directory.is_relative_to(PROJECT_ROOT):
        raise ProducerError("refusing to publish artifacts inside the project checkout")
    published: dict[Mode, Path] = {}
    try:
        destinations = {
            mode: output_directory / f"{snapshot.side}-{mode}.json" for mode in artifacts
        }
        for destination in destinations.values():
            ensure_publishable(destination, forbidden_roots=PROTECTED_ROOTS)
        batch = [
            (
                destinations[mode],
                (json.dumps(record, indent=2, sort_keys=True, allow_nan=False) + "\n").encode(),
            )
            for mode, record in artifacts.items()
        ]
        publish_exclusive_batch(batch, forbidden_roots=PROTECTED_ROOTS)
        published.update(destinations)
    except (SecurePathError, OSError, TypeError, ValueError) as error:
        # Exclusive publication ensures no existing artifact was overwritten. A
        # second-file collision can leave the first new artifact in place, so report it.
        raise ProducerError(
            f"artifact publication stopped after {len(published)} file(s): {error}"
        ) from error
    return published


def produce_target_baseline(
    target: SnapshotInput,
    baseline: SnapshotInput,
    configuration: EntryConfiguration,
    output_directory: Path,
    *,
    runner: ArtifactRunner | None = None,
    runtime_evidence: dict[Snapshot, TrustedRuntimeEvidence] | None = None,
) -> dict[tuple[Snapshot, Mode], Path]:
    """Create the complete four-artifact matrix and publish it only after all runs finish."""
    if target.side != "target" or baseline.side != "baseline":
        raise ProducerError("target and baseline inputs must declare their matching snapshot sides")
    output_directory = output_directory.expanduser().absolute()
    if output_directory == PROJECT_ROOT or output_directory.is_relative_to(PROJECT_ROOT):
        raise ProducerError("refusing to publish artifacts inside the project checkout")
    with tempfile.TemporaryDirectory(prefix="secure-runtime-artifacts-") as staging_name:
        staging = Path(staging_name)
        staged: dict[tuple[Snapshot, Mode], Path] = {}
        for snapshot in (target, baseline):
            pair = produce_snapshot_pair(
                snapshot,
                configuration,
                staging,
                runner=runner,
                runtime_evidence=(runtime_evidence or {}).get(snapshot.side),
            )
            staged.update({(snapshot.side, mode): path for mode, path in pair.items()})
        try:
            compare_target_baseline(
                secure_target_path=staged[("target", "secure")],
                runtime_target_path=staged[("target", "runtime")],
                secure_baseline_path=staged[("baseline", "secure")],
                runtime_baseline_path=staged[("baseline", "runtime")],
            )
        except ComparisonError as error:
            raise ProducerError(f"produced matrix failed comparator validation: {error}") from error
        destinations = {key: output_directory / f"{key[0]}-{key[1]}.json" for key in staged}
        try:
            for destination in destinations.values():
                ensure_publishable(destination, forbidden_roots=PROTECTED_ROOTS)
            publish_exclusive_batch(
                [(destinations[key], source.read_bytes()) for key, source in staged.items()],
                forbidden_roots=PROTECTED_ROOTS,
            )
        except (SecurePathError, OSError) as error:
            raise ProducerError(
                f"could not publish complete target/baseline matrix: {error}"
            ) from error
    return destinations


def load_evidence(path: Path) -> TrustedRuntimeEvidence:
    """Load a host-operator trusted canary receipt; its trust is external to this tool."""
    try:
        raw = strict_json_loads(path.read_text(encoding="utf-8"), str(path))
    except (OSError, UnicodeError, BenchmarkSchemaError) as error:
        raise ProducerError(f"cannot read trusted runtime evidence: {error}") from error
    if not isinstance(raw, dict) or set(raw) != {
        "status",
        "host_boundary",
        "runtime_version",
        "image_digest",
        "dependency_lock_sha256",
        "snapshot_lock_sha256",
        "sbom_sha256",
        "seccomp_sha256",
        "policy_sha256",
        "canary_receipt_sha256",
        "key_id",
        "issued_at",
        "expires_at",
        "request_sha256",
        "signature",
    }:
        raise ProducerError("trusted runtime evidence has an unknown or incomplete schema")
    try:
        return TrustedRuntimeEvidence(**raw)
    except TypeError as error:
        raise ProducerError("trusted runtime evidence has invalid fields") from error
