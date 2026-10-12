"""GH104 controlled-synthetic phase assay preparation (test-only)."""

from __future__ import annotations

import hashlib
import json
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi_endpoint_detector.analyzer.framework_phase_integration import (
    collect_framework_phase_evidence,
)
from fastapi_endpoint_detector.analyzer.framework_phase_report import phase_report_payload
from fastapi_endpoint_detector.analyzer.framework_phase_runtime import (
    PhaseManifest,
    PhaseObservation,
    compare_phase_observation,
    manifest_from_report,
)
from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.analyzer.mypy_incremental import (
    BuildConfig,
    MypyIncrementalProvider,
)
from fastapi_endpoint_detector.executor.vm_executor import VMExecutor
from fastapi_endpoint_detector.models.surface_contract import load_surface_preset
from fastapi_endpoint_detector.parser.custom_surface_extractor import CustomSurfaceExtractor

FIXTURE_SOURCE = (
    "from fastapi import FastAPI\n\n"
    "app = FastAPI()\n\n"
    '@app.on_event("startup")\n'
    "def startup() -> None:\n"
    "    pass\n\n"
    '@app.on_event("shutdown")\n'
    "def shutdown() -> None:\n"
    "    pass\n"
)
FIXTURE_BYTES = FIXTURE_SOURCE.encode("utf-8")
FIXTURE_SHA256 = hashlib.sha256(FIXTURE_BYTES).hexdigest()
EXPECTED_PHASES = {"startup", "shutdown"}
MAX_REQUEST_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class ControlledSyntheticResult:
    role: str
    execution_claim: str
    comparison: dict[str, Any]
    host_manifest_sha256: str
    container_manifest_sha256: str
    container_manifest: dict[str, Any]


def _new_fixture_root(parent: Path | None = None) -> Path:
    """Create a fresh private directory and write the owned source exclusively."""
    root = Path(tempfile.mkdtemp(prefix="gh104-controlled-", dir=parent))
    source = root / "main.py"
    fd = source.open("xb")
    with fd:
        fd.write(FIXTURE_BYTES)
    return root


def _make_fixture_readonly(root: Path) -> None:
    """Make the bind-mounted source traversable and immutable to the worker."""
    source = root / "main.py"
    source.chmod(0o444)
    root.chmod(0o555)


def _remove_owned_fixture(root: Path) -> None:
    """Remove only the two paths created by this helper, including on failures."""
    source = root / "main.py"
    try:
        root.chmod(0o700)
        source.unlink(missing_ok=True)
        root.rmdir()
    except FileNotFoundError:
        pass


def write_fixture(root: Path) -> Path:
    """Create the owned fixture in a new, empty directory (never overwrite)."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=False)
    source = root / "main.py"
    with source.open("xb") as stream:
        stream.write(FIXTURE_BYTES)
    return source


def _validate_fixture_root(root: Path) -> Path:
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("fixture root must be an owned nonsymlink directory")
    source = root / "main.py"
    if source.is_symlink() or not source.is_file():
        raise ValueError("fixture main.py must be a regular nonsymlink file")
    if {item.name for item in root.iterdir()} != {"main.py"}:
        raise ValueError("fixture root must contain only main.py")
    if source.read_bytes() != FIXTURE_BYTES:
        raise ValueError("fixture main.py does not match the exact owned source bytes")
    return source.resolve(strict=True)


def static_phase_manifest(source: Path) -> PhaseManifest:
    """Run source inventory and typed framework integration for the fixture."""
    source = Path(source).resolve(strict=True)
    _validate_fixture_root(source.parent)
    contracts = load_surface_preset("framework-v1")
    inventory = CustomSurfaceExtractor(source.parent, contracts).extract_inventory()
    modules = {source.stem: str(source)}
    typed = MypyIncrementalProvider(BuildConfig(source.parent)).build(modules)
    integration = collect_framework_phase_evidence(
        inventory, contracts, MypyAnalyzer(source.parent), typed
    )
    report = phase_report_payload(integration)
    manifest = manifest_from_report(integration)
    phases = {entry.phase for entry in manifest.entries}
    if phases != EXPECTED_PHASES or len(manifest.entries) != 2:
        raise ValueError("static framework phase report is incomplete for the owned fixture")
    if report.record_count != 2 or report.unavailable_count:
        raise ValueError("static framework phase report contains unavailable records")
    callbacks = {(entry.phase, entry.callback.symbol) for entry in manifest.entries}
    if callbacks != {("startup", "startup"), ("shutdown", "shutdown")}:
        raise ValueError("static framework phase report does not bind the expected callbacks")
    return manifest


def compare_controlled_synthetic(
    manifest: PhaseManifest, observation: PhaseObservation
) -> ControlledSyntheticResult:
    comparison = compare_phase_observation(manifest, observation)
    if observation.execution_status != "completed":
        raise ValueError("controlled fixture execution did not complete")
    if observation.role != "positive_observation_only":
        raise ValueError("controlled fixture requires a positive raw observation role")
    if {row.status for row in comparison.rows} != {"observed_positive"}:
        raise ValueError("controlled fixture did not observe every expected lifecycle callback")
    return ControlledSyntheticResult(
        role="controlled_synthetic",
        execution_claim="raw fixture observation only; not trusted runtime evidence",
        comparison=comparison.model_dump(mode="json"),
        host_manifest_sha256=manifest.digest,
        container_manifest_sha256=manifest.digest,
        container_manifest=manifest.model_dump(mode="json"),
    )


def prepare_command(
    *,
    image: str,
    dependency_lock_hash: str,
    snapshot_lock_hash: str,
    sbom_hash: str,
    seccomp_profile: Path,
    seccomp_hash: str,
    expected_policy_sha256: str,
) -> list[str]:
    """Return an inspection-only command; its temporary mounts are removed on return.

    The rendered argument list is useful for review but cannot be launched because
    its fixture and cidfile paths are deliberately cleaned up before returning.
    """
    root = _new_fixture_root()
    try:
        source = _validate_fixture_root(root)
        manifest = static_phase_manifest(source)
        _make_fixture_readonly(root)
        executor = VMExecutor(
            image=image,
            runtime="runsc",
            network_disabled=True,
            dependency_lock_hash=dependency_lock_hash,
            snapshot_lock_hash=snapshot_lock_hash,
            sbom_hash=sbom_hash,
            seccomp_profile=seccomp_profile,
            seccomp_hash=seccomp_hash,
            expected_policy_sha256=expected_policy_sha256,
        )
        with tempfile.TemporaryDirectory(prefix="gh104-plan-") as temporary:
            cidfile = Path(temporary) / "container.cid"
            return executor._container_command(
                root,
                None,
                "app",
                "json",
                cidfile,
                f"gh104-controlled-synthetic-{uuid.uuid4().hex[:16]}",
                phase_manifest=manifest.model_dump(mode="json"),
                phase_manifest_source_root=root,
            )
    finally:
        _remove_owned_fixture(root)


def execute_raw_controlled_fixture(executor: VMExecutor) -> ControlledSyntheticResult:
    """Execute only a fresh internally-created owned fixture via bounded primitives."""
    root = _new_fixture_root()
    try:
        source = _validate_fixture_root(root)
        manifest = static_phase_manifest(source)
        _make_fixture_readonly(root)
        with tempfile.TemporaryDirectory(prefix="gh104-run-") as temporary:
            cidfile = Path(temporary) / "container.cid"
            name = f"gh104-controlled-synthetic-{uuid.uuid4().hex[:16]}"
            command = executor._container_command(
                root,
                None,
                "app",
                "json",
                cidfile,
                name,
                phase_manifest=manifest.model_dump(mode="json"),
                phase_manifest_source_root=root,
            )
            if len(command) >= 2 and command[-2] == "--request-file":
                request_path = cidfile.with_suffix(".request.json")
                with request_path.open("rb") as request_file:
                    raw_bytes = request_file.read(MAX_REQUEST_BYTES + 1)
                if len(raw_bytes) > MAX_REQUEST_BYTES:
                    raise ValueError("worker request sidecar exceeded the byte limit")
                raw_request = raw_bytes.decode("utf-8")
            else:
                raw_request = command[-1]
            request_payload = _strict_json_object(raw_request)
            if (
                type(request_payload.get("schema_version")) is not int
                or request_payload.get("schema_version") != 3
                or request_payload.get("phase") != "list"
            ):
                raise ValueError("worker request schema or phase is invalid")
            expected_projection = VMExecutor._container_phase_manifest(
                manifest.model_dump(mode="json"), root, "/workspace/app", source_root=root
            )
            if request_payload.get("phase_manifest") != expected_projection:
                raise ValueError("worker request phase manifest projection mismatch")
            projected_manifest = PhaseManifest.model_validate(request_payload["phase_manifest"])
            if request_payload.get("phase_manifest_sha256") != projected_manifest.digest:
                raise ValueError("worker request phase manifest digest mismatch")
            stdout, _stderr = executor._execute_bounded(command, cidfile, name)
        payload = _strict_json_object(stdout)
        if (
            not isinstance(payload, dict)
            or type(payload.get("schema_version")) is not int
            or payload.get("schema_version") != 3
            or payload.get("status") != "ok"
            or payload.get("phase") != "list"
        ):
            raise ValueError("raw worker response schema, status, or phase is invalid")
        raw_value = payload.get("phase_observation")
        if not isinstance(raw_value, dict) or type(raw_value.get("schema_version")) is not int:
            raise ValueError("raw phase observation schema version must be an integer")
        raw = PhaseObservation.model_validate(raw_value)
        if raw.manifest_sha256 != projected_manifest.digest:
            raise ValueError("raw fixture observation container manifest digest mismatch")
        compared = compare_controlled_synthetic(projected_manifest, raw)
        return ControlledSyntheticResult(
            role=compared.role,
            execution_claim=compared.execution_claim,
            comparison=compared.comparison,
            host_manifest_sha256=manifest.digest,
            container_manifest_sha256=projected_manifest.digest,
            container_manifest=expected_projection,
        )
    finally:
        _remove_owned_fixture(root)


def _strict_json_object(value: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in items:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = item
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number {value}")

    decoded = json.loads(value, object_pairs_hook=pairs, parse_constant=reject_constant)
    if not isinstance(decoded, dict):
        raise ValueError("JSON payload must be an object")
    return decoded
