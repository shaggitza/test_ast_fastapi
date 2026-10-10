"""Safe producer tests: fake lanes plus a source-only secure CLI smoke check."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import time
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from benchmarks.real_world import _secure_publish
from benchmarks.real_world import produce_runtime as producer
from benchmarks.real_world.compare_runtime import compare, compare_target_baseline
from benchmarks.real_world.produce_runtime import (
    CommandRunner,
    EntryConfiguration,
    InvocationResult,
    PhaseFailure,
    ProducerError,
    RunRequest,
    SnapshotInput,
    TrustedRuntimeEvidence,
    _hash_file,
    produce_snapshot_pair,
    produce_target_baseline,
)

from fastapi_endpoint_detector.analyzer.framework_phase_bridge import FrameworkPhase, SourceIdentity
from fastapi_endpoint_detector.analyzer.framework_phase_report import unavailable_phase_report
from fastapi_endpoint_detector.analyzer.framework_phase_runtime import (
    PhaseManifest,
    PhaseManifestEntry,
    PhaseObservation,
    manifest_from_report,
)
from fastapi_endpoint_detector.models.surface_contract import load_surface_preset

H = "sha256:" + "a" * 64
IMAGE = "registry.example/detector@sha256:" + "b" * 64


class FakeRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def __call__(self, mode: str, phase: str, request: Any) -> InvocationResult:
        self.calls.append((mode, phase))
        seconds = 0.25 if phase == "list" else 0.5
        if mode == "secure" and phase == "impact" and request.phase_manifest_state is not None:
            request.phase_manifest_state.update(
                _phase_manifest(request.snapshot.app_path / "main.py")
            )
        if phase == "list":
            status = "established" if mode == "secure" else "runtime_observed"
            return InvocationResult(
                inventory={
                    "inventory_status": status,
                    "endpoints": [{"methods": ["GET"], "path": "/items", "surface": None}],
                },
                seconds=seconds,
                peak_rss_bytes=2048,
                phase_manifest=(request.phase_manifest_state if mode == "runtime" else None),
                phase_observation=(
                    PhaseObservation(
                        manifest_sha256=PhaseManifest.model_validate(
                            request.phase_manifest_state
                        ).digest,
                        observed=(),
                        unavailable=(),
                        execution_status="completed",
                    ).model_dump(mode="json")
                    if mode == "runtime" and request.phase_manifest_state
                    else None
                ),
            )
        return InvocationResult(
            impact={
                "candidate_endpoints": [
                    {"endpoint": {"methods": ["GET"], "path": "/items", "surface": None}}
                ]
            },
            seconds=seconds,
            peak_rss_bytes=2048,
            phase_manifest=(request.phase_manifest_state if mode == "runtime" else None),
            phase_observation=(
                PhaseObservation(
                    manifest_sha256=PhaseManifest.model_validate(
                        request.phase_manifest_state
                    ).digest,
                    observed=(),
                    unavailable=(),
                    execution_status="completed",
                ).model_dump(mode="json")
                if mode == "runtime" and request.phase_manifest_state
                else None
            ),
        )


class SignedFakeRunner(FakeRunner):
    """Controlled protocol double; never operational runtime attestation."""

    def __init__(self, key: str) -> None:
        super().__init__()
        self.key = key

    def __call__(self, mode: str, phase: str, request: Any) -> InvocationResult:
        result = super().__call__(mode, phase, request)
        if mode != "runtime":
            return result
        if (
            result.phase_manifest
            and result.phase_manifest.get("entries")
            and result.phase_observation
        ):
            entry = result.phase_manifest["entries"][0]
            forged_observation = dict(result.phase_observation)
            forged_observation.update(
                observed=[
                    {
                        "callback": entry["callback"],
                        "registration": entry["registration"],
                        "phase": entry["phase"],
                        "manifest_sha256": PhaseManifest.model_validate(
                            result.phase_manifest
                        ).digest,
                        "execution_conditions": entry["execution_conditions"],
                    }
                ],
                role="positive_observation_only",
            )
            result = replace(result, phase_observation=forged_observation)
        assert request.custody_binding is not None
        now = int(time.time())
        receipt = {
            "binding": request.custody_binding.model_dump(mode="json"),
            "result_sha256": producer.custody_digest(producer._invocation_payload(result)),
            "key_id": "fixture-custody-authority",
            "issued_at": now,
            "expires_at": now + 60,
        }
        signature = hmac.new(
            self.key.encode(),
            json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode(),
            hashlib.sha256,
        ).hexdigest()
        return replace(result, custody_receipt={**receipt, "signature": signature})


class FailingRunner(FakeRunner):
    def __init__(self, phase: str, failure_phase: str) -> None:
        super().__init__()
        self.failed_phase = phase
        self.failure_phase = failure_phase

    def __call__(self, mode: str, phase: str, request: Any) -> InvocationResult:
        if phase == self.failed_phase:
            raise PhaseFailure(self.failure_phase, "fixture failure")
        return super().__call__(mode, phase, request)


def _inputs(tmp_path: Path, *, side: str = "target") -> SnapshotInput:
    tmp_path.mkdir(parents=True, exist_ok=True)
    app = tmp_path / "app"
    app.mkdir(exist_ok=True)
    (app / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/')\n"
        "def home(): return {'ok': True}\n",
        encoding="utf-8",
    )
    lock = tmp_path / "requirements.lock"
    lock.write_text("fastapi==0.100.0\n", encoding="utf-8")
    source_lock = tmp_path / "source.lock"
    source_lock.write_text("git-tree-lock-v1\n", encoding="utf-8")
    sbom = tmp_path / "sbom.json"
    sbom.write_text('{"packages": []}\n', encoding="utf-8")
    diff = tmp_path / "change.diff"
    diff.write_text("", encoding="utf-8")
    if not (app / ".git").exists():
        subprocess.run(["git", "init", "-q", str(app)], check=True)
        subprocess.run(["git", "-C", str(app), "add", "main.py"], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(app),
                "-c",
                "user.name=Producer Test",
                "-c",
                "user.email=producer-test@example.invalid",
                "commit",
                "-qm",
                "fixture",
            ],
            check=True,
        )
    revision = subprocess.run(
        ["git", "-C", str(app), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    return SnapshotInput(
        side=side,  # type: ignore[arg-type]
        app_path=app,
        diff_path=diff,
        source_revision=revision,
        dependency_lock=lock,
        source_snapshot_lock=source_lock,
        runtime_image=IMAGE,
        sbom=sbom,
    )


def _evidence(paths: dict[str, Path], spec: SnapshotInput) -> TrustedRuntimeEvidence:
    secure = json.loads(paths["secure"].read_text(encoding="utf-8"))
    runtime = json.loads(paths["runtime"].read_text(encoding="utf-8"))
    return TrustedRuntimeEvidence(
        status="passed",
        host_boundary="gvisor",
        runtime_version="runsc test version",
        image_digest=IMAGE,
        dependency_lock_sha256=secure["configuration"]["dependency_lock_sha256"],
        snapshot_lock_sha256=_hash_file(spec.source_snapshot_lock, "source lock"),
        sbom_sha256=secure["provenance"]["runtime_sbom_sha256"],
        seccomp_sha256=runtime["provenance"]["runtime_seccomp_sha256"],
        policy_sha256=runtime["provenance"]["runtime_policy_sha256"],
        canary_receipt_sha256=H,
    )


def _request(spec: SnapshotInput) -> RunRequest:
    lock_hash = _hash_file(spec.dependency_lock, "lock")
    snapshot_hash = _hash_file(spec.source_snapshot_lock, "source lock")
    sbom_hash = _hash_file(spec.sbom, "sbom")
    seccomp = (
        producer.PROJECT_ROOT
        / "src/fastapi_endpoint_detector/executor/policies/"
        / "runtime-seccomp-v1.json"
    )
    seccomp_hash = _hash_file(seccomp, "seccomp")
    values = {
        "image": spec.runtime_image,
        "dependency_lock_sha256": lock_hash,
        "snapshot_lock_sha256": snapshot_hash,
        "sbom_sha256": sbom_hash,
        "seccomp_sha256": seccomp_hash,
    }
    return RunRequest(
        snapshot=spec,
        configuration=EntryConfiguration(None, None, "app", "mypy"),
        dependency_lock_sha256=lock_hash,
        snapshot_lock_sha256=snapshot_hash,
        runtime_image=spec.runtime_image,
        sbom_sha256=sbom_hash,
        seccomp_sha256=seccomp_hash,
        runtime_policy_sha256=producer._runtime_policy_digest(values),
    )


def _signed_evidence(request: RunRequest, key: str) -> TrustedRuntimeEvidence:
    now = int(time.time())
    value = TrustedRuntimeEvidence(
        status="passed",
        host_boundary="gvisor",
        runtime_version="controlled protocol fixture",
        image_digest=request.runtime_image,
        dependency_lock_sha256=request.dependency_lock_sha256,
        snapshot_lock_sha256=request.snapshot_lock_sha256,
        sbom_sha256=request.sbom_sha256,
        seccomp_sha256=request.seccomp_sha256,
        policy_sha256=request.runtime_policy_sha256,
        canary_receipt_sha256=H,
        key_id="test-authority",
        issued_at=now,
        expires_at=now + 300,
        request_sha256=producer._request_digest(request),
    )
    payload = json.dumps(producer._evidence_payload(value), sort_keys=True, separators=(",", ":"))
    signature = hmac.new(key.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return replace(value, signature=signature)


def test_default_runtime_gate_abstains_without_calling_runtime(tmp_path: Path) -> None:
    runner = FakeRunner()
    outputs = produce_snapshot_pair(
        _inputs(tmp_path),
        EntryConfiguration(None, None, "app", "mypy"),
        tmp_path / "out",
        runner=runner,
    )

    assert runner.calls == [("secure", "list"), ("secure", "impact")]
    runtime = json.loads(outputs["runtime"].read_text(encoding="utf-8"))
    assert runtime["status"] == "failure"
    assert runtime["failure"]["phase"] == "unavailable"
    assert "independently trusted" in runtime["failure"]["message"]
    comparison = compare(outputs["secure"], outputs["runtime"])
    assert comparison["quality_eligible"] is False


@pytest.mark.parametrize("conditional", [False, True])
def test_empty_or_conditional_phase_manifest_preserves_operational_pair(
    tmp_path: Path, conditional: bool
) -> None:
    class PhaseRunner(FakeRunner):
        def __call__(self, mode: str, phase: str, request: Any) -> InvocationResult:
            result = super().__call__(mode, phase, request)
            if mode == "secure" and phase == "impact":
                request.phase_manifest_state.clear()
                request.phase_manifest_state.update(
                    {"conditional": True}
                    if conditional
                    else PhaseManifest(entries=()).model_dump(mode="json")
                )
            return result

    runner = PhaseRunner()
    outputs = produce_snapshot_pair(
        _inputs(tmp_path),
        EntryConfiguration(None, None, "app", "mypy"),
        tmp_path / "out",
        runner=runner,
    )
    secure = json.loads(outputs["secure"].read_text())
    runtime = json.loads(outputs["runtime"].read_text())
    assert secure["status"] == "success"
    assert secure["inventory"]["endpoints"]
    assert secure["impact"]["candidate_endpoints"]
    assert runtime["status"] == "failure"
    assert runner.calls == [("secure", "list"), ("secure", "impact")]
    if conditional:
        assert "framework_phase_manifest" not in secure
        assert "framework_phase_manifest" not in runtime
    else:
        assert secure["framework_phase_manifest"]["entries"] == []
        assert runtime["framework_phase_manifest"] == secure["framework_phase_manifest"]
    assert compare(outputs["secure"], outputs["runtime"])["quality_eligible"] is False


@pytest.mark.parametrize(
    ("phase", "failure_phase"),
    [
        ("list", "dependency"),
        ("list", "import"),
        ("list", "app_resolution"),
        ("impact", "extraction"),
        ("impact", "timeout"),
        ("impact", "unavailable"),
    ],
)
def test_runner_failures_are_accounted_without_partial_claims(
    tmp_path: Path, phase: str, failure_phase: str
) -> None:
    outputs = produce_snapshot_pair(
        _inputs(tmp_path),
        EntryConfiguration(None, None, "app", "mypy"),
        tmp_path / "out",
        runner=FailingRunner(phase, failure_phase),
    )
    secure = json.loads(outputs["secure"].read_text(encoding="utf-8"))
    if phase == "impact":
        # Runtime defaults to an unavailable abstention without a canary receipt.
        assert secure["failure"]["phase"] == failure_phase
        assert secure["inventory"] is None
        assert secure["impact"] is None
        assert secure["timing"]["list"]["status"] == "measured"
        assert secure["timing"]["impact"]["status"] == "not_measured"
    else:
        assert secure["failure"]["phase"] == failure_phase
        assert secure["inventory"] is None
        assert secure["impact"] is None
        assert secure["timing"]["list"]["status"] == "not_measured"


def test_caller_supplied_matching_json_cannot_open_runtime_lane(tmp_path: Path) -> None:
    runner = FakeRunner()
    first = produce_snapshot_pair(
        _inputs(tmp_path),
        EntryConfiguration(None, None, "app", "mypy"),
        tmp_path / "first",
        runner=runner,
    )
    evidence = _evidence(first, _inputs(tmp_path))
    outputs = produce_snapshot_pair(
        _inputs(tmp_path),
        EntryConfiguration(None, None, "app", "mypy"),
        tmp_path / "paired",
        runner=runner,
        runtime_evidence=evidence,
    )

    assert runner.calls[-2:] == [("secure", "list"), ("secure", "impact")]
    runtime = json.loads(outputs["runtime"].read_text(encoding="utf-8"))
    assert runtime["status"] == "failure"
    assert "independently trusted" in runtime["failure"]["message"]
    assert compare(outputs["secure"], outputs["runtime"])["quality_eligible"] is False


@pytest.mark.parametrize(
    "tamper",
    [
        lambda receipt: replace(receipt, canary_receipt_sha256="sha256:" + "f" * 64),
        lambda receipt: replace(receipt, runtime_version="stale runtime version"),
        lambda receipt: replace(receipt, image_digest="registry.invalid/image@sha256:" + "0" * 64),
        lambda receipt: replace(receipt, host_boundary="caller-claimed-gvisor"),
    ],
    ids=["forged-digest", "stale", "mismatched-image", "forged-host"],
)
def test_forged_stale_and_mismatched_receipts_never_open_lane(tmp_path: Path, tamper: Any) -> None:
    runner = FakeRunner()
    initial = produce_snapshot_pair(
        _inputs(tmp_path),
        EntryConfiguration(None, None, "app", "mypy"),
        tmp_path / "initial",
        runner=runner,
    )
    receipt = tamper(_evidence(initial, _inputs(tmp_path)))
    outputs = produce_snapshot_pair(
        _inputs(tmp_path),
        EntryConfiguration(None, None, "app", "mypy"),
        tmp_path / "tampered",
        runner=runner,
        runtime_evidence=receipt,
    )

    assert runner.calls[-2:] == [("secure", "list"), ("secure", "impact")]
    runtime = json.loads(outputs["runtime"].read_text(encoding="utf-8"))
    assert runtime["status"] == "failure"
    assert "independently trusted" in runtime["failure"]["message"]


def test_source_mutation_between_phases_aborts_before_next_lane(tmp_path: Path) -> None:
    spec = _inputs(tmp_path)

    class MutatingRunner(FakeRunner):
        def __call__(self, mode: str, phase: str, request: Any) -> InvocationResult:
            result = super().__call__(mode, phase, request)
            if mode == "secure" and phase == "list":
                (spec.app_path / "main.py").write_text("app = None\n", encoding="utf-8")
            return result

    runner = MutatingRunner()
    outputs = produce_snapshot_pair(
        spec,
        EntryConfiguration(None, None, "app", "mypy"),
        tmp_path / "mutation",
        runner=runner,
    )

    secure = json.loads(outputs["secure"].read_text(encoding="utf-8"))
    assert secure["failure"]["phase"] == "unavailable"
    assert "snapshot checkout has uncommitted" in secure["failure"]["message"]
    assert runner.calls == [("secure", "list")]


def test_runtime_factory_configuration_is_kept_behind_closed_trust_gate(tmp_path: Path) -> None:
    runner = FakeRunner()
    initial = produce_snapshot_pair(
        _inputs(tmp_path),
        EntryConfiguration(None, None, "app", "mypy"),
        tmp_path / "initial",
        runner=runner,
    )
    evidence = _evidence(initial, _inputs(tmp_path))
    outputs = produce_snapshot_pair(
        _inputs(tmp_path),
        EntryConfiguration("main:create_app", "main:bootstrap", "app", "mypy"),
        tmp_path / "factory",
        runner=runner,
        runtime_evidence=evidence,
    )

    runtime = json.loads(outputs["runtime"].read_text(encoding="utf-8"))
    assert runtime["configuration"]["app_entry"] == "main:create_app"
    assert runtime["configuration"]["bootstrap_entry"] == "main:bootstrap"
    assert runtime["failure"]["phase"] == "unavailable"
    assert "independently trusted" in runtime["failure"]["message"]
    assert runner.calls[-2:] == [("secure", "list"), ("secure", "impact")]
    comparison = compare(outputs["secure"], outputs["runtime"])
    assert comparison["quality_eligible"] is False


def test_publication_never_overwrites_existing_artifact(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    existing = out / "target-runtime.json"
    existing.write_text("canonical", encoding="utf-8")
    with pytest.raises(ProducerError, match="publication stopped"):
        produce_snapshot_pair(
            _inputs(tmp_path),
            EntryConfiguration(None, None, "app", "mypy"),
            out,
            runner=FakeRunner(),
        )
    assert existing.read_text(encoding="utf-8") == "canonical"
    assert not (out / "target-secure.json").exists()


def test_matrix_publication_rolls_back_earlier_new_files_on_late_collision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    real_publish = _secure_publish.publish_exclusive_bytes
    calls = 0

    def collide_late(path: Path, content: bytes, **kwargs: Any) -> tuple[int, int]:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise _secure_publish.SecurePathError("late collision")
        return real_publish(path, content, **kwargs)

    monkeypatch.setattr(_secure_publish, "publish_exclusive_bytes", collide_late)
    with pytest.raises(_secure_publish.SecurePathError, match="rolled back 1"):
        _secure_publish.publish_exclusive_batch([(first, b"a"), (second, b"b")])
    assert not first.exists()
    assert not second.exists()


def test_independent_signature_verifies_exact_pins_and_expiry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _request(_inputs(tmp_path))
    key = "controlled-test-secret"
    monkeypatch.setenv("FASTAPI_DETECTOR_RUNTIME_TRUST_KEY", key)
    monkeypatch.setenv("FASTAPI_DETECTOR_RUNTIME_TRUST_KEY_ID", "test-authority")
    monkeypatch.setenv("FASTAPI_DETECTOR_RUNTIME_TRUST_VERSION", "controlled protocol fixture")
    receipt = _signed_evidence(request, key)
    producer._validate_evidence(receipt, request)
    with pytest.raises(ProducerError, match="signature authentication"):
        producer._validate_evidence(replace(receipt, signature="f" * 64), request)
    with pytest.raises(ProducerError, match="request_sha256"):
        producer._validate_evidence(replace(receipt, request_sha256=H), request)
    expired = replace(receipt, issued_at=int(time.time()) - 4000, expires_at=int(time.time()) - 1)
    body = json.dumps(producer._evidence_payload(expired), sort_keys=True, separators=(",", ":"))
    signature = hmac.new(key.encode(), body.encode(), hashlib.sha256).hexdigest()
    expired = replace(expired, signature=signature)
    with pytest.raises(ProducerError, match="stale, expired"):
        producer._validate_evidence(expired, request)


def test_valid_signed_receipt_reaches_runtime_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec = _inputs(tmp_path)
    key = "controlled-test-secret"
    monkeypatch.setenv("FASTAPI_DETECTOR_RUNTIME_TRUST_KEY", key)
    monkeypatch.setenv("FASTAPI_DETECTOR_RUNTIME_TRUST_KEY_ID", "test-authority")
    monkeypatch.setenv("FASTAPI_DETECTOR_RUNTIME_TRUST_VERSION", "controlled protocol fixture")
    receipt = _signed_evidence(_request(spec), key)
    custody_key = "controlled-custody-test-secret-at-least-32-bytes"
    monkeypatch.setenv("FASTAPI_DETECTOR_RUNTIME_CUSTODY_KEY", custody_key)
    monkeypatch.setenv("FASTAPI_DETECTOR_RUNTIME_CUSTODY_KEY_ID", "fixture-custody-authority")
    runner = SignedFakeRunner(custody_key)
    outputs = produce_snapshot_pair(
        spec,
        EntryConfiguration(None, None, "app", "mypy"),
        tmp_path / "signed-pair",
        runner=runner,
        runtime_evidence=receipt,
    )
    assert runner.calls == [
        ("secure", "list"),
        ("secure", "impact"),
        ("runtime", "list"),
        ("runtime", "impact"),
    ]
    runtime = json.loads(outputs["runtime"].read_text(encoding="utf-8"))
    assert runtime["status"] == "success"
    assert runtime["provenance"]["runtime_attestation_sha256"].startswith("sha256:")
    assert runtime["framework_phase"]["role"] == "self_reported_nonpositive"
    for phase, observation in runtime["framework_phase"]["observations"].items():
        assert observation["observed"] == []
        assert observation["role"] == "self_reported_nonpositive"
        assert runtime["runtime_custody"][phase]["result"]["phase_observation"] == observation


def test_target_baseline_orchestrator_publishes_comparator_valid_matrix(tmp_path: Path) -> None:
    outputs = produce_target_baseline(
        _inputs(tmp_path / "target", side="target"),
        _inputs(tmp_path / "baseline", side="baseline"),
        EntryConfiguration(None, None, "app", "mypy"),
        tmp_path / "matrix",
        runner=FakeRunner(),
    )

    assert len(outputs) == 4
    result = compare_target_baseline(
        secure_target_path=outputs[("target", "secure")],
        runtime_target_path=outputs[("target", "runtime")],
        secure_baseline_path=outputs[("baseline", "secure")],
        runtime_baseline_path=outputs[("baseline", "runtime")],
    )
    assert result["operational"]["artifact_count"] == 4
    assert result["operational"]["failure_phase_counts"]["runtime"] == {"unavailable": 2}


@pytest.mark.parametrize("tampered", [False, True], ids=["unsigned", "changed-after-signing"])
def test_valid_admission_does_not_accept_unattested_runtime_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tampered: bool
) -> None:
    spec = _inputs(tmp_path)
    trust_key = "controlled-test-secret"
    custody_key = "controlled-custody-test-secret-at-least-32-bytes"
    monkeypatch.setenv("FASTAPI_DETECTOR_RUNTIME_TRUST_KEY", trust_key)
    monkeypatch.setenv("FASTAPI_DETECTOR_RUNTIME_TRUST_KEY_ID", "test-authority")
    monkeypatch.setenv("FASTAPI_DETECTOR_RUNTIME_TRUST_VERSION", "controlled protocol fixture")
    monkeypatch.setenv("FASTAPI_DETECTOR_RUNTIME_CUSTODY_KEY", custody_key)
    monkeypatch.setenv("FASTAPI_DETECTOR_RUNTIME_CUSTODY_KEY_ID", "fixture-custody-authority")

    class TamperingRunner(SignedFakeRunner):
        def __call__(self, mode: str, phase: str, request: Any) -> InvocationResult:
            result = super().__call__(mode, phase, request)
            if mode == "runtime":
                return replace(result, seconds=result.seconds + 1)
            return result

    runner = TamperingRunner(custody_key) if tampered else FakeRunner()
    outputs = produce_snapshot_pair(
        spec,
        EntryConfiguration(None, None, "app", "mypy"),
        tmp_path / "rejected",
        runner=runner,
        runtime_evidence=_signed_evidence(_request(spec), trust_key),
    )
    runtime = json.loads(outputs["runtime"].read_text(encoding="utf-8"))
    assert runtime["status"] == "failure"
    assert runtime["inventory"] is None
    assert runtime["impact"] is None
    assert "runtime_custody" not in runtime


def test_secure_command_runs_only_ast_over_local_fixture(tmp_path: Path) -> None:
    spec = _inputs(tmp_path)
    result = CommandRunner(timeout_seconds=60)(
        "secure",
        "list",
        # Constructing via producer provides fully hashed and pinned run input.
        _request_for_source_only_test(spec),
    )
    assert result.inventory is not None
    assert result.inventory["inventory_status"] in {"established", "conditional", "unavailable"}
    assert any(endpoint.get("path") == "/" for endpoint in result.inventory["endpoints"])


def test_runtime_command_uses_worker_phases_with_exact_configuration_pins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _request_for_source_only_test(_inputs(tmp_path))
    request = replace(
        request,
        configuration=EntryConfiguration("main:create_app", "main:bootstrap", "app", "scip"),
        phase_manifest_state=_phase_manifest(request.snapshot.app_path / "main.py"),
    )
    constructor_args: dict[str, Any] = {}
    invocations: list[dict[str, Any]] = []

    class FakeVMExecutor:
        def __init__(self, **kwargs: Any) -> None:
            constructor_args.update(kwargs)

        def analyze_in_vm(self, **kwargs: Any) -> dict[str, Any]:
            invocations.append(kwargs)
            phase = "list" if kwargs["diff_path"] is None else "analyze"
            return {
                "status": "ok",
                "phase": phase,
                "endpoints": [{"path": "/fixture"}],
                "candidate_endpoints": [],
                "telemetry": {
                    "container_peak_rss_bytes": 8192,
                    "container_peak_rss_status": "measured",
                    "source": "sampled-/proc/[pid]/statm",
                },
            }

    monkeypatch.setattr(producer, "VMExecutor", FakeVMExecutor)
    # This tests VM argument forwarding, separately from the host custody broker.
    listed = producer._run_runtime_phase("list", request)
    analyzed = producer._run_runtime_phase("impact", request)

    assert constructor_args == {
        "image": request.runtime_image,
        "dependency_lock_hash": request.dependency_lock_sha256,
        "snapshot_lock_hash": request.snapshot_lock_sha256,
        "sbom_hash": request.sbom_sha256,
        "seccomp_hash": request.seccomp_sha256,
        "expected_policy_sha256": request.runtime_policy_sha256,
    }
    assert [call["app_entry"] for call in invocations] == ["main:create_app"] * 2
    assert [call["bootstrap_entry"] for call in invocations] == ["main:bootstrap"] * 2
    assert invocations[0]["diff_path"] is None
    assert invocations[1]["diff_path"] == request.snapshot.diff_path
    assert all(call["phase_manifest"] == request.phase_manifest_state for call in invocations)
    assert all(
        call["phase_manifest_source_root"] == request.phase_manifest_source_root
        for call in invocations
    )
    assert listed.inventory == {
        "inventory_status": "runtime_observed",
        "endpoints": [{"path": "/fixture"}],
    }
    assert analyzed.impact == {"candidate_endpoints": []}
    assert listed.peak_rss_bytes == analyzed.peak_rss_bytes == 8192


def _request_for_source_only_test(spec: SnapshotInput) -> Any:
    policy = Path("src/fastapi_endpoint_detector/executor/policies/runtime-seccomp-v1.json")
    return RunRequest(
        snapshot=spec,
        configuration=EntryConfiguration(None, None, "app", "mypy"),
        dependency_lock_sha256=_hash_file(spec.dependency_lock, "lock"),
        snapshot_lock_sha256=_hash_file(spec.source_snapshot_lock, "source lock"),
        runtime_image=spec.runtime_image,
        sbom_sha256=_hash_file(spec.sbom, "sbom"),
        seccomp_sha256=_hash_file(policy, "seccomp"),
        runtime_policy_sha256="sha256:" + "c" * 64,
    )


def test_frozen_lane_copy_is_readable_by_runtime_uid_and_source_modes_stay_private(
    tmp_path: Path,
) -> None:
    spec = _inputs(tmp_path)
    source = spec.app_path / "main.py"
    nested = spec.app_path / "nested"
    nested.mkdir()
    nested_file = nested / "module.py"
    nested_file.write_text("value = 1\n", encoding="utf-8")
    # Update the pinned fixture revision to include the nested file, then
    # exercise the private copy with owner-only source permissions.
    subprocess.run(["git", "-C", str(spec.app_path), "add", "nested/module.py"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(spec.app_path),
            "-c",
            "user.name=Producer Test",
            "-c",
            "user.email=producer-test@example.invalid",
            "commit",
            "-m",
            "add nested source",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    revision = subprocess.run(
        ["git", "-C", str(spec.app_path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    spec = replace(
        spec,
        source_revision=revision,
        diff_path_sha256=_hash_file(spec.diff_path, "test diff"),
    )
    source.chmod(0o600)
    nested.chmod(0o700)
    nested_file.chmod(0o600)
    original_hash = producer._source_digest(spec.app_path)
    original_modes = (source.stat().st_mode & 0o777, nested.stat().st_mode & 0o777)
    request = _request_for_source_only_test(spec)

    with producer._frozen_lane_request(request, original_hash, producer._tool_digest()) as lane:
        staged_source = lane.snapshot.app_path / "main.py"
        staged_nested = lane.snapshot.app_path / "nested"
        staged_file = staged_nested / "module.py"
        assert staged_source.stat().st_mode & 0o444 == 0o444
        assert staged_nested.stat().st_mode & 0o555 == 0o555
        assert staged_file.stat().st_mode & 0o444 == 0o444
        assert staged_source.stat().st_mode & 0o222 == 0
        assert staged_nested.stat().st_mode & 0o222 == 0
        assert staged_file.stat().st_mode & 0o222 == 0
        # Permission bits and unchanged source modes are checked on every host.
        # Switching to the runtime UID additionally requires root privileges.
        assert os.access(staged_file, os.R_OK)
        assert os.access(staged_nested, os.X_OK)
        if os.geteuid() == 0:
            # Confirm access under the same unprivileged uid used by the runtime.
            unprivileged = [
                "setpriv",
                "--reuid=65532",
                "--regid=65532",
                "--clear-groups",
                "test",
            ]
            assert (
                subprocess.run(
                    [*unprivileged, "-r", "nested/module.py"],
                    cwd=lane.snapshot.app_path,
                    check=False,
                ).returncode
                == 0
            )
            assert (
                subprocess.run(
                    [*unprivileged, "-x", "nested"],
                    cwd=lane.snapshot.app_path,
                    check=False,
                ).returncode
                == 0
            )

    assert producer._source_digest(spec.app_path) == original_hash
    assert (source.stat().st_mode & 0o777, nested.stat().st_mode & 0o777) == original_modes


def _phase_manifest(source: Path) -> dict[str, Any]:
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    source_digest = "sha256:" + digest
    identity = SourceIdentity(
        module="main",
        symbol="startup",
        file=str(source.resolve()),
        line=1,
        column=0,
        source_sha256=source_digest,
    )
    entry = PhaseManifestEntry(
        callback=identity,
        registration=identity,
        phase="startup",
        execution_conditions=("startup succeeds",),
        contract_id="fastapi-lifespan-startup",
        contract_sha256=load_surface_preset("framework-v1").document.contract_hashes[
            "fastapi-lifespan-startup"
        ],
        source_sha256=source_digest,
        callback_file_sha256=digest,
        registration_file_sha256=digest,
        inventory_sha256=source_digest,
        engine_sha256=source_digest,
        config_sha256=source_digest,
    )
    return PhaseManifest(entries=(entry,)).model_dump(mode="json")


@pytest.mark.parametrize("field", ["runtime_version", "issued_at", "canary_receipt_sha256"])
def test_resigned_receipt_rejects_untrusted_runtime_or_invalid_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    request = _request(_inputs(tmp_path))
    key = "controlled-test-secret"
    monkeypatch.setenv("FASTAPI_DETECTOR_RUNTIME_TRUST_KEY", key)
    monkeypatch.setenv("FASTAPI_DETECTOR_RUNTIME_TRUST_KEY_ID", "test-authority")
    monkeypatch.setenv("FASTAPI_DETECTOR_RUNTIME_TRUST_VERSION", "controlled protocol fixture")
    receipt = _signed_evidence(request, key)
    changes = {
        "runtime_version": "a different authorized-but-unpinned runtime",
        "issued_at": float(receipt.issued_at),
        "canary_receipt_sha256": "arbitrary non-digest",
    }
    receipt = replace(receipt, **{field: changes[field]})
    body = json.dumps(producer._evidence_payload(receipt), sort_keys=True, separators=(",", ":"))
    receipt = replace(
        receipt, signature=hmac.new(key.encode(), body.encode(), hashlib.sha256).hexdigest()
    )
    with pytest.raises(ProducerError):
        producer._validate_evidence(receipt, request)


def test_receipt_request_binds_snapshot_side_and_actual_diff_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _request(_inputs(tmp_path))
    key = "controlled-test-secret"
    monkeypatch.setenv("FASTAPI_DETECTOR_RUNTIME_TRUST_KEY", key)
    monkeypatch.setenv("FASTAPI_DETECTOR_RUNTIME_TRUST_KEY_ID", "test-authority")
    monkeypatch.setenv("FASTAPI_DETECTOR_RUNTIME_TRUST_VERSION", "controlled protocol fixture")
    receipt = _signed_evidence(request, key)
    other_side = replace(request, snapshot=replace(request.snapshot, side="baseline"))
    with pytest.raises(ProducerError, match="request_sha256"):
        producer._validate_evidence(receipt, other_side)
    request.snapshot.diff_path.write_text("changed diff bytes\n")
    with pytest.raises(ProducerError, match="request_sha256"):
        producer._validate_evidence(receipt, request)


def test_secure_public_command_emits_source_bound_startup_manifest(tmp_path: Path) -> None:
    spec = _inputs(tmp_path)
    source = spec.app_path / "main.py"
    source.write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.on_event('startup')\n"
        "def startup() -> None: pass\n"
        "@app.on_event('shutdown')\n"
        "def shutdown() -> None: pass\n"
    )
    request = replace(
        _request_for_source_only_test(spec),
        phase_manifest_state={},
        phase_manifest_source_root=spec.app_path,
    )
    result = CommandRunner(timeout_seconds=120)("secure", "impact", request)
    assert result.impact is not None
    assert request.phase_manifest_state is not None
    assert request.phase_manifest_state != {"conditional": True}
    entries = request.phase_manifest_state["entries"]
    assert {entry["phase"] for entry in entries} == {"startup", "shutdown"}
    assert {entry["callback"]["symbol"] for entry in entries} == {"startup", "shutdown"}
    assert all(entry["callback"]["module"] == "main" for entry in entries)
    assert all(entry["callback"]["file"] == str(source.resolve()) for entry in entries)
    assert all(
        entry["callback_file_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
        for entry in entries
    )
    assert all(
        entry["execution_conditions"]
        == [f"framework executes {entry['phase']} callback only when that phase is dispatched"]
        for entry in entries
    )


def test_secure_public_command_keeps_startup_added_route_coverage_conditional(
    tmp_path: Path,
) -> None:
    spec = _inputs(tmp_path)
    source = spec.app_path / "main.py"
    source.write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "async def late() -> dict[str, bool]: return {'ready': True}\n"
        "@app.on_event('startup')\n"
        "def startup() -> None:\n"
        "    app.add_api_route('/late', late, methods=['POST'])\n"
    )
    request = replace(
        _request_for_source_only_test(spec),
        phase_manifest_state={},
        phase_manifest_source_root=spec.app_path,
    )

    result = CommandRunner(timeout_seconds=120)("secure", "impact", request)

    assert result.impact is not None
    assert request.phase_manifest_state == {"conditional": True}


def test_runtime_phase_gate_requires_complete_exact_record_manifest_pairs(
    tmp_path: Path,
) -> None:
    source = tmp_path / "main.py"
    source.write_text("def startup() -> None: pass\n", encoding="utf-8")
    manifest = _phase_manifest(source)
    entry = manifest["entries"][0]
    registration = entry["registration"]
    report_record = {
        "status": "conditional",
        "phase": entry["phase"],
        "callback": entry["callback"],
        "registration": registration,
        "typed_callback_symbol": "main.startup",
        "typed_framework_symbol": "fastapi.applications.FastAPI.on_event",
        "registration_call_site": {
            "file_path": registration["file"],
            "line": registration["line"],
            "column": registration["column"],
            "end_line": registration["end_line"],
            "end_column": registration["end_column"],
            "canonical_symbol": "fastapi.applications.FastAPI.on_event",
            "status": "exact",
        },
        "limitations": [],
        "execution_conditions": entry["execution_conditions"],
        "contract_id": entry["contract_id"],
        "canonical_contract_sha256": entry["contract_sha256"],
        "source_sha256": entry["source_sha256"],
        "callback_file_sha256": entry["callback_file_sha256"],
        "registration_file_sha256": entry["registration_file_sha256"],
        "inventory_sha256": entry["inventory_sha256"],
        "engine_sha256": entry["engine_sha256"],
        "config_sha256": entry["config_sha256"],
    }
    report: dict[str, Any] = {
        "backend": "mypy",
        "record_count": 1,
        "established_count": 0,
        "conditional_count": 1,
        "unavailable_count": 0,
        "records": [report_record],
        "limitations": [],
        "lifecycle_conditional_surfaces": [],
    }
    assert producer._has_complete_static_phase_coverage(report, manifest)

    invalid_reports = [
        {**report, "limitations": ["inventory unknown"]},
        {**report, "lifecycle_conditional_surfaces": [{"surface_id": "/late"}]},
        {**report, "unavailable_count": 1},
        {**report, "record_count": 2},
        {
            **report,
            "records": [{**report_record, "registration_call_site": {"status": "ambiguous"}}],
        },
    ]
    invalid_manifests = [
        {"entries": []},
        {"entries": [{**entry, "execution_conditions": ["different condition"]}]},
    ]
    assert all(
        not producer._has_complete_static_phase_coverage(candidate, manifest)
        for candidate in invalid_reports
    )
    assert all(
        not producer._has_complete_static_phase_coverage(report, candidate)
        for candidate in invalid_manifests
    )
    empty_report = {
        **report,
        "record_count": 0,
        "conditional_count": 0,
        "records": [],
    }
    assert not producer._has_complete_static_phase_coverage(
        empty_report, PhaseManifest(entries=()).model_dump(mode="json")
    )


def test_secure_runner_abstains_for_reported_phase_coverage_gaps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec = _inputs(tmp_path)
    source = spec.app_path / "main.py"
    source.write_text("def startup() -> None: pass\n", encoding="utf-8")
    identity = SourceIdentity(
        module="main",
        symbol="startup",
        file=str(source.resolve()),
        line=1,
        column=0,
        source_sha256="sha256:" + hashlib.sha256(source.read_bytes()).hexdigest(),
    )
    # This mirrors the mypy integration's honest partial record: a selected
    # lifecycle callback exists, but its exact registration site is unknown.
    partial = SimpleNamespace(
        records=(
            SimpleNamespace(
                phase=FrameworkPhase.STARTUP,
                contract_id="fastapi-lifespan-startup",
                callback=identity,
                registration=identity,
                framework_declaration_sha256=None,
                limitations=("no unique exact mypy call site",),
            ),
        )
    )
    partial_manifest = manifest_from_report(partial).model_dump(mode="json")
    assert partial_manifest["entries"] == []

    reports = [
        {
            "backend": "mypy",
            "unavailable_count": 1,
            "limitations": ["no unique exact mypy call site"],
            "runtime_manifest": partial_manifest,
        },
        unavailable_phase_report(
            snapshot_side="target", limitation="typed frontend unavailable"
        ).model_dump(mode="json"),
    ]

    for report in reports:
        request = replace(
            _request(spec),
            phase_manifest_state={},
            phase_manifest_source_root=spec.app_path,
        )
        payload = {
            "candidate_endpoints": [],
            "framework_phase_report": report,
        }
        monkeypatch.setattr(
            producer.subprocess,
            "run",
            lambda _command, _payload=payload, **_kwargs: SimpleNamespace(
                returncode=0, stdout=json.dumps(_payload), stderr=""
            ),
        )
        result = CommandRunner(timeout_seconds=10)("secure", "impact", request)
        assert result.impact == {"candidate_endpoints": []}
        assert request.phase_manifest_state is not None
        assert request.phase_manifest_state == {"conditional": True}


@pytest.mark.parametrize("expired_lane", [3, 4])
def test_runtime_admission_rechecked_after_each_frozen_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, expired_lane: int
) -> None:
    spec = _inputs(tmp_path)
    key = "controlled-test-secret"
    custody_key = "controlled-custody-test-secret-at-least-32-bytes"
    monkeypatch.setenv("FASTAPI_DETECTOR_RUNTIME_TRUST_KEY", key)
    monkeypatch.setenv("FASTAPI_DETECTOR_RUNTIME_TRUST_KEY_ID", "test-authority")
    monkeypatch.setenv("FASTAPI_DETECTOR_RUNTIME_TRUST_VERSION", "controlled protocol fixture")
    monkeypatch.setenv("FASTAPI_DETECTOR_RUNTIME_CUSTODY_KEY", custody_key)
    monkeypatch.setenv("FASTAPI_DETECTOR_RUNTIME_CUSTODY_KEY_ID", "fixture-custody-authority")
    receipt = _signed_evidence(_request(spec), key)
    clock = [receipt.issued_at]
    monkeypatch.setattr(producer.time, "time", lambda: clock[0])
    original_lane = producer._frozen_lane_request
    lanes = 0

    @contextmanager
    def expiring_lane(*args: Any, **kwargs: Any) -> Any:
        nonlocal lanes
        with original_lane(*args, **kwargs) as request:
            lanes += 1
            if lanes == expired_lane:
                clock[0] = receipt.expires_at
            yield request

    monkeypatch.setattr(producer, "_frozen_lane_request", expiring_lane)
    runner = SignedFakeRunner(custody_key)
    outputs = produce_snapshot_pair(
        spec,
        EntryConfiguration(None, None, "app", "mypy"),
        tmp_path / "expired-admission",
        runner=runner,
        runtime_evidence=receipt,
    )
    expected = [("secure", "list"), ("secure", "impact")]
    if expired_lane == 4:
        expected.append(("runtime", "list"))
    assert runner.calls == expected
    runtime = json.loads(outputs["runtime"].read_text(encoding="utf-8"))
    assert runtime["status"] == "failure"
    assert "stale, expired" in runtime["failure"]["message"]
    assert "runtime_custody" not in runtime
