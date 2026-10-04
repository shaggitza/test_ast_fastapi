"""Safe producer tests: fake lanes plus a source-only secure CLI smoke check."""

from __future__ import annotations

import json
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from benchmarks.real_world import _secure_publish
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

H = "sha256:" + "a" * 64
IMAGE = "registry.example/detector@sha256:" + "b" * 64


class FakeRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def __call__(self, mode: str, phase: str, request: Any) -> InvocationResult:  # noqa: ARG002
        self.calls.append((mode, phase))
        seconds = 0.25 if phase == "list" else 0.5
        if phase == "list":
            status = "established" if mode == "secure" else "runtime_observed"
            return InvocationResult(
                inventory={
                    "inventory_status": status,
                    "endpoints": [{"methods": ["GET"], "path": "/items", "surface": None}],
                },
                seconds=seconds,
                peak_rss_bytes=2048,
            )
        return InvocationResult(
            impact={
                "candidate_endpoints": [
                    {"endpoint": {"methods": ["GET"], "path": "/items", "surface": None}}
                ]
            },
            seconds=seconds,
            peak_rss_bytes=2048,
        )


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
def test_forged_stale_and_mismatched_receipts_never_open_lane(
    tmp_path: Path, tamper: Any
) -> None:
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
