"""Owned-fixture protocol checks. All container calls remain mocked."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Literal
from unittest.mock import Mock

import pytest
from tests.benchmarks.controlled_synthetic_phase import (
    FIXTURE_BYTES,
    compare_controlled_synthetic,
    execute_raw_controlled_fixture,
    static_phase_manifest,
    write_fixture,
)

from fastapi_endpoint_detector.analyzer.framework_phase_runtime import (
    PhaseManifest,
    PhaseObservation,
)
from fastapi_endpoint_detector.executor.vm_executor import VMExecutor


@pytest.fixture(scope="module")
def owned_static_fixture(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, PhaseManifest]:
    source = write_fixture(tmp_path_factory.mktemp("gh104-owned") / "fixture")
    return source, static_phase_manifest(source)


def _observation(
    manifest: PhaseManifest,
    *,
    phases: tuple[str, ...] = ("startup", "shutdown"),
    status: Literal["completed", "startup_failed", "unavailable"] = "completed",
    role: Literal["positive_observation_only", "self_reported_nonpositive"] = (
        "positive_observation_only"
    ),
) -> PhaseObservation:
    entries = manifest.entries
    return PhaseObservation(
        manifest_sha256=manifest.digest,
        observed=tuple(
            {
                "callback": entry.callback.model_dump(mode="json"),
                "registration": entry.registration.model_dump(mode="json"),
                "phase": entry.phase,
                "manifest_sha256": manifest.digest,
                "execution_conditions": list(entry.execution_conditions),
            }
            for entry in entries
            if entry.phase in phases
        ),
        unavailable=(),
        execution_status=status,
        role=role,
    )


def _projected_request(
    executor: object, root: Path, kwargs: dict[str, object]
) -> dict[str, object]:
    manifest = PhaseManifest.model_validate(kwargs["phase_manifest"])
    projected = VMExecutor._container_phase_manifest(
        manifest.model_dump(mode="json"), root, "/workspace/app", source_root=root
    )
    request: dict[str, object] = {
        "schema_version": 3,
        "phase": "list",
        "phase_manifest": projected,
        "phase_manifest_sha256": PhaseManifest.model_validate(projected).digest,
    }
    return request


def test_static_manifest_comes_from_real_framework_phase_report(
    owned_static_fixture: tuple[Path, PhaseManifest],
) -> None:
    source, manifest = owned_static_fixture
    assert source.read_bytes() == FIXTURE_BYTES
    assert {entry.phase for entry in manifest.entries} == {"startup", "shutdown"}
    assert {entry.callback.symbol for entry in manifest.entries} == {"startup", "shutdown"}
    assert all(entry.callback.file == str(source.resolve()) for entry in manifest.entries)
    assert all(entry.inventory_sha256 != entry.source_sha256 for entry in manifest.entries)


def test_real_executor_command_contains_projected_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    owned_static_fixture: tuple[Path, PhaseManifest],
) -> None:
    source, manifest = owned_static_fixture
    executor = VMExecutor(
        image="fixture/runtime:latest",
        dependency_lock_hash="sha256:" + "1" * 64,
        snapshot_lock_hash="sha256:" + "2" * 64,
        sbom_hash="sha256:" + "3" * 64,
    )
    monkeypatch.setattr(executor, "_resolve_image", lambda: "fixture/runtime@sha256:" + "4" * 64)
    command = executor._container_command(
        source.parent,
        None,
        "app",
        "json",
        tmp_path / "container.cid",
        "gh104-projection-test",
        phase_manifest=manifest.model_dump(mode="json"),
        phase_manifest_source_root=source.parent,
    )
    assert command[-2] == "--request-json"
    request = json.loads(command[-1])
    expected = VMExecutor._container_phase_manifest(
        manifest.model_dump(mode="json"),
        source.parent,
        "/workspace/app",
        source_root=source.parent,
    )
    assert request["phase_manifest"] == expected
    projected = PhaseManifest.model_validate(request["phase_manifest"])
    assert request["phase_manifest_sha256"] == projected.digest
    assert request["phase_manifest_sha256"] != manifest.digest


def test_only_complete_raw_observation_is_positive(
    owned_static_fixture: tuple[Path, PhaseManifest],
) -> None:
    _, manifest = owned_static_fixture
    result = compare_controlled_synthetic(manifest, _observation(manifest))
    assert result.role == "controlled_synthetic"
    assert "not trusted runtime evidence" in result.execution_claim
    with pytest.raises(ValueError, match="every expected"):
        compare_controlled_synthetic(manifest, _observation(manifest, phases=()))
    with pytest.raises(ValueError, match="positive raw"):
        compare_controlled_synthetic(
            manifest, _observation(manifest, role="self_reported_nonpositive")
        )
    with pytest.raises(ValueError, match="failed execution cannot carry"):
        compare_controlled_synthetic(manifest, _observation(manifest, status="startup_failed"))
    mismatched = _observation(manifest).model_copy(update={"manifest_sha256": "sha256:" + "0" * 64})
    with pytest.raises(ValueError, match="different manifest"):
        compare_controlled_synthetic(manifest, mismatched)


def test_fixture_creation_rejects_existing_root_symlink_and_extra_files(tmp_path: Path) -> None:
    existing = tmp_path / "existing"
    existing.mkdir()
    (existing / "main.py").write_text("caller code", encoding="utf-8")
    with pytest.raises(FileExistsError):
        write_fixture(existing)
    assert (existing / "main.py").read_text(encoding="utf-8") == "caller code"

    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(FileExistsError):
        write_fixture(link)

    source = write_fixture(tmp_path / "owned")
    (source.parent / "extra.py").write_text("pass", encoding="utf-8")
    with pytest.raises(ValueError, match=r"only main\.py"):
        static_phase_manifest(source)


def test_modified_fixture_is_rejected(tmp_path: Path) -> None:
    source = write_fixture(tmp_path / "fixture")
    source.write_bytes(FIXTURE_BYTES + b"# modified\n")
    with pytest.raises(ValueError, match="exact owned source bytes"):
        static_phase_manifest(source)


def test_raw_execution_creates_and_uses_its_own_exact_fixture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor = Mock()

    def command(root: Path, *_args: object, **kwargs: object) -> list[str]:
        assert (root / "main.py").read_bytes() == FIXTURE_BYTES
        assert sorted(item.name for item in root.iterdir()) == ["main.py"]
        executor.manifest = kwargs["phase_manifest"]
        request = _projected_request(executor, root, kwargs)
        executor.request = request
        return ["docker", "run", "--request-json", json.dumps(request)]

    executor._container_command.side_effect = command

    def execute(_command: list[str], _cidfile: Path, _name: str) -> tuple[str, str]:
        root = Path(executor._container_command.call_args.args[0])
        assert (root / "main.py").read_bytes() == FIXTURE_BYTES
        assert stat.S_IMODE(root.stat().st_mode) == 0o555
        assert stat.S_IMODE((root / "main.py").stat().st_mode) == 0o444
        assert root.stat().st_uid == os.geteuid()
        assert os.access(root, os.X_OK)
        assert os.access(root / "main.py", os.R_OK)
        manifest = PhaseManifest.model_validate(executor.request["phase_manifest"])
        observation = _observation(manifest)
        return json.dumps(
            {
                "schema_version": 3,
                "status": "ok",
                "phase": "list",
                "phase_observation": observation.model_dump(mode="json"),
            }
        ), ""

    executor._execute_bounded.side_effect = execute
    result = execute_raw_controlled_fixture(executor)
    executor._container_command.assert_called_once()
    executor._execute_bounded.assert_called_once()
    assert result.role == "controlled_synthetic"
    assert result.host_manifest_sha256 != result.container_manifest_sha256


def test_real_command_and_bounded_execution_use_exact_projected_fixture(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executor = VMExecutor(
        image="fixture/runtime:latest",
        dependency_lock_hash="sha256:" + "1" * 64,
        snapshot_lock_hash="sha256:" + "2" * 64,
        sbom_hash="sha256:" + "3" * 64,
    )
    monkeypatch.setattr(executor, "_resolve_image", lambda: "fixture/runtime@sha256:" + "4" * 64)
    original_transport = executor._worker_request_transport

    def large_transport(request: dict[str, object], cidfile: Path) -> tuple[list[str], list[str]]:
        # Keep the real projection and request builder, adding only enough padding to
        # exercise their genuine request-file transport branch.
        request["transport_padding"] = "x" * (65 * 1024)
        return original_transport(request, cidfile)

    monkeypatch.setattr(executor, "_worker_request_transport", large_transport)
    seen: dict[str, object] = {}

    def bounded(command: list[str], cidfile: Path, _name: str) -> tuple[str, str]:
        app_mount = next(
            arg
            for index, arg in enumerate(command[:-1])
            if command[index - 1] == "--mount" and "dst=/workspace/app" in arg
        )
        root = Path(next(part[4:] for part in app_mount.split(",") if part.startswith("src=")))
        source = root / "main.py"
        assert source.read_bytes() == FIXTURE_BYTES
        assert stat.S_IMODE(root.stat().st_mode) == 0o555
        assert stat.S_IMODE(source.stat().st_mode) == 0o444
        assert command[-2:] == ["--request-file", "/workspace/runtime-request.json"]
        req_path = cidfile.with_suffix(".request.json")
        assert req_path.stat().st_size > 64 * 1024
        request = json.loads(req_path.read_text(encoding="utf-8"))
        seen["request"] = request
        projected = PhaseManifest.model_validate(request["phase_manifest"])
        host = PhaseManifest.model_validate(seen["host_manifest"])
        assert request["schema_version"] == 3 and request["phase"] == "list"
        assert request["phase_manifest_sha256"] == projected.digest
        assert request["phase_manifest_sha256"] != host.digest
        host_by_phase = {entry.phase: entry for entry in host.entries}
        for entry in projected.entries:
            expected = host_by_phase[entry.phase]
            assert entry.callback.file == "/workspace/app/main.py"
            assert entry.registration.file == "/workspace/app/main.py"
            callback = entry.callback.model_copy(update={"file": expected.callback.file})
            registration = entry.registration.model_copy(
                update={"file": expected.registration.file}
            )
            assert callback == expected.callback
            assert registration == expected.registration
            projected_entry = entry.model_copy(
                update={"callback": expected.callback, "registration": expected.registration}
            )
            assert projected_entry == expected
        output = {
            "schema_version": 3,
            "status": "ok",
            "phase": "list",
            "phase_observation": _observation(projected).model_dump(mode="json"),
        }
        return json.dumps(output), ""

    def command_builder(root: Path, *args: object, **kwargs: object) -> list[str]:
        seen["host_manifest"] = kwargs["phase_manifest"]
        assert (root / "main.py").read_bytes() == FIXTURE_BYTES
        return original_builder(root, *args, **kwargs)

    original_builder = executor._container_command
    monkeypatch.setattr(executor, "_container_command", command_builder)
    monkeypatch.setattr(executor, "_execute_bounded", bounded)
    result = execute_raw_controlled_fixture(executor)
    assert result.role == "controlled_synthetic"
    assert result.host_manifest_sha256 != result.container_manifest_sha256
    assert seen["request"]["transport_padding"]


@pytest.mark.parametrize("corruption", ["host_digest", "projection", "digest", "schema", "phase"])
def test_raw_execution_rejects_invalid_request_before_bounded_execution(
    monkeypatch: pytest.MonkeyPatch, corruption: str
) -> None:
    executor = Mock()

    def command(root: Path, *_args: object, **kwargs: object) -> list[str]:
        request = _projected_request(executor, root, kwargs)
        if corruption == "host_digest":
            request["phase_manifest_sha256"] = PhaseManifest.model_validate(
                kwargs["phase_manifest"]
            ).digest
        elif corruption == "projection":
            request["phase_manifest"]["entries"][0]["phase"] = "altered"
        elif corruption == "digest":
            request["phase_manifest_sha256"] = "sha256:" + "0" * 64
        elif corruption == "schema":
            request["schema_version"] = True
        else:
            request["phase"] = "analyze"
        return ["docker", "run", "--request-json", json.dumps(request)]

    executor._container_command.side_effect = command
    with pytest.raises(ValueError):
        execute_raw_controlled_fixture(executor)
    executor._execute_bounded.assert_not_called()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("status", "failed"),
        ("phase", "analyze"),
        ("schema_version", 2),
        ("observation_digest", "host"),
    ],
)
def test_raw_execution_rejects_invalid_response_envelope(field: str, value: object) -> None:
    executor = Mock()

    def command(root: Path, *_args: object, **kwargs: object) -> list[str]:
        executor.request = _projected_request(executor, root, kwargs)
        return ["docker", "run", "--request-json", json.dumps(executor.request)]

    executor._container_command.side_effect = command

    def execute(*_args: object) -> tuple[str, str]:
        projected = PhaseManifest.model_validate(executor.request["phase_manifest"])
        payload: dict[str, object] = {
            "schema_version": 3,
            "status": "ok",
            "phase": "list",
            "phase_observation": _observation(projected).model_dump(mode="json"),
        }
        if field == "observation_digest":
            host = PhaseManifest.model_validate(
                executor._container_command.call_args.kwargs["phase_manifest"]
            )
            assert host.digest != projected.digest
            payload["phase_observation"]["manifest_sha256"] = host.digest
        else:
            payload[field] = value
        return json.dumps(payload), ""

    executor._execute_bounded.side_effect = execute
    error_match = (
        "manifest digest mismatch" if field == "observation_digest" else "schema, status, or phase"
    )
    with pytest.raises(ValueError, match=error_match):
        execute_raw_controlled_fixture(executor)


@pytest.mark.parametrize("schema_version", [2, "3", True])
def test_raw_payload_requires_integer_schema_three(schema_version: object) -> None:
    executor = Mock()

    def command(root: Path, *_args: object, **kwargs: object) -> list[str]:
        executor.request = _projected_request(executor, root, kwargs)
        return ["docker", "run", "--request-json", json.dumps(executor.request)]

    executor._container_command.side_effect = command

    def execute(*_args: object) -> tuple[str, str]:
        manifest = PhaseManifest.model_validate(executor.request["phase_manifest"])
        return json.dumps(
            {
                "schema_version": schema_version,
                "status": "ok",
                "phase_observation": _observation(manifest).model_dump(mode="json"),
            }
        ), ""

    executor._execute_bounded.side_effect = execute
    with pytest.raises(ValueError, match="schema, status, or phase"):
        execute_raw_controlled_fixture(executor)


def test_raw_payload_requires_both_expected_phases() -> None:
    executor = Mock()

    def command(root: Path, *_args: object, **kwargs: object) -> list[str]:
        executor.request = _projected_request(executor, root, kwargs)
        return ["docker", "run", "--request-json", json.dumps(executor.request)]

    executor._container_command.side_effect = command

    def execute(*_args: object) -> tuple[str, str]:
        manifest = PhaseManifest.model_validate(executor.request["phase_manifest"])
        observation = _observation(manifest, phases=("startup",))
        return json.dumps(
            {
                "schema_version": 3,
                "status": "ok",
                "phase": "list",
                "phase_observation": observation.model_dump(mode="json"),
            }
        ), ""

    executor._execute_bounded.side_effect = execute
    with pytest.raises(ValueError, match="every expected"):
        execute_raw_controlled_fixture(executor)


def test_raw_payload_requires_list_phase() -> None:
    executor = Mock()

    def command(root: Path, *_args: object, **kwargs: object) -> list[str]:
        executor.request = _projected_request(executor, root, kwargs)
        return ["docker", "run", "--request-json", json.dumps(executor.request)]

    executor._container_command.side_effect = command

    def execute(*_args: object) -> tuple[str, str]:
        manifest = PhaseManifest.model_validate(executor.request["phase_manifest"])
        return json.dumps(
            {
                "schema_version": 3,
                "status": "ok",
                "phase": "analyze",
                "phase_observation": _observation(manifest).model_dump(mode="json"),
            }
        ), ""

    executor._execute_bounded.side_effect = execute
    with pytest.raises(ValueError, match="schema, status, or phase"):
        execute_raw_controlled_fixture(executor)
