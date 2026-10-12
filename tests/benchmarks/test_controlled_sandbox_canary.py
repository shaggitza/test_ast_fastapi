"""Offline policy and ownership tests for the GH101 canary assay."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from tests.benchmarks import controlled_sandbox_canary as assay

from fastapi_endpoint_detector.executor.vm_executor import VMExecutor, VMExecutorError


def test_inspection_only_renders_hardened_command_and_removes_owned_mount(tmp_path: Path) -> None:
    result = assay._run_case(tmp_path, "canary", 10, inspect_only=True)
    command = result["pins"]["argv"]

    assert result["mode"] == "inspection-only"
    assert command[:2] == ["docker", "run"]
    assert command[command.index("--runtime") + 1] == "runsc"
    assert command[command.index("--network") + 1] == "none"
    assert command[command.index("--user") + 1] == "65532:65532"
    assert command[command.index("--read-only")] == "--read-only"
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert "no-new-privileges=true" in command
    assert command[command.index("--tmpfs") + 1].startswith("/tmp:rw,noexec,nosuid,nodev,")
    mount = command[command.index("--mount") + 1]
    assert mount.endswith("dst=/workspace/app,readonly,bind-recursive=disabled")
    assert command[-3:] == ["/workspace/app/canary.py", "canary", command[-1]]
    assert (
        len(
            {
                result["pins"][key]
                for key in (
                    "source_sha256",
                    "fixture_lock_sha256",
                    "dependency_lock_sha256",
                    "sbom_sha256",
                    "seccomp_sha256",
                    "policy_sha256",
                )
            }
        )
        == 6
    )
    assert list(tmp_path.iterdir()) == []


def test_assay_execution_is_mocked_and_reports_only_controlled_synthetic(tmp_path: Path) -> None:
    observation = {"marker_hidden": True, "network_unavailable": True, "readonly": True}
    with patch.object(
        VMExecutor, "_execute_bounded", return_value=(json.dumps(observation), "")
    ) as run:
        result = assay._run_case(tmp_path, "canary", 10, inspect_only=False)

    run.assert_called_once()
    assert result["mode"] == "controlled_synthetic"
    assert result["canary_observation"] == observation
    assert "trusted_runtime_proof" not in result
    assert list(tmp_path.iterdir()) == []


def test_timeout_requires_executor_timeout_and_unique_cid_cleanup(tmp_path: Path) -> None:
    with patch.object(
        VMExecutor,
        "_execute_bounded",
        side_effect=VMExecutorError("Container execution timed out after 2 seconds"),
    ) as run:
        result = assay._run_case(tmp_path, "timeout", 2, inspect_only=False)

    command, cidfile, name = run.call_args.args
    assert command[command.index("--name") + 1] == name
    assert name.startswith("gh101-canary-")
    assert cidfile.parent.parent == tmp_path
    assert result["host_execution_deadline_observed"] is True
    assert result["cleanup_verified"] is False
    assert "container_id" not in result
    assert "loop_execution_observed" not in result
    assert result["mode"] == "controlled_synthetic"
    assert list(tmp_path.iterdir()) == []


def test_timeout_without_timeout_evidence_fails_and_cleanup_still_removes_fixture(
    tmp_path: Path,
) -> None:
    with (
        patch.object(VMExecutor, "_execute_bounded", return_value=("finished", "")),
        pytest.raises(RuntimeError, match="unexpectedly completed"),
    ):
        assay._run_case(tmp_path, "timeout", 2, inspect_only=False)
    assert list(tmp_path.iterdir()) == []


def test_cid_cleanup_targets_only_recorded_owned_container_and_verifies_absence(
    tmp_path: Path,
) -> None:
    cid = "a" * 64
    cidfile = tmp_path / "owned.cid"
    cidfile.write_text(cid, encoding="utf-8")
    completed = subprocess.CompletedProcess([], 0, stdout="", stderr="")
    with patch(
        "fastapi_endpoint_detector.executor.vm_executor.subprocess.run", return_value=completed
    ) as run:
        VMExecutor._cleanup_container(cidfile, "gh101-canary-owned")

    commands = [call.args[0] for call in run.call_args_list]
    assert commands[:2] == [["docker", "kill", cid], ["docker", "rm", "--force", cid]]
    assert commands[2][-2:] == ["--filter", "name=^/gh101-canary-owned$"]
    assert commands[3][-2:] == ["--filter", f"id={cid}"]


def test_timeout_cleanup_failure_cannot_be_reported_as_observed(tmp_path: Path) -> None:
    with (
        patch.object(
            VMExecutor,
            "_execute_bounded",
            side_effect=VMExecutorError("sandbox cleanup failed: still exists"),
        ),
        pytest.raises(VMExecutorError, match="cleanup failed"),
    ):
        assay._run_case(tmp_path, "timeout", 2, inspect_only=False)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    ("cid_text", "cleanup_ok", "expected_verified", "expected_id"),
    [
        ("a" * 64, True, True, "a" * 64),
        ("", True, False, None),
        ("not-a-cid", True, False, None),
        ("z" * 129, True, False, None),
        ("b" * 64, False, False, "b" * 64),
    ],
)
def test_recorded_executor_captures_cid_before_unmodified_cleanup(
    tmp_path: Path,
    cid_text: str,
    cleanup_ok: bool,
    expected_verified: bool,
    expected_id: str | None,
) -> None:
    cidfile = tmp_path / "owned.cid"
    cidfile.write_text(cid_text, encoding="utf-8")
    executor = assay.RecordedExecutor()
    completed = subprocess.CompletedProcess([], 0, stdout="", stderr="")

    def run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if command[1:3] == ["container", "ls"]:
            if not cleanup_ok:
                return subprocess.CompletedProcess(command, 0, stdout="still-present", stderr="")
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        return completed

    with patch(
        "fastapi_endpoint_detector.executor.vm_executor.subprocess.run", side_effect=run
    ) as docker:
        if cleanup_ok:
            executor._cleanup_container(cidfile, "gh101-canary-owned")
        else:
            with pytest.raises(VMExecutorError, match="cleanup failed"):
                executor._cleanup_container(cidfile, "gh101-canary-owned")

    receipt = executor.cleanup_receipt
    assert receipt["container_id"] == expected_id
    assert receipt["cleanup_verified"] is expected_verified
    assert receipt["container_name"] == "gh101-canary-owned"
    assert receipt.get("name_absence_verified", False) is cleanup_ok
    commands = [call.args[0] for call in docker.call_args_list]
    assert commands[0] == ["docker", "kill", expected_id or "gh101-canary-owned"]
    assert commands[1][:3] == ["docker", "rm", "--force"]
    assert commands[1][-1] == (expected_id or "gh101-canary-owned")
    assert any("name=^/gh101-canary-owned$" in command for command in commands)
    assert any(
        (expected_id is None and "id=" not in " ".join(command))
        or (expected_id is not None and f"id={expected_id}" in command)
        for command in commands
        if command[1:3] == ["container", "ls"]
    )


def test_recorded_executor_cleanup_runs_when_cid_capture_read_fails(tmp_path: Path) -> None:
    executor = assay.RecordedExecutor()
    cidfile = tmp_path / "unreadable.cid"
    completed = subprocess.CompletedProcess([], 0, stdout="", stderr="")

    def fail_original_read(path: Path, *args: object, **kwargs: object):
        if path == cidfile:
            raise OSError("read denied")
        return original_open(path, *args, **kwargs)

    original_open = Path.open
    with (
        patch.object(Path, "open", fail_original_read),
        patch(
            "fastapi_endpoint_detector.executor.vm_executor.subprocess.run",
            return_value=completed,
        ) as docker,
    ):
        executor._cleanup_container(cidfile, "gh101-canary-owned")

    assert executor.cleanup_receipt["container_id"] is None
    assert executor.cleanup_receipt["cleanup_verified"] is False
    assert docker.call_count == 3
    assert docker.call_args_list[0].args[0] == ["docker", "kill", "gh101-canary-owned"]


def test_recorded_executor_binds_core_cleanup_to_captured_snapshot(tmp_path: Path) -> None:
    captured = "a" * 64
    replacement = "b" * 64
    cidfile = tmp_path / "owned.cid"
    cidfile.write_text(captured, encoding="utf-8")
    completed = subprocess.CompletedProcess([], 0, stdout="", stderr="")

    def run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if command[:2] == ["docker", "kill"]:
            cidfile.write_text(replacement, encoding="utf-8")
        return completed

    with patch(
        "fastapi_endpoint_detector.executor.vm_executor.subprocess.run", side_effect=run
    ) as docker:
        assay.RecordedExecutor._cleanup_container(cidfile, "gh101-canary-owned")

    commands = [call.args[0] for call in docker.call_args_list]
    assert commands[0] == ["docker", "kill", captured]
    assert commands[1] == ["docker", "rm", "--force", captured]
    assert any(f"id={captured}" in command for command in commands)
    assert not any(f"id={replacement}" in command for command in commands)
    assert assay.RecordedExecutor.cleanup_receipt["container_id"] == captured
    assert assay.RecordedExecutor.cleanup_receipt["cleanup_verified"] is True


@pytest.mark.parametrize(
    ("error", "timeout"),
    [
        (VMExecutorError("sandbox cleanup failed: docker container ls timed out after 10s"), 2),
        (RuntimeError("Container execution timed out after 2 seconds"), 2),
        (VMExecutorError("Container execution timed out after 3 seconds"), 2),
    ],
)
def test_timeout_rejects_cleanup_timeout_wrong_type_and_mismatched_deadline(
    tmp_path: Path, error: Exception, timeout: int
) -> None:
    with (
        patch.object(VMExecutor, "_execute_bounded", side_effect=error),
        pytest.raises(type(error), match=r"timed out|cleanup failed"),
    ):
        assay._run_case(tmp_path, "timeout", timeout, inspect_only=False)
    assert list(tmp_path.iterdir()) == []
