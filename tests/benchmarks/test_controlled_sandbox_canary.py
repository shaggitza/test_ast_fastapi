"""Offline policy and ownership tests for the GH101 canary assay."""

from __future__ import annotations

import json
import subprocess
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest
from tests.benchmarks import controlled_sandbox_canary as assay

from fastapi_endpoint_detector.executor.vm_executor import VMExecutor, VMExecutorError

if TYPE_CHECKING:
    from pathlib import Path


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
    assert result["timeout_observed"] is True
    assert result["cleanup_verified"] is True
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
