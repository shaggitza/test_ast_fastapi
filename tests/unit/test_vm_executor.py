"""Fail-closed policy tests for the isolated runtime comparator."""

import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from fastapi_endpoint_detector.executor.vm_executor import (
    SandboxPolicy,
    VMExecutor,
    VMExecutorError,
)

_DIGEST = "registry.example/detector@sha256:" + "a" * 64


def _executor(tmp_path: Path, **kwargs: object) -> VMExecutor:
    profile = tmp_path / "seccomp.json"
    profile.write_text('{"defaultAction":"SCMP_ACT_ERRNO"}', encoding="utf-8")
    return VMExecutor(
        image=_DIGEST,
        seccomp_profile=profile,
        dependency_lock_hash="sha256:" + "b" * 64,
        sbom_hash="sha256:" + "c" * 64,
        **kwargs,  # type: ignore[arg-type]
    )


def test_policy_rejects_default_runtime_and_network() -> None:
    with pytest.raises(ValueError, match="gVisor/Kata"):
        SandboxPolicy(runtime="runc")
    with pytest.raises(ValueError, match="network"):
        VMExecutor(network_disabled=False)


def test_default_policy_is_bounded() -> None:
    executor = VMExecutor()

    assert executor.memory_limit == "512m"
    assert executor.cpu_quota == 50_000
    assert executor.timeout == 60
    assert executor.network_disabled is True
    assert executor.policy.pids_limit == 128
    assert executor.policy.output_limit_bytes == 4 * 1024 * 1024


@patch("subprocess.run")
def test_mutable_image_resolves_to_one_repository_digest(mock_run: Mock) -> None:
    mock_run.return_value = Mock(returncode=0, stdout=json.dumps([_DIGEST]), stderr="")
    executor = VMExecutor(image="registry.example/detector:comparison")

    assert executor.check_image_exists() is True
    assert executor._resolve_image() == _DIGEST
    assert mock_run.call_count == 1


@patch("subprocess.run")
def test_ambiguous_or_missing_image_digest_fails_closed(mock_run: Mock) -> None:
    mock_run.return_value = Mock(
        returncode=0,
        stdout=json.dumps([_DIGEST, "other.example/detector@sha256:" + "b" * 64]),
        stderr="",
    )

    assert VMExecutor(image="detector:tag").check_image_exists() is False


@patch("subprocess.run")
def test_build_image_uses_argv_and_disables_base_pull(
    mock_run: Mock,
    tmp_path: Path,
) -> None:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM scratch\n", encoding="utf-8")
    mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

    VMExecutor().build_image(dockerfile)

    command = mock_run.call_args.args[0]
    assert command[:3] == ["docker", "build", "--pull=false"]
    assert isinstance(command, list)


def test_container_command_has_complete_hardening_and_narrow_mounts(tmp_path: Path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    diff = tmp_path / "change.diff"
    diff.write_text("", encoding="utf-8")
    executor = _executor(tmp_path)
    executor._resolved_image = _DIGEST
    cidfile = tmp_path / "cid"

    command = executor._container_command(
        app,
        diff,
        "app",
        "json",
        cidfile,
        "comparison-id",
    )

    assert command[0:2] == ["docker", "run"]
    for pair in (
        ("--runtime", "runsc"),
        ("--network", "none"),
        ("--user", "65532:65532"),
        ("--cap-drop", "ALL"),
        ("--pids-limit", "128"),
        ("--memory", "512m"),
        ("--memory-swap", "512m"),
    ):
        index = command.index(pair[0])
        assert command[index + 1] == pair[1]
    assert "--read-only" in command
    assert "no-new-privileges=true" in command
    assert any(item.startswith("seccomp=") for item in command)
    assert "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777" in command
    mounts = [command[index + 1] for index, item in enumerate(command) if item == "--mount"]
    assert mounts == [
        f"type=bind,src={app},dst=/workspace/app,readonly,bind-nonrecursive",
        f"type=bind,src={diff},dst=/workspace/change.diff,readonly,bind-nonrecursive",
    ]
    assert _DIGEST in command
    assert "--device" not in command
    assert "--privileged" not in command
    assert "--env" not in command
    entrypoint = command.index("--entrypoint")
    assert command[entrypoint + 1] == "/usr/bin/env"
    image = command.index(_DIGEST)
    assert command[image + 1] == "-i"
    assert "fastapi-endpoint-detector" in command[image + 2 :]


def test_runtime_launch_requires_lock_and_sbom_attestations(tmp_path: Path) -> None:
    profile = tmp_path / "seccomp.json"
    profile.write_text('{"defaultAction":"SCMP_ACT_ERRNO"}', encoding="utf-8")
    app = tmp_path / "app"
    app.mkdir()
    executor = VMExecutor(
        image=_DIGEST,
        seccomp_profile=profile,
    )
    executor._resolved_image = _DIGEST

    with pytest.raises(VMExecutorError, match="dependency lock"):
        executor._container_command(app, None, "app", "json", tmp_path / "cid", "name")


def test_list_and_analyze_preserve_equivalent_app_configuration(tmp_path: Path) -> None:
    app = tmp_path / "application.py"
    app.write_text("application = None\n", encoding="utf-8")
    diff = tmp_path / "change.diff"
    diff.write_text("", encoding="utf-8")
    executor = _executor(tmp_path)
    executor._resolved_image = _DIGEST

    listed = executor._container_command(
        app, None, "application", "json", tmp_path / "list.cid", "list-name"
    )
    analyzed = executor._container_command(
        app, diff, "application", "json", tmp_path / "analyze.cid", "analyze-name"
    )

    for command in (listed, analyzed):
        app_index = command.index("--app")
        variable_index = command.index("--app-var")
        assert command[app_index + 1] == "/workspace/application.py"
        assert command[variable_index + 1] == "application"
    assert "list" in listed
    assert "analyze" in analyzed


def test_policy_provenance_attests_digest_seccomp_and_environment(tmp_path: Path) -> None:
    executor = _executor(tmp_path)
    executor._resolved_image = _DIGEST

    provenance = executor.policy_provenance()

    assert provenance["image"] == _DIGEST
    assert provenance["seccomp_sha256"].startswith("sha256:")
    assert provenance["policy_sha256"].startswith("sha256:")
    assert provenance["dependency_lock_hash"] == "sha256:" + "b" * 64
    assert provenance["sbom_hash"] == "sha256:" + "c" * 64
    assert set(provenance["environment"]) == set(VMExecutor.CLEAN_ENV)


def test_analyze_uses_bounded_executor_and_parses_json(tmp_path: Path) -> None:
    app = tmp_path / "app.py"
    app.write_text("app = None\n", encoding="utf-8")
    executor = _executor(tmp_path)
    executor._resolved_image = _DIGEST

    with patch.object(
        executor,
        "_execute_bounded",
        return_value=('{"endpoints": []}', ""),
    ) as execute:
        result = executor.analyze_in_vm(app)

    assert result == {"endpoints": []}
    command = execute.call_args.args[0]
    assert command[-7:] == [
        "list",
        "--app",
        "/workspace/app.py",
        "--format",
        "json",
        "--app-var",
        "app",
    ]


def test_invalid_json_and_endpoint_payload_fail_closed(tmp_path: Path) -> None:
    app = tmp_path / "app.py"
    app.write_text("app = None\n", encoding="utf-8")
    executor = _executor(tmp_path)
    executor._resolved_image = _DIGEST

    with (
        patch.object(executor, "_execute_bounded", return_value=("not-json", "")),
        pytest.raises(VMExecutorError, match="bounded JSON"),
    ):
        executor.analyze_in_vm(app)
    with (
        patch.object(executor, "analyze_in_vm", return_value={"endpoints": [{}]}),
        pytest.raises(VMExecutorError, match="invalid endpoint"),
    ):
        executor.list_endpoints_in_vm(app)


@patch("subprocess.run")
def test_cleanup_prefers_cid_and_always_kills_then_removes(
    mock_run: Mock,
    tmp_path: Path,
) -> None:
    cidfile = tmp_path / "cid"
    cidfile.write_text("abc123\n", encoding="utf-8")

    mock_run.side_effect = [
        Mock(returncode=0),
        Mock(returncode=0),
        Mock(returncode=1),
    ]

    VMExecutor._cleanup_container(cidfile, "fallback-name")

    commands = [call.args[0] for call in mock_run.call_args_list]
    assert commands == [
        ["docker", "kill", "abc123"],
        ["docker", "rm", "--force", "abc123"],
        ["docker", "container", "inspect", "abc123"],
    ]


@patch("subprocess.run")
def test_cleanup_verification_fails_if_container_remains(
    mock_run: Mock,
    tmp_path: Path,
) -> None:
    mock_run.side_effect = [
        Mock(returncode=0),
        Mock(returncode=0),
        Mock(returncode=0),
    ]

    with pytest.raises(VMExecutorError, match="still exists"):
        VMExecutor._cleanup_container(tmp_path / "missing-cid", "container-name")


@patch("subprocess.Popen")
@patch.object(VMExecutor, "_cleanup_container")
def test_launch_failure_is_structured(
    cleanup: Mock,
    popen: Mock,
    tmp_path: Path,
) -> None:
    popen.side_effect = OSError("missing")
    executor = _executor(tmp_path)

    with pytest.raises(VMExecutorError, match="failed to launch Docker"):
        executor._execute_bounded(["docker", "run"], tmp_path / "cid", "name")

    cleanup.assert_not_called()


def test_seccomp_profile_is_packaged_and_deny_by_default() -> None:
    executor = VMExecutor()
    payload = json.loads(executor.seccomp_profile.read_text(encoding="utf-8"))

    assert payload["defaultAction"] == "SCMP_ACT_ERRNO"
    assert payload["syscalls"][0]["action"] == "SCMP_ACT_ALLOW"
    assert "mount" not in payload["syscalls"][0]["names"]
    assert "ptrace" not in payload["syscalls"][0]["names"]
