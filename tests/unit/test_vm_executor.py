"""Fail-closed policy tests for the isolated runtime comparator."""

import hashlib
import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import pytest

from fastapi_endpoint_detector.executor.vm_executor import (
    SandboxPolicy,
    VMExecutor,
    VMExecutorError,
)

_DIGEST = "registry.example/detector@sha256:" + "a" * 64


@pytest.fixture(autouse=True)
def _clear_vm_policy_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in tuple(os.environ):
        if name.startswith("FASTAPI_ENDPOINT_DETECTOR_VM_"):
            monkeypatch.delenv(name)


def _image_inspect(*, digests: object, volumes: object = None) -> str:
    return json.dumps([{"RepoDigests": digests, "Config": {"Volumes": volumes}}])


def _executor(tmp_path: Path, **kwargs: object) -> VMExecutor:
    profile = tmp_path / "seccomp.json"
    profile.write_text('{"defaultAction":"SCMP_ACT_ERRNO"}', encoding="utf-8")
    profile_hash = "sha256:" + hashlib.sha256(profile.read_bytes()).hexdigest()
    return VMExecutor(
        image=_DIGEST,
        seccomp_profile=profile,
        seccomp_hash=profile_hash,
        dependency_lock_hash="sha256:" + "b" * 64,
        snapshot_lock_hash="sha256:" + "d" * 64,
        sbom_hash="sha256:" + "c" * 64,
        **kwargs,  # type: ignore[arg-type]
    )


def test_policy_rejects_unsupported_runtime_unbounded_limits_root_and_network() -> None:
    for runtime in ("runc", "custom-runtime", ""):
        with pytest.raises(ValueError, match="gVisor/Kata"):
            SandboxPolicy(runtime=runtime)
    with pytest.raises(ValueError, match="memory limit"):
        SandboxPolicy(memory_limit="unlimited", memory_swap="unlimited")
    with pytest.raises(ValueError, match="non-root"):
        SandboxPolicy(user="0:0")
    with pytest.raises(ValueError, match="network"):
        VMExecutor(network_disabled=False)


def test_image_reference_rejects_docker_option_injection_and_mutable_attestation() -> None:
    for image in ("--privileged@sha256:" + "a" * 64, "detector name:tag", "../detector:tag"):
        with pytest.raises(VMExecutorError, match="invalid Docker reference"):
            VMExecutor(image=image)
    with pytest.raises(VMExecutorError, match="immutable"):
        VMExecutor._validate_image_reference("detector:tag", immutable=True)


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
    mock_run.return_value = Mock(
        returncode=0,
        stdout=_image_inspect(digests=[_DIGEST]),
        stderr="",
    )
    executor = VMExecutor(image="registry.example/detector:comparison")

    assert executor.check_image_exists() is True
    assert executor._resolve_image() == _DIGEST
    assert mock_run.call_count == 1
    assert mock_run.call_args.args[0] == [
        "docker",
        "image",
        "inspect",
        "registry.example/detector:comparison",
    ]


@patch("subprocess.run")
def test_inspected_image_digest_cannot_become_a_docker_option(mock_run: Mock) -> None:
    mock_run.return_value = Mock(
        returncode=0,
        stdout=_image_inspect(digests=["--privileged@sha256:" + "a" * 64]),
        stderr="",
    )

    with pytest.raises(VMExecutorError, match="invalid Docker reference"):
        VMExecutor(image="detector:tag")._resolve_image()


@patch("subprocess.run")
def test_ambiguous_or_missing_image_digest_fails_closed(mock_run: Mock) -> None:
    mock_run.return_value = Mock(
        returncode=0,
        stdout=_image_inspect(digests=[_DIGEST, "other.example/detector@sha256:" + "b" * 64]),
        stderr="",
    )

    assert VMExecutor(image="detector:tag").check_image_exists() is False


@patch("subprocess.run")
def test_image_declared_volumes_are_rejected(mock_run: Mock) -> None:
    mock_run.return_value = Mock(
        returncode=0,
        stdout=_image_inspect(digests=[_DIGEST], volumes={"/host-consuming-data": {}}),
        stderr="",
    )

    with pytest.raises(VMExecutorError, match="must not declare writable volumes"):
        VMExecutor(image=_DIGEST)._resolve_image()


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


def test_container_command_has_complete_hardening_and_narrow_mounts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "HOST-SECRET")
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

    assert command[:5] == ["docker", "run", "--pull", "never", "--name"]
    assert command[command.index("--runtime") + 1] == "runsc"
    assert command[command.index("--network") + 1] == "none"
    assert command[command.index("--read-only")] == "--read-only"
    assert command[command.index("--user") + 1] == "65532:65532"
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert command[command.index("--memory") + 1] == "512m"
    assert command[command.index("--mount") + 1] == (
        f"type=bind,src={app},dst=/workspace/app,readonly,bind-recursive=disabled"
    )
    assert command[command.index("--mount", command.index("--mount") + 1) + 1] == (
        f"type=bind,src={diff},dst=/workspace/change.diff,readonly,bind-recursive=disabled"
    )
    assert command[-3:-1] == ["fastapi_endpoint_detector.parser.runtime_worker", "--request-json"]
    worker_request = json.loads(command[-1])
    assert worker_request["phase"] == "analyze"
    assert worker_request["diff_path"] == "/workspace/change.diff"
    assert all("HOST-SECRET" not in item for item in command)


def test_runtime_launch_rejects_mutated_seccomp_and_missing_snapshot_attestation(
    tmp_path: Path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    executor = _executor(tmp_path)
    executor._resolved_image = _DIGEST
    executor.seccomp_profile.write_text('{"defaultAction":"SCMP_ACT_ALLOW"}', encoding="utf-8")

    with pytest.raises(VMExecutorError, match="immutable attestation"):
        executor._container_command(app, None, "app", "json", tmp_path / "cid", "name")

    profile = tmp_path / "other-seccomp.json"
    profile.write_text('{"defaultAction":"SCMP_ACT_ERRNO"}', encoding="utf-8")
    profile_hash = "sha256:" + hashlib.sha256(profile.read_bytes()).hexdigest()
    missing_snapshot = VMExecutor(
        image=_DIGEST,
        seccomp_profile=profile,
        seccomp_hash=profile_hash,
        dependency_lock_hash="sha256:" + "b" * 64,
        sbom_hash="sha256:" + "c" * 64,
    )
    missing_snapshot._resolved_image = _DIGEST
    with pytest.raises(VMExecutorError, match="snapshot lock"):
        missing_snapshot._container_command(app, None, "app", "json", tmp_path / "cid", "name")


def test_runtime_mounts_reject_symlinks_broad_roots_and_special_files(tmp_path: Path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(app, target_is_directory=True)
    fifo = tmp_path / "change.diff"
    os.mkfifo(fifo)
    executor = _executor(tmp_path)
    executor._resolved_image = _DIGEST

    with pytest.raises(VMExecutorError, match="symlinks"):
        executor._container_command(alias, None, "app", "json", tmp_path / "cid", "name")
    with pytest.raises(VMExecutorError, match="broad"):
        executor._container_command(Path("/"), None, "app", "json", tmp_path / "cid", "name")
    nested_fifo = app / "host.pipe"
    os.mkfifo(nested_fifo)
    with pytest.raises(VMExecutorError, match="special file"):
        executor._container_command(app, None, "app", "json", tmp_path / "cid", "name")
    nested_fifo.unlink()
    with pytest.raises(VMExecutorError, match="regular file"):
        executor._container_command(app, fifo, "app", "json", tmp_path / "cid", "name")


def test_runtime_mounts_reject_docker_grammar_metacharacters(tmp_path: Path) -> None:
    executor = _executor(tmp_path)
    executor._resolved_image = _DIGEST

    for unsafe_name in ("source,src=", "source\rfield", "source\nfield"):
        app = tmp_path / unsafe_name
        app.mkdir()
        with pytest.raises(VMExecutorError, match="mount grammar metacharacter"):
            executor._container_command(app, None, "app", "json", tmp_path / "cid", "name")

        diff = tmp_path / f"{unsafe_name}.diff"
        diff.write_text("", encoding="utf-8")
        safe_app = tmp_path / f"safe-{len(unsafe_name)}"
        safe_app.mkdir(exist_ok=True)
        with pytest.raises(VMExecutorError, match="mount grammar metacharacter"):
            executor._container_command(
                safe_app,
                diff,
                "app",
                "json",
                tmp_path / "cid",
                "name",
            )

    with pytest.raises(VMExecutorError, match="mount grammar metacharacter"):
        executor._mount(tmp_path, "/workspace/app,dst=/host")


def test_runtime_mount_scan_fails_closed_on_unreadable_subtree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = tmp_path / "app"
    blocked = app / "blocked"
    blocked.mkdir(parents=True)
    os.mkfifo(blocked / "host.pipe")
    executor = _executor(tmp_path)
    executor._resolved_image = _DIGEST
    real_scandir = os.scandir

    def guarded_scandir(path: os.PathLike[str] | str) -> Any:
        if Path(path) == blocked:
            raise PermissionError("mocked unreadable subtree")
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", guarded_scandir)

    with pytest.raises(VMExecutorError, match="mocked unreadable subtree"):
        executor._container_command(app, None, "app", "json", tmp_path / "cid", "name")


def test_runtime_mount_tree_scan_is_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "main.py").write_text("app = None\n", encoding="utf-8")
    executor = _executor(tmp_path)
    executor._resolved_image = _DIGEST
    monkeypatch.setattr(VMExecutor, "_MOUNT_SCAN_LIMIT", 0)

    with pytest.raises(VMExecutorError, match="bounded mount scan"):
        executor._container_command(app, None, "app", "json", tmp_path / "cid", "name")


def test_runtime_launch_requires_lock_and_sbom_attestations(tmp_path: Path) -> None:
    profile = tmp_path / "seccomp.json"
    profile.write_text('{"defaultAction":"SCMP_ACT_ERRNO"}', encoding="utf-8")
    app = tmp_path / "app"
    app.mkdir()
    profile_hash = "sha256:" + hashlib.sha256(profile.read_bytes()).hexdigest()
    executor = VMExecutor(
        image=_DIGEST,
        seccomp_profile=profile,
        seccomp_hash=profile_hash,
        snapshot_lock_hash="sha256:" + "d" * 64,
        sbom_hash="sha256:" + "c" * 64,
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
        assert command[-3:-1] == [
            "fastapi_endpoint_detector.parser.runtime_worker",
            "--request-json",
        ]
    list_request = json.loads(listed[-1])
    analyze_request = json.loads(analyzed[-1])
    assert list_request["phase"] == "list"
    assert list_request["app_path"] == "/workspace/application.py"
    assert analyze_request["phase"] == "analyze"
    assert analyze_request["diff_path"] == "/workspace/change.diff"


def test_lifespan_manifest_uses_same_hardened_worker_request(tmp_path: Path) -> None:
    app = tmp_path / "application.py"
    app.write_text("application = None\n", encoding="utf-8")
    executor = _executor(tmp_path)
    executor._resolved_image = _DIGEST
    identity = {
        "module": "sample",
        "symbol": "lifespan",
        "file": str(app.resolve()),
        "line": 1,
        "column": 0,
        "end_line": 1,
        "end_column": 1,
        "source_sha256": "sha256:" + "a" * 64,
    }
    manifest = {
        "schema_version": 1,
        "protocol": "framework-phase-manifest-v1",
        "entries": [
            {
                "callback": identity,
                "registration": identity,
                "phase": "startup",
                "execution_conditions": [],
                "contract_id": "fastapi-lifespan-startup",
                "contract_sha256": "sha256:" + "b" * 64,
                "source_sha256": "sha256:" + "c" * 64,
                "callback_file_sha256": "d" * 64,
                "registration_file_sha256": "e" * 64,
                "inventory_sha256": "sha256:" + "f" * 64,
                "engine_sha256": "sha256:" + "1" * 64,
                "config_sha256": "sha256:" + "2" * 64,
            }
        ],
    }

    command = executor._container_command(
        app,
        None,
        "application",
        "json",
        tmp_path / "phase.cid",
        "phase-name",
        phase_manifest=manifest,
    )
    request = json.loads(command[-1])

    assert request["phase"] == "list"
    assert request["phase_manifest"]["entries"][0]["callback"]["file"] == (
        "/workspace/application.py"
    )
    assert (
        request["phase_manifest_sha256"]
        == "sha256:"
        + hashlib.sha256(
            json.dumps(request["phase_manifest"], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )
    assert "--runtime" in command
    assert executor.policy.runtime in command
    assert "--network" in command and command[command.index("--network") + 1] == "none"
    assert "--pid" in command and command[command.index("--pid") + 1] == ""
    assert "--security-opt" in command


def test_selected_runtime_entry_is_explicit_in_worker_argv(tmp_path: Path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "main.py").write_text("app = None\n", encoding="utf-8")
    executor = _executor(tmp_path)
    executor._resolved_image = _DIGEST
    command = executor._container_command(
        app,
        None,
        "application",
        "json",
        tmp_path / "cid",
        "selected-entry",
        "project.factory:create_app",
        "project.bootstrap:register_routes",
    )
    request = json.loads(command[-1])
    assert request == {
        "schema_version": 3,
        "phase": "list",
        "app_path": "/workspace/app",
        "app_variable": "application",
        "app_entry": "project.factory:create_app",
        "bootstrap_entry": "project.bootstrap:register_routes",
        "diff_path": None,
        "output_limit_bytes": executor.policy.output_limit_bytes,
        "dependency_max_depth": 10,
        "dependency_max_nodes": 4096,
        "dependency_max_work": 65536,
        "runtime_pins": {
            "runtime_image": _DIGEST,
            "runtime_image_digest": _DIGEST.split("@", maxsplit=1)[1],
            "dependency_lock_sha256": "sha256:" + "b" * 64,
            "snapshot_lock_sha256": "sha256:" + "d" * 64,
            "sbom_sha256": "sha256:" + "c" * 64,
            "seccomp_sha256": executor.seccomp_hash,
            "runtime_policy_sha256": executor.policy_provenance()["policy_sha256"],
        },
    }


def test_selected_entry_with_diff_uses_equivalent_analyze_worker(tmp_path: Path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    diff = tmp_path / "change.diff"
    diff.write_text("", encoding="utf-8")
    executor = _executor(tmp_path)
    executor._resolved_image = _DIGEST
    command = executor._container_command(
        app,
        diff,
        "app",
        "json",
        tmp_path / "cid",
        "selected-entry",
        "project.factory:create_app",
    )
    request = json.loads(command[-1])
    assert request["phase"] == "analyze"
    assert request["app_entry"] == "project.factory:create_app"
    assert request["diff_path"] == "/workspace/change.diff"


def test_worker_rejects_drift_from_the_producer_policy_pin(tmp_path: Path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    executor = _executor(tmp_path, expected_policy_sha256="sha256:" + "0" * 64)
    executor._resolved_image = _DIGEST

    with pytest.raises(VMExecutorError, match="producer's immutable pin"):
        executor._container_command(app, None, "app", "json", tmp_path / "cid", "name")


def test_policy_provenance_attests_digest_seccomp_and_environment(tmp_path: Path) -> None:
    executor = _executor(tmp_path)
    executor._resolved_image = _DIGEST

    provenance = executor.policy_provenance()

    assert provenance["image"] == _DIGEST
    assert provenance["seccomp_sha256"].startswith("sha256:")
    assert provenance["policy_sha256"].startswith("sha256:")
    assert provenance["dependency_lock_hash"] == "sha256:" + "b" * 64
    assert provenance["snapshot_lock_hash"] == "sha256:" + "d" * 64
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
    assert command[-2] == "--request-json"
    request = json.loads(command[-1])
    assert request["phase"] == "list"
    assert request["app_path"] == "/workspace/app.py"


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
def test_cleanup_proves_generated_name_and_cid_are_absent(
    mock_run: Mock,
    tmp_path: Path,
) -> None:
    cidfile = tmp_path / "cid"
    cid = "a" * 64
    cidfile.write_text(cid + "\n", encoding="utf-8")
    mock_run.side_effect = [
        Mock(returncode=0),
        Mock(returncode=0),
        Mock(returncode=0, stdout="", stderr=""),
        Mock(returncode=0, stdout="\n", stderr=""),
    ]

    VMExecutor._cleanup_container(cidfile, "fallback-name")

    assert [call.args[0] for call in mock_run.call_args_list] == [
        ["docker", "kill", cid],
        ["docker", "rm", "--force", cid],
        [
            "docker",
            "container",
            "ls",
            "--all",
            "--no-trunc",
            "--quiet",
            "--filter",
            "name=^/fallback-name$",
        ],
        [
            "docker",
            "container",
            "ls",
            "--all",
            "--no-trunc",
            "--quiet",
            "--filter",
            f"id={cid}",
        ],
    ]
    for call in mock_run.call_args_list[2:]:
        assert call.kwargs["timeout"] == 10
        assert call.kwargs["text"] is True


@patch("subprocess.run")
def test_cleanup_rejects_invalid_cid_but_removes_by_safe_name(
    mock_run: Mock,
    tmp_path: Path,
) -> None:
    cidfile = tmp_path / "cid"
    cidfile.write_text("--all\n", encoding="utf-8")
    mock_run.side_effect = [
        Mock(returncode=0),
        Mock(returncode=0),
        Mock(returncode=0, stdout="", stderr=""),
    ]

    with pytest.raises(VMExecutorError, match="invalid container identifier"):
        VMExecutor._cleanup_container(cidfile, "safe-container")

    assert [call.args[0] for call in mock_run.call_args_list] == [
        ["docker", "kill", "safe-container"],
        ["docker", "rm", "--force", "safe-container"],
        [
            "docker",
            "container",
            "ls",
            "--all",
            "--no-trunc",
            "--quiet",
            "--filter",
            "name=^/safe-container$",
        ],
    ]


@patch("subprocess.run")
def test_cleanup_verification_fails_if_container_remains(
    mock_run: Mock,
    tmp_path: Path,
) -> None:
    mock_run.side_effect = [
        Mock(returncode=0),
        Mock(returncode=0),
        Mock(returncode=0, stdout="a" * 64 + "\n", stderr=""),
    ]

    with pytest.raises(VMExecutorError, match="still exists"):
        VMExecutor._cleanup_container(tmp_path / "missing-cid", "container-name")


@patch("subprocess.run")
def test_cleanup_verification_treats_daemon_errors_as_failures(
    mock_run: Mock,
    tmp_path: Path,
) -> None:
    mock_run.side_effect = [
        Mock(returncode=0),
        Mock(returncode=0),
        Mock(returncode=1, stdout="", stderr="permission denied by daemon"),
    ]

    with pytest.raises(VMExecutorError, match=r"query.*failed.*permission denied"):
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

    assert executor._verified_seccomp_hash() == VMExecutor.PACKAGED_SECCOMP_SHA256
    assert payload["defaultAction"] == "SCMP_ACT_ERRNO"
    assert payload["syscalls"][0]["action"] == "SCMP_ACT_ALLOW"
    assert "mount" not in payload["syscalls"][0]["names"]
    assert "ptrace" not in payload["syscalls"][0]["names"]
