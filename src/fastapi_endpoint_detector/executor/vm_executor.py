"""Hardened container boundary for explicit runtime-import comparisons.

Docker alone is not described as a VM boundary.  Runtime execution is allowed only
with an immutable image digest and a non-default isolation runtime (gVisor/Kata).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import stat
import subprocess
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, ClassVar

from fastapi_endpoint_detector.models.endpoint import Endpoint


class VMExecutorError(Exception):
    """A sandbox policy, launch, timeout, or extraction failure."""


@dataclass(frozen=True)
class SandboxPolicy:
    """Versioned fail-closed runtime policy and bounded resource limits."""

    SAFE_RUNTIMES: ClassVar[frozenset[str]] = frozenset(
        {"runsc", "io.containerd.runsc.v1", "kata-runtime", "io.containerd.kata.v2"}
    )

    version: int = 1
    runtime: str = "runsc"
    user: str = "65532:65532"
    memory_limit: str = "512m"
    memory_swap: str = "512m"
    cpu_quota: int = 50_000
    cpu_period: int = 100_000
    pids_limit: int = 128
    nofile_limit: int = 256
    nproc_limit: int = 128
    fsize_limit_kib: int = 16_384
    tmpfs_size: str = "64m"
    output_limit_bytes: int = 4 * 1024 * 1024

    def __post_init__(self) -> None:
        if self.version != 1:
            raise ValueError("unsupported sandbox policy version")
        if self.runtime not in self.SAFE_RUNTIMES:
            raise ValueError("runtime sandbox requires an explicitly supported gVisor/Kata runtime")
        if re.fullmatch(r"[1-9][0-9]*[bkmg]?", self.memory_limit) is None:
            raise ValueError("memory limit must be a positive Docker byte value")
        if self.memory_swap != self.memory_limit:
            raise ValueError("memory and swap limits must be identical")
        user_match = re.fullmatch(r"([0-9]+):([0-9]+)", self.user)
        if user_match is None or any(int(value) == 0 for value in user_match.groups()):
            raise ValueError("sandbox user must be a numeric non-root uid:gid")
        positive = (
            self.cpu_quota,
            self.cpu_period,
            self.pids_limit,
            self.nofile_limit,
            self.nproc_limit,
            self.fsize_limit_kib,
            self.output_limit_bytes,
        )
        if any(value <= 0 for value in positive):
            raise ValueError("sandbox limits must be positive")


class VMExecutor:
    """Execute an explicit runtime comparator under a hardened container policy."""

    DOCKER_IMAGE = "fastapi-endpoint-detector:vm"
    PACKAGED_SECCOMP_SHA256 = (
        "sha256:96dbac26aac6041de88eaf99f653d606933469dd104157b877190d998ab68d4a"
    )
    _IMAGE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]*(?:@sha256:[0-9a-f]{64})?")
    _CONTAINER_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
    _CID_PATTERN = re.compile(r"[0-9a-f]{12,64}")
    _MOUNT_SCAN_LIMIT = 100_000
    CLEAN_ENV: ClassVar[dict[str, str]] = {
        "HOME": "/tmp/home",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "TMPDIR": "/tmp",
    }

    def __init__(
        self,
        memory_limit: str = "512m",
        cpu_quota: int = 50_000,
        timeout: int = 60,
        network_disabled: bool = True,
        *,
        image: str | None = None,
        runtime: str = "runsc",
        seccomp_profile: Path | None = None,
        output_limit_bytes: int = 4 * 1024 * 1024,
        dependency_lock_hash: str | None = None,
        snapshot_lock_hash: str | None = None,
        sbom_hash: str | None = None,
        seccomp_hash: str | None = None,
    ) -> None:
        if not network_disabled:
            raise ValueError("runtime comparator network access cannot be enabled")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.timeout = timeout
        self.network_disabled = True
        self.image = (
            image or os.environ.get("FASTAPI_ENDPOINT_DETECTOR_VM_IMAGE") or self.DOCKER_IMAGE
        )
        self._validate_image_reference(self.image)
        packaged_seccomp = (
            Path(__file__).resolve().parent / "policies" / "runtime-seccomp-v1.json"
        ).resolve()
        self.seccomp_profile = self._validated_mount_source(
            seccomp_profile or packaged_seccomp,
            "seccomp profile",
            allow_directory=False,
        )
        self.seccomp_hash = seccomp_hash or os.environ.get(
            "FASTAPI_ENDPOINT_DETECTOR_VM_SECCOMP_SHA256"
        )
        if self.seccomp_hash is None and self.seccomp_profile == packaged_seccomp:
            self.seccomp_hash = self.PACKAGED_SECCOMP_SHA256
        self.policy = SandboxPolicy(
            runtime=runtime,
            memory_limit=memory_limit,
            memory_swap=memory_limit,
            cpu_quota=cpu_quota,
            output_limit_bytes=output_limit_bytes,
        )
        self.memory_limit = memory_limit
        self.cpu_quota = cpu_quota
        self.dependency_lock_hash = dependency_lock_hash or os.environ.get(
            "FASTAPI_ENDPOINT_DETECTOR_VM_LOCK_SHA256"
        )
        self.snapshot_lock_hash = snapshot_lock_hash or os.environ.get(
            "FASTAPI_ENDPOINT_DETECTOR_VM_SNAPSHOT_SHA256"
        )
        self.sbom_hash = sbom_hash or os.environ.get("FASTAPI_ENDPOINT_DETECTOR_VM_SBOM_SHA256")
        self._resolved_image: str | None = None

    @classmethod
    def _validate_image_reference(cls, value: str, *, immutable: bool = False) -> str:
        if (
            len(value) > 512
            or cls._IMAGE_PATTERN.fullmatch(value) is None
            or value.startswith("-")
            or ".." in value
        ):
            raise VMExecutorError("runtime image has an invalid Docker reference")
        if immutable and "@sha256:" not in value:
            raise VMExecutorError("runtime image must use an immutable sha256 digest")
        return value

    @staticmethod
    def _validated_hash(value: str | None, label: str) -> str:
        if value is None or not value.startswith("sha256:"):
            raise VMExecutorError(f"{label} sha256 attestation is required")
        digest = value.removeprefix("sha256:")
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise VMExecutorError(f"{label} has an invalid sha256 attestation")
        return value

    def build_image(self, dockerfile_path: Path | None = None) -> None:
        """Build a local candidate image; execution still resolves a repository digest."""
        dockerfile = dockerfile_path or (Path(__file__).resolve().parents[3] / "Dockerfile")
        if not dockerfile.is_file():
            raise VMExecutorError(f"Dockerfile not found at {dockerfile}")
        command = [
            "docker",
            "build",
            "--pull=false",
            "-t",
            self.image,
            "-f",
            str(dockerfile),
            str(dockerfile.parent),
        ]
        try:
            subprocess.run(command, check=True, capture_output=True, text=True, timeout=300)
        except subprocess.CalledProcessError as exc:
            raise VMExecutorError(f"Failed to build Docker image: {exc.stderr}") from exc
        except subprocess.TimeoutExpired as exc:
            raise VMExecutorError("Docker image build timed out") from exc
        self._resolved_image = None

    def _resolve_image(self) -> str:
        if self._resolved_image is not None:
            return self._resolved_image
        try:
            result = subprocess.run(
                ["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", self.image],
                capture_output=True,
                check=False,
                text=True,
                timeout=10,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            raise VMExecutorError("Docker or the configured image is unavailable") from exc
        if result.returncode != 0:
            raise VMExecutorError(f"Docker image {self.image!r} is unavailable")
        if "@sha256:" in self.image:
            resolved = self.image
        else:
            try:
                digests = json.loads(result.stdout)
            except (json.JSONDecodeError, TypeError) as exc:
                raise VMExecutorError("image inspect did not return repository digests") from exc
            candidates = sorted(
                item for item in digests or [] if isinstance(item, str) and "@sha256:" in item
            )
            if len(candidates) != 1:
                raise VMExecutorError("runtime image must resolve to exactly one repository digest")
            resolved = candidates[0]
        self._validate_image_reference(resolved, immutable=True)
        digest = resolved.rsplit("@sha256:", maxsplit=1)[-1]
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise VMExecutorError("runtime image has an invalid sha256 digest")
        self._resolved_image = resolved
        return resolved

    def check_image_exists(self) -> bool:
        """Return whether the configured image resolves to one immutable digest."""
        try:
            self._resolve_image()
        except VMExecutorError:
            return False
        return True

    def _verified_seccomp_hash(self) -> str:
        expected = self._validated_hash(self.seccomp_hash, "seccomp profile")
        try:
            mode = self.seccomp_profile.stat(follow_symlinks=False).st_mode
            if not stat.S_ISREG(mode):
                raise VMExecutorError("seccomp profile must be a regular file")
            content = self.seccomp_profile.read_bytes()
        except OSError as exc:
            raise VMExecutorError(
                f"seccomp profile is unavailable: {self.seccomp_profile}"
            ) from exc
        actual = f"sha256:{hashlib.sha256(content).hexdigest()}"
        if actual != expected:
            raise VMExecutorError("seccomp profile does not match its immutable attestation")
        try:
            payload = json.loads(content)
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise VMExecutorError("seccomp profile is not valid JSON") from exc
        if not isinstance(payload, dict) or payload.get("defaultAction") != "SCMP_ACT_ERRNO":
            raise VMExecutorError("seccomp profile must be deny-by-default")
        return actual

    def policy_provenance(self) -> dict[str, Any]:
        """Return deterministic policy/image provenance suitable for benchmark manifests."""
        seccomp_hash = self._verified_seccomp_hash()
        payload = {
            "policy": asdict(self.policy),
            "image": self._resolve_image(),
            "seccomp_sha256": seccomp_hash,
            "environment": dict(sorted(self.CLEAN_ENV.items())),
            "dependency_lock_hash": self._validated_hash(
                self.dependency_lock_hash,
                "dependency lock",
            ),
            "snapshot_lock_hash": self._validated_hash(
                self.snapshot_lock_hash,
                "snapshot lock",
            ),
            "sbom_hash": self._validated_hash(self.sbom_hash, "SBOM"),
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return {**payload, "policy_sha256": f"sha256:{hashlib.sha256(canonical).hexdigest()}"}

    @classmethod
    def _validate_directory_entries(cls, root: Path, label: str) -> None:
        inspected = 0
        try:
            for directory, names, files in os.walk(root, followlinks=False):
                parent = Path(directory)
                for name in (*names, *files):
                    inspected += 1
                    if inspected > cls._MOUNT_SCAN_LIMIT:
                        raise VMExecutorError(f"{label} exceeds the bounded mount scan limit")
                    mode = (parent / name).lstat().st_mode
                    if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode)):
                        raise VMExecutorError(
                            f"{label} contains a socket, device, fifo, or other special file"
                        )
        except OSError as exc:
            raise VMExecutorError(f"cannot inspect {label} directory {root}: {exc}") from exc

    @classmethod
    def _validated_mount_source(
        cls,
        path: Path,
        label: str,
        *,
        allow_directory: bool,
    ) -> Path:
        # Resolving here would follow the symlink components rejected below.
        absolute = Path(os.path.abspath(path.expanduser()))  # noqa: PTH100
        current = Path(absolute.anchor)
        try:
            for component in absolute.parts[1:]:
                current /= component
                if stat.S_ISLNK(os.lstat(current).st_mode):
                    raise VMExecutorError(f"{label} path cannot contain symlinks")
            resolved = absolute.resolve(strict=True)
            mode = resolved.stat(follow_symlinks=False).st_mode
        except FileNotFoundError as exc:
            raise VMExecutorError(f"{label} path does not exist: {path}") from exc
        except OSError as exc:
            raise VMExecutorError(f"cannot inspect {label} path {path}: {exc}") from exc
        if stat.S_ISDIR(mode):
            broad_roots = {
                Path(resolved.anchor),
                Path.home().resolve(),
                Path(tempfile.gettempdir()).resolve(),
                Path("/dev"),
                Path("/etc"),
                Path("/home"),
                Path("/proc"),
                Path("/run"),
                Path("/sys"),
                Path("/usr"),
                Path("/var"),
            }
            if not allow_directory:
                raise VMExecutorError(f"{label} must be a regular file")
            if resolved in broad_roots:
                raise VMExecutorError(f"refusing broad {label} directory mount: {resolved}")
            cls._validate_directory_entries(resolved, label)
        elif not stat.S_ISREG(mode):
            raise VMExecutorError(f"{label} must be a regular file or directory")
        return resolved

    def _mount(self, source: Path, target: str) -> str:
        return f"type=bind,src={source},dst={target},readonly,bind-nonrecursive"

    def _container_command(
        self,
        app_path: Path,
        diff_path: Path | None,
        app_variable: str,
        output_format: str,
        cidfile: Path,
        name: str,
    ) -> list[str]:
        self._verified_seccomp_hash()
        self._validated_hash(self.dependency_lock_hash, "dependency lock")
        self._validated_hash(self.snapshot_lock_hash, "snapshot lock")
        self._validated_hash(self.sbom_hash, "SBOM")
        app = self._validated_mount_source(app_path, "application", allow_directory=True)
        app_target = "/workspace/app" if app.is_dir() else f"/workspace/{app.name}"
        command = [
            "docker",
            "run",
            "--pull",
            "never",
            "--name",
            name,
            "--cidfile",
            str(cidfile),
            "--runtime",
            self.policy.runtime,
            "--network",
            "none",
            "--ipc",
            "none",
            "--pid",
            "private",
            "--log-driver",
            "none",
            "--read-only",
            "--user",
            self.policy.user,
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges=true",
            "--security-opt",
            f"seccomp={self.seccomp_profile}",
            "--memory",
            self.policy.memory_limit,
            "--memory-swap",
            self.policy.memory_swap,
            "--cpu-period",
            str(self.policy.cpu_period),
            "--cpu-quota",
            str(self.policy.cpu_quota),
            "--pids-limit",
            str(self.policy.pids_limit),
            "--ulimit",
            f"nofile={self.policy.nofile_limit}:{self.policy.nofile_limit}",
            "--ulimit",
            f"nproc={self.policy.nproc_limit}:{self.policy.nproc_limit}",
            "--ulimit",
            f"fsize={self.policy.fsize_limit_kib}:{self.policy.fsize_limit_kib}",
            "--ulimit",
            "core=0:0",
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,nodev,size={self.policy.tmpfs_size},mode=1777",
            "--mount",
            self._mount(app, app_target),
            "--entrypoint",
            "/usr/bin/env",
        ]
        cli = ["list", "--app", app_target, "--format", output_format, "--app-var", app_variable]
        if diff_path is not None:
            diff = self._validated_mount_source(diff_path, "diff", allow_directory=False)
            command.extend(["--mount", self._mount(diff, "/workspace/change.diff")])
            cli = [
                "analyze",
                "--app",
                app_target,
                "--diff",
                "/workspace/change.diff",
                "--format",
                output_format,
                "--app-var",
                app_variable,
            ]
        command.append(self._resolve_image())
        command.append("-i")
        command.extend(f"{key}={value}" for key, value in sorted(self.CLEAN_ENV.items()))
        command.append("fastapi-endpoint-detector")
        command.extend(cli)
        return command

    @classmethod
    def _cleanup_container(cls, cidfile: Path, name: str) -> None:
        if cls._CONTAINER_NAME_PATTERN.fullmatch(name) is None or name.startswith("-"):
            raise VMExecutorError("sandbox container name is invalid")
        target = name
        failures: list[str] = []
        try:
            if cidfile.is_file():
                candidate = cidfile.read_text(encoding="utf-8").strip()
                if candidate:
                    if cls._CID_PATTERN.fullmatch(candidate) is None:
                        failures.append("CID file contained an invalid container identifier")
                    else:
                        target = candidate
        except (OSError, UnicodeError) as exc:
            failures.append(f"cannot read CID file: {exc}")
        for command in (
            ["docker", "kill", target],
            ["docker", "rm", "--force", target],
        ):
            try:
                subprocess.run(
                    command,
                    capture_output=True,
                    check=False,
                    timeout=10,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                failures.append(f"{' '.join(command[:2])}: {exc}")
        try:
            remaining = subprocess.run(
                ["docker", "container", "inspect", target],
                capture_output=True,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            failures.append(f"cleanup verification: {exc}")
        else:
            if remaining.returncode == 0:
                failures.append("container still exists after forced removal")
        if failures:
            raise VMExecutorError("sandbox cleanup failed: " + "; ".join(failures))

    def _execute_bounded(  # noqa: PLR0912, PLR0915
        self,
        command: list[str],
        cidfile: Path,
        name: str,
    ) -> tuple[str, str]:
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except (FileNotFoundError, OSError) as exc:
            raise VMExecutorError(f"failed to launch Docker: {exc}") from exc
        streams = selectors.DefaultSelector()
        assert process.stdout is not None and process.stderr is not None
        streams.register(process.stdout, selectors.EVENT_READ, "stdout")
        streams.register(process.stderr, selectors.EVENT_READ, "stderr")
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        deadline = time.monotonic() + self.timeout
        failure: str | None = None
        try:
            while streams.get_map():
                if time.monotonic() >= deadline:
                    failure = f"Container execution timed out after {self.timeout} seconds"
                    break
                events = streams.select(timeout=0.1)
                for key, _mask in events:
                    chunk = os.read(key.fd, 65_536)
                    if not chunk:
                        streams.unregister(key.fileobj)
                        continue
                    buffers[key.data].extend(chunk)
                    output_size = sum(len(value) for value in buffers.values())
                    if output_size > self.policy.output_limit_bytes:
                        failure = "Container output exceeded the configured byte limit"
                        break
                if failure is not None:
                    break
                if process.poll() is not None and not events:
                    for key in list(streams.get_map().values()):
                        chunk = os.read(key.fd, 65_536)
                        if chunk:
                            buffers[key.data].extend(chunk)
                            output_size = sum(len(value) for value in buffers.values())
                            if output_size > self.policy.output_limit_bytes:
                                failure = "Container output exceeded the configured byte limit"
                                break
                        else:
                            streams.unregister(key.fileobj)
            if failure is not None:
                process.kill()
            return_code = process.wait(timeout=5)
        finally:
            streams.close()
            self._cleanup_container(cidfile, name)
        try:
            stdout = buffers["stdout"].decode("utf-8", errors="strict")
            stderr = buffers["stderr"].decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise VMExecutorError("Container output is not valid UTF-8") from exc
        if failure is not None:
            raise VMExecutorError(failure)
        if return_code != 0:
            raise VMExecutorError(f"Container execution failed: {stderr.strip()}")
        return stdout, stderr

    def analyze_in_vm(
        self,
        app_path: Path,
        diff_path: Path | None = None,
        app_variable: str = "app",
        output_format: str = "json",
    ) -> Any:
        """Run list/analyze with no host import and return bounded output."""
        with tempfile.TemporaryDirectory(prefix="endpoint-detector-cid-") as directory:
            cidfile = Path(directory) / "container.cid"
            name = f"endpoint-detector-{uuid.uuid4().hex}"
            command = self._container_command(
                app_path,
                diff_path,
                app_variable,
                output_format,
                cidfile,
                name,
            )
            stdout, _stderr = self._execute_bounded(command, cidfile, name)
        if output_format != "json":
            return stdout
        try:
            return json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise VMExecutorError("Failed to parse bounded JSON output") from exc

    def list_endpoints_in_vm(
        self,
        app_path: Path,
        app_variable: str = "app",
    ) -> list[Endpoint]:
        """Deserialize runtime-list output into endpoint models when available."""
        result = self.analyze_in_vm(app_path, app_variable=app_variable, output_format="json")
        if not isinstance(result, dict) or not isinstance(result.get("endpoints"), list):
            raise VMExecutorError("runtime list output does not contain an endpoints array")
        try:
            return [Endpoint.model_validate(item) for item in result["endpoints"]]
        except (TypeError, ValueError) as exc:
            raise VMExecutorError("runtime list output contains invalid endpoint data") from exc
