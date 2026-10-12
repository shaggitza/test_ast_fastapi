"""Explicit, owned-source sandbox canary; default mode only renders its command."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import tempfile
from pathlib import Path
from typing import Any

from fastapi_endpoint_detector.executor.vm_executor import VMExecutor

IMAGE = (
    "test-ast-runtime-phase-15508bc@sha256:"
    "8c2d95773208aab2a4391316ba4bd6446ac6d896ba581420545053822d9f24e4"
)
DEPENDENCY_LOCK = Path("/tmp/test-ast-runtime-image-build-20261010/requirements.lock")
SBOM = Path("/tmp/test-ast-runtime-phase-15508bc-validation-20261010/machine-sbom.json")
CANARY_SOURCE = r"""import json, os, socket, sys, time
mode, marker = sys.argv[1], sys.argv[2]
if mode == "timeout":
    while True:
        time.sleep(1)
result = {"marker_hidden": not os.path.exists(marker)}
try:
    with open("/workspace/app/canary.py", "a", encoding="utf-8") as stream:
        stream.write("mutation")
except OSError:
    result["readonly"] = True
else:
    result["readonly"] = False
try:
    with socket.create_connection(("192.0.2.1", 443), timeout=0.5):
        result["network_unavailable"] = False
except OSError:
    result["network_unavailable"] = True
print(json.dumps(result, sort_keys=True))
"""


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _fixture_lock(source: bytes) -> str:
    # A fresh, deterministic lock for this one-file generated fixture.
    return _sha256(b"controlled-synthetic-v1\0canary.py\0" + _sha256(source).encode())


def _executor(source: bytes, timeout: int) -> VMExecutor:
    dependency_hash = _sha256(DEPENDENCY_LOCK.read_bytes())
    sbom_hash = _sha256(SBOM.read_bytes())
    return VMExecutor(
        image=IMAGE,
        runtime="runsc",
        timeout=timeout,
        dependency_lock_hash=dependency_hash,
        snapshot_lock_hash=_fixture_lock(source),
        sbom_hash=sbom_hash,
    )


def _prepare_directory(parent: Path, source: bytes) -> tuple[Path, Path]:
    root = Path(tempfile.mkdtemp(prefix="gh101-owned-canary-", dir=parent))
    app = root / "fixture"
    app.mkdir(mode=0o755)
    script = app / "canary.py"
    script.write_bytes(source)
    script.chmod(0o444)
    app.chmod(0o555)
    root.chmod(0o755)
    # An inert marker is outside the sole bind mount and contains no secret.
    marker = root / "private-marker.txt"
    marker.write_text("gh101 synthetic visibility marker\n", encoding="utf-8")
    marker.chmod(0o600)
    entries = sorted(p.name for p in app.iterdir())
    if entries != ["canary.py"] or _sha256(script.read_bytes()) != _sha256(source):
        raise RuntimeError("owned fixture static preflight failed")
    return root, marker


def _command(
    executor: VMExecutor, app: Path, cidfile: Path, name: str, mode: str, marker: Path
) -> list[str]:
    executor._resolved_image = IMAGE
    command = executor._container_command(app, None, "app", "text", cidfile, name)
    # Keep VMExecutor's complete policy flags, image, and clean env; only use
    # this generated stdlib fixture as argv, never the project worker/client.
    cli_start = command.index("-i") + 1 + len(VMExecutor.CLEAN_ENV)
    command[cli_start:] = [
        "python",
        "/workspace/app/canary.py",
        mode,
        str(marker),
    ]
    return command


def _run_case(parent: Path, mode: str, timeout: int, *, inspect_only: bool) -> dict[str, Any]:
    source = CANARY_SOURCE.encode("utf-8")
    root, marker = _prepare_directory(parent, source)
    try:
        executor = _executor(source, timeout)
        cidfile = root / "container.cid"
        name = "gh101-canary-" + os.urandom(12).hex()
        command = _command(executor, root / "fixture", cidfile, name, mode, marker)
        pins = {
            "source_sha256": _sha256(source),
            "fixture_lock_sha256": _fixture_lock(source),
            "dependency_lock_sha256": executor.dependency_lock_hash,
            "sbom_sha256": executor.sbom_hash,
            "seccomp_sha256": executor._verified_seccomp_hash(),
            "policy_sha256": executor.policy_provenance()["policy_sha256"],
            "image": IMAGE,
            "command_sha256": _sha256("\0".join(command).encode()),
            "argv": command,
        }
        if inspect_only:
            return {
                "mode": "inspection-only",
                "rendered_command": shlex.join(command),
                "pins": pins,
            }
        if mode == "timeout":
            try:
                executor._execute_bounded(command, cidfile, name)
            except Exception as exc:
                if "timed out" not in str(exc).lower():
                    raise
                return {
                    "mode": "controlled_synthetic",
                    "timeout_observed": True,
                    "cleanup_verified": True,
                    "pins": pins,
                }
            raise RuntimeError("timeout fixture unexpectedly completed")
        stdout, _ = executor._execute_bounded(command, cidfile, name)
        observation = json.loads(stdout)
        if observation != {"marker_hidden": True, "network_unavailable": True, "readonly": True}:
            raise RuntimeError(
                "canary preflight failed: " + json.dumps(observation, sort_keys=True)
            )
        return {"mode": "controlled_synthetic", "canary_observation": observation, "pins": pins}
    finally:
        # The private temp root and its own files are the only paths removed.
        for child in root.iterdir():
            if child.is_dir() and not child.is_symlink():
                child.chmod(0o755)
                for owned in child.iterdir():
                    if owned.is_file():
                        owned.chmod(0o644)
        shutil.rmtree(root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--execute", action="store_true", help="explicitly run the owned canary and timeout assay"
    )
    parser.add_argument("--temp-parent", type=Path, default=Path(tempfile.gettempdir()))
    args = parser.parse_args()
    parent = args.temp_parent.resolve(strict=True)
    if not parent.is_dir() or not os.access(parent, os.W_OK | os.X_OK):
        parser.error("temp parent must be a writable directory")
    try:
        canary = _run_case(parent, "canary", 10, inspect_only=not args.execute)
        if not args.execute:
            print(json.dumps(canary, sort_keys=True, indent=2))
            return 0
        timeout = _run_case(parent, "timeout", 2, inspect_only=False)
    except Exception as exc:
        print(json.dumps({"mode": "controlled_synthetic", "status": "failed", "error": str(exc)}))
        return 1
    print(
        json.dumps(
            {
                "mode": "controlled_synthetic",
                "status": "observed",
                "canary": canary,
                "timeout": timeout,
            },
            sort_keys=True,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
