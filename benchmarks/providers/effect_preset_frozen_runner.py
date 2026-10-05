"""Run the v4 matrix replay with its committed first-party source snapshot."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

RUNTIME_DIR = Path(__file__).resolve().parents[1] / "results" / "effect-preset-matrix-v5"
FROZEN_PROJECT = RUNTIME_DIR / "frozen-project"
REPLAY_ENVIRONMENTS = RUNTIME_DIR / "replay-envs"
RUNTIME_MANIFEST = RUNTIME_DIR / "frozen-runtime.json"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RUNTIME_DISTRIBUTIONS = {
    "librt": "0.16.0",
    "mypy-extensions": "1.1.0",
    "pathspec": "1.1.1",
    "pydantic": "2.13.5",
    "pydantic-core": "2.46.5",
    "PyYAML": "6.0.3",
    "typing-extensions": "4.16.0",
}
_SUPPORTED_ENVS = {
    ("3.10.21", "1.19.1"),
    ("3.11.16", "1.19.1"),
    ("3.12.14", "1.19.1"),
    ("3.11.16", "2.4.0"),
}


def _verify_runtime_distributions(version_lookup: Callable[[str], str] | None = None) -> None:
    """Reject runtimes whose installed replay dependencies differ from the recorded set."""
    lookup = version_lookup or importlib.metadata.version
    for distribution, expected_version in _RUNTIME_DISTRIBUTIONS.items():
        try:
            actual_version = lookup(distribution)
        except importlib.metadata.PackageNotFoundError as exc:
            raise FrozenReplayError(
                f"runtime dependency metadata is unavailable: {distribution}"
            ) from exc
        if actual_version != expected_version:
            raise FrozenReplayError(f"runtime dependency identity mismatch: {distribution}")


class FrozenReplayError(ValueError):
    """Raised when the committed historical replay source is incomplete or altered."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FrozenReplayError(f"duplicate key in frozen runtime manifest: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise FrozenReplayError(f"non-finite frozen runtime manifest value: {value}")


def _verify_snapshot(artifact_root: Path) -> dict[str, Any]:  # noqa: PLR0912, PLR0915
    try:
        raw = RUNTIME_MANIFEST.read_bytes()
        manifest = json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=_reject_constant)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FrozenReplayError("cannot read frozen runtime manifest") from exc
    if (
        not isinstance(manifest, dict)
        or set(manifest)
        != {
            "schema_version",
            "runtime_id",
            "source_commit",
            "v4_snapshot_sha256",
            "v4_artifact_files",
            "replay_environment_files",
            "replay_lock_tool",
            "runner_sha256",
            "runtime_distributions",
            "files",
        }
        or type(manifest["schema_version"]) is not int
        or manifest["schema_version"] != 1
        or manifest["runtime_id"] != "gh97-effect-analyzer-frozen-runtime-v1"
        or manifest["source_commit"] != "88ec7c33b45ec45435aaf7ffb72494c02f2328e4"
        or not isinstance(manifest["v4_snapshot_sha256"], str)
        or _SHA256.fullmatch(manifest["v4_snapshot_sha256"]) is None
        or not isinstance(manifest["runner_sha256"], str)
        or _SHA256.fullmatch(manifest["runner_sha256"]) is None
        or not isinstance(manifest["files"], list)
        or not isinstance(manifest["v4_artifact_files"], list)
        or not isinstance(manifest["replay_environment_files"], list)
        or manifest["replay_lock_tool"] != {"name": "uv", "version": "0.12.19"}
        or manifest["runtime_distributions"] != _RUNTIME_DISTRIBUTIONS
    ):
        raise FrozenReplayError("frozen runtime manifest has invalid schema or identity")
    if _sha256(Path(__file__)) != manifest["runner_sha256"]:
        raise FrozenReplayError("frozen replay runner hash differs from runtime manifest")

    rows = manifest["files"]
    paths: list[str] = []
    for row in rows:
        if (
            not isinstance(row, dict)
            or set(row) != {"path", "sha256"}
            or not isinstance(row["path"], str)
            or not row["path"]
            or "\\" in row["path"]
            or PurePosixPath(row["path"]).is_absolute()
            or ".." in PurePosixPath(row["path"]).parts
            or PurePosixPath(row["path"]).as_posix() != row["path"]
            or not isinstance(row["sha256"], str)
            or _SHA256.fullmatch(row["sha256"]) is None
        ):
            raise FrozenReplayError("frozen runtime source row is malformed")
        paths.append(row["path"])
    if not paths or paths != sorted(paths) or len(paths) != len(set(paths)):
        raise FrozenReplayError("frozen runtime source path set is not unique and sorted")

    expected = set(paths)
    actual = {
        path.relative_to(FROZEN_PROJECT).as_posix()
        for path in FROZEN_PROJECT.rglob("*")
        if path.is_file()
    }
    if actual != expected:
        raise FrozenReplayError("frozen runtime source tree has missing or extra files")
    source_hashes: dict[str, str] = {}
    for row in rows:
        source = FROZEN_PROJECT / row["path"]
        if source.is_symlink() or _sha256(source) != row["sha256"]:
            raise FrozenReplayError(f"frozen runtime source hash mismatch: {row['path']}")
        source_hashes[row["path"]] = row["sha256"]

    artifact_rows = manifest["v4_artifact_files"]
    artifact_paths: list[str] = []
    for row in artifact_rows:
        if (
            not isinstance(row, dict)
            or set(row) != {"path", "sha256"}
            or not isinstance(row["path"], str)
            or not row["path"]
            or "\\" in row["path"]
            or PurePosixPath(row["path"]).is_absolute()
            or ".." in PurePosixPath(row["path"]).parts
            or PurePosixPath(row["path"]).as_posix() != row["path"]
            or not isinstance(row["sha256"], str)
            or _SHA256.fullmatch(row["sha256"]) is None
        ):
            raise FrozenReplayError("historical v4 artifact row is malformed")
        artifact_paths.append(row["path"])
    if (
        not artifact_paths
        or artifact_paths != sorted(artifact_paths)
        or len(artifact_paths) != len(set(artifact_paths))
    ):
        raise FrozenReplayError("historical v4 artifact set is not unique and sorted")
    for row in artifact_rows:
        snapshot_path = f"benchmarks/results/effect-preset-matrix-v4/{row['path']}"
        if source_hashes.get(snapshot_path) != row["sha256"]:
            raise FrozenReplayError(f"frozen source bundle changed v4 artifact: {row['path']}")
    actual_artifacts = {
        path.relative_to(artifact_root).as_posix()
        for path in artifact_root.rglob("*")
        if path.is_file()
    }
    if actual_artifacts != set(artifact_paths):
        raise FrozenReplayError("historical v4 artifact tree has missing or extra files")
    for row in artifact_rows:
        path = artifact_root / row["path"]
        if path.is_symlink() or _sha256(path) != row["sha256"]:
            raise FrozenReplayError(f"historical v4 artifact changed: {row['path']}")

    environment_rows = manifest["replay_environment_files"]
    environment_paths: list[str] = []
    for row in environment_rows:
        if (
            not isinstance(row, dict)
            or set(row) != {"path", "sha256"}
            or not isinstance(row["path"], str)
            or not row["path"].startswith("replay-envs/")
            or "\\" in row["path"]
            or PurePosixPath(row["path"]).is_absolute()
            or ".." in PurePosixPath(row["path"]).parts
            or PurePosixPath(row["path"]).as_posix() != row["path"]
            or not isinstance(row["sha256"], str)
            or _SHA256.fullmatch(row["sha256"]) is None
        ):
            raise FrozenReplayError("replay environment file row is malformed")
        environment_paths.append(row["path"])
    if (
        not environment_paths
        or environment_paths != sorted(environment_paths)
        or len(environment_paths) != len(set(environment_paths))
    ):
        raise FrozenReplayError("replay environment file set is not unique and sorted")
    expected_environment_paths = set(environment_paths)
    actual_environment_paths = {
        path.relative_to(RUNTIME_DIR).as_posix()
        for path in REPLAY_ENVIRONMENTS.rglob("*")
        if path.is_file() and ".venv" not in path.relative_to(REPLAY_ENVIRONMENTS).parts
    }
    if actual_environment_paths != expected_environment_paths:
        raise FrozenReplayError("replay environment file tree has missing or extra files")
    for row in environment_rows:
        environment_file = RUNTIME_DIR / row["path"]
        if environment_file.is_symlink() or _sha256(environment_file) != row["sha256"]:
            raise FrozenReplayError(f"replay environment file hash mismatch: {row['path']}")
    return manifest


def _load_frozen_provider(artifact_root: Path) -> Any:
    _verify_snapshot(artifact_root)
    source_root = FROZEN_PROJECT / "src"
    project_root = FROZEN_PROJECT
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(project_root))
    sys.path.insert(0, str(source_root))
    # Import only after binding sys.path to the frozen source tree.
    from benchmarks.providers import effect_preset_matrix as frozen_provider  # noqa: PLC0415

    frozen_provider.MATRIX_ROOT = artifact_root
    frozen_provider.MANIFEST_PATH = artifact_root / "package-symbols.json"
    frozen_provider.RESULTS_PATH = (
        artifact_root / "runs" / "python-placeholder" / "controlled-results.json"
    )
    frozen_provider.FIXTURE_PATH = artifact_root / "fixtures" / "pathlib_open_handles.py"
    frozen_provider.ANALYZER_SNAPSHOT_PATH = artifact_root / "analyzer-source-snapshots.json"
    frozen_provider.PACKAGE_CASES_PATH = artifact_root / "package-analyzer-cases.json"
    frozen_provider.PACKAGE_CASE_RESULTS_PATH = (
        artifact_root / "runs" / "python-placeholder" / "package-analyzer-results.json"
    )
    frozen_provider.SIGNATURE_REPORT_PATH = artifact_root / "source-signature-observations.json"
    frozen_provider.PROJECT_ROOT = project_root
    return frozen_provider


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices={"fixture", "package-cases", "presets"})
    parser.add_argument("artifact_root", type=Path)
    parser.add_argument("python_version")
    parser.add_argument("mypy_version")
    args = parser.parse_args()

    try:
        manifest = _verify_snapshot(args.artifact_root.resolve())
        del manifest
        actual_python = platform.python_version()
        try:
            actual_mypy = importlib.metadata.version("mypy")
        except importlib.metadata.PackageNotFoundError as exc:
            raise FrozenReplayError("mypy resolver metadata is unavailable") from exc
        if (actual_python, actual_mypy) not in _SUPPORTED_ENVS or (actual_python, actual_mypy) != (
            args.python_version,
            args.mypy_version,
        ):
            raise FrozenReplayError("child process exact Python/mypy identity mismatch")
        _verify_runtime_distributions()
        with tempfile.TemporaryDirectory(prefix="gh97_frozen_replay_") as work_dir:
            os.chdir(work_dir)
            provider = _load_frozen_provider(args.artifact_root.resolve())
            if args.operation == "fixture":
                result = provider._replay_fixture()
            elif args.operation == "package-cases":
                result = provider.replay_package_analyzer_cases()
            else:
                result = provider.verify_preset_contracts()
        sys.stdout.write(json.dumps(result, separators=(",", ":"), sort_keys=True))
        sys.stdout.write("\n")
    except Exception as exc:
        message = str(exc).replace("\n", " ")[:1000]
        sys.stderr.write(f"frozen analyzer replay failed: {type(exc).__name__}: {message}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
