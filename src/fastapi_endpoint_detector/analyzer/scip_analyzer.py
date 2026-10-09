"""SCIP-backed Python symbol and reverse-impact queries."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from collections.abc import Sequence


class _SourceInventory(Protocol):
    """Structural subset of the shared inventory consumed by SCIP."""

    @property
    def paths(self) -> Sequence[Path]: ...


class SCIPAnalyzerError(RuntimeError):
    """Raised when the explicit SCIP backend cannot produce reliable evidence."""


@dataclass(frozen=True)
class SCIPDefinition:
    """A definition returned by ``scip-query outline``."""

    symbol: str
    short_name: str
    file_path: Path
    start_line: int  # one-based, inclusive
    end_line: int  # one-based, inclusive


@dataclass(frozen=True)
class SCIPReachedDefinition:
    """A reverse-reachable definition and its distance from the change."""

    definition: SCIPDefinition
    depth: int


@dataclass(frozen=True)
class SCIPOccurrence:
    """A source occurrence returned by ``scip-query refs``."""

    file_path: Path
    line: int  # one-based


@dataclass(frozen=True)
class SCIPReverseCallEdge:
    """A source-bound reference; SCIP and AST syntax do not establish execution."""

    caller: SCIPDefinition
    callee: SCIPDefinition
    occurrence: SCIPOccurrence
    execution_status: str = "reference_only"
    confidence: str = "LOW"
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class SCIPSourceScope:
    """Selected evidence scope and the broader scope used to build SCIP's index."""

    index_scope: str
    selected_inventory_paths: tuple[str, ...] | None
    limitations: tuple[str, ...]


class SCIPAnalyzer:
    """Run a pinned Sourcegraph Python SCIP index through ``scip-query``."""

    QUERY_VERSION = "0.16.0"
    PYTHON_INDEXER_VERSION = "0.6.6"
    MAX_DEPTH = 1000
    MAX_SOURCE_FILES = 50_000
    MAX_SOURCE_FILE_BYTES = 32 * 1024 * 1024
    MAX_SOURCE_SNAPSHOT_BYTES = 1024 * 1024 * 1024
    MAX_SOURCE_READ_BYTES = MAX_SOURCE_FILE_BYTES + 1

    def __init__(
        self,
        project_root: Path,
        *,
        use_cache: bool = True,
        timeout: float = 300.0,
        source_inventory: _SourceInventory | None = None,
    ):
        self.project_root = project_root.resolve()
        try:
            root_metadata = self.project_root.stat()
        except OSError as error:
            raise SCIPAnalyzerError(f"Invalid SCIP project root: {project_root}") from error
        if not stat.S_ISDIR(root_metadata.st_mode):
            raise SCIPAnalyzerError(f"SCIP project root is not a directory: {project_root}")
        self._project_root_identity = self._directory_identity(root_metadata)
        self.use_cache = use_cache
        self.timeout = timeout
        self.source_inventory = source_inventory
        try:
            inventory_values = (
                [self._inventory_relative_path(path).as_posix() for path in source_inventory.paths]
                if source_inventory is not None
                else None
            )
            if inventory_values is not None and len(set(inventory_values)) != len(inventory_values):
                raise SCIPAnalyzerError("SCIP source inventory contains duplicate canonical paths")
            self._inventory_paths = set(inventory_values) if inventory_values is not None else None
        except (OSError, ValueError) as error:
            raise SCIPAnalyzerError(
                "SCIP source inventory contains a missing or escaping path"
            ) from error

        self._outline_cache: dict[Path, tuple[SCIPDefinition, ...]] = {}
        self._base_method_cache: dict[str, tuple[SCIPDefinition, ...]] = {}
        self._reverse_call_edge_cache: dict[
            tuple[str, str, Path], tuple[SCIPReverseCallEdge, ...]
        ] = {}
        self._reverse_call_edge_limitations: dict[tuple[str, str, Path], tuple[str, ...]] = {}
        self._ast_cache: dict[Path, ast.Module | None] = {}
        self._module_paths: dict[str, Path] | None = None
        self._inventory_digest: str | None = None
        self._cache_home: Path | None = None
        self._active_index: Path | None = None
        self._toolchain_versions: dict[str, str] = {}
        self._runtime_environment: dict[str, Any] = {}

    def _executable(self, name: str) -> str:
        executable = shutil.which(name)
        if executable is None:
            raise SCIPAnalyzerError(
                f"Missing {name!r}. Install scip-query@{self.QUERY_VERSION}, "
                f"@sourcegraph/scip-python@{self.PYTHON_INDEXER_VERSION}, and SCIP CLI."
            )
        return executable

    def _run(self, args: list[str], *, json_output: bool = False) -> Any:
        try:
            result = subprocess.run(
                args,
                cwd=self.project_root,
                env=self._command_environment(),
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired as error:
            raise SCIPAnalyzerError(f"SCIP command timed out: {args[0]}") from error
        if result.returncode:
            detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic output"
            raise SCIPAnalyzerError(f"SCIP command failed ({result.returncode}): {detail}")
        if not json_output:
            return result.stdout.strip()
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise SCIPAnalyzerError(f"SCIP command returned invalid JSON: {error}") from error
        if not isinstance(payload, dict) or "result" not in payload:
            raise SCIPAnalyzerError("SCIP JSON response has no result field")
        return payload["result"]

    def validate_tools(self) -> None:
        """Reject missing, moving, or empirically incorrect toolchains."""
        query = self._executable("scip-query")
        indexer = self._executable("scip-python")
        scip = self._executable("scip")
        python = self._executable("python")
        pip = self._executable("pip")
        if shutil.which("scip-python-plus") is not None:
            raise SCIPAnalyzerError(
                "scip-python-plus is visible on PATH and may be selected by scip-query; "
                "remove it and install @sourcegraph/scip-python@0.6.6"
            )
        query_version = str(self._run([query, "--version"]))
        indexer_version = str(self._run([indexer, "--version"]))
        scip_version = str(self._run([scip, "--version"]))
        python_version = str(self._run([python, "--version"]))
        try:
            raw_packages = json.loads(str(self._run([pip, "list", "--format=json"])))
        except json.JSONDecodeError as error:
            raise SCIPAnalyzerError("Python environment package list was not valid JSON") from error
        if not isinstance(raw_packages, list) or any(
            not isinstance(package, dict)
            or not isinstance(package.get("name"), str)
            or not isinstance(package.get("version"), str)
            for package in raw_packages
        ):
            raise SCIPAnalyzerError("Python environment package list was incomplete")
        if self.QUERY_VERSION not in query_version:
            raise SCIPAnalyzerError(
                f"Unsupported scip-query version {query_version!r}; expected {self.QUERY_VERSION}"
            )
        if self.PYTHON_INDEXER_VERSION not in indexer_version:
            raise SCIPAnalyzerError(
                f"Unsupported scip-python version {indexer_version!r}; "
                f"expected {self.PYTHON_INDEXER_VERSION}"
            )
        self._toolchain_versions = {
            "query": query_version,
            "indexer": indexer_version,
            "scip": scip_version,
        }
        self._runtime_environment = {
            "python": python_version,
            "pip": str(self._run([pip, "--version"])),
            "packages": sorted(
                ({"name": item["name"], "version": item["version"]} for item in raw_packages),
                key=lambda item: (item["name"].casefold(), item["version"]),
            ),
        }

    def ensure_index(self, *, force: bool = False) -> None:  # noqa: PLR0912, PLR0915
        # SCIP's implicit cache has no trustworthy provenance contract. Keep a
        # canonical content manifest beside the index, and only permit reuse
        # when both the toolchain and every indexed source still match.
        self.validate_tools()
        sources = self._source_manifest()
        provenance = {
            "schema": 1,
            "toolchain": self._toolchain_versions,
            "runtimeEnvironment": self._runtime_environment,
            "sources": sources,
            "configs": self._config_manifest(),
            "inventory": self._inventory_configuration(),
            "indexScope": "project_root",
        }
        digest = hashlib.sha256(
            json.dumps(provenance, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if self._inventory_digest != digest:
            self._clear_source_observations()
        cache_base = self.project_root / ".cache"
        cache_namespace = cache_base / "fastapi-endpoint-detector"
        cache_root = cache_namespace / "scip"
        for directory, parent, private in (
            (cache_base, self.project_root, False),
            (cache_namespace, cache_base, True),
            (cache_root, cache_namespace, True),
        ):
            directory.mkdir(mode=0o700, exist_ok=True)
            self._require_owned_directory(directory, parent, private=private)
        cache_dir = cache_root / digest
        cache_dir.mkdir(mode=0o700, exist_ok=True)
        self._require_owned_directory(cache_dir, cache_root.resolve(strict=True))
        manifest = cache_dir / "provenance.json"
        if manifest.exists() or manifest.is_symlink():
            try:
                manifest.resolve(strict=True).relative_to(cache_dir.resolve(strict=True))
            except (OSError, ValueError) as error:
                raise SCIPAnalyzerError(
                    "SCIP cache manifest escapes its owner directory"
                ) from error
        if not force and self.use_cache and manifest.is_file() and not manifest.is_symlink():
            try:
                saved = json.loads(manifest.read_text(encoding="utf-8"))
                index = (cache_dir / saved["index"]).resolve(strict=True)
                if (
                    saved.get("provenance") == provenance
                    and self._valid_index(index, cache_dir)
                    and saved.get("index_sha256") == self._file_sha256(index)
                ):
                    if (
                        self._source_manifest() != sources
                        or self._config_manifest() != provenance["configs"]
                        or self._inventory_configuration() != provenance["inventory"]
                    ):
                        raise SCIPAnalyzerError("SCIP inputs changed while validating cached index")
                    self._active_index = index
                    self._inventory_digest = digest
                    self._cache_home = cache_dir / "home"
                    self._require_owned_directory(self._cache_home, cache_dir.resolve(strict=True))
                    return
            except (OSError, ValueError, KeyError, TypeError):
                pass
        manifest.unlink(missing_ok=True)
        self._cache_home = cache_dir / "home"
        self._cache_home.mkdir(mode=0o700, exist_ok=True)
        self._require_owned_directory(self._cache_home, cache_dir.resolve(strict=True))
        args = [
            self._executable("scip-query"),
            "reindex",
            "--language",
            "python",
            "--force",
            "--json",
        ]
        result = self._run(args, json_output=True)
        if not isinstance(result, dict) or "indexPath" not in result:
            raise SCIPAnalyzerError("scip-query reindex did not return an index path")
        if result.get("reused") is not False:
            raise SCIPAnalyzerError("scip-query unexpectedly reused an unverified cached index")
        shards = result.get("shards")
        if not isinstance(shards, list) or not shards:
            raise SCIPAnalyzerError("scip-query reindex did not report indexer provenance")
        commands: list[str] = []
        for shard in shards:
            if isinstance(shard, dict):
                command = shard.get("command")
                if isinstance(command, str):
                    commands.append(command)
        if commands and not any("scip-python index" in command for command in commands):
            raise SCIPAnalyzerError(f"Unexpected Python SCIP indexer provenance: {commands!r}")
        raw_index = Path(str(result["indexPath"]))
        try:
            actual_index = raw_index.resolve(strict=True)
            actual_index.relative_to(self._cache_home.resolve(strict=True))
        except (OSError, ValueError) as error:
            raise SCIPAnalyzerError(
                "SCIP returned an index path outside its owned cache"
            ) from error
        if not actual_index.is_file():
            raise SCIPAnalyzerError("SCIP index path is not a regular file")
        if not self._valid_index(actual_index, cache_dir):
            raise SCIPAnalyzerError("SCIP produced an invalid or empty index")
        if (
            self._source_manifest() != sources
            or self._config_manifest() != provenance["configs"]
            or self._inventory_configuration() != provenance["inventory"]
        ):
            raise SCIPAnalyzerError("SCIP inputs changed while the index was being built")
        self._active_index = actual_index
        if self.use_cache:
            manifest_value = {
                "provenance": provenance,
                "index": actual_index.relative_to(cache_dir).as_posix(),
                "index_sha256": self._file_sha256(actual_index),
            }
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=cache_dir, prefix=".provenance-", delete=False
            ) as stream:
                stream.write(json.dumps(manifest_value, sort_keys=True))
                temporary = Path(stream.name)
            temporary.replace(manifest)
        self._inventory_digest = digest

    def _clear_source_observations(self) -> None:
        self._outline_cache.clear()
        self._base_method_cache.clear()
        self._reverse_call_edge_cache.clear()
        self._reverse_call_edge_limitations.clear()
        self._ast_cache.clear()
        self._module_paths = None

    def _command_environment(self) -> dict[str, str]:
        env = os.environ.copy()
        if self._cache_home is not None:
            env["HOME"] = str(self._cache_home)
            env["USERPROFILE"] = str(self._cache_home)
        env["SCIP_QUERY_UPDATE_CHECK"] = "0"
        return env

    @staticmethod
    def _valid_index(path: Path, owner: Path) -> bool:
        try:
            real = path.resolve(strict=True)
            real.relative_to(owner.resolve(strict=True))
            return real.is_file() and real.stat().st_size > 0
        except (OSError, ValueError):
            return False

    @staticmethod
    def _require_owned_directory(path: Path, parent: Path, *, private: bool = True) -> None:
        try:
            if path.is_symlink():
                raise SCIPAnalyzerError(f"SCIP cache directory is a symlink: {path}")
            real = path.resolve(strict=True)
            if real.parent != parent.resolve(strict=True):
                raise SCIPAnalyzerError(f"SCIP cache path escapes its owner: {path}")
            metadata = real.stat()
        except (OSError, ValueError) as error:
            raise SCIPAnalyzerError(f"Invalid SCIP cache directory: {path}") from error
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise SCIPAnalyzerError(f"SCIP cache directory has a different owner: {path}")
        if private and os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise SCIPAnalyzerError(f"SCIP cache directory permissions are too broad: {path}")

    @staticmethod
    def _file_sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    def _source_manifest(self) -> list[dict[str, str]]:
        # scip-query reindexes the project root, even when callers select a
        # narrower evidence inventory. Hash the actual broader index scope so
        # edits outside that inventory cannot leave a stale index reusable.
        self._verify_project_root_identity()
        current_inventory = self._current_inventory_paths()
        paths = self._python_source_paths()
        if len(paths) > self.MAX_SOURCE_FILES:
            raise SCIPAnalyzerError("SCIP project source snapshot exceeded the file-count cap")
        records: list[dict[str, str]] = []
        seen: set[str] = set()
        total_bytes = 0
        for path in paths:
            try:
                relative_path = path.relative_to(self.project_root)
                relative = relative_path.as_posix()
                if relative in seen:
                    raise SCIPAnalyzerError(f"Invalid or duplicate SCIP source path: {relative}")
                seen.add(relative)
                content_hash, identity, size, _ = self._read_source_snapshot(relative_path)
            except (OSError, ValueError) as error:
                raise SCIPAnalyzerError(
                    f"SCIP source inventory changed or escaped: {path}"
                ) from error
            total_bytes += size
            if total_bytes > self.MAX_SOURCE_SNAPSHOT_BYTES:
                raise SCIPAnalyzerError("SCIP project source snapshot exceeded the byte-count cap")
            records.append({"path": relative, "sha256": content_hash, "identity": identity})
        if (
            self._python_source_paths() != paths
            or self._current_inventory_paths() != current_inventory
        ):
            raise SCIPAnalyzerError("SCIP source set changed while creating a stable snapshot")
        return sorted(records, key=lambda item: item["path"])

    @staticmethod
    def _directory_identity(metadata: os.stat_result) -> tuple[int, int, int]:
        return (metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode))

    @staticmethod
    def _source_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            stat.S_IFMT(metadata.st_mode),
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )

    def _verify_project_root_identity(self) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.project_root, flags)
        except OSError as error:
            raise SCIPAnalyzerError("SCIP project root changed or became a symlink") from error
        try:
            metadata = os.fstat(descriptor)
            if self._directory_identity(metadata) != self._project_root_identity:
                raise SCIPAnalyzerError("SCIP project root changed after analyzer creation")
        finally:
            os.close(descriptor)

    def _inventory_relative_path(self, value: Path) -> Path:
        candidate = value if value.is_absolute() else self.project_root / value
        if ".." in candidate.parts:
            raise SCIPAnalyzerError("SCIP source inventory contains a non-canonical path")
        lexical = candidate
        try:
            relative = lexical.relative_to(self.project_root)
        except ValueError as error:
            raise SCIPAnalyzerError(
                "SCIP source inventory contains a missing or escaping path"
            ) from error
        if not relative.parts or any(part in {".", ".."} for part in relative.parts):
            raise SCIPAnalyzerError("SCIP source inventory contains a non-canonical path")
        current = self.project_root
        try:
            for part in relative.parts:
                current = current / part
                if current.is_symlink():
                    raise SCIPAnalyzerError("SCIP source inventory contains a symlink path")
            resolved = lexical.resolve(strict=True)
        except OSError as error:
            raise SCIPAnalyzerError("SCIP source inventory contains a missing path") from error
        if resolved != lexical or not current.is_file():
            raise SCIPAnalyzerError("SCIP source inventory contains a non-canonical file path")
        return relative

    def _current_inventory_paths(self) -> set[str] | None:
        if self.source_inventory is None:
            return None
        try:
            values = [
                self._inventory_relative_path(path).as_posix()
                for path in self.source_inventory.paths
            ]
        except (OSError, ValueError) as error:
            raise SCIPAnalyzerError("SCIP source inventory changed or escaped") from error
        current = set(values)
        if len(current) != len(values):
            raise SCIPAnalyzerError("SCIP source inventory contains duplicate canonical paths")
        if current != self._inventory_paths:
            raise SCIPAnalyzerError("SCIP source inventory changed after analyzer creation")
        return current

    def _python_source_paths(self) -> list[Path]:
        try:
            paths = sorted(self.project_root.rglob("*.py"))
        except OSError as error:
            raise SCIPAnalyzerError("Could not enumerate SCIP project sources") from error
        if len(paths) > self.MAX_SOURCE_FILES:
            raise SCIPAnalyzerError("SCIP project source snapshot exceeded the file-count cap")
        return paths

    def _read_source_snapshot(  # noqa: PLR0912, PLR0915 - explicit fail-closed descriptor audit
        self, relative: Path
    ) -> tuple[str, str, int, bytes]:
        """Read and hash one bounded regular file through no-follow descriptors."""
        if relative.is_absolute() or not relative.parts or ".." in relative.parts:
            raise SCIPAnalyzerError(f"Invalid SCIP source path: {relative}")
        if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
            raise SCIPAnalyzerError("Platform lacks race-safe no-follow source snapshot support")
        directory_flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)

        def open_chain() -> tuple[int, list[int], tuple[tuple[int, int, int], ...]]:
            root_fd = os.open(self.project_root, directory_flags)
            descriptors = [root_fd]
            identities = [self._directory_identity(os.fstat(root_fd))]
            if identities[0] != self._project_root_identity:
                os.close(root_fd)
                raise SCIPAnalyzerError("SCIP project root changed while hashing sources")
            try:
                for component in relative.parts[:-1]:
                    child = os.open(component, directory_flags, dir_fd=descriptors[-1])
                    metadata = os.fstat(child)
                    if not stat.S_ISDIR(metadata.st_mode):
                        os.close(child)
                        raise SCIPAnalyzerError(
                            f"SCIP source parent is not a directory: {relative}"
                        )
                    descriptors.append(child)
                    identities.append(self._directory_identity(metadata))
            except BaseException:
                for descriptor in reversed(descriptors):
                    os.close(descriptor)
                raise
            return descriptors[-1], descriptors, tuple(identities)

        parent_fd, parent_descriptors, directory_identities = open_chain()
        source_fd = -1
        try:
            source_fd = os.open(relative.parts[-1], file_flags, dir_fd=parent_fd)
            before = os.fstat(source_fd)
            if not stat.S_ISREG(before.st_mode):
                raise SCIPAnalyzerError(f"SCIP source is not a regular file: {relative}")
            if before.st_size > self.MAX_SOURCE_FILE_BYTES:
                raise SCIPAnalyzerError(f"SCIP source exceeded the per-file byte cap: {relative}")
            digest = hashlib.sha256()
            size = 0
            content: list[bytes] = []
            while True:
                block = os.read(source_fd, min(1024 * 1024, self.MAX_SOURCE_READ_BYTES - size))
                if not block:
                    break
                size += len(block)
                if size > self.MAX_SOURCE_FILE_BYTES:
                    raise SCIPAnalyzerError(
                        f"SCIP source exceeded the per-file byte cap: {relative}"
                    )
                digest.update(block)
                content.append(block)
            after = os.fstat(source_fd)
            if self._source_identity(before) != self._source_identity(after):
                raise SCIPAnalyzerError(f"SCIP source changed while hashing: {relative}")
            named = os.stat(relative.parts[-1], dir_fd=parent_fd, follow_symlinks=False)
            if self._source_identity(named) != self._source_identity(after):
                raise SCIPAnalyzerError(f"SCIP source path was replaced while hashing: {relative}")
        except OSError as error:
            raise SCIPAnalyzerError(
                f"Could not authenticate SCIP source path: {relative}"
            ) from error
        finally:
            if source_fd >= 0:
                os.close(source_fd)
            for descriptor in reversed(parent_descriptors):
                os.close(descriptor)

        # Re-open the path from the root after reading. Directory and file
        # identities must still match the chain held during the read, and the
        # ordinary resolved path must remain the same canonical repository path.
        check_parent_fd, check_descriptors, check_directories = open_chain()
        try:
            if check_directories != directory_identities:
                raise SCIPAnalyzerError(
                    f"SCIP source parent path changed while hashing: {relative}"
                )
            current = os.stat(relative.parts[-1], dir_fd=check_parent_fd, follow_symlinks=False)
            if self._source_identity(current) != self._source_identity(after):
                raise SCIPAnalyzerError(f"SCIP source path was replaced while hashing: {relative}")
            canonical = (self.project_root / relative).resolve(strict=True)
            if canonical != self.project_root / relative:
                raise SCIPAnalyzerError(f"SCIP source path became a symlink: {relative}")
        except OSError as error:
            raise SCIPAnalyzerError(
                f"SCIP source path changed while hashing: {relative}"
            ) from error
        finally:
            for descriptor in reversed(check_descriptors):
                os.close(descriptor)
        identity = ":".join(str(value) for value in self._source_identity(after))
        return digest.hexdigest(), identity, size, b"".join(content)

    def _config_manifest(self) -> list[dict[str, str]]:
        names = (
            "pyproject.toml",
            "pyrightconfig.json",
            "setup.cfg",
            "mypy.ini",
            "uv.lock",
            "poetry.lock",
            "Pipfile.lock",
            ".scipquery.json",
        )
        paths = {self.project_root / name for name in names}
        paths.update(self.project_root.glob("requirements*.txt"))
        records: list[dict[str, str]] = []
        for path in sorted(paths):
            if not path.exists() and not path.is_symlink():
                continue
            if path.is_symlink():
                raise SCIPAnalyzerError(f"SCIP configuration path is a symlink: {path}")
            try:
                resolved = path.resolve(strict=True)
                relative = resolved.relative_to(self.project_root).as_posix()
                if not resolved.is_file():
                    raise SCIPAnalyzerError(f"Invalid SCIP configuration file: {relative}")
                digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
            except (OSError, ValueError) as error:
                raise SCIPAnalyzerError(f"SCIP configuration escapes project: {path}") from error
            records.append({"path": relative, "sha256": digest})
        return records

    def _inventory_configuration(self) -> dict[str, Any] | None:
        if self.source_inventory is None:
            return None
        names = (
            "follow_imports",
            "max_depth",
            "excluded_files",
            "unresolved_imports",
            "limitations",
        )
        return {
            "paths": sorted(self._inventory_paths or ()),
            **{name: getattr(self.source_inventory, name, None) for name in names},
        }

    def source_scope(self) -> SCIPSourceScope:
        """Describe the selected evidence inventory and actual broader index scope."""
        if self._inventory_paths is None:
            return SCIPSourceScope(
                index_scope="project_root",
                selected_inventory_paths=None,
                limitations=(
                    "No selected source inventory was supplied; SCIP evidence uses project scope.",
                    "SCIP syntax/reference results are not execution observations.",
                ),
            )
        return SCIPSourceScope(
            index_scope="project_root",
            selected_inventory_paths=tuple(sorted(self._inventory_paths)),
            limitations=(
                "The selected inventory filters returned evidence, but SCIP indexing remains "
                "project-root-wide.",
                "SCIP syntax/reference results are not execution observations.",
            ),
        )

    def _relative_file(  # noqa: PLR0912
        self, file_path: Path, *, repository_relative: bool = False
    ) -> Path:
        if file_path.is_absolute():
            try:
                return file_path.resolve().relative_to(self.project_root)
            except ValueError as error:
                raise SCIPAnalyzerError(
                    f"Changed file is outside SCIP project: {file_path}"
                ) from error
        text = str(file_path)
        git_quoted = text.startswith('"') and text.endswith('"')
        if git_quoted:
            text = self._decode_git_quoted_path(text)
        if not git_quoted or os.name == "nt":
            text = text.replace("\\", "/")
        candidate = Path(text)
        windows_absolute = re.match(r"^[A-Za-z]:/", text) is not None
        if windows_absolute and not repository_relative:
            raise SCIPAnalyzerError(f"Changed file is outside SCIP project: {file_path}")
        if windows_absolute:
            candidate = Path(*candidate.parts[1:])
        if candidate.is_absolute() or ".." in candidate.parts:
            if not repository_relative:
                raise SCIPAnalyzerError(f"Changed file is outside SCIP project: {file_path}")
            candidate = Path(*candidate.parts[1:])
        direct = self.project_root / candidate
        if direct.exists() or direct.is_symlink():
            try:
                return direct.resolve(strict=True).relative_to(self.project_root)
            except (OSError, ValueError) as error:
                raise SCIPAnalyzerError(f"SCIP path escapes or is invalid: {file_path}") from error
        try:
            resolved = direct.resolve(strict=True)
            return resolved.relative_to(self.project_root)
        except (OSError, ValueError):
            pass
        if not repository_relative:
            return candidate
        matches: set[Path] = set()
        for offset in range(1, len(candidate.parts)):
            suffix = Path(*candidate.parts[offset:])
            try:
                resolved = (self.project_root / suffix).resolve(strict=True)
                matches.add(resolved.relative_to(self.project_root))
            except (OSError, ValueError):
                continue
        if len(matches) != 1:
            raise SCIPAnalyzerError(f"Ambiguous or missing repository-relative path: {file_path}")
        return next(iter(matches))

    @staticmethod
    def _decode_git_quoted_path(value: str) -> str:
        escapes = {
            '"': 0x22,
            "\\": 0x5C,
            "a": 0x07,
            "b": 0x08,
            "t": 0x09,
            "n": 0x0A,
            "v": 0x0B,
            "f": 0x0C,
            "r": 0x0D,
        }
        encoded = bytearray()
        body = value[1:-1]
        offset = 0
        while offset < len(body):
            char = body[offset]
            if char != "\\":
                encoded.extend(char.encode("utf-8"))
                offset += 1
                continue
            offset += 1
            if offset >= len(body):
                raise SCIPAnalyzerError(f"Malformed quoted SCIP path: {value!r}")
            escaped = body[offset]
            if escaped in escapes:
                encoded.append(escapes[escaped])
                offset += 1
            elif escaped in "01234567":
                digits = body[offset : offset + 3]
                if len(digits) != 3 or any(digit not in "01234567" for digit in digits):
                    raise SCIPAnalyzerError(f"Malformed octal SCIP path escape: {value!r}")
                encoded.append(int(digits, 8))
                offset += 3
            else:
                raise SCIPAnalyzerError(f"Unsupported SCIP path escape: {value!r}")
        try:
            return encoded.decode("utf-8")
        except UnicodeDecodeError as error:
            raise SCIPAnalyzerError(f"Invalid UTF-8 Git path: {value!r}") from error

    def outline(self, file_path: Path) -> tuple[SCIPDefinition, ...]:
        relative = self._relative_file(file_path)
        if self._inventory_paths is not None and relative.as_posix() not in self._inventory_paths:
            return ()
        if relative in self._outline_cache:
            return self._outline_cache[relative]
        result = self._run(
            [self._executable("scip-query"), "outline", relative.as_posix(), "--json"],
            json_output=True,
        )
        if not isinstance(result, list):
            raise SCIPAnalyzerError(f"Invalid outline result for {relative}")
        definitions: list[SCIPDefinition] = []

        def collect(items: list[object]) -> None:
            for item in items:
                if not isinstance(item, dict):
                    raise SCIPAnalyzerError(f"Malformed outline entry for {relative}")
                symbol = item.get("symbol")
                short_name = item.get("shortName")
                start = item.get("startLine")
                end = item.get("endLine")
                if not (
                    isinstance(symbol, str)
                    and isinstance(short_name, str)
                    and isinstance(start, int)
                    and isinstance(end, int)
                ):
                    raise SCIPAnalyzerError(f"Incomplete outline entry for {relative}")
                definitions.append(SCIPDefinition(symbol, short_name, relative, start + 1, end + 1))
                children = item.get("children", [])
                if not isinstance(children, list):
                    raise SCIPAnalyzerError(f"Malformed outline children for {relative}")
                collect(children)

        collect(result)
        tree = self._source_ast(relative, self.project_root / relative)
        if tree is not None:
            callable_ends = {
                node.lineno: node.end_lineno
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and node.end_lineno is not None
            }
            definitions = [
                SCIPDefinition(
                    definition.symbol,
                    definition.short_name,
                    definition.file_path,
                    definition.start_line,
                    max(definition.end_line, callable_ends.get(definition.start_line, 0)),
                )
                for definition in definitions
            ]
        value = tuple(definitions)
        self._outline_cache[relative] = value
        return value

    def definitions_at(self, file_path: Path, lines: set[int]) -> tuple[SCIPDefinition, ...]:
        found: dict[str, SCIPDefinition] = {}
        relative = self._relative_file(file_path, repository_relative=True)
        definitions = self.outline(relative)
        for line in lines:
            containing = [item for item in definitions if item.start_line <= line <= item.end_line]
            if containing:
                narrowest = min(
                    containing,
                    key=lambda item: (item.end_line - item.start_line, -item.start_line),
                )
                found[narrowest.symbol] = narrowest
        return tuple(found.values())

    def _project_module_paths(self) -> dict[str, Path]:
        if self._module_paths is None:
            paths: dict[str, Path] = {}
            ambiguous: set[str] = set()
            source_paths = (
                self.source_inventory.paths
                if self.source_inventory is not None
                else self.project_root.rglob("*.py")
            )
            for source_path in source_paths:
                try:
                    resolved_path = source_path.resolve(strict=True)
                    resolved_path.relative_to(self.project_root)
                except (OSError, ValueError):
                    continue
                relative = resolved_path.relative_to(self.project_root).with_suffix("")
                parts = list(relative.parts)
                if parts and parts[0] in {"src", "python"}:
                    parts.pop(0)
                if parts and parts[-1] == "__init__":
                    parts.pop()
                module = ".".join(parts)
                if module:
                    module_path = relative.with_suffix(".py")
                    if module in ambiguous:
                        continue
                    if module in paths and paths[module] != module_path:
                        paths.pop(module, None)
                        ambiguous.add(module)
                        continue
                    paths[module] = module_path
            self._module_paths = paths
        return self._module_paths

    def _imported_module_path(self, statement: ast.ImportFrom, importer: Path) -> Path | None:
        module = statement.module or ""
        if statement.level:
            importer_parts = list(importer.with_suffix("").parts)
            if importer_parts and importer_parts[-1] == "__init__":
                package_parts = importer_parts
            else:
                package_parts = importer_parts[:-1]
            remove = statement.level - 1
            if remove > len(package_parts):
                return None
            package_parts = package_parts[: len(package_parts) - remove]
            module_parts = package_parts + (module.split(".") if module else [])
            module = ".".join(module_parts)
        return self._project_module_paths().get(module)

    def base_method_definitions(  # noqa: PLR0912
        self, definition: SCIPDefinition
    ) -> tuple[SCIPDefinition, ...]:
        """Resolve explicitly inherited base methods for one concrete method."""
        cached = self._base_method_cache.get(definition.symbol)
        if cached is not None:
            return cached
        parts = definition.short_name.split(":")
        if len(parts) < 3 or not parts[-1].endswith("()"):
            self._base_method_cache[definition.symbol] = ()
            return ()
        class_name = parts[-2]
        method_name = parts[-1][:-2]
        try:
            relative = self._inventory_relative_path(definition.file_path)
        except SCIPAnalyzerError:
            self._base_method_cache[definition.symbol] = ()
            return ()
        tree = self._source_ast(relative, self.project_root / relative)
        if tree is None:
            self._base_method_cache[definition.symbol] = ()
            return ()
        imports: dict[str, tuple[str, str] | None] = {}
        for statement in tree.body:
            if isinstance(statement, ast.ImportFrom):
                for import_alias in statement.names:
                    local_name = import_alias.asname or import_alias.name
                    imported_path = self._imported_module_path(statement, definition.file_path)
                    imported = (
                        imported_path.as_posix() if imported_path is not None else "",
                        import_alias.name,
                    )
                    existing = imports.get(local_name)
                    if local_name in imports and existing != imported:
                        imports[local_name] = None
                    else:
                        imports[local_name] = imported
        classes = [
            node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name
        ]
        if len(classes) != 1:
            self._base_method_cache[definition.symbol] = ()
            return ()
        found: dict[str, SCIPDefinition] = {}
        for base in classes[0].bases:
            if not isinstance(base, ast.Name):
                continue
            import_info = imports.get(base.id)
            base_path: Path | None
            if base.id in imports and import_info is None:
                continue
            if import_info is None:
                base_path = definition.file_path
                base_name = base.id
            else:
                base_path = Path(import_info[0]) if import_info[0] else None
                base_name = import_info[1]
            if base_path is None:
                continue
            suffix = f":{base_name}:{method_name}()"
            matches = [item for item in self.outline(base_path) if item.short_name.endswith(suffix)]
            if len(matches) == 1:
                found[matches[0].symbol] = matches[0]
        result = tuple(found.values())
        self._base_method_cache[definition.symbol] = result
        return result

    def _definition_for_affected(self, file_path: Path, short_name: str) -> SCIPDefinition | None:
        matches = [item for item in self.outline(file_path) if item.short_name == short_name]
        return matches[0] if len(matches) == 1 else None

    def _validated_project_file(self, value: str) -> tuple[Path, Path]:
        """Return a canonical project-relative path and its absolute source path."""
        if not value or "\x00" in value:
            raise SCIPAnalyzerError(f"Malformed SCIP reference path: {value!r}")
        supplied = Path(value)
        if supplied.is_absolute() or ".." in supplied.parts:
            raise SCIPAnalyzerError(f"SCIP reference path is outside project: {value!r}")
        try:
            relative = self._inventory_relative_path(supplied)
            absolute = self.project_root / relative
        except (OSError, ValueError, SCIPAnalyzerError) as error:
            raise SCIPAnalyzerError(f"Invalid SCIP reference path: {value!r}") from error
        if not absolute.is_file():
            raise SCIPAnalyzerError(f"SCIP reference path is not a file: {value!r}")
        return relative, absolute

    def _source_ast(self, relative: Path, absolute: Path) -> ast.Module | None:
        if relative not in self._ast_cache:
            try:
                _, _, _, content = self._read_source_snapshot(relative)
                self._ast_cache[relative] = ast.parse(
                    content.decode("utf-8"), filename=str(absolute)
                )
            except (OSError, SyntaxError, UnicodeError, SCIPAnalyzerError):
                self._ast_cache[relative] = None
        return self._ast_cache[relative]

    def _caller_at_reference(  # noqa: PLR0911, PLR0912
        self,
        relative: Path,
        absolute: Path,
        line: int,
        callee: SCIPDefinition,
    ) -> tuple[SCIPDefinition, ast.Module, ast.Call, ast.FunctionDef | ast.AsyncFunctionDef] | None:
        tree = self._source_ast(relative, absolute)
        if tree is None:
            return None
        enclosing_functions = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.end_lineno is not None
            and node.lineno <= line <= node.end_lineno
        ]
        if not enclosing_functions:
            return None
        enclosing_functions.sort(
            key=lambda node: ((node.end_lineno or node.lineno) - node.lineno, -node.lineno)
        )
        callee_short = callee.short_name.split(":")[-1]
        if not callee_short.endswith("()"):
            return None
        callee_name = callee_short[:-2]
        callee_parts = callee.short_name.split(":")
        call_names = (
            {callee_name}
            if relative == callee.file_path
            and len(callee_parts) == 2
            and sum(
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == callee_name
                for node in tree.body
            )
            == 1
            else set()
        )
        imported_names: dict[str, set[tuple[str, str]]] = {}
        for statement in tree.body:
            if isinstance(statement, ast.ImportFrom):
                imported_path = self._imported_module_path(statement, relative)
                for alias in statement.names:
                    local_name = alias.asname or alias.name
                    identity = (imported_path.as_posix() if imported_path else "", alias.name)
                    imported_names.setdefault(local_name, set()).add(identity)
        for local_name, identities in imported_names.items():
            if identities == {(callee.file_path.as_posix(), callee_name)}:
                call_names.add(local_name)
        if not call_names:
            return None
        function_scope = enclosing_functions[0]
        shadowed = {
            node.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
        }
        function_args = function_scope.args
        shadowed.update(
            arg.arg
            for arg in (
                *function_args.posonlyargs,
                *function_args.args,
                *function_args.kwonlyargs,
                *((function_args.vararg,) if function_args.vararg else ()),
                *((function_args.kwarg,) if function_args.kwarg else ()),
            )
        )
        if call_names & shadowed:
            return None
        references = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Name)
            and node.id in call_names
            and node.end_lineno is not None
            and node.lineno <= line <= node.end_lineno
        ]
        # A SCIP line cannot distinguish two references to the resolved callee.
        if len(references) != 1:
            return None
        reference = references[0]
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in call_names
            and node.func is reference
        ]
        if len(calls) != 1 or calls[0].lineno != line:
            return None
        containing = [
            definition
            for definition in self.outline(relative)
            if definition.short_name.endswith("()")
            and definition.start_line <= line <= definition.end_line
        ]
        if not containing:
            return None
        narrowest_size = min(item.end_line - item.start_line for item in containing)
        narrowest = [
            item for item in containing if item.end_line - item.start_line == narrowest_size
        ]
        if len(narrowest) != 1:
            return None
        outline = narrowest[0]
        ast_scope = enclosing_functions[0]
        if outline.start_line != ast_scope.lineno:
            return None
        return outline, tree, calls[0], ast_scope

    @staticmethod
    def _scope_has_yield(scope: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        pending: list[ast.AST] = list(scope.body)
        while pending:
            node = pending.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                continue
            if isinstance(node, (ast.Yield, ast.YieldFrom)):
                return True
            pending.extend(ast.iter_child_nodes(node))
        return False

    @staticmethod
    def _call_is_after_terminal(
        scope: ast.FunctionDef | ast.AsyncFunctionDef, call: ast.Call
    ) -> bool:
        def contains_target(node: ast.AST) -> bool:
            if node is call:
                return True
            if node is not scope and isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
            ):
                return False
            return any(contains_target(child) for child in ast.iter_child_nodes(node))

        def scan_block(statements: list[ast.stmt], terminal_seen: bool = False) -> bool:
            for statement in statements:
                if contains_target(statement):
                    if terminal_seen:
                        return True
                    for _, value in ast.iter_fields(statement):
                        if (
                            isinstance(value, list)
                            and all(isinstance(item, ast.stmt) for item in value)
                            and value
                            and any(contains_target(item) for item in value)
                        ):
                            return scan_block(value)
                    return False
                if isinstance(statement, (ast.Return, ast.Raise)):
                    terminal_seen = True
            return False

        return scan_block(scope.body)

    @staticmethod
    def _literal_truth(expression: ast.expr) -> bool | None:
        try:
            return bool(ast.literal_eval(expression))
        except (ValueError, TypeError, SyntaxError):
            return None

    @staticmethod
    def _call_is_in_lambda(
        parents: dict[ast.AST, ast.AST],
        call: ast.Call,
        scope: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> bool:
        current: ast.AST = call
        while current is not scope and current in parents:
            current = parents[current]
            if isinstance(current, ast.Lambda):
                return True
        return False

    def _callee_execution_kind(self, callee: SCIPDefinition) -> tuple[bool, bool]:
        name = callee.short_name.split(":")[-1].removesuffix("()")
        try:
            tree = self._source_ast(callee.file_path, self.project_root / callee.file_path)
        except (OSError, ValueError):
            return False, False
        if tree is None:
            return False, False
        definitions = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == name
            and node.lineno == callee.start_line
        ]
        if len(definitions) != 1:
            return False, False
        definition = definitions[0]
        return isinstance(definition, ast.AsyncFunctionDef), self._scope_has_yield(definition)

    def _source_call_limitations(
        self,
        tree: ast.Module,
        call: ast.Call,
        scope: ast.FunctionDef | ast.AsyncFunctionDef,
        callee: SCIPDefinition,
    ) -> tuple[str, ...]:
        limitations = {
            "A SCIP reference and matching AST call are reference-only evidence; execution is "
            "unverified (LOW)."
        }
        limitations.update(self.source_scope().limitations)
        parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
        if self._call_is_after_terminal(scope, call):
            limitations.add(
                "The call follows a return or raise in its lexical block; execution is not "
                "established."
            )
        if self._call_is_in_lambda(parents, call, scope):
            limitations.add("The call is inside a lambda whose invocation is unverified.")
        if isinstance(scope, ast.AsyncFunctionDef):
            limitations.add(
                "The enclosing async callable may be unawaited; its body execution is unverified."
            )
        if self._scope_has_yield(scope):
            limitations.add(
                "The enclosing generator may be unconsumed; its body execution is unverified."
            )
        current: ast.AST = call
        while current in parents:
            parent = parents[current]
            if isinstance(parent, ast.If):
                test_truth = self._literal_truth(parent.test)
                body_contains = any(
                    isinstance(node, ast.AST)
                    and any(descendant is current for descendant in ast.walk(node))
                    for node in parent.body
                )
                else_contains = any(
                    isinstance(node, ast.AST)
                    and any(descendant is current for descendant in ast.walk(node))
                    for node in parent.orelse
                )
                if (body_contains and test_truth is False) or (
                    else_contains and test_truth is True
                ):
                    limitations.add(
                        "The call is guarded by a literal-false branch; execution is impossible "
                        "there."
                    )
            if parent is scope:
                break
            current = parent
        callee_is_async, callee_is_generator = self._callee_execution_kind(callee)
        if (
            callee_is_async
            and parents.get(call) is not None
            and not isinstance(parents[call], ast.Await)
        ):
            limitations.add(
                "The async callee call is not directly awaited; coroutine body execution is "
                "unverified."
            )
        if callee_is_generator:
            limitations.add(
                "The callee is a generator; its body executes only if the result is consumed."
            )
        return tuple(sorted(limitations))

    def reverse_call_edges(  # noqa: PLR0912, PLR0915
        self, callee: SCIPDefinition
    ) -> tuple[SCIPReverseCallEdge, ...]:
        """Return only unambiguous direct calls confirmed by source and SCIP references."""
        cache_key = (callee.symbol, callee.short_name, callee.file_path)
        cached = self._reverse_call_edge_cache.get(cache_key)
        if cached is not None:
            return cached
        result = self._run(
            [self._executable("scip-query"), "refs", callee.symbol, "--json"],
            json_output=True,
        )
        if not isinstance(result, dict) or result.get("matched") is not True:
            raise SCIPAnalyzerError(f"SCIP could not resolve referenced symbol: {callee.symbol}")
        resolved = result.get("resolved")
        if not isinstance(resolved, dict) or resolved.get("symbol") != callee.symbol:
            raise SCIPAnalyzerError(
                f"SCIP resolved the wrong refs seed for {callee.symbol!r}: {resolved!r}"
            )
        resolved_short_name = resolved.get("shortName")
        resolved_path = resolved.get("relativePath")
        if not isinstance(resolved_short_name, str) or not isinstance(resolved_path, str):
            raise SCIPAnalyzerError("Incomplete SCIP refs resolution")
        if resolved_short_name != callee.short_name:
            raise SCIPAnalyzerError("SCIP refs resolution has an inconsistent short name")
        resolved_relative, _ = self._validated_project_file(resolved_path)
        try:
            supplied_callee_relative = self._relative_file(callee.file_path)
        except SCIPAnalyzerError as error:
            raise SCIPAnalyzerError("SCIP refs callee path is invalid") from error
        if resolved_relative != supplied_callee_relative:
            raise SCIPAnalyzerError(
                "SCIP refs resolution path does not match the supplied callee definition"
            )
        canonical_callee = SCIPDefinition(
            callee.symbol,
            callee.short_name,
            resolved_relative,
            callee.start_line,
            callee.end_line,
        )
        parts = callee.short_name.split(":")
        if not parts or not parts[-1].endswith("()"):
            raise SCIPAnalyzerError("SCIP refs callee is not a callable definition")
        if type(result.get("totalMatches")) is not int or result["totalMatches"] != 1:
            raise SCIPAnalyzerError(
                f"SCIP refs seed was ambiguous for {callee.symbol!r}: "
                f"{result.get('totalMatches')!r} matches"
            )
        other_matches = result.get("otherMatches")
        references = result.get("references")
        if not isinstance(other_matches, list) or not isinstance(references, list):
            raise SCIPAnalyzerError("Invalid SCIP refs result")

        edges: set[SCIPReverseCallEdge] = set()
        limitations: set[str] = set()
        limitations.add(
            "SCIP reverse-call edges are source-bound references only, not execution evidence "
            "(LOW)."
        )
        limitations.update(self.source_scope().limitations)
        if not references:
            limitations.add("SCIP reported no references; absence is not proof of no callers")
        if other_matches:
            limitations.add(
                "SCIP reported additional symbol matches; direct-call proof is ambiguous"
            )
        for reference in references:
            if not isinstance(reference, dict):
                raise SCIPAnalyzerError("Malformed SCIP reference entry")
            reference_path = reference.get("relativePath")
            zero_based_line = reference.get("line")
            if not isinstance(reference_path, str) or type(zero_based_line) is not int:
                raise SCIPAnalyzerError("Incomplete SCIP reference entry")
            if zero_based_line < 0:
                raise SCIPAnalyzerError("SCIP reference line cannot be negative")
            relative, absolute = self._validated_project_file(reference_path)
            if (
                self._inventory_paths is not None
                and relative.as_posix() not in self._inventory_paths
            ):
                limitations.add("SCIP reference was outside the selected source inventory")
                continue
            line = zero_based_line + 1
            source_call = self._caller_at_reference(relative, absolute, line, canonical_callee)
            if source_call is None:
                limitations.add(
                    "SCIP reference was unsupported or ambiguous as a source-bound direct call"
                )
                continue
            caller, tree, call, scope = source_call
            edge_limitations = self._source_call_limitations(tree, call, scope, canonical_callee)
            occurrence = SCIPOccurrence(relative, line)
            edges.add(
                SCIPReverseCallEdge(
                    caller,
                    canonical_callee,
                    occurrence,
                    execution_status="reference_only",
                    confidence="LOW",
                    limitations=edge_limitations,
                )
            )
            limitations.update(edge_limitations)

        value = tuple(
            sorted(
                edges,
                key=lambda edge: (
                    edge.caller.symbol,
                    edge.callee.symbol,
                    edge.occurrence.file_path.as_posix(),
                    edge.occurrence.line,
                ),
            )
        )
        self._reverse_call_edge_cache[cache_key] = value
        self._reverse_call_edge_limitations[cache_key] = tuple(sorted(limitations))
        return value

    def reverse_call_edge_limitations(self, callee: SCIPDefinition) -> tuple[str, ...]:
        """Describe references that were deferred or outside inventory scope."""
        cache_key = (callee.symbol, callee.short_name, callee.file_path)
        return self._reverse_call_edge_limitations.get(
            cache_key, ("SCIP direct-call query has not been completed",)
        )

    def affected(
        self, seed: SCIPDefinition, *, max_depth: int | None = None
    ) -> tuple[SCIPReachedDefinition, ...]:
        depth_limit = self.MAX_DEPTH if max_depth is None else max_depth
        result = self._run(
            [
                self._executable("scip-query"),
                "affected",
                seed.short_name,
                "--max-depth",
                str(depth_limit),
                "--json",
            ],
            json_output=True,
        )
        if not isinstance(result, dict) or result.get("matched") is not True:
            raise SCIPAnalyzerError(f"SCIP could not resolve changed symbol: {seed.symbol}")
        resolved = result.get("resolved")
        if not isinstance(resolved, dict) or resolved.get("symbol") != seed.symbol:
            raise SCIPAnalyzerError(
                f"SCIP resolved the wrong seed for {seed.symbol!r}: {resolved!r}"
            )
        if result.get("totalMatches") != 1:
            raise SCIPAnalyzerError(
                f"SCIP seed was ambiguous for {seed.symbol!r}: "
                f"{result.get('totalMatches')!r} matches"
            )
        reached: list[SCIPReachedDefinition] = [SCIPReachedDefinition(seed, 0)]
        raw_affected = result.get("affected", [])
        if not isinstance(raw_affected, list):
            raise SCIPAnalyzerError("Invalid affected-symbol list")
        for item in raw_affected:
            if not isinstance(item, dict):
                raise SCIPAnalyzerError("Malformed affected-symbol entry")
            file_name, short_name, depth = (
                item.get("file"),
                item.get("shortName"),
                item.get("depth"),
            )
            if not (
                isinstance(file_name, str)
                and isinstance(short_name, str)
                and isinstance(depth, int)
            ):
                raise SCIPAnalyzerError("Incomplete affected-symbol entry")
            definition = self._definition_for_affected(Path(file_name), short_name)
            if definition is None:
                raise SCIPAnalyzerError(
                    f"Could not uniquely resolve affected definition {short_name!r} in {file_name}"
                )
            reached.append(SCIPReachedDefinition(definition, depth))
        return tuple(reached)
