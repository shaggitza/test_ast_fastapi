"""Local synthetic diagnostic for Mypy dependency-cache loading.

The caller-pinned manifest digest establishes local self-consistency only. This
syntactic fixture filter is not a consumer-closure proof or admission authority.
The analyzer always discards the warm result and returns a full cold build.
"""

from __future__ import annotations

import ast
import contextlib
import hashlib
import json
import math
import os
import shutil
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - exercised in a simulated Windows subprocess
    fcntl = None  # type: ignore[assignment]

TRUST_ID = "source-committed-local-mypy-cache-v1"
MANIFEST_SCHEMA = "fastapi-mypy-cache-v1"
CONSUMER_PROFILE = "syntactic-event-registration-diagnostic-v1"
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_CACHE_FILES = 20_000
MAX_CACHE_BYTES = 256 * 1024 * 1024
MAX_SOURCE_FILE_BYTES = 4 * 1024 * 1024
MAX_SOURCE_BYTES = 128 * 1024 * 1024


class CacheAdmissionError(ValueError):
    """The local cache cannot be admitted under the committed policy."""


@dataclass(frozen=True)
class LocalTypedCachePolicy:
    """Diagnostic opt-in to an owner-private local cache store."""

    root: Path
    enabled: bool = True
    trust_id: str = TRUST_ID
    expected_manifest_sha256: str | None = None

    @classmethod
    def disabled(cls) -> LocalTypedCachePolicy:
        return cls(Path(), enabled=False)

    @classmethod
    def local_user_store(
        cls, root: Path | None = None, *, expected_manifest_sha256: str | None = None
    ) -> LocalTypedCachePolicy:
        if root is None:
            root = Path.home() / ".cache" / "fastapi-endpoint-detector" / "typed-mypy-v1"
        return cls(root.expanduser().absolute(), expected_manifest_sha256=expected_manifest_sha256)


@dataclass(frozen=True)
class CacheRunPlan:
    """Diagnostic cache inputs staged below a private per-run directory.

    This plan proves only a local synthetic Mypy load observation. It is not
    an admission authority or production trust token.
    """

    run_root: Path
    cache_map: dict[str, tuple[str, str]]
    expected_graph: dict[str, str | None]
    expected_roots: frozenset[str]
    admitted_modules: frozenset[str]
    manifest_sha256: str
    trust_id: str
    descriptors: tuple[int, ...] = ()
    artifact_hashes: dict[str, str] | None = None


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise CacheAdmissionError("cache manifest contains unsupported values") from exc


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _private_root(root: Path, *, create: bool) -> Path:
    if create:
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        info = root.lstat()
    except OSError as exc:
        raise CacheAdmissionError("local cache root is unavailable") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
    ):
        raise CacheAdmissionError("local cache root is not a private owned directory")
    return root.resolve(strict=True)


def _read_relative(root: Path, relative: str, limit: int) -> bytes:
    if os.open not in os.supports_dir_fd or not getattr(os, "O_NOFOLLOW", 0):
        raise CacheAdmissionError("no-follow directory-relative reads are unavailable")
    parts = Path(relative).parts
    if not parts or Path(relative).is_absolute() or any(p in {"", ".", ".."} for p in parts):
        raise CacheAdmissionError("cache member path is not canonical and contained")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(root, flags)
    leaf = -1
    try:
        for part in parts[:-1]:
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        leaf = os.open(
            parts[-1],
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
            dir_fd=descriptor,
        )
        info = os.fstat(leaf)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            raise CacheAdmissionError("cache member is not a bounded single-link regular file")
        blocks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            block = os.read(leaf, min(remaining, 1024 * 1024))
            if not block:
                break
            blocks.append(block)
            remaining -= len(block)
        data = b"".join(blocks)
        if len(data) > limit:
            raise CacheAdmissionError("cache member exceeds its byte limit")
        return data
    except OSError as exc:
        raise CacheAdmissionError("cache member could not be read without following links") from exc
    finally:
        if leaf >= 0:
            os.close(leaf)
        os.close(descriptor)


def read_source_snapshot(
    paths: dict[str, str], *, root: Path, expected_sha256: dict[str, str]
) -> dict[str, bytes]:
    """Capture exact project source bytes through the bounded no-follow reader."""
    canonical_root = root.resolve(strict=True)
    result: dict[str, bytes] = {}
    total = 0
    for module, raw_path in sorted(paths.items()):
        path = Path(raw_path).resolve(strict=True)
        try:
            relative = path.relative_to(canonical_root).as_posix()
        except ValueError as exc:
            raise CacheAdmissionError("project source escapes its inventory root") from exc
        data = _read_relative(canonical_root, relative, MAX_SOURCE_FILE_BYTES)
        total += len(data)
        if total > MAX_SOURCE_BYTES or _digest(data) != expected_sha256[module]:
            raise CacheAdmissionError("project source snapshot differs from its inventory")
        result[str(path)] = data
    return result


def _options_record(options: object) -> dict[str, object]:
    names = {name for cls in type(options).__mro__ for name in getattr(cls, "__mypyc_attrs__", ())}
    if not names:
        raise CacheAdmissionError("Mypy effective options are not inspectable")

    def encode(value: object, depth: int = 0) -> object:
        if depth > 16:
            raise CacheAdmissionError("Mypy options exceed the canonical depth limit")
        if value is None or isinstance(value, (bool, int, str)):
            return value
        if isinstance(value, float):
            if not math.isfinite(value):
                raise CacheAdmissionError("Mypy options contain a non-finite number")
            return value
        if isinstance(value, (list, tuple)):
            if len(value) > 10_000:
                raise CacheAdmissionError("Mypy options exceed the item limit")
            return [encode(item, depth + 1) for item in value]
        if isinstance(value, (set, frozenset)):
            encoded = [encode(item, depth + 1) for item in value]
            return sorted(encoded, key=_canonical)
        if isinstance(value, dict):
            if len(value) > 10_000 or not all(isinstance(key, str) for key in value):
                raise CacheAdmissionError("Mypy options contain unsupported mapping keys")
            return {key: encode(item, depth + 1) for key, item in sorted(value.items())}
        raise CacheAdmissionError(f"unsupported Mypy option value: {type(value).__name__}")

    return {name: encode(getattr(options, name)) for name in sorted(names)}


def _manifest_payload(manifest: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in manifest.items() if key != "manifest_sha256"}


def _load_manifest(root: Path) -> tuple[dict[str, Any], str]:
    raw = _read_relative(root, "manifest.json", MAX_MANIFEST_BYTES)
    try:
        manifest = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        raise CacheAdmissionError("local cache manifest is malformed") from exc
    if not isinstance(manifest, dict) or manifest.get("schema") != MANIFEST_SCHEMA:
        raise CacheAdmissionError("local cache manifest schema is unsupported")
    # A valid digest does not make attacker-controlled nesting safe. Restrict
    # both depth and total values before any recursive canonical serialization.
    pending: list[tuple[object, int]] = [(manifest, 0)]
    values = 0
    while pending:
        value, depth = pending.pop()
        values += 1
        if depth > 32 or values > 100_000:
            raise CacheAdmissionError("local cache manifest exceeds structural limits")
        if isinstance(value, dict):
            pending.extend((key, depth + 1) for key in value)
            pending.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            pending.extend((item, depth + 1) for item in value)
    expected = manifest.get("manifest_sha256")
    actual = _digest(_canonical(_manifest_payload(manifest)))
    if expected != actual:
        raise CacheAdmissionError("local cache manifest digest is inconsistent")
    return manifest, actual


def prepare_cache_run(  # noqa: PLR0912, PLR0915
    policy: LocalTypedCachePolicy,
    *,
    project_root: Path,
    module_root: Path,
    project_sources: dict[str, str],
    source_hashes: dict[str, str],
    options: object,
    mypy_version: str,
    source_texts: dict[str, str],
) -> tuple[CacheRunPlan, dict[str, bytes]]:
    """Check and stage local cache bytes for one discarded diagnostic build."""
    if not policy.enabled or policy.trust_id != TRUST_ID:
        raise CacheAdmissionError("cache policy is disabled or has an unknown trust ID")
    if fcntl is None or not hasattr(os, "memfd_create"):
        raise CacheAdmissionError("sealed in-memory cache descriptors are unsupported")
    root = _private_root(policy.root, create=False)
    manifest, manifest_sha256 = _load_manifest(root)
    if policy.expected_manifest_sha256 != manifest_sha256:
        raise CacheAdmissionError("local cache manifest differs from the configured digest pin")
    if manifest.get("trust_id") != TRUST_ID or manifest.get("mypy_version") != mypy_version:
        raise CacheAdmissionError("local cache producer or Mypy version does not match")
    if manifest.get("project_root") != str(project_root.resolve()):
        raise CacheAdmissionError("local cache belongs to a different project root")
    if manifest.get("module_root") != str(module_root.resolve()):
        raise CacheAdmissionError("local cache belongs to a different module root")
    source_rows = manifest.get("project_sources")
    expected_paths = {str(Path(path).resolve()): module for module, path in project_sources.items()}
    if (
        len(expected_paths) != len(project_sources)
        or not isinstance(source_rows, dict)
        or source_rows != source_hashes
        or set(source_hashes) != set(project_sources)
        or manifest.get("project_source_paths") != expected_paths
    ):
        raise CacheAdmissionError("local cache project source inventory differs")
    graph = manifest.get("module_graph")
    artifacts = manifest.get("artifacts")
    if not isinstance(graph, dict) or not isinstance(artifacts, list):
        raise CacheAdmissionError("local cache graph or artifacts are malformed")
    external_source_records = manifest.get("external_sources")
    if not isinstance(external_source_records, dict) or not all(
        isinstance(module, str) and isinstance(row, dict)
        for module, row in external_source_records.items()
    ):
        raise CacheAdmissionError("local cache external source inventory is malformed")
    artifact_modules: list[str] = []
    for row in artifacts:
        if not isinstance(row, dict) or not isinstance(row.get("module"), str):
            raise CacheAdmissionError("local cache artifact identity is malformed")
        artifact_modules.append(row["module"])
    if len(artifact_modules) != len(set(artifact_modules)) or set(artifact_modules) != set(
        external_source_records
    ):
        raise CacheAdmissionError("cache artifacts do not match the external source inventory")
    actual_options = _options_record(options)
    semantic = {
        k: v
        for k, v in actual_options.items()
        if k not in {"incremental", "cache_dir", "cache_map"}
    }
    if manifest.get("semantic_options_sha256") != _digest(_canonical(semantic)):
        raise CacheAdmissionError("local cache semantic Mypy options differ")
    graph_digest = _digest(_canonical(graph))
    if graph_digest != manifest.get("module_graph_sha256"):
        raise CacheAdmissionError("local cache module graph digest is inconsistent")

    run_root: Path | None = None
    descriptors: list[int] = []
    try:
        run_root = Path(tempfile.mkdtemp(prefix="r13-run-", dir=root))
        run_root.chmod(0o700)
        input_root = run_root / "input"
        output_root = run_root / "output"
        input_root.mkdir(mode=0o700)
        output_root.mkdir(mode=0o700)
        cache_map: dict[str, tuple[str, str]] = {}
        admitted_modules: set[str] = set()
        artifact_hashes: dict[str, str] = {}
        cache_total = 0
        cache_count = 0
        current_external_sources: dict[str, bytes] = {}
        external_source_total = 0
        source_records = external_source_records
        for module, row in sorted(source_records.items()):
            if not isinstance(row, dict) or not isinstance(row.get("path"), str):
                raise CacheAdmissionError("local cache external source entry is malformed")
            path = Path(row["path"])
            remaining_source_bytes = MAX_SOURCE_BYTES - external_source_total
            data = _read_external(path, min(MAX_SOURCE_FILE_BYTES, remaining_source_bytes))
            external_source_total += len(data)
            if _digest(data) != row.get("sha256"):
                raise CacheAdmissionError(f"external source changed for {module}")
            current_external_sources[str(path.resolve())] = data
        external_module_texts = {
            module: next(
                (
                    data.decode("utf-8")
                    for path, data in current_external_sources.items()
                    if Path(row["path"]).resolve() == Path(path)
                ),
                "",
            )
            for module, row in source_records.items()
        }
        if not _known_event_registration_consumers(source_texts, external_module_texts):
            raise CacheAdmissionError(
                "external cache consumer is outside the event-registration closure"
            )
        for item in artifacts:
            if not isinstance(item, dict):
                raise CacheAdmissionError("local cache artifact record is malformed")
            module = item.get("module")
            source_path = item.get("source_path")
            meta_rel = item.get("meta")
            data_rel = item.get("data")
            if not all(
                isinstance(value, str) for value in (module, source_path, meta_rel, data_rel)
            ):
                raise CacheAdmissionError("local cache artifact identity is malformed")
            assert isinstance(module, str)
            assert isinstance(source_path, str)
            assert isinstance(meta_rel, str)
            assert isinstance(data_rel, str)
            source_row = source_records.get(module)
            if not isinstance(source_row, dict) or source_row.get("path") != source_path:
                raise CacheAdmissionError("cache artifact path differs from its source record")
            meta_bytes = _read_relative(root, meta_rel, MAX_CACHE_BYTES)
            data_bytes = _read_relative(root, data_rel, MAX_CACHE_BYTES)
            try:
                meta_record = json.loads(meta_bytes)
            except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
                raise CacheAdmissionError("cache artifact metadata is malformed") from exc
            if not isinstance(meta_record, dict) or type(meta_record.get("data_mtime")) is not int:
                raise CacheAdmissionError("cache artifact metadata has no valid data mtime")
            data_mtime = meta_record["data_mtime"]
            cache_count += 2
            cache_total += len(meta_bytes) + len(data_bytes)
            if cache_count > MAX_CACHE_FILES or cache_total > MAX_CACHE_BYTES:
                raise CacheAdmissionError("local cache exceeds the member or byte budget")
            if _digest(meta_bytes) != item.get("meta_sha256") or _digest(data_bytes) != item.get(
                "data_sha256"
            ):
                raise CacheAdmissionError(f"local cache artifact changed for {module}")
            meta_fd = os.memfd_create(f"mypy-{module}-meta", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            data_fd = os.memfd_create(f"mypy-{module}-data", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            descriptors.extend((meta_fd, data_fd))
            for descriptor, contents in ((meta_fd, meta_bytes), (data_fd, data_bytes)):
                with os.fdopen(os.dup(descriptor), "wb") as stream:
                    stream.write(contents)
            # Writing the bytes gives the memfd a new timestamp. Mypy validates
            # CacheMeta.data_mtime against stat(data_file), so preserve the
            # timestamp declared by the unchanged metadata after writing.
            os.utime(data_fd, (data_mtime, data_mtime))
            for descriptor in (meta_fd, data_fd):
                fcntl.fcntl(
                    descriptor,
                    fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_WRITE
                    | fcntl.F_SEAL_GROW
                    | fcntl.F_SEAL_SHRINK
                    | fcntl.F_SEAL_SEAL,
                )
            meta_fd_path = f"/proc/self/fd/{meta_fd}"
            data_fd_path = f"/proc/self/fd/{data_fd}"
            artifact_hashes[meta_fd_path] = _digest(meta_bytes)
            artifact_hashes[data_fd_path] = _digest(data_bytes)
            source_path_norm = os.path.normpath(source_path)
            cache_map[source_path_norm] = (meta_fd_path, data_fd_path)
            admitted_modules.add(module)
        expected_roots = frozenset(project_sources)
        for module, root_path in project_sources.items():
            key = os.path.normpath(root_path)
            meta_path = output_root / f"{module.replace('.', '/')}.meta.json"
            data_path = output_root / f"{module.replace('.', '/')}.data.json"
            cache_map[key] = (str(meta_path), str(data_path))
        (output_root / f"{sys.version_info.major}.{sys.version_info.minor}").mkdir(mode=0o700)
        plan = CacheRunPlan(
            run_root,
            cache_map,
            {str(key): value for key, value in graph.items()},
            expected_roots,
            frozenset(admitted_modules),
            manifest_sha256,
            TRUST_ID,
            tuple(descriptors),
            artifact_hashes,
        )
        return plan, current_external_sources

    except BaseException:
        # Cancellation and process-control exceptions still release resources.
        for descriptor in descriptors:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        if run_root is not None:
            shutil.rmtree(run_root, ignore_errors=True)
        raise


def _known_event_registration_consumers(  # noqa: PLR0911, PLR0912
    source_texts: dict[str, str], external_sources: dict[str, str]
) -> bool:
    """Filter a syntactic diagnostic fixture shape; never authorize cache results.

    The analyzer always discards the warm result. This scanner does not prove
    FastAPI identity or the complete typed-node consumer closure.
    """
    if not external_sources:
        return False
    cached_modules = set(external_sources)
    imported: dict[str, str] = {}
    trees: list[ast.Module] = []
    try:
        for text in source_texts.values():
            tree = ast.parse(text)
            trees.append(tree)
            for node in tree.body:
                if isinstance(node, ast.ImportFrom) and node.module in cached_modules:
                    for alias in node.names:
                        local_name = alias.asname or alias.name
                        if local_name in imported:
                            return False
                        imported[local_name] = node.module
                elif isinstance(node, ast.Import) and any(
                    alias.name.split(".")[0] in cached_modules for alias in node.names
                ):
                    return False
    except (SyntaxError, ValueError):
        return False
    if not imported:
        return False
    callbacks: dict[str, set[str]] = {}
    try:
        for module, text in external_sources.items():
            tree = ast.parse(text)
            callbacks[module] = {
                node.name
                for node in tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
    except (SyntaxError, ValueError):
        return False
    permitted: dict[str, str] = {}
    permitted_nodes: set[int] = set()
    for tree in trees:
        for node in tree.body:
            if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Call):
                continue
            call = node.value
            if (
                not isinstance(call.func, ast.Attribute)
                or call.func.attr != "add_event_handler"
                or not isinstance(call.func.value, ast.Name)
                or call.func.value.id != "app"
                or len(call.args) != 2
                or not isinstance(call.args[0], ast.Constant)
                or call.args[0].value not in {"startup", "shutdown"}
                or not isinstance(call.args[1], ast.Name)
                or call.args[1].id not in imported
                or call.keywords
            ):
                continue
            permitted[call.args[1].id] = imported[call.args[1].id]
            permitted_nodes.add(id(call.args[1]))
    found: set[str] = set()
    found_nodes: set[int] = set()
    for tree in trees:
        for walked_node in ast.walk(tree):
            if isinstance(walked_node, ast.Name) and walked_node.id in imported:
                found.add(walked_node.id)
                found_nodes.add(id(walked_node))
    return (
        bool(permitted)
        and found == set(permitted)
        and found_nodes == permitted_nodes
        and all(name in callbacks.get(module, set()) for name, module in permitted.items())
    )


def _read_external(path: Path, limit: int) -> bytes:
    """Read an absolute file while refusing symlinks in every path component."""
    try:
        absolute = path.absolute()
        if not absolute.is_absolute() or ".." in absolute.parts:
            raise CacheAdmissionError("external source path is not canonical")
        if os.open not in os.supports_dir_fd or not getattr(os, "O_NOFOLLOW", 0):
            raise CacheAdmissionError("no-follow directory-relative reads are unavailable")
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in absolute.parts[1:-1]:
                next_descriptor = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = next_descriptor
            leaf = os.open(
                absolute.parts[-1],
                os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
                dir_fd=descriptor,
            )
            try:
                opened = os.fstat(leaf)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_nlink != 1
                    or opened.st_size > limit
                ):
                    raise CacheAdmissionError(
                        "external source is not a bounded single-link regular file"
                    )
                chunks: list[bytes] = []
                remaining = limit + 1
                while remaining:
                    block = os.read(leaf, min(remaining, 1024 * 1024))
                    if not block:
                        break
                    chunks.append(block)
                    remaining -= len(block)
                data = b"".join(chunks)
                if len(data) > limit:
                    raise CacheAdmissionError("external source exceeds its byte limit")
                return data
            finally:
                os.close(leaf)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise CacheAdmissionError("external source cannot be snapshotted safely") from exc


def external_snapshots_unchanged(snapshots: dict[str, bytes]) -> bool:
    """Re-read bounded external sources without following links after the build."""
    try:
        return all(
            _digest(_read_external(Path(path), MAX_SOURCE_FILE_BYTES)) == _digest(contents)
            for path, contents in snapshots.items()
        )
    except CacheAdmissionError:
        return False


def write_seed_manifest(
    policy: LocalTypedCachePolicy,
    *,
    _cache_dir: Path,
    project_root: Path,
    module_root: Path,
    project_sources: dict[str, str],
    source_hashes: dict[str, str],
    options: object,
    mypy_version: str,
    graph: dict[str, str | None],
    cache_rows: list[dict[str, str]],
    external_sources: dict[str, dict[str, str]],
) -> str:
    """Write a self-consistent manifest for a private local diagnostic cache."""
    root = _private_root(policy.root, create=True)
    actual_options = _options_record(options)
    semantic = {
        k: v
        for k, v in actual_options.items()
        if k not in {"incremental", "cache_dir", "cache_map"}
    }
    payload: dict[str, object] = {
        "schema": MANIFEST_SCHEMA,
        "trust_id": TRUST_ID,
        "producer": "fastapi-endpoint-detector-local-mypy-cache-v1",
        "mypy_version": mypy_version,
        "project_root": str(project_root.resolve()),
        "module_root": str(module_root.resolve()),
        "project_sources": source_hashes,
        "project_source_paths": {
            str(Path(path).resolve()): module for module, path in project_sources.items()
        },
        "semantic_options_sha256": _digest(_canonical(semantic)),
        "module_graph": graph,
        "module_graph_sha256": _digest(_canonical(graph)),
        "external_sources": external_sources,
        "artifacts": cache_rows,
    }
    manifest = dict(payload)
    manifest["manifest_sha256"] = _digest(_canonical(payload))
    raw = _canonical(manifest)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise CacheAdmissionError("local cache manifest exceeds its byte budget")
    manifest_path = root / "manifest.json"
    temp_path = root / ".manifest.tmp"
    temp_path.write_bytes(raw)
    temp_path.chmod(0o400)
    temp_path.replace(manifest_path)
    manifest_path.chmod(0o400)
    return str(manifest["manifest_sha256"])


def private_cache_directory(root: Path) -> Path:
    """Create and return an owned 0700 cache subdirectory."""
    _private_root(root, create=True)
    directory = Path(tempfile.mkdtemp(prefix="build-", dir=root))
    directory.chmod(0o700)
    return directory


def seed_artifact_path(root: Path, relative: str) -> Path:
    """Resolve a generated cache artifact after enforcing contained syntax."""
    if Path(relative).is_absolute() or any(part in {"..", "."} for part in Path(relative).parts):
        raise CacheAdmissionError("generated cache path escapes its seed directory")
    path = root / relative
    if not path.resolve().is_relative_to(root.resolve()):
        raise CacheAdmissionError("generated cache path escapes its seed directory")
    return path


def copy_cache_snapshot(source: Path, destination: Path, relative: str) -> str:
    """Copy one generated Mypy artifact into the owner-private trusted store."""
    data = _read_external(source, MAX_CACHE_BYTES)
    target = seed_artifact_path(destination, relative)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    target.write_bytes(data)
    target.chmod(0o400)
    return _digest(data)


def remove_run(plan: CacheRunPlan | None) -> None:
    if plan is not None:
        for descriptor in plan.descriptors:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        shutil.rmtree(plan.run_root, ignore_errors=True)
