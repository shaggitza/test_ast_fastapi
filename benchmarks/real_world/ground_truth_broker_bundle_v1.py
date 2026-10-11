"""Versioned source bundle and descriptor-sealed runtime for the Python broker.

This module is an integration seam. It does not launch a broker or authorize a
campaign. Callers must hold :class:`FreezeLease` from prepare until escrow finalization.
The ZIP snapshot is write-sealed before child imports, so broker-owned Python
bytes come from a stable descriptor. The cooperative filesystem lease remains
race detection, not a same-UID security boundary. Deployment still requires a
trusted, attested interpreter/toolchain.
"""

from __future__ import annotations

import ast
import fcntl
import hashlib
import importlib.machinery
import json
import os
import re
import stat
import subprocess
import sys
import sysconfig
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Literal

PROTOCOL = "ground-truth-python-broker-bundle-v1"
RECEIPT_PROTOCOL = "ground-truth-python-broker-freeze-receipt-v1"
LAUNCH_PROFILE_PROTOCOL = "ground-truth-python-broker-launch-profile-v2"
RECEIPT_SCHEMA = "benchmarks/real_world/production_v2/broker-freeze-receipt-schema-v1.json"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_FILE = 32 * 1024 * 1024
_MANIFEST = "bundle-manifest-v1.json"
_EXTERNAL_ROOT = "__external__/site-packages"
_EXTERNAL_REGISTRY = {
    "pydantic": (
        "pydantic",
        "pydantic_core",
        "annotated_types",
        "typing_extensions",
        "typing_inspection",
    ),
}


def derive_source_closure(source_root: Path, entrypoint: str) -> tuple[str, ...]:  # noqa: PLR0912
    """Return the complete statically resolvable local Python import closure.

    Dynamic imports, star imports, and extension loading are rejected. Local
    modules are added transitively. The child runs isolated, so non-standard
    dependencies must be included in the bundle; standard-library imports come
    from the interpreter identified by the pinned toolchain digest.
    """
    entrypoint = _relative(entrypoint)
    pending = [entrypoint]
    seen: set[str] = set()
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        raw = _read_regular(source_root / name)
        try:
            tree = ast.parse(raw, filename=name)
        except (SyntaxError, ValueError) as exc:
            raise BundleError("source closure contains invalid Python") from exc
        package = name.rsplit("/", 1)[0].replace("/", ".") if "/" in name else ""
        ctypes_aliases = {
            alias.asname or alias.name
            for node in tree.body
            if isinstance(node, ast.Import)
            for alias in node.names
            if alias.name == "ctypes"
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                if any(alias.name == "*" for alias in node.names):
                    raise BundleError("star imports are not allowed in sealed source closure")
                base = node.module or ""
                if node.level:
                    parts = package.split(".") if package else []
                    if node.level > len(parts) + 1:
                        raise BundleError("relative import escapes source root")
                    base = ".".join(parts[: len(parts) - node.level + 1] + ([base] if base else []))
                modules = [base] if base else []
                modules.extend(f"{base}.{alias.name}" for alias in node.names if base)
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in {
                    "__import__",
                    "exec",
                    "eval",
                }:
                    raise BundleError(
                        "dynamic import or code loading prevents source closure proof"
                    )
                if (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr
                    in {"import_module", "find_spec", "load_module", "CDLL", "PyDLL"}
                    and not _trusted_process_libc_call(node, ctypes_aliases)

                ):
                    raise BundleError(
                        "dynamic import/native loading is outside the trusted "
                        "toolchain allowlist"
                    )
            else:
                continue
            if not isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            for module in modules:
                candidate = module.replace(".", "/") + ".py"
                package_init = module.replace(".", "/") + "/__init__.py"
                if (source_root / candidate).is_file() or (source_root / package_init).is_file():
                    pending.append(
                        candidate if (source_root / candidate).is_file() else package_init
                    )
    return tuple(sorted(seen))


def derive_external_imports(source_root: Path, closure: tuple[str, ...]) -> tuple[str, ...]:
    """List non-stdlib top-level imports not included in the source closure."""
    external: set[str] = set()
    for relative in closure:
        tree = ast.parse(_read_regular(source_root / relative), filename=relative)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules = [alias.name.split(".", 1)[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                modules = [node.module.split(".", 1)[0]]
            else:
                continue
            for module in modules:
                if module in sys.stdlib_module_names:
                    continue
                if (source_root / f"{module}.py").is_file() or (source_root / module).is_dir():
                    continue
                external.add(module)
    return tuple(sorted(external))


def _external_files(external_imports: tuple[str, ...]) -> dict[str, tuple[Path, bytes]]:
    """Capture a finite registered distribution closure from interpreter site roots."""
    package_names: set[str] = set()
    for name in external_imports:
        if name not in _EXTERNAL_REGISTRY:
            raise BundleError("external import has no committed toolchain registry")
        package_names.update(_EXTERNAL_REGISTRY[name])
    roots = {
        Path(sysconfig.get_paths()[key]).resolve(strict=True)
        for key in ("purelib", "platlib")
        if sysconfig.get_paths().get(key)
    }
    captured: dict[str, tuple[Path, bytes]] = {}
    for package in sorted(package_names):
        matches: list[tuple[Path, Path]] = []
        for site_root in sorted(roots):
            directory = site_root / package
            module = site_root / f"{package}.py"
            if directory.is_dir() and not directory.is_symlink():
                matches.append((site_root, directory))
            elif module.is_file() and not module.is_symlink():
                matches.append((site_root, module))
        if len(matches) != 1:
            raise BundleError("registered external distribution is missing or ambiguous")
        site_root, package_root = matches[0]
        files = [package_root] if package_root.is_file() else sorted(package_root.rglob("*"))
        for candidate in files:
            if candidate.is_dir() or "__pycache__" in candidate.parts:
                continue
            status = candidate.lstat()
            if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
                raise BundleError("registered external distribution contains a special file")
            relative = candidate.relative_to(site_root).as_posix()
            target = f"{_EXTERNAL_ROOT}/{relative}"
            captured[target] = (candidate, _read_regular(candidate))
    if len(captured) > 10000 or sum(len(raw) for _, raw in captured.values()) > 256 * 1024 * 1024:
        raise BundleError("registered external toolchain exceeds finite snapshot limits")
    return captured


def _runtime_identity() -> dict[str, Any]:
    executable = Path(sys.executable).resolve(strict=True)
    paths = sysconfig.get_paths()
    library_dir = sysconfig.get_config_var("LIBDIR")
    library_name = sysconfig.get_config_var("LDLIBRARY")
    runtime_libraries: dict[str, str] = {}
    if library_dir and library_name and library_name.endswith((".so", ".dylib", ".dll")):
        runtime_path = (Path(library_dir) / library_name).resolve(strict=True)
        runtime_libraries[str(runtime_path)] = _sha(_read_regular(runtime_path))
    try:
        maps = Path("/proc/self/maps").read_text(encoding="ascii")
    except OSError as exc:
        raise BundleError("runtime native-library map is unavailable") from exc
    for line in maps.splitlines():
        fields = line.split(maxsplit=5)
        mapped = fields[5].removesuffix(" (deleted)") if len(fields) == 6 else ""
        basename = Path(mapped).name
        if mapped.startswith("/") and ".so" in basename:
            runtime_path = Path(mapped).resolve(strict=True)
            runtime_libraries[str(runtime_path)] = _sha(_read_regular(runtime_path))
    return {
        "executable": str(executable),
        "executable_sha256": _sha(_read_regular(executable)),
        "version": sys.version,
        "implementation": sys.implementation.name,
        "cache_tag": sys.implementation.cache_tag,
        "soabi": sysconfig.get_config_var("SOABI"),
        "stdlib": str(Path(paths["stdlib"]).resolve(strict=True)),
        "platstdlib": str(Path(paths["platstdlib"]).resolve(strict=True)),
        "runtime_libraries": runtime_libraries,
    }


def _source_inventory(
    source_root: Path, files: dict[str, str], external_imports: tuple[str, ...]
) -> dict[str, Path]:
    external = _external_files(external_imports)
    sources: dict[str, Path] = {}
    for name in files:
        if name.startswith(_EXTERNAL_ROOT + "/"):
            item = external.get(name)
            if item is None:
                raise BundleError("sealed external file is outside the registered inventory")
            sources[name] = item[0]
        else:
            sources[name] = source_root / _relative(name)
    if {name for name in files if name.startswith(_EXTERNAL_ROOT + "/")} != set(external):
        raise BundleError("sealed external package closure is incomplete")
    return sources


def _toolchain_identity(external_imports: tuple[str, ...]) -> dict[str, Any]:
    external = {
        path: _sha(raw)
        for path, (_, raw) in sorted(_external_files(external_imports).items())
    }
    return {
        "protocol": "ground-truth-python-toolchain-identity-v2",
        "runtime": _runtime_identity(),
        "external": external,
        "registry": {
            name: list(_EXTERNAL_REGISTRY[name]) for name in sorted(set(external_imports))
        },
    }


def compute_toolchain_sha256(external_imports: tuple[str, ...]) -> str:
    """Bind interpreter ABI/runtime and every registered package byte."""
    return _sha(_canonical(_toolchain_identity(external_imports)))


def _trusted_process_libc_call(node: ast.Call, ctypes_aliases: set[str]) -> bool:
    """Allow only the audited ctypes handle for the current process libc."""
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "CDLL"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in ctypes_aliases
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value is None
        and len(node.keywords) == 1
        and node.keywords[0].arg == "use_errno"
        and isinstance(node.keywords[0].value, ast.Constant)
        and node.keywords[0].value.value is True
    )


class BundleError(RuntimeError):
    """Bundle input, receipt, or freeze invariant failed closed."""


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _json(raw: bytes) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise BundleError("duplicate JSON key")
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: _bad_json())
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        raise BundleError("invalid bundle JSON") from exc


def _bad_json() -> None:
    raise BundleError("non-finite JSON value")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _relative(value: str) -> str:
    path = PurePosixPath(value)
    if (not value or "\\" in value or "\x00" in value or path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts)
            or not value.endswith(".py")):
        raise BundleError("bundle path is not a safe Python source path")
    return value


def _read_regular(path: Path) -> bytes:
    current = Path(path.anchor)
    for part in path.parts[1:-1]:
        current /= part
        try:
            if stat.S_ISLNK(current.lstat().st_mode):
                raise BundleError("source has a symlink ancestor")
        except FileNotFoundError as exc:
            raise BundleError("source path is missing") from exc
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise BundleError("source cannot be opened without following symlinks") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise BundleError("source must be a regular file owned by the current uid")
        blocks: list[bytes] = []
        size = 0
        while size <= _MAX_FILE:
            block = os.read(fd, min(65536, _MAX_FILE + 1 - size))
            if not block:
                break
            blocks.append(block)
            size += len(block)
        if size > _MAX_FILE:
            raise BundleError("source exceeds byte limit")
        return b"".join(blocks)
    finally:
        os.close(fd)


def _write_new(path: Path, raw: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o400)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


@dataclass(frozen=True)
class Bundle:
    """Materialized bundle identity and its source paths for mutation checks."""

    root: Path
    digest: str
    profile_sha256: str
    toolchain_sha256: str
    files: dict[str, str]
    sources: dict[str, Path]

    def verify(self) -> None:
        verify_bundle(self)


def materialize_bundle(
    source_root: Path,
    destination: Path,
    source_files: tuple[str, ...],
    *,
    profile_sha256: str,
    toolchain_sha256: str,
    entrypoint: str | None = None,
    trusted_external_imports: tuple[str, ...] = (),
) -> Bundle:
    """Copy an explicit, finite transitive Python source closure into a new directory.

    ``source_files`` must enumerate every broker-owned Python module. External
    dependencies are represented by the separately pinned ``toolchain_sha256``.
    No wildcard discovery or source symlink is accepted.
    """
    if not source_root.is_absolute() or not destination.is_absolute():
        raise BundleError("source and destination roots must be absolute")
    if not _DIGEST.fullmatch(profile_sha256) or not _DIGEST.fullmatch(toolchain_sha256):
        raise BundleError("profile and toolchain identities must be SHA-256 digests")
    if not source_files or len(set(source_files)) != len(source_files):
        raise BundleError("source closure must be nonempty and unique")
    selected = sorted(_relative(item) for item in source_files)
    if entrypoint is not None:
        closure = derive_source_closure(source_root, entrypoint)
        if tuple(selected) != closure:
            raise BundleError("source files differ from statically derived import closure")
    external_imports = derive_external_imports(source_root, tuple(selected))
    if tuple(sorted(set(trusted_external_imports))) != external_imports:
        raise BundleError("external imports differ from committed toolchain allowlist")
    sources = {item: source_root / item for item in selected}
    captured = {item: _read_regular(path) for item, path in sources.items()}
    external_sources = _external_files(external_imports)
    toolchain_identity = _toolchain_identity(external_imports)
    if _sha(_canonical(toolchain_identity)) != toolchain_sha256:
        raise BundleError("runtime or registered toolchain changed during snapshot")
    for name, (path, raw) in external_sources.items():
        captured[name] = raw
        sources[name] = path
    if toolchain_identity["external"] != {
        name: _sha(captured[name]) for name in sorted(external_sources)
    }:
        raise BundleError("external package snapshot differs from toolchain identity")
    file_hashes = {item: _sha(raw) for item, raw in captured.items()}
    manifest = {
        "schema_version": 1,
        "protocol": PROTOCOL,
        "profile_sha256": profile_sha256,
        "toolchain_sha256": toolchain_sha256,
        "files": file_hashes,
        "entrypoint": entrypoint,
        "closure_sha256": _sha(_canonical(sorted(captured))),
        "external_imports": list(external_imports),
        "toolchain_identity": toolchain_identity,
    }
    raw_manifest = _canonical(manifest)
    try:
        destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    except OSError as exc:
        raise BundleError("bundle destination must be new") from exc
    try:
        for relative, raw in captured.items():
            _write_new(destination / relative, raw)
        _write_new(destination / _MANIFEST, raw_manifest)
        bundle = Bundle(destination, _sha(raw_manifest), profile_sha256, toolchain_sha256,
                        file_hashes, sources)
        verify_bundle(bundle)
        return bundle
    except Exception:
        # Leave a failed, non-reusable destination as evidence; never overwrite it.
        raise


def verify_bundle(bundle: Bundle) -> None:
    """Rehash source and materialized files; reject replacement, symlink, or drift."""
    try:
        root_info = bundle.root.stat(follow_symlinks=False)
    except OSError as exc:
        raise BundleError("bundle root is unavailable") from exc
    if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.getuid()
            or stat.S_IMODE(root_info.st_mode) != 0o700):
        raise BundleError("bundle root owner, type, or mode is invalid")
    manifest_path = bundle.root / _MANIFEST
    raw_manifest = _read_regular(manifest_path)
    if stat.S_IMODE(manifest_path.stat(follow_symlinks=False).st_mode) != 0o400:
        raise BundleError("bundle manifest mode is invalid")
    if _sha(raw_manifest) != bundle.digest:
        raise BundleError("bundle manifest changed")
    manifest = _json(raw_manifest)
    expected = {
        "schema_version": 1,
        "protocol": PROTOCOL,
        "profile_sha256": bundle.profile_sha256,
        "toolchain_sha256": bundle.toolchain_sha256,
        "files": bundle.files,
        "entrypoint": manifest.get("entrypoint"),
        "closure_sha256": _sha(_canonical(sorted(bundle.files))),
        "external_imports": manifest.get("external_imports"),
        "toolchain_identity": manifest.get("toolchain_identity"),
    }
    if manifest != expected or set(bundle.files) != set(bundle.sources):
        raise BundleError("bundle manifest identity mismatch")
    external_imports = manifest.get("external_imports")
    external_hashes = {
        name: bundle.files[name]
        for name in sorted(bundle.files)
        if name.startswith(_EXTERNAL_ROOT + "/")
    }
    if (
        not isinstance(external_imports, list)
        or any(not isinstance(item, str) for item in external_imports)
        or manifest.get("toolchain_identity")
        != _toolchain_identity(tuple(external_imports))
        or manifest["toolchain_identity"].get("external") != external_hashes
        or compute_toolchain_sha256(tuple(external_imports)) != bundle.toolchain_sha256
    ):
        raise BundleError("registered Python toolchain identity changed")
    for relative, expected_hash in bundle.files.items():
        source_raw = _read_regular(bundle.sources[relative])
        sealed_path = bundle.root / relative
        sealed_raw = _read_regular(sealed_path)
        if stat.S_IMODE(sealed_path.stat(follow_symlinks=False).st_mode) != 0o400:
            raise BundleError("sealed bundle file mode is invalid")
        if _sha(source_raw) != expected_hash or _sha(sealed_raw) != expected_hash:
            raise BundleError("source or sealed bundle file changed")


@dataclass(frozen=True)
class FreezeReceipt:
    """Strict binding tying runtime attestation, code, profile, and launch identity."""

    runtime_attestation_sha256: str
    bundle_sha256: str
    binding_sha256: str
    launch_profile_sha256: str
    toolchain_sha256: str
    runtime_attestation_path: str = ""
    bundle_manifest_path: str = ""
    binding_path: str = ""
    launch_profile_path: str = ""
    lease_path: str = ""

    @classmethod
    def parse(cls, value: object) -> FreezeReceipt:
        keys = {"schema_version", "protocol", "runtime_attestation_path",
                "runtime_attestation_sha256", "bundle_manifest_path", "bundle_sha256",
                "binding_path", "binding_sha256", "launch_profile_path",
                "launch_profile_protocol", "launch_profile_sha256", "toolchain_sha256",
                "lease_path",
                "hold_until"}
        if not isinstance(value, dict) or set(value) != keys:
            raise BundleError("freeze receipt keys are invalid")
        if value["schema_version"] != 1 or value["protocol"] != RECEIPT_PROTOCOL:
            raise BundleError("freeze receipt protocol is invalid")
        if value["hold_until"] != "escrow_finalized":
            raise BundleError("freeze receipt lifecycle must extend through escrow finalization")
        if value["launch_profile_protocol"] != LAUNCH_PROFILE_PROTOCOL:
            raise BundleError("historical launch profiles are audit-only")
        path_keys = ("runtime_attestation_path", "bundle_manifest_path", "binding_path",
                     "launch_profile_path", "lease_path")
        for key in path_keys:
            path = value[key]
            if (not isinstance(path, str) or not Path(path).is_absolute()
                    or os.path.normpath(path) != path):
                raise BundleError("freeze receipt paths must be normalized absolute paths")
        digests = [value[key] for key in keys - {
            "schema_version", "protocol", "runtime_attestation_path", "bundle_manifest_path",
            "binding_path", "launch_profile_path", "launch_profile_protocol", "lease_path",
            "hold_until"
        }]
        if any(not isinstance(item, str) or not _DIGEST.fullmatch(item) for item in digests):
            raise BundleError("freeze receipt digest is invalid")
        return cls(value["runtime_attestation_sha256"], value["bundle_sha256"],
                   value["binding_sha256"], value["launch_profile_sha256"],
                   value["toolchain_sha256"], value["runtime_attestation_path"],
                   value["bundle_manifest_path"], value["binding_path"],
                   value["launch_profile_path"], value["lease_path"])

    def assert_equal(self, *, runtime_attestation_sha256: str, bundle: Bundle,
                     binding_sha256: str, launch_profile_sha256: str,
                     toolchain_sha256: str) -> None:
        actual = (runtime_attestation_sha256, bundle.digest, binding_sha256,
                  launch_profile_sha256, toolchain_sha256)
        expected = (self.runtime_attestation_sha256, self.bundle_sha256, self.binding_sha256,
                    self.launch_profile_sha256, self.toolchain_sha256)
        if actual != expected:
            raise BundleError("runtime, bundle, binding, launch profile, or toolchain mismatch")
        if bundle.toolchain_sha256 != toolchain_sha256:
            raise BundleError("bundle toolchain differs from launch toolchain")


class FreezeLease:
    """Exclusive lock held across prepare, readiness, claim, and finalization checks.

    The open descriptor can be passed to a child process (``pass_fds``); the caller
    must keep this object open until escrow finalization. A lock pathname replacement
    is detected on each boundary check. This is cooperative locking, not protection
    against a hostile same-UID process or a privileged filesystem administrator.
    """

    def __init__(self, path: Path, bundle: Bundle, receipt: FreezeReceipt, *,
                 receipt_path: Path | None = None, receipt_sha256: str | None = None) -> None:
        if not path.is_absolute():
            raise BundleError("lease path must be absolute")
        self.path = path
        self.bundle = bundle
        self.receipt = receipt
        self.receipt_path = receipt_path
        self.receipt_sha256 = receipt_sha256
        self.fd = -1
        self._identity: tuple[int, int] | None = None

    def acquire(self, **identities: str) -> FreezeLease:
        self.receipt.assert_equal(bundle=self.bundle, **identities)
        self.bundle.verify()
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent = Path(self.path.anchor)
        for part in self.path.parent.parts[1:]:
            parent /= part
            if stat.S_ISLNK(parent.lstat().st_mode):
                raise BundleError("lease path has a symlink ancestor")
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        info = os.fstat(self.fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600):
            os.close(self.fd)
            self.fd = -1
            raise BundleError("lease file owner or type is invalid")
        self._identity = (info.st_dev, info.st_ino)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(self.fd)
            self.fd = -1
            raise BundleError("bundle/profile freeze lease is already held") from exc
        self.check(**identities)
        return self

    def check(self, **identities: str) -> None:
        if self.fd < 0 or self._identity is None:
            raise BundleError("freeze lease is not held")
        info = os.fstat(self.fd)
        try:
            current = self.path.stat(follow_symlinks=False)
        except OSError as exc:
            raise BundleError("freeze lease path disappeared") from exc
        if ((info.st_dev, info.st_ino) != self._identity
                or (current.st_dev, current.st_ino) != self._identity
            or not stat.S_ISREG(current.st_mode)
            or current.st_uid != os.getuid()
            or stat.S_IMODE(current.st_mode) != 0o600):
            raise BundleError("freeze lease identity changed")
        if self.receipt_path is not None and self.receipt_sha256 is not None:
            fresh, _ = _read_receipt_file(self.receipt_path, self.receipt_sha256)
            if FreezeReceipt.parse(fresh) != self.receipt:
                raise BundleError("freeze receipt changed during lease")
            for path, expected in (
                (self.receipt.runtime_attestation_path, self.receipt.runtime_attestation_sha256),
                (self.receipt.binding_path, self.receipt.binding_sha256),
                (self.receipt.launch_profile_path, self.receipt.launch_profile_sha256),
            ):
                if _sha(_read_regular(Path(path))) != expected:
                    raise BundleError("runtime, binding, or launch profile changed during freeze")
        self.receipt.assert_equal(bundle=self.bundle, **identities)
        self.bundle.verify()

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1
            self._identity = None

    @property
    def pass_fds(self) -> tuple[int, ...]:
        """Descriptor tuple that the broker launcher must pass to the child."""
        if self.fd < 0:
            raise BundleError("freeze lease is not held")
        return (self.fd,)

    def __enter__(self) -> FreezeLease:
        if self.fd < 0:
            raise BundleError("acquire lease before entering its context")
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


@dataclass
class LaunchLeaseHandle:
    """Broker-owned persistent lease; close is forbidden before finalization.

    The prepare process must pass ``lease.pass_fds`` to the broker and close its
    copy only after successful broker startup. The broker must keep its inherited
    descriptor open through the explicit claim and escrow-finalized transitions.
    """

    lease: FreezeLease
    phase: Literal["prepared", "ready", "claimed", "escrow_finalized"] = "prepared"

    def pass_fds(self) -> tuple[int, ...]:
        return self.lease.pass_fds

    def mark_ready(self, **identities: str) -> None:
        if self.phase != "prepared":
            raise BundleError("readiness transition is out of order")
        self.lease.check(**identities)
        self.phase = "ready"

    def mark_claimed(self, **identities: str) -> None:
        if self.phase != "ready":
            raise BundleError("launch claim transition is out of order")
        self.lease.check(**identities)
        self.phase = "claimed"

    def mark_escrow_finalized(self, **identities: str) -> None:
        if self.phase != "claimed":
            raise BundleError("escrow finalization transition is out of order")
        self.lease.check(**identities)
        self.phase = "escrow_finalized"
        self.lease.close()

    def close(self) -> None:
        if self.phase != "escrow_finalized":
            raise BundleError("freeze lease must remain held until escrow finalization")
        self.lease.close()


def _read_receipt_file(path: Path, expected_sha256: str) -> tuple[dict[str, Any], bytes]:
    raw = _read_regular(path)
    info = path.stat(follow_symlinks=False)
    if stat.S_IMODE(info.st_mode) != 0o400 or _sha(raw) != expected_sha256:
        raise BundleError("freeze receipt file mode or digest is invalid")
    value = _json(raw)
    if not isinstance(value, dict):
        raise BundleError("freeze receipt root must be an object")
    return value, raw


def acquire_launch_lease(
    *,
    receipt_path: Path,
    receipt_sha256: str,
    bundle_root: Path,
    source_root: Path,
    expected_bundle_sha256: str,
    runtime_attestation_path: Path,
    runtime_attestation_sha256: str,
    binding_path: Path,
    binding_sha256: str,
    launch_profile_path: Path,
    launch_profile_sha256: str,
    toolchain_sha256: str,
    require_exclusive_freeze: bool,
    hold_until: Literal["escrow_finalized"],
) -> LaunchLeaseHandle:
    """Validate receipt by bytes/path, then acquire an exclusive persistent launch lease.

    Cross-file contract: the strict receipt hashes the exact raw runtime attestation,
    binding, launch-profile bytes and bundle manifest. The caller's corresponding
    bytes are reopened from explicitly supplied normalized paths and independently
    hashed before acquisition. The launch profile must identify the new versioned
    profile bytes; historical v7 profile compatibility is audit-only and cannot be
    used by this API as a launch profile.
    """
    if require_exclusive_freeze is not True or hold_until != "escrow_finalized":
        raise BundleError("launch requires exclusive freeze through escrow finalization")
    if not _DIGEST.fullmatch(receipt_sha256):
        raise BundleError("freeze receipt file digest is invalid")
    value, _ = _read_receipt_file(receipt_path, receipt_sha256)
    receipt = FreezeReceipt.parse(value)
    if (Path(receipt.bundle_manifest_path) != bundle_root / _MANIFEST
            or Path(receipt.runtime_attestation_path) != runtime_attestation_path
            or Path(receipt.binding_path) != binding_path
            or Path(receipt.launch_profile_path) != launch_profile_path
            or receipt.bundle_sha256 != expected_bundle_sha256):
        raise BundleError("explicit artifact paths or bundle digest differ from freeze receipt")
    if receipt.lease_path == receipt_path.as_posix():
        raise BundleError("receipt and lease paths must differ")
    raw_manifest = _read_regular(bundle_root / _MANIFEST)
    if _sha(raw_manifest) != expected_bundle_sha256:
        raise BundleError("bundle manifest digest differs from expected bundle identity")
    manifest = _json(raw_manifest)
    if (not isinstance(manifest, dict)
                or set(manifest) != {"schema_version", "protocol", "profile_sha256",
                                     "toolchain_sha256", "files", "entrypoint", "closure_sha256",
                                     "external_imports", "toolchain_identity"}
            or manifest.get("schema_version") != 1
            or manifest.get("protocol") != PROTOCOL
            or not isinstance(manifest.get("files"), dict)
            or not isinstance(manifest.get("toolchain_identity"), dict)):
        raise BundleError("bundle manifest schema is invalid")
    file_hashes = manifest["files"]
    if (not file_hashes or any(not isinstance(name, str) or not isinstance(file_hash, str)
                               or not _DIGEST.fullmatch(file_hash)
                               for name, file_hash in file_hashes.items())):
        raise BundleError("bundle manifest file inventory is invalid")
    sources = _source_inventory(source_root, file_hashes, tuple(manifest["external_imports"]))
    bundle = Bundle(bundle_root, expected_bundle_sha256, manifest["profile_sha256"],
                    manifest["toolchain_sha256"], file_hashes, sources)
    for path, expected in (
        (runtime_attestation_path, runtime_attestation_sha256),
        (Path(receipt.bundle_manifest_path), receipt.bundle_sha256),
        (binding_path, binding_sha256),
        (launch_profile_path, launch_profile_sha256),
    ):
        if not _DIGEST.fullmatch(expected) or _sha(_read_regular(path)) != expected:
            raise BundleError("receipt cross-file identity check failed")
    profile_value = _json(_read_regular(launch_profile_path))
    if (not isinstance(profile_value, dict)
            or set(profile_value) != {"schema_version", "protocol", "production_profile_sha256",
                                     "toolchain_sha256", "entrypoint", "external_imports"}
            or profile_value.get("schema_version") != 2
            or profile_value.get("protocol") != LAUNCH_PROFILE_PROTOCOL
            or profile_value.get("toolchain_sha256") != toolchain_sha256
            or profile_value.get("production_profile_sha256") != bundle.profile_sha256
            or profile_value.get("entrypoint") not in bundle.files
            or manifest.get("entrypoint") != profile_value.get("entrypoint")
            or manifest.get("closure_sha256") != _sha(_canonical(sorted(bundle.files)))
            or manifest.get("toolchain_identity")
            != _toolchain_identity(tuple(manifest.get("external_imports", [])))
            or manifest.get("external_imports") != profile_value.get("external_imports")):
        raise BundleError("launch profile is not the exact new versioned bundle profile")
    if receipt.runtime_attestation_sha256 != runtime_attestation_sha256:
        raise BundleError("runtime attestation differs from receipt")
    receipt.assert_equal(
        runtime_attestation_sha256=runtime_attestation_sha256,
        bundle=bundle,
        binding_sha256=binding_sha256,
        launch_profile_sha256=launch_profile_sha256,
        toolchain_sha256=toolchain_sha256,
    )
    lease = FreezeLease(Path(receipt.lease_path), bundle, receipt,
                        receipt_path=receipt_path, receipt_sha256=receipt_sha256).acquire(
        runtime_attestation_sha256=runtime_attestation_sha256,
        binding_sha256=binding_sha256,
        launch_profile_sha256=launch_profile_sha256,
        toolchain_sha256=toolchain_sha256,
    )
    return LaunchLeaseHandle(lease)


def _sealed_bundle_fd(bundle: Bundle) -> int:
    """Build an immutable, descriptor-backed ZIP snapshot for the child import path."""
    if not hasattr(os, "memfd_create"):
        raise BundleError("sealed memfd runtime boundary is unavailable")
    bundle.verify()
    manifest = _json(_read_regular(bundle.root / _MANIFEST))
    entrypoint = manifest.get("entrypoint")
    if not isinstance(entrypoint, str) or entrypoint not in bundle.files:
        raise BundleError("bundle has no committed sealed entrypoint")
    fd = os.memfd_create("ground-truth-broker-bundle", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        with os.fdopen(os.dup(fd), "w+b") as stream, zipfile.ZipFile(
            stream, "w", zipfile.ZIP_DEFLATED
        ) as archive:
            for name in sorted(bundle.files):
                raw = _read_regular(bundle.root / name)
                if _sha(raw) != bundle.files[name]:
                    raise BundleError("bundle changed before sealed snapshot creation")
                archive.writestr(name, raw)
        os.fsync(fd)
        seals = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
        if fcntl.fcntl(fd, fcntl.F_GET_SEALS) & seals != seals:
            raise BundleError("sealed runtime snapshot did not acquire all write seals")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _native_module_name(relative: str) -> str:
    prefix = _EXTERNAL_ROOT + "/"
    if not relative.startswith(prefix) or not relative.endswith(
        tuple(importlib.machinery.EXTENSION_SUFFIXES)
    ):
        raise BundleError("native extension path is not registered")
    package_path = Path(relative[len(prefix):])
    module = package_path.name.split(".", 1)[0]
    if not module.isidentifier():
        raise BundleError("native extension module name is invalid")
    return ".".join((*package_path.parent.parts, module))


def _sealed_native_fds(bundle: Bundle) -> tuple[dict[str, dict[str, Any]], tuple[int, ...]]:
    native: dict[str, dict[str, Any]] = {}
    descriptors: list[int] = []
    for relative, expected in sorted(bundle.files.items()):
        if not relative.endswith(tuple(importlib.machinery.EXTENSION_SUFFIXES)):
            continue
        module = _native_module_name(relative)
        if module in native:
            raise BundleError("native extension module is ambiguous")
        raw = _read_regular(bundle.root / relative)
        if _sha(raw) != expected:
            raise BundleError("native extension changed before snapshot")
        fd = os.memfd_create("ground-truth-native-extension", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            view = memoryview(raw)
            while view:
                view = view[os.write(fd, view):]
            seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
            if fcntl.fcntl(fd, fcntl.F_GET_SEALS) & seals != seals:
                raise BundleError("native extension snapshot could not be sealed")
        except BaseException:
            os.close(fd)
            raise
        native[module] = {"fd": fd, "sha256": expected, "seals": seals}
        descriptors.append(fd)
    return native, tuple(descriptors)


def launch_with_escrow_lease(
    *,
    lease: LaunchLeaseHandle,
    bundle: Bundle,
    argv: tuple[str, ...] = (),
    env: dict[str, str] | None = None,
) -> subprocess.Popen[bytes]:
    """Run only sealed source/package/native bytes while holding inherited lease."""
    if lease.phase != "prepared":
        raise BundleError("launch requires a prepared, held escrow lease")
    lease.lease.check(
        runtime_attestation_sha256=lease.lease.receipt.runtime_attestation_sha256,
        binding_sha256=lease.lease.receipt.binding_sha256,
        launch_profile_sha256=lease.lease.receipt.launch_profile_sha256,
        toolchain_sha256=lease.lease.receipt.toolchain_sha256,
    )
    sealed_fd = _sealed_bundle_fd(bundle)
    native, native_fds = _sealed_native_fds(bundle)
    manifest = _json(_read_regular(bundle.root / _MANIFEST))
    entrypoint = manifest["entrypoint"]
    module = entrypoint[:-3].replace("/", ".")
    runtime_identity = manifest["toolchain_identity"]["runtime"]
    bootstrap = f'''import fcntl
import hashlib
import importlib.abc
import importlib.machinery
import importlib.util
import json
import os
import pathlib
import runpy
import sys
import sysconfig
bundle_fd=int(os.environ.pop("GT_BUNDLE_FD"))
native=json.loads(os.environ.pop("GT_NATIVE_EXTENSIONS"))
runtime=json.loads(os.environ.pop("GT_RUNTIME_IDENTITY"))
exe=pathlib.Path(sys.executable).resolve(strict=True)
raw=exe.read_bytes()
if (str(exe)!=runtime["executable"]
 or "sha256:"+hashlib.sha256(raw).hexdigest()!=runtime["executable_sha256"]):
 raise RuntimeError("interpreter executable differs from sealed toolchain identity")
if (sys.version!=runtime["version"] or sys.implementation.name!=runtime["implementation"]
 or sys.implementation.cache_tag!=runtime["cache_tag"]
 or sysconfig.get_config_var("SOABI")!=runtime["soabi"]):
 raise RuntimeError("interpreter ABI differs from sealed toolchain identity")
stdlib=pathlib.Path(sysconfig.get_paths()["stdlib"]).resolve(strict=True)
if stdlib.as_posix()!=pathlib.Path(runtime["stdlib"]).as_posix():
 raise RuntimeError("standard library root differs from sealed toolchain identity")
registered=runtime["runtime_libraries"]
for line in pathlib.Path("/proc/self/maps").read_text(encoding="ascii").splitlines():
 fields=line.split(maxsplit=5)
 path=fields[5].removesuffix(" (deleted)") if len(fields)==6 else ""
 if path.startswith("/") and ".so" in pathlib.Path(path).name:
  resolved=str(pathlib.Path(path).resolve(strict=True))
  if resolved not in registered:
   raise RuntimeError("unregistered native runtime library is loaded")
  data=pathlib.Path(resolved).read_bytes()
  if "sha256:"+hashlib.sha256(data).hexdigest()!=registered[resolved]:
   raise RuntimeError("native runtime library differs from sealed toolchain identity")
required=fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL
for name,item in native.items():
 fd=item["fd"]
 if fcntl.fcntl(fd,fcntl.F_GET_SEALS)&required != required:
  raise RuntimeError("native descriptor is not sealed")
 data=b""; offset=0
 while True:
  block=os.pread(fd,1048576,offset)
  if not block: break
  data+=block; offset+=len(block)
 if "sha256:"+hashlib.sha256(data).hexdigest()!=item["sha256"]:
  raise RuntimeError("native descriptor hash mismatch")
class ExactSealedNativeFinder(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path=None,target=None):
  item=native.get(fullname)
  if item is None: return None
  loader=importlib.machinery.ExtensionFileLoader(fullname,"/proc/self/fd/"+str(item["fd"]))
  return importlib.util.spec_from_loader(fullname,loader)
sys.meta_path.insert(0,ExactSealedNativeFinder())
sys.path[:]=[p for p in sys.path if "site-packages" not in p and "dist-packages" not in p]
sys.path.insert(0,"/proc/self/fd/"+str(bundle_fd)+"/{_EXTERNAL_ROOT}")
sys.path.insert(0,"/proc/self/fd/"+str(bundle_fd))
runpy.run_module({module!r},run_name="__main__")'''
    child_env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    child_env["GT_BUNDLE_FD"] = str(sealed_fd)
    child_env["GT_BROKER_FREEZE_FD"] = str(lease.lease.fd)
    child_env["GT_NATIVE_EXTENSIONS"] = json.dumps(native, sort_keys=True)
    child_env["GT_RUNTIME_IDENTITY"] = json.dumps(runtime_identity, sort_keys=True)
    if env:
        if {"GT_BUNDLE_FD", "GT_BROKER_FREEZE_FD", "GT_NATIVE_EXTENSIONS",
            "GT_RUNTIME_IDENTITY"} & set(env):
            os.close(sealed_fd)
            for fd in native_fds:
                os.close(fd)
            raise BundleError("caller cannot override sealed runtime descriptors")
        child_env.update(env)
    try:
        process = subprocess.Popen(
            [sys.executable, "-I", "-c", bootstrap, *argv],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            pass_fds=(sealed_fd, *native_fds, *lease.pass_fds()),
            env=child_env,
            start_new_session=True,
        )
    finally:
        os.close(sealed_fd)
        for fd in native_fds:
            os.close(fd)
    return process

def adopt_inherited_launch_lease(
    *,
    freeze_fd: int,
    bundle_root: Path,
    source_root: Path,
    receipt_path: Path,
    receipt_sha256: str,
) -> LaunchLeaseHandle:
    """Adopt the broker-inherited lease descriptor without reacquiring its flock."""
    value, _ = _read_receipt_file(receipt_path, receipt_sha256)
    receipt = FreezeReceipt.parse(value)
    manifest_path = bundle_root / _MANIFEST
    manifest_raw = _read_regular(manifest_path)
    manifest = _json(manifest_raw)
    if not isinstance(manifest, dict) or _sha(manifest_raw) != receipt.bundle_sha256:
        raise BundleError("inherited lease bundle identity is invalid")
    files = manifest.get("files")
    if not isinstance(files, dict) or not all(
        isinstance(path, str) and isinstance(digest, str) and _DIGEST.fullmatch(digest)
        for path, digest in files.items()
    ):
        raise BundleError("inherited lease source inventory is invalid")
    bundle = Bundle(
        bundle_root,
        receipt.bundle_sha256,
        manifest["profile_sha256"],
        manifest["toolchain_sha256"],
        files,
        _source_inventory(source_root, files, tuple(manifest["external_imports"])),
    )
    lease = FreezeLease.__new__(FreezeLease)
    lease.path = Path(receipt.lease_path)
    lease.bundle = bundle
    lease.receipt = receipt
    lease.receipt_path = receipt_path
    lease.receipt_sha256 = receipt_sha256
    lease.fd = freeze_fd
    status = os.fstat(freeze_fd)
    lease._identity = (status.st_dev, status.st_ino)
    handle = LaunchLeaseHandle(lease)
    lease.check(
        runtime_attestation_sha256=receipt.runtime_attestation_sha256,
        binding_sha256=receipt.binding_sha256,
        launch_profile_sha256=receipt.launch_profile_sha256,
        toolchain_sha256=receipt.toolchain_sha256,
    )
    return handle
