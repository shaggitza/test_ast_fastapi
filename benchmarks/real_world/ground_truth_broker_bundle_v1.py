"""Versioned immutable-source bundle and freeze lease for the Python review broker.

This module is an integration seam. It does not launch a broker or authorize a
campaign. Callers must hold :class:`FreezeLease` from prepare until escrow finalization.
The filesystem checks detect accidental and concurrent mutation; they are not a
same-UID security boundary. Deployment still requires a trusted, attested runtime.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
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
    sources = {item: source_root / item for item in selected}
    captured = {item: _read_regular(path) for item, path in sources.items()}
    file_hashes = {item: _sha(raw) for item, raw in captured.items()}
    manifest = {
        "schema_version": 1,
        "protocol": PROTOCOL,
        "profile_sha256": profile_sha256,
        "toolchain_sha256": toolchain_sha256,
        "files": file_hashes,
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
    }
    if manifest != expected or set(bundle.files) != set(bundle.sources):
        raise BundleError("bundle manifest identity mismatch")
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
                                 "toolchain_sha256", "files"}
            or manifest.get("schema_version") != 1
            or manifest.get("protocol") != PROTOCOL
            or not isinstance(manifest.get("files"), dict)):
        raise BundleError("bundle manifest schema is invalid")
    file_hashes = manifest["files"]
    if (not file_hashes or any(not isinstance(name, str) or not isinstance(file_hash, str)
                               or not _DIGEST.fullmatch(file_hash)
                               for name, file_hash in file_hashes.items())):
        raise BundleError("bundle manifest file inventory is invalid")
    sources = {name: source_root / _relative(name) for name in file_hashes}
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
                                     "toolchain_sha256", "entrypoint"}
            or profile_value.get("schema_version") != 2
            or profile_value.get("protocol") != LAUNCH_PROFILE_PROTOCOL
            or profile_value.get("toolchain_sha256") != toolchain_sha256
            or profile_value.get("production_profile_sha256") != bundle.profile_sha256
            or profile_value.get("entrypoint") not in bundle.files):
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
