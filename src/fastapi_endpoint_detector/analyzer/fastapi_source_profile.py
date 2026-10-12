"""Verify the narrowly pinned FastAPI source profile without importing upstream code.

This module only reads a wheel as a bounded ZIP archive and hashes source bytes.
It does not install, import, or execute FastAPI.
"""

from __future__ import annotations

import hashlib
import io
import json
import stat
import zipfile
from dataclasses import dataclass
from email import policy
from email.parser import Parser
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from collections.abc import Mapping
    from os import PathLike

PROFILE_VERSION = "0.139.0"
WHEEL_FILENAME = "fastapi-0.139.0-py3-none-any.whl"
WHEEL_SHA256 = "cf15e1e9e667ddb0ad63811e60bd11390d1aac838ca4a7a23f421807b2308189"
WHEEL_SIZE = 130339
MANIFEST_SHA256 = "96808436ce00a7c25085a079342c480a9b1b48f94bb04fb65c67ffab7111ac92"
MAX_ARCHIVE_MEMBERS = 80
MAX_MEMBER_UNCOMPRESSED = 300_000
MAX_TOTAL_UNCOMPRESSED = 1_000_000
MAX_COMPRESSION_RATIO = 1_000
MAX_MANIFEST_SIZE = 16_384


class FastAPISourceProfileError(ValueError):
    """The supplied wheel cannot satisfy this trusted source profile."""


@dataclass(frozen=True)
class VerifiedFastAPISourceProfile:
    """Authenticated source bytes and their explicit logical wheel paths."""

    version: str
    wheel_sha256: str
    manifest_sha256: str
    profile_fingerprint: str
    source_root: str
    source_files: Mapping[str, bytes]
    source_hashes: Mapping[str, str]

    def __post_init__(self) -> None:
        """Reject profiles that do not carry the pinned, complete source set."""
        manifest, manifest_hash = _read_trusted_manifest()
        if (
            self.version != PROFILE_VERSION
            or self.wheel_sha256 != WHEEL_SHA256
            or self.manifest_sha256 != MANIFEST_SHA256
            or manifest_hash != self.manifest_sha256
            or self.profile_fingerprint != _profile_fingerprint(self.wheel_sha256, manifest_hash)
            or not isinstance(self.source_root, str)
        ):
            raise FastAPISourceProfileError(
                "profile identity does not match the pinned source profile"
            )
        expected_hashes = {
            path: record["sha256"] for path, record in manifest["source_files"].items()
        }
        try:
            files = dict(self.source_files)
            hashes = dict(self.source_hashes)
        except (TypeError, ValueError) as exc:
            raise FastAPISourceProfileError("profile source mappings are invalid") from exc
        if set(files) != set(expected_hashes) or hashes != expected_hashes:
            raise FastAPISourceProfileError(
                "profile source mappings do not match the trusted manifest"
            )
        for member, expected_hash in expected_hashes.items():
            content = files[member]
            if (
                not isinstance(content, bytes)
                or hashlib.sha256(content).hexdigest() != expected_hash
            ):
                raise FastAPISourceProfileError(f"profile source bytes are invalid: {member}")
        object.__setattr__(self, "source_files", MappingProxyType(files))
        object.__setattr__(self, "source_hashes", MappingProxyType(hashes))

    def match_source_snapshot(self, member_path: str, snapshot_bytes: bytes) -> bool:
        """Match retained analyzer bytes to one exact verified wheel member.

        Callers must first map their analyzer node path to the logical wheel member
        using their independently retained environment/source-root information.
        This method deliberately does not infer a match from a basename.
        """
        expected = self.source_files.get(member_path)
        return (
            expected is not None
            and isinstance(snapshot_bytes, bytes)
            and expected == snapshot_bytes
        )


def _reject_constant(value: str) -> None:
    raise FastAPISourceProfileError(f"non-finite JSON constant is not allowed: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FastAPISourceProfileError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _parse_manifest(raw: bytes) -> dict[str, Any]:
    try:
        manifest = cast(
            "dict[str, Any]",
            json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FastAPISourceProfileError("source manifest is malformed") from exc
    _validate_manifest(manifest)
    return manifest


def _read_trusted_manifest() -> tuple[dict[str, Any], str]:
    manifest_path = Path(__file__).with_name("data") / "fastapi_source_profiles" / "0.139.0.json"
    try:
        with manifest_path.open("rb") as stream:
            raw = stream.read(MAX_MANIFEST_SIZE + 1)
    except OSError as exc:
        raise FastAPISourceProfileError("cannot read trusted FastAPI source manifest") from exc
    if len(raw) > MAX_MANIFEST_SIZE:
        raise FastAPISourceProfileError("trusted FastAPI source manifest exceeds size limit")
    digest = hashlib.sha256(raw).hexdigest()
    if digest != MANIFEST_SHA256:
        raise FastAPISourceProfileError("trusted FastAPI source manifest identity mismatch")
    manifest = _parse_manifest(raw)
    return manifest, digest


def _validate_manifest(manifest: Any) -> None:
    expected_keys = {
        "schema_version",
        "profile_id",
        "distribution",
        "version",
        "wheel_filename",
        "wheel_url",
        "wheel_size",
        "wheel_sha256",
        "source_files",
    }
    if not isinstance(manifest, dict) or set(manifest) != expected_keys:
        raise FastAPISourceProfileError("manifest schema has missing or extra fields")
    if (
        manifest["schema_version"] != 1
        or manifest["profile_id"] != "fastapi-auth-prerequisite"
        or manifest["distribution"] != "fastapi"
        or manifest["version"] != PROFILE_VERSION
        or manifest["wheel_filename"] != WHEEL_FILENAME
        or manifest["wheel_size"] != WHEEL_SIZE
        or manifest["wheel_sha256"] != WHEEL_SHA256
        or manifest["wheel_url"]
        != "https://files.pythonhosted.org/packages/9e/7c/8e3c6ad324ea5cb36604fc3f968554887891c316d9dfde57761611d907ad/fastapi-0.139.0-py3-none-any.whl"
    ):
        raise FastAPISourceProfileError("manifest does not identify the pinned FastAPI wheel")
    files = manifest["source_files"]
    if not isinstance(files, dict) or set(files) != _EXPECTED_ROLES.keys():
        raise FastAPISourceProfileError("manifest source paths are missing or extra")
    for path, role in _EXPECTED_ROLES.items():
        record = files[path]
        if (
            not isinstance(record, dict)
            or set(record) != {"sha256", "role"}
            or record["role"] != role
            or not isinstance(record["sha256"], str)
            or len(record["sha256"]) != 64
            or any(char not in "0123456789abcdef" for char in record["sha256"])
        ):
            raise FastAPISourceProfileError(f"invalid manifest record for {path}")


def _verify_source_payload(member: str, content: bytes, expected_hash: str) -> str:
    actual = hashlib.sha256(content).hexdigest()
    if actual != expected_hash:
        raise FastAPISourceProfileError(f"source hash mismatch: {member}")
    return actual


_EXPECTED_ROLES = {
    "fastapi/__init__.py": "package_public_surface",
    "fastapi/params.py": "dependency_marker_records",
    "fastapi/param_functions.py": "dependency_marker_wrappers",
    "fastapi/dependencies/utils.py": "dependency_graph_construction_and_solver",
    "fastapi/dependencies/models.py": "dependency_graph_record_model",
    "fastapi/routing.py": "request_routing_solver_entrypoint",
}


def _validate_zip_infos(infos: list[zipfile.ZipInfo]) -> dict[str, zipfile.ZipInfo]:
    if len(infos) > MAX_ARCHIVE_MEMBERS:
        raise FastAPISourceProfileError("wheel contains too many ZIP members")
    by_name: dict[str, zipfile.ZipInfo] = {}
    total_size = 0
    for info in infos:
        name = info.filename
        path = PurePosixPath(name)
        if (
            not name
            or "\\" in name
            or name.startswith("/")
            or "\x00" in name
            or any(part in {"", ".", ".."} for part in name.rstrip("/").split("/"))
            or path.is_absolute()
        ):
            raise FastAPISourceProfileError(f"unsafe ZIP member path: {name!r}")
        if name in by_name:
            raise FastAPISourceProfileError(f"duplicate ZIP member: {name}")
        mode = (info.external_attr >> 16) & 0xFFFF
        if stat.S_ISLNK(mode):
            raise FastAPISourceProfileError(f"symlink ZIP member is not allowed: {name}")
        if info.flag_bits & 0x1:
            raise FastAPISourceProfileError(f"encrypted ZIP member is not allowed: {name}")
        if info.file_size > MAX_MEMBER_UNCOMPRESSED:
            raise FastAPISourceProfileError(f"ZIP member exceeds size limit: {name}")
        if info.compress_size == 0 and info.file_size:
            raise FastAPISourceProfileError(f"invalid compressed size for ZIP member: {name}")
        if info.compress_size and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
            raise FastAPISourceProfileError(f"ZIP member compression ratio exceeds limit: {name}")
        total_size += info.file_size
        if total_size > MAX_TOTAL_UNCOMPRESSED:
            raise FastAPISourceProfileError("wheel exceeds total uncompressed size limit")
        by_name[name] = info
    return by_name


def _profile_fingerprint(wheel_hash: str, manifest_hash: str) -> str:
    return hashlib.sha256(
        f"fastapi-source-profile-v1:{PROFILE_VERSION}:{wheel_hash}:{manifest_hash}".encode()
    ).hexdigest()


def verify_fastapi_wheel(wheel_path: str | PathLike[str]) -> VerifiedFastAPISourceProfile:
    """Verify the pinned official wheel and return its attested source file mapping.

    The wheel must be exactly FastAPI 0.139.0 from the trusted profile. No
    caller-supplied manifest, version, or source hash can expand that authority.
    """
    path = Path(wheel_path)
    if path.name != WHEEL_FILENAME:
        raise FastAPISourceProfileError("wheel filename is not the pinned FastAPI wheel")
    try:
        with path.open("rb") as stream:
            wheel_bytes = stream.read(WHEEL_SIZE + 1)
    except OSError as exc:
        raise FastAPISourceProfileError("cannot read FastAPI wheel") from exc
    if len(wheel_bytes) != WHEEL_SIZE:
        raise FastAPISourceProfileError("wheel size does not match the pinned artifact")
    wheel_hash = hashlib.sha256(wheel_bytes).hexdigest()
    if wheel_hash != WHEEL_SHA256:
        raise FastAPISourceProfileError("wheel SHA-256 does not match the pinned artifact")

    manifest, manifest_hash = _read_trusted_manifest()
    try:
        with zipfile.ZipFile(io.BytesIO(wheel_bytes)) as archive:
            members = _validate_zip_infos(archive.infolist())
            metadata_name = "fastapi-0.139.0.dist-info/METADATA"
            if metadata_name not in members:
                raise FastAPISourceProfileError("wheel has no expected distribution metadata")
            metadata = Parser(policy=policy.default).parsestr(
                archive.read(metadata_name).decode("utf-8"), headersonly=True
            )
            if metadata.get_all("Name") != ["fastapi"] or metadata.get_all("Version") != [
                "0.139.0"
            ]:
                raise FastAPISourceProfileError(
                    "wheel distribution metadata is not FastAPI 0.139.0"
                )
            source_files: dict[str, bytes] = {}
            source_hashes: dict[str, str] = {}
            for member, record in manifest["source_files"].items():
                info = members.get(member)
                if info is None or info.is_dir():
                    raise FastAPISourceProfileError(f"required source file is missing: {member}")
                content = archive.read(info)
                actual = _verify_source_payload(member, content, record["sha256"])
                source_files[member] = content
                source_hashes[member] = actual
    except (
        zipfile.BadZipFile,
        OSError,
        RuntimeError,
        UnicodeDecodeError,
        EOFError,
        NotImplementedError,
    ) as exc:
        raise FastAPISourceProfileError(
            "pinned FastAPI wheel is not a valid bounded ZIP archive"
        ) from exc

    return VerifiedFastAPISourceProfile(
        version=PROFILE_VERSION,
        wheel_sha256=wheel_hash,
        manifest_sha256=manifest_hash,
        profile_fingerprint=_profile_fingerprint(wheel_hash, manifest_hash),
        source_root=f"{path.resolve()}!/{PROFILE_VERSION}",
        source_files=MappingProxyType(source_files),
        source_hashes=MappingProxyType(source_hashes),
    )
