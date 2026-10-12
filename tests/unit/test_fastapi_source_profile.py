"""FastAPI source authentication tests; upstream code is never imported."""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer import fastapi_source_profile as profile

WHEEL = Path("/tmp/gh107-fastapi-profile/fastapi-0.139.0-py3-none-any.whl")


@pytest.fixture
def official_wheel() -> Path:
    if not WHEEL.is_file():
        pytest.skip("download the locked official FastAPI wheel to run artifact verification")
    return WHEEL


def test_official_pinned_wheel_verifies_without_importing_fastapi(official_wheel: Path) -> None:
    verified = profile.verify_fastapi_wheel(official_wheel)

    assert verified.version == "0.139.0"
    assert verified.wheel_sha256 == profile.WHEEL_SHA256
    assert verified.manifest_sha256 == profile.MANIFEST_SHA256
    assert len(verified.profile_fingerprint) == 64
    assert set(verified.source_files) == set(profile._EXPECTED_ROLES)
    assert verified.match_source_snapshot(
        "fastapi/params.py", verified.source_files["fastapi/params.py"]
    )
    assert not verified.match_source_snapshot(
        "params.py", verified.source_files["fastapi/params.py"]
    )
    assert not verified.match_source_snapshot("fastapi/params.py", b"substituted source")


def test_rejects_altered_wheel_bytes_before_zip_inspection(
    tmp_path: Path, official_wheel: Path
) -> None:
    altered = tmp_path / profile.WHEEL_FILENAME
    altered.write_bytes(official_wheel.read_bytes()[:-1] + b"X")

    with pytest.raises(profile.FastAPISourceProfileError, match=r"size|SHA-256"):
        profile.verify_fastapi_wheel(altered)


def test_wheel_growth_is_rejected_with_a_single_bounded_read(
    tmp_path: Path, official_wheel: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    grown = tmp_path / profile.WHEEL_FILENAME
    grown.write_bytes(official_wheel.read_bytes() + b"extra")
    real_open = Path.open
    requests: list[int] = []

    def tracked_open(path: Path, *args: object, **kwargs: object):
        stream = real_open(path, *args, **kwargs)
        if path == grown and args and args[0] == "rb":
            real_read = stream.read

            def tracked_read(size: int = -1) -> bytes:
                requests.append(size)
                return real_read(size)

            stream.read = tracked_read  # type: ignore[method-assign]
        return stream

    monkeypatch.setattr(Path, "open", tracked_open)
    with pytest.raises(profile.FastAPISourceProfileError, match="size"):
        profile.verify_fastapi_wheel(grown)
    assert requests == [profile.WHEEL_SIZE + 1]


def test_replacement_after_capture_does_not_change_archive_input(
    tmp_path: Path, official_wheel: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wheel = tmp_path / profile.WHEEL_FILENAME
    original = official_wheel.read_bytes()
    wheel.write_bytes(original)
    real_zipfile = zipfile.ZipFile
    inputs: list[object] = []

    def replacing_zipfile(file: object, *args: object, **kwargs: object):
        inputs.append(file)
        assert isinstance(file, io.BytesIO)
        wheel.write_bytes(b"X" * profile.WHEEL_SIZE)
        return real_zipfile(file, *args, **kwargs)

    monkeypatch.setattr(profile.zipfile, "ZipFile", replacing_zipfile)
    verified = profile.verify_fastapi_wheel(wheel)
    assert verified.wheel_sha256 == profile.WHEEL_SHA256
    assert len(inputs) == 1
    assert wheel.read_bytes() != original


def test_rejects_wrong_wheel_name_and_unavailable_artifact(tmp_path: Path) -> None:
    with pytest.raises(profile.FastAPISourceProfileError, match="filename"):
        profile.verify_fastapi_wheel(tmp_path / "fastapi-0.100.0-py3-none-any.whl")
    with pytest.raises(profile.FastAPISourceProfileError, match="cannot read"):
        profile.verify_fastapi_wheel(tmp_path / profile.WHEEL_FILENAME)


def test_rejects_altered_source_payload() -> None:
    source = b"trusted source"
    digest = hashlib.sha256(source).hexdigest()
    assert profile._verify_source_payload("fastapi/params.py", source, digest) == digest
    with pytest.raises(profile.FastAPISourceProfileError, match="source hash mismatch"):
        profile._verify_source_payload("fastapi/params.py", b"altered source", digest)


def test_manifest_profile_cannot_authorize_another_wheel_or_path_set() -> None:
    manifest_path = (
        Path(profile.__file__).with_name("data") / "fastapi_source_profiles" / "0.139.0.json"
    )
    manifest = json.loads(manifest_path.read_text())
    manifest["version"] = "0.140.0"
    with pytest.raises(profile.FastAPISourceProfileError, match="pinned FastAPI wheel"):
        profile._validate_manifest(manifest)

    manifest["version"] = profile.PROFILE_VERSION
    manifest["source_files"]["fastapi/extra.py"] = {"sha256": "0" * 64, "role": "extra"}
    with pytest.raises(profile.FastAPISourceProfileError, match="paths are missing or extra"):
        profile._validate_manifest(manifest)


def test_manifest_json_rejects_duplicate_keys_and_nonfinite_numbers() -> None:
    with pytest.raises(profile.FastAPISourceProfileError, match="duplicate JSON key"):
        profile._parse_manifest(b'{"schema_version":1,"schema_version":1}')
    with pytest.raises(profile.FastAPISourceProfileError, match="non-finite"):
        profile._parse_manifest(b'{"schema_version":NaN}')


def test_trusted_manifest_read_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    manifest_path = (
        Path(profile.__file__).with_name("data") / "fastapi_source_profiles" / "0.139.0.json"
    )
    real_open = Path.open
    requests: list[int] = []

    class OversizedManifest:
        def __enter__(self) -> OversizedManifest:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self, size: int = -1) -> bytes:
            requests.append(size)
            return b"x" * size

    def bounded_open(path: Path, *args: object, **kwargs: object):
        if path == manifest_path:
            return OversizedManifest()
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", bounded_open)
    with pytest.raises(profile.FastAPISourceProfileError, match="exceeds size limit"):
        profile._read_trusted_manifest()
    assert requests == [profile.MAX_MANIFEST_SIZE + 1]


def test_zip_member_validation_rejects_duplicate_unsafe_symlink_and_oversize() -> None:
    duplicate = [zipfile.ZipInfo("fastapi/a.py"), zipfile.ZipInfo("fastapi/a.py")]
    with pytest.raises(profile.FastAPISourceProfileError, match="duplicate"):
        profile._validate_zip_infos(duplicate)

    with pytest.raises(profile.FastAPISourceProfileError, match="unsafe"):
        profile._validate_zip_infos([zipfile.ZipInfo("fastapi/../escape.py")])

    symlink = zipfile.ZipInfo("fastapi/link.py")
    symlink.external_attr = 0o120777 << 16
    with pytest.raises(profile.FastAPISourceProfileError, match="symlink"):
        profile._validate_zip_infos([symlink])

    oversized = zipfile.ZipInfo("fastapi/large.py")
    oversized.file_size = profile.MAX_MEMBER_UNCOMPRESSED + 1
    with pytest.raises(profile.FastAPISourceProfileError, match="size limit"):
        profile._validate_zip_infos([oversized])


def test_rejects_manifest_identity_change(
    monkeypatch: pytest.MonkeyPatch, official_wheel: Path
) -> None:
    monkeypatch.setattr(profile, "MANIFEST_SHA256", "0" * 64)
    with pytest.raises(profile.FastAPISourceProfileError, match="manifest identity"):
        profile.verify_fastapi_wheel(official_wheel)


def test_profile_constructor_rejects_forgery_and_copies_mutable_mappings(
    official_wheel: Path,
) -> None:
    verified = profile.verify_fastapi_wheel(official_wheel)
    forged = dict(verified.source_files)
    forged["fastapi/params.py"] = b"forged"
    with pytest.raises(profile.FastAPISourceProfileError, match="source bytes"):
        profile.VerifiedFastAPISourceProfile(
            verified.version,
            verified.wheel_sha256,
            verified.manifest_sha256,
            verified.profile_fingerprint,
            "diagnostic-only-root",
            forged,
            dict(verified.source_hashes),
        )

    mutable = dict(verified.source_files)
    copied = profile.VerifiedFastAPISourceProfile(
        verified.version,
        verified.wheel_sha256,
        verified.manifest_sha256,
        verified.profile_fingerprint,
        "arbitrary diagnostic text is not identity",
        mutable,
        dict(verified.source_hashes),
    )
    mutable.clear()
    assert copied.match_source_snapshot(
        "fastapi/params.py", verified.source_files["fastapi/params.py"]
    )
    with pytest.raises(TypeError):
        copied.source_files["fastapi/params.py"] = b"mutation"  # type: ignore[index]
