#!/usr/bin/env python3
"""Immutable broker-bundle and prepare-to-escrow freeze governance.

This module is deliberately independent of the historical production-v1 ledger.
It creates no launch authority, escrow, review, label, or canonical import. A new
campaign lineage may use the receipts only as a prerequisite for later,
independently reviewed governance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, Final, Literal, NoReturn, cast

from benchmarks.real_world import ground_truth_packet_v1 as packet_v1
from benchmarks.real_world import ground_truth_submit_v1 as submit_v1
from benchmarks.real_world.ground_truth_v2.schema import canonical_json

if TYPE_CHECKING:
    from collections.abc import Mapping

_MAX_FILE: Final = 8 * 1024 * 1024
_MAX_FILES: Final = 64
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_BUNDLE_PROTOCOL: Final = "ground-truth-broker-bundle-v1"
_RECEIPT_PROTOCOL: Final = "ground-truth-broker-bundle-receipt-v1"
_FREEZE_PROTOCOL: Final = "ground-truth-broker-prepare-freeze-v1"
_LAUNCH_PROFILE_PROTOCOL: Final = "ground-truth-broker-launch-profile-v1"
_BUNDLE_DOMAIN: Final = b"ground-truth-broker-bundle-v1\0"
_FREEZE_PHASES: Final = ("prepared", "launch_claimed", "pre_escrow")


class BrokerBundleError(RuntimeError):
    """Fail-closed immutable broker-bundle error."""


def _fail(message: str) -> NoReturn:
    raise BrokerBundleError(message)


def _sha(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _strict_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        _fail(f"{label} keys are invalid")


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate JSON key")
        result[key] = value
    return result


def _constant(value: str) -> NoReturn:
    _fail(f"non-finite JSON value: {value}")


def _owned_bytes(path: Path, *, modes: set[int] | None = None) -> bytes:
    if not path.is_absolute() or ".." in path.parts:
        _fail(f"input path must be normalized absolute: {path}")
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_uid != os.getuid()
            or status.st_nlink != 1
            or stat.S_IMODE(status.st_mode) not in (modes or {0o400, 0o444, 0o600, 0o644})
            or status.st_size > _MAX_FILE
        ):
            _fail(f"input is not an exact owned regular file: {path}")
        chunks: list[bytes] = []
        remaining = _MAX_FILE + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        current = path.stat(follow_symlinks=False)
        identity = (status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns)
        if (
            len(raw) != status.st_size
            or identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or identity != (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
        ):
            _fail(f"input changed while reading: {path}")
        return raw
    except BrokerBundleError:
        raise
    except OSError as error:
        raise BrokerBundleError(f"cannot read exact input {path}: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _json_file(path: Path, *, modes: set[int] | None = None) -> tuple[dict[str, Any], bytes]:
    raw = _owned_bytes(path, modes=modes)
    try:
        value = json.loads(raw, object_pairs_hook=_unique, parse_constant=_constant)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, RecursionError) as error:
        raise BrokerBundleError(f"invalid JSON: {path}") from error
    if not isinstance(value, dict) or canonical_json(value) != raw:
        _fail(f"JSON is not a canonical object: {path}")
    return cast("dict[str, Any]", value), raw


def _safe_relative(value: str) -> str:
    if not value or "\\" in value or "\x00" in value or value.startswith("/"):
        _fail("bundle source path is unsafe")
    normalized = PurePosixPath(value)
    parts = normalized.parts
    if (
        not parts
        or normalized.as_posix() != value
        or any(part in {"", ".", ".."} for part in parts)
    ):
        _fail("bundle source path is unsafe")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        _fail(f"{label} is not a SHA-256 digest")
    return value


def _launch_profile(value: dict[str, Any]) -> None:
    _strict_keys(
        value,
        {
            "schema_version",
            "protocol",
            "provider",
            "model",
            "model_version",
            "client_version",
            "decoding",
            "tools",
            "agent_sha256",
            "broker_entrypoint",
            "broker_entrypoint_sha256",
        },
        "launch profile",
    )
    if value["schema_version"] != 1 or value["protocol"] != _LAUNCH_PROFILE_PROTOCOL:
        _fail("launch profile protocol is invalid")
    for field in ("provider", "model", "model_version", "client_version"):
        if not isinstance(value[field], str) or not value[field] or len(value[field]) > 256:
            _fail(f"launch profile {field} is invalid")
    if not isinstance(value["decoding"], dict):
        _fail("launch profile decoding is invalid")
    canonical_json(value["decoding"])
    tools = value["tools"]
    if (
        not isinstance(tools, list)
        or not tools
        or len(tools) > 32
        or any(not isinstance(item, str) or not item or len(item) > 128 for item in tools)
        or len(set(tools)) != len(tools)
    ):
        _fail("launch profile tools are invalid")
    _digest(value["agent_sha256"], "launch profile agent_sha256")
    if not isinstance(value["broker_entrypoint"], str):
        _fail("launch profile broker entrypoint is invalid")
    _safe_relative(value["broker_entrypoint"])
    _digest(value["broker_entrypoint_sha256"], "launch profile broker entrypoint")


def _control_snapshot(
    runtime_attestation: Path,
    binding: Path,
    production_profile: Path,
    launch_profile: Path,
) -> dict[str, Any]:
    runtime, runtime_raw = _json_file(runtime_attestation)
    bindings, binding_raw = _json_file(binding)
    _production, profile_raw = _json_file(production_profile)
    launch, launch_raw = _json_file(launch_profile)
    _launch_profile(launch)
    runtime_hash = _digest(runtime.get("entry_hash"), "runtime entry hash")
    runtime_profile = _digest(
        runtime.get("production_profile_sha256"), "runtime production profile"
    )
    records = bindings.get("records")
    if not isinstance(records, list) or len(records) != 1 or not isinstance(records[0], dict):
        _fail("binding must contain exactly one record")
    record = cast("dict[str, Any]", records[0])
    if (
        _digest(record.get("runtime_attestation_entry_hash"), "binding runtime hash")
        != runtime_hash
        or _digest(record.get("profile_checksum_sha256"), "binding profile hash") != runtime_profile
        or _sha(profile_raw) != runtime_profile
    ):
        _fail("runtime, binding, and production profile are not exactly coupled")
    return {
        "runtime_attestation_entry_hash": runtime_hash,
        "runtime_attestation_sha256": _sha(runtime_raw),
        "binding_sha256": _sha(binding_raw),
        "production_profile_sha256": _sha(profile_raw),
        "launch_profile_sha256": _sha(launch_raw),
        "launch_profile": launch,
        "raw": {
            "runtime-attestation.json": runtime_raw,
            "binding.json": binding_raw,
            "production-profile.json": profile_raw,
            "launch-profile.json": launch_raw,
        },
    }


def _private_parent(path: Path) -> os.stat_result:
    if not path.is_absolute() or ".." in path.parts or path.name in {"", ".", ".."}:
        _fail("output path must be normalized absolute")
    if path.exists() or path.is_symlink():
        _fail(f"output already exists: {path}")
    parent = path.parent
    try:
        status = parent.stat(follow_symlinks=False)
    except OSError as error:
        raise BrokerBundleError(f"cannot inspect output parent: {error}") from error
    if (
        not stat.S_ISDIR(status.st_mode)
        or status.st_uid != os.getuid()
        or stat.S_IMODE(status.st_mode) != 0o700
    ):
        _fail("output parent must be an owned non-symlinked mode-0700 directory")
    return status


def _atomic(path: Path, value: dict[str, Any]) -> None:
    try:
        submit_v1._atomic_no_clobber(path, canonical_json(value), mode=0o400)
    except submit_v1.SubmissionRejected as error:
        raise BrokerBundleError(f"cannot publish {path.name}") from error


def _entry(path: str, raw: bytes, category: str) -> dict[str, Any]:
    return {
        "path": path,
        "category": category,
        "bytes": len(raw),
        "mode": "0400",
        "sha256": _sha(raw),
    }


def materialize_bundle(  # noqa: PLR0915
    runtime_attestation: Path,
    binding: Path,
    production_profile: Path,
    launch_profile: Path,
    sources: Mapping[str, Path],
    output: Path,
    *,
    lineage_id: str,
) -> dict[str, Any]:
    """Atomically publish one immutable bundle and its sibling identity receipt."""
    _private_parent(output)
    receipt_path = output.with_name(output.name + ".receipt.json")
    _private_parent(receipt_path)
    if not lineage_id or len(lineage_id) > 128 or not re.fullmatch(r"[A-Za-z0-9_.:-]+", lineage_id):
        _fail("lineage_id is invalid")
    if not sources or len(sources) > _MAX_FILES:
        _fail("bundle source cardinality is invalid")
    snapshot = _control_snapshot(runtime_attestation, binding, production_profile, launch_profile)
    source_rows: list[tuple[str, bytes]] = []
    for relative, path in sorted(sources.items()):
        safe = _safe_relative(relative)
        source_rows.append((f"broker/{safe}", _owned_bytes(path)))
    launch = cast("dict[str, Any]", snapshot["launch_profile"])
    entrypoint = f"broker/{launch['broker_entrypoint']}"
    source_by_path = dict(source_rows)
    if (
        entrypoint not in source_by_path
        or _sha(source_by_path[entrypoint]) != launch["broker_entrypoint_sha256"]
    ):
        _fail("launch profile broker entrypoint is not exactly bundled")
    control_rows = [
        (f"control/{name}", raw)
        for name, raw in sorted(cast("dict[str, bytes]", snapshot["raw"]).items())
    ]
    rows = [
        *(_entry(path, raw, "control") for path, raw in control_rows),
        *(_entry(path, raw, "broker") for path, raw in source_rows),
    ]
    manifest_body = {
        "schema_version": 1,
        "protocol": _BUNDLE_PROTOCOL,
        "lineage_id": lineage_id,
        "runtime_attestation_entry_hash": snapshot["runtime_attestation_entry_hash"],
        "runtime_attestation_sha256": snapshot["runtime_attestation_sha256"],
        "binding_sha256": snapshot["binding_sha256"],
        "production_profile_sha256": snapshot["production_profile_sha256"],
        "launch_profile_sha256": snapshot["launch_profile_sha256"],
        "files": rows,
        "inventory_sha256": _sha(canonical_json(rows)),
        "authorizations": {
            "review_launch": False,
            "escrow": False,
            "adjudication": False,
            "canonical_import": False,
        },
    }
    bundle_id = _sha(_BUNDLE_DOMAIN + canonical_json(manifest_body))
    manifest = {**manifest_body, "bundle_id": bundle_id}
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    staging.chmod(0o700)
    try:
        for directory in (staging / "control", staging / "broker"):
            directory.mkdir(mode=0o700)
        for relative, raw in (*control_rows, *source_rows):
            target = staging / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(raw)
            target.chmod(0o400)
        (staging / "manifest.json").write_bytes(canonical_json(manifest))
        (staging / "manifest.json").chmod(0o400)
        for directory in sorted(
            (item for item in staging.rglob("*") if item.is_dir()), reverse=True
        ):
            directory.chmod(0o500)
        staging.chmod(0o500)
        packet_v1._rename_noreplace(staging, output)
    except BaseException:
        if staging.exists():
            for item in sorted(staging.rglob("*"), reverse=True):
                if item.is_dir():
                    item.chmod(0o700)
                    item.rmdir()
                else:
                    item.chmod(0o600)
                    item.unlink()
            staging.chmod(0o700)
            staging.rmdir()
        raise
    status = output.stat(follow_symlinks=False)
    receipt_body = {
        "schema_version": 1,
        "protocol": _RECEIPT_PROTOCOL,
        "lineage_id": lineage_id,
        "bundle_id": bundle_id,
        "bundle_path": str(output),
        "bundle_device": status.st_dev,
        "bundle_inode": status.st_ino,
        "manifest_sha256": _sha(canonical_json(manifest)),
        "inventory_sha256": manifest["inventory_sha256"],
        "runtime_attestation_entry_hash": snapshot["runtime_attestation_entry_hash"],
        "runtime_attestation_sha256": snapshot["runtime_attestation_sha256"],
        "binding_sha256": snapshot["binding_sha256"],
        "production_profile_sha256": snapshot["production_profile_sha256"],
        "launch_profile_sha256": snapshot["launch_profile_sha256"],
        "authorizations": manifest["authorizations"],
    }
    receipt = {**receipt_body, "receipt_sha256": _sha(canonical_json(receipt_body))}
    _atomic(receipt_path, receipt)
    verify_bundle(receipt_path)
    return receipt


def verify_bundle(receipt_path: Path) -> dict[str, Any]:  # noqa: PLR0912, PLR0915
    """Verify receipt identity, exact inventory, modes, and copied bytes."""
    receipt, receipt_raw = _json_file(receipt_path, modes={0o400})
    expected = {
        "schema_version",
        "protocol",
        "lineage_id",
        "bundle_id",
        "bundle_path",
        "bundle_device",
        "bundle_inode",
        "manifest_sha256",
        "inventory_sha256",
        "runtime_attestation_entry_hash",
        "runtime_attestation_sha256",
        "binding_sha256",
        "production_profile_sha256",
        "launch_profile_sha256",
        "authorizations",
        "receipt_sha256",
    }
    _strict_keys(receipt, expected, "bundle receipt")
    body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    if (
        receipt["schema_version"] != 1
        or receipt["protocol"] != _RECEIPT_PROTOCOL
        or receipt["receipt_sha256"] != _sha(canonical_json(body))
        or canonical_json(receipt) != receipt_raw
        or receipt["authorizations"]
        != {
            "review_launch": False,
            "escrow": False,
            "adjudication": False,
            "canonical_import": False,
        }
    ):
        _fail("bundle receipt is invalid")
    bundle = Path(cast("str", receipt["bundle_path"]))
    if not bundle.is_absolute():
        _fail("bundle path is invalid")
    status = bundle.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(status.st_mode)
        or status.st_uid != os.getuid()
        or stat.S_IMODE(status.st_mode) != 0o500
        or status.st_dev != receipt["bundle_device"]
        or status.st_ino != receipt["bundle_inode"]
    ):
        _fail("bundle directory identity changed")
    manifest, manifest_raw = _json_file(bundle / "manifest.json", modes={0o400})
    if (
        _sha(manifest_raw) != receipt["manifest_sha256"]
        or manifest.get("bundle_id") != receipt["bundle_id"]
        or manifest.get("inventory_sha256") != receipt["inventory_sha256"]
    ):
        _fail("bundle manifest identity changed")
    manifest_body = {key: value for key, value in manifest.items() if key != "bundle_id"}
    if manifest["bundle_id"] != _sha(_BUNDLE_DOMAIN + canonical_json(manifest_body)):
        _fail("bundle ID is invalid")
    rows = manifest.get("files")
    if not isinstance(rows, list) or not rows or len(rows) > _MAX_FILES + 4:
        _fail("bundle inventory is invalid")
    expected_files = {"manifest.json"}
    expected_directories = {"control", "broker"}
    for row in rows:
        if not isinstance(row, dict):
            _fail("bundle inventory row is invalid")
        _strict_keys(row, {"path", "category", "bytes", "mode", "sha256"}, "bundle row")
        relative = _safe_relative(cast("str", row["path"]))
        if relative in expected_files or row["category"] not in {"control", "broker"}:
            _fail("bundle inventory row is invalid")
        expected_files.add(relative)
        parent = PurePosixPath(relative).parent
        while parent.as_posix() not in {".", ""}:
            expected_directories.add(parent.as_posix())
            parent = parent.parent
        raw = _owned_bytes(bundle / relative, modes={0o400})
        if row["mode"] != "0400" or row["bytes"] != len(raw) or row["sha256"] != _sha(raw):
            _fail("bundle file identity changed")
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    for path in bundle.rglob("*"):
        relative = path.relative_to(bundle).as_posix()
        status = path.stat(follow_symlinks=False)
        if path.is_dir():
            if not stat.S_ISDIR(status.st_mode) or stat.S_IMODE(status.st_mode) != 0o500:
                _fail("bundle directory mode changed")
            actual_directories.add(relative)
        else:
            actual_files.add(relative)
    if (
        actual_files != expected_files
        or actual_directories != expected_directories
        or manifest["inventory_sha256"] != _sha(canonical_json(rows))
    ):
        _fail("bundle inventory changed")
    for field in (
        "runtime_attestation_entry_hash",
        "runtime_attestation_sha256",
        "binding_sha256",
        "production_profile_sha256",
        "launch_profile_sha256",
    ):
        if manifest.get(field) != receipt[field]:
            _fail("bundle control identity changed")
    return receipt


def prepare_freeze(
    receipt_path: Path,
    runtime_attestation: Path,
    binding: Path,
    production_profile: Path,
    launch_profile: Path,
    output: Path,
    *,
    clock: datetime | None = None,
) -> dict[str, Any]:
    """Freeze exact bundle/control identity without granting launch or escrow authority."""
    _private_parent(output)
    receipt = verify_bundle(receipt_path)
    snapshot = _control_snapshot(runtime_attestation, binding, production_profile, launch_profile)
    for field in (
        "runtime_attestation_entry_hash",
        "runtime_attestation_sha256",
        "binding_sha256",
        "production_profile_sha256",
        "launch_profile_sha256",
    ):
        if snapshot[field] != receipt[field]:
            _fail("prepare inputs differ from the receipt-bound bundle")
    now = (clock or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    body = {
        "schema_version": 1,
        "protocol": _FREEZE_PROTOCOL,
        "lineage_id": receipt["lineage_id"],
        "bundle_id": receipt["bundle_id"],
        "bundle_receipt_path": str(receipt_path),
        "bundle_receipt_sha256": _sha(canonical_json(receipt)),
        "runtime_attestation_entry_hash": snapshot["runtime_attestation_entry_hash"],
        "runtime_attestation_sha256": snapshot["runtime_attestation_sha256"],
        "binding_sha256": snapshot["binding_sha256"],
        "production_profile_sha256": snapshot["production_profile_sha256"],
        "launch_profile_sha256": snapshot["launch_profile_sha256"],
        "bundle_inventory_sha256": receipt["inventory_sha256"],
        "phase_scope": list(_FREEZE_PHASES),
        "prepared_at": now.isoformat().replace("+00:00", "Z"),
        "authorizations": {
            "review_launch": False,
            "escrow": False,
            "adjudication": False,
            "canonical_import": False,
        },
    }
    freeze = {**body, "freeze_sha256": _sha(canonical_json(body))}
    _atomic(output, freeze)
    verify_freeze(
        output,
        runtime_attestation,
        binding,
        production_profile,
        launch_profile,
        phase="prepared",
    )
    return freeze


def verify_freeze(
    freeze_path: Path,
    runtime_attestation: Path,
    binding: Path,
    production_profile: Path,
    launch_profile: Path,
    *,
    phase: Literal["prepared", "launch_claimed", "pre_escrow"],
) -> dict[str, Any]:
    """Reauthenticate the same immutable boundary at each pre-escrow phase."""
    if phase not in _FREEZE_PHASES:
        _fail("freeze phase is invalid")
    freeze, freeze_raw = _json_file(freeze_path, modes={0o400})
    expected = {
        "schema_version",
        "protocol",
        "lineage_id",
        "bundle_id",
        "bundle_receipt_path",
        "bundle_receipt_sha256",
        "runtime_attestation_entry_hash",
        "runtime_attestation_sha256",
        "binding_sha256",
        "production_profile_sha256",
        "launch_profile_sha256",
        "bundle_inventory_sha256",
        "phase_scope",
        "prepared_at",
        "authorizations",
        "freeze_sha256",
    }
    _strict_keys(freeze, expected, "prepare freeze")
    body = {key: value for key, value in freeze.items() if key != "freeze_sha256"}
    if (
        freeze["schema_version"] != 1
        or freeze["protocol"] != _FREEZE_PROTOCOL
        or freeze["freeze_sha256"] != _sha(canonical_json(body))
        or canonical_json(freeze) != freeze_raw
        or freeze["phase_scope"] != list(_FREEZE_PHASES)
        or freeze["authorizations"]
        != {
            "review_launch": False,
            "escrow": False,
            "adjudication": False,
            "canonical_import": False,
        }
    ):
        _fail("prepare freeze is invalid")
    receipt_path = Path(cast("str", freeze["bundle_receipt_path"]))
    receipt = verify_bundle(receipt_path)
    if (
        freeze["bundle_receipt_sha256"] != _sha(canonical_json(receipt))
        or freeze["bundle_id"] != receipt["bundle_id"]
        or freeze["bundle_inventory_sha256"] != receipt["inventory_sha256"]
    ):
        _fail("prepare freeze bundle identity changed")
    snapshot = _control_snapshot(runtime_attestation, binding, production_profile, launch_profile)
    for field in (
        "runtime_attestation_entry_hash",
        "runtime_attestation_sha256",
        "binding_sha256",
        "production_profile_sha256",
        "launch_profile_sha256",
    ):
        if freeze[field] != snapshot[field] or freeze[field] != receipt[field]:
            _fail(f"{phase} control identity changed")
    return freeze


def _sources(values: list[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            _fail("--source must be RELATIVE=ABSOLUTE")
        relative, raw_path = value.split("=", 1)
        relative = _safe_relative(relative)
        if relative in result:
            _fail("duplicate --source path")
        result[relative] = Path(raw_path)
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--runtime-attestation", type=Path, required=True)
    common.add_argument("--binding", type=Path, required=True)
    common.add_argument("--production-profile", type=Path, required=True)
    common.add_argument("--launch-profile", type=Path, required=True)
    build = sub.add_parser("build-bundle", parents=[common])
    build.add_argument("--source", action="append", required=True)
    build.add_argument("--lineage-id", required=True)
    build.add_argument("--output", type=Path, required=True)
    verify = sub.add_parser("verify-bundle")
    verify.add_argument("--receipt", type=Path, required=True)
    freeze = sub.add_parser("prepare-freeze", parents=[common])
    freeze.add_argument("--receipt", type=Path, required=True)
    freeze.add_argument("--output", type=Path, required=True)
    verify_freeze_parser = sub.add_parser("verify-freeze", parents=[common])
    verify_freeze_parser.add_argument("--freeze", type=Path, required=True)
    verify_freeze_parser.add_argument("--phase", choices=_FREEZE_PHASES, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "build-bundle":
            result = materialize_bundle(
                args.runtime_attestation,
                args.binding,
                args.production_profile,
                args.launch_profile,
                _sources(args.source),
                args.output,
                lineage_id=args.lineage_id,
            )
        elif args.command == "verify-bundle":
            result = verify_bundle(args.receipt)
        elif args.command == "prepare-freeze":
            result = prepare_freeze(
                args.receipt,
                args.runtime_attestation,
                args.binding,
                args.production_profile,
                args.launch_profile,
                args.output,
            )
        else:
            result = verify_freeze(
                args.freeze,
                args.runtime_attestation,
                args.binding,
                args.production_profile,
                args.launch_profile,
                phase=args.phase,
            )
    except BrokerBundleError as error:
        _parser().error(str(error))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
