"""Versioned broker adapter for a single official pre-readiness retry review."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import stat
import struct
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

from benchmarks.real_world import ground_truth_broker_bundle_v1 as bundle_v1
from benchmarks.real_world import ground_truth_submit_retry_v2 as submit_v1
from benchmarks.real_world.ground_truth_v2.schema import canonical_json


class RetryBrokerError(RuntimeError):
    """Versioned retry broker rejected an invalid identity or transition."""


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _read(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        status = os.fstat(fd)
        if not stat.S_ISREG(status.st_mode) or status.st_uid != os.getuid():
            raise RetryBrokerError("retry broker identity file is unsafe")
        chunks = []
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                return b"".join(chunks)
            chunks.append(block)
    finally:
        os.close(fd)


def _write_new(path: Path, raw: bytes) -> None:
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o400,
    )
    try:
        view = memoryview(raw)
        while view:
            view = view[os.write(fd, view) :]
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _validate_record(raw: bytes, protocol_name: str, expected: dict[str, Any]) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (ValueError, TypeError, RecursionError) as exc:
        raise RetryBrokerError("retry broker binding is malformed") from exc
    if not isinstance(value, dict) or canonical_json(value) != raw:
        raise RetryBrokerError("retry broker binding is noncanonical")
    if any(value.get(key) != item for key, item in expected.items()):
        raise RetryBrokerError("retry broker binding differs from authenticated identity")
    if value.get("protocol") != protocol_name or value.get("schema_version") != 2:
        raise RetryBrokerError("retry broker binding protocol is unsupported")
    return value


def _send(connection: socket.socket, value: dict[str, Any]) -> None:
    raw = canonical_json(value)
    connection.sendall(struct.pack("!I", len(raw)) + raw)


def _receive(connection: socket.socket) -> bytes:
    header = submit_v1._read_exact(connection, 4)
    size = struct.unpack("!I", header)[0]
    if size <= 0 or size > submit_v1._MAX_REQUEST_BYTES:
        raise RetryBrokerError("retry broker request size is invalid")
    chunks = []
    while size:
        chunks.append(submit_v1._read_exact(connection, size))
        size = 0
    return b"".join(chunks)


def _process_start_identity(pid: int) -> str:
    raw = Path(f"/proc/{pid}/stat").read_text()
    close = raw.rfind(")")
    fields = raw[close + 2 :].split()
    if close < 0 or len(fields) <= 19 or not fields[19].isdigit():
        raise RetryBrokerError("broker process identity is unavailable")
    return fields[19]


def serve_one_retry(  # noqa: PLR0915
    *,
    binding_path: Path,
    runtime_binding_path: Path,
    overlay_binding_path: Path,
    socket_path: Path,
    claim_receipt_path: Path,
    escrow_receipt_path: Path,
    runtime_expected: dict[str, Any],
    overlay_expected: dict[str, Any],
    runtime_attestation_path: Path,
    custody_receipt_path: Path,
    freeze_receipt_path: Path,
    freeze_receipt_sha256: str,
    bundle_root: Path,
    source_root: Path,
    freeze_fd: int,
    deadline: datetime,
    clock: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    """Serve one real submission using v1 semantic checks and v2 run receipts."""
    runtime_raw = _read(runtime_binding_path)
    overlay_raw = _read(overlay_binding_path)
    runtime = _validate_record(
        runtime_raw, "ground-truth-review-retry-runtime-binding-v2", runtime_expected
    )
    overlay = _validate_record(
        overlay_raw, "ground-truth-review-retry-overlay-binding-v2", overlay_expected
    )
    attestation_raw = _read(runtime_attestation_path)
    custody_raw = _read(custody_receipt_path)
    try:
        attestation = json.loads(attestation_raw)
    except (ValueError, TypeError) as exc:
        raise RetryBrokerError("official runtime attestation is malformed") from exc
    if (
        not isinstance(attestation, dict)
        or attestation.get("entry_hash") != runtime["official_runtime_entry_hash"]
        or _sha(attestation_raw) != runtime["runtime_attestation_sha256"]
        or _sha(custody_raw) != runtime["runtime_custody_receipt_sha256"]
    ):
        raise RetryBrokerError("runtime binding differs from official runtime custody bytes")
    record = submit_v1.load_bindings(binding_path, project_root=source_root).records[0]
    if (
        record.attempt_id != overlay["campaign_attempt_id"]
        or _sha(_read(binding_path)) != overlay["official_binding_sha256"]
        or _sha(runtime_raw) != overlay["runtime_binding_sha256"]
        or runtime["run_id"] != overlay["run_id"]
        or runtime["grant_entry_hash"] != overlay["grant_entry_hash"]
        or Path(record.escrow_path).parent.name != "escrow"
        or Path(record.escrow_path).parent.parent != escrow_receipt_path.parent
        or not socket_path.is_absolute()
    ):
        raise RetryBrokerError("retry broker bindings do not identify this fresh run")
    lease = bundle_v1.adopt_inherited_launch_lease(
        freeze_fd=freeze_fd,
        bundle_root=bundle_root,
        source_root=source_root,
        receipt_path=freeze_receipt_path,
        receipt_sha256=freeze_receipt_sha256,
    )
    identities = {
        "runtime_attestation_sha256": lease.lease.receipt.runtime_attestation_sha256,
        "binding_sha256": lease.lease.receipt.binding_sha256,
        "launch_profile_sha256": lease.lease.receipt.launch_profile_sha256,
        "toolchain_sha256": lease.lease.receipt.toolchain_sha256,
    }
    if identities["binding_sha256"] != _sha(runtime_raw):
        raise RetryBrokerError("freeze receipt does not bind versioned runtime binding")
    socket_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    bound = False
    try:
        server.bind(str(socket_path))
        bound = True
        socket_path.chmod(0o600)
        server.listen(1)
        server.settimeout(max(0.01, (deadline - datetime.now(timezone.utc)).total_seconds()))
        socket_info = socket_path.stat(follow_symlinks=False)
        lease.mark_ready(**identities)
        claim = {
            "schema_version": 2,
            "protocol": "ground-truth-review-retry-claim-receipt-v2",
            "run_id": overlay["run_id"],
            "campaign_attempt_id": overlay["campaign_attempt_id"],
            "grant_entry_hash": overlay["grant_entry_hash"],
            "runtime_binding_sha256": _sha(runtime_raw),
            "official_binding_sha256": _sha(_read(binding_path)),
            "broker_pid": os.getpid(),
            "broker_start_identity": _process_start_identity(os.getpid()),
            "socket_path": str(socket_path),
            "socket_device": socket_info.st_dev,
            "socket_inode": socket_info.st_ino,
            "claimed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        claim["entry_hash"] = _sha(
            b"ground-truth-review-retry-claim-receipt-v2\0" + canonical_json(claim)
        )
        _write_new(claim_receipt_path, canonical_json(claim))
        lease.mark_claimed(**identities)
        server.settimeout(max(0.01, (deadline - datetime.now(timezone.utc)).total_seconds()))
        connection, _ = server.accept()
        with connection:
            remaining = max(0.01, (deadline - datetime.now(timezone.utc)).total_seconds())
            connection.settimeout(remaining)
            peer_pid, peer_uid = submit_v1._peer_credentials(connection)
            if peer_uid != os.getuid():
                raise RetryBrokerError("retry broker peer uid is invalid")
            submit_v1._verify_peer_cwd(peer_pid, record)
            draft = submit_v1._request(_receive(connection), record)
            receipt = submit_v1.escrow_submission(
                draft, record, deadline=deadline, clock=clock, project_root=source_root
            )
            _send(connection, submit_v1._success(receipt))
        validated = submit_v1.recover_submission(record, project_root=source_root)
        if validated != receipt:
            raise RetryBrokerError("validated escrow receipt changed after submission")
        escrow = {
            "schema_version": 2,
            "protocol": "ground-truth-review-retry-escrow-receipt-v2",
            "run_id": overlay["run_id"],
            "campaign_attempt_id": overlay["campaign_attempt_id"],
            "grant_entry_hash": overlay["grant_entry_hash"],
            "runtime_binding_sha256": _sha(runtime_raw),
            "claim_receipt_sha256": _sha(_read(claim_receipt_path)),
            "official_binding_sha256": _sha(_read(binding_path)),
            "submission_receipt": receipt.model_dump(mode="json"),
            "finalized_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        escrow["entry_hash"] = _sha(
            b"ground-truth-review-retry-escrow-receipt-v2\0" + canonical_json(escrow)
        )
        _write_new(escrow_receipt_path, canonical_json(escrow))
        lease.mark_escrow_finalized(**identities)
        return escrow
    finally:
        server.close()
        if bound:
            socket_path.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for the sealed bundle dispatcher."""
    parser = argparse.ArgumentParser(description=__doc__)
    names = (
        "binding", "runtime-binding", "overlay-binding", "runtime-attestation",
        "custody-receipt", "freeze-receipt", "bundle-root", "source-root", "socket",
        "claim-receipt", "escrow-receipt", "campaign-attempt-id", "grant-entry-hash",
        "run-id", "extension-profile-sha256", "bundle-manifest-sha256",
        "source-closure-sha256", "launch-profile-sha256", "toolchain-sha256",
        "freeze-receipt-sha256", "runtime-binding-sha256", "official-binding-sha256",
    )
    for name in names:
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--rank", type=int, required=True)
    parser.add_argument("--lane", choices=("A", "B"), required=True)
    parser.add_argument("--retry-ordinal", type=int, required=True)
    args = parser.parse_args(argv)
    runtime_expected = {
        "extension_profile_sha256": args.extension_profile_sha256,
        "bundle_manifest_sha256": args.bundle_manifest_sha256,
        "source_closure_sha256": args.source_closure_sha256,
        "launch_profile_sha256": args.launch_profile_sha256,
        "toolchain_sha256": args.toolchain_sha256,
        "campaign_attempt_id": args.campaign_attempt_id,
        "grant_entry_hash": args.grant_entry_hash,
        "retry_ordinal": args.retry_ordinal,
        "run_id": args.run_id,
        "official_binding_sha256": args.official_binding_sha256,
    }
    overlay_expected = {
        "campaign_attempt_id": args.campaign_attempt_id,
        "run_id": args.run_id,
        "retry_ordinal": args.retry_ordinal,
        "grant_entry_hash": args.grant_entry_hash,
        "runtime_binding_sha256": args.runtime_binding_sha256,
        "official_binding_sha256": args.official_binding_sha256,
        "rank": args.rank,
        "lane": args.lane,
    }
    binding_path = Path(args.binding)
    source_root = Path(args.source_root)
    record = submit_v1.load_bindings(binding_path, project_root=source_root).records[0]
    deadline = record.run.started_at + timedelta(seconds=record.run.limits.max_seconds)
    serve_one_retry(
        binding_path=binding_path,
        runtime_binding_path=Path(args.runtime_binding),
        overlay_binding_path=Path(args.overlay_binding),
        socket_path=Path(args.socket),
        claim_receipt_path=Path(args.claim_receipt),
        escrow_receipt_path=Path(args.escrow_receipt),
        runtime_expected=runtime_expected,
        overlay_expected=overlay_expected,
        runtime_attestation_path=Path(args.runtime_attestation),
        custody_receipt_path=Path(args.custody_receipt),
        freeze_receipt_path=Path(args.freeze_receipt),
        freeze_receipt_sha256=args.freeze_receipt_sha256,
        bundle_root=Path(args.bundle_root),
        source_root=Path(args.source_root),
        freeze_fd=int(os.environ["GT_BROKER_FREEZE_FD"]),
        deadline=deadline,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
