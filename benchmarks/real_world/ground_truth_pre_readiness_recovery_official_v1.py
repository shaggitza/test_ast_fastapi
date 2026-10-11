"""Official custody adapter for the versioned pre-readiness grant and retry.

Retry startup is delegated to a separately versioned immutable broker-bundle
lease API; absent that API, the dispatcher fails closed before run allocation.
This module never launches a model or reviewer.
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import importlib
import json
import os
import shutil
import stat
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from benchmarks.real_world import ground_truth_pre_readiness_recovery_v1 as protocol
from benchmarks.real_world import ground_truth_run_v1 as run_v1
from benchmarks.real_world.ground_truth_v2.schema import canonical_json


class OfficialRecoveryError(ValueError):
    """Official custody or recovery evidence failed closed."""


def _broker_bundle_api() -> Any:
    try:
        broker_bundle = importlib.import_module(
            "benchmarks.real_world.ground_truth_broker_bundle_v1"
        )
    except ImportError as exc:
        raise OfficialRecoveryError("the broker bundle lease validator is unavailable") from exc
    acquire = getattr(broker_bundle, "acquire_launch_lease", None)
    launch = getattr(broker_bundle, "launch_with_escrow_lease", None)
    if not callable(acquire) or not callable(launch):
        raise OfficialRecoveryError("the broker bundle lease validator is unavailable")
    return broker_bundle


def acquire_broker_bundle_lease(
    *,
    root: Path,
    lease_receipt: Path | None,
    runtime_attestation: dict[str, Any],
    binding_sha256: str,
    launch_profile_sha256: str,
) -> Any:
    """Acquire the separately versioned exclusive launch-frozen bundle lease.

    The broker-bundle implementation is maintained independently. Until its
    public validator/lease API is present, operational broker startup is denied.
    The proof must be acquired only after the real binding exists and held until
    the broker's official escrow finalization has completed.
    """
    if lease_receipt is None:
        raise OfficialRecoveryError("a validated broker bundle lease is required")
    acquire = _broker_bundle_api().acquire_launch_lease
    try:
        lease = acquire(
            root=root,
            receipt_path=lease_receipt,
            runtime_attestation=runtime_attestation,
            binding_sha256=binding_sha256,
            launch_profile_sha256=launch_profile_sha256,
            require_exclusive_freeze=True,
            hold_until="escrow_finalized",
        )
    except Exception as exc:
        raise OfficialRecoveryError("broker bundle lease validation failed") from exc
    if lease is None:
        raise OfficialRecoveryError("broker bundle lease was not acquired")
    return lease


def launch_broker_with_bundle_lease(lease: Any, **launch_request: Any) -> int:
    """Delegate process creation to the bundle so its lease is broker-owned."""
    launch = _broker_bundle_api().launch_with_escrow_lease
    try:
        pid = launch(lease=lease, **launch_request)
    except Exception as exc:
        raise OfficialRecoveryError("broker bundle launch with escrow lease failed") from exc
    if not isinstance(pid, int) or isinstance(pid, bool) or pid < 1:
        raise OfficialRecoveryError("broker bundle launcher returned an invalid process id")
    return pid


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _private_file(path: Path) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise OfficialRecoveryError(f"official evidence unavailable: {path.name}") from exc
    try:
        st = os.fstat(fd)
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_uid != os.getuid()
            or stat.S_IMODE(st.st_mode) not in {0o400, 0o600}
        ):
            raise OfficialRecoveryError("official evidence file ownership or mode is invalid")
        chunks = []
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                return b"".join(chunks)
            chunks.append(block)
    finally:
        os.close(fd)


def _profile_file(path: Path) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise OfficialRecoveryError("extension profile file is unavailable") from exc
    try:
        st = os.fstat(fd)
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_uid != os.getuid()
            or stat.S_IMODE(st.st_mode) not in {0o400, 0o444, 0o600, 0o644}
        ):
            raise OfficialRecoveryError("extension profile file ownership or mode is invalid")
        chunks = []
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                return b"".join(chunks)
            chunks.append(block)
    finally:
        os.close(fd)


def _profile_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OfficialRecoveryError("extension checksum profile has duplicate keys")
        result[key] = value
    return result


def authenticate_extension_profile(root: Path) -> str:
    """Verify the published sibling profile and all files it names."""
    profile_root = root / "benchmarks/real_world/production_v1/extensions/pre-readiness-recovery-v1"
    manifest_path = profile_root / "checksums-v1.json"
    try:
        raw = _profile_file(manifest_path)
        manifest = json.loads(raw, object_pairs_hook=_profile_object)
    except (OfficialRecoveryError, ValueError) as exc:
        raise OfficialRecoveryError(
            "pre-readiness extension checksum profile is unavailable"
        ) from exc
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != 1
        or manifest.get("profile_id") != "ground-truth-review-canary-pre-readiness-recovery-v1"
        or set(manifest) != {"schema_version", "profile_id", "files"}
        or not isinstance(manifest.get("files"), dict)
    ):
        raise OfficialRecoveryError("pre-readiness extension checksum profile is malformed")
    for relative, expected in manifest["files"].items():
        if (
            not isinstance(relative, str)
            or not relative.startswith("benchmarks/real_world/")
            or ".." in Path(relative).parts
        ):
            raise OfficialRecoveryError(
                "extension checksum path is outside the production source tree"
            )
        if not isinstance(expected, str) or not expected.startswith("sha256:"):
            raise OfficialRecoveryError("extension checksum entry is malformed")
        candidate = root / relative
        try:
            candidate.resolve(strict=True).relative_to(root.resolve(strict=True))
        except (OSError, RuntimeError, ValueError) as exc:
            raise OfficialRecoveryError("extension checksum path escapes repository root") from exc
        if _sha(_profile_file(candidate)) != expected:
            raise OfficialRecoveryError("pre-readiness extension checksum mismatch")
    return _sha(raw)


def validate_official_campaign_preflight(
    caller_path: Path, canonical_path: str, caller_raw: bytes, canonical_sha256: str
) -> None:
    """Exact path/hash gate that runs before every durable recovery write."""
    try:
        resolved = str(caller_path.resolve(strict=True))
    except (OSError, RuntimeError) as exc:
        raise OfficialRecoveryError("caller campaign path is unavailable") from exc
    if resolved != canonical_path or _sha(caller_raw) != canonical_sha256:
        raise OfficialRecoveryError(
            "caller campaign path or hash differs from official canonical custody"
        )


def _atomic_archive(
    archive_root: Path, attempt_id: str, items: dict[str, bytes]
) -> list[dict[str, str]]:
    archive_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if archive_root.is_symlink() or stat.S_IMODE(archive_root.stat().st_mode) != 0o700:
        raise OfficialRecoveryError("evidence archive root must be a private directory")
    lock_path = archive_root / ".lock"
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        target = archive_root / attempt_id
        if target.exists() or target.is_symlink():
            raise OfficialRecoveryError("evidence archive already exists; refusing to clobber")
        stage = archive_root / f".{attempt_id}.{os.getpid()}.staging"
        stage.mkdir(mode=0o700)
        inventory = []
        try:
            for kind, raw in items.items():
                name = f"{kind}.json"
                path = stage / name
                fd = os.open(
                    path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o400,
                )
                with os.fdopen(fd, "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                inventory.append(
                    {
                        "kind": kind,
                        "sha256": _sha(raw),
                        "archive_path": f"evidence/{attempt_id}/{name}",
                    }
                )
            directory = os.open(stage, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            stage.rename(target)
            directory = os.open(archive_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except BaseException:
            shutil.rmtree(stage, ignore_errors=True)
            raise
        return inventory
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def _active_broker_processes(attempt_id: str) -> list[int]:
    matches = []
    marker = attempt_id.encode()
    try:
        process_entries = list(Path("/proc").iterdir())
    except OSError as exc:
        raise OfficialRecoveryError("process table is unavailable for broker death proof") from exc
    for process in process_entries:
        if not process.name.isdigit():
            continue
        try:
            status = (process / "status").read_text()
        except FileNotFoundError:
            continue
        except OSError:
            raise OfficialRecoveryError(
                "process ownership is unavailable for broker death proof"
            ) from None
        uid_row = next((line for line in status.splitlines() if line.startswith("Uid:")), None)
        try:
            same_user = uid_row is not None and int(uid_row.split()[1]) == os.getuid()
        except (IndexError, ValueError) as exc:
            raise OfficialRecoveryError("process ownership record is malformed") from exc
        if uid_row is None:
            raise OfficialRecoveryError("process ownership record is unavailable")
        if not same_user:
            continue
        try:
            command = (process / "cmdline").read_bytes()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise OfficialRecoveryError("same-user process command line is unavailable") from exc
        if b"serve-broker" in command and marker in command:
            matches.append(int(process.name))
    return matches


def _attempt_from_campaign(campaign: dict[str, Any], attempt_id: str) -> dict[str, Any]:
    rows = [row for row in campaign["lanes"] if row.get("attempt_id") == attempt_id]
    if len(rows) != 1 or rows[0].get("rank") != 1 or rows[0].get("lane") not in {"A", "B"}:
        raise OfficialRecoveryError("attempt is not one uniquely assigned rank-1 review lane")
    return rows[0]


def issue_official_grant(  # noqa: PLR0912, PLR0915
    root: Path,
    campaign_path: Path,
    bindings: Path,
    cache: Path,
    ledger: Path,
    packets: Path,
    execution_root: Path,
    attempt_id: str,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Authenticate official custody, derive the failed transition, archive, append grant."""
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    extension_profile_sha256 = authenticate_extension_profile(root)
    # Authenticate the whole official custody chain before examining or writing
    # recovery state. Path identity is checked against the ledger genesis below.
    campaign, campaign_raw, custody, _ = run_v1._custody(
        root, campaign_path, bindings, cache, ledger, packets
    )
    private = run_v1.campaign_v1._private_root(ledger)
    with run_v1.campaign_v1._ledger_lock(private), run_v1._locked_slots(execution_root) as slots:
        current = run_v1._extended_ledger(private, root)
        genesis, _ = run_v1.campaign_v1._json(private / "ledger-genesis.json", modes={0o400})
        canonical_path = str(Path(genesis["campaign_manifest_path"]).resolve(strict=True))
        # Exact-path/hash rejection happens before archive, grant, slot, or claim writes.
        validate_official_campaign_preflight(
            campaign_path, canonical_path, campaign_raw, genesis["campaign_manifest_sha256"]
        )
        lane = _attempt_from_campaign(campaign, attempt_id)
        authorization = current.get("authorization")
        if not isinstance(authorization, dict):
            raise OfficialRecoveryError("no current official authorization")
        run_v1._authorization(current, moment)
        attestation = run_v1._runtime_attestation(root, execution_root)
        installation = run_v1._installed_agent(root, execution_root)
        attestation, _ = run_v1._runtime_boundary(
            root, execution_root, current, attestation, installation
        )
        receipt_path = Path(attestation["runtime_custody_receipt_path"])
        receipt_raw = _private_file(receipt_path)
        receipt = json.loads(receipt_raw)
        path_pairs = {
            "campaign": (campaign_path, receipt["campaign_path"]),
            "source": (bindings, receipt["source_bindings_path"]),
            "cache": (cache, receipt["cache"]["cache_root"]),
            "ledger": (ledger, receipt["ledger_root"]),
            "packets": (packets, receipt["packets"]["packets_root"]),
        }
        for name, (caller, authenticated) in path_pairs.items():
            if str(caller.resolve(strict=True)) != str(Path(authenticated).resolve(strict=True)):
                raise OfficialRecoveryError(f"caller {name} path differs from runtime custody")
        if _sha(receipt_raw) != attestation["runtime_custody_receipt_sha256"]:
            raise OfficialRecoveryError("runtime custody receipt hash differs from attestation")
        allowed = [row for row in authorization["lanes"] if row.get("attempt_id") == attempt_id]
        if len(allowed) != 1 or current["states"].get(attempt_id) != "operational_failed":
            raise OfficialRecoveryError("attempt is not a uniquely authorized failed lane")
        prior_rows = [event for event in current["events"] if event.get("attempt_id") == attempt_id]
        if len(prior_rows) != 1 or prior_rows[0].get("kind") != "operational_failed":
            raise OfficialRecoveryError("attempt history is not exactly one pre-readiness failure")
        failure = prior_rows[0]
        failure_raw_path = (
            private / "events" / f"{failure['sequence']:06d}-operational_failed-{attempt_id}.json"
        )
        failure_raw = _private_file(failure_raw_path)
        try:
            failure_disk = json.loads(failure_raw)
        except ValueError as exc:
            raise OfficialRecoveryError("failed event evidence is malformed") from exc
        if failure_disk != failure or failure_disk.get("entry_hash") != failure.get("entry_hash"):
            raise OfficialRecoveryError("failed event file differs from validated official ledger")
        attempt_root = execution_root / "attempts" / attempt_id
        if attempt_id in current["launched_attempts"] or attempt_id in current["native_results"]:
            raise OfficialRecoveryError("official ledger contains launch or native-result evidence")
        if any(
            event.get("attempt_id") == attempt_id
            and event.get("kind")
            in {"prepared", "launch_claimed", "native_result", "pending", "completed"}
            for event in current["events"]
        ):
            raise OfficialRecoveryError(
                "attempt has a prepare, launch, result, or completion event"
            )
        if (
            (attempt_root / "native-state.json").exists()
            or (attempt_root / "pending-result.json").exists()
            or (attempt_root / "session-audit.json").exists()
        ):
            raise OfficialRecoveryError(
                "attempt contains native, pending, or reviewer-session state"
            )
        slot = slots / f"{attempt_id}.json"
        if slot.exists() or slot.is_symlink():
            raise OfficialRecoveryError("attempt still has a durable slot claim")
        runtime_base = Path(f"/tmp/ground-truth-review-v1-{os.getuid()}")
        socket_path = (
            runtime_base
            / "sockets"
            / (hashlib.sha256(attempt_id.encode()).hexdigest()[:24] + ".sock")
        )
        registry_root = runtime_base / "registry"
        if socket_path.exists() or socket_path.is_symlink():
            raise OfficialRecoveryError("attempt broker socket still exists")
        registry_hits = []
        if registry_root.exists():
            for registry_path in registry_root.glob("*.json"):
                raw = _private_file(registry_path)
                try:
                    value = json.loads(raw)
                except ValueError as exc:
                    raise OfficialRecoveryError("broker registry is malformed") from exc
                if value.get("attempt_id") == attempt_id:
                    registry_hits.append(registry_path.name)
        if registry_hits:
            raise OfficialRecoveryError("attempt broker registry still exists")
        active_brokers = _active_broker_processes(attempt_id)
        if active_brokers:
            raise OfficialRecoveryError("attempt broker process is still alive")
        reason = failure.get("reason")
        if reason == "runtime custody paths or profile changed":
            phase = "prebinding"
            kinds = {"failed_event", "no_launch_census", "cleanup_inventory"}
        elif reason == "broker failed before readiness":
            phase = "binding_created_broker_not_ready"
            kinds = {
                "failed_event",
                "binding",
                "broker_log",
                "no_launch_census",
                "cleanup_inventory",
            }
        else:
            raise OfficialRecoveryError("failure reason is outside the published recovery policy")
        if (lane["lane"] == "A" and phase != "prebinding") or (
            lane["lane"] == "B" and phase != "binding_created_broker_not_ready"
        ):
            raise OfficialRecoveryError("failure phase does not match the assigned lane policy")
        evidence: dict[str, bytes] = {"failed_event": failure_raw}
        if phase != "prebinding":
            evidence["binding"] = _private_file(attempt_root / "binding.json")
            stdout = _private_file(attempt_root / "logs" / "broker.stdout")
            stderr = _private_file(attempt_root / "logs" / "broker.stderr")
            evidence["broker_log"] = canonical_json(
                {
                    "stdout_base64": base64.b64encode(stdout).decode("ascii"),
                    "stdout_sha256": _sha(stdout),
                    "stderr_base64": base64.b64encode(stderr).decode("ascii"),
                    "stderr_sha256": _sha(stderr),
                }
            )
        census = {
            "ledger_head": current["head"],
            "attempt_events": prior_rows,
            "prepared_absent": True,
            "launch_claim_absent": True,
            "native_result_absent": True,
            "pending_absent": True,
            "completed_absent": True,
            "submission_absent": True,
            "reviewer_interaction_absent": True,
        }
        cleanup = {
            "slot_absent": True,
            "socket_absent": True,
            "registry_absent": True,
            "active_broker_processes": active_brokers,
            "native_state_absent": True,
            "pending_state_absent": True,
        }
        evidence["no_launch_census"] = canonical_json(census)
        evidence["cleanup_inventory"] = canonical_json(cleanup)
        if set(evidence) != kinds:
            raise OfficialRecoveryError(
                "derived evidence does not match the selected failure contract"
            )
        # Retain official event lineage in the grant. The custody receipt and
        # validators provide the source, packet, runtime and profile bindings.
        authorization_expiry = authorization["expires_at"]
        source_hash = custody["source"]["sha256"]
        packet_hash = custody["packet"]["publication_entry_hash"]
        expected = {
            "campaign_id": campaign["id"],
            "campaign_manifest_sha256": _sha(campaign_raw),
            "canonical_campaign_path": canonical_path,
            "corpus_sha256": campaign["corpus"]["manifest_sha256"],
            "attempt_id": attempt_id,
            "lane": lane["lane"],
            "reviewer_id": lane["reviewer"]["name"],
            "source_bindings_sha256": source_hash,
            "packet_publication_entry_hash": packet_hash,
            "runtime_attestation_entry_hash": attestation["entry_hash"],
            "production_profile_sha256": extension_profile_sha256,
            "prior_authorization_entry_hash": authorization["entry_hash"],
            "prior_authorization_expires_at": authorization_expiry,
            "failed_event_entry_hash": failure["entry_hash"],
            "failed_event_kind": "operational_failed",
            "failure_phase": phase,
            "failure_reason": reason,
        }
        recovery_root = execution_root / "recovery"
        recovery_root.mkdir(mode=0o700, exist_ok=True)
        if recovery_root.is_symlink() or stat.S_IMODE(recovery_root.stat().st_mode) != 0o700:
            raise OfficialRecoveryError("recovery root must be a private directory")
        archive = recovery_root / "evidence"
        inventory = _atomic_archive(archive, attempt_id, evidence)
        record = {
            **expected,
            "evidence": inventory,
            "no_launch_proof": dict.fromkeys(protocol._PROOF_KEYS, True),
            "custody_inventory_sha256": _sha(
                canonical_json(
                    {
                        "campaign": _sha(campaign_raw),
                        "source": source_hash,
                        "packet": packet_hash,
                        "runtime": attestation["entry_hash"],
                        "official_ledger_head": current["head"],
                        "evidence": inventory,
                    }
                )
            ),
            "issued_at": moment.isoformat().replace("+00:00", "Z"),
            "expires_at": min(
                moment + timedelta(hours=24),
                datetime.fromisoformat(authorization_expiry.replace("Z", "+00:00")),
            )
            .isoformat()
            .replace("+00:00", "Z"),
        }
        grant = protocol.append_grant(
            execution_root / "recovery" / "ledger", record, expected=expected, now=moment
        )
        return {
            "grant": grant,
            "official_ledger_head": current["head"],
            "evidence_count": len(inventory),
            "operational_prepare_performed": False,
        }


def validate_official_grants(
    root: Path,
    execution_root: Path,
    expected_by_attempt: dict[str, dict[str, Any]],
    *,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Validate extension grants and ensure every referenced archived byte is intact."""
    del root
    moment = now or datetime.now(timezone.utc)
    rows = protocol.validate_chain(
        execution_root / "recovery" / "ledger", expected_by_attempt=expected_by_attempt, now=moment
    )
    for row in rows:
        for item in row["evidence"]:
            path = execution_root / "recovery" / item["archive_path"]
            raw = _private_file(path)
            if _sha(raw) != item["sha256"]:
                raise OfficialRecoveryError("archived recovery evidence hash mismatch")
            if item["kind"] == "failed_event":
                try:
                    event = json.loads(raw)
                except ValueError as exc:
                    raise OfficialRecoveryError("archived failed event is malformed") from exc
                if event.get("entry_hash") != row["failed_event_entry_hash"]:
                    raise OfficialRecoveryError("archived failed event hash binding mismatch")
    return rows


_RETRY_PROTOCOL = "ground-truth-review-canary-pre-readiness-retry-run-v1"
_RETRY_DOMAIN = (_RETRY_PROTOCOL + "\0").encode()
_RETRY_EVENTS = {"retry_consumed", "retry_prepared", "retry_failed"}
_RETRY_COMMON = {
    "schema_version",
    "protocol",
    "sequence",
    "kind",
    "previous_hash",
    "entry_hash",
}
_RETRY_FIELDS = {
    "retry_consumed": _RETRY_COMMON
    | {
        "attempt_id",
        "grant_entry_hash",
        "retry_ordinal",
        "run_id",
        "allocated_at",
    },
    "retry_prepared": _RETRY_COMMON
    | {
        "attempt_id",
        "grant_entry_hash",
        "run_id",
        "binding_sha256",
        "broker_bundle_lease_receipt_sha256",
        "runtime_attestation_entry_hash",
        "prepared_at",
    },
    "retry_failed": _RETRY_COMMON
    | {
        "attempt_id",
        "grant_entry_hash",
        "run_id",
        "failure",
        "failed_at",
    },
}
_RETRY_STATE_REQUIRED = {
    "schema_version",
    "protocol",
    "phase",
    "run_id",
    "retry_ordinal",
    "campaign_attempt_id",
    "rank",
    "lane",
    "binding",
    "binding_sha256",
    "broker_bundle_lease_receipt_sha256",
    "broker_pid",
    "broker_start_identity",
    "socket",
    "registry",
    "runtime_attestation_entry_hash",
    "recovery_grant_entry_hash",
    "prepared_at",
}


def validate_retry_state(state: dict[str, Any]) -> None:
    """Validate the overlay's broker-ready state against its published schema."""
    if set(state) != _RETRY_STATE_REQUIRED:
        raise OfficialRecoveryError("retry state fields do not match the published schema")
    try:
        if str(uuid.UUID(state["run_id"])) != state["run_id"]:
            raise ValueError("noncanonical UUID")
    except (ValueError, TypeError, AttributeError) as exc:
        raise OfficialRecoveryError("retry run id is invalid") from exc
    if (
        state["schema_version"] != 1
        or state["protocol"] != _RETRY_PROTOCOL
        or state["phase"] != "broker_ready"
        or state["retry_ordinal"] != 1
        or not isinstance(state["campaign_attempt_id"], str)
        or not protocol._ATTEMPT.fullmatch(state["campaign_attempt_id"])
        or state["lane"] not in {"A", "B"}
        or not state["campaign_attempt_id"].endswith("-" + state["lane"])
        or state["rank"] != 1
        or isinstance(state["rank"], bool)
        or not isinstance(state["broker_pid"], int)
        or isinstance(state["broker_pid"], bool)
        or state["broker_pid"] < 1
        or not all(
            isinstance(state[key], str) and state[key]
            for key in ("binding", "broker_start_identity", "socket", "registry")
        )
    ):
        raise OfficialRecoveryError("retry broker-ready state is invalid")
    for key in ("binding_sha256", "runtime_attestation_entry_hash", "recovery_grant_entry_hash"):
        protocol._hash(state[key], key)
    protocol._hash(
        state["broker_bundle_lease_receipt_sha256"], "broker_bundle_lease_receipt_sha256"
    )
    protocol._time(state["prepared_at"], "prepared_at")


_GRANT_BINDING_KEYS = (
    "campaign_id",
    "campaign_manifest_sha256",
    "canonical_campaign_path",
    "corpus_sha256",
    "attempt_id",
    "lane",
    "reviewer_id",
    "source_bindings_sha256",
    "packet_publication_entry_hash",
    "runtime_attestation_entry_hash",
    "production_profile_sha256",
    "prior_authorization_entry_hash",
    "prior_authorization_expires_at",
    "failed_event_entry_hash",
    "failed_event_kind",
    "failure_phase",
    "failure_reason",
)


def _retry_hash(value: dict[str, Any]) -> str:
    body = {key: item for key, item in value.items() if key != "entry_hash"}
    return _sha(_RETRY_DOMAIN + canonical_json(body))


def _retry_rows(  # noqa: PLR0912, PLR0915
    journal: Path, *, create: bool
) -> list[dict[str, Any]]:
    fd = protocol._open_chain_root(journal, create=create)
    try:
        names = sorted(os.listdir(fd))  # noqa: PTH208
        rows = []
        previous = "sha256:" + "0" * 64
        consumed: set[str] = set()
        run_ids: set[str] = set()
        for index, name in enumerate(names, 1):
            if not name.startswith(f"{index:06d}-") or not name.endswith(".json"):
                raise OfficialRecoveryError("retry journal sequence is invalid")
            entry = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
            try:
                status = os.fstat(entry)
                if not stat.S_ISREG(status.st_mode) or stat.S_IMODE(status.st_mode) != 0o400:
                    raise OfficialRecoveryError("retry journal entry is unsafe")
                chunks = []
                while True:
                    block = os.read(entry, 1024 * 1024)
                    if not block:
                        break
                    chunks.append(block)
                raw = b"".join(chunks)
                row = json.loads(raw)
                if canonical_json(row) != raw:
                    raise OfficialRecoveryError("retry journal entry is not canonical JSON")
            finally:
                os.close(entry)
            if not isinstance(row, dict):
                raise OfficialRecoveryError("retry journal entry is malformed")
            run_id = row.get("run_id")
            try:
                valid_run_id = isinstance(run_id, str) and str(uuid.UUID(run_id)) == run_id
            except (ValueError, AttributeError):
                valid_run_id = False
            if (
                name != f"{index:06d}-{row.get('kind')}-{row.get('run_id')}.json"
                or row.get("schema_version") != 1
                or row.get("protocol") != _RETRY_PROTOCOL
                or row.get("sequence") != index
                or row.get("previous_hash") != previous
                or row.get("entry_hash") != _retry_hash(row)
                or row.get("kind") not in _RETRY_EVENTS
                or set(row) != _RETRY_FIELDS.get(row.get("kind"))
                or not valid_run_id
                or not isinstance(row.get("attempt_id"), str)
                or not protocol._ATTEMPT.fullmatch(row["attempt_id"])
                or row.get("retry_ordinal", 1) != 1
            ):
                raise OfficialRecoveryError("retry journal hash chain is invalid")
            if row["kind"] == "retry_consumed":
                if run_id in run_ids:
                    raise OfficialRecoveryError("retry journal reuses a run identifier")
                run_ids.add(run_id)
            protocol._hash(row["grant_entry_hash"], "grant_entry_hash")
            timestamp_key = {
                "retry_consumed": "allocated_at",
                "retry_prepared": "prepared_at",
                "retry_failed": "failed_at",
            }[row["kind"]]
            protocol._time(row[timestamp_key], timestamp_key)
            if row["kind"] == "retry_prepared":
                protocol._hash(row["binding_sha256"], "binding_sha256")
                protocol._hash(
                    row["broker_bundle_lease_receipt_sha256"],
                    "broker_bundle_lease_receipt_sha256",
                )
                protocol._hash(
                    row["runtime_attestation_entry_hash"], "runtime_attestation_entry_hash"
                )
            if row["kind"] == "retry_failed" and (
                not isinstance(row["failure"], str) or len(row["failure"]) > 512
            ):
                raise OfficialRecoveryError("retry failure record is invalid")
            if row["kind"] == "retry_consumed":
                if row["attempt_id"] in consumed:
                    raise OfficialRecoveryError("recovery grant was already consumed")
                consumed.add(row["attempt_id"])
            elif row["attempt_id"] not in consumed or any(
                prior.get("attempt_id") == row["attempt_id"]
                and prior.get("kind") in {"retry_prepared", "retry_failed"}
                for prior in rows
            ):
                raise OfficialRecoveryError("retry journal has an invalid terminal transition")
            rows.append(row)
            previous = row["entry_hash"]
        return rows
    finally:
        os.close(fd)


def _append_retry_event(journal: Path, kind: str, fields: dict[str, Any]) -> dict[str, Any]:
    if kind not in _RETRY_EVENTS:
        raise OfficialRecoveryError("unsupported retry journal transition")
    rows = _retry_rows(journal, create=True)
    if kind == "retry_consumed" and any(
        row.get("kind") == "retry_consumed" and row.get("attempt_id") == fields.get("attempt_id")
        for row in rows
    ):
        raise OfficialRecoveryError("recovery grant is already consumed")
    sequence = len(rows) + 1
    record = {
        "schema_version": 1,
        "protocol": _RETRY_PROTOCOL,
        "sequence": sequence,
        "kind": kind,
        "previous_hash": rows[-1]["entry_hash"] if rows else "sha256:" + "0" * 64,
        **fields,
    }
    record["entry_hash"] = _retry_hash(record)
    if set(record) != _RETRY_FIELDS[kind]:
        raise OfficialRecoveryError("retry journal fields do not match the transition schema")
    fd = protocol._open_chain_root(journal, create=False)
    try:
        name = f"{sequence:06d}-{kind}-{record['run_id']}.json"
        output = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o400,
            dir_fd=fd,
        )
        with os.fdopen(output, "wb") as stream:
            stream.write(canonical_json(record))
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(fd)
    except OSError as exc:
        raise OfficialRecoveryError("retry journal append failed safely") from exc
    finally:
        os.close(fd)
    return record


def prepare_authorized_retry(  # noqa: PLR0912, PLR0915
    root: Path,
    campaign_path: Path,
    bindings: Path,
    cache: Path,
    ledger: Path,
    packets: Path,
    execution_root: Path,
    failed_attempt_id: str,
    *,
    broker_lease_receipt: Path | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Consume one validated grant, allocate a fresh run id, and prepare its broker.

    This versioned path never edits the original campaign lane/event. Only this
    function allocates a run id, after complete custody and canonical path checks.
    """
    # Fail before any durable claim/consumption until the independently reviewed
    # broker bundle publishes its receipt/lease implementation.
    if broker_lease_receipt is None:
        raise OfficialRecoveryError("a validated broker bundle lease is required")
    # The missing sibling validator must reject before any run journal, slot,
    # binding, or attempt claim can be created or consumed.
    _broker_bundle_api()
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    extension_profile_sha256 = authenticate_extension_profile(root)
    campaign, campaign_raw, custody, _ = run_v1._custody(
        root, campaign_path, bindings, cache, ledger, packets
    )
    private = run_v1.campaign_v1._private_root(ledger)
    recovery_root = execution_root / "recovery"
    journal = recovery_root / "runs" / "journal"
    with run_v1.campaign_v1._ledger_lock(private), run_v1._locked_slots(execution_root) as slots:
        current = run_v1._extended_ledger(private, root)
        genesis, _ = run_v1.campaign_v1._json(private / "ledger-genesis.json", modes={0o400})
        canonical_path = str(Path(genesis["campaign_manifest_path"]).resolve(strict=True))
        validate_official_campaign_preflight(
            campaign_path, canonical_path, campaign_raw, genesis["campaign_manifest_sha256"]
        )
        authorization = run_v1._authorization(current, moment)
        lane = _attempt_from_campaign(campaign, failed_attempt_id)
        attestation = run_v1._runtime_attestation(root, execution_root)
        installation = run_v1._installed_agent(root, execution_root)
        attestation, _ = run_v1._runtime_boundary(
            root, execution_root, current, attestation, installation
        )
        receipt_raw = _private_file(Path(attestation["runtime_custody_receipt_path"]))
        receipt = json.loads(receipt_raw)
        paths = {
            "campaign": (campaign_path, receipt["campaign_path"]),
            "source": (bindings, receipt["source_bindings_path"]),
            "cache": (cache, receipt["cache"]["cache_root"]),
            "ledger": (ledger, receipt["ledger_root"]),
            "packets": (packets, receipt["packets"]["packets_root"]),
        }
        for name, (caller, authenticated) in paths.items():
            if str(caller.resolve(strict=True)) != str(Path(authenticated).resolve(strict=True)):
                raise OfficialRecoveryError(f"caller {name} path differs from runtime custody")
        if _sha(receipt_raw) != attestation["runtime_custody_receipt_sha256"]:
            raise OfficialRecoveryError("runtime custody receipt hash differs from attestation")
        if current["states"].get(failed_attempt_id) != "operational_failed":
            raise OfficialRecoveryError("the original failed campaign event is no longer current")
        old_events = [
            event for event in current["events"] if event.get("attempt_id") == failed_attempt_id
        ]
        if len(old_events) != 1 or old_events[0].get("kind") != "operational_failed":
            raise OfficialRecoveryError("the original failed attempt history changed")
        failed_event = old_events[0]
        lane_auth = [
            row for row in authorization["lanes"] if row.get("attempt_id") == failed_attempt_id
        ]
        if len(lane_auth) != 1 or failed_attempt_id in current["launched_attempts"]:
            raise OfficialRecoveryError("the failed lane is no longer eligible for one recovery")
        if failed_attempt_id in current["native_results"]:
            raise OfficialRecoveryError("native result exists for the failed lane")
        if (execution_root / "attempts" / failed_attempt_id / "native-state.json").exists():
            raise OfficialRecoveryError("native state exists for the failed lane")
        grant_path = recovery_root / "ledger"
        grant_rows = protocol._load_chain(grant_path)
        grants_by_id = {row["attempt_id"]: row for row in grant_rows}
        grant = grants_by_id.get(failed_attempt_id)
        if grant is None:
            raise OfficialRecoveryError("no recovery grant exists for the failed lane")
        expected_current = {
            "campaign_id": campaign["id"],
            "campaign_manifest_sha256": _sha(campaign_raw),
            "canonical_campaign_path": canonical_path,
            "corpus_sha256": campaign["corpus"]["manifest_sha256"],
            "attempt_id": failed_attempt_id,
            "lane": lane["lane"],
            "reviewer_id": lane["reviewer"]["name"],
            "source_bindings_sha256": custody["source"]["sha256"],
            "packet_publication_entry_hash": custody["packet"]["publication_entry_hash"],
            "runtime_attestation_entry_hash": attestation["entry_hash"],
            "production_profile_sha256": extension_profile_sha256,
            "prior_authorization_entry_hash": authorization["entry_hash"],
            "prior_authorization_expires_at": authorization["expires_at"],
            "failed_event_entry_hash": failed_event["entry_hash"],
            "failed_event_kind": "operational_failed",
            "failure_phase": grant["failure_phase"],
            "failure_reason": failed_event["reason"],
        }
        if any(grant.get(key) != value for key, value in expected_current.items()):
            raise OfficialRecoveryError("recovery grant no longer matches official custody")
        chain_expected = {
            row["attempt_id"]: {key: row[key] for key in _GRANT_BINDING_KEYS} for row in grant_rows
        }
        valid_grants = validate_official_grants(root, execution_root, chain_expected, now=moment)
        grant = next(row for row in valid_grants if row["attempt_id"] == failed_attempt_id)
        archived_census = next(
            item for item in grant["evidence"] if item["kind"] == "no_launch_census"
        )
        census = json.loads(_private_file(recovery_root / archived_census["archive_path"]))
        if census.get("ledger_head") != current["head"]:
            raise OfficialRecoveryError(
                "official ledger head changed since recovery evidence review"
            )
        slot = slots / f"{failed_attempt_id}.json"
        if slot.exists() or slot.is_symlink():
            raise OfficialRecoveryError("failed attempt still owns a durable slot claim")
        attempt_root = execution_root / "attempts" / failed_attempt_id
        if any(
            (attempt_root / name).exists()
            for name in ("native-state.json", "pending-result.json", "session-audit.json")
        ):
            raise OfficialRecoveryError("failed attempt has native, pending, or reviewer state")
        process_matches = _active_broker_processes(failed_attempt_id)
        if process_matches:
            raise OfficialRecoveryError("failed attempt broker is still alive")
        runs_root = recovery_root / "runs"
        runs_root.mkdir(mode=0o700, exist_ok=True)
        if runs_root.is_symlink() or stat.S_IMODE(runs_root.stat().st_mode) != 0o700:
            raise OfficialRecoveryError("retry run root is not private")
        journal_rows = _retry_rows(journal, create=True)
        if any(
            row.get("kind") == "retry_consumed" and row.get("attempt_id") == failed_attempt_id
            for row in journal_rows
        ):
            raise OfficialRecoveryError("recovery grant is already consumed")
        run_id = str(uuid.uuid4())
        run_root = runs_root / run_id
        _append_retry_event(
            journal,
            "retry_consumed",
            {
                "attempt_id": failed_attempt_id,
                "grant_entry_hash": grant["entry_hash"],
                "retry_ordinal": 1,
                "run_id": run_id,
                "allocated_at": moment.isoformat().replace("+00:00", "Z"),
            },
        )
        rank = lane["rank"]
        lane_name = lane["lane"]
        pid = None
        process_identity = None
        registry = None
        socket_path = None
        try:
            run_root.mkdir(mode=0o700)
            claims = [
                path for path in slots.iterdir() if path.name != ".lock" and path.suffix == ".json"
            ]
            if len(claims) >= run_v1._MAX_ACTIVE:
                raise OfficialRecoveryError("global active lane bound exceeded")
            run_v1._atomic(
                slots / f"{run_id}.json",
                {
                    "schema_version": 1,
                    "attempt_id": run_id,
                    "owner_pid": os.getpid(),
                    "owner_start_identity": run_v1._proc_identity(os.getpid()),
                    "rank": rank,
                    "lane": lane_name,
                    "broker_pid": None,
                    "broker_start_identity": None,
                    "claimed_at": run_v1._timestamp(moment),
                },
            )
            submit_v1 = run_v1.submit_v1
            submit_v1.prepare_binding(
                root,
                campaign_path,
                bindings,
                cache,
                ledger,
                packets,
                rank,
                lane_name,
                failed_attempt_id,
                run_root,
                runtime_attestation_entry_hash=attestation["entry_hash"],
                runtime_custody_receipt_path=Path(attestation["runtime_custody_receipt_path"]),
                runtime_custody_receipt_sha256=attestation["runtime_custody_receipt_sha256"],
                generation=1,
                started_at=moment,
            )
            record = submit_v1.load_bindings(run_root / "binding.json").records[0]
            binding_sha256 = _sha(_private_file(run_root / "binding.json"))
            launch_profile_sha256 = _sha(
                _profile_file(root / "benchmarks/real_world/production_v1/checksums-v1.json")
            )
            # Keep the lease object strongly referenced for the complete broker
            # startup. The bundle integration must extend this lifetime through
            # escrow finalization before operational use is enabled.
            broker_bundle_lease = acquire_broker_bundle_lease(
                root=root,
                lease_receipt=broker_lease_receipt,
                runtime_attestation=attestation,
                binding_sha256=binding_sha256,
                launch_profile_sha256=launch_profile_sha256,
            )
            if broker_bundle_lease is None:
                raise OfficialRecoveryError("broker bundle lease was not acquired")
            lease_receipt_sha256 = _sha(_private_file(broker_lease_receipt))
            logs = run_root / "logs"
            logs.mkdir(mode=0o700)
            socket_path = run_v1._broker_socket_path(run_id)
            registry = run_v1._registry(run_root / "packet", record, socket_path)
            deadline = int(moment.timestamp() * 1000) + run_v1._MAX_WALL * 1000
            output = os.open(logs / "broker.stdout", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            error = os.open(logs / "broker.stderr", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                pid = launch_broker_with_bundle_lease(
                    broker_bundle_lease,
                    root=root,
                    run_id=run_id,
                    binding_path=run_root / "binding.json",
                    binding_sha256=binding_sha256,
                    launch_profile_sha256=launch_profile_sha256,
                    socket_path=socket_path,
                    deadline_unix_ms=deadline,
                    runtime_attestation=attestation,
                    ledger_root=ledger,
                    execution_root=execution_root,
                    stdout_fd=output,
                    stderr_fd=error,
                    hold_until="escrow_finalized",
                )
            finally:
                os.close(output)
                os.close(error)
            process_identity = run_v1._proc_identity(pid)
            run_v1._slot_update_broker(execution_root, run_id, pid, process_identity)
            run_v1._wait_socket(socket_path, pid, process_identity)
            state = {
                "schema_version": 1,
                "protocol": _RETRY_PROTOCOL,
                "phase": "broker_ready",
                "run_id": run_id,
                "retry_ordinal": 1,
                "campaign_attempt_id": failed_attempt_id,
                "rank": rank,
                "lane": lane_name,
                "binding": str(run_root / "binding.json"),
                "binding_sha256": binding_sha256,
                "broker_bundle_lease_receipt_sha256": lease_receipt_sha256,
                "broker_pid": pid,
                "broker_start_identity": process_identity,
                "socket": str(socket_path),
                "registry": str(registry),
                "runtime_attestation_entry_hash": attestation["entry_hash"],
                "recovery_grant_entry_hash": grant["entry_hash"],
                "prepared_at": moment.isoformat().replace("+00:00", "Z"),
            }
            validate_retry_state(state)
            run_v1._atomic(run_root / "retry-state.json", state)
            _append_retry_event(
                journal,
                "retry_prepared",
                {
                    "attempt_id": failed_attempt_id,
                    "grant_entry_hash": grant["entry_hash"],
                    "run_id": run_id,
                    "binding_sha256": state["binding_sha256"],
                    "broker_bundle_lease_receipt_sha256": lease_receipt_sha256,
                    "runtime_attestation_entry_hash": attestation["entry_hash"],
                    "prepared_at": moment.isoformat().replace("+00:00", "Z"),
                },
            )
        except BaseException as exc:
            if pid is not None and process_identity is not None:
                run_v1._terminate(pid, process_identity)
            if registry is not None:
                registry.unlink(missing_ok=True)
            if socket_path is not None:
                socket_path.unlink(missing_ok=True)
            with run_v1.contextlib.suppress(OSError):
                (slots / f"{run_id}.json").unlink(missing_ok=True)
            _append_retry_event(
                journal,
                "retry_failed",
                {
                    "attempt_id": failed_attempt_id,
                    "grant_entry_hash": grant["entry_hash"],
                    "run_id": run_id,
                    "failure": str(exc)[:512],
                    "failed_at": moment.isoformat().replace("+00:00", "Z"),
                },
            )
            raise
        return {
            "run_id": run_id,
            "campaign_attempt_id": failed_attempt_id,
            "retry_ordinal": 1,
            "broker_ready": True,
            "native_or_model_launch_performed": False,
            "journal_head": _retry_rows(journal, create=False)[-1]["entry_hash"],
        }


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("issue-grant", "prepare-retry"):
        item = sub.add_parser(command)
        for name in ("campaign", "bindings", "cache", "ledger-root", "packets", "execution-root"):
            item.add_argument("--" + name, type=Path, required=True)
        item.add_argument("--attempt-id", required=True)
        if command == "prepare-retry":
            item.add_argument("--broker-lease-receipt", type=Path, required=True)
    args = parser.parse_args()
    call_args = (
        args.root,
        args.campaign,
        args.bindings,
        args.cache,
        args.ledger_root,
        args.packets,
        args.execution_root,
        args.attempt_id,
    )
    if args.command == "prepare-retry":
        result = prepare_authorized_retry(
            *call_args, broker_lease_receipt=args.broker_lease_receipt
        )
    else:
        result = issue_official_grant(*call_args)
    print(canonical_json(result).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
