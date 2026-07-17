from __future__ import annotations

import hashlib
import json
import socket
import stat
import struct
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from collections.abc import Sequence

import pytest
from benchmarks.real_world import pilot_submit_v3 as submit
from benchmarks.real_world.ground_truth_v2 import GroundTruthError
from benchmarks.real_world.ground_truth_v2.evidence import (
    GitEvidenceValidator,
    collision_resistant_cache_name,
)
from benchmarks.real_world.ground_truth_v2.schema import (
    Actor,
    ResourceLimits,
    SnapshotBinding,
    canonical_json,
)

BASE = "1" * 40
TARGET = "2" * 40
BASE_BLOB = "3" * 40
TARGET_BLOB = "4" * 40
BASE_TREE = "5" * 40
TARGET_TREE = "6" * 40
START = datetime(2026, 1, 1, tzinfo=timezone.utc)
END = datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc)


class FakeEvidence:
    def __init__(self, *, reject: bool = False) -> None:
        self.reject = reject
        self.changed = 0
        self.edges = 0

    def validate_changed_location(self, _location: object) -> None:
        self.changed += 1
        if self.reject:
            raise GroundTruthError("changed-symbol location does not overlap changed hunk")

    def validate_location(self, _location: object) -> None:
        if self.reject:
            raise GroundTruthError("location is invalid")

    def validate_edges(self, _edges: object) -> None:
        self.edges += 1
        if self.reject:
            raise GroundTruthError("evidence is invalid")


def _private(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True)
    return path


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _payload(path: Path, relative: str, raw: bytes) -> dict[str, object]:
    target = path / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    target.chmod(0o444)
    return {"path": relative, "bytes": len(raw), "sha256": _sha(raw)}


def _packet_and_record(
    tmp_path: Path,
    *,
    attempts: int = 3,
    baseline_commit: str = BASE,
    target_commit: str = TARGET,
    baseline_tree: str = BASE_TREE,
    target_tree: str = TARGET_TREE,
    baseline_blob: str = BASE_BLOB,
    target_blob: str = TARGET_BLOB,
    baseline_content: bytes = b"old\n",
    target_content: bytes = b"new\n",
) -> submit.SubmissionBinding:
    packet = _private(tmp_path / "packet").resolve()
    cache = _private(tmp_path / "cache").resolve()
    escrow = _private(tmp_path / "escrow") / "review.json"
    payloads = [
        _payload(packet, "baseline/src/main.py", baseline_content),
        _payload(packet, "target/src/main.py", target_content),
    ]
    policy_raw: dict[str, bytes] = {
        "review_prompt": b"review prompt v3\n",
        "model_policy": b'{"model":"luna"}\n',
        "tool_policy": b'{"tool":"submit"}\n',
        "source_policy": b'{"source":"packet"}\n',
    }
    policy_paths = {name: f"policies/{name.replace('_', '-')}.txt" for name in policy_raw}
    for name, raw in policy_raw.items():
        payloads.append(_payload(packet, policy_paths[name], raw))
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "id": "test-packet",
        "repository": "owner/repo",
        "pr": 7,
        "baseline_commit": baseline_commit,
        "target_commit": target_commit,
        "baseline_tree": baseline_tree,
        "target_tree": target_tree,
        "snapshots": {
            "baseline": {
                "files": [
                    {
                        "path": "src/main.py",
                        "mode": "100644",
                        "oid": baseline_blob,
                        "bytes": len(baseline_content),
                        "sha256": _sha(baseline_content),
                    }
                ]
            },
            "target": {
                "files": [
                    {
                        "path": "src/main.py",
                        "mode": "100644",
                        "oid": target_blob,
                        "bytes": len(target_content),
                        "sha256": _sha(target_content),
                    }
                ]
            },
        },
        "payload_files": payloads,
        "packet_root_sha256": "",
    }
    manifest["packet_root_sha256"] = submit._manifest_root(manifest)
    manifest_raw = canonical_json(manifest)
    manifest_path = packet / "packet-manifest.json"
    manifest_path.write_bytes(manifest_raw)
    manifest_path.chmod(0o444)
    _, inventory_digest = submit._inventory(manifest)
    inputs = [
        submit.AuthenticatedInput(
            name="packet_manifest",
            path=str(manifest_path),
            sha256=_sha(manifest_raw),
            bytes=len(manifest_raw),
            mode=0o444,
        )
    ]
    for name, raw in policy_raw.items():
        inputs.append(
            submit.AuthenticatedInput(
                name=cast("Any", name),
                path=str(packet / policy_paths[name]),
                sha256=_sha(raw),
                bytes=len(raw),
                mode=0o444,
            )
        )
    status = packet.stat()
    return submit.SubmissionBinding(
        schema_version=1,
        attempt_id="attempt-1",
        capability="b" * 64,
        packet_path=str(packet),
        packet_device=status.st_dev,
        packet_inode=status.st_ino,
        packet_manifest_sha256=_sha(manifest_raw),
        packet_root_sha256=cast("str", manifest["packet_root_sha256"]),
        blob_inventory_sha256=inventory_digest,
        authenticated_inputs=tuple(inputs),
        escrow_path=str(escrow.resolve()),
        cache_root=str(cache),
        corpus_id="pilot-v3",
        repository="owner/repo",
        pr=7,
        lane="A",
        snapshots=SnapshotBinding(baseline_commit=baseline_commit, target_commit=target_commit),
        baseline_tree=baseline_tree,
        target_tree=target_tree,
        reviewer=Actor(kind="agent", name="luna-reviewer", version="luna:medium"),
        run=submit.BoundRun(
            prompt_sha256=_sha(policy_raw["review_prompt"]),
            model_policy_sha256=_sha(policy_raw["model_policy"]),
            tool_policy_sha256=_sha(policy_raw["tool_policy"]),
            source_policy_sha256=_sha(policy_raw["source_policy"]),
            started_at=START,
            limits=ResourceLimits(
                max_tokens=100_000,
                max_tool_calls=200,
                max_seconds=1800,
                max_output_bytes=2_097_152,
            ),
        ),
        max_validation_attempts=attempts,
    )


def _location(*, line: int = 1) -> dict[str, object]:
    return {
        "side": "target",
        "path": "src/main.py",
        "start_line": line,
        "end_line": line,
        "symbol": "changed",
    }


def _negative() -> dict[str, object]:
    return {
        "terminal_recommendation": "negative_control",
        "changed_symbols": [{"canonical_name": "module.changed", "location": _location()}],
        "claims": [],
        "unknowns": [],
        "negative_assessment": {
            "changed_symbol_census_complete": True,
            "searched_entrypoint_families": ["http", "sdk"],
            "limitations": ["Static source only."],
        },
        "notes": "No public entrypoint changed.",
    }


def _positive(*, recommendation: str = "include") -> dict[str, object]:
    location = _location()
    return {
        "terminal_recommendation": "positive",
        "changed_symbols": [{"canonical_name": "module.changed", "location": location}],
        "claims": [
            {
                "recommendation": recommendation,
                "summary": "Changed public SDK entrypoint.",
                "entrypoint": {
                    "public_id": "module.changed",
                    "kind": "sdk",
                    "confidence": "confirmed",
                },
                "evidence": [
                    {
                        "relation": "direct",
                        "from_location": location,
                        "to_location": location,
                    }
                ],
            }
        ],
        "unknowns": [],
        "negative_assessment": None,
        "notes": "One public SDK entrypoint changed.",
    }


def _unknown(terminal: str = "unknown") -> dict[str, object]:
    return {
        "terminal_recommendation": terminal,
        "changed_symbols": [],
        "claims": [],
        "unknowns": [
            {
                "category": "dynamic registration",
                "description": "Cannot establish the runtime target statically.",
                "evidence_limit": "Packet has no finite target binding.",
            }
        ],
        "negative_assessment": None,
        "notes": "Bounded unknown.",
    }


def _write_bindings(path: Path, record: submit.SubmissionBinding, *, mode: int = 0o600) -> None:
    payload = submit.SubmissionBindings(
        schema_version=1, protocol="blind-review-submit-v3", records=(record,)
    )
    path.write_bytes(canonical_json(payload.model_dump(mode="json")))
    path.chmod(mode)


@pytest.mark.parametrize("terminal", ["unknown", "not_evaluable"])
def test_draft_terminal_shapes_and_materialization(tmp_path: Path, terminal: str) -> None:
    record = _packet_and_record(tmp_path)
    review, raw = submit.validate_submission(
        _unknown(terminal), record, validator=FakeEvidence(), completed_at=END
    )
    assert review.terminal_recommendation == terminal
    assert review.run.completed_at == END
    assert review.corpus_id == record.corpus_id
    assert review.unknowns[0].unknown_id == "unknown-0000"
    assert raw.endswith(b"\n")


def test_broker_injects_all_identity_oids_ids_ordinals_and_summary(tmp_path: Path) -> None:
    record = _packet_and_record(tmp_path)
    evidence = FakeEvidence()
    review, raw = submit.validate_submission(
        _positive(), record, validator=evidence, completed_at=END
    )
    assert review.snapshots == record.snapshots
    assert review.reviewer == record.reviewer
    assert review.changed_symbols[0].symbol_id == "symbol-0000"
    assert review.changed_symbols[0].location.commit_sha == TARGET
    assert review.changed_symbols[0].location.blob_sha == TARGET_BLOB
    assert review.claims[0].claim_id == "claim-0000"
    assert review.claims[0].evidence[0].ordinal == 0
    assert evidence.changed == evidence.edges == 1
    assert submit.deterministic_summary(review, raw).startswith(
        "SUBMITTED schema=1 lane=A repository=owner/repo pr=7 recommendation=positive"
    )


def test_draft_schema_semantics_inventory_and_evidence_fail_before_publish(tmp_path: Path) -> None:
    record = _packet_and_record(tmp_path)
    extra = _negative()
    extra["repository"] = "model/cannot-bind-this"
    with pytest.raises(submit.SubmissionRejected, match="DRAFT_INVALID"):
        submit.escrow_submission(extra, record, validator=FakeEvidence(), clock=lambda: END)
    with pytest.raises(submit.SubmissionRejected, match="DRAFT_INVALID"):
        submit.escrow_submission(
            _positive(recommendation="exclude"),
            record,
            validator=FakeEvidence(),
            clock=lambda: END,
        )
    missing = _negative()
    cast("dict[str, object]", cast("list[object]", missing["changed_symbols"])[0])["location"] = {
        **_location(),
        "path": "src/missing.py",
    }
    with pytest.raises(submit.SubmissionRejected, match="LOCATION_NOT_IN_BOUND_INVENTORY"):
        submit.escrow_submission(missing, record, validator=FakeEvidence(), clock=lambda: END)
    with pytest.raises(submit.SubmissionRejected, match="EVIDENCE_INVALID"):
        submit.escrow_submission(
            _negative(), record, validator=FakeEvidence(reject=True), clock=lambda: END
        )
    assert not Path(record.escrow_path).exists()


def test_bound_output_limit_rejects_before_publish(tmp_path: Path) -> None:
    record = _packet_and_record(tmp_path)
    tiny_run = record.run.model_copy(
        update={
            "limits": ResourceLimits(
                max_tokens=100_000,
                max_tool_calls=200,
                max_seconds=1800,
                max_output_bytes=1,
            )
        }
    )
    limited = record.model_copy(update={"run": tiny_run})
    with pytest.raises(submit.SubmissionRejected, match="OUTPUT_LIMIT_EXCEEDED"):
        submit.escrow_submission(_negative(), limited, validator=FakeEvidence(), clock=lambda: END)
    assert not Path(limited.escrow_path).exists()


def test_completion_and_publish_deadlines_fail_closed(tmp_path: Path) -> None:
    record = _packet_and_record(tmp_path)
    late = START + timedelta(seconds=record.run.limits.max_seconds, microseconds=1)
    with pytest.raises(submit.SubmissionRejected, match="COMPLETION_TIME_INVALID"):
        submit.validate_submission(
            _negative(), record, validator=FakeEvidence(), completed_at=late
        )

    times = iter([END, START + timedelta(seconds=record.run.limits.max_seconds)])
    with pytest.raises(submit.SubmissionRejected, match="DEADLINE_EXPIRED"):
        submit.escrow_submission(
            _negative(),
            record,
            validator=FakeEvidence(),
            clock=lambda: next(times),
            deadline=START + timedelta(seconds=record.run.limits.max_seconds),
        )
    assert not Path(record.escrow_path).exists()


def test_escrow_idempotent_recovery_and_altered_artifact_fail_closed(tmp_path: Path) -> None:
    record = _packet_and_record(tmp_path)
    first = submit.escrow_submission(
        _negative(), record, validator=FakeEvidence(), clock=lambda: END
    )
    second = submit.escrow_submission(
        _positive(), record, validator=FakeEvidence(), clock=lambda: END
    )
    assert second == first
    path = Path(record.escrow_path)
    receipt_path = path.with_name(path.name + ".receipt.json")
    assert stat.S_IMODE(path.stat().st_mode) == 0o400
    assert stat.S_IMODE(receipt_path.stat().st_mode) == 0o400
    path.chmod(0o600)
    path.write_bytes(path.read_bytes().replace(b"No public", b"Not public", 1))
    path.chmod(0o400)
    with pytest.raises(submit.PilotSubmitError):
        submit.recover_submission(record, validator=FakeEvidence())


def test_concurrent_submission_is_no_clobber_and_exactly_recoverable(tmp_path: Path) -> None:
    record = _packet_and_record(tmp_path)
    receipts: list[submit.SubmissionReceipt] = []
    errors: list[BaseException] = []

    def run() -> None:
        try:
            receipts.append(
                submit.escrow_submission(
                    _negative(), record, validator=FakeEvidence(), clock=lambda: END
                )
            )
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    threads = [threading.Thread(target=run) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert errors == []
    assert len(receipts) == 4
    assert {item.sha256 for item in receipts} == {receipts[0].sha256}


def test_binding_loader_reauthenticates_packet_policies_and_recovery_state(tmp_path: Path) -> None:
    record = _packet_and_record(tmp_path)
    binding = tmp_path / "bindings.json"
    _write_bindings(binding, record)
    assert submit.load_bindings(binding).records[0] == record
    policy = next(item for item in record.authenticated_inputs if item.name == "tool_policy")
    path = Path(policy.path)
    path.chmod(0o600)
    path.write_text("tampered\n")
    path.chmod(0o444)
    with pytest.raises(submit.PilotSubmitError, match=r"input changed|payload bytes changed"):
        submit.load_bindings(binding)


def test_binding_loader_rejects_unmanifested_packet_file(tmp_path: Path) -> None:
    record = _packet_and_record(tmp_path)
    binding = tmp_path / "bindings.json"
    _write_bindings(binding, record)
    extra = Path(record.packet_path) / "unexpected.txt"
    extra.write_text("not in the authenticated manifest\n")
    extra.chmod(0o444)
    with pytest.raises(submit.PilotSubmitError, match="filesystem census"):
        submit.load_bindings(binding)


def test_binding_loader_rejects_modes_identity_manifest_and_incomplete_recovery(
    tmp_path: Path,
) -> None:
    record = _packet_and_record(tmp_path)
    binding = tmp_path / "bindings.json"
    _write_bindings(binding, record)
    binding.chmod(0o644)
    with pytest.raises(submit.PilotSubmitError, match="owner, type, or mode"):
        submit.load_bindings(binding)
    binding.chmod(0o600)
    altered = record.model_copy(update={"packet_inode": record.packet_inode + 1})
    _write_bindings(binding, altered)
    with pytest.raises(submit.PilotSubmitError, match="identity changed"):
        submit.load_bindings(binding)
    _write_bindings(binding, record)
    Path(record.escrow_path).write_text("orphan")
    with pytest.raises(submit.PilotSubmitError, match="recovery state is incomplete"):
        submit.load_bindings(binding)


def test_strict_json_and_diagnostics_are_bounded_and_separate_protocol_capability(
    tmp_path: Path,
) -> None:
    record = _packet_and_record(tmp_path)
    with pytest.raises(submit.PilotSubmitError, match="nesting"):
        submit._strict_json(("[" * 101 + "]" * 101).encode(), "request")
    with pytest.raises(submit.PilotSubmitError, match="duplicate key"):
        submit._strict_json(b'{"x":1,"x":2}\n', "request")
    with pytest.raises(submit.PilotSubmitError, match="non-finite"):
        submit._strict_json(b'{"x":NaN}\n', "request")
    base = {
        "protocol_version": 3,
        "capability": record.capability,
        "cwd": record.packet_path,
        "draft": _negative(),
    }
    assert submit._request(canonical_json(base), record) == base["draft"]
    bad_protocol = dict(base, protocol_version=1)
    with pytest.raises(submit.SubmissionRejected, match="PROTOCOL_VERSION_INVALID"):
        submit._request(canonical_json(bad_protocol), record)
    bad_capability = dict(base, capability="c" * 64)
    with pytest.raises(submit.SubmissionRejected, match="CAPABILITY_INVALID"):
        submit._request(canonical_json(bad_capability), record)
    oversized_integer = (
        '{"protocol_version":3,"capability":"'
        + record.capability
        + '","cwd":'
        + json.dumps(record.packet_path)
        + ',"draft":{"value":'
        + "9" * 5_000
        + "}}"
    ).encode()
    with pytest.raises(submit.SubmissionRejected, match="REQUEST_INVALID"):
        submit._request(oversized_integer, record)
    diagnostic = submit._diagnostic(
        GroundTruthError(record.cache_root + "\n" + "x" * 1000 + "\N{SNOWMAN}"), record
    )
    assert record.cache_root not in diagnostic and diagnostic.isascii()
    assert len(diagnostic) <= submit._MAX_DIAGNOSTIC


def _fake_evidence_factory(*_args: object, **_kwargs: object) -> FakeEvidence:
    return FakeEvidence()


def _exchange(path: Path, payload: dict[str, object]) -> dict[str, Any]:
    raw = canonical_json(payload)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        deadline = time.monotonic() + 5
        while True:
            try:
                client.connect(str(path))
                break
            except FileNotFoundError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.01)
        client.sendall(struct.pack("!I", len(raw)) + raw)
        header = client.recv(4)
        if len(header) != 4:
            raise ConnectionError("response was dropped")
        (size,) = struct.unpack("!I", header)
        chunks = bytearray()
        while len(chunks) < size:
            chunk = client.recv(size - len(chunks))
            if not chunk:
                raise ConnectionError("response was truncated")
            chunks.extend(chunk)
    value = json.loads(bytes(chunks))
    return cast("dict[str, Any]", value)


def _serve_thread(
    socket_path: Path, bindings: Path, outcome: list[BaseException | int]
) -> threading.Thread:
    def run() -> None:
        try:
            outcome.append(submit.serve(socket_path, bindings, timeout_seconds=5))
        except BaseException as exc:  # pragma: no cover - asserted by caller
            outcome.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    return thread


def test_server_rejects_then_accepts_and_cleans_socket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = _packet_and_record(tmp_path, attempts=2)
    record = record.model_copy(
        update={"run": record.run.model_copy(update={"started_at": datetime.now(timezone.utc)})}
    )
    bindings = tmp_path / "bindings.json"
    _write_bindings(bindings, record)
    socket_path = _private(tmp_path / "socket") / "submit.sock"
    monkeypatch.setattr(submit, "GitEvidenceValidator", _fake_evidence_factory)
    monkeypatch.setattr(submit, "_verify_peer_cwd", lambda *_args: None)
    outcome: list[BaseException | int] = []
    thread = _serve_thread(socket_path, bindings, outcome)
    base = {
        "protocol_version": 3,
        "capability": "c" * 64,
        "cwd": record.packet_path,
        "draft": _negative(),
    }
    assert _exchange(socket_path, base)["code"] == "CAPABILITY_INVALID"
    response = _exchange(socket_path, dict(base, capability=record.capability))
    thread.join(timeout=10)
    assert response["ok"] is True and response["summary"].startswith("SUBMITTED schema=1")
    assert outcome == [0]
    assert not socket_path.exists()


def test_dropped_success_response_retries_to_exact_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = _packet_and_record(tmp_path)
    record = record.model_copy(
        update={"run": record.run.model_copy(update={"started_at": datetime.now(timezone.utc)})}
    )
    bindings = tmp_path / "bindings.json"
    _write_bindings(bindings, record)
    socket_path = _private(tmp_path / "socket") / "submit.sock"
    monkeypatch.setattr(submit, "GitEvidenceValidator", _fake_evidence_factory)
    monkeypatch.setattr(submit, "_verify_peer_cwd", lambda *_args: None)
    original = submit._send_frame
    dropped = False

    def send(connection: socket.socket, value: dict[str, object]) -> None:
        nonlocal dropped
        if value.get("ok") is True and not dropped:
            dropped = True
            raise BrokenPipeError("simulated lost success response")
        original(connection, value)

    monkeypatch.setattr(submit, "_send_frame", send)
    outcome: list[BaseException | int] = []
    thread = _serve_thread(socket_path, bindings, outcome)
    request = {
        "protocol_version": 3,
        "capability": record.capability,
        "cwd": record.packet_path,
        "draft": _negative(),
    }
    with pytest.raises(ConnectionError, match="dropped"):
        _exchange(socket_path, request)
    response = _exchange(socket_path, request)
    thread.join(timeout=10)
    assert response["ok"] is True
    assert (
        response["receipt"]["sha256"]
        == submit.recover_submission(record, validator=FakeEvidence()).sha256
    )
    assert outcome == [0]


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def test_real_git_evidence_validator_integration(tmp_path: Path) -> None:
    work = _private(tmp_path / "work")
    _git(work, "init", "-q")
    _git(work, "config", "user.email", "pilot@example.invalid")
    _git(work, "config", "user.name", "Pilot")
    source = work / "src/main.py"
    source.parent.mkdir()
    source.write_text("old\n")
    _git(work, "add", "src/main.py")
    _git(work, "commit", "-qm", "baseline")
    base = _git(work, "rev-parse", "HEAD")
    base_tree = _git(work, "rev-parse", "HEAD^{tree}")
    base_blob = _git(work, "rev-parse", "HEAD:src/main.py")
    source.write_text("new\n")
    _git(work, "commit", "-qam", "target")
    target = _git(work, "rev-parse", "HEAD")
    target_tree = _git(work, "rev-parse", "HEAD^{tree}")
    target_blob = _git(work, "rev-parse", "HEAD:src/main.py")
    record = _packet_and_record(
        tmp_path / "bound",
        baseline_commit=base,
        target_commit=target,
        baseline_tree=base_tree,
        target_tree=target_tree,
        baseline_blob=base_blob,
        target_blob=target_blob,
    )
    cache = Path(record.cache_root) / collision_resistant_cache_name(record.repository)
    subprocess.run(["git", "clone", "--bare", "-q", str(work), str(cache)], check=True)
    _git(cache, "config", "remote.origin.url", f"https://github.com/{record.repository}.git")

    def bounded_runner(repository: Path, args: Sequence[str]) -> bytes:
        result = subprocess.run(
            ["git", *args],
            cwd=repository,
            check=True,
            capture_output=True,
        )
        return result.stdout

    validator = GitEvidenceValidator(
        Path(record.cache_root),
        record.repository,
        record.snapshots.baseline_commit,
        record.snapshots.target_commit,
        record.baseline_tree,
        record.target_tree,
        runner=bounded_runner,
    )
    receipt = submit.escrow_submission(_negative(), record, validator=validator, clock=lambda: END)
    assert receipt.recommendation == "negative_control"


def test_frozen_v3_checksums_and_binding_schema_match_sources() -> None:
    root = Path(__file__).resolve().parents[2]
    profile = root / "benchmarks/real_world/pilot_v3"
    checksums = json.loads((profile / "checksums-v1.json").read_text())
    for relative, expected in checksums["files"].items():
        assert _sha((root / relative).read_bytes()) == expected
    expected_schema = submit.SubmissionBindings.model_json_schema()
    expected_schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    expected_schema["title"] = "Blind review submission binding v3"
    assert (
        json.loads((profile / "submission-binding-schema-v1.json").read_text()) == expected_schema
    )


def test_extension_schema_is_semantic_only_and_runtime_load_is_deferred() -> None:
    root = Path(__file__).resolve().parents[2]
    schema = (root / ".pi/extensions/blind-review-submit/review-schema.ts").read_text()
    assert "ReviewDraftSchema" in schema
    for forbidden in (
        "artifact_type",
        "corpus_id",
        "commit_sha",
        "blob_sha",
        "claim_id",
        "ordinal:",
        "escrow_path",
    ):
        assert forbidden not in schema
    runtime = json.loads(
        (root / "benchmarks/real_world/pilot_v3/runtime-policy-v1.json").read_text()
    )
    assert runtime["child_extension_loading"]["phase_1_source_contract_test"] is True
    loading = runtime["child_extension_loading"]
    assert loading["phase_2_extension_load_proved_live_for_pinned_execution"] is True
    assert loading["phase_2_subagent_propagation_proved_for_pinned_execution"] is True
    assert loading["global_unversioned_propagation_proof"] is False
