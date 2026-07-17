from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from benchmarks.real_world import pilot_review_b_v2 as capture
from benchmarks.real_world.ground_truth_v2.schema import ReviewArtifactV1, canonical_json
from tests.benchmarks.ground_truth_helpers import BASE, TARGET, review


def _usage() -> dict[str, Any]:
    return {
        "input": 10,
        "output": 4,
        "cacheRead": 3,
        "cost": {
            "input": 0.00005,
            "output": 0.00012,
            "cacheRead": 0.0000015,
            "cacheWrite": 0,
            "total": 0.0001715,
        },
    }


def _assistant(identity: str, tools: list[tuple[str, dict[str, Any]]], text: str = "") -> bytes:
    content: list[dict[str, Any]] = []
    if text:
        content.append({"type": "text", "text": text})
    content.extend(
        {
            "type": "toolCall",
            "id": f"{identity}-call-{index}",
            "name": name,
            "arguments": arguments,
        }
        for index, (name, arguments) in enumerate(tools)
    )
    return (
        json.dumps(
            {
                "type": "message",
                "id": identity,
                "message": {
                    "role": "assistant",
                    "timestamp": 1000,
                    "usage": _usage(),
                    "content": content,
                },
            },
            separators=(",", ":"),
        )
        + "\n"
    ).encode()


def _with_thinking(raw: bytes, count: int = 1) -> bytes:
    item = json.loads(raw)
    for index in range(count):
        item["message"]["content"].insert(
            index,
            {"type": "thinking", "thinking": f"internal-{index}"},
        )
    return (json.dumps(item, separators=(",", ":")) + "\n").encode()


def _tool_result(
    identity: str, call_id: str | None = None, tool_name: str | None = None, *, error: bool = False
) -> bytes:
    base = identity.removesuffix("-result")
    call_id = call_id or f"{base}-call-0"
    tool_name = tool_name or ("bash" if base == "write" else "read")
    return (
        json.dumps(
            {
                "type": "message",
                "id": identity,
                "message": {
                    "role": "toolResult",
                    "toolCallId": call_id,
                    "toolName": tool_name,
                    "content": [{"type": "text", "text": "ok"}],
                    "isError": error,
                    "timestamp": 1001,
                },
            },
            separators=(",", ":"),
        )
        + "\n"
    ).encode()


def _private(path: Path) -> Path:
    path.mkdir(mode=0o700)
    return path


def _interval_fixture(tmp_path: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    packet = _private(tmp_path / "packet")
    source = packet / "snapshot.diff"
    source.write_text("diff")
    assigned = _private(tmp_path / "interval")
    artifact = assigned / "review-b.json"
    finish = ["python", "-m", "benchmarks.real_world.pilot_review_b_v2", "--finish"]
    marker = {
        "packet_path": str(packet),
        "artifact_path": str(artifact),
        "assigned_root": str(assigned),
        "repository": "owner/repo",
        "pr": 1,
        "expected_finish_tokens": finish,
        "start_tool_call_id": "start-call",
    }
    boundary = {"session_offset": 0}
    manifest = {
        "source_bindings": [
            {"repository": "owner/repo", "pr": 1},
            {"repository": "other/repo", "pr": 222},
        ]
    }
    return marker, boundary, manifest


def _start_result() -> bytes:
    return _tool_result("start-result", "start-call", "bash")


def _finish_line(tokens: list[str], identity: str = "finish") -> bytes:
    return _assistant(
        identity, [("bash", {"command": " ".join(shlex_quote(item) for item in tokens)})]
    )


def shlex_quote(value: str) -> str:
    return shlex.quote(value)


def _valid_interval(marker: dict[str, Any]) -> bytes:
    packet = marker["packet_path"]
    artifact = marker["artifact_path"]
    return b"".join(
        [
            _start_result(),
            _assistant("read", [("read", {"path": f"{packet}/snapshot.diff"})]),
            _tool_result("read-result"),
            _assistant(
                "write",
                [("bash", {"command": f"cat > {artifact} <<'EOF'\n{{}}\nEOF"})],
            ),
            _tool_result("write-result"),
            _finish_line(marker["expected_finish_tokens"]),
        ]
    )


def test_clean_interval_exact_finish_and_usage(tmp_path: Path) -> None:
    marker, boundary, manifest = _interval_fixture(tmp_path)
    packet = marker["packet_path"]
    artifact = marker["artifact_path"]
    raw = b"".join(
        [
            _start_result(),
            _assistant("read", [("read", {"path": f"{packet}/snapshot.diff"})]),
            _tool_result("read-result"),
            _assistant(
                "write",
                [("bash", {"command": f"cat > {artifact} <<'EOF'\n{{}}\nEOF"})],
            ),
            _tool_result("write-result"),
            _finish_line(marker["expected_finish_tokens"]),
        ]
    )
    interval, objects = capture._interval(raw, marker, boundary, manifest)
    assert b'"id":"finish"' not in interval
    assert len(objects) == 4
    assert capture._usage(
        objects, {"input": 5_000_000, "cached_input": 500_000, "output": 30_000_000}
    ) == (20, 8, 6, 2, 343)


@pytest.mark.parametrize(
    "mutation,match",
    [
        (lambda raw, _m: raw.replace(b'"id":"write"', b'"id":"read"'), "duplicate"),
        (
            lambda raw, _m: raw + _tool_result("after-finish"),
            "finish boundary",
        ),
    ],
)
def test_interval_rejects_bad_ids_or_finish_position(
    tmp_path: Path, mutation: Any, match: str
) -> None:
    marker, boundary, manifest = _interval_fixture(tmp_path)
    packet = marker["packet_path"]
    artifact = marker["artifact_path"]
    raw = b"".join(
        [
            _start_result(),
            _assistant("read", [("read", {"path": f"{packet}/snapshot.diff"})]),
            _tool_result("read-result"),
            _assistant("write", [("bash", {"command": f"cat > {artifact} <<'EOF'\n{{}}\nEOF"})]),
            _tool_result("write-result"),
            _finish_line(marker["expected_finish_tokens"]),
        ]
    )
    with pytest.raises(capture.PilotReviewBError, match=match):
        capture._interval(mutation(raw, marker), marker, boundary, manifest)


@pytest.mark.parametrize(
    "tool,arguments,text,match",
    [
        ("subagent", {"task": "x"}, "", "forbidden orchestration"),
        ("read", {"path": "<SIBLING>"}, "", "outside assigned"),
        ("read", {"path": "<PACKET>", "extra": 1}, "", "exact schema"),
        ("read", {"path": "<PACKET>"}, "see OTHER/REPO", "visible or unknown"),
        ("read", {"path": "<PACKET>"}, "see #222", "visible or unknown"),
        ("read", {"path": "<PACKET>"}, "call /pull/222", "visible or unknown"),
        ("read", {"path": "<PACKET>"}, "prior labels", "visible or unknown"),
    ],
)
def test_interval_rejects_tools_paths_identity_and_text(
    tmp_path: Path, tool: str, arguments: dict[str, Any], text: str, match: str
) -> None:
    marker, boundary, manifest = _interval_fixture(tmp_path)
    arguments = dict(arguments)
    if arguments.get("path") == "<PACKET>":
        arguments["path"] = str(Path(marker["packet_path"]) / "snapshot.diff")
    elif arguments.get("path") == "<SIBLING>":
        sibling = _private(tmp_path / "packet-sibling") / "file"
        sibling.write_text("x")
        arguments["path"] = str(sibling)
    raw = (
        _start_result()
        + _assistant("bad", [(tool, arguments)], text)
        + _tool_result("bad-result", "bad-call-0", tool)
        + _finish_line(marker["expected_finish_tokens"])
    )
    with pytest.raises(capture.PilotReviewBError, match=match):
        capture._interval(raw, marker, boundary, manifest)


def test_interval_accounts_but_does_not_treat_thinking_as_activity(tmp_path: Path) -> None:
    marker, boundary, manifest = _interval_fixture(tmp_path)
    packet = marker["packet_path"]
    artifact = marker["artifact_path"]
    read = _with_thinking(
        _assistant("read", [("read", {"path": f"{packet}/snapshot.diff"})]), count=1
    ).replace(b"internal-0", b"predictions prior labels other/repo #222 orchestration")
    raw = b"".join(
        [
            _start_result(),
            read,
            _tool_result("read-result"),
            _assistant("write", [("bash", {"command": f"cat > {artifact} <<'EOF'\n{{}}\nEOF"})]),
            _tool_result("write-result"),
            _finish_line(marker["expected_finish_tokens"]),
        ]
    )
    interval, objects = capture._interval(raw, marker, boundary, manifest)
    assert b"predictions prior labels other/repo" in interval
    assert len(objects) == 4


def test_interval_rejects_forbidden_executable_arguments(tmp_path: Path) -> None:
    marker, boundary, manifest = _interval_fixture(tmp_path)
    raw = b"".join(
        [
            _start_result(),
            _assistant(
                "grep",
                [
                    (
                        "grep",
                        {"pattern": "prior labels", "path": marker["packet_path"]},
                    )
                ],
            ),
            _tool_result("grep-result", "grep-call-0", "grep"),
            _finish_line(marker["expected_finish_tokens"]),
        ]
    )
    with pytest.raises(capture.PilotReviewBError, match="forbidden orchestration"):
        capture._interval(raw, marker, boundary, manifest)


def test_start_detection_requires_exact_sole_executable_command() -> None:
    expected = [sys.executable, "-m", "benchmarks.real_world.pilot_review_b_v2", "--start"]
    command = shlex.join(expected)
    exact = _assistant("start", [("bash", {"command": command})])
    assert capture._last_start_call(exact, expected)
    assert capture._last_start_call(_with_thinking(exact, count=2), expected)
    for bad in (
        _with_thinking(_assistant("compound", [("bash", {"command": f"curl bad; {command}"})])),
        _assistant("text", [("bash", {"command": command})], "extra"),
        _assistant(
            "tools",
            [("bash", {"command": command}), ("bash", {"command": "true"})],
        ),
    ):
        with pytest.raises(capture.PilotReviewBError, match="sole executable canonical"):
            capture._last_start_call(bad, expected)


def test_finish_detection_requires_exact_command(tmp_path: Path) -> None:
    marker, boundary, manifest = _interval_fixture(tmp_path)
    packet = marker["packet_path"]
    artifact = marker["artifact_path"]
    spoof = _assistant(
        "spoof",
        [("bash", {"command": "echo pilot_review_b_v2 --finish"})],
    )
    raw = (
        _start_result()
        + _assistant("r", [("read", {"path": f"{packet}/snapshot.diff"})])
        + _tool_result("r-result", "r-call-0", "read")
        + _assistant("w", [("bash", {"command": f"cat > {artifact} <<'EOF'\n{{}}\nEOF"})])
        + _tool_result("w-result", "w-call-0", "bash")
        + spoof
    )
    with pytest.raises(capture.PilotReviewBError, match="finish boundary"):
        capture._interval(raw, marker, boundary, manifest)


def test_finish_boundary_accepts_internal_thinking(tmp_path: Path) -> None:
    marker, boundary, manifest = _interval_fixture(tmp_path)
    raw = _valid_interval(marker)
    finish = _finish_line(marker["expected_finish_tokens"])
    thinking_finish = _with_thinking(finish, count=2)
    raw = raw[: -len(finish)] + thinking_finish
    interval, _ = capture._interval(raw, marker, boundary, manifest)
    assert b'"type":"thinking"' not in interval


@pytest.mark.parametrize("extra", ["text", "second-tool"])
def test_finish_boundary_is_one_executable_tool_call_only(tmp_path: Path, extra: str) -> None:
    marker, boundary, manifest = _interval_fixture(tmp_path)
    raw = _valid_interval(marker)
    finish = _finish_line(marker["expected_finish_tokens"])
    item = json.loads(finish)
    if extra == "text":
        item["message"]["content"].insert(0, {"type": "text", "text": "finish"})
    else:
        item["message"]["content"].append(
            {"type": "toolCall", "id": "extra", "name": "bash", "arguments": {"command": "true"}}
        )
    bad_finish = (json.dumps(item, separators=(",", ":")) + "\n").encode()
    raw = raw[: -len(finish)] + bad_finish
    with pytest.raises(capture.PilotReviewBError, match="finish boundary"):
        capture._interval(raw, marker, boundary, manifest)


@pytest.mark.parametrize(
    "prefix,match",
    [
        (_tool_result("wrong", "wrong-call", "bash"), "exact start"),
        (_start_result() + _tool_result("extra", "other", "bash"), "multiple leading"),
        (_tool_result("start-result", "start-call", "bash", error=True), "exact start"),
    ],
)
def test_leading_start_result_is_exactly_one_success(
    tmp_path: Path, prefix: bytes, match: str
) -> None:
    marker, boundary, manifest = _interval_fixture(tmp_path)
    valid = _valid_interval(marker)
    raw = prefix + valid[len(_start_result()) :]
    with pytest.raises(capture.PilotReviewBError, match=match):
        capture._interval(raw, marker, boundary, manifest)


@pytest.mark.parametrize(
    "mode,match", [("missing", "prior tool results|before all"), ("error", "failed")]
)
def test_every_tool_call_requires_one_successful_result(
    tmp_path: Path, mode: str, match: str
) -> None:
    marker, boundary, manifest = _interval_fixture(tmp_path)
    raw = _valid_interval(marker)
    result = _tool_result("read-result")
    if mode == "missing":
        raw = raw.replace(result, b"")
    else:
        raw = raw.replace(result, _tool_result("read-result", error=True))
    with pytest.raises(capture.PilotReviewBError, match=match):
        capture._interval(raw, marker, boundary, manifest)


@pytest.mark.parametrize(
    "tool,args",
    [
        ("read", {"path": 7}),
        ("read", {"path": "/tmp/x", "offset": True}),
        ("grep", {"path": "/tmp/x", "pattern": {"bad": "object"}}),
        ("find", {"path": "/tmp/x", "pattern": ["*.py"]}),
        ("ls", {"path": "/tmp/x", "limit": False}),
        ("bash", {"command": ["cat"]}),
    ],
)
def test_tool_argument_types_are_exact(tool: str, args: dict[str, Any]) -> None:
    with pytest.raises(capture.PilotReviewBError, match="argument"):
        capture._validate_tool_arguments(tool, args)


@pytest.mark.parametrize(
    "text",
    [
        "PR 222",
        "pull request 222",
        "#222",
        "/pull/222",
        '{"pr":222}',
        '{"number":222}',
        "OTHER/REPO",
    ],
)
def test_other_identity_detection_covers_common_spellings(text: str) -> None:
    assert capture._contains_other_identity(text, "other/repo", 222)


def test_session_ancestor_symlink_is_rejected(tmp_path: Path) -> None:
    real = _private(tmp_path / "real-session")
    session = real / "session.jsonl"
    session.write_bytes(_assistant("x", []))
    link = tmp_path / "session-link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(capture.PilotReviewBError, match="symbolic"):
        capture._session_snapshot(link / "session.jsonl", session.resolve())


def test_ancestor_symlink_is_rejected(tmp_path: Path) -> None:
    real = _private(tmp_path / "real")
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    child = link / "child"
    child.mkdir()
    with pytest.raises(capture.PilotReviewBError, match="symbolic"):
        capture._private_directory(child)


def test_supervisor_ancestor_and_process_starttime_fail_closed() -> None:
    current = os.getpid()
    starttime = capture._proc_starttime(current)
    with pytest.raises(capture.PilotReviewBError, match=r"reused|start time"):
        capture._owned_process(current, starttime + 1)
    with pytest.raises(capture.PilotReviewBError, match=r"ancestor|parent Pi"):
        capture._declared_supervisor(current)
    with pytest.raises(capture.PilotReviewBError, match=r"does not exist|unavailable"):
        capture._owned_process(999_999_999)


def test_usage_rejects_missing_string_bool_and_overflow() -> None:
    item = json.loads(_assistant("a", []))
    for value in ("10", True, -1):
        bad = json.loads(json.dumps(item))
        bad["message"]["usage"]["input"] = value
        with pytest.raises(capture.PilotReviewBError, match="nonnegative integer"):
            capture._usage([bad], {"input": 1, "cached_input": 1, "output": 1})
    missing = json.loads(json.dumps(item))
    del missing["message"]["usage"]["output"]
    with pytest.raises(capture.PilotReviewBError, match="missing"):
        capture._usage([missing], {"input": 1, "cached_input": 1, "output": 1})
    overflow = json.loads(json.dumps(item))
    overflow["message"]["usage"]["input"] = 100_001
    with pytest.raises(capture.PilotReviewBError, match="bound"):
        capture._usage([overflow], {"input": 1, "cached_input": 1, "output": 1})


def test_usage_rejects_nonfinite_and_mismatched_provider_cost() -> None:
    item = json.loads(_assistant("a", []))
    item["message"]["usage"]["cost"]["total"] = float("inf")
    with pytest.raises(capture.PilotReviewBError, match="finite"):
        capture._usage([item], {"input": 1, "cached_input": 1, "output": 1})
    item = json.loads(_assistant("a", []))
    item["message"]["usage"]["cost"]["total"] = 10
    with pytest.raises(capture.PilotReviewBError, match="differs"):
        capture._usage([item], {"input": 1, "cached_input": 1, "output": 1})


def test_samples_validate_coverage_cadence_and_processes(tmp_path: Path) -> None:
    path = tmp_path / "samples"
    path.write_bytes(
        b"".join(
            capture._canonical(
                {"monotonic_ns": n, "unix_ms": u, "rss_bytes": r, "process_count": 1}
            )
            for n, u, r in [
                (1_000_000_000, 1000, 100),
                (2_000_000_000, 2000, 160),
                (2_400_000_000, 2400, 120),
            ]
        )
    )
    assert capture._samples(path, 40, 1_100_000_000, 2_300_000_000, 1100, 2300) == (120, 3)
    rows = path.read_bytes().replace(b'"process_count":1', b'"process_count":0', 1)
    path.write_bytes(rows)
    with pytest.raises(capture.PilotReviewBError, match="process count"):
        capture._samples(path, 0, 1_100_000_000, 2_300_000_000, 1100, 2300)


@pytest.mark.parametrize("iteration", range(3))
def test_sampler_final_sample_covers_stop_boundary(tmp_path: Path, iteration: int) -> None:
    assigned = _private(tmp_path / f"sample-{iteration}")
    samples = assigned / "samples.jsonl"
    stop = assigned / "stop"
    ready = assigned / "ready"
    root = Path(__file__).resolve().parents[2]
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "benchmarks.real_world.pilot_review_b_v2",
            "--sample",
            str(samples),
            str(stop),
            str(ready),
            str(os.getpid()),
            str(capture._proc_starttime(os.getpid())),
        ],
        cwd=root,
        env={**os.environ, "PYTHONPATH": str(root)},
    )
    deadline = time.monotonic() + 5
    while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.01)
    assert ready.exists() and process.poll() is None
    first = json.loads(samples.read_text().splitlines()[0])
    end_monotonic = time.monotonic_ns()
    end_unix = time.time_ns() // 1_000_000
    stop.write_text("stop\n")
    assert process.wait(timeout=5) == 0
    _peak, count = capture._samples(
        samples,
        0,
        first["monotonic_ns"],
        end_monotonic,
        first["unix_ms"],
        end_unix,
    )
    assert count >= 2
    final = json.loads(samples.read_text().splitlines()[-1])
    assert final["monotonic_ns"] >= end_monotonic
    assert final["unix_ms"] >= end_unix


def _review_artifact(started: str, completed: str) -> bytes:
    payload = json.loads(review("B"))
    payload["corpus_id"] = "pilot"
    payload["repository"] = "owner/repo"
    payload["pr"] = 1
    payload["reviewer"] = {"kind": "agent", "name": "parent", "version": "provider/model"}
    payload["run"].update(
        {
            "prompt_sha256": "sha256:" + "1" * 64,
            "model_policy_sha256": "sha256:" + "2" * 64,
            "tool_policy_sha256": "sha256:" + "3" * 64,
            "source_policy_sha256": "sha256:" + "4" * 64,
            "started_at": started,
            "completed_at": completed,
            "limits": {
                "max_tokens": 100_000,
                "max_tool_calls": 200,
                "max_seconds": 1800,
                "max_output_bytes": 2_097_152,
            },
        }
    )
    model = ReviewArtifactV1.model_validate(payload)
    return canonical_json(model.model_dump(mode="json"))


def _artifact_manifest(execution: Path, session: Path, packet: Path) -> dict[str, Any]:
    return {
        "custody_ledger_path": str(execution / "custody.jsonl"),
        "review_b_measurement": {"supervisor_session_path": str(session)},
        "source_bindings": [
            {
                "corpus_id": "pilot",
                "repository": "owner/repo",
                "pr": 1,
                "baseline_commit": BASE,
                "target_commit": TARGET,
            }
        ],
        "source_packet_hashes": [{"repository": "owner/repo", "pr": 1, "packet_path": str(packet)}],
        "pre_pilot_budget_approved_by": "parent",
        "provider": "provider",
        "model": "model",
        "model_version": "model-version",
        "client_version": "client-version",
        "policy_hashes": {
            "model-policy-v1.json": "sha256:" + "2" * 64,
            "tool-policy-v1.json": "sha256:" + "3" * 64,
            "source-policy-v1.json": "sha256:" + "4" * 64,
        },
        "prompt_hashes": {"review-prompt-v1.md": "sha256:" + "1" * 64},
        "pricing_micro_usd_per_million_tokens": {
            "input": 5_000_000,
            "cached_input": 500_000,
            "output": 30_000_000,
        },
        "resource_projection_inputs": {"idle_supervisor_rss_bytes": 0},
    }


def test_artifact_timestamps_equal_start_and_finish_within_boundary() -> None:
    boundary = {"started_at": "2026-01-01T00:00:00Z"}
    valid = ReviewArtifactV1.model_validate(
        json.loads(_review_artifact("2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z"))
    )
    capture._validate_artifact_times(valid, boundary, 1_767_225_602_000)
    wrong_start = ReviewArtifactV1.model_validate(
        json.loads(_review_artifact("2026-01-01T00:00:00.001000Z", "2026-01-01T00:00:01Z"))
    )
    with pytest.raises(capture.PilotReviewBError, match="timestamps"):
        capture._validate_artifact_times(wrong_start, boundary, 1_767_225_602_000)
    late = ReviewArtifactV1.model_validate(
        json.loads(_review_artifact("2026-01-01T00:00:00Z", "2026-01-01T00:00:03Z"))
    )
    with pytest.raises(capture.PilotReviewBError, match="timestamps"):
        capture._validate_artifact_times(late, boundary, 1_767_225_602_000)


def test_artifact_exact_limits_and_binding(tmp_path: Path) -> None:
    raw = _review_artifact("2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z")
    manifest = _artifact_manifest(tmp_path, tmp_path / "session", tmp_path / "packet")
    parsed = capture._artifact(raw, {"repository": "owner/repo", "pr": 1}, manifest)
    assert parsed.lane == "B"
    payload = json.loads(raw)
    payload["run"]["limits"]["max_tokens"] = 1
    with pytest.raises(capture.PilotReviewBError, match="limits binding"):
        capture._artifact(canonical_json(payload), {"repository": "owner/repo", "pr": 1}, manifest)


def test_proc_stat_uses_final_parenthesis() -> None:
    assert capture._stat_parent("123 (name with ) paren) S 456 0 0") == 456
    with pytest.raises(capture.PilotReviewBError, match="malformed"):
        capture._stat_parent("broken")


def test_component_safe_containment_and_private_root(tmp_path: Path) -> None:
    root = _private(tmp_path / "packet")
    child = root / "child"
    child.write_text("x")
    assert capture._relative_child(child, root, strict=True) == child.resolve()
    sibling = _private(tmp_path / "packet-sibling") / "x"
    sibling.write_text("x")
    with pytest.raises(capture.PilotReviewBError, match="outside"):
        capture._relative_child(sibling, root, strict=True)
    link = root / "link"
    link.symlink_to(child)
    with pytest.raises(capture.PilotReviewBError, match="symbolic"):
        capture._relative_child(link, root, strict=True)


def _fork_cli(arguments: list[str]) -> bytes:
    read_descriptor, write_descriptor = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(read_descriptor)
            os.dup2(write_descriptor, sys.stdout.fileno())
            os.close(write_descriptor)
            sys.argv = ["pilot_review_b_v2", *arguments]
            code = capture.main()
            sys.stdout.flush()
        except BaseException:
            traceback.print_exc()
            os._exit(1)
        os._exit(code)
    os.close(write_descriptor)
    chunks: list[bytes] = []
    while chunk := os.read(read_descriptor, 64 * 1024):
        chunks.append(chunk)
    os.close(read_descriptor)
    waited, status = os.waitpid(pid, 0)
    assert waited == pid
    assert os.waitstatus_to_exitcode(status) == 0
    return b"".join(chunks)


def test_start_sampler_finish_integration(  # noqa: PLR0915 - full public CLI lifecycle
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    execution = _private(tmp_path / "execution")
    packet = _private(tmp_path / "packet")
    cache = _private(tmp_path / "cache")
    session = tmp_path / "session.jsonl"
    manifest_path = execution / "manifest.json"
    manifest_path.write_text("{}")
    agent = tmp_path / "agent"
    agent.write_text("x")
    interval = execution / "interval"
    manifest = _artifact_manifest(execution, session, packet)
    monkeypatch.setattr(capture, "_manifest", lambda *_args: (manifest, "sha256:" + "a" * 64))
    monkeypatch.setattr(capture, "_clean_state", lambda *_args: None)

    def declared(pid: int) -> int:
        return capture._proc_starttime(pid)

    monkeypatch.setattr(capture, "_declared_supervisor", declared)
    common = [
        "--manifest",
        str(manifest_path),
        "--execution-root",
        str(execution),
        "--packet-root",
        str(packet),
        "--repository",
        "owner/repo",
        "--pr",
        "1",
        "--supervisor-session",
        str(session),
        "--interval-root",
        str(interval),
        "--agent-config",
        str(agent),
        "--cache-root",
        str(cache),
    ]
    root = Path(__file__).resolve().parents[2]
    printed_start = subprocess.run(
        [
            sys.executable,
            "-m",
            "benchmarks.real_world.pilot_review_b_v2",
            "--print-start-command",
            *common,
            "--supervisor-pid",
            str(os.getpid()),
        ],
        cwd=root,
        env={**os.environ, "PYTHONPATH": str(root)},
        check=True,
        capture_output=True,
        text=True,
    )
    start_command = printed_start.stdout.strip()
    session.write_bytes(_assistant("start", [("bash", {"command": start_command})]))
    assert shlex.split(start_command)[3] == "--start"
    start_output = json.loads(_fork_cli(shlex.split(start_command)[3:]))
    assigned = interval / "owner--repo--1"
    assert start_output["assigned_root"] == str(assigned)
    assert start_output["started_at"].endswith("Z")
    assert start_output["boundary_sha256"].startswith("sha256:")
    marker = json.loads((assigned / "marker.json").read_bytes())
    boundary = json.loads((assigned / "start-boundary.json").read_bytes())
    started = boundary["started_at"]
    time.sleep(1.1)
    completed = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    artifact = assigned / "review-b.json"
    artifact_raw = _review_artifact(started, completed)
    write_command = f"cat > {artifact} <<'EOF'\n{artifact_raw.decode().rstrip()}\nEOF"
    artifact.write_bytes(artifact_raw)
    printed = subprocess.run(
        [
            sys.executable,
            "-m",
            "benchmarks.real_world.pilot_review_b_v2",
            "--print-finish-command",
            *common,
            "--artifact",
            str(artifact),
        ],
        cwd=root,
        env={**os.environ, "PYTHONPATH": str(root)},
        check=True,
        capture_output=True,
        text=True,
    )
    finish_command = printed.stdout.strip()
    assert shlex.split(finish_command) == marker["expected_finish_tokens"]
    with session.open("ab") as session_handle:
        session_handle.write(
            _tool_result("start-result", marker["start_tool_call_id"], "bash")
            + _assistant("read", [("read", {"path": str(packet / "source.py")})])
            + _tool_result("read-result")
            + _assistant("write", [("bash", {"command": write_command})])
            + _tool_result("write-result")
            + _assistant("finish", [("bash", {"command": finish_command})])
        )
    (packet / "source.py").write_text("source")
    finish_tokens = shlex.split(finish_command)
    assert finish_tokens[:3] == [sys.executable, "-m", "benchmarks.real_world.pilot_review_b_v2"]
    finish_output = json.loads(_fork_cli(finish_tokens[3:]))
    telemetry_path = assigned / "telemetry.json"
    assert finish_output == {"telemetry": str(telemetry_path)}
    telemetry = json.loads(telemetry_path.read_bytes())
    assert telemetry["succeeded"] is True
    assert telemetry["start_message_id"] == "read"
    assert telemetry["end_message_id"] == "write"
    assert telemetry["sampled_peak_process_tree_rss_bytes"] >= 0
    assert finish_command
    assert not (interval / "active.json").exists()


def test_session_inode_prefix_replacement_fails(tmp_path: Path) -> None:
    session = tmp_path / "session"
    session.write_bytes(b"a\n")
    raw, status = capture._session_snapshot(session, session.resolve())
    marker = {
        "session_device": status.st_dev,
        "session_inode": status.st_ino,
        "session_prefix_bytes": len(raw),
        "session_prefix_sha256": capture._sha(raw),
    }
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"a\n")
    replacement.replace(session)
    new_raw, new_status = capture._session_snapshot(session, session.resolve())
    with pytest.raises(capture.PilotReviewBError, match="append-only"):
        capture._verify_session_append(new_raw, new_status, marker)


def test_readonly_owned_packet_and_symlink_lock(tmp_path: Path) -> None:
    packet = _private(tmp_path / "packet")
    (packet / "source").write_text("x")
    packet.chmod(0o555)
    assert capture._allocated(packet) > 0
    private = _private(tmp_path / "private")
    target = private / "target"
    target.write_text("x")
    (private / "lock").symlink_to(target)
    with pytest.raises(capture.PilotReviewBError, match=r"safely|lock|symbolic"):
        capture._open_lock(private / "lock")
