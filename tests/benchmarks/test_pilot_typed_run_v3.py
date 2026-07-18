from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, cast

import pytest
from benchmarks.real_world import pilot_submit_v3 as submit
from benchmarks.real_world import pilot_typed_run_v3 as runner
from benchmarks.real_world.ground_truth_v2.evidence import collision_resistant_cache_name
from benchmarks.real_world.ground_truth_v2.schema import canonical_json

_REAL_PI_AGENTS_MODULE = (
    Path.home() / ".pi/agent/npm/node_modules/pi-subagents/src/agents/agents.ts"
)


def _private(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True)
    return path


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def _repo(tmp_path: Path) -> dict[str, str]:
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
    return {
        "work": str(work),
        "baseline_commit": base,
        "baseline_tree": base_tree,
        "baseline_blob": base_blob,
        "target_commit": target,
        "target_tree": target_tree,
        "target_blob": target_blob,
    }


def _payload(packet: Path, relative: str, raw: bytes) -> dict[str, object]:
    path = packet / relative
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(0o444)
    return {"path": relative, "bytes": len(raw), "sha256": _sha(raw)}


def _v3_packet(root: Path, source_root: Path, record: dict[str, Any]) -> Path:
    packet = _private(root / "packet")
    payload = [
        _payload(packet, "baseline/src/main.py", b"old\n"),
        _payload(packet, "target/src/main.py", b"new\n"),
        _payload(packet, "snapshot.diff", b"@@ -1 +1 @@\n-old\n+new\n"),
    ]
    for name in runner._POLICY_FILES.values():
        raw = (source_root / "benchmarks/real_world/pilot_v3" / name).read_bytes()
        payload.append(_payload(packet, f"policies-v3/{name}", raw))
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "id": runner._PACKET_ID,
        "repository": "owner/repo",
        "pr": 7,
        "baseline_commit": record["baseline_commit"],
        "baseline_tree": record["baseline_tree"],
        "target_commit": record["target_commit"],
        "target_tree": record["target_tree"],
        "snapshots": {
            "baseline": {
                "files": [
                    {
                        "path": "src/main.py",
                        "mode": "100644",
                        "oid": record["baseline_blob"],
                        "bytes": 4,
                        "sha256": _sha(b"old\n"),
                    }
                ]
            },
            "target": {
                "files": [
                    {
                        "path": "src/main.py",
                        "mode": "100644",
                        "oid": record["target_blob"],
                        "bytes": 4,
                        "sha256": _sha(b"new\n"),
                    }
                ]
            },
        },
        "payload_files": payload,
        "payload_bytes": sum(cast("int", item["bytes"]) for item in payload),
        "packet_root_sha256": "",
    }
    manifest["packet_root_sha256"] = submit._manifest_root(manifest)
    path = packet / "packet-manifest.json"
    path.write_bytes(canonical_json(manifest))
    path.chmod(0o444)
    runner._freeze_tree(packet)
    return root


def _cache(root: Path, record: dict[str, Any]) -> Path:
    cache_root = _private(root / "cache")
    cache = cache_root / collision_resistant_cache_name("owner/repo")
    subprocess.run(["git", "clone", "--bare", "-q", record["work"], str(cache)], check=True)
    _git(cache, "config", "remote.origin.url", "https://github.com/owner/repo.git")
    return cache_root


def _record(record: dict[str, str]) -> dict[str, object]:
    return {
        "repository": "owner/repo",
        "pr": 7,
        "baseline_commit": record["baseline_commit"],
        "baseline_tree": record["baseline_tree"],
        "target_commit": record["target_commit"],
        "target_tree": record["target_tree"],
    }


def _setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, Path, Path]:
    source_root = Path(__file__).resolve().parents[2]
    record = _repo(tmp_path)
    packets = _v3_packet(_private(tmp_path / "packets"), source_root, record)
    cache = _cache(tmp_path, record)
    home = _private(tmp_path / "home")
    agent_dir = _private(tmp_path / "pi-home")
    user_agents = _private(agent_dir / "agents")
    builtin_agents = _private(tmp_path / "pi-builtin/agents")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PI_CODING_AGENT_DIR", str(agent_dir))
    monkeypatch.setenv("PILOT_PI_USER_AGENT_ROOT", str(user_agents))
    monkeypatch.setenv("PILOT_PI_BUILTIN_AGENT_ROOT", str(builtin_agents))
    monkeypatch.setenv("PILOT_PI_SUBAGENTS_AGENTS_MODULE", str(_REAL_PI_AGENTS_MODULE))
    monkeypatch.delenv("PI_SUBAGENT_EXTRA_AGENT_DIRS", raising=False)
    monkeypatch.setattr(runner, "_source_record", lambda *_args: _record(record))
    return source_root, packets, cache, tmp_path / "execution"


def _draft() -> dict[str, object]:
    return {
        "terminal_recommendation": "negative_control",
        "changed_symbols": [
            {
                "canonical_name": "module.changed",
                "location": {
                    "side": "target",
                    "path": "src/main.py",
                    "start_line": 1,
                    "end_line": 1,
                    "symbol": "changed",
                },
            }
        ],
        "claims": [],
        "unknowns": [],
        "negative_assessment": {
            "changed_symbol_census_complete": True,
            "searched_entrypoint_families": ["http", "sdk"],
            "limitations": ["Static source only."],
        },
        "notes": "No public entrypoint changed.",
    }


def _client_script(path: Path) -> Path:
    path.write_text("""import json, socket, struct, sys
registry, mode = sys.argv[1], sys.argv[2]
binding = json.load(open(registry))
request = {"protocol_version": 3, "capability": binding["capability"],
           "cwd": __import__("os").getcwd(), "draft": json.loads(sys.argv[3])}
raw = json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
def send(read=True):
    client = socket.socket(socket.AF_UNIX); client.connect(binding["socket_path"])
    client.sendall(struct.pack("!I", len(raw)) + raw)
    if not read:
        client.close(); return None
    header = client.recv(4); size = struct.unpack("!I", header)[0]; out = b""
    while len(out) < size: out += client.recv(size-len(out))
    client.close(); return json.loads(out)
if mode == "lost": send(False)
result = send(True)
print(json.dumps(result, sort_keys=True))
raise SystemExit(0 if result.get("ok") else 7)
""")
    return path


def _prepare(
    source: Path,
    packets: Path,
    cache: Path,
    execution: Path,
    attempt: str,
    lane: str = "A",
    timeout: int = 20,
) -> dict[str, object]:
    return runner.prepare_native_attempt(
        source_root=source,
        cache_root=cache,
        packet_root=packets,
        execution_root=execution,
        repository="owner/repo",
        pr=7,
        lane=cast("Any", lane),
        attempt_id=attempt,
        timeout_seconds=timeout,
    )


def _install(execution: Path, root: Path) -> Path:
    directory = _private(root / "pi-home/agents/private")
    output = (directory / "reviewer.md").resolve()
    runner.create_native_agent(execution, output)
    return output


def _submit(
    execution: Path,
    attempt: str,
    script: Path,
    *,
    cwd: Path | None = None,
    mode: str = "normal",
    registry: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    _attempt, state = runner._load_native_state(execution, attempt)
    return subprocess.run(
        [
            sys.executable,
            str(script),
            str(registry or state["registry"]),
            mode,
            json.dumps(_draft()),
        ],
        cwd=cwd or Path(str(state["packet"])),
        text=True,
        capture_output=True,
        check=False,
        timeout=20,
    )


def test_native_prepare_submit_finalize_and_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, packets, cache, execution = _setup(tmp_path, monkeypatch)
    launch = _prepare(source, packets, cache, execution, "lane-a")
    assert set(launch) == {"agent", "cwd", "model", "thinking", "attempt"}
    client = _client_script(tmp_path / "client.py")
    response = _submit(execution, "lane-a", client, mode="lost")
    assert response.returncode == 0, response.stderr
    result = runner.finalize_native_attempt(execution_root=execution, attempt_id="lane-a")
    assert cast("dict[str, Any]", result["receipt"])["recommendation"] == "negative_control"
    assert runner.finalize_native_attempt(execution_root=execution, attempt_id="lane-a") == result
    attempt = execution / "attempts/lane-a"
    state = runner._json(attempt / "native-state.json", 512 * 1024, modes={0o600})
    assert not Path(str(state["registry"])).exists()
    assert not Path(str(state["socket_dir"])).exists()
    assert not Path(str(state["lease"])).exists()


def test_two_lanes_are_distinct_and_cross_wire_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, packets, cache, execution = _setup(tmp_path, monkeypatch)
    first = _prepare(source, packets, cache, execution, "lane-a", "A")
    second = _prepare(source, packets, cache, execution, "lane-b", "B")
    _, state_a = runner._load_native_state(execution, "lane-a")
    _, state_b = runner._load_native_state(execution, "lane-b")
    registry_a = runner._json(Path(str(state_a["registry"])), 128 * 1024, modes={0o600})
    registry_b = runner._json(Path(str(state_b["registry"])), 128 * 1024, modes={0o600})
    assert first["cwd"] != second["cwd"]
    assert registry_a["socket_path"] != registry_b["socket_path"]
    assert registry_a["capability"] != registry_b["capability"]
    client = _client_script(tmp_path / "client.py")
    crossed = _submit(execution, "lane-a", client, cwd=Path(str(state_b["packet"])))
    assert crossed.returncode == 7
    assert json.loads(crossed.stdout)["code"] == "PEER_CWD_INVALID"
    for attempt in ("lane-a", "lane-b"):
        with pytest.raises((runner.PilotTypedRunError, submit.PilotSubmitError)):
            runner.finalize_native_attempt(
                execution_root=execution, attempt_id=attempt, wait_seconds=0
            )


def test_no_submit_finalizes_failure_and_cleans_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, packets, cache, execution = _setup(tmp_path, monkeypatch)
    _prepare(source, packets, cache, execution, "no-submit")
    _, state = runner._load_native_state(execution, "no-submit")
    with pytest.raises((runner.PilotTypedRunError, submit.PilotSubmitError)):
        runner.finalize_native_attempt(
            execution_root=execution, attempt_id="no-submit", wait_seconds=0
        )
    assert (execution / "attempts/no-submit/native-failure.json").is_file()
    assert not Path(str(state["registry"])).exists()
    assert not Path(str(state["lease"])).exists()
    with pytest.raises(runner.PilotTypedRunError, match="already finalized"):
        runner.finalize_native_attempt(execution_root=execution, attempt_id="no-submit")


def test_durable_lease_caps_three_active_attempts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, packets, cache, execution = _setup(tmp_path, monkeypatch)
    for index in range(3):
        _prepare(source, packets, cache, execution, f"active-{index}")
    with pytest.raises(runner.PilotTypedRunError, match="maximum three"):
        _prepare(source, packets, cache, execution, "active-3")
    for index in range(3):
        with pytest.raises((runner.PilotTypedRunError, submit.PilotSubmitError)):
            runner.finalize_native_attempt(
                execution_root=execution, attempt_id=f"active-{index}", wait_seconds=0
            )


def test_launch_plan_is_deterministic_and_exact_native_tool_shape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, packets, cache, execution = _setup(tmp_path, monkeypatch)
    _prepare(source, packets, cache, execution, "b", "B")
    _prepare(source, packets, cache, execution, "a", "A")
    installed = _install(execution, tmp_path)
    deadlines = [
        int(runner._load_native_state(execution, attempt)[1]["deadline_unix_ms"])
        for attempt in ("a", "b")
    ]
    frozen_now = (min(deadlines) - 10_000) / 1_000
    monkeypatch.setattr("benchmarks.real_world.pilot_typed_run_v3.time.time", lambda: frozen_now)
    first = canonical_json(runner.native_launch_plan(execution, ["b", "a"]))
    second = canonical_json(runner.native_launch_plan(execution, ["a", "b"]))
    assert first == second
    plan = json.loads(first)
    assert plan["authentication"]["agent_sha256"].startswith("sha256:")
    assert plan["authentication"]["agent_file"] == str(installed)
    call = plan["subagent_call"]
    assert call["concurrency"] == 3
    assert call["context"] == "fresh"
    assert call["artifacts"] is call["includeProgress"] is False
    assert 0 < call["timeoutMs"] <= 20_000
    assert all(task["output"] is False and task["progress"] is False for task in call["tasks"])
    assert all(task["toolBudget"]["hard"] == 203 for task in call["tasks"])
    for attempt in ("a", "b"):
        with pytest.raises((runner.PilotTypedRunError, submit.PilotSubmitError)):
            runner.finalize_native_attempt(
                execution_root=execution, attempt_id=attempt, wait_seconds=0
            )


def _write_agent_definition(path: Path, *, package: str | None = None) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    package_line = f"package: {package}\n" if package else ""
    path.write_text(
        "---\n"
        f"name: {runner._NATIVE_AGENT_NAME}\n"
        f"{package_line}"
        "description: collision fixture\n"
        "tools: read\n"
        "---\n"
    )
    path.chmod(0o400)


def test_agent_install_rejects_nondiscovered_output_and_builtin_collision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, packets, cache, execution = _setup(tmp_path, monkeypatch)
    _prepare(source, packets, cache, execution, "agent-install")
    outside = _private(tmp_path / "outside") / "reviewer.md"
    with pytest.raises(runner.PilotTypedRunError, match="outside Pi user discovery"):
        runner.create_native_agent(execution, outside.resolve())
    real_agents = _private(tmp_path / "real-agents")
    linked_agents = tmp_path / "linked-agents"
    linked_agents.symlink_to(real_agents, target_is_directory=True)
    identity = runner._reauthenticate_execution(execution)
    with pytest.raises(runner.PilotTypedRunError, match="symlink ancestor"):
        runner._agent_discovery_census(identity, user_agent_root=linked_agents)
    builtin_root = Path(os.environ["PILOT_PI_BUILTIN_AGENT_ROOT"])
    _write_agent_definition(builtin_root / "collision.md")
    output = Path(os.environ["PILOT_PI_USER_AGENT_ROOT"]) / "private/reviewer.md"
    with pytest.raises(runner.PilotTypedRunError, match="already has a resolver definition"):
        runner.create_native_agent(execution, output.resolve())
    with pytest.raises((runner.PilotTypedRunError, submit.PilotSubmitError)):
        runner.finalize_native_attempt(
            execution_root=execution, attempt_id="agent-install", wait_seconds=0
        )


def test_launch_rejects_duplicate_user_project_collision_and_extra_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, packets, cache, execution = _setup(tmp_path, monkeypatch)
    _prepare(source, packets, cache, execution, "resolver")
    installed = _install(execution, tmp_path)
    duplicate = Path(os.environ["PILOT_PI_USER_AGENT_ROOT"]) / "duplicate.md"
    _write_agent_definition(duplicate)
    with pytest.raises(runner.PilotTypedRunError, match="discovery census changed"):
        runner.native_launch_plan(execution, ["resolver"])
    duplicate.unlink()
    valid_plan = runner.native_launch_plan(execution, ["resolver"])
    assert cast("dict[str, Any]", valid_plan["authentication"])["agent_file"] == str(installed)

    fake_project = _private(tmp_path / "fake-project")
    _write_agent_definition(fake_project / ".pi/agents/collision.md")
    identity_path = execution / "execution.json"
    identity = runner._json(identity_path, 512 * 1024, modes={0o400})
    identity["source_root"] = str(fake_project.resolve())
    identity_path.chmod(0o600)
    identity_path.write_bytes(canonical_json(identity))
    identity_path.chmod(0o400)
    with pytest.raises(runner.PilotTypedRunError, match="discovery census changed"):
        runner.native_launch_plan(execution, ["resolver"])

    identity_path.chmod(0o600)
    identity["source_root"] = str(source.resolve())
    identity_path.write_bytes(canonical_json(identity))
    identity_path.chmod(0o400)
    monkeypatch.setenv("PI_SUBAGENT_EXTRA_AGENT_DIRS", str(_private(tmp_path / "extra")))
    with pytest.raises(runner.PilotTypedRunError, match="EXTRA_AGENT_DIRS"):
        runner.native_launch_plan(execution, ["resolver"])
    with pytest.raises((runner.PilotTypedRunError, submit.PilotSubmitError)):
        runner.finalize_native_attempt(
            execution_root=execution, attempt_id="resolver", wait_seconds=0
        )


def test_launch_rejects_legacy_user_agent_dir_pi_dir_and_package_collisions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, packets, cache, execution = _setup(tmp_path, monkeypatch)
    _prepare(source, packets, cache, execution, "complete-resolver")
    installed = _install(execution, tmp_path)
    assert runner.native_launch_plan(execution, ["complete-resolver"])

    legacy = Path(os.environ["HOME"]) / ".agents/collision.md"
    _write_agent_definition(legacy)
    with pytest.raises(runner.PilotTypedRunError, match="discovery census changed"):
        runner.native_launch_plan(execution, ["complete-resolver"])
    legacy.unlink()
    legacy.parent.rmdir()
    assert runner.native_launch_plan(execution, ["complete-resolver"])

    original_agent_dir = os.environ["PI_CODING_AGENT_DIR"]
    alternate = _private(tmp_path / "alternate-pi-agent")
    _write_agent_definition(alternate / "agents/collision.md")
    monkeypatch.setenv("PI_CODING_AGENT_DIR", str(alternate))
    with pytest.raises(runner.PilotTypedRunError, match="discovery census changed"):
        runner.native_launch_plan(execution, ["complete-resolver"])
    monkeypatch.setenv("PI_CODING_AGENT_DIR", original_agent_dir)
    assert runner.native_launch_plan(execution, ["complete-resolver"])

    package = _private(tmp_path / "configured-package")
    package_agents = _private(package / "agents")
    _write_agent_definition(package_agents / "collision.md")
    (package / "package.json").write_bytes(
        canonical_json(
            {
                "name": "configured-collision",
                "version": "1.0.0",
                "pi-subagents": {"agents": ["agents"]},
            }
        )
    )
    settings = Path(original_agent_dir) / "settings.json"
    settings.write_bytes(canonical_json({"packages": [{"source": f"file:{package}"}]}))
    runtime = runner._runtime_agent_discovery(runner._reauthenticate_execution(execution))
    package_rows = cast("dict[str, Any]", runtime["definitions"])["package"]
    assert any(row["name"] == runner._NATIVE_AGENT_NAME for row in package_rows)
    with pytest.raises(runner.PilotTypedRunError, match="discovery census changed"):
        runner.native_launch_plan(execution, ["complete-resolver"])
    settings.unlink()
    plan = runner.native_launch_plan(execution, ["complete-resolver"])
    assert cast("dict[str, Any]", plan["authentication"])["agent_file"] == str(installed)


def test_registry_and_agent_contracts_are_private_no_clobber_and_native_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, packets, cache, execution = _setup(tmp_path, monkeypatch)
    _prepare(source, packets, cache, execution, "contract")
    with pytest.raises(FileExistsError):
        _prepare(source, packets, cache, execution, "contract")
    assert not (execution / "attempts/contract/native-failure.json").exists()
    _, state = runner._load_native_state(execution, "contract")
    registry = Path(str(state["registry"]))
    packet = Path(str(state["packet"]))
    assert stat.S_IMODE(registry.stat().st_mode) == 0o600
    original = registry.read_bytes()
    registry.chmod(0o644)
    with pytest.raises(runner.PilotTypedRunError, match="descriptor is unsafe"):
        runner._validate_registry_descriptor(registry, packet)
    registry.chmod(0o600)
    registry.write_text("{}")
    with pytest.raises(runner.PilotTypedRunError, match="fields are invalid"):
        runner._validate_registry_descriptor(registry, packet)
    registry.unlink()
    registry.symlink_to(tmp_path / "missing")
    with pytest.raises(runner.PilotTypedRunError, match="descriptor is unsafe"):
        runner._validate_registry_descriptor(registry, packet)
    registry.unlink()
    registry.write_bytes(original)
    registry.chmod(0o600)
    extension = (source / ".pi/extensions/blind-review-submit/index.ts").read_text()
    assert "blind-review-native-registry-v3" in extension
    assert "cwdStatus.dev" in extension and "cwdStatus.ino" in extension
    assert "descriptorStatus.mode & 0o777" in extension
    agent_dir = _private(tmp_path / "pi-home/agents/agent")
    info = runner.create_native_agent(execution, agent_dir / "reviewer.md")
    assert info["runtime_name"] == "pilot-blind-reviewer-luna-medium-v3"
    agent_text = (agent_dir / "reviewer.md").read_text()
    assert "subagentOnlyExtensions: /" in agent_text
    assert "systemPromptMode: replace" in agent_text
    with pytest.raises(runner.PilotTypedRunError, match="already exists"):
        runner.create_native_agent(execution, agent_dir / "reviewer.md")
    registry.chmod(0o600)
    with pytest.raises((runner.PilotTypedRunError, submit.PilotSubmitError)):
        runner.finalize_native_attempt(
            execution_root=execution, attempt_id="contract", wait_seconds=0
        )


def test_finalize_is_serialized_and_existing_result_is_reauthenticated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, packets, cache, execution = _setup(tmp_path, monkeypatch)
    _prepare(source, packets, cache, execution, "concurrent")
    client = _client_script(tmp_path / "client.py")
    assert _submit(execution, "concurrent", client).returncode == 0
    results: list[dict[str, object]] = []
    failures: list[BaseException] = []

    def finish() -> None:
        try:
            results.append(
                runner.finalize_native_attempt(execution_root=execution, attempt_id="concurrent")
            )
        except BaseException as exc:  # pragma: no cover - assertion captures thread failure
            failures.append(exc)

    threads = [threading.Thread(target=finish) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)
    assert not failures
    assert len(results) == 2 and results[0] == results[1]
    attempt = execution / "attempts/concurrent"
    assert (attempt / "native-result.json").is_file()
    assert not (attempt / "native-failure.json").exists()


def test_launch_reauthenticates_runtime_packet_and_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, packets, cache, execution = _setup(tmp_path, monkeypatch)
    _prepare(source, packets, cache, execution, "reauth")
    installed = _install(execution, tmp_path)
    identity = runner._reauthenticate_execution(execution)
    agent = Path(cast("dict[str, Any]", identity["agent"])["path"])
    agent.chmod(0o600)
    with pytest.raises(runner.PilotTypedRunError, match=r"(?:runtime bytes changed|file mode)"):
        runner.native_launch_plan(execution, ["reauth"])
    agent.chmod(0o400)
    installed.chmod(0o600)
    with pytest.raises(runner.PilotTypedRunError, match=r"(?:installed agent bytes|file mode)"):
        runner.native_launch_plan(execution, ["reauth"])
    installed.chmod(0o400)
    _, state = runner._load_native_state(execution, "reauth")
    packet_file = Path(str(state["packet"])) / "target/src/main.py"
    packet_file.chmod(0o600)
    packet_file.write_text("evil\n")
    packet_file.chmod(0o444)
    with pytest.raises(submit.PilotSubmitError):
        runner.native_launch_plan(execution, ["reauth"])
    packet_file.chmod(0o600)
    packet_file.write_text("new\n")
    packet_file.chmod(0o444)
    state["deadline_unix_ms"] = 0
    runner._replace_private_json(
        execution / "attempts/reauth/native-state.json", cast("dict[str, object]", state)
    )
    with pytest.raises(runner.PilotTypedRunError, match="deadline expired"):
        runner.native_launch_plan(execution, ["reauth"])
    with pytest.raises((runner.PilotTypedRunError, submit.PilotSubmitError)):
        runner.finalize_native_attempt(
            execution_root=execution, attempt_id="reauth", wait_seconds=0
        )


def test_relative_execution_root_rejected_by_api_and_cli(tmp_path: Path) -> None:
    relative = Path("relative-execution")
    with pytest.raises(runner.PilotTypedRunError, match="must be absolute"):
        runner.native_launch_plan(relative, ["attempt"])
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "benchmarks.real_world.pilot_typed_run_v3",
            "native-launch-plan",
            "--execution-root",
            str(relative),
            "--attempt-id",
            "attempt",
        ],
        cwd=Path(__file__).resolve().parents[2],
        text=True,
        capture_output=True,
        check=False,
        timeout=20,
    )
    assert result.returncode != 0
    assert "execution root must be absolute" in result.stderr


def test_dead_unpublished_preparation_lease_is_reconciled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = Path(__file__).resolve().parents[2]
    parent = _private(tmp_path / "private")
    execution = parent / "execution"
    execution = runner._open_execution(source, execution, "openai-codex/gpt-5.6-luna", "medium")
    attempt = _private(execution / "attempts/orphan")
    lease = execution / "leases/slot-0.json"
    lease.write_bytes(
        canonical_json(
            {
                "schema_version": 1,
                "slot": 0,
                "attempt_id": "orphan",
                "phase": "preparing",
                "owner_pid": 999_999_999,
                "owner_start_identity": "1",
                "created_at": runner._utc_text(runner._utc_now()),
                "state_path": str(attempt / "native-state.json"),
                "broker_pid": None,
                "broker_start_identity": None,
                "registry": None,
                "socket_dir": None,
            }
        )
    )
    lease.chmod(0o600)
    slot, claimed = runner._claim_lease(execution, "replacement")
    assert slot == 0 and claimed == lease
    assert (attempt / "native-failure.json").is_file()
    assert runner._json(lease, 128 * 1024, modes={0o600})["attempt_id"] == "replacement"
    runner._release_lease(lease, "replacement")


def test_prepare_failure_cleans_lease_registry_and_socket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, packets, cache, execution = _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(
        runner,
        "_wait_socket",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            runner.PilotTypedRunError("forced readiness failure")
        ),
    )
    with pytest.raises(runner.PilotTypedRunError, match="forced readiness"):
        _prepare(source, packets, cache, execution, "setup-failure")
    attempt = execution / "attempts/setup-failure"
    assert (attempt / "native-failure.json").is_file()
    assert not list((execution / "leases").iterdir())
    runtime = runner._runtime_root()
    descriptors = [
        runner._json(path, 128 * 1024, modes={0o600})
        for path in (runtime / "registry").glob("*.json")
    ]
    assert all(item.get("attempt_id") != "setup-failure" for item in descriptors)


def test_python_production_has_no_direct_pi_model_launch() -> None:
    source = Path(__file__).resolve().parents[2]
    runner_text = (source / "benchmarks/real_world/pilot_typed_run_v3.py").read_text()
    assert "--model" not in runner_text
    assert "--thinking" not in runner_text
    assert "pi_executable" not in runner_text
    assert "direct Pi child" not in runner_text


def _session_file(
    path: Path,
    packet: Path,
    receipt: dict[str, Any],
    *,
    escaped_path: str | None = None,
    prose: str = "",
    model: str = "gpt-5.6-luna",
    submit_transport_error: bool = False,
) -> Path:
    calls = [
        {
            "type": "message",
            "message": {
                "role": "assistant",
                "content": [
                    {"type": "thinking", "thinking": "inspect"},
                    {
                        "type": "toolCall",
                        "id": "read-1",
                        "name": "read",
                        "arguments": {"path": escaped_path or "target/src/main.py"},
                    },
                ],
                "usage": {
                    "input": 10,
                    "output": 2,
                    "cacheRead": 3,
                    "cost": {"total": 0.0012344},
                },
            },
        },
        {
            "type": "message",
            "message": {
                "role": "toolResult",
                "toolCallId": "read-1",
                "toolName": "read",
                "content": [{"type": "text", "text": "new"}],
                "isError": False,
            },
        },
        {
            "type": "message",
            "message": {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": prose},
                    {
                        "type": "toolCall",
                        "id": "submit-1",
                        "name": "submit_blind_review",
                        "arguments": _draft(),
                    },
                ],
                "usage": {
                    "input": 20,
                    "output": 4,
                    "cacheRead": 5,
                    "cost": {"total": 0.0023456},
                },
            },
        },
        {
            "type": "message",
            "message": {
                "role": "toolResult",
                "toolCallId": "submit-1",
                "toolName": "submit_blind_review",
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "connection refused"
                            if submit_transport_error
                            else "SUBMISSION_REJECTED code=EVIDENCE_INVALID "
                            "diagnostic=claims[0].evidence[0] misses changed hunk"
                        ),
                    }
                ],
                **(
                    {}
                    if submit_transport_error
                    else {
                        "details": {
                            "protocol_version": 3,
                            "ok": False,
                            "code": "EVIDENCE_INVALID",
                            "diagnostic": "claims[0].evidence[0] misses changed hunk",
                        }
                    }
                ),
                "isError": submit_transport_error,
            },
        },
        {
            "type": "message",
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "type": "toolCall",
                        "id": "submit-2",
                        "name": "submit_blind_review",
                        "arguments": _draft(),
                    }
                ],
                "usage": {
                    "input": 30,
                    "output": 6,
                    "cacheRead": 7,
                    "cost": {"total": 0.0034567},
                },
            },
        },
        {
            "type": "message",
            "message": {
                "role": "toolResult",
                "toolCallId": "submit-2",
                "toolName": "submit_blind_review",
                "content": [{"type": "text", "text": "submitted"}],
                "details": receipt,
                "isError": False,
            },
        },
        {
            "type": "message",
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "type": "text",
                        "text": "SUBMISSION_COMPLETE",
                        "textSignature": '{"v":1,"phase":"final_answer"}',
                    }
                ],
                "usage": {
                    "input": 5,
                    "output": 1,
                    "cacheRead": 0,
                    "cost": {"total": 0.0001},
                },
            },
        },
    ]
    events = [
        {"type": "session", "version": 3, "id": "session", "cwd": str(packet)},
        {
            "type": "model_change",
            "provider": "openai-codex",
            "modelId": model,
        },
        {"type": "thinking_level_change", "thinkingLevel": "medium"},
        {"type": "session_info", "name": "native-review"},
        {"type": "message", "message": {"role": "user", "content": []}},
        *calls,
    ]
    path.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events))
    return path


def test_native_session_audit_accepts_nonerror_rejection_then_terminal_escrow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, packets, cache, execution = _setup(tmp_path, monkeypatch)
    _prepare(source, packets, cache, execution, "audited")
    client = _client_script(tmp_path / "client.py")
    assert _submit(execution, "audited", client).returncode == 0
    runner.finalize_native_attempt(execution_root=execution, attempt_id="audited")
    _, state = runner._load_native_state(execution, "audited")
    authenticated = runner._json(
        execution / "attempts/audited/native-result.json", 2 * 1024 * 1024, modes={0o400}
    )
    session = _session_file(
        tmp_path / "session.jsonl",
        Path(str(state["packet"])),
        cast("dict[str, Any]", authenticated["receipt"]),
    )
    result = runner.audit_native_sessions(execution, [("audited", session)])
    row = cast("list[dict[str, Any]]", result["results"])[0]
    assert row["eventual_escrow_accepted"] is True
    assert row["submit_calls"] == 2
    assert row["correction_submissions"] == 1
    assert row["submit_errors"] == 0
    assert row["semantic_rejections"] == 1
    assert row["terminal_acknowledgement"] == "SUBMISSION_COMPLETE"
    assert row["parent_success_compatible"] is True
    assert row["usage"] == {
        "input_tokens": 65,
        "output_tokens": 13,
        "cache_read_tokens": 15,
        "cost_usd_observed": pytest.approx(0.0071367),
        "cost_micro_usd": 7137,
    }


def test_native_session_audit_accepts_first_success_then_exact_acknowledgement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, packets, cache, execution = _setup(tmp_path, monkeypatch)
    _prepare(source, packets, cache, execution, "first-success")
    client = _client_script(tmp_path / "client.py")
    assert _submit(execution, "first-success", client).returncode == 0
    runner.finalize_native_attempt(execution_root=execution, attempt_id="first-success")
    _, state = runner._load_native_state(execution, "first-success")
    authenticated = runner._json(
        execution / "attempts/first-success/native-result.json",
        2 * 1024 * 1024,
        modes={0o400},
    )
    session = _session_file(
        tmp_path / "first-success.jsonl",
        Path(str(state["packet"])),
        cast("dict[str, Any]", authenticated["receipt"]),
    )
    events = [json.loads(line) for line in session.read_text().splitlines()]
    events = [
        event
        for event in events
        if not (
            event.get("type") == "message"
            and event["message"].get("role") in {"assistant", "toolResult"}
            and (
                event["message"].get("toolCallId") == "submit-1"
                or any(
                    part.get("id") == "submit-1"
                    for part in event["message"].get("content", [])
                    if isinstance(part, dict)
                )
            )
        )
    ]
    session.write_text("".join(json.dumps(event) + "\n" for event in events))
    row = runner.audit_native_session(execution, "first-success", session)
    assert row["submit_calls"] == 1
    assert row["correction_submissions"] == 0
    assert row["terminal_acknowledgement"] == "SUBMISSION_COMPLETE"


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        ("missing", "submission result is invalid"),
        ("wrong", "exact terminal acknowledgement"),
        ("early", "forbidden prose"),
        ("later_tool", "exact terminal acknowledgement"),
    ],
)
def test_native_session_audit_rejects_invalid_acknowledgement_sequence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    match: str,
) -> None:
    source, packets, cache, execution = _setup(tmp_path, monkeypatch)
    _prepare(source, packets, cache, execution, f"ack-{mutation}")
    client = _client_script(tmp_path / "client.py")
    assert _submit(execution, f"ack-{mutation}", client).returncode == 0
    runner.finalize_native_attempt(execution_root=execution, attempt_id=f"ack-{mutation}")
    _, state = runner._load_native_state(execution, f"ack-{mutation}")
    authenticated = runner._json(
        execution / f"attempts/ack-{mutation}/native-result.json",
        2 * 1024 * 1024,
        modes={0o400},
    )
    session = _session_file(
        tmp_path / f"ack-{mutation}.jsonl",
        Path(str(state["packet"])),
        cast("dict[str, Any]", authenticated["receipt"]),
    )
    events = [json.loads(line) for line in session.read_text().splitlines()]
    ack = events[-1]
    if mutation == "missing":
        events.pop()
    elif mutation == "wrong":
        ack["message"]["content"][0]["text"] = "SUBMISSION COMPLETE"
    elif mutation == "early":
        events.pop()
        events.insert(-1, ack)
    else:
        events.insert(
            -1,
            {
                "type": "message",
                "message": {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "toolCall",
                            "id": "read-late",
                            "name": "read",
                            "arguments": {"path": "target/src/main.py"},
                        }
                    ],
                    "usage": {
                        "input": 1,
                        "output": 1,
                        "cacheRead": 0,
                        "cost": {"total": 0.0},
                    },
                },
            },
        )
    session.write_text("".join(json.dumps(event) + "\n" for event in events))
    with pytest.raises(runner.PilotTypedRunError, match=match):
        runner.audit_native_session(execution, f"ack-{mutation}", session)


def test_native_session_audit_rejects_submit_transport_error_even_before_escrow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, packets, cache, execution = _setup(tmp_path, monkeypatch)
    _prepare(source, packets, cache, execution, "transport-error")
    client = _client_script(tmp_path / "client.py")
    assert _submit(execution, "transport-error", client).returncode == 0
    runner.finalize_native_attempt(execution_root=execution, attempt_id="transport-error")
    _, state = runner._load_native_state(execution, "transport-error")
    authenticated = runner._json(
        execution / "attempts/transport-error/native-result.json",
        2 * 1024 * 1024,
        modes={0o400},
    )
    session = _session_file(
        tmp_path / "transport-error.jsonl",
        Path(str(state["packet"])),
        cast("dict[str, Any]", authenticated["receipt"]),
        submit_transport_error=True,
    )
    with pytest.raises(runner.PilotTypedRunError, match="transport, security, or protocol"):
        runner.audit_native_session(execution, "transport-error", session)


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"escaped_path": "/outside/source.py"}, "escaped assigned packet"),
        ({"prose": "forbidden final prose"}, "forbidden prose"),
        ({"model": "gpt-5.6-other"}, "model does not match"),
    ],
)
def test_native_session_audit_rejects_identity_path_and_prose_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kwargs: dict[str, str],
    match: str,
) -> None:
    source, packets, cache, execution = _setup(tmp_path, monkeypatch)
    _prepare(source, packets, cache, execution, "tampered-session")
    client = _client_script(tmp_path / "client.py")
    assert _submit(execution, "tampered-session", client).returncode == 0
    runner.finalize_native_attempt(execution_root=execution, attempt_id="tampered-session")
    _, state = runner._load_native_state(execution, "tampered-session")
    authenticated = runner._json(
        execution / "attempts/tampered-session/native-result.json",
        2 * 1024 * 1024,
        modes={0o400},
    )
    session = _session_file(
        tmp_path / "session.jsonl",
        Path(str(state["packet"])),
        cast("dict[str, Any]", authenticated["receipt"]),
        **cast("dict[str, Any]", kwargs),
    )
    with pytest.raises(runner.PilotTypedRunError, match=match):
        runner.audit_native_session(execution, "tampered-session", session)


def test_rename_noreplace_allows_exactly_one_concurrent_publisher(tmp_path: Path) -> None:
    parent = _private(tmp_path / "publish")
    sources = [parent / "one", parent / "two"]
    for index, source in enumerate(sources):
        source.mkdir()
        (source / "value").write_text(str(index))
    target = parent / "target"
    barrier = threading.Barrier(2)
    outcomes: list[str] = []

    def publish(source: Path) -> None:
        barrier.wait()
        try:
            runner._rename_noreplace(source, target)
            outcomes.append("published")
        except runner.PilotTypedRunError:
            outcomes.append("refused")

    threads = [threading.Thread(target=publish, args=(source,)) for source in sources]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert sorted(outcomes) == ["published", "refused"]
    assert (target / "value").read_text() in {"0", "1"}


def test_finalize_waits_for_inflight_submission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, packets, cache, execution = _setup(tmp_path, monkeypatch)
    _prepare(source, packets, cache, execution, "inflight")
    client = _client_script(tmp_path / "client.py")
    responses: list[subprocess.CompletedProcess[str]] = []

    def delayed_submit() -> None:
        __import__("time").sleep(0.15)
        responses.append(_submit(execution, "inflight", client))

    thread = threading.Thread(target=delayed_submit)
    thread.start()
    result = runner.finalize_native_attempt(execution_root=execution, attempt_id="inflight")
    thread.join(timeout=10)
    assert responses and responses[0].returncode == 0
    assert result["attempt_id"] == "inflight"


def test_audit_reauthenticates_result_and_enforces_terminal_sequence_and_usage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, packets, cache, execution = _setup(tmp_path, monkeypatch)
    _prepare(source, packets, cache, execution, "audit-hardening")
    client = _client_script(tmp_path / "client.py")
    assert _submit(execution, "audit-hardening", client).returncode == 0
    runner.finalize_native_attempt(execution_root=execution, attempt_id="audit-hardening")
    _, state = runner._load_native_state(execution, "audit-hardening")
    result_path = execution / "attempts/audit-hardening/native-result.json"
    original = result_path.read_bytes()
    result = json.loads(original)
    fake = "sha256:" + "0" * 64
    result["artifact_sha256"] = fake
    result["receipt"]["sha256"] = fake
    result_path.chmod(0o600)
    result_path.write_bytes(canonical_json(result))
    result_path.chmod(0o400)
    receipt = cast("dict[str, Any]", json.loads(original)["receipt"])
    session = _session_file(tmp_path / "base.jsonl", Path(str(state["packet"])), receipt)
    with pytest.raises(runner.PilotTypedRunError, match="authentication"):
        runner.audit_native_session(execution, "audit-hardening", session)
    result_path.chmod(0o600)
    result_path.write_bytes(original)
    result_path.chmod(0o400)

    events = [json.loads(line) for line in session.read_text().splitlines()]
    events.append({"type": "session_info", "name": "after-success"})
    trailing = tmp_path / "trailing.jsonl"
    trailing.write_text("".join(json.dumps(item) + "\n" for item in events))
    with pytest.raises(runner.PilotTypedRunError, match="terminal session event"):
        runner.audit_native_session(execution, "audit-hardening", trailing)

    events = [json.loads(line) for line in session.read_text().splitlines()]
    assistant = next(
        item
        for item in events
        if item.get("type") == "message" and item["message"].get("role") == "assistant"
    )
    events.remove(assistant)
    events.insert(1, assistant)
    early = tmp_path / "early.jsonl"
    early.write_text("".join(json.dumps(item) + "\n" for item in events))
    with pytest.raises(runner.PilotTypedRunError, match="preceded model/thinking"):
        runner.audit_native_session(execution, "audit-hardening", early)

    events = [json.loads(line) for line in session.read_text().splitlines()]
    first_assistant = next(
        item
        for item in events
        if item.get("type") == "message" and item["message"].get("role") == "assistant"
    )
    first_assistant["message"]["usage"]["input"] = 1.5
    bad_usage = tmp_path / "bad-usage.jsonl"
    bad_usage.write_text("".join(json.dumps(item) + "\n" for item in events))
    with pytest.raises(runner.PilotTypedRunError, match="usage input"):
        runner.audit_native_session(execution, "audit-hardening", bad_usage)
