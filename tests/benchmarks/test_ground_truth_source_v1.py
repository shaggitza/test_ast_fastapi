from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from benchmarks.real_world import ground_truth_campaign_v1 as campaign_module
from benchmarks.real_world import ground_truth_source_v1 as source
from benchmarks.real_world.ground_truth_v2.schema import canonical_json


def _git(git_dir: Path, *args: str, input_bytes: bytes | None = None) -> bytes:
    result = subprocess.run(
        ["git", "--git-dir", str(git_dir), *args],
        input=input_bytes,
        capture_output=True,
        check=True,
    )
    return result.stdout


def _remote(tmp_path: Path) -> tuple[Path, list[str]]:
    remote = tmp_path / "inert.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    tree = _git(remote, "mktree", input_bytes=b"").decode().strip()
    parent = _git(remote, "commit-tree", tree, "-m", "hidden parent").decode().strip()
    commits: list[str] = []
    for index in range(2):
        commit = (
            _git(
                remote,
                "commit-tree",
                tree,
                "-p",
                parent,
                "-m",
                f"wanted {index}",
            )
            .decode()
            .strip()
        )
        _git(remote, "update-ref", f"refs/heads/wanted-{index}", commit)
        commits.append(commit)
    return remote, commits


def _campaign(commits: list[str], *, unique: bool = False) -> tuple[dict[str, Any], bytes]:
    commit_rows = [f"{index:040x}" for index in range(1, 101)] if unique else commits * 50
    records = []
    lanes = []
    for index in range(50):
        baseline = commit_rows[index * 2]
        target = commit_rows[index * 2 + 1]
        pr = 1000 + index
        records.append(
            {
                "rank": index + 1,
                "repository": "owner/repository",
                "pr": pr,
                "baseline_commit": baseline,
                "target_commit": target,
                "diff_sha256": "sha256:" + f"{index + 1:064x}",
                "diff_bytes": index + 1,
                "diff_final_url": f"https://example.invalid/{pr}.diff",
                "diff_content_type": "text/plain; charset=utf-8",
            }
        )
        for lane in ("A", "B"):
            lanes.append({"lane": lane, "pr": pr})
    value = {
        "schema_version": 1,
        "id": "ground-truth-production-v1-issue-149",
        "authorization": {
            "canonical_import_authorized": False,
            "live_launch_authorized": False,
            "source_packet_materialization_authorized": False,
        },
        "corpus": {"id": "oss-expansion-pr-lock-2500-v2"},
        "assignment": {"issue": 149, "repository": "owner/repository"},
        "records": records,
        "lanes": lanes,
    }
    return value, canonical_json(value)


def _install_campaign(monkeypatch: pytest.MonkeyPatch, value: dict[str, Any], raw: bytes) -> None:
    monkeypatch.setattr(source, "_profile", lambda _root: None)
    monkeypatch.setattr(source, "_campaign", lambda _root, _path: (value, raw))


def _freeze(path: Path) -> None:
    source._freeze(path)


def _thaw(path: Path) -> None:
    for directory, names, filenames in os.walk(path):
        Path(directory).chmod(0o700)
        for name in names:
            Path(directory, name).chmod(0o700)
        for name in filenames:
            Path(directory, name).chmod(0o600)


@pytest.fixture
def prepared(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path, Path, dict[str, Any], bytes]:
    remote, commits = _remote(tmp_path)
    campaign, raw = _campaign(commits)
    _install_campaign(monkeypatch, campaign, raw)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    campaign_path = tmp_path / "unused-campaign.json"
    cache = private / "source.git"
    source.prepare_cache(
        tmp_path,
        campaign_path,
        cache,
        _test_transport=(str(remote), source._TEST_TRANSPORT_CAPABILITY),
    )
    return private, campaign_path, cache, campaign, raw


def test_expected_commit_set_supports_fifty_records_and_one_hundred_commits() -> None:
    campaign, _ = _campaign([], unique=True)
    commits = source._expected_commits(campaign)
    assert len(campaign["records"]) == 50
    assert len(commits) == 100


def test_prepare_and_validate_cache_deduplicate_and_freeze(prepared: tuple[Any, ...]) -> None:
    _, campaign_path, cache, _, _ = prepared
    result = source.validate_cache(Path.cwd(), campaign_path, cache)
    assert len(result["commits"]) == 2
    assert result["validated_offline"] is True
    assert stat.S_IMODE(cache.stat().st_mode) == 0o500
    assert all(
        stat.S_IMODE(path.stat().st_mode) == 0o400 for path in cache.rglob("*") if path.is_file()
    )
    assert not (cache / "FETCH_HEAD").exists()
    assert not _git(cache, "for-each-ref", "--format=%(refname)")


def test_symlinked_private_parent_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign, raw = _campaign(["1" * 40, "2" * 40])
    _install_campaign(monkeypatch, campaign, raw)
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    with pytest.raises(source.SourceV1Error, match="symlink"):
        source.prepare_cache(
            tmp_path,
            tmp_path / "unused.json",
            linked / "source.git",
            _test_transport=(str(tmp_path / "unused.git"), source._TEST_TRANSPORT_CAPABILITY),
        )


def test_prepare_is_no_clobber(prepared: tuple[Any, ...]) -> None:
    private, campaign_path, cache, _, _ = prepared
    with pytest.raises(source.SourceV1Error, match=r"absent|already exists"):
        source.prepare_cache(
            Path.cwd(),
            campaign_path,
            cache,
            _test_transport=(str(private), source._TEST_TRANSPORT_CAPABILITY),
        )


def test_atomic_publication_racing_empty_destination_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    remote, commits = _remote(tmp_path)
    campaign, raw = _campaign(commits)
    _install_campaign(monkeypatch, campaign, raw)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    cache = private / "source.git"
    original = source._rename_noreplace

    def race(staging: Path, destination: Path, parent_descriptor: int | None = None) -> None:
        destination.mkdir(mode=0o700)
        original(staging, destination, parent_descriptor)

    monkeypatch.setattr(source, "_rename_noreplace", race)
    with pytest.raises(source.SourceV1Error, match="already exists"):
        source.prepare_cache(
            tmp_path,
            tmp_path / "unused.json",
            cache,
            _test_transport=(str(remote), source._TEST_TRANSPORT_CAPABILITY),
        )
    assert cache.is_dir() and not list(cache.iterdir())


def test_validation_rejects_symlinked_private_parent(
    prepared: tuple[Any, ...], tmp_path: Path
) -> None:
    private, campaign_path, cache, _, _ = prepared
    linked = tmp_path / "linked-private"
    linked.symlink_to(private, target_is_directory=True)
    with pytest.raises(source.SourceV1Error, match="symlink"):
        source.validate_cache(Path.cwd(), campaign_path, linked / cache.name)


def test_wrong_shallow_boundary_fails(prepared: tuple[Any, ...]) -> None:
    _, campaign_path, cache, _, _ = prepared
    _thaw(cache)
    shallow = cache / "shallow"
    shallow.write_text(shallow.read_text().splitlines()[0] + "\n")
    _freeze(cache)
    with pytest.raises(source.SourceV1Error, match="shallow boundary"):
        source.validate_cache(Path.cwd(), campaign_path, cache)


def test_duplicate_shallow_boundary_fails(prepared: tuple[Any, ...]) -> None:
    _, campaign_path, cache, _, _ = prepared
    _thaw(cache)
    shallow = cache / "shallow"
    first = shallow.read_text().splitlines()[0]
    shallow.write_text(shallow.read_text() + first + "\n")
    _freeze(cache)
    with pytest.raises(source.SourceV1Error, match="canonical commit list"):
        source.validate_cache(Path.cwd(), campaign_path, cache)


def test_extra_ref_fails(prepared: tuple[Any, ...]) -> None:
    _, campaign_path, cache, campaign, _ = prepared
    _thaw(cache)
    _git(cache, "update-ref", "refs/heads/extra", campaign["records"][0]["baseline_commit"])
    _freeze(cache)
    with pytest.raises(source.SourceV1Error, match="refs"):
        source.validate_cache(Path.cwd(), campaign_path, cache)


def test_extra_object_fails(prepared: tuple[Any, ...]) -> None:
    _, campaign_path, cache, _, _ = prepared
    _thaw(cache)
    _git(cache, "hash-object", "-w", "--stdin", input_bytes=b"unreachable extra")
    _freeze(cache)
    with pytest.raises(source.SourceV1Error, match="extra Git objects"):
        source.validate_cache(Path.cwd(), campaign_path, cache)


@pytest.mark.parametrize("kind", ["alternate", "promisor", "replace"])
def test_forbidden_git_indirection_fails(prepared: tuple[Any, ...], kind: str) -> None:
    _, campaign_path, cache, campaign, _ = prepared
    _thaw(cache)
    if kind == "alternate":
        path = cache / "objects" / "info" / "alternates"
        path.write_text("/tmp/forbidden\n")
    elif kind == "promisor":
        _git(cache, "config", "remote.origin.promisor", "true")
    else:
        _git(
            cache,
            "update-ref",
            "refs/replace/" + campaign["records"][0]["baseline_commit"],
            campaign["records"][0]["target_commit"],
        )
    _freeze(cache)
    with pytest.raises(source.SourceV1Error, match=r"forbidden|refs|replacement"):
        source.validate_cache(Path.cwd(), campaign_path, cache)


def test_symlink_and_mode_tamper_fail(prepared: tuple[Any, ...]) -> None:
    _, campaign_path, cache, _, _ = prepared
    cache.chmod(0o700)
    (cache / "bad-link").symlink_to("config")
    cache.chmod(0o500)
    with pytest.raises(source.SourceV1Error, match=r"symlink|mode"):
        source.validate_cache(Path.cwd(), campaign_path, cache)


def test_missing_commit_and_wrong_tree_fail(
    prepared: tuple[Any, ...], monkeypatch: pytest.MonkeyPatch
) -> None:
    _, campaign_path, cache, campaign, raw = prepared
    missing = json.loads(json.dumps(campaign))
    missing["records"][0]["baseline_commit"] = "0" * 40
    _install_campaign(monkeypatch, missing, canonical_json(missing))
    with pytest.raises(source.SourceV1Error, match=r"shallow boundary|Git command failed"):
        source.validate_cache(Path.cwd(), campaign_path, cache)

    _install_campaign(monkeypatch, campaign, raw)
    runner = source.GitRunner()
    commit = source._expected_commits(campaign)[0]
    original = source._git_text

    def wrong_tree(
        active_runner: source.GitRunner,
        active_cache: Path,
        args: list[str],
        *,
        check: bool = True,
    ) -> str:
        if args[:3] == ["show", "-s", "--format=%T"]:
            return "not-a-tree\n"
        return original(active_runner, active_cache, args, check=check)

    monkeypatch.setattr(source, "_git_text", wrong_tree)
    with pytest.raises(source.SourceV1Error, match="tree identity"):
        source._derive(runner, cache, [commit])


def test_disk_and_file_bounds(prepared: tuple[Any, ...], monkeypatch: pytest.MonkeyPatch) -> None:
    _, _, cache, _, _ = prepared
    monkeypatch.setattr(source, "_MAX_DISK", 0)
    with pytest.raises(source.SourceV1Error, match="disk bound"):
        source._tree_bounds(cache)
    monkeypatch.setattr(source, "_MAX_DISK", 5 * 1024 * 1024 * 1024)
    monkeypatch.setattr(source, "_MAX_FILES", 0)
    with pytest.raises(source.SourceV1Error, match="file bound"):
        source._tree_bounds(cache)


def test_validation_detects_descendant_added_after_git_checks(
    prepared: tuple[Any, ...], monkeypatch: pytest.MonkeyPatch
) -> None:
    _, campaign_path, cache, _, _ = prepared
    original = source._cache_summary
    start = threading.Event()
    finished = threading.Event()

    def concurrent_mutation() -> None:
        assert start.wait(5)
        cache.chmod(0o700)
        extra = cache / "concurrent-extra"
        extra.write_bytes(b"drift")
        extra.chmod(0o400)
        cache.chmod(0o500)
        finished.set()

    def coordinate(*args: Any, **kwargs: Any) -> dict[str, Any]:
        result = original(*args, **kwargs)
        start.set()
        assert finished.wait(5)
        return result

    thread = threading.Thread(target=concurrent_mutation)
    thread.start()
    monkeypatch.setattr(source, "_cache_summary", coordinate)
    with pytest.raises(source.SourceV1Error, match=r"inventory drifted|identity.*drifted"):
        source.validate_cache(Path.cwd(), campaign_path, cache)
    thread.join(timeout=5)
    assert not thread.is_alive()


def test_stable_extra_is_completely_bound(prepared: tuple[Any, ...]) -> None:
    _, campaign_path, cache, _, _ = prepared
    before = source.validate_cache(Path.cwd(), campaign_path, cache)
    cache.chmod(0o700)
    extra = cache / "bound-extra"
    extra.write_bytes(b"bound data")
    extra.chmod(0o400)
    cache.chmod(0o500)
    after = source.validate_cache(Path.cwd(), campaign_path, cache)
    assert after["inventory_sha256"] != before["inventory_sha256"]
    assert after["file_count"] == before["file_count"] + 1
    assert after["disk_bytes"] == before["disk_bytes"] + len(b"bound data")


def test_build_and_validate_bindings_and_tamper(prepared: tuple[Any, ...]) -> None:
    private, campaign_path, cache, _, _ = prepared
    output = private / "bindings.json"
    source.build_source_bindings(Path.cwd(), campaign_path, cache, output)
    with pytest.raises(source.SourceV1Error, match="absent"):
        source.build_source_bindings(Path.cwd(), campaign_path, cache, output)
    result = source.validate_source_bindings(Path.cwd(), campaign_path, cache, output)
    assert result == {
        "valid": True,
        "sha256": result["sha256"],
        "records": 50,
        "commit_count": 2,
        "live_launch_authorized": False,
    }
    output.chmod(0o600)
    value = json.loads(output.read_text())
    value["records"][0]["baseline_tree"] = "0" * 40
    output.write_bytes(canonical_json(value))
    output.chmod(0o400)
    with pytest.raises(source.SourceV1Error, match="differ"):
        source.validate_source_bindings(Path.cwd(), campaign_path, cache, output)


def test_binding_publication_detects_concurrent_descendant_extra(
    prepared: tuple[Any, ...], monkeypatch: pytest.MonkeyPatch
) -> None:
    private, campaign_path, cache, _, _ = prepared
    output = private / "bindings.json"
    original = source._publish

    def publish_then_mutate(path: Path, value: dict[str, Any]) -> None:
        original(path, value)
        cache.chmod(0o700)
        extra = cache / "publish-race"
        extra.write_bytes(b"race")
        extra.chmod(0o400)
        cache.chmod(0o500)

    monkeypatch.setattr(source, "_publish", publish_then_mutate)
    with pytest.raises(source.SourceV1Error, match="drifted around"):
        source.build_source_bindings(Path.cwd(), campaign_path, cache, output)


def test_binding_validation_detects_concurrent_descendant_extra(
    prepared: tuple[Any, ...], monkeypatch: pytest.MonkeyPatch
) -> None:
    private, campaign_path, cache, _, _ = prepared
    output = private / "bindings.json"
    source.build_source_bindings(Path.cwd(), campaign_path, cache, output)
    original = source._campaign
    calls = 0

    def campaign_then_mutate(root: Path, path: Path) -> tuple[dict[str, Any], bytes]:
        nonlocal calls
        calls += 1
        result = original(root, path)
        if calls == 2:
            cache.chmod(0o700)
            extra = cache / "validation-race"
            extra.write_bytes(b"race")
            extra.chmod(0o400)
            cache.chmod(0o500)
        return result

    monkeypatch.setattr(source, "_campaign", campaign_then_mutate)
    with pytest.raises(source.SourceV1Error, match="drifted around"):
        source.validate_source_bindings(Path.cwd(), campaign_path, cache, output)


def test_cache_inode_swap_invalidates_existing_bindings(prepared: tuple[Any, ...]) -> None:
    private, campaign_path, cache, _, _ = prepared
    output = private / "bindings.json"
    source.build_source_bindings(Path.cwd(), campaign_path, cache, output)
    replacement = private / "replacement.git"
    shutil.copytree(cache, replacement, copy_function=shutil.copy2)
    backup = private / "old.git"
    cache.rename(backup)
    replacement.rename(cache)
    with pytest.raises(source.SourceV1Error, match="differ"):
        source.validate_source_bindings(Path.cwd(), campaign_path, cache, output)


def test_root_and_file_mode_tamper_fail(prepared: tuple[Any, ...]) -> None:
    _, campaign_path, cache, _, _ = prepared
    cache.chmod(0o700)
    with pytest.raises(source.SourceV1Error, match="cache root"):
        source.validate_cache(Path.cwd(), campaign_path, cache)


def test_full_cardinality_command_formula_and_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign, _ = _campaign([], unique=True)
    commits = source._expected_commits(campaign)
    exact = 2 * len(commits) + 2 + 3 * len(commits) + 13
    assert exact == source._MAX_PREPARATION_COMMANDS == 515
    assert source._MAX_VALIDATION_COMMANDS == 313

    class CompletedProcess:
        returncode = 0

    monkeypatch.setattr(subprocess, "Popen", lambda *_args, **_kwargs: CompletedProcess())
    monkeypatch.setattr(source.GitRunner, "_collect", lambda *_args, **_kwargs: (b"", b""))
    runner = source.GitRunner(command_limit=exact)
    for _ in range(exact):
        runner.run(Path("/unused"), ["status"])
    assert runner.commands == exact
    with pytest.raises(source.SourceV1Error, match="command bound"):
        runner.run(Path("/unused"), ["status"])


def test_streaming_output_overflow_kills_and_reaps(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    terminated: list[int] = []
    original = source.GitRunner._terminate

    def record(process: subprocess.Popen[bytes]) -> None:
        terminated.append(process.pid)
        original(process)

    monkeypatch.setattr(source, "_MAX_OUTPUT", 1)
    monkeypatch.setattr(source.GitRunner, "_terminate", staticmethod(record))
    runner = source.GitRunner()
    with pytest.raises(source.SourceV1Error, match=r"output bound.*reaped"):
        runner.run(tmp_path, ["--version"])
    assert len(terminated) == 1


def test_streaming_timeout_kills_and_reaps(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    terminated: list[int] = []
    original = source.GitRunner._terminate

    def record(process: subprocess.Popen[bytes]) -> None:
        terminated.append(process.pid)
        original(process)

    monkeypatch.setattr(source, "_COMMAND_TIMEOUT", -1)
    monkeypatch.setattr(source.GitRunner, "_terminate", staticmethod(record))
    runner = source.GitRunner()
    with pytest.raises(source.SourceV1Error, match=r"timed out.*reaped"):
        runner.run(tmp_path, ["--version"])
    assert len(terminated) == 1


def test_fetch_disk_monitor_kills_and_reaps(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    terminated: list[int] = []
    original_terminate = source.GitRunner._terminate
    original_bounds = source._tree_bounds

    def record(process: subprocess.Popen[bytes]) -> None:
        terminated.append(process.pid)
        original_terminate(process)

    def overflow(path: Path) -> tuple[int, int]:
        if path == tmp_path:
            raise source.SourceV1Error("cache disk bound exceeded")
        return original_bounds(path)

    monkeypatch.setattr(source.GitRunner, "_terminate", staticmethod(record))
    monkeypatch.setattr(source, "_tree_bounds", overflow)
    runner = source.GitRunner()
    with pytest.raises(source.SourceV1Error, match="disk bound"):
        runner.run(tmp_path, ["--version"], monitor_root=tmp_path)
    assert len(terminated) == 1


def test_timeout_after_output_pipes_close_kills_and_reaps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    terminated: list[int] = []
    original = source.GitRunner._terminate

    def record(process: subprocess.Popen[bytes]) -> None:
        terminated.append(process.pid)
        original(process)

    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import os,time; os.close(1); os.close(2); time.sleep(1)",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    monkeypatch.setattr(source, "_COMMAND_TIMEOUT", 0.05)
    monkeypatch.setattr(source.GitRunner, "_terminate", staticmethod(record))
    started = time.monotonic()
    with pytest.raises(source.SourceV1Error, match=r"timed out.*reaped"):
        source.GitRunner()._collect(process, monitor_root=None)
    assert time.monotonic() - started < 0.5
    assert terminated == [process.pid]


def test_test_transport_requires_unforgeable_direct_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign, raw = _campaign(["1" * 40, "2" * 40])
    _install_campaign(monkeypatch, campaign, raw)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "forged")
    with pytest.raises(source.SourceV1Error, match="capability"):
        source.prepare_cache(
            tmp_path,
            tmp_path / "unused.json",
            private / "source.git",
            _test_transport=(str(tmp_path / "remote.git"), object()),
        )


def test_campaign_requires_false_gates_and_canonical_corpus(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    campaign, _ = _campaign(["1" * 40, "2" * 40])
    campaign["authorization"]["live_launch_authorized"] = True
    path = tmp_path / "campaign.json"
    path.write_bytes(canonical_json(campaign))
    path.chmod(0o400)
    monkeypatch.setattr(source, "_profile", lambda _root: None)
    monkeypatch.setattr(
        campaign_module,
        "validate_manifest",
        lambda _root, _value: None,
    )
    with pytest.raises(source.SourceV1Error, match="canonical offline"):
        source._campaign(tmp_path, path)


def test_source_module_has_no_model_or_source_execution_surface() -> None:
    text = Path(source.__file__).read_text()
    forbidden = ["subagent(", "pi -p", "checkout", "worktree", "archive", "submodule", "git clone"]
    for token in forbidden:
        assert token not in text
