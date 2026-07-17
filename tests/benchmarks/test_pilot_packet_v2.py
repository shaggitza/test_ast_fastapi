from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from benchmarks.real_world import pilot_packet_v2 as packet
from benchmarks.real_world.ground_truth_v2.evidence import collision_resistant_cache_name


def _git(path: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(path), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _cache(tmp_path: Path) -> tuple[Path, list[dict[str, Any]]]:
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init")
    _git(source, "config", "user.email", "pilot@example.invalid")
    _git(source, "config", "user.name", "Pilot")
    (source / "app.py").write_text("def value():\n    return 1\n")
    _git(source, "add", "app.py")
    _git(source, "commit", "-m", "baseline")
    baseline = _git(source, "rev-parse", "HEAD")
    baseline_tree = _git(source, "rev-parse", "HEAD^{tree}")
    (source / "app.py").write_text("def value():\n    return 2\n")
    (source / ".gitattributes").write_text("app.py export-ignore\n")
    (source / "link").symlink_to("app.py")
    _git(source, "add", ".gitattributes", "app.py", "link")
    _git(source, "commit", "-m", "target")
    target = _git(source, "rev-parse", "HEAD")
    target_tree = _git(source, "rev-parse", "HEAD^{tree}")
    cache_root = tmp_path / "cache"
    cache_root.mkdir()
    repository = "owner/repo"
    cache = cache_root / collision_resistant_cache_name(repository)
    cache.mkdir()
    _git(cache, "init", "--bare")
    _git(cache, "remote", "add", "origin", source.resolve().as_uri())
    _git(cache, "fetch", "--no-tags", "--depth=1", "origin", baseline)
    _git(cache, "fetch", "--no-tags", "--depth=1", "origin", target)
    _git(cache, "remote", "set-url", "origin", "https://github.com/owner/repo.git")
    records = [
        {
            "repository": repository,
            "pr": 7,
            "baseline_commit": baseline,
            "baseline_tree": baseline_tree,
            "target_commit": target,
            "target_tree": target_tree,
            "diff_sha256": "sha256:" + "d" * 64,
            "diff_bytes": 99,
        }
    ]
    packet._readonly(cache_root)
    return cache_root, records


def _make_writable(root: Path) -> None:
    for path in root.rglob("*"):
        path.chmod(0o700 if path.is_dir() else 0o600)
    root.chmod(0o700)


def test_validate_cache_identity_and_reject_remote_tree_and_promisor(tmp_path: Path) -> None:
    cache_root, records = _cache(tmp_path)
    packet.validate_cache(cache_root, records)
    cache = cache_root / collision_resistant_cache_name("owner/repo")
    _make_writable(cache)
    _git(cache, "remote", "set-url", "origin", "https://github.com/other/repo.git")
    packet._readonly(cache)
    with pytest.raises(packet.PilotPacketError, match="remote"):
        packet.validate_cache(cache_root, records)
    _make_writable(cache)
    _git(cache, "remote", "set-url", "origin", "https://github.com/owner/repo.git")
    packet._readonly(cache)
    wrong = [dict(records[0], target_tree="0" * 40)]
    with pytest.raises(packet.PilotPacketError, match="tree"):
        packet.validate_cache(cache_root, wrong)
    _make_writable(cache)
    _git(cache, "config", "remote.origin.promisor", "true")
    packet._readonly(cache)
    with pytest.raises(packet.PilotPacketError, match="partial/promisor"):
        packet.validate_cache(cache_root, records)


def test_publication_lock_rejects_concurrent_writer(tmp_path: Path) -> None:
    final = tmp_path / "output"
    lock = tmp_path / ".output.publication.lock"
    lock.write_text("held")
    with (
        pytest.raises(packet.PilotPacketError, match="already in progress"),
        packet._publication_lock(final),
    ):
        pass


def test_prepare_cache_refuses_existing_destination(tmp_path: Path) -> None:
    cache_root = tmp_path / "cache"
    cache_root.mkdir()
    repository = "owner/repo"
    (cache_root / collision_resistant_cache_name(repository)).mkdir()
    with pytest.raises(packet.PilotPacketError, match="overwrite cache"):
        packet.prepare_cache(cache_root, [{"repository": repository}])


def test_validate_cache_rejects_disk_bound(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cache_root, records = _cache(tmp_path)
    monkeypatch.setattr(packet, "_MAX_CACHE_BYTES", 1)
    with pytest.raises(packet.PilotPacketError, match="byte bound"):
        packet.validate_cache(cache_root, records)


def test_validate_cache_rejects_missing_commit(tmp_path: Path) -> None:
    cache_root, records = _cache(tmp_path)
    wrong = [dict(records[0], target_commit="0" * 40)]
    with pytest.raises(packet.PilotPacketError, match=r"shallow|Git command failed"):
        packet.validate_cache(cache_root, wrong)


def test_tree_parser_rejects_unsafe_duplicate_and_unknown_entries() -> None:
    oid = b"a" * 40
    for raw in (
        b"100644 blob " + oid + b"\t../escape\0",
        b"100644 blob " + oid + b"\t./escape\0",
        b"100644 blob " + oid + b"\tdouble//slash\0",
        b"100644 blob " + oid + b"\tleading/./dot\0",
        b"100600 blob " + oid + b"\tbad\0",
        b"100644 blob " + oid + b"\ta\0" + b"100644 blob " + oid + b"\ta\0",
        b"100644 blob " + oid + b"\tnon-utf8-\xff\0",
    ):
        with pytest.raises(packet.PilotPacketError):
            packet._parse_tree(raw)


def _validate(
    packet_root: Path, cache_root: Path, records: list[dict[str, Any]], binding: str
) -> None:
    packet.validate_packets(
        packet_root,
        records,
        binding,
        source_root=Path(__file__).resolve().parents[2],
        cache_root=cache_root,
    )


def test_blob_chunk_accounting_avoids_recursive_hot_loop(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "staging"
    root.mkdir()
    source = root / "source"
    source.write_bytes(b"x" * (2 * 1024 * 1024))
    budget = packet.StagingByteBudget.from_root(root, 8 * 1024 * 1024)
    original = packet._lstat_inventory
    inventories = 0

    def counted(path: Path, *, byte_limit: int) -> tuple[set[str], set[str], int]:
        nonlocal inventories
        inventories += 1
        return original(path, byte_limit=byte_limit)

    monkeypatch.setattr(packet, "_lstat_inventory", counted)
    digest = packet._copy_exact(source, root / "target", source.stat().st_size, budget)
    assert digest == packet._sha(source.read_bytes())
    assert inventories == 0
    budget.reconcile()
    assert inventories == 1


def test_empty_blob_and_parent_metadata_are_budgeted(tmp_path: Path) -> None:
    root = tmp_path / "staging"
    root.mkdir()
    source = root / "empty"
    source.write_bytes(b"")
    budget = packet.StagingByteBudget.from_root(root, 1024 * 1024)
    before = budget.accounted
    target = root / "a" / "b" / "c" / "empty.py"
    packet._copy_exact(source, target, 0, budget)
    assert budget.accounted - before == 4 * packet._METADATA_RESERVE_BYTES
    assert target.is_file()


def test_prepare_validate_exact_packet_and_no_clobber(tmp_path: Path) -> None:
    cache_root, records = _cache(tmp_path)
    packet_root = tmp_path / "packets"
    root = Path(__file__).resolve().parents[2]
    binding_hash = "sha256:" + "a" * 64
    packet.prepare_packets(root, cache_root, packet_root, records, binding_hash)
    _validate(packet_root, cache_root, records, binding_hash)
    name = packet._packet_name(records[0])
    built = packet_root / name
    manifest = json.loads((built / "packet-manifest.json").read_bytes())
    link = manifest["snapshots"]["target"]["symlinks"][0]
    assert link["path"] == "link"
    assert bytes.fromhex(link["target_hex"]) == b"app.py"
    assert manifest["remote_diff_sha256"] == records[0]["diff_sha256"]
    assert manifest["remote_diff_bytes"] == records[0]["diff_bytes"]
    assert manifest["local_diff_bytes"] > 0
    assert (built / "target/app.py").read_text() == "def value():\n    return 2\n"
    assert not (built / "target/link").exists()
    with pytest.raises(packet.PilotPacketError, match="overwrite"):
        packet.prepare_packets(root, cache_root, packet_root, records, binding_hash)


def test_rehashed_payload_and_semantic_tamper_fail_regeneration(tmp_path: Path) -> None:
    cache_root, records = _cache(tmp_path)
    packet_root = tmp_path / "packets"
    root = Path(__file__).resolve().parents[2]
    binding_hash = "sha256:" + "a" * 64
    packet.prepare_packets(root, cache_root, packet_root, records, binding_hash)
    built = packet_root / packet._packet_name(records[0])
    _make_writable(packet_root)
    target = built / "target/app.py"
    target.write_text("tampered\n")
    manifest_path = built / "packet-manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    digest = packet._sha(target.read_bytes())
    size = target.stat().st_size
    for item in manifest["payload_files"]:
        if item["path"] == "target/app.py":
            item.update({"sha256": digest, "bytes": size})
    for item in manifest["snapshots"]["target"]["files"]:
        if item["path"] == "app.py":
            item.update({"sha256": digest, "bytes": size})
    manifest["payload_bytes"] = sum(item["bytes"] for item in manifest["payload_files"])
    manifest["packet_root_sha256"] = packet._manifest_root(manifest)
    manifest_path.write_bytes(packet._canonical(manifest))
    packet._readonly(packet_root)
    with pytest.raises(packet.PilotPacketError, match="regeneration"):
        _validate(packet_root, cache_root, records, binding_hash)

    _make_writable(packet_root)
    target.write_text("def value():\n    return 2\n")
    manifest = json.loads(manifest_path.read_bytes())
    digest = packet._sha(target.read_bytes())
    size = target.stat().st_size
    for item in manifest["payload_files"]:
        if item["path"] == "target/app.py":
            item.update({"sha256": digest, "bytes": size})
    for item in manifest["snapshots"]["target"]["files"]:
        if item["path"] == "app.py":
            item.update({"sha256": digest, "bytes": size})
    manifest["snapshots"]["target"]["symlinks"][0]["target_hex"] = b"other".hex()
    manifest["payload_bytes"] = sum(item["bytes"] for item in manifest["payload_files"])
    manifest["packet_root_sha256"] = packet._manifest_root(manifest)
    manifest_path.write_bytes(packet._canonical(manifest))
    packet._readonly(packet_root)
    with pytest.raises(packet.PilotPacketError, match="regeneration"):
        _validate(packet_root, cache_root, records, binding_hash)


def test_packet_root_extra_fifo_and_permissions_rejected(tmp_path: Path) -> None:
    cache_root, records = _cache(tmp_path)
    packet_root = tmp_path / "packets"
    root = Path(__file__).resolve().parents[2]
    binding_hash = "sha256:" + "a" * 64
    packet.prepare_packets(root, cache_root, packet_root, records, binding_hash)
    built = packet_root / packet._packet_name(records[0])
    _make_writable(packet_root)
    extra = packet_root / "extra"
    extra.write_text("x")
    packet._readonly(packet_root)
    with pytest.raises(packet.PilotPacketError, match="extra"):
        _validate(packet_root, cache_root, records, binding_hash)
    _make_writable(packet_root)
    extra.unlink()
    fifo = built / "fifo"
    fifo.parent.mkdir(exist_ok=True)
    fifo_path = str(fifo)
    os.mkfifo(fifo_path)
    packet_root.chmod(0o555)
    built.chmod(0o555)
    with pytest.raises(packet.PilotPacketError, match="special"):
        _validate(packet_root, cache_root, records, binding_hash)


def test_cache_rejects_replacements_alternates_and_writable(tmp_path: Path) -> None:
    cache_root, records = _cache(tmp_path)
    cache = cache_root / collision_resistant_cache_name("owner/repo")
    _make_writable(cache_root)
    (cache / "objects/info/alternates").write_text("/tmp/objects\n")
    packet._readonly(cache_root)
    with pytest.raises(packet.PilotPacketError, match="alternate"):
        packet.validate_cache(cache_root, records)
    _make_writable(cache_root)
    (cache / "objects/info/alternates").unlink()
    _git(
        cache,
        "update-ref",
        "refs/replace/" + records[0]["target_commit"],
        records[0]["baseline_commit"],
    )
    packet._readonly(cache_root)
    with pytest.raises(packet.PilotPacketError, match="refs"):
        packet.validate_cache(cache_root, records)
    _make_writable(cache_root)
    _git(cache, "update-ref", "-d", "refs/replace/" + records[0]["target_commit"])
    with pytest.raises(packet.PilotPacketError, match="writable"):
        packet.validate_cache(cache_root, records)


def test_validate_cache_rejects_refs_nonshallow_and_extra_history(tmp_path: Path) -> None:
    cache_root, records = _cache(tmp_path)
    cache = cache_root / collision_resistant_cache_name("owner/repo")
    _make_writable(cache_root)
    _git(cache, "update-ref", "refs/heads/extra", records[0]["target_commit"])
    packet._readonly(cache_root)
    with pytest.raises(packet.PilotPacketError, match="refs"):
        packet.validate_cache(cache_root, records)
    _make_writable(cache_root)
    _git(cache, "update-ref", "-d", "refs/heads/extra")
    shallow = cache / "shallow"
    original = shallow.read_text()
    shallow.write_text(original + "0" * 40 + "\n")
    packet._readonly(cache_root)
    with pytest.raises(packet.PilotPacketError, match="extra history"):
        packet.validate_cache(cache_root, records)
    _make_writable(cache_root)
    shallow.write_text(original)
    shallow.unlink()
    packet._readonly(cache_root)
    with pytest.raises(packet.PilotPacketError, match="shallow"):
        packet.validate_cache(cache_root, records)


def test_validate_cache_rejects_unreachable_extra_object(tmp_path: Path) -> None:
    cache_root, records = _cache(tmp_path)
    cache = cache_root / collision_resistant_cache_name("owner/repo")
    _make_writable(cache_root)
    subprocess.run(
        ["git", "-C", str(cache), "hash-object", "-w", "--stdin"],
        input=b"unreachable",
        check=True,
        capture_output=True,
    )
    packet._readonly(cache_root)
    with pytest.raises(packet.PilotPacketError, match="unreachable"):
        packet.validate_cache(cache_root, records)


def test_validate_packets_directly_rejects_writable_cache(tmp_path: Path) -> None:
    cache_root, records = _cache(tmp_path)
    packet_root = tmp_path / "packets"
    root = Path(__file__).resolve().parents[2]
    binding = "sha256:" + "a" * 64
    packet.prepare_packets(root, cache_root, packet_root, records, binding)
    _make_writable(cache_root)
    with pytest.raises(packet.PilotPacketError, match="writable"):
        _validate(packet_root, cache_root, records, binding)


def test_cache_inode_swap_during_locked_validation_is_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cache_root, records = _cache(tmp_path)
    cache = cache_root / collision_resistant_cache_name("owner/repo")
    original = packet._validate_one_cache

    def validate_then_swap(
        runner: packet.GitRunner,
        cache_arg: Path,
        record: dict[str, Any],
        *,
        require_readonly: bool,
    ) -> None:
        original(runner, cache_arg, record, require_readonly=require_readonly)
        _make_writable(cache_root)
        old = cache_root / "old-cache"
        cache.rename(old)
        shutil.copytree(old, cache)
        packet._readonly(cache_root)

    monkeypatch.setattr(packet, "_validate_one_cache", validate_then_swap)
    with pytest.raises(packet.PilotPacketError, match="changed during validation"):
        packet.validate_cache(cache_root, records)


def test_validate_packets_directly_runs_full_cache_validation(tmp_path: Path) -> None:
    cache_root, records = _cache(tmp_path)
    packet_root = tmp_path / "packets"
    root = Path(__file__).resolve().parents[2]
    binding = "sha256:" + "a" * 64
    packet.prepare_packets(root, cache_root, packet_root, records, binding)
    cache = cache_root / collision_resistant_cache_name("owner/repo")
    _make_writable(cache_root)
    _git(cache, "update-ref", "refs/heads/extra", records[0]["target_commit"])
    packet._readonly(cache_root)
    with pytest.raises(packet.PilotPacketError, match="refs"):
        _validate(packet_root, cache_root, records, binding)


def test_failed_cache_prep_cleans_staging(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    final = tmp_path / "cache"
    records = [{"repository": "owner/repo", "baseline_commit": "a" * 40, "target_commit": "b" * 40}]

    def fail(*_args: object, **_kwargs: object) -> bytes:
        raise packet.PilotPacketError("forced")

    monkeypatch.setattr(packet.GitRunner, "run", fail)
    with pytest.raises(packet.PilotPacketError, match="forced"):
        packet.prepare_cache(final, records)
    assert not final.exists()
    assert list(tmp_path.iterdir()) == []


def test_tree_parser_records_gitlink_without_materializing() -> None:
    oid = b"b" * 40
    blobs, gitlinks = packet._parse_tree(b"160000 commit " + oid + b"\tvendor\0")
    assert blobs == []
    assert gitlinks == [{"path": "vendor", "commit": "b" * 40}]


def test_snapshot_total_bound_cleans_failed_packet(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cache_root, records = _cache(tmp_path)
    packet_root = tmp_path / "packets"
    monkeypatch.setattr(packet, "_MAX_TOTAL_BYTES", 1)
    with pytest.raises(packet.PilotPacketError, match=r"total bytes|byte bound"):
        packet.prepare_packets(
            Path(__file__).resolve().parents[2],
            cache_root,
            packet_root,
            records,
            "sha256:" + "a" * 64,
        )
    assert not packet_root.exists()
    assert not any(path.name.startswith(".packets.") for path in tmp_path.iterdir())


def test_packet_aggregate_staging_bound_cleans_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cache_root, records = _cache(tmp_path)
    packet_root = tmp_path / "packets"
    monkeypatch.setattr(packet, "_MAX_PACKET_STAGING_BYTES", 1)
    with pytest.raises(packet.PilotPacketError, match=r"byte (bound|budget)"):
        packet.prepare_packets(
            Path(__file__).resolve().parents[2],
            cache_root,
            packet_root,
            records,
            "sha256:" + "a" * 64,
        )
    assert not packet_root.exists()


def test_unsafe_parent_permissions_rejected(tmp_path: Path) -> None:
    parent = tmp_path / "public"
    parent.mkdir(mode=0o755)
    cache_root = parent / "cache"
    with pytest.raises(packet.PilotPacketError, match="private"):
        packet.prepare_cache(cache_root, [])


def test_git_runner_expired_deadline_does_not_publish_output(tmp_path: Path) -> None:
    cache_root, _records = _cache(tmp_path)
    cache = cache_root / collision_resistant_cache_name("owner/repo")
    output = tmp_path / "timeout-output"
    with pytest.raises(packet.PilotPacketError, match="wall-clock"):
        packet.GitRunner(deadline=0).run_to_path(cache, ("show", "HEAD:app.py"), output, limit=1024)
    assert not output.exists()


def test_git_runner_timeout_kills_spawned_process_group(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pid_path = tmp_path / "child.pid"
    script = (
        "import subprocess,sys,time;"
        f"p=subprocess.Popen([{sys.executable!r},'-c','import time;time.sleep(60)']);"
        f"open({str(pid_path)!r},'w').write(str(p.pid));"
        "time.sleep(60)"
    )
    runner = packet.GitRunner(deadline=time.monotonic() + 0.2)
    monkeypatch.setattr(runner, "_command", lambda _cache, _args: [sys.executable, "-c", script])
    output = tmp_path / "timeout-group-output"
    with pytest.raises(packet.PilotPacketError, match="wall-clock"):
        runner.run_to_path(tmp_path, ("ignored",), output, limit=1024)
    assert pid_path.exists()
    child_pid = int(pid_path.read_text())
    status = Path(f"/proc/{child_pid}/stat")
    if status.exists():
        assert status.read_text().split()[2] == "Z"
    assert not output.exists()


def test_git_runner_success_kills_remaining_descendant(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pid_path = tmp_path / "success-child.pid"
    script = (
        "import subprocess,sys;"
        f"p=subprocess.Popen([{sys.executable!r},'-c','import time;time.sleep(60)']);"
        f"open({str(pid_path)!r},'w').write(str(p.pid))"
    )
    runner = packet.GitRunner()
    monkeypatch.setattr(runner, "_command", lambda _cache, _args: [sys.executable, "-c", script])
    output = tmp_path / "success-group-output"
    runner.run_to_path(tmp_path, ("ignored",), output, limit=1024)
    child_pid = int(pid_path.read_text())
    status = Path(f"/proc/{child_pid}/stat")
    deadline = time.monotonic() + 1
    while status.exists() and status.read_text().split()[2] not in {"Z", "X"}:
        assert time.monotonic() < deadline
        time.sleep(0.01)
    assert output.read_bytes() == b""


def test_git_runner_overflow_removes_internal_output(tmp_path: Path) -> None:
    cache_root, records = _cache(tmp_path)
    cache = cache_root / collision_resistant_cache_name("owner/repo")
    output = tmp_path / "out"
    with pytest.raises(packet.PilotPacketError, match="output exceeded"):
        packet.GitRunner().run_to_path(
            cache, ("show", f"{records[0]['target_commit']}:app.py"), output, limit=1
        )
    assert not output.exists()
    assert not output.with_name(".out.stderr").exists()
