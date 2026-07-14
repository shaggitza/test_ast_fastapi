from __future__ import annotations

import json
import subprocess
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from benchmarks.real_world import build_route_census as census


def endpoint(file: Path, *, methods: list[str] | None = None) -> dict:
    return {
        "path": "/items",
        "methods": methods or ["GET", "POST"],
        "handler": {
            "name": "items",
            "module": "app",
            "file": str(file),
            "line": 2,
            "end_line": 3,
        },
    }


def test_normalize_inventory_expands_methods_and_preserves_occurrences(tmp_path: Path) -> None:
    first = tmp_path / "a.py"
    second = tmp_path / "b.py"
    first.write_text("raise RuntimeError('must not import')\n")
    second.write_text("def items(): ...\n")
    report = {"endpoints": [endpoint(first), endpoint(second), endpoint(first)]}

    items, unresolved, status, limitations = census.normalize_inventory(report, tmp_path, ".")

    assert [item["id"] for item in items] == ["HTTP GET /items", "HTTP POST /items"]
    assert len(items[0]["occurrences"]) == 2
    assert [item["file"] for item in items[0]["occurrences"]] == ["a.py", "b.py"]
    assert unresolved == []
    assert status == "established"
    assert limitations == []


def test_normalize_inventory_keeps_websocket_and_rejects_escape(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("def ws(): ...\n")
    outside = tmp_path.parent / "outside-census.py"
    outside.write_text("def outside(): ...\n")
    report = {
        "endpoints": [
            endpoint(source, methods=["websocket"]),
            endpoint(outside, methods=["GET"]),
        ]
    }

    items, unresolved, _status, _limitations = census.normalize_inventory(report, tmp_path, "src")

    assert [item["id"] for item in items] == ["WEBSOCKET /items"]
    assert items[0]["kind"] == "event"
    assert "escapes or is absent" in unresolved[0]


def test_normalize_inventory_preserves_conditional_discovery(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("def route(): ...\n")
    route = endpoint(source, methods=["GET"])
    route.update(
        {
            "discovery_status": "conditional",
            "discovery_conditions": [
                {
                    "source_path": str(source),
                    "source_line": 1,
                    "reason": "unknown helper may mutate app",
                }
            ],
        }
    )

    items, unresolved, status, limitations = census.normalize_inventory(
        {"endpoints": [route]}, tmp_path, "."
    )

    occurrence = items[0]["occurrences"][0]
    assert occurrence["discovery_status"] == "conditional"
    assert occurrence["discovery_conditions"] == [
        {"source": "app.py", "line": 1, "reason": "unknown helper may mutate app"}
    ]
    assert unresolved == []
    assert status == "conditional"
    assert limitations == [
        {"source": "app.py", "line": 1, "reason": "unknown helper may mutate app"}
    ]


def test_normalize_inventory_preserves_conditional_whole_inventory(tmp_path: Path) -> None:
    source = tmp_path / "main.py"
    source.write_text("def route(): ...\n")
    report = {
        "schema_version": 2,
        "inventory_status": "conditional",
        "inventory_limitations": [
            {
                "source_path": str(source),
                "source_line": 1,
                "reason": "unknown plugin may register routes",
            }
        ],
        "endpoints": [],
    }

    items, unresolved, status, limitations = census.normalize_inventory(report, tmp_path, ".")

    assert items == []
    assert unresolved == []
    assert status == "conditional"
    assert limitations == [
        {"source": "main.py", "line": 1, "reason": "unknown plugin may register routes"}
    ]


def test_normalize_inventory_rejects_established_endpoint_in_unavailable_inventory(
    tmp_path: Path,
) -> None:
    source = tmp_path / "main.py"
    source.write_text("def route(): ...\n")
    report = {
        "inventory_status": "unavailable",
        "inventory_limitations": [
            {"source_path": str(source), "source_line": 1, "reason": "root unresolved"}
        ],
        "endpoints": [endpoint(source, methods=["GET"])],
    }

    with pytest.raises(census.RunnerError, match="established endpoints"):
        census.normalize_inventory(report, tmp_path, ".")


def test_normalize_inventory_rejects_inventory_limitation_escape(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-inventory.py"
    outside.write_text("pass\n")
    report = {
        "inventory_status": "conditional",
        "inventory_limitations": [
            {"source_path": str(outside), "source_line": 1, "reason": "unknown plugin"}
        ],
        "endpoints": [],
    }

    with pytest.raises(census.RunnerError, match="invalid"):
        census.normalize_inventory(report, tmp_path, ".")


def test_normalize_inventory_rejects_symlink_escape(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-symlink-census.py"
    outside.write_text("def outside(): ...\n")
    link = tmp_path / "linked.py"
    link.symlink_to(outside)

    items, unresolved, _status, _limitations = census.normalize_inventory(
        {"endpoints": [endpoint(link, methods=["GET"])]}, tmp_path, "."
    )

    assert items == []
    assert unresolved


def test_normalize_inventory_rejects_unsupported_method(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("def route(): ...\n")

    items, unresolved, _status, _limitations = census.normalize_inventory(
        {"endpoints": [endpoint(source, methods=["BREW"])]}, tmp_path, "."
    )

    assert items == []
    assert "unsupported method 'BREW'" in unresolved[0]


def test_invoke_secure_list_uses_argv_and_output_file(tmp_path: Path, monkeypatch) -> None:
    app_root = tmp_path / "app"
    app_root.mkdir()
    source = app_root / "main.py"
    source.write_text("raise RuntimeError('must not import')\n")
    output = tmp_path / "routes.json"
    seen: list[str] = []

    def fake_command(args, *, cwd=None, timeout=None):
        del cwd, timeout
        seen.extend(args)
        output.write_text(json.dumps({"endpoints": [endpoint(source, methods=["GET"])]}))
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(census, "command", fake_command)

    items, unresolved, status, limitations, _elapsed = census.invoke_secure_list(
        tmp_path, app_root, tmp_path, "app", output, 10, "main:create_app"
    )

    assert "--secure-ast" in seen
    assert seen[seen.index("--app-entry") + 1] == "main:create_app"
    assert "--vm" not in seen
    assert seen[:5] == ["uv", "run", "--frozen", "fastapi-endpoint-detector", "list"]
    assert items[0]["id"] == "HTTP GET /items"
    assert unresolved == []
    assert status == "established"
    assert limitations == []


def test_real_secure_list_never_imports_analyzed_application(tmp_path: Path) -> None:
    app_root = tmp_path / "app"
    app_root.mkdir()
    (app_root / "main.py").write_text(
        "raise RuntimeError('must never import')\n"
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/safe')\n"
        "def safe(): return {}\n"
    )
    output = tmp_path / "routes.json"

    items, unresolved, status, limitations, _elapsed = census.invoke_secure_list(
        census.PROJECT_ROOT, app_root, tmp_path, "app", output, 60
    )

    assert [item["id"] for item in items] == ["HTTP GET /safe"]
    assert unresolved == []
    assert status == "established"
    assert limitations == []


def test_invoke_secure_list_timeout_is_explicit(tmp_path: Path, monkeypatch) -> None:
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("uv", 1)

    monkeypatch.setattr(census, "command", timeout)
    with pytest.raises(census.RunnerError, match="timed out"):
        census.invoke_secure_list(tmp_path, tmp_path, tmp_path, ".", tmp_path / "x", 1)


def test_process_entry_extracts_target_and_baseline_for_non_python_pr(
    tmp_path: Path, monkeypatch
) -> None:
    calls: list[tuple[str, str, str | None]] = []
    monkeypatch.setattr(census, "ensure_cache", lambda *_args: tmp_path / "cache.git")
    monkeypatch.setattr(census, "merge_parents", lambda *_args: ["b" * 40])
    monkeypatch.setattr(census, "resolve_base_parent", lambda *_args: "b" * 40)

    def extract(_cache, sha, _worktree, _root, _config, label, app_entry=None):
        calls.append((label, sha, app_entry))
        return ({"status": "completed", "entrypoints": [], "unresolved": []}, 0.1)

    monkeypatch.setattr(census, "_extract_side", extract)
    config = census.CensusConfig(
        tmp_path,
        tmp_path / "out",
        tmp_path / "manifest",
        tmp_path,
        1,
        ".",
        {},
        {"owner/repo": "main:create_app"},
    )
    entry = {
        "repository": "owner/repo",
        "number": 7,
        "mergeCommit": {"oid": "a" * 40},
        "commits": [],
        "files": [{"path": "frontend.ts"}],
    }

    record, manifest = census.process_entry(entry, config, "candidate")

    assert calls == [
        ("target", "a" * 40, "main:create_app"),
        ("baseline", "b" * 40, "main:create_app"),
    ]
    assert record["status"] == "completed"
    assert record["complete"] is True
    assert manifest["target_status"] == manifest["baseline_status"] == "completed"


def test_extract_side_removes_partially_added_worktree(tmp_path: Path, monkeypatch) -> None:
    removed: list[Path] = []

    def fail_after_registering(_cache: Path, worktree: Path, _sha: str) -> None:
        worktree.mkdir()
        raise census.RunnerError("checkout failed")

    monkeypatch.setattr(census, "add_detached_worktree", fail_after_registering)
    monkeypatch.setattr(
        census, "remove_worktree", lambda _cache, worktree: removed.append(worktree)
    )
    config = census.CensusConfig(
        tmp_path, tmp_path / "out", tmp_path / "manifest", tmp_path, 1, ".", {}
    )
    worktree = tmp_path / "target"

    side, _elapsed = census._extract_side(
        tmp_path / "cache", "a" * 40, worktree, ".", config, "target"
    )

    assert side["status"] == "unresolved"
    assert removed == [worktree]


def test_extract_side_always_removes_worktree(tmp_path: Path, monkeypatch) -> None:
    removed: list[Path] = []

    def add(_cache: Path, worktree: Path, _sha: str) -> None:
        worktree.mkdir()

    monkeypatch.setattr(census, "add_detached_worktree", add)
    monkeypatch.setattr(
        census, "remove_worktree", lambda _cache, worktree: removed.append(worktree)
    )
    monkeypatch.setattr(census, "safe_app_root", lambda worktree, _root: worktree)

    def invoke(*_args, **_kwargs):
        return (
            [{"id": "HTTP GET /", "kind": "http"}],
            [],
            "established",
            [],
            0.1,
        )

    monkeypatch.setattr(census, "invoke_secure_list", invoke)
    config = census.CensusConfig(
        tmp_path, tmp_path / "out", tmp_path / "manifest", tmp_path, 1, ".", {}
    )
    worktree = tmp_path / "target"

    side, _elapsed = census._extract_side(
        tmp_path / "cache", "a" * 40, worktree, ".", config, "target"
    )

    assert side["status"] == "completed"
    assert removed == [worktree]
