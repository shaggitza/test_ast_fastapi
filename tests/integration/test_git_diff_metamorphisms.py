"""Real-Git mapper regressions for side-qualified lifecycle and orphan accounting."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.models.diff import ChangeType

if TYPE_CHECKING:
    from fastapi_endpoint_detector.models.report import AnalysisReport
from fastapi_endpoint_detector.parser.diff_parser import DiffParser


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout


def _write_files(root: Path, files: dict[str, str]) -> None:
    for relative_path, content in files.items():
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def _committed_pair(
    tmp_path: Path,
    baseline_files: dict[str, str],
    target_files: dict[str, str],
) -> tuple[Path, Path, str]:
    target_root = tmp_path / "target"
    baseline_root = tmp_path / "baseline"
    target_root.mkdir()
    baseline_root.mkdir()

    _write_files(target_root, baseline_files)
    _write_files(baseline_root, baseline_files)
    _git(target_root, "init", "-q")
    _git(target_root, "config", "user.name", "Mapper regression")
    _git(target_root, "config", "user.email", "mapper@example.invalid")
    _git(target_root, "add", "--all")
    _git(target_root, "commit", "-q", "-m", "baseline")

    for relative_path in baseline_files.keys() - target_files.keys():
        (target_root / relative_path).unlink()
    _write_files(target_root, target_files)
    _git(target_root, "add", "--all")
    _git(target_root, "commit", "-q", "-m", "target")

    diff = _git(
        target_root,
        "-c",
        "core.quotePath=true",
        "diff",
        "--find-renames",
        "--no-ext-diff",
        "--unified=0",
        "HEAD^",
        "HEAD",
    )
    return target_root, baseline_root, diff


def _analyze_pair(target_root: Path, baseline_root: Path, diff: str) -> AnalysisReport:
    mapper = ChangeMapper(
        target_root / "main.py",
        baseline_app_path=baseline_root / "main.py",
        secure_ast=True,
        use_cache=False,
    )
    return mapper.analyze_diff(diff)


def _main_source(module: str, handler: str) -> str:
    return (
        "from fastapi import FastAPI\n"
        f"from {module} import {handler}\n"
        "app = FastAPI()\n"
        "app.add_api_route('/items', "
        f"{handler}, methods=['GET'])\n"
    )


def test_real_git_deletion_uses_baseline_reachability_and_keeps_unrelated_orphans(
    tmp_path: Path,
) -> None:
    baseline_files = {
        "main.py": (
            "from fastapi import FastAPI\n"
            "from service import load_value\n"
            "app = FastAPI()\n"
            "@app.get('/items')\n"
            "def get_items():\n"
            "    return load_value()\n"
        ),
        "service.py": ("def load_value():\n    return 1\n\ndef unrelated():\n    return 2\n"),
    }
    target_files = {
        "main.py": baseline_files["main.py"],
        "service.py": "def unrelated():\n    return 3\n",
    }
    target_root, baseline_root, diff = _committed_pair(tmp_path, baseline_files, target_files)

    parsed = DiffParser.parse_string(diff)
    service_change = next(item for item in parsed if item.path == Path("service.py"))
    removed_lines, added_lines = service_change.get_side_qualified_lines()
    assert removed_lines and added_lines

    report = _analyze_pair(target_root, baseline_root, diff)

    assert not report.errors
    assert [item.endpoint.identifier for item in report.candidate_endpoints] == ["GET /items"]
    service_orphans = [
        item for item in report.orphan_changes if Path(item.file_path) == Path("service.py")
    ]
    assert len(service_orphans) == 1
    assert service_orphans[0].removed_lines
    assert service_orphans[0].added_lines
    assert set(service_orphans[0].removed_lines).issubset(removed_lines)
    assert set(service_orphans[0].added_lines).issubset(added_lines)
    assert 5 in service_orphans[0].removed_lines
    assert 2 in service_orphans[0].added_lines
    assert {1, 2}.isdisjoint(service_orphans[0].removed_lines)


@pytest.mark.parametrize(
    ("target_module", "target_handler", "expected_lifecycle"),
    [
        ("new_routes", "get_items", "moved"),
        ("routes", "fetch_items", "renamed"),
    ],
    ids=["file-move", "function-rename"],
)
def test_real_git_move_or_rename_keeps_public_route_identity(
    tmp_path: Path,
    target_module: str,
    target_handler: str,
    expected_lifecycle: str,
) -> None:
    baseline_files = {
        "main.py": _main_source("routes", "get_items"),
        "routes.py": "def get_items():\n    return {'items': []}\n",
    }
    target_filename = f"{target_module}.py"
    target_files = {
        "main.py": _main_source(target_module, target_handler),
        target_filename: f"def {target_handler}():\n    return {{'items': []}}\n",
    }
    target_root, baseline_root, diff = _committed_pair(tmp_path, baseline_files, target_files)

    parsed = DiffParser.parse_string(diff)
    if expected_lifecycle == "moved":
        route_move = next(item for item in parsed if item.path == Path("new_routes.py"))
        assert route_move.change_type is ChangeType.RENAMED
        assert route_move.source_path == Path("routes.py")

    report = _analyze_pair(target_root, baseline_root, diff)

    assert not report.errors
    assert [item.endpoint.identifier for item in report.candidate_endpoints] == ["GET /items"]
    lifecycle = next(item for item in report.endpoint_lifecycle if item.identity == "GET /items")
    assert lifecycle.lifecycle.value == expected_lifecycle
    assert lifecycle.baseline_endpoint is not None
    assert lifecycle.target_endpoint is not None
    assert lifecycle.baseline_endpoint.path == lifecycle.target_endpoint.path == "/items"
    assert lifecycle.baseline_endpoint.handler.file_path.name == "routes.py"
    assert lifecycle.target_endpoint.handler.file_path.name == target_filename
    assert not report.orphan_changes


def test_real_git_replacement_tracks_both_snapshots_and_quoted_config_path(
    tmp_path: Path,
) -> None:
    baseline_app = (
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/items')\n"
        "def get_items():\n"
        "    return 1"
    )
    target_app = baseline_app.replace("return 1", "return 2")
    quoted_path = "café\tsettings.yaml"
    baseline_files = {
        "main.py": baseline_app,
        quoted_path: "mode: old\n",
    }
    target_files = {
        "main.py": target_app,
        quoted_path: "mode: new\n",
    }
    target_root, baseline_root, diff = _committed_pair(tmp_path, baseline_files, target_files)

    assert r"\t" in diff
    assert "\\ No newline at end of file" in diff
    parsed = DiffParser.parse_string(diff)
    app_change = next(item for item in parsed if item.path == Path("main.py"))
    removed_lines, added_lines = app_change.get_side_qualified_lines()
    assert removed_lines == [5]
    assert added_lines == [5]
    config_change = next(item for item in parsed if item.path == Path(quoted_path))
    config_removed, config_added = config_change.get_side_qualified_lines()
    assert config_removed == [1]
    assert config_added == [1]

    report = _analyze_pair(target_root, baseline_root, diff)

    assert not report.errors
    assert [item.endpoint.identifier for item in report.candidate_endpoints] == ["GET /items"]
    assert any(quoted_path in warning for warning in report.warnings)
    assert report.source_evidence_graph is not None
    app_nodes = {
        node.provenance.side: node
        for node in report.source_evidence_graph.nodes
        if node.kind == "source_file" and node.provenance.source_path == "main.py"
    }
    assert set(app_nodes) == {"baseline", "target"}
    assert app_nodes["baseline"].attributes["sha256"] != app_nodes["target"].attributes["sha256"]
