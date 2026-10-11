"""Real Git path and line-less change cases for the bounded GH274 matrix."""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

import pytest

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.models.diff import ChangeType
from fastapi_endpoint_detector.parser.diff_parser import DiffParser

if TYPE_CHECKING:
    from pathlib import Path


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo with spaces.dot"
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "Fixture")
    _git(root, "config", "user.email", "fixture@example.invalid")
    return root


def _write(root: Path, name: str, content: bytes = b"old = 1\n") -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def _commit(root: Path, message: str) -> None:
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", message)


@pytest.mark.parametrize(
    "name",
    [
        "space name.py",
        "tab\tname.py",
        "café.py",
        "line\nbreak.py",
        "literal\\windows\\style.py",
        "pkg/one/route.py",
        "pkg/two/route.py",
    ],
)
def test_real_git_quoted_and_ambiguous_paths_keep_exact_occurrences(
    tmp_path: Path, name: str
) -> None:
    root = _repo(tmp_path)
    old = b"old = 1\n"
    new = b"old = 2\n"
    _write(root, name, old)
    if name == "pkg/one/route.py":
        _write(root, "pkg/two/route.py", b"other = 1\n")
    if name == "pkg/two/route.py":
        _write(root, "pkg/one/route.py", b"first = 1\n")
    _commit(root, "baseline")
    _write(root, name, new)
    _commit(root, "target")

    diff = _git(
        root,
        "-c",
        "core.quotePath=true",
        "diff",
        "--no-ext-diff",
        "--find-renames",
        "HEAD^",
        "HEAD",
    )
    parsed = DiffParser.parse_string(diff)
    changed = [item for item in parsed if item.path.as_posix() == name]
    assert len(changed) == 1
    assert changed[0].change_type == ChangeType.MODIFIED
    assert changed[0].path.as_posix() == name
    assert changed[0].get_side_qualified_lines() == ([1], [1])
    assert {item.path.as_posix() for item in parsed} == {name}


def test_real_git_no_newline_metadata_does_not_shift_source_or_target_lines(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path)
    _write(root, "app.py", b"old = 1")
    _commit(root, "baseline without final newline")
    _write(root, "app.py", b"new = 2")
    _commit(root, "target without final newline")

    diff = _git(root, "diff", "--no-ext-diff", "HEAD^", "HEAD")
    parsed = DiffParser.parse_string(diff)
    assert len(parsed) == 1
    assert parsed[0].get_side_qualified_lines() == ([1], [1])
    assert parsed[0].hunks[0].added_content[0].text == "new = 2"
    assert parsed[0].hunks[0].removed_content[0].text == "old = 1"


def test_real_git_quoted_unicode_tab_newline_path_maps_through_secure_ast(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path)
    relative = "odd\tname/café\napi.py"
    before = (
        "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/items')\ndef items(): return 1\n"
    )
    after = before.replace("return 1", "return 2")
    _write(root, relative, before.encode())
    _commit(root, "baseline")
    _write(root, relative, after.encode())
    _commit(root, "target")
    diff = _git(root, "-c", "core.quotePath=true", "diff", "--no-ext-diff", "HEAD^", "HEAD")
    parsed = DiffParser.parse_string(diff)
    assert len(parsed) == 1
    assert parsed[0].path.as_posix() == relative

    baseline = tmp_path / "baseline"
    target = tmp_path / "target"
    baseline.mkdir()
    target.mkdir()
    _write(baseline, relative, before.encode())
    target_app = _write(target, relative, after.encode())
    report = ChangeMapper(
        target_app,
        baseline_app_path=baseline / relative,
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)
    assert {item.endpoint.identifier for item in report.candidate_endpoints} == {"GET /items"}
    assert not report.orphan_changes
    assert not report.errors


def test_real_git_mode_only_change_reaches_target_occurrence_and_baseline(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path)
    app = (
        "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/items')\ndef items(): return 1\n"
    )
    _write(root, "main.py", app.encode())
    _commit(root, "baseline")
    (root / "main.py").chmod(0o755)
    _commit(root, "executable mode")
    diff = _git(root, "diff", "--no-ext-diff", "--find-renames", "HEAD^", "HEAD")
    parsed = DiffParser.parse_string(diff)
    assert len(parsed) == 1
    assert parsed[0].hunks == []
    assert parsed[0].added_lines == parsed[0].removed_lines == 0

    baseline = tmp_path / "baseline"
    target = tmp_path / "target"
    baseline.mkdir()
    target.mkdir()
    (baseline / "main.py").write_text(app, encoding="utf-8")
    (target / "main.py").write_text(app, encoding="utf-8")
    report = ChangeMapper(
        target / "main.py",
        baseline_app_path=baseline / "main.py",
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)
    assert {item.endpoint.identifier for item in report.candidate_endpoints} == {"GET /items"}
    assert not report.orphan_changes
    assert report.analysis_completeness == "complete"


def test_real_git_rename_move_maps_file_lifecycle_with_spaces_and_unicode(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path)
    old_name = "old_dir/café.py"
    new_name = "new_dir/café.py"
    main = (
        "from fastapi import FastAPI\n"
        f"from {old_name[:-3].replace('/', '.')} import router\n"
        "app = FastAPI()\napp.include_router(router)\n"
    ).encode()
    body = (
        b"from fastapi import APIRouter\nrouter = APIRouter()\n"
        b"@router.get('/items')\ndef items(): return 1\n"
    )
    _write(root, "main.py", main)
    _write(root, old_name, body)
    _commit(root, "baseline")
    (root / "new_dir").mkdir()
    _git(root, "mv", old_name, new_name)
    target_main = main.replace(b"old_dir", b"new_dir")
    _write(root, "main.py", target_main)
    _commit(root, "move endpoint source")
    diff = _git(
        root,
        "-c",
        "core.quotePath=true",
        "diff",
        "--no-ext-diff",
        "--find-renames",
        "HEAD^",
        "HEAD",
    )
    parsed = DiffParser.parse_string(diff)
    moved_file = next(item for item in parsed if item.path.as_posix() == new_name)
    assert moved_file.change_type == ChangeType.RENAMED
    assert moved_file.source_path is not None
    assert moved_file.source_path.as_posix() == old_name

    baseline = tmp_path / "baseline"
    target = tmp_path / "target"
    _write(baseline, "main.py", main)
    _write(baseline, old_name, body)
    target_app = _write(target, "main.py", target_main)
    _write(target, new_name, body)
    report = ChangeMapper(
        target_app,
        baseline_app_path=baseline / "main.py",
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)
    assert {item.endpoint.identifier for item in report.candidate_endpoints} == {"GET /items"}
    assert any(
        item.identity == "GET /items" and item.lifecycle.value == "moved"
        for item in report.endpoint_lifecycle
    )
    assert not report.orphan_changes
