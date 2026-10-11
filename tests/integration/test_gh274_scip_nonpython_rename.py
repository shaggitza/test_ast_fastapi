"""Real Git regression for a hunk-less Python-to-non-Python SCIP rename."""

import subprocess
from pathlib import Path

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.analyzer.scip_analyzer import SCIPDefinition, SCIPSourceScope
from fastapi_endpoint_detector.models.report import ConfidenceLevel
from fastapi_endpoint_detector.parser.diff_parser import DiffParser


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, check=True
    ).stdout


class _EmptyIndex:
    """Exercise registry ownership through the public SCIP flow without an external indexer."""

    def __init__(self) -> None:
        self.indexed = False

    def ensure_index(self, *, force: bool = False) -> None:
        assert force
        self.indexed = True

    def source_scope(self) -> SCIPSourceScope:
        return SCIPSourceScope("project_root", None, ())

    def definitions_at(self, _path: Path, _lines: set[int]) -> tuple[SCIPDefinition, ...]:
        return ()

    def reverse_call_edges(self, _seed: SCIPDefinition) -> tuple[()]:
        return ()

    def reverse_call_edge_limitations(self, _callee: SCIPDefinition) -> tuple[str, ...]:
        return ()


def test_real_git_python_to_nonpython_rename_seeds_only_baseline_ownership(tmp_path: Path) -> None:
    target = tmp_path / "target"
    baseline = tmp_path / "baseline"
    target.mkdir()
    baseline.mkdir()
    route_source = (
        "from fastapi import FastAPI\napp = FastAPI()\n"
        "@app.get('/removed')\ndef removed():\n    return 1\n"
    )
    for root in (target, baseline):
        (root / "routes.py").write_text(route_source, encoding="utf-8")
        (root / "main.py").write_text("from routes import app\n", encoding="utf-8")
    _git(target, "init", "-q")
    _git(target, "config", "user.name", "SCIP rename regression")
    _git(target, "config", "user.email", "rename@example.invalid")
    _git(target, "add", "--all")
    _git(target, "commit", "-q", "-m", "baseline")
    _git(target, "mv", "routes.py", "routes.py.disabled")
    (target / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8"
    )
    _git(target, "add", "--all")
    _git(target, "commit", "-q", "-m", "disable route file")
    diff = _git(target, "diff", "--find-renames", "--no-ext-diff", "--unified=0", "HEAD^", "HEAD")
    changes = DiffParser.parse_string(diff)
    renamed = next(change for change in changes if change.path.name == "routes.py.disabled")
    assert renamed.source_path == Path("routes.py")
    assert renamed.is_python_file
    assert DiffParser.get_changed_line_numbers(renamed) == ([], [])

    mapper = ChangeMapper(
        target,
        baseline_app_path=baseline,
        app_entry="main:app",
        secure_ast=True,
        use_cache=False,
        use_scip=True,
    )
    target_index, baseline_index = _EmptyIndex(), _EmptyIndex()
    mapper._scip_analyzer = target_index  # type: ignore[assignment]
    mapper._baseline_scip_analyzer = baseline_index  # type: ignore[assignment]
    report = mapper.analyze_diff(diff)
    assert target_index.indexed and baseline_index.indexed
    candidates = [
        item for item in report.candidate_endpoints if item.endpoint.identifier == "GET /removed"
    ]
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.endpoint.handler.file_path == baseline / "routes.py"
    assert candidate.confidence == ConfidenceLevel.HIGH
    assert any(
        item.summary.startswith("Git reported a baseline file change without line hunks")
        and item.changed_location is not None
        and item.changed_location.file_path.endswith("routes.py")
        for item in candidate.effect_evidence
    )
    assert not any(
        item.summary.startswith("Git reported a target file change without line hunks")
        for item in candidate.effect_evidence
    )
    assert not mapper.registry.get_all()
    assert any(
        item.identity == "GET /removed"
        and item.lifecycle.value == "removed"
        and item.baseline_endpoint is not None
        and item.target_endpoint is None
        for item in report.endpoint_lifecycle
    )
