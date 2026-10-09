"""Public CLI coverage for the opt-in offline Graphify report overlay."""

from __future__ import annotations

import hashlib
import json
from difflib import unified_diff
from typing import TYPE_CHECKING

from click.testing import CliRunner

from fastapi_endpoint_detector.cli import cli

if TYPE_CHECKING:
    from pathlib import Path


def _write_graph(path: Path, *, changed_line: int) -> None:
    """Write a synthetic node-link graph; it is not produced by Graphify."""
    path.write_text(
        json.dumps(
            {
                "directed": True,
                "multigraph": True,
                "graph": {},
                "built_at_commit": "1" * 40,
                "nodes": [
                    {
                        "id": "handler",
                        "label": "items",
                        "file_type": "code",
                        "source_file": "app.py",
                        "source_location": "L5-L6",
                        "confidence": "EXTRACTED",
                    },
                    {
                        "id": "changed_helper",
                        "label": "changed_helper",
                        "file_type": "code",
                        "source_file": "service.py",
                        "source_location": f"L{changed_line}",
                        "confidence": "EXTRACTED",
                    },
                ],
                "links": [
                    {
                        "source": "handler",
                        "target": "changed_helper",
                        "relation": "calls",
                        "confidence": "EXTRACTED",
                        "source_file": "app.py",
                        "source_location": "L6",
                        "context": "synthetic handler call",
                    }
                ],
                "hyperedges": [],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _scenario(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path]:
    baseline = tmp_path / "baseline"
    target = tmp_path / "target"
    baseline.mkdir()
    target.mkdir()
    route_source = (
        "from fastapi import FastAPI\n"
        "from service import changed_helper\n"
        "app = FastAPI()\n"
        "@app.get('/items')\n"
        "def items():\n"
        "    return changed_helper()\n"
    )
    for root in (baseline, target):
        (root / "app.py").write_text(route_source, encoding="utf-8")
    before = "def changed_helper():\n    return 'before'\n"
    after = "def changed_helper():\n    return 'after'\n"
    (baseline / "service.py").write_text(before, encoding="utf-8")
    (target / "service.py").write_text(after, encoding="utf-8")

    diff = tmp_path / "change.diff"
    diff.write_text(
        "diff --git a/service.py b/service.py\n"
        + "".join(
            unified_diff(
                before.splitlines(keepends=True),
                after.splitlines(keepends=True),
                fromfile="a/service.py",
                tofile="b/service.py",
                n=0,
            )
        ),
        encoding="utf-8",
    )
    baseline_graph = tmp_path / "baseline-graph.json"
    target_graph = tmp_path / "target-graph.json"
    _write_graph(baseline_graph, changed_line=2)
    _write_graph(target_graph, changed_line=2)
    return baseline, target, diff, baseline_graph, target_graph


def _invoke(
    runner: CliRunner,
    *,
    baseline: Path,
    target: Path,
    diff: Path,
    baseline_graph: Path,
    target_graph: Path,
    graphify: bool,
):
    args = [
        "analyze",
        "--app",
        str(target),
        "--baseline-app",
        str(baseline),
        "--diff",
        str(diff),
        "--secure-ast",
        "--no-cache",
        "--format",
        "json",
    ]
    if graphify:
        args.extend(
            [
                "--graphify",
                "--graphify-baseline",
                str(baseline_graph),
                "--graphify-target",
                str(target_graph),
                "--graphify-schema",
                "node-link-v1",
            ]
        )
    return runner.invoke(cli, args)


def test_enabled_graphify_cli_emits_side_bound_low_lexical_overlay(tmp_path: Path) -> None:
    baseline, target, diff, baseline_graph, target_graph = _scenario(tmp_path)
    result = _invoke(
        CliRunner(),
        baseline=baseline,
        target=target,
        diff=diff,
        baseline_graph=baseline_graph,
        target_graph=target_graph,
        graphify=True,
    )

    assert result.exit_code == 0, result.output
    report = json.loads(result.output)
    overlay = report["graphify_overlay"]
    assert overlay["schema_version"] == 1
    assert overlay["evidence_scope"] == "validated_offline_snapshots"
    assert overlay["baseline_snapshot"]["side"] == "baseline"
    assert overlay["target_snapshot"]["side"] == "target"
    assert overlay["baseline_snapshot"]["graph_sha256"] == hashlib.sha256(
        baseline_graph.read_bytes()
    ).hexdigest()
    assert overlay["target_snapshot"]["graph_sha256"] == hashlib.sha256(
        target_graph.read_bytes()
    ).hexdigest()

    evidence_by_side = {item["side"]: item for item in overlay["evidence"]}
    assert set(evidence_by_side) == {"baseline", "target"}
    assert evidence_by_side["baseline"]["changed_node_id"] == "changed_helper"
    assert evidence_by_side["target"]["changed_node_id"] == "changed_helper"
    for side, root in (("baseline", baseline), ("target", target)):
        evidence = evidence_by_side[side]
        assert evidence["confidence"] == "LOW"
        assert evidence["binding_kind"] == "handler"
        assert evidence["endpoint_id"]
        assert any(
            span["file_path"] == "service.py"
            and span["source_sha256"]
            == hashlib.sha256((root / "service.py").read_bytes()).hexdigest()
            for span in evidence["node_source_spans"]
        )
        assert any("lexical evidence only" in item for item in evidence["limitations"])

    assert report["candidate_endpoints"]
    assert all(item["confidence"] != "LOW" for item in report["candidate_endpoints"])


def test_disabled_graphify_cli_omits_overlay_field(tmp_path: Path) -> None:
    baseline, target, diff, baseline_graph, target_graph = _scenario(tmp_path)
    result = _invoke(
        CliRunner(),
        baseline=baseline,
        target=target,
        diff=diff,
        baseline_graph=baseline_graph,
        target_graph=target_graph,
        graphify=False,
    )

    assert result.exit_code == 0, result.output
    report = json.loads(result.output)
    assert "graphify_overlay" not in report
    assert report["candidate_endpoints"]
