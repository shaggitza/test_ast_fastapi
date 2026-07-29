"""Offline contract tests for the opt-in pinned Graphify POC boundary."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from fastapi_endpoint_detector.analyzer.graphify_adapter import (
    GRAPHIFY_GRAPH_SCHEMA_VERSION,
    GRAPHIFY_PACKAGE_VERSION,
    GraphifyAdapterError,
    GraphifyRunner,
    GraphifySourceSpan,
    load_graphify_snapshot,
)

FIXTURE = Path(__file__).parents[1] / "fixtures" / "graphify_0_9_30_graph.json"


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(
        "from helpers import helper\n\ndef handler():\n    return helper()\n", encoding="utf-8"
    )
    (project / "helpers.py").write_text("def helper():\n    return 1\n", encoding="utf-8")
    return project


def _write_payload(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, allow_nan=False, sort_keys=True), encoding="utf-8")


def _completed(
    stdout: str = "", *, code: int = 0, stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], code, stdout, stderr)


def test_loads_pinned_fixture_with_separate_provenance_and_direction(tmp_path: Path) -> None:
    project = _project(tmp_path)
    snapshot = load_graphify_snapshot(FIXTURE, project_root=project, side="target")

    assert snapshot.side == "target"
    assert snapshot.graphify_version == GRAPHIFY_PACKAGE_VERSION
    assert snapshot.graph_schema_version == GRAPHIFY_GRAPH_SCHEMA_VERSION
    assert snapshot.graph_sha256 == hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    assert snapshot.built_at_commit == "1" * 40
    assert snapshot.nodes[1].span == GraphifySourceSpan(Path("app.py"), 2, 3)
    assert snapshot.nodes[1].extractor_strength == "EXTRACTED"
    assert snapshot.edges[1].source_id == "handler"
    assert snapshot.edges[1].target_id == "helper"
    assert snapshot.edges[1].traversable is True
    assert snapshot.edges[2].extractor_strength == "INFERRED"
    assert snapshot.edges[2].traversable is True
    assert snapshot.edges[3].extractor_strength == "AMBIGUOUS"
    assert snapshot.edges[3].traversable is False


def test_snapshot_hash_is_checked_against_the_same_byte_snapshot(tmp_path: Path) -> None:
    project = _project(tmp_path)
    expected = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()

    snapshot = load_graphify_snapshot(
        FIXTURE,
        project_root=project,
        side="baseline",
        expected_sha256=expected,
    )
    assert snapshot.graph_sha256 == expected

    with pytest.raises(GraphifyAdapterError, match="hash mismatch"):
        load_graphify_snapshot(
            FIXTURE,
            project_root=project,
            side="baseline",
            expected_sha256="0" * 64,
        )
    with pytest.raises(GraphifyAdapterError, match="unsupported Graphify version"):
        load_graphify_snapshot(
            FIXTURE,
            project_root=project,
            side="baseline",
            graphify_version="0.9.29",
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update({"schema_version": 2}), "top-level schema"),
        (lambda value: value["hyperedges"].append({"semantic": True}), "hyperedges"),
        (lambda value: value["nodes"].append(dict(value["nodes"][0])), "duplicate"),
        (lambda value: value["links"][0].update({"target": "missing"}), "unknown node"),
        (lambda value: value["nodes"][0].update({"file_type": "document"}), "code-only"),
        (lambda value: value["nodes"][0].update({"source_file": "missing.py"}), "project file"),
        (lambda value: value["nodes"][1].update({"source_location": "L9-L2"}), "reversed"),
        (lambda value: value["links"][0].update({"confidence_score": 2.0}), "between 0 and 1"),
        (lambda value: value.update({"built_at_commit": "ABC"}), "full Git OID"),
        (lambda value: value["links"][0].update({"unexpected": "drift"}), "unsupported fields"),
    ],
    ids=[
        "schema-drift",
        "semantic-hyperedge",
        "duplicate-node",
        "dangling-edge",
        "non-code-node",
        "missing-source",
        "reversed-span",
        "invalid-confidence-score",
        "invalid-commit",
        "edge-schema-drift",
    ],
)
def test_strict_schema_rejects_unsupported_or_ambiguous_graphs(
    tmp_path: Path,
    mutation: Any,
    message: str,
) -> None:
    project = _project(tmp_path)
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    mutation(payload)
    graph = tmp_path / "graph.json"
    _write_payload(graph, payload)

    with pytest.raises(GraphifyAdapterError, match=message):
        load_graphify_snapshot(graph, project_root=project, side="target")


def test_strict_json_rejects_duplicate_members_and_non_finite_numbers(tmp_path: Path) -> None:
    project = _project(tmp_path)
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"directed":false,"directed":true}', encoding="utf-8")
    with pytest.raises(GraphifyAdapterError, match="duplicate"):
        load_graphify_snapshot(duplicate, project_root=project, side="target")

    non_finite = tmp_path / "non-finite.json"
    non_finite.write_text(
        FIXTURE.read_text(encoding="utf-8").replace('"weight": 0.5', '"weight": NaN'),
        encoding="utf-8",
    )
    with pytest.raises(GraphifyAdapterError, match="non-finite"):
        load_graphify_snapshot(non_finite, project_root=project, side="target")


def test_source_paths_must_remain_inside_the_analyzed_project(tmp_path: Path) -> None:
    project = _project(tmp_path)
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload["nodes"][0]["source_file"] = "../outside.py"
    graph = tmp_path / "escape.json"
    _write_payload(graph, payload)

    with pytest.raises(GraphifyAdapterError, match="escapes the project root"):
        load_graphify_snapshot(graph, project_root=project, side="target")


def test_runner_invokes_only_pinned_code_only_pipeline_and_writes_receipt(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path)
    executable = tmp_path / "graphify"
    executable.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    executable.chmod(0o700)
    output_root = tmp_path / "snapshots"
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((args, kwargs))
        if args[-1] == "--version":
            return _completed(f"graphify {GRAPHIFY_PACKAGE_VERSION}\n")
        graph = output_root / "target" / "graphify-out" / "graph.json"
        graph.parent.mkdir(parents=True)
        shutil.copyfile(FIXTURE, graph)
        return _completed("code-only graph written\n")

    with (
        patch.dict(
            os.environ,
            {
                "GEMINI_API_KEY": "must-not-pass",
                "GOOGLE_API_KEY": "must-not-pass",
                "HTTP_PROXY": "must-not-pass",
            },
        ),
        patch("subprocess.run", side_effect=fake_run),
    ):
        snapshot = GraphifyRunner(project, executable, timeout=12).extract_snapshot(
            "target", output_root
        )

    assert snapshot.graph_sha256 == hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    assert len(calls) == 2
    extract_args, extract_kwargs = calls[1]
    assert extract_args == [
        str(executable.resolve()),
        "extract",
        str(project.resolve()),
        "--code-only",
        "--no-cluster",
        "--force",
        "--out",
        str((output_root / "target").resolve()),
    ]
    assert extract_kwargs.get("shell", False) is False
    environment = extract_kwargs["env"]
    assert isinstance(environment, dict)
    assert "GEMINI_API_KEY" not in environment
    assert "GOOGLE_API_KEY" not in environment
    assert "HTTP_PROXY" not in environment
    assert "NO_PROXY" not in environment
    assert all(
        forbidden not in extract_args
        for forbidden in ("--backend", "--mcp", "--wiki", "--watch", "--global")
    )
    receipt_path = output_root / "target" / "snapshot-receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt == {
        "edge_count": 4,
        "graph_schema_version": GRAPHIFY_GRAPH_SCHEMA_VERSION,
        "graph_sha256": snapshot.graph_sha256,
        "graphify_version": GRAPHIFY_PACKAGE_VERSION,
        "node_count": 3,
        "side": "target",
    }


def test_runner_is_no_clobber_and_rejects_project_local_output_before_execution(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path)
    executable = tmp_path / "graphify"
    executable.write_text("tool", encoding="utf-8")
    executable.chmod(0o700)
    runner = GraphifyRunner(project, executable)

    with (
        patch("subprocess.run") as run,
        pytest.raises(GraphifyAdapterError, match="outside"),
    ):
        runner.extract_snapshot("target", project / "snapshots")
    run.assert_not_called()

    output_root = tmp_path / "snapshots"
    (output_root / "baseline").mkdir(parents=True)
    with (
        patch("subprocess.run") as run,
        pytest.raises(GraphifyAdapterError, match="already exists"),
    ):
        runner.extract_snapshot("baseline", output_root)
    run.assert_not_called()


def test_runner_rejects_unpinned_version_and_command_failure(tmp_path: Path) -> None:
    project = _project(tmp_path)
    executable = tmp_path / "graphify"
    executable.write_text("tool", encoding="utf-8")
    executable.chmod(0o700)
    runner = GraphifyRunner(project, executable)

    with (
        patch("subprocess.run", return_value=_completed("graphify 9.9.9\n")),
        pytest.raises(GraphifyAdapterError, match="unsupported Graphify version"),
    ):
        runner.extract_snapshot("target", tmp_path / "version-output")

    def failed(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if args[-1] == "--version":
            return _completed(f"graphify {GRAPHIFY_PACKAGE_VERSION}\n")
        return _completed(code=7, stderr="structural extraction failed")

    with (
        patch("subprocess.run", side_effect=failed),
        pytest.raises(GraphifyAdapterError, match="structural extraction failed"),
    ):
        runner.extract_snapshot("baseline", tmp_path / "failure-output")
