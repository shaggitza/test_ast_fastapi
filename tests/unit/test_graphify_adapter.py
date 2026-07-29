"""Offline contract tests for the pinned Graphify graph import boundary."""

from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

import pytest

from fastapi_endpoint_detector.analyzer import graphify_adapter
from fastapi_endpoint_detector.analyzer.graphify_adapter import (
    GRAPHIFY_EXPECTED_DIRECTED,
    GRAPHIFY_EXPECTED_MULTIGRAPH,
    GRAPHIFY_GRAPH_SCHEMA_VERSION,
    GRAPHIFY_PACKAGE_NAME,
    GRAPHIFY_PACKAGE_VERSION,
    GraphifyAdapterError,
    GraphifySourceSpan,
    import_graphify_snapshot,
    load_graphify_snapshot,
)

if TYPE_CHECKING:
    from collections.abc import Callable


FIXTURE = Path(__file__).parents[1] / "fixtures" / "graphify_0_9_30_graph.json"


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(
        "from helpers import helper\n\ndef handler():\n    return helper()\n", encoding="utf-8"
    )
    (project / "helpers.py").write_text("def helper():\n    return 1\n", encoding="utf-8")
    return project


def _payload() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _write_payload(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, allow_nan=False, sort_keys=True), encoding="utf-8")


def _assert_fifo_rejected_without_writer(fifo: Path, load: Callable[[], object]) -> None:
    outcomes: list[object] = []

    def invoke() -> None:
        try:
            outcomes.append(load())
        except Exception as error:
            outcomes.append(error)

    thread = threading.Thread(target=invoke, daemon=True)
    thread.start()
    thread.join(timeout=1.0)
    if thread.is_alive():
        try:
            writer = os.open(fifo, os.O_WRONLY | getattr(os, "O_NONBLOCK", 0))
        except OSError:
            pass
        else:
            os.close(writer)
        thread.join(timeout=1.0)
        pytest.fail("FIFO read blocked while waiting for a writer")

    assert len(outcomes) == 1
    error = outcomes[0]
    assert isinstance(error, GraphifyAdapterError)
    assert "not a regular file" in str(error)


def test_loads_pinned_fixture_with_exact_source_provenance_and_orientation(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path)
    snapshot = load_graphify_snapshot(FIXTURE, project_root=project, side="target")
    app_hash = hashlib.sha256((project / "app.py").read_bytes()).hexdigest()

    assert snapshot.side == "target"
    assert snapshot.expected_graphify_package == GRAPHIFY_PACKAGE_NAME
    assert snapshot.expected_graphify_version == GRAPHIFY_PACKAGE_VERSION
    assert snapshot.expected_graphify_command == "graphify"
    assert snapshot.expected_version_output == "graphify 0.9.30"
    assert snapshot.graph_schema_version == GRAPHIFY_GRAPH_SCHEMA_VERSION
    assert snapshot.graph_sha256 == hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    assert snapshot.directed is GRAPHIFY_EXPECTED_DIRECTED
    assert snapshot.multigraph is GRAPHIFY_EXPECTED_MULTIGRAPH
    assert snapshot.built_at_commit == "1" * 40
    assert snapshot.nodes[1].source_file == Path("app.py")
    assert snapshot.nodes[1].source_sha256 == app_hash
    assert snapshot.nodes[1].span == GraphifySourceSpan(Path("app.py"), 2, 3, app_hash)
    assert snapshot.nodes[1].extractor_strength == "EXTRACTED"
    assert snapshot.edges[1].source_id == "handler"
    assert snapshot.edges[1].target_id == "helper"
    assert snapshot.edges[1].orientation == "caller-to-callee"
    assert snapshot.edges[1].traversable is True
    assert snapshot.edges[2].orientation == "importer-to-imported"
    assert snapshot.edges[2].extractor_strength == "INFERRED"
    assert snapshot.edges[2].traversable is True
    assert snapshot.edges[3].orientation == "symmetric"
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
    with pytest.raises(GraphifyAdapterError, match="lowercase SHA-256"):
        load_graphify_snapshot(
            FIXTURE,
            project_root=project,
            side="baseline",
            expected_sha256="not-a-hash",
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update({"schema_version": 2}), "top-level schema"),
        (lambda value: value["hyperedges"].append({"semantic": True}), "hyperedges"),
        (lambda value: value["nodes"].append(dict(value["nodes"][0])), "duplicate"),
        (lambda value: value["links"][0].update({"target": "missing"}), "unknown node"),
        (lambda value: value["nodes"][0].update({"file_type": "document"}), "code-only"),
        (lambda value: value["nodes"][1].update({"source_location": "L9-L2"}), "reversed"),
        (lambda value: value["links"][0].update({"confidence_score": 2.0}), "between 0 and 1"),
        (lambda value: value.update({"built_at_commit": "ABC"}), "full Git OID"),
        (lambda value: value["links"][0].update({"unexpected": "drift"}), "unsupported schema"),
        (lambda value: value.update({"graph": {"name": "unchecked"}}), "empty object"),
        (lambda value: value["nodes"][0].update({"metadata": {}}), "unsupported schema"),
        (lambda value: value["links"][0].update({"context": []}), "context"),
    ],
    ids=[
        "schema-drift",
        "semantic-hyperedge",
        "duplicate-node",
        "dangling-edge",
        "non-code-node",
        "reversed-span",
        "invalid-confidence-score",
        "invalid-commit",
        "edge-schema-drift",
        "nonempty-graph-metadata",
        "removed-unvalidated-field",
        "malformed-known-field",
    ],
)
def test_strict_schema_rejects_unsupported_or_malformed_graphs(
    tmp_path: Path,
    mutation: Any,
    message: str,
) -> None:
    project = _project(tmp_path)
    payload = _payload()
    mutation(payload)
    graph = tmp_path / "graph.json"
    _write_payload(graph, payload)

    with pytest.raises(GraphifyAdapterError, match=message):
        load_graphify_snapshot(graph, project_root=project, side="target")


@pytest.mark.parametrize(
    ("collection", "field", "value"),
    [
        ("nodes", "confidence", []),
        ("links", "confidence", []),
        ("nodes", "confidence_score", 10**400),
        ("links", "weight", 10**400),
    ],
    ids=[
        "node-confidence-list",
        "edge-confidence-list",
        "huge-node-score",
        "huge-edge-weight",
    ],
)
def test_malformed_confidence_and_huge_numbers_are_adapter_errors(
    tmp_path: Path,
    collection: str,
    field: str,
    value: object,
) -> None:
    project = _project(tmp_path)
    payload = _payload()
    payload[collection][0][field] = value
    graph = tmp_path / "malformed-known-field.json"
    _write_payload(graph, payload)

    with pytest.raises(GraphifyAdapterError):
        load_graphify_snapshot(graph, project_root=project, side="target")


def test_parser_value_errors_are_adapter_errors(tmp_path: Path) -> None:
    project = _project(tmp_path)
    graph = tmp_path / "huge-json-number.json"
    graph.write_text(
        FIXTURE.read_text(encoding="utf-8").replace('"weight": 0.5', '"weight": ' + "9" * 5000),
        encoding="utf-8",
    )

    with pytest.raises(GraphifyAdapterError):
        load_graphify_snapshot(graph, project_root=project, side="target")


@pytest.mark.parametrize("source_value", [None, ""])
def test_nodes_require_nonempty_source_paths(tmp_path: Path, source_value: object) -> None:
    project = _project(tmp_path)
    payload = _payload()
    if source_value is None:
        del payload["nodes"][0]["source_file"]
    else:
        payload["nodes"][0]["source_file"] = source_value
    graph = tmp_path / "missing-source.json"
    _write_payload(graph, payload)

    with pytest.raises(GraphifyAdapterError, match=r"source_file|missing"):
        load_graphify_snapshot(graph, project_root=project, side="target")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value["nodes"][1].update({"source_location": "L999999"}),
        lambda value: value["links"][1].update({"source_location": "L999999"}),
    ],
    ids=["node-occurrence", "edge-occurrence"],
)
def test_occurrences_cannot_exceed_exact_source_bytes(tmp_path: Path, mutate: Any) -> None:
    project = _project(tmp_path)
    payload = _payload()
    mutate(payload)
    graph = tmp_path / "out-of-range.json"
    _write_payload(graph, payload)

    with pytest.raises(GraphifyAdapterError, match="exceeds the exact source bytes"):
        load_graphify_snapshot(graph, project_root=project, side="target")


@pytest.mark.parametrize(
    ("field", "value"),
    [("directed", False), ("multigraph", False), ("directed", 1)],
)
def test_requires_attested_graph_direction_values(
    tmp_path: Path, field: str, value: object
) -> None:
    project = _project(tmp_path)
    payload = _payload()
    payload[field] = value
    graph = tmp_path / "direction.json"
    _write_payload(graph, payload)

    with pytest.raises(GraphifyAdapterError, match=field):
        load_graphify_snapshot(graph, project_root=project, side="target")


def test_rejects_relations_without_attested_orientation(tmp_path: Path) -> None:
    project = _project(tmp_path)
    payload = _payload()
    payload["links"][1]["relation"] = "unknown_direction"
    graph = tmp_path / "orientation.json"
    _write_payload(graph, payload)

    with pytest.raises(GraphifyAdapterError, match="no attested source-to-target orientation"):
        load_graphify_snapshot(graph, project_root=project, side="target")


def test_strict_json_rejects_duplicate_members_and_non_finite_numbers(tmp_path: Path) -> None:
    project = _project(tmp_path)
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"directed":true,"directed":false}', encoding="utf-8")
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
    payload = _payload()
    payload["nodes"][0]["source_file"] = "../outside.py"
    graph = tmp_path / "escape.json"
    _write_payload(graph, payload)

    with pytest.raises(GraphifyAdapterError, match="confined project file"):
        load_graphify_snapshot(graph, project_root=project, side="target")


def test_graph_and_source_reads_enforce_exact_and_over_limit_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _project(tmp_path)
    graph_size = len(FIXTURE.read_bytes())
    source_size = max(len(path.read_bytes()) for path in project.glob("*.py"))

    monkeypatch.setattr(graphify_adapter, "MAX_GRAPH_BYTES", graph_size)
    monkeypatch.setattr(graphify_adapter, "MAX_SOURCE_BYTES", source_size)
    load_graphify_snapshot(FIXTURE, project_root=project, side="target")

    monkeypatch.setattr(graphify_adapter, "MAX_GRAPH_BYTES", graph_size - 1)
    with pytest.raises(GraphifyAdapterError, match="Graphify snapshot exceeds"):
        load_graphify_snapshot(FIXTURE, project_root=project, side="target")

    monkeypatch.setattr(graphify_adapter, "MAX_GRAPH_BYTES", graph_size)
    monkeypatch.setattr(graphify_adapter, "MAX_SOURCE_BYTES", source_size - 1)
    with pytest.raises(GraphifyAdapterError, match="source file exceeds"):
        load_graphify_snapshot(FIXTURE, project_root=project, side="target")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are unavailable")
@pytest.mark.parametrize("fifo_input", ["graph", "source"])
def test_graph_and_source_fifos_fail_without_a_writer(tmp_path: Path, fifo_input: str) -> None:
    project = _project(tmp_path)
    graph = tmp_path / "graph.json"
    if fifo_input == "graph":
        fifo = graph
    else:
        fifo = project / "app.py"
        fifo.unlink()
        _write_payload(graph, _payload())
    os.mkfifo(fifo)

    _assert_fifo_rejected_without_writer(
        fifo,
        lambda: load_graphify_snapshot(graph, project_root=project, side="target"),
    )


def test_graph_read_rejects_non_regular_and_mutating_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _project(tmp_path)
    with pytest.raises(GraphifyAdapterError, match="not a regular file"):
        load_graphify_snapshot(Path(os.devnull), project_root=project, side="target")

    real_fstat = os.fstat
    calls = 0

    def changing_fstat(fd: int) -> os.stat_result | SimpleNamespace:
        nonlocal calls
        calls += 1
        result = real_fstat(fd)
        if calls == 2:
            return SimpleNamespace(
                st_mode=result.st_mode,
                st_dev=result.st_dev,
                st_ino=result.st_ino,
                st_size=result.st_size,
                st_mtime_ns=result.st_mtime_ns + 1,
                st_ctime_ns=result.st_ctime_ns,
            )
        return result

    monkeypatch.setattr(graphify_adapter.os, "fstat", changing_fstat)
    with pytest.raises(GraphifyAdapterError, match="changed while it was being read"):
        load_graphify_snapshot(FIXTURE, project_root=project, side="target")


def test_missing_graph_project_and_source_failures_are_adapter_errors(tmp_path: Path) -> None:
    project = _project(tmp_path)
    with pytest.raises(GraphifyAdapterError, match="cannot read Graphify snapshot"):
        load_graphify_snapshot(tmp_path / "missing.json", project_root=project, side="target")
    with pytest.raises(GraphifyAdapterError, match="project root does not exist"):
        load_graphify_snapshot(
            FIXTURE, project_root=tmp_path / "missing-project", side="target"
        )

    payload = _payload()
    payload["nodes"][0]["source_file"] = "missing.py"
    graph = tmp_path / "missing-source-file.json"
    _write_payload(graph, payload)
    with pytest.raises(GraphifyAdapterError, match="confined project file"):
        load_graphify_snapshot(graph, project_root=project, side="target")


def test_offline_import_writes_pinned_receipt_without_subprocess(tmp_path: Path) -> None:
    project = _project(tmp_path)
    receipt_path = tmp_path / "snapshot-receipt.json"

    with patch("subprocess.run") as run:
        snapshot = import_graphify_snapshot(
            FIXTURE,
            project_root=project,
            side="target",
            receipt_path=receipt_path,
            expected_sha256=hashlib.sha256(FIXTURE.read_bytes()).hexdigest(),
        )
    run.assert_not_called()
    assert not hasattr(graphify_adapter, "GraphifyRunner")

    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt == {
        "directed": True,
        "edge_count": 4,
        "expected_graphify_command": "graphify",
        "expected_graphify_package": "graphifyy",
        "expected_graphify_version": "0.9.30",
        "expected_version_output": "graphify 0.9.30",
        "graph_schema_version": GRAPHIFY_GRAPH_SCHEMA_VERSION,
        "graph_sha256": snapshot.graph_sha256,
        "import_mode": "offline-only",
        "multigraph": True,
        "node_count": 3,
        "side": "target",
    }

    with pytest.raises(GraphifyAdapterError, match="cannot publish"):
        import_graphify_snapshot(
            FIXTURE,
            project_root=project,
            side="target",
            receipt_path=receipt_path,
        )
