"""Integrity checks for the inert, source-only GH99 real-PR fixture."""

from __future__ import annotations

import ast
import base64
import hashlib
import json
from pathlib import Path

from fastapi_endpoint_detector.parser.diff_parser import DiffParser

FIXTURE = Path(__file__).parents[1] / "fixtures" / "sql_transactions" / "logstotal_7"


def test_fixture_snapshot_hashes_and_frozen_call_spans_match() -> None:
    provenance = json.loads((FIXTURE / "provenance.json").read_text())
    provenance_bytes = (FIXTURE / "provenance.json").read_bytes()
    labels_path = FIXTURE / "expected-static-labels-before-prediction.json"
    labels_bytes = labels_path.read_bytes()
    assert hashlib.sha256(provenance_bytes).hexdigest() == (
        "35780a865030890264f9fb2609dd8c3058be392a63ecd5476dd4d4f7d736f306"
    )
    assert hashlib.sha256(labels_bytes).hexdigest() == (
        "9dcd1bbe3462e57d66e316f5862f017c95a9b7d6dfc6929aeebdc3216b50b68b"
    )
    assert (
        hashlib.sha256(labels_bytes).hexdigest()
        == provenance["selection"]["preprediction_label_sha256"]
    )
    labels = json.loads(labels_bytes)

    for relpath, expected in provenance["source_files"].items():
        source = (FIXTURE / relpath).read_bytes()
        assert len(source) == expected["bytes"]
        assert hashlib.sha256(source).hexdigest() == expected["sha256"]

    for side, snapshot in (("base", "base"), ("head", "target")):
        source_path = FIXTURE / "source" / snapshot / "app" / "job_watch.py.txt"
        source = source_path.read_text(encoding="utf-8")
        digest = hashlib.sha256(source.encode()).hexdigest()
        tree = ast.parse(source, filename="app/job_watch.py")
        calls = {
            (
                node.lineno,
                node.end_lineno,
                node.col_offset,
                node.end_col_offset,
            ): ast.get_source_segment(source, node)
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
        }
        for span in labels["physical_call_spans"]:
            if span["side"] != side:
                continue
            assert span["source_path"] == "app/job_watch.py"
            assert span["source_sha256"] == digest
            key = (span["line"], span["end_line"], span["column"], span["end_column"])
            assert calls[key] == span["call_text"]

    assert labels["recorded_before_analyzer_output"] is True
    assert labels["typed_applicability_expected_before_prediction"][
        "expected_typed_result"
    ].startswith("No typed SQLAlchemy")

    adjudication = json.loads((FIXTURE / "independent-source-adjudication-r7.json").read_text())
    assert adjudication["schema"] == "gh99-real-pr-independent-source-adjudication-v1"
    assert adjudication["reviewed_inputs"]["fixture_provenance_sha256"] == (
        hashlib.sha256(provenance_bytes).hexdigest()
    )
    assert adjudication["reviewed_inputs"]["preprediction_labels_sha256"] == (
        hashlib.sha256(labels_bytes).hexdigest()
    )
    assert adjudication["reviewed_inputs"]["physical_call_span_count"] == 18
    assert adjudication["reviewed_candidate"]["commit"] == (
        "6f16089942581d0bd39e8aa3d3b1d283881e882d"
    )
    assert adjudication["limitations"]["typed_sqlalchemy_positive"] is False
    assert adjudication["limitations"]["durability"] is False
    assert adjudication["collection_protocol"]["strict_per_attempt_cap_compliant"] is False

    encoded_patch = (FIXTURE / "github-pr.patch.base64").read_bytes()
    assert hashlib.sha256(encoded_patch).hexdigest() == provenance["patch"]["encoded_sha256"]
    patch = base64.b64decode(encoded_patch.rstrip(b"\n"), validate=True).decode("utf-8")
    assert len(patch.encode()) == provenance["patch"]["bytes"]
    assert hashlib.sha256(patch.encode()).hexdigest() == provenance["patch"]["sha256"]
    changed = DiffParser.parse_string(patch)
    assert {item.path.as_posix() for item in changed} == {
        "app/job_watch.py",
        "tests/test_job_watch.py",
    }
    source_change = next(item for item in changed if item.path.as_posix() == "app/job_watch.py")
    assert source_change.added_lines == provenance["changed_files"][0]["additions"]
    assert source_change.removed_lines == provenance["changed_files"][0]["deletions"]
