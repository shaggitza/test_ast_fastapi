"""Conservative endpoint-reachable SQL staging and transaction diagnostics."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
import yaml
from pydantic import ValidationError

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.config import AnalysisConfig, Config
from fastapi_endpoint_detector.models.report import AnalysisReport
from fastapi_endpoint_detector.models.sql_transaction import (
    build_sql_transaction_path_report,
)
from fastapi_endpoint_detector.output.formatters import get_formatter

if TYPE_CHECKING:
    from pathlib import Path


def _project(root: Path) -> tuple[Path, Path]:
    (root / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n\n"
        "def stage(value: str) -> None: pass\n"
        "def flush() -> None: pass\n"
        "def begin() -> None: pass\n"
        "def commit() -> None: pass\n"
        "def rollback() -> None: pass\n\n"
        "@app.post('/pending')\n"
        "def pending() -> None:\n"
        "    stage('pending')\n\n"
        "@app.post('/committed')\n"
        "def committed() -> None:\n"
        "    begin()\n"
        "    stage('committed')\n"
        "    flush()\n"
        "    commit()\n\n"
        "@app.post('/rolled-back')\n"
        "def rolled_back() -> None:\n"
        "    stage('rolled')\n"
        "    rollback()\n\n"
        "@app.post('/unresolved')\n"
        "def unresolved() -> None:\n"
        "    stage('unknown')\n"
        "    commit()\n"
        "    rollback()\n",
        encoding="utf-8",
    )
    contracts = root / "effects.yaml"
    contract_rows = []
    for contract_id, operation in (
        ("begin", "begin"),
        ("commit", "commit"),
        ("flush", "flush"),
        ("rollback", "rollback"),
        ("stage", "stage"),
    ):
        contract_rows.append(
            {
                "id": contract_id,
                "symbol": f"{root.name}.main.{contract_id}",
                "invocation": "function",
                "operation": operation,
                "channel": "sql",
            }
        )
    contracts.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "preset": {
                    "id": "sql-test",
                    "version": "1.0.0",
                    "provenance": {"kind": "user", "source": "effects.yaml"},
                },
                "contracts": contract_rows,
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    diff = root / "change.diff"
    diff.write_text(
        "diff --git a/main.py b/main.py\n"
        "--- a/main.py\n"
        "+++ b/main.py\n"
        "@@ -5,1 +5,1 @@\n"
        "-def stage(value: str) -> None: pass\n"
        "+def stage(value: str) -> None: return None\n",
        encoding="utf-8",
    )
    return contracts, diff


def _candidate_projection(report: AnalysisReport) -> list[dict[str, object]]:
    return [item.model_dump(mode="json") for item in report.candidate_endpoints]


def test_sql_diagnostics_separate_pending_and_reachable_boundaries(tmp_path: Path) -> None:
    contracts, diff = _project(tmp_path)
    baseline = ChangeMapper(
        app_path=tmp_path,
        config=Config(analysis=AnalysisConfig(effect_contracts=contracts)),
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)
    configured = ChangeMapper(
        app_path=tmp_path,
        config=Config(
            analysis=AnalysisConfig(
                effect_contracts=contracts,
                sql_transaction_diagnostics=True,
            )
        ),
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)

    assert _candidate_projection(configured) == _candidate_projection(baseline)
    assert configured.affected_endpoints == baseline.affected_endpoints
    assert configured.orphan_changes == baseline.orphan_changes
    report = configured.sql_transaction_report
    assert report is not None
    assert report.schema_version == 2
    assert report.status == "diagnostic_only"
    assert report.summary.model_dump() == {
        "endpoints_with_staging": 4,
        "transaction_begins": 0,
        "savepoint_begins": 0,
        "unclassified_begins": 1,
        "pending_persistence": 1,
        "commit_reachable": 1,
        "rollback_reachable": 1,
        "outcome_unresolved": 1,
    }
    outcomes = {item.outcome.value for item in report.endpoint_evidence}
    assert outcomes == {
        "pending_persistence",
        "commit_reachable",
        "rollback_reachable",
        "outcome_unresolved",
    }
    assert all(item.persistence_status == "not_established" for item in report.endpoint_evidence)
    committed = next(
        item for item in report.endpoint_evidence if item.outcome.value == "commit_reachable"
    )
    assert committed.flush_occurrence_ids
    assert committed.begin_occurrence_ids
    serialized = json.dumps(configured.model_dump(mode="json"))
    assert "durable_write" not in serialized


def test_sql_diagnostics_are_opt_in_and_require_effect_contracts(tmp_path: Path) -> None:
    _contracts, diff = _project(tmp_path)
    with pytest.raises(ValueError, match="requires effect_contracts"):
        AnalysisConfig(sql_transaction_diagnostics=True)

    report = ChangeMapper(
        app_path=tmp_path,
        config=Config(),
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)
    assert report.sql_transaction_report is None


def test_sql_report_tampering_is_rejected_and_formats_disclose_limitations(
    tmp_path: Path,
) -> None:
    contracts, diff = _project(tmp_path)
    report = ChangeMapper(
        app_path=tmp_path,
        config=Config(
            analysis=AnalysisConfig(
                effect_contracts=contracts,
                sql_transaction_diagnostics=True,
            )
        ),
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)
    payload = report.model_dump(mode="json")
    payload["sql_transaction_report"]["endpoint_evidence"][0]["endpoint_id"] = f"sha256:{'0' * 64}"
    with pytest.raises(ValidationError):
        AnalysisReport.model_validate(payload)

    json_data = json.loads(get_formatter("json").format(report))
    yaml_data = yaml.safe_load(get_formatter("yaml").format(report))
    assert json_data["sql_transaction_report"]["status"] == "diagnostic_only"
    assert yaml_data["sql_transaction_report"] == json_data["sql_transaction_report"]
    for output_format in ("text", "markdown", "html"):
        rendered = get_formatter(output_format).format(report).lower()
        assert "sql transactions" in rendered
        assert "persistence not established" in rendered


def _ordered_project(root: Path) -> tuple[Path, Path]:
    (root / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n\n"
        "class Session:\n"
        "    def begin(self) -> None: pass\n"
        "    def begin_nested(self) -> None: pass\n"
        "    def add(self, value: str) -> None: pass\n"
        "    def commit(self) -> None: pass\n"
        "    def rollback(self) -> None: pass\n\n"
        "class Holder:\n"
        "    def __init__(self) -> None:\n"
        "        self.session = Session()\n\n"
        "def stage_helper(session: Session) -> None:\n"
        "    session.add('helper')\n\n"
        "@app.post('/ordered')\n"
        "def ordered() -> None:\n"
        "    session = Session()\n"
        "    session.begin()\n"
        "    session.add('ordered')\n"
        "    session.commit()\n\n"
        "@app.post('/nested')\n"
        "def nested() -> None:\n"
        "    session = Session()\n"
        "    session.begin_nested()\n"
        "    session.add('nested')\n"
        "    session.commit()\n\n"
        "@app.post('/attribute')\n"
        "def attribute_receiver() -> None:\n"
        "    holder = Holder()\n"
        "    holder.session.add('attribute')\n"
        "    holder.session.commit()\n\n"
        "@app.post('/branch')\n"
        "def branch(flag: bool) -> None:\n"
        "    session = Session()\n"
        "    if flag:\n"
        "        session.add('branch')\n"
        "    session.commit()\n\n"
        "@app.post('/mismatch')\n"
        "def mismatch() -> None:\n"
        "    left = Session()\n"
        "    right = Session()\n"
        "    left.add('mismatch')\n"
        "    right.commit()\n\n"
        "@app.post('/reassigned')\n"
        "def reassigned() -> None:\n"
        "    session = Session()\n"
        "    session.add('first')\n"
        "    session = Session()\n"
        "    session.commit()\n\n"
        "@app.post('/precedes')\n"
        "def precedes() -> None:\n"
        "    session = Session()\n"
        "    session.rollback()\n"
        "    session.add('later')\n\n"
        "@app.post('/helper')\n"
        "def helper() -> None:\n"
        "    session = Session()\n"
        "    stage_helper(session)\n"
        "    session.commit()\n",
        encoding="utf-8",
    )
    contracts = root / "ordered-effects.yaml"
    contracts.write_text(
        yaml.safe_dump(
            {
                "schema_version": 2,
                "preset": {
                    "id": "sql-ordered-test",
                    "version": "1.0.0",
                    "provenance": {"kind": "user", "source": "ordered-effects.yaml"},
                },
                "contracts": [
                    {
                        "id": operation,
                        "symbol": f"{root.name}.main.Session.{operation}",
                        "invocation": "instance_method",
                        "operation": (
                            "stage"
                            if operation == "add"
                            else "begin"
                            if operation == "begin_nested"
                            else operation
                        ),
                        "channel": "sql",
                        **(
                            {
                                "behavior": {
                                    "timing": "context_enter",
                                    "transaction_scope": (
                                        "savepoint"
                                        if operation == "begin_nested"
                                        else "transaction"
                                    ),
                                }
                            }
                            if operation in {"begin", "begin_nested"}
                            else {}
                        ),
                    }
                    for operation in ("add", "begin", "begin_nested", "commit", "rollback")
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    diff = root / "ordered.diff"
    diff.write_text(
        "diff --git a/main.py b/main.py\n"
        "--- a/main.py\n"
        "+++ b/main.py\n"
        "@@ -8,1 +8,1 @@\n"
        "-    def add(self, value: str) -> None: pass\n"
        "+    def add(self, value: str) -> None: return None\n",
        encoding="utf-8",
    )
    return contracts, diff


def test_ordered_paths_require_same_scope_receiver_and_straight_line(tmp_path: Path) -> None:
    contracts, diff = _ordered_project(tmp_path)
    baseline = ChangeMapper(
        app_path=tmp_path,
        config=Config(
            analysis=AnalysisConfig(
                effect_contracts=contracts,
                sql_transaction_diagnostics=True,
            )
        ),
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)
    configured = ChangeMapper(
        app_path=tmp_path,
        config=Config(
            analysis=AnalysisConfig(
                effect_contracts=contracts,
                sql_transaction_diagnostics=True,
                sql_transaction_ordered_paths=True,
            )
        ),
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)

    assert _candidate_projection(configured) == _candidate_projection(baseline)
    assert configured.affected_endpoints == baseline.affected_endpoints
    assert configured.orphan_changes == baseline.orphan_changes
    paths = configured.sql_transaction_path_report
    assert paths is not None
    assert paths.schema_version == 2
    assert paths.summary.model_dump() == {
        "ordered_paths": 3,
        "ordered_commits": 3,
        "ordered_rollbacks": 0,
        "unresolved_pairs": 5,
    }
    ordered = next(item for item in paths.ordered_paths if item.function_name == "ordered")
    assert {item.function_name for item in paths.ordered_paths} == {
        "attribute_receiver",
        "nested",
        "ordered",
    }
    assert ordered.begin_occurrence_id is not None
    assert ordered.begin_scope is not None and ordered.begin_scope.value == "transaction"
    nested = next(item for item in paths.ordered_paths if item.function_name == "nested")
    assert nested.begin_scope is not None and nested.begin_scope.value == "savepoint"
    assert ordered.persistence_status == "not_established"
    assert {item.reason_code for item in paths.diagnostics} == {
        "boundary_precedes_stage",
        "control_flow_unavailable",
        "different_source_scope",
        "receiver_mismatch",
        "receiver_reassigned",
    }
    payload = json.dumps(configured.model_dump(mode="json"))
    assert "runtime object identity" in payload
    assert "durable_write" not in payload

    forged_paths = build_sql_transaction_path_report(
        paths.effect_audit_hash,
        f"sha256:{'0' * 64}",
        paths.ordered_paths,
        paths.diagnostics,
        max_pairs=paths.max_pairs,
    )
    forged_report = configured.model_dump(mode="json")
    forged_report["sql_transaction_path_report"] = forged_paths.model_dump(mode="json")
    with pytest.raises(ValidationError, match="exact reports"):
        AnalysisReport.model_validate(forged_report)

    for output_format in ("json", "yaml", "text", "markdown", "html"):
        rendered = get_formatter(output_format).format(configured).lower()
        assert "sql_transaction_path_report" in rendered or "sql ordered paths" in rendered


def test_ordered_paths_are_explicit_and_atomically_bounded(tmp_path: Path) -> None:
    contracts, diff = _ordered_project(tmp_path)
    with pytest.raises(ValueError, match="requires sql_transaction_diagnostics"):
        AnalysisConfig(
            effect_contracts=contracts,
            sql_transaction_ordered_paths=True,
        )

    with pytest.raises(ValueError, match="pair limit exceeded"):
        ChangeMapper(
            app_path=tmp_path,
            config=Config(
                analysis=AnalysisConfig(
                    effect_contracts=contracts,
                    sql_transaction_diagnostics=True,
                    sql_transaction_ordered_paths=True,
                    sql_transaction_path_max_pairs=6,
                )
            ),
            secure_ast=True,
            use_cache=False,
        ).analyze_diff(diff)
