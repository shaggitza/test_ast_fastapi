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
    assert report.status == "diagnostic_only"
    assert report.summary.model_dump() == {
        "endpoints_with_staging": 4,
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
