"""Conservative endpoint-reachable SQL staging and transaction diagnostics."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from pydantic import ValidationError

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.analyzer.sql_transaction_paths import (
    build_sql_transaction_path_diagnostics,
)
from fastapi_endpoint_detector.config import AnalysisConfig, Config
from fastapi_endpoint_detector.models.effect_contract import (
    ContextExitSemantics,
    EffectTiming,
    TransactionScope,
    load_effect_contracts,
)
from fastapi_endpoint_detector.models.report import AnalysisReport
from fastapi_endpoint_detector.models.sql_transaction import (
    build_sql_transaction_path_report,
)
from fastapi_endpoint_detector.output.formatters import get_formatter


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


def _fixture_occurrence(
    fixture: Path,
    relative_path: str,
    spelling: str,
    ordinal: int = 0,
) -> SimpleNamespace:
    tree = ast.parse((fixture / relative_path).read_bytes(), filename=relative_path)
    matches = [
        node.func
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and ast.unparse(node.func) == spelling
        and node.func.end_lineno is not None
        and node.func.end_col_offset is not None
    ]
    node = matches[ordinal]
    path = Path(relative_path).as_posix()
    identity = hashlib.sha256(
        f"{path}:{node.lineno}:{node.col_offset}:{node.end_lineno}:{node.end_col_offset}".encode()
    ).hexdigest()
    return SimpleNamespace(
        id=f"sha256:{identity}",
        file_path=path,
        line=node.lineno,
        column=node.col_offset,
        end_line=node.end_lineno,
        end_column=node.end_col_offset,
    )


def _assert_langflow_fixture_path_analysis(fixture: Path) -> None:
    """Exercise transaction path analysis against source positions in pinned files."""
    stage = _fixture_occurrence(fixture, "source/langflow/api/v1/traces.py.txt", "session.execute")
    begin = _fixture_occurrence(
        fixture,
        "source/langflow/api/v1/traces.py.txt",
        "session_scope",
        ordinal=1,
    )
    flush = _fixture_occurrence(fixture, "source/langflow/api/v1/flows.py.txt", "db.flush")
    commit = _fixture_occurrence(fixture, "source/lfx/services/deps.py.txt", "session.commit")
    rollbacks = [
        _fixture_occurrence(
            fixture,
            "source/lfx/services/deps.py.txt",
            "session.rollback",
            ordinal,
        )
        for ordinal in range(2)
    ]
    boundaries = (flush, commit, *rollbacks)
    endpoint_id = f"sha256:{hashlib.sha256(b'langflow-13960-delete-traces').hexdigest()}"
    begin_scope = SimpleNamespace(
        occurrence_id=begin.id,
        scope=TransactionScope.TRANSACTION,
        timing=EffectTiming.CONTEXT_ENTER,
        context_exit=ContextExitSemantics.TRANSACTION_COMMIT_ROLLBACK,
    )
    evidence = SimpleNamespace(
        endpoint_id=endpoint_id,
        stage_occurrence_ids=(stage.id,),
        flush_occurrence_ids=(flush.id,),
        begin_occurrence_ids=(begin.id,),
        begin_scopes=(begin_scope,),
        commit_occurrence_ids=(commit.id,),
        rollback_occurrence_ids=tuple(item.id for item in rollbacks),
    )
    transaction_report = SimpleNamespace(
        endpoint_evidence=(evidence,),
        report_hash=f"sha256:{'1' * 64}",
    )
    audit = SimpleNamespace(
        provenance=SimpleNamespace(audit_hash=f"sha256:{'2' * 64}"),
        occurrences=(stage, begin, *boundaries),
    )
    paths = build_sql_transaction_path_diagnostics(
        fixture,
        audit,
        transaction_report,
        max_pairs=8,
    )
    assert paths.ordered_paths == ()
    assert len(paths.context_paths) == 1
    context_path = paths.context_paths[0]
    assert context_path.normal_exit == "commit_reachable"
    assert context_path.exceptional_exit == "rollback_reachable"
    assert context_path.status == "conditional_on_context_exit"
    assert context_path.persistence_status == "not_established"
    assert any("runtime transaction identity" in item for item in context_path.limitations)
    assert len(paths.diagnostics) == 4
    assert {item.reason_code for item in paths.diagnostics} == {"different_source_scope"}


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
    assert report.schema_version == 3
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
        "    def flush(self) -> None: pass\n"
        "    def commit(self) -> None: pass\n"
        "    def rollback(self) -> None: pass\n\n"
        "class Other:\n"
        "    def flush(self) -> None: pass\n\n"
        "class AsyncSession:\n"
        "    def begin(self): return self\n"
        "    async def __aenter__(self): return self\n"
        "    async def __aexit__(self, exc_type, exc, tb): pass\n"
        "    async def add(self, value: str) -> None: pass\n\n"
        "class Holder:\n"
        "    def __init__(self) -> None:\n"
        "        self.session = Session()\n\n"
        "class UnitOfWork:\n"
        "    def begin(self): return self\n"
        "    def __enter__(self): return self\n"
        "    def __exit__(self, exc_type, exc, tb): return False\n"
        "    def add(self, value: str) -> None: pass\n\n"
        "def stage_helper(session: Session) -> None:\n"
        "    session.add('helper')\n\n"
        "@app.post('/ordered')\n"
        "def ordered() -> None:\n"
        "    session = Session()\n"
        "    session.begin()\n"
        "    session.add('ordered')\n"
        "    session.flush()\n"
        "    session.commit()\n\n"
        "@app.post('/generic-flush')\n"
        "def generic_flush() -> None:\n"
        "    session = Session()\n"
        "    other = Other()\n"
        "    session.add('generic')\n"
        "    other.flush()\n\n"
        "@app.post('/nested')\n"
        "def nested() -> None:\n"
        "    session = Session()\n"
        "    session.begin_nested()\n"
        "    session.add('nested')\n"
        "    session.commit()\n\n"
        "@app.post('/context')\n"
        "def managed_context() -> None:\n"
        "    session = Session()\n"
        "    with session.begin():\n"
        "        session.add('context')\n\n"
        "@app.post('/async-context')\n"
        "async def managed_async_context() -> None:\n"
        "    session = AsyncSession()\n"
        "    async with session.begin():\n"
        "        await session.add('async-context')\n\n"
        "@app.post('/savepoint-context')\n"
        "def managed_savepoint() -> None:\n"
        "    session = Session()\n"
        "    with session.begin_nested():\n"
        "        session.add('savepoint')\n\n"
        "@app.post('/captured-context')\n"
        "def captured_context() -> None:\n"
        "    session = Session()\n"
        "    with session.begin() as transaction:\n"
        "        session.add('captured')\n\n"
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
        "    session.commit()\n\n"
        "@app.post('/wrapper-context')\n"
        "def wrapper_context() -> None:\n"
        "    work = UnitOfWork()\n"
        "    with work.begin():\n"
        "        work.add('wrapped')\n\n"
        "@app.post('/exception-path')\n"
        "def exception_path() -> None:\n"
        "    session = Session()\n"
        "    session.add('exception')\n"
        "    try:\n"
        "        session.flush()\n"
        "        session.commit()\n"
        "    except Exception:\n"
        "        session.rollback()\n",
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
                                    "context_exit": (
                                        "savepoint_release_rollback"
                                        if operation == "begin_nested"
                                        else "transaction_commit_rollback"
                                    ),
                                }
                            }
                            if operation in {"begin", "begin_nested"}
                            else {}
                        ),
                    }
                    for operation in (
                        "add",
                        "flush",
                        "begin",
                        "begin_nested",
                        "commit",
                        "rollback",
                    )
                ]
                + [
                    {
                        "id": "uow-begin",
                        "symbol": f"{root.name}.main.UnitOfWork.begin",
                        "invocation": "instance_method",
                        "operation": "begin",
                        "channel": "sql",
                        "behavior": {
                            "timing": "context_enter",
                            "transaction_scope": "transaction",
                            "context_exit": "transaction_commit_rollback",
                        },
                    },
                    {
                        "id": "uow-add",
                        "symbol": f"{root.name}.main.UnitOfWork.add",
                        "invocation": "instance_method",
                        "operation": "stage",
                        "channel": "sql",
                    },
                ]
                + [
                    {
                        "id": f"async-{operation}",
                        "symbol": f"{root.name}.main.AsyncSession.{operation}",
                        "invocation": "instance_method",
                        "operation": "stage" if operation == "add" else "begin",
                        "channel": "sql",
                        "behavior": (
                            {"async_mode": "async", "timing": "await"}
                            if operation == "add"
                            else {
                                "async_mode": "sync",
                                "timing": "context_enter",
                                "transaction_scope": "transaction",
                                "context_exit": "transaction_commit_rollback",
                            }
                        ),
                    }
                    for operation in ("add", "begin")
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
    assert paths.schema_version == 4
    assert paths.summary.model_dump() == {
        "ordered_paths": 4,
        "ordered_flushes": 1,
        "ordered_commits": 3,
        "ordered_rollbacks": 0,
        "context_manager_paths": 5,
        "context_transactions": 4,
        "context_savepoints": 1,
        "unresolved_pairs": 8,
    }
    ordered = next(item for item in paths.ordered_paths if item.function_name == "ordered")
    assert {item.function_name for item in paths.ordered_paths} == {
        "attribute_receiver",
        "nested",
        "ordered",
    }
    ordered_flush = next(
        item
        for item in paths.ordered_paths
        if item.function_name == "ordered" and item.boundary == "flush"
    )
    assert ordered_flush.persistence_status == "not_established"
    assert any("pending sql" in item.lower() for item in ordered_flush.limitations)
    assert all(item.function_name != "generic_flush" for item in paths.ordered_paths)
    assert ordered.begin_occurrence_id is not None
    assert ordered.begin_scope is not None and ordered.begin_scope.value == "transaction"
    nested = next(item for item in paths.ordered_paths if item.function_name == "nested")
    assert nested.begin_scope is not None and nested.begin_scope.value == "savepoint"
    assert ordered.persistence_status == "not_established"
    assert {item.function_name for item in paths.context_paths} == {
        "managed_async_context",
        "managed_context",
        "managed_savepoint",
        "wrapper_context",
        "captured_context",
    }
    managed = next(item for item in paths.context_paths if item.function_name == "managed_context")
    assert managed.normal_exit == "commit_reachable"
    assert managed.exceptional_exit == "rollback_reachable"
    assert managed.status == "conditional_on_context_exit"
    wrapper = next(item for item in paths.context_paths if item.function_name == "wrapper_context")
    assert wrapper.normal_exit == "commit_reachable"
    assert wrapper.exceptional_exit == "rollback_reachable"
    assert all(item.persistence_status == "not_established" for item in paths.context_paths)
    assert (
        sum(item.reason_code == "control_flow_unavailable" for item in paths.diagnostics) >= 4
    )  # Branch flow plus all three try/except boundaries stay unresolved.
    savepoint = next(
        item for item in paths.context_paths if item.function_name == "managed_savepoint"
    )
    assert savepoint.normal_exit == "savepoint_release_reachable"
    assert all(item.persistence_status == "not_established" for item in paths.context_paths)
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
    for output_format in ("text", "markdown", "html"):
        assert "flushes" in get_formatter(output_format).format(configured).lower()


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


def test_langflow_13960_real_source_transaction_fixture_is_pinned_and_bounded(
    tmp_path: Path,
) -> None:
    """Parse complete pinned upstream snapshots as data; never import or execute them."""
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    provenance = json.loads((fixture / "provenance.json").read_text(encoding="utf-8"))
    assert provenance["repository"] == "langflow-ai/langflow"
    assert provenance["pull_request"] == 13960
    assert provenance["base_sha"] == "b40e4aa02661dcc9d630e1e97a0af45d45e88ae4"
    assert provenance["target_merge_sha"] == "a69a47ff1b5c99ce9c50edc4df45de4397151f17"
    assert provenance["license"]["spdx"] == "MIT"
    assert "Copyright (c) 2024 Langflow" in (fixture / "LICENSE.langflow.txt").read_text()
    snapshot_sources = tuple((fixture / "source").rglob("*.py.txt"))
    assert snapshot_sources
    assert not tuple((fixture / "source").rglob("*.py"))
    snapshot_paths = set()
    for upstream_path, snapshot in provenance["source_snapshots"].items():
        relative_path = snapshot["snapshot_path"]
        snapshot_paths.add(relative_path)
        content = (fixture / relative_path).read_bytes()
        start, end = snapshot["byte_start"], snapshot["byte_end"]
        assert start == 0 and end == len(content)
        assert content[start:end] == content
        assert hashlib.sha256(content).hexdigest() == snapshot["sha256"]
        assert snapshot["sha256"] == provenance["upstream_sources"][upstream_path]["sha256"]
        assert snapshot["line_start"] == 1
        assert snapshot["line_end"] == len(content.splitlines())
        ast.parse(content, filename=upstream_path)
    assert snapshot_paths == {path.relative_to(fixture).as_posix() for path in snapshot_sources}

    route = (fixture / "source/langflow/api/v1/traces.py.txt").read_text(encoding="utf-8")
    wrapper = (fixture / "source/lfx/services/deps.py.txt").read_text(encoding="utf-8")
    flow_flush = (fixture / "source/langflow/api/v1/flows.py.txt").read_text(encoding="utf-8")
    regression = (fixture / "source/langflow/tests/test_span_cascade_delete.py.txt").read_text(
        encoding="utf-8"
    )
    assert "async with session_scope() as session" in route
    assert "await session.execute(delete_stmt)" in route
    assert "await db.flush()" in flow_flush
    assert "await session.commit()" in wrapper
    assert "await session.rollback()" in wrapper
    assert "except HTTPException" in wrapper and "except Exception" in wrapper
    assert "await session.commit()" in regression
    assert "begin_nested" not in route and "begin_nested" not in wrapper
    assert provenance["transaction_semantics"]["durability"].startswith("commit reachable")
    contract_info = provenance["configured_wrapper_contract"]
    contract_bytes = (fixture / contract_info["path"]).read_bytes()
    assert hashlib.sha256(contract_bytes).hexdigest() == contract_info["sha256"]
    contract = load_effect_contracts(fixture / contract_info["path"]).document.contracts[0]
    assert contract.id == contract_info["contract_id"]
    assert contract.symbol == "langflow.services.deps.session_scope"
    assert contract.operation.value == "begin"
    assert contract.behavior.context_exit.value == "transaction_commit_rollback"
    _assert_langflow_fixture_path_analysis(fixture)
