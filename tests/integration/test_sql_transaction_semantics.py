"""Conservative endpoint-reachable SQL staging and transaction diagnostics."""

from __future__ import annotations

import ast
import hashlib
import json
import re
import shutil
from importlib.util import resolve_name
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.analyzer.effect_contract_auditor import audit_effect_contracts
from fastapi_endpoint_detector.analyzer.sql_transaction import build_sql_transaction_diagnostics
from fastapi_endpoint_detector.analyzer.sql_transaction_paths import (
    _module_snapshot,
    _receiver_reassigned,
    _scope_parents,
    _yield_can_reach_normal_boundary,
    build_sql_transaction_path_diagnostics,
)
from fastapi_endpoint_detector.config import AnalysisConfig, Config
from fastapi_endpoint_detector.models.effect_contract import (
    CallResolutionStatus,
    InvocationKind,
    ResolvedCallSite,
    load_effect_contracts,
)
from fastapi_endpoint_detector.models.endpoint import (
    Endpoint,
    EndpointInventory,
    EndpointMethod,
    HandlerInfo,
    InventoryStatus,
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
                "symbol": f"main.{contract_id}",
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


def _savepoint_target_project(root: Path) -> tuple[Path, Path]:
    contracts, diff = _ordered_project(root)
    source = root / "main.py"
    text = source.read_text(encoding="utf-8")
    text = text.replace(
        "    def begin_nested(self) -> None: pass",
        "    def begin_nested(self) -> NestedTransaction: return NestedTransaction()",
        1,
    )
    text += (
        "\n@app.post('/nested-target')\n"
        "def nested_target() -> None:\n"
        "    session = Session()\n"
        "    transaction = session.begin_nested()\n"
        "    session.add('nested-target')\n"
        "    transaction.commit()\n\n"
        "@app.post('/nested-target-rollback')\n"
        "def nested_target_rollback() -> None:\n"
        "    session = Session()\n"
        "    transaction = session.begin_nested()\n"
        "    session.add('nested-target-rollback')\n"
        "    transaction.rollback()\n\n"
        "@app.post('/nested-rebound-target')\n"
        "def nested_rebound_target() -> None:\n"
        "    session = Session()\n"
        "    transaction = session.begin_nested()\n"
        "    session.add('nested-rebound')\n"
        "    transaction = session.begin_nested()\n"
        "    transaction.commit()\n\n"
        "@app.post('/nested-alias-target')\n"
        "def nested_alias_target() -> None:\n"
        "    session = Session()\n"
        "    transaction = session.begin_nested()\n"
        "    alias = transaction\n"
        "    session.add('nested-alias')\n"
        "    alias.commit()\n\n"
        "@app.post('/nested-foreign-target')\n"
        "def nested_foreign_target() -> None:\n"
        "    session = Session()\n"
        "    session.begin_nested()\n"
        "    session.add('nested-foreign')\n"
        "    foreign = ForeignTransaction()\n"
        "    foreign.commit()\n\n"
        "@final\n"
        "class ForeignTransaction:\n"
        "    def commit(self) -> None: pass\n"
        "    def rollback(self) -> None: pass\n\n"
        "@final\n"
        "class NestedTransaction:\n"
        "    def commit(self) -> None: pass\n"
        "    def rollback(self) -> None: pass\n"
    )
    source.write_text(text, encoding="utf-8")

    document = yaml.safe_load(contracts.read_text(encoding="utf-8"))
    for item in document["contracts"]:
        if item["id"] == "begin_nested":
            item["behavior"]["returns_transaction_scope"] = "savepoint"
    document["contracts"].extend(
        [
            {
                "id": "nested-transaction-commit",
                "symbol": "main.NestedTransaction.commit",
                "invocation": "instance_method",
                "operation": "commit",
                "channel": "sql",
                "behavior": {"transaction_target_from_receiver": True},
            },
            {
                "id": "nested-transaction-rollback",
                "symbol": "main.NestedTransaction.rollback",
                "invocation": "instance_method",
                "operation": "rollback",
                "channel": "sql",
                "behavior": {"transaction_target_from_receiver": True},
            },
        ]
    )
    contracts.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return contracts, diff


def _candidate_projection(report: AnalysisReport) -> list[dict[str, object]]:
    return [item.model_dump(mode="json") for item in report.candidate_endpoints]


def _assert_open_receiver_flush_is_unmatched(report: AnalysisReport) -> None:
    audit = report.effect_contract_audit
    assert audit is not None
    occurrence = next(item for item in audit.occurrences if item.source_spelling == "other.flush")
    assert occurrence.audit_status == "ambiguous"
    assert occurrence.reason_code == "open_receiver_dispatch"
    assert occurrence.contract_id is None


def _fixture_endpoint_calls(fixture: Path) -> tuple[Endpoint, tuple[ResolvedCallSite, ...]]:
    """Resolve only call names proven by imports; leave untyped receiver calls unresolved."""
    relative = Path("source/langflow/api/v1/traces.py.txt")
    file_path = fixture / relative
    source = file_path.read_bytes()
    tree = ast.parse(source, filename=str(file_path))
    handler = next(
        node
        for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "delete_traces_by_flow"
    )
    imported_symbols = {
        alias.asname or alias.name: (
            f"{resolve_name('.' * node.level + node.module, 'langflow.api.v1')}.{alias.name}"
            if node.level
            else f"{node.module}.{alias.name}"
        )
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and node.module is not None
        for alias in node.names
    }
    for node in tree.body:
        if not isinstance(node, ast.ImportFrom) or node.module != "services":
            continue
        package_path = fixture / "source/langflow/services/__init__.py.txt"
        if not package_path.is_file():
            continue
        package_tree = ast.parse(package_path.read_bytes(), filename=str(package_path))
        for alias in node.names:
            local_name = alias.asname or alias.name
            exports = [
                (statement, exported)
                for statement in package_tree.body
                if isinstance(statement, ast.ImportFrom)
                for exported in statement.names
                if (exported.asname or exported.name) == alias.name
            ]
            if len(exports) != 1:
                continue
            statement, exported = exports[0]
            module = statement.module or ""
            base = "langflow.services"
            if statement.level:
                base_parts = base.split(".")[: len(base.split(".")) - statement.level + 1]
                module = ".".join([*base_parts, *module.split(".")])
            imported_symbols[local_name] = f"{module}.{exported.name}"
    prefix = next(
        keyword.value.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "router" for target in node.targets)
        and isinstance(node.value, ast.Call)
        and ast.unparse(node.value.func) == "APIRouter"
        for keyword in node.value.keywords
        if keyword.arg == "prefix" and isinstance(keyword.value, ast.Constant)
    )
    route = next(
        decorator
        for decorator in handler.decorator_list
        if isinstance(decorator, ast.Call)
        and isinstance(decorator.func, ast.Attribute)
        and decorator.func.attr == "delete"
    )
    suffix = route.args[0].value
    endpoint_path = prefix.rstrip("/") + (suffix if suffix.startswith("/") else f"/{suffix}")
    endpoint = Endpoint(
        path=endpoint_path,
        methods=[EndpointMethod.DELETE],
        handler=HandlerInfo(
            name=handler.name,
            module="langflow.api.v1.traces",
            file_path=file_path,
            line_number=handler.lineno,
        ),
    )
    sites = []
    for node in ast.walk(handler):
        if not isinstance(node, ast.Call):
            continue
        source_spelling = ast.unparse(node.func)
        common = {
            "file_path": str(file_path),
            "line": node.func.lineno,
            "column": node.func.col_offset,
            "end_line": node.func.end_lineno,
            "end_column": node.func.end_col_offset,
            "source_spelling": source_spelling,
            "resolver": "pinned_fixture_ast",
            "resolver_version": "1",
        }
        imported_symbol = (
            imported_symbols.get(node.func.id) if isinstance(node.func, ast.Name) else None
        )
        if imported_symbol == "langflow.services.deps.session_scope":
            sites.append(
                ResolvedCallSite(
                    **common,
                    canonical_symbol=imported_symbol,
                    invocation=InvocationKind.FUNCTION,
                    status=CallResolutionStatus.EXACT,
                )
            )
        else:
            sites.append(
                ResolvedCallSite(
                    **common,
                    status=CallResolutionStatus.UNRESOLVED,
                    reason_code="fixture_type_proof_unavailable",
                )
            )
    return endpoint, tuple(sites)


def _langflow_fixture_transaction_reports(fixture: Path):
    """Run configured audit, transaction aggregation, and bounded path analysis."""
    effects = load_effect_contracts(fixture / "effects.yaml")
    endpoint, sites = _fixture_endpoint_calls(fixture)
    inventory = EndpointInventory(endpoints=[endpoint], status=InventoryStatus.ESTABLISHED)
    audit = audit_effect_contracts(
        effects,
        source_root=fixture,
        inventory=inventory,
        endpoint_call_sites=((endpoint, sites),),
        track_transitive=False,
        max_depth=1,
        cache_enabled=False,
        resolver_versions=("pinned_fixture_ast@1",),
    )
    transaction = build_sql_transaction_diagnostics(effects, audit)
    paths = build_sql_transaction_path_diagnostics(
        fixture,
        audit,
        transaction,
        effects,
        max_pairs=8,
    )
    return audit, transaction, paths


def _assert_langflow_pinned_snapshots(fixture: Path, provenance: dict[str, Any]) -> None:
    assert provenance["repository"] == "langflow-ai/langflow"
    assert provenance["pull_request"] == 13960
    assert provenance["base_sha"] == "b40e4aa02661dcc9d630e1e97a0af45d45e88ae4"
    assert provenance["target_merge_sha"] == "a69a47ff1b5c99ce9c50edc4df45de4397151f17"
    assert provenance["license"]["spdx"] == "MIT"
    assert "Copyright (c) 2024 Langflow" in (fixture / "LICENSE.langflow.txt").read_text()
    snapshots = provenance["source_snapshots"]
    snapshot_sources = tuple((fixture / "source").rglob("*.py.txt"))
    assert snapshot_sources
    assert not tuple((fixture / "source").rglob("*.py"))
    snapshot_paths = set()
    for upstream_path, snapshot in snapshots.items():
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


def _assert_langflow_context_yield_identity(fixture: Path) -> None:
    langflow_wrapper = (fixture / "source/langflow/services/deps.py.txt").read_text(
        encoding="utf-8"
    )
    wrapper = (fixture / "source/lfx/services/deps.py.txt").read_text(encoding="utf-8")
    assert "async with lfx_session_scope() as session" in langflow_wrapper
    assert "yield session" in langflow_wrapper
    assert "yield session" in wrapper


def _assert_langflow_source_transaction_evidence(
    fixture: Path,
    provenance: dict[str, Any],
) -> None:
    route = (fixture / "source/langflow/api/v1/traces.py.txt").read_text(encoding="utf-8")
    wrapper = (fixture / "source/lfx/services/deps.py.txt").read_text(encoding="utf-8")
    flow_source = (fixture / "source/langflow/api/v1/flows.py.txt").read_text(encoding="utf-8")
    regression = (fixture / "source/langflow/tests/test_span_cascade_delete.py.txt").read_text(
        encoding="utf-8"
    )
    assert "async with session_scope() as session" in route
    assert "await session.execute(delete_stmt)" in route
    _assert_langflow_context_yield_identity(fixture)
    assert "await db.flush()" in flow_source
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

    audit, transaction, paths = _langflow_fixture_transaction_reports(fixture)
    assert audit.summary.matched_calls == 1
    assert audit.summary.unresolved_calls > 0
    assert transaction.summary.endpoints_with_staging == 0
    assert transaction.summary.pending_persistence == 0
    assert transaction.summary.commit_reachable == 0
    assert transaction.summary.rollback_reachable == 0
    assert transaction.endpoint_evidence == ()
    assert paths.effect_audit_hash == audit.provenance.audit_hash
    assert paths.transaction_report_hash == transaction.report_hash
    assert paths.ordered_paths == ()
    assert paths.context_paths == ()
    assert paths.summary.ordered_paths == 0
    assert paths.summary.context_manager_paths == 0
    assert len(paths.source_projections) == 1
    projection = paths.source_projections[0]
    assert projection.endpoint_id in {
        endpoint.id
        for occurrence in audit.occurrences
        if occurrence.id == projection.unresolved_stage_occurrence_id
        for endpoint in occurrence.endpoints
    }
    assert projection.method_identity == "unresolved"
    assert projection.status == "conditional_source_association"
    assert projection.persistence_status == "not_established"
    assert projection.receiver_expression == "session"
    for path_field, hash_field in (
        (projection.endpoint_file_path, projection.endpoint_source_hash),
        (projection.wrapper_file_path, projection.wrapper_source_hash),
        (
            projection.delegated_wrapper_file_path,
            projection.delegated_wrapper_source_hash,
        ),
    ):
        digest = hashlib.sha256((fixture / path_field).read_bytes()).hexdigest()
        assert hash_field == f"sha256:{digest}"


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
        "from __future__ import annotations\n"
        "from typing import final\n"
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n\n"
        "@final\n"
        "class Session:\n"
        "    def begin(self) -> None: pass\n"
        "    def begin_nested(self) -> None: pass\n"
        "    def add(self, value: str) -> None: pass\n"
        "    def flush(self) -> None: pass\n"
        "    def commit(self) -> None: pass\n"
        "    def rollback(self) -> None: pass\n\n"
        "class Other:\n"
        "    def flush(self) -> None: pass\n\n"
        "@final\n"
        "class AsyncSession:\n"
        "    def begin(self): return self\n"
        "    async def __aenter__(self): return self\n"
        "    async def __aexit__(self, exc_type, exc, tb): pass\n"
        "    async def add(self, value: str) -> None: pass\n\n"
        "class Holder:\n"
        "    def __init__(self) -> None:\n"
        "        self.session = Session()\n\n"
        "@final\n"
        "class UnitOfWork:\n"
        "    def begin(self): return self\n"
        "    def __enter__(self): return self\n"
        "    def __exit__(self, exc_type, exc, tb): return False\n"
        "    def add(self, value: str) -> None: pass\n\n"
        "@final\n"
        "class YieldedUnitOfWork:\n"
        "    def __enter__(self) -> YieldedUnitOfWork: return self\n"
        "    def __exit__(self, exc_type, exc, tb): return False\n"
        "    def add(self, value: str) -> None: pass\n\n"
        "@final\n"
        "class UnitOfWorkFactory:\n"
        "    def begin(self) -> YieldedUnitOfWork: return YieldedUnitOfWork()\n\n"
        "    def untrusted_begin(self) -> YieldedUnitOfWork: return YieldedUnitOfWork()\n\n"
        "class ReceiverlessContext:\n"
        "    def __enter__(self) -> Session: return Session()\n"
        "    def __exit__(self, exc_type, exc, tb): return False\n\n"
        "def begin_context() -> ReceiverlessContext: return ReceiverlessContext()\n\n"
        "def trusted_begin_context() -> ReceiverlessContext: return ReceiverlessContext()\n\n"
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
        "@app.post('/receiverless-captured-context')\n"
        "def receiverless_captured_context() -> None:\n"
        "    with begin_context() as transaction:\n"
        "        transaction.add('unproven')\n\n"
        "@app.post('/trusted-receiverless-captured-context')\n"
        "def trusted_receiverless_captured_context() -> None:\n"
        "    with trusted_begin_context() as transaction:\n"
        "        transaction.add('contracted')\n\n"
        "@app.post('/receiver-shadow-context')\n"
        "def receiver_shadow_context() -> None:\n"
        "    work = UnitOfWorkFactory()\n"
        "    with work.begin() as work:\n"
        "        work.add('shadowed')\n\n"
        "@app.post('/trusted-method-yield-context')\n"
        "def trusted_method_yield_context() -> None:\n"
        "    factory = UnitOfWorkFactory()\n"
        "    with factory.begin() as transaction:\n"
        "        transaction.add('yielded')\n\n"
        "@app.post('/untrusted-method-yield-context')\n"
        "def untrusted_method_yield_context() -> None:\n"
        "    factory = UnitOfWorkFactory()\n"
        "    with factory.untrusted_begin() as transaction:\n"
        "        transaction.add('unproven-yielded')\n\n"
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
                        "symbol": f"main.Session.{operation}",
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
                        "symbol": "main.UnitOfWork.begin",
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
                        "symbol": "main.UnitOfWork.add",
                        "invocation": "instance_method",
                        "operation": "stage",
                        "channel": "sql",
                    },
                    {
                        "id": "yielded-uow-add",
                        "symbol": "main.YieldedUnitOfWork.add",
                        "invocation": "instance_method",
                        "operation": "stage",
                        "channel": "sql",
                    },
                    {
                        "id": "uow-factory-begin",
                        "symbol": "main.UnitOfWorkFactory.begin",
                        "invocation": "instance_method",
                        "operation": "begin",
                        "channel": "sql",
                        "behavior": {
                            "timing": "context_enter",
                            "transaction_scope": "transaction",
                            "context_exit": "transaction_commit_rollback",
                            "stage_receiver_from_yield": True,
                        },
                    },
                    {
                        "id": "uow-factory-untrusted-begin",
                        "symbol": "main.UnitOfWorkFactory.untrusted_begin",
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
                        "id": "receiverless-begin",
                        "symbol": "main.begin_context",
                        "invocation": "function",
                        "operation": "begin",
                        "channel": "sql",
                        "behavior": {
                            "timing": "context_enter",
                            "transaction_scope": "transaction",
                            "context_exit": "transaction_commit_rollback",
                        },
                    },
                    {
                        "id": "trusted-receiverless-begin",
                        "symbol": "main.trusted_begin_context",
                        "invocation": "function",
                        "operation": "begin",
                        "channel": "sql",
                        "behavior": {
                            "timing": "context_enter",
                            "transaction_scope": "transaction",
                            "context_exit": "transaction_commit_rollback",
                            "stage_receiver_from_yield": True,
                        },
                    },
                ]
                + [
                    {
                        "id": f"async-{operation}",
                        "symbol": f"main.AsyncSession.{operation}",
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


@pytest.mark.parametrize(
    "annotation", ["(session := replacement).attr: int", "holder[session := replacement]: int"]
)
def test_annotation_target_evaluation_preserves_receiver_reassignment(annotation: str) -> None:
    source = "def run(session, replacement, holder):\n    " + annotation + "\n    return session\n"
    namespace: dict[str, Any] = {}
    exec(compile(source, "<annotation-target-control>", "exec"), namespace)
    original, replacement = object(), object()
    assert namespace["run"](original, replacement, {}) is replacement
    function = ast.parse(
        "def run():\n    session.add('value')\n    " + annotation + "\n    session.commit()\n"
    ).body[0]
    assert isinstance(function, ast.FunctionDef)
    assert _receiver_reassigned(tuple(function.body), 0, 2, ("session",))


@pytest.mark.parametrize("assign_value", [False, True])
def test_sql_ordering_distinguishes_local_annotation_from_reassignment(
    tmp_path: Path, assign_value: bool
) -> None:
    contracts, diff = _ordered_project(tmp_path)
    source = tmp_path / "main.py"
    text = source.read_text(encoding="utf-8")
    original = "    session.add('ordered')\n    session.flush()\n"
    assert text.count(original) == 1
    annotation = "    session: Session" + (" = Session()" if assign_value else "") + "\n"
    source.write_text(
        text.replace(
            original, "    session.add('ordered')\n" + annotation + "    session.flush()\n"
        ),
        encoding="utf-8",
    )
    report = ChangeMapper(
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
    paths = report.sql_transaction_path_report
    assert paths is not None
    ordered = [path for path in paths.ordered_paths if path.function_name == "ordered"]
    if assign_value:
        assert ordered == []
        assert any(item.reason_code == "receiver_reassigned" for item in paths.diagnostics)
    else:
        assert {path.boundary for path in ordered} == {"flush", "commit"}
        assert all(path.limitations for path in ordered)


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
    _assert_open_receiver_flush_is_unmatched(configured)
    paths = configured.sql_transaction_path_report
    assert paths is not None
    assert paths.schema_version == 6
    assert paths.summary.model_dump() == {
        "ordered_paths": 4,
        "ordered_flushes": 1,
        "ordered_commits": 3,
        "ordered_rollbacks": 0,
        "context_manager_paths": 7,
        "context_transactions": 6,
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
        "trusted_receiverless_captured_context",
        "trusted_method_yield_context",
    }
    assert all(
        item.function_name
        not in {
            "receiverless_captured_context",
            "receiver_shadow_context",
            "untrusted_method_yield_context",
        }
        for item in paths.context_paths
    )
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


def test_savepoint_boundary_target_requires_exact_returned_transaction_binding(
    tmp_path: Path,
) -> None:
    contracts, diff = _savepoint_target_project(tmp_path)
    report = ChangeMapper(
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
    paths = report.sql_transaction_path_report
    assert paths is not None
    target_paths = {
        item.function_name: item
        for item in paths.ordered_paths
        if item.receiver_relation == "returned_transaction"
    }
    assert set(target_paths) == {"nested_target", "nested_target_rollback"}
    assert target_paths["nested_target"].boundary == "commit"
    assert target_paths["nested_target"].boundary_target_scope.value == "savepoint"
    assert target_paths["nested_target_rollback"].boundary == "rollback"
    assert target_paths["nested_target_rollback"].boundary_target_scope.value == "savepoint"
    direct_session_boundary = next(
        item
        for item in paths.ordered_paths
        if item.function_name == "nested" and item.boundary == "commit"
    )
    assert direct_session_boundary.begin_scope.value == "savepoint"
    assert direct_session_boundary.boundary_target_scope.value == "unknown"
    assert not any(
        item.function_name
        in {"nested_rebound_target", "nested_alias_target", "nested_foreign_target"}
        and item.receiver_relation == "returned_transaction"
        for item in paths.ordered_paths
    )
    foreign_call = next(
        item
        for item in report.effect_contract_audit.occurrences
        if item.source_spelling == "foreign.commit"
    )
    assert foreign_call.canonical_symbol == "main.ForeignTransaction.commit"
    assert foreign_call.audit_status.value == "unmatched"
    assert all(item.persistence_status == "not_established" for item in paths.ordered_paths)
    assert report.sql_transaction_report is not None
    assert report.sql_transaction_report.status == "diagnostic_only"
    assert _candidate_projection(report) == _candidate_projection(
        ChangeMapper(
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
    )


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


def test_langflow_13960_real_source_transaction_fixture_is_pinned_and_bounded() -> None:
    """Parse complete pinned upstream snapshots as data; never import or execute them."""
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    provenance = json.loads((fixture / "provenance.json").read_text(encoding="utf-8"))
    _assert_langflow_pinned_snapshots(fixture, provenance)
    _assert_langflow_source_transaction_evidence(fixture, provenance)


@pytest.mark.parametrize(
    ("relative_path", "old", "new"),
    [
        (
            "source/langflow/api/v1/traces.py.txt",
            "from langflow.services.deps import session_scope\n",
            "from langflow.services.deps import session_scope as foreign_scope\n",
        ),
        (
            "source/langflow/api/v1/traces.py.txt",
            "from langflow.services.deps import session_scope\n",
            "from langflow.services.deps import session_scope\nsession_scope = unrelated_scope\n",
        ),
        (
            "source/langflow/api/v1/traces.py.txt",
            "from langflow.services.deps import session_scope\n",
            "from langflow.services.deps import session_scope\nsession_scope += unrelated_scope\n",
        ),
        (
            "source/langflow/api/v1/traces.py.txt",
            "from langflow.services.deps import session_scope\n",
            "from langflow.services.deps import session_scope\ndel session_scope\n",
        ),
        (
            "source/langflow/api/v1/traces.py.txt",
            "from langflow.services.deps import session_scope\n",
            "from langflow.services.deps import session_scope\n"
            "from other.module import session_scope\n",
        ),
        (
            "source/langflow/api/v1/traces.py.txt",
            "from langflow.services.deps import session_scope\n",
            "from langflow.services.deps import session_scope\n"
            "if condition:\n    session_scope = unrelated_scope\n",
        ),
        (
            "source/langflow/api/v1/traces.py.txt",
            "from langflow.services.deps import session_scope\n",
            "from langflow.services.deps import session_scope\n"
            'exec("session_scope = unrelated_scope")\n',
        ),
        (
            "source/langflow/api/v1/traces.py.txt",
            "from langflow.services.deps import session_scope\n",
            "from langflow.services.deps import session_scope\n"
            'globals()["session_scope"] = unrelated_scope\n',
        ),
        (
            "source/langflow/api/v1/traces.py.txt",
            "from langflow.services.deps import session_scope\n",
            "from langflow.services.deps import session_scope\n"
            "globals().update(session_scope=unrelated_scope)\n",
        ),
        (
            "source/langflow/api/v1/traces.py.txt",
            "    try:\n        async with session_scope() as session:\n            flow_stmt",
            "    try:\n        def session_scope(): pass\n"
            "        async with session_scope() as session:\n            flow_stmt",
        ),
        (
            "source/langflow/api/v1/traces.py.txt",
            "async def delete_traces_by_flow(\n",
            "async def delete_traces_by_flow(session_scope,\n",
        ),
        (
            "source/langflow/api/v1/traces.py.txt",
            '    """\n    try:\n'
            "        async with session_scope() as session:\n            flow_stmt",
            '    """\n    session_scope = shadowed_scope\n'
            "    try:\n        async with session_scope() as session:\n            flow_stmt",
        ),
        (
            "source/langflow/api/v1/traces.py.txt",
            "            await session.execute(delete_stmt)",
            "            await session.execute(delete_stmt)\n"
            "        session_scope = shadowed_scope",
        ),
        (
            "source/langflow/services/deps.py.txt",
            "    async with lfx_session_scope() as session:\n        yield session",
            "    lfx_session_scope = shadowed_scope\n"
            "    async with lfx_session_scope() as session:\n        yield session",
        ),
        (
            "source/langflow/api/v1/traces.py.txt",
            "await session.execute(delete_stmt)",
            "await other.execute(delete_stmt)",
        ),
        (
            "source/langflow/api/v1/traces.py.txt",
            "            await session.execute(delete_stmt)",
            "            session = other\n            await session.execute(delete_stmt)",
        ),
        (
            "source/langflow/services/deps.py.txt",
            "        yield session\n",
            "        yield other_session\n",
        ),
        (
            "source/langflow/services/deps.py.txt",
            "        yield session\n",
            "        async def deferred():\n            yield session\n"
            "        yield other_session\n",
        ),
        (
            "source/langflow/services/deps.py.txt",
            "import session_scope as lfx_session_scope",
            "import session_scope as unrelated_delegate",
        ),
        (
            "source/lfx/services/deps.py.txt",
            "await session.commit()",
            "await other_session.commit()",
        ),
        (
            "source/langflow/api/v1/traces.py.txt",
            "            await session.execute(delete_stmt)",
            "        await session.execute(delete_stmt)",
        ),
        (
            "source/langflow/api/v1/traces.py.txt",
            "            await session.execute(delete_stmt)",
            "            pass  # no staged SQL call in the owning context\n",
        ),
        (
            "source/langflow/api/v1/traces.py.txt",
            "from langflow.services.deps import session_scope\n",
            "from langflow.services.deps import session_scope\n"
            "def unused(seed=exec('session_scope = unrelated_scope')):\n    pass\n",
        ),
        (
            "source/langflow/api/v1/traces.py.txt",
            "from langflow.services.deps import session_scope\n",
            "from langflow.services.deps import session_scope\n"
            '@eval("globals().update(session_scope=unrelated_scope) or (lambda f: f)")\n'
            "def unused():\n    pass\n",
        ),
        (
            "source/langflow/api/v1/traces.py.txt",
            "from langflow.services.deps import session_scope\n",
            "from langflow.services.deps import session_scope\n"
            "rebind = exec\nrebind('session_scope = unrelated_scope')\n",
        ),
        (
            "source/langflow/api/v1/traces.py.txt",
            "from langflow.services.deps import session_scope\n",
            "from langflow.services.deps import session_scope\n"
            "import builtins\nbuiltins.exec('session_scope = unrelated_scope')\n",
        ),
        (
            "source/langflow/api/v1/traces.py.txt",
            "from langflow.services.deps import session_scope\n",
            "from langflow.services.deps import session_scope\n"
            "getattr(__builtins__, 'exec')('session_scope = unrelated_scope')\n",
        ),
    ],
    ids=(
        "imported-name-alias",
        "module-rebound-after-import",
        "module-augmented-after-import",
        "module-deleted-after-import",
        "module-duplicate-import",
        "module-control-flow-rebind",
        "module-exec-rebind",
        "module-globals-item-rebind",
        "module-globals-update-rebind",
        "same-name-local-wrapper",
        "wrapper-parameter-shadow",
        "wrapper-local-before-call",
        "wrapper-local-after-call",
        "delegated-alias-local-shadow",
        "different-receiver",
        "receiver-reassigned",
        "yield-unknown",
        "deferred-yield-is-not-outer-receiver",
        "delegated-unknown-alias",
        "delegated-boundary-other-receiver",
        "stage-outside-context",
        "context-unrelated",
        "eager-default-exec",
        "eager-decorator-eval",
        "aliased-exec",
        "builtins-exec",
        "getattr-builtins-exec",
    ),
)
def test_langflow_source_projection_fails_closed_for_unproven_ownership(
    tmp_path: Path, relative_path: str, old: str, new: str
) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    source_path = copied / relative_path
    source = source_path.read_text(encoding="utf-8")
    assert old in source
    source_path.write_text(source.replace(old, new, 1), encoding="utf-8")

    _audit, _transaction, paths = _langflow_fixture_transaction_reports(copied)
    assert paths.source_projections == ()


def test_deferred_dynamic_exec_does_not_rebind_module_wrapper(
    tmp_path: Path,
) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    endpoint = copied / "source/langflow/api/v1/traces.py.txt"
    endpoint.write_text(
        endpoint.read_text(encoding="utf-8")
        + "\ndef unused():\n    exec('session_scope = unrelated_scope')\n",
        encoding="utf-8",
    )

    _audit, _transaction, paths = _langflow_fixture_transaction_reports(copied)
    assert len(paths.source_projections) == 1


@pytest.mark.parametrize("branched", [False, True])
def test_source_projection_rejects_multiple_delegated_contexts(
    tmp_path: Path, branched: bool
) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    source = copied / "source/langflow/services/deps.py.txt"
    old = "    async with lfx_session_scope() as session:\n        yield session"
    replacement = (
        "    if flag:\n"
        "        async with foreign_scope() as session:\n            yield session\n"
        "    else:\n"
        "        async with lfx_session_scope() as session:\n            yield session"
        if branched
        else "    async with foreign_scope() as session:\n        yield session\n" + old
    )
    text = source.read_text()
    assert old in text
    source.write_text(text.replace(old, replacement, 1))
    assert _langflow_fixture_transaction_reports(copied)[2].source_projections == ()


def test_source_projection_uses_imported_delegate_name(tmp_path: Path) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    wrapper = copied / "source/langflow/services/deps.py.txt"
    wrapper.write_text(
        wrapper.read_text().replace(
            "from lfx.services.deps import session_scope as lfx_session_scope",
            "from lfx.services.deps import transaction_scope as lfx_session_scope",
            1,
        )
    )
    delegate = copied / "source/lfx/services/deps.py.txt"
    text = delegate.read_text()
    assert "async def session_scope(" in text
    delegate.write_text(text.replace("async def session_scope(", "async def transaction_scope(", 1))
    assert len(_langflow_fixture_transaction_reports(copied)[2].source_projections) == 1


def test_source_projection_covers_each_shared_handler_route() -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    effects = load_effect_contracts(fixture / "effects.yaml")
    endpoint, sites = _fixture_endpoint_calls(fixture)
    sibling = endpoint.model_copy(update={"path": endpoint.path + "/alias"})
    audit = audit_effect_contracts(
        effects,
        source_root=fixture,
        inventory=EndpointInventory(
            endpoints=[endpoint, sibling], status=InventoryStatus.ESTABLISHED
        ),
        endpoint_call_sites=((endpoint, sites), (sibling, sites)),
        track_transitive=False,
        max_depth=1,
        cache_enabled=False,
        resolver_versions=("pinned_fixture_ast@1",),
    )
    transaction = build_sql_transaction_diagnostics(effects, audit)
    paths = build_sql_transaction_path_diagnostics(
        fixture, audit, transaction, effects, max_pairs=1
    )
    expected_ids = {ref.id for occurrence in audit.occurrences for ref in occurrence.endpoints}
    assert len(expected_ids) == 2
    assert {item.endpoint_id for item in paths.source_projections} == expected_ids
    assert len(paths.source_projections) == 2


def test_source_projection_resolves_relative_wrapper_delegate_import(tmp_path: Path) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    wrapper = copied / "source/langflow/services/deps.py.txt"
    wrapper.write_text(
        wrapper.read_text().replace(
            "from lfx.services.deps import session_scope as lfx_session_scope",
            "from .transaction import session_scope as lfx_session_scope",
            1,
        )
    )
    delegate = copied / "source/lfx/services/deps.py.txt"
    relative_delegate = copied / "source/langflow/services/transaction.py.txt"
    relative_delegate.write_bytes(delegate.read_bytes())
    assert len(_langflow_fixture_transaction_reports(copied)[2].source_projections) == 1


@pytest.mark.parametrize(
    "relative_module, expected", [("...services.deps", 1), (".services.deps", 0)]
)
def test_source_projection_resolves_endpoint_relative_imports_against_its_package(
    tmp_path: Path, relative_module: str, expected: int
) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    source = copied / "source/langflow/api/v1/traces.py.txt"
    source.write_text(
        source.read_text().replace(
            "from langflow.services.deps import session_scope",
            f"from {relative_module} import session_scope",
            1,
        )
    )
    assert len(_langflow_fixture_transaction_reports(copied)[2].source_projections) == expected


def test_source_projection_resolves_relative_package_initializer_export(tmp_path: Path) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    endpoint = copied / "source/langflow/api/v1/traces.py.txt"
    endpoint.write_text(
        endpoint.read_text().replace(
            "from langflow.services.deps import session_scope",
            "from ...services import exported_scope as session_scope",
            1,
        )
    )
    package = copied / "source/langflow/services/__init__.py.txt"
    package.write_text("from .deps import session_scope as exported_scope\n")
    projections = _langflow_fixture_transaction_reports(copied)[2].source_projections
    assert len(projections) == 1
    assert projections[0].endpoint_file_path == "source/langflow/api/v1/traces.py.txt"
    assert projections[0].unresolved_stage_occurrence_id


def test_source_projection_rejects_wrong_package_initializer_export(tmp_path: Path) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    endpoint = copied / "source/langflow/api/v1/traces.py.txt"
    endpoint.write_text(
        endpoint.read_text().replace(
            "from langflow.services.deps import session_scope",
            "from ...services import exported_scope as session_scope",
            1,
        )
    )
    package = copied / "source/langflow/services/__init__.py.txt"
    package.write_text("from .foreign import session_scope as exported_scope\n")
    foreign = copied / "source/langflow/services/foreign.py.txt"
    foreign.write_text("async def session_scope():\n    pass\n")
    assert _langflow_fixture_transaction_reports(copied)[2].source_projections == ()


@pytest.mark.parametrize(
    "initializer",
    [
        "from .deps import session_scope as exported_scope\nexported_scope = foreign_scope\n",
        "from .deps import session_scope as exported_scope\n"
        "exported_scope: object = foreign_scope\n",
        "from .deps import session_scope as exported_scope\nexported_scope += foreign_scope\n",
        "from .deps import session_scope as exported_scope\ndel exported_scope\n",
        "from .deps import session_scope as exported_scope\n"
        "if FLAG:\n    exported_scope = foreign_scope\n",
        "from .deps import session_scope as exported_scope\n"
        "exec('exported_scope = foreign_scope')\n",
    ],
)
def test_source_projection_rejects_rebound_package_initializer_export(
    tmp_path: Path, initializer: str
) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    endpoint = copied / "source/langflow/api/v1/traces.py.txt"
    endpoint.write_text(
        endpoint.read_text().replace(
            "from langflow.services.deps import session_scope",
            "from ...services import exported_scope as session_scope",
            1,
        )
    )
    package = copied / "source/langflow/services/__init__.py.txt"
    package.write_text(initializer)
    assert _langflow_fixture_transaction_reports(copied)[2].source_projections == ()


def test_source_projection_rejects_overridden_package_initializer_definition(
    tmp_path: Path,
) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    endpoint = copied / "source/langflow/api/v1/traces.py.txt"
    endpoint.write_text(
        endpoint.read_text().replace(
            "from langflow.services.deps import session_scope",
            "from ...services import session_scope",
            1,
        )
    )
    package = copied / "source/langflow/services/__init__.py.txt"
    package.write_text("def session_scope():\n    pass\nsession_scope = foreign_scope\n")
    assert _langflow_fixture_transaction_reports(copied)[2].source_projections == ()


@pytest.mark.parametrize("terminator", ["return", "raise RuntimeError()"])
def test_source_projection_rejects_unreachable_endpoint_stage(
    tmp_path: Path, terminator: str
) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    endpoint = copied / "source/langflow/api/v1/traces.py.txt"
    text = endpoint.read_text()
    stage = "            await session.execute(delete_stmt)"
    assert stage in text
    endpoint.write_text(text.replace(stage, f"            {terminator}\n{stage}", 1))
    assert _langflow_fixture_transaction_reports(copied)[2].source_projections == ()


@pytest.mark.parametrize(
    "mutation",
    [
        "contextlib.asynccontextmanager = foreign_factory",
        "del contextlib.asynccontextmanager",
        "contextlib.asynccontextmanager += foreign_factory",
        "factory_owner = contextlib\nfactory_owner.asynccontextmanager = foreign_factory",
        'setattr(contextlib, "asynccontextmanager", foreign_factory)',
    ],
)
def test_source_projection_rejects_mutated_qualified_context_factory(
    tmp_path: Path, mutation: str
) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    wrapper = copied / "source/langflow/services/deps.py.txt"
    text = wrapper.read_text()
    text = text.replace(
        "from contextlib import asynccontextmanager",
        "import contextlib\n" + mutation,
        1,
    ).replace(
        "@asynccontextmanager\nasync def session_scope",
        "@contextlib.asynccontextmanager\nasync def session_scope",
        1,
    )
    wrapper.write_text(text)
    assert _langflow_fixture_transaction_reports(copied)[2].source_projections == ()


def test_source_projection_accepts_qualified_context_factory_and_late_mutation(
    tmp_path: Path,
) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    wrapper = copied / "source/langflow/services/deps.py.txt"
    text = (
        wrapper.read_text()
        .replace(
            "from contextlib import asynccontextmanager",
            "import contextlib",
            1,
        )
        .replace(
            "@asynccontextmanager\nasync def session_scope",
            "@contextlib.asynccontextmanager\nasync def session_scope",
            1,
        )
    )
    wrapper.write_text(text + "\ncontextlib.asynccontextmanager = foreign_factory\n")
    assert len(_langflow_fixture_transaction_reports(copied)[2].source_projections) == 1


def test_source_projection_report_accepts_a_file_application_root(tmp_path: Path) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    app_file = copied / "main.py"
    app_file.write_text("# source-only application entry identity\n", encoding="utf-8")
    audit, transaction, paths = _langflow_fixture_transaction_reports(copied)
    assert paths.source_projections
    report = AnalysisReport.model_validate(
        {
            "app_path": str(app_file),
            "diff_source": "fixture",
            "total_endpoints": 1,
            "effect_contract_audit": audit,
            "sql_transaction_report": transaction,
            "sql_transaction_path_report": paths,
        }
    )
    assert report.sql_transaction_path_report == paths


@pytest.mark.parametrize(
    ("relative_path", "suffix"),
    [
        ("source/langflow/services/deps.py.txt", "\nsession_scope = foreign_scope\n"),
        ("source/langflow/services/deps.py.txt", "\nasync def session_scope():\n    pass\n"),
        ("source/langflow/services/deps.py.txt", "\ndel session_scope\n"),
        ("source/langflow/services/deps.py.txt", '\nexec("session_scope = foreign_scope")\n'),
        ("source/lfx/services/deps.py.txt", "\nsession_scope = foreign_scope\n"),
        ("source/langflow/services/deps.py.txt", "\nfrom foreign import *\n"),
        ("source/lfx/services/deps.py.txt", "\nfrom foreign import *\n"),
        ("source/langflow/api/v1/traces.py.txt", "\nfrom foreign import *\n"),
        (
            "source/langflow/services/deps.py.txt",
            "\nimport sys\nsys.modules[__name__].session_scope = unrelated_scope\n",
        ),
        (
            "source/lfx/services/deps.py.txt",
            "\nimport sys\nsys.modules[__name__].session_scope = unrelated_scope\n",
        ),
        (
            "source/langflow/api/v1/traces.py.txt",
            "\nimport sys\nsys.modules[__name__].session_scope = unrelated_scope\n",
        ),
    ],
)
def test_source_projection_rejects_rebound_wrapper_exports(
    tmp_path: Path, relative_path: str, suffix: str
) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    source = copied / relative_path
    source.write_text(source.read_text() + suffix)
    assert _langflow_fixture_transaction_reports(copied)[2].source_projections == ()


@pytest.mark.parametrize(
    "replacement",
    [
        "yield session\n            session = foreign_session",
        "yield session\n            session += foreign_session",
        "yield session\n            del session",
        "yield session\n            if flag:\n                session = foreign_session",
        "session = foreign_session\n            yield session",
    ],
)
def test_source_projection_rejects_reassigned_delegated_receiver(
    tmp_path: Path, replacement: str
) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    source = copied / "source/lfx/services/deps.py.txt"
    text = source.read_text()
    old = "yield session\n            await session.commit()"
    assert old in text
    source.write_text(text.replace(old, replacement + "\n            await session.commit()", 1))
    assert _langflow_fixture_transaction_reports(copied)[2].source_projections == ()


def test_source_projection_rejects_alternate_wrapper_yields(tmp_path: Path) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    source = copied / "source/langflow/services/deps.py.txt"
    text = source.read_text()
    original = "    async with lfx_session_scope() as session:\n        yield session"
    assert original in text
    replacement = (
        "    if flag:\n        yield other\n    else:\n"
        "        async with lfx_session_scope() as session:\n"
        "            yield session"
    )
    source.write_text(text.replace(original, replacement, 1))
    assert _langflow_fixture_transaction_reports(copied)[2].source_projections == ()


@pytest.mark.parametrize("boundary", ["commit", "rollback"])
def test_source_projection_requires_context_exit_boundaries_after_yield(
    tmp_path: Path, boundary: str
) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    source = copied / "source/lfx/services/deps.py.txt"
    text = source.read_text()
    if boundary == "commit":
        original = "yield session\n            await session.commit()"
        replacement = "await session.commit()\n            yield session"
        assert original in text
        text = text.replace(original, replacement, 1)
    else:
        text = text.replace("await session.rollback()", "pass # rollback removed")
        text = text.replace(
            "yield session", "await session.rollback()\n            yield session", 1
        )
    source.write_text(text)
    assert _langflow_fixture_transaction_reports(copied)[2].source_projections == ()


@pytest.mark.parametrize(
    ("relative_path", "old", "new"),
    [
        (
            "source/lfx/services/deps.py.txt",
            "await session.commit()",
            "session.commit()",
        ),
        (
            "source/lfx/services/deps.py.txt",
            "await session.rollback()",
            "await session.rollback(force=True)",
        ),
        (
            "source/langflow/services/deps.py.txt",
            "@asynccontextmanager\nasync def session_scope()",
            "@replace_with_foreign_scope\n@asynccontextmanager\nasync def session_scope()",
        ),
    ],
)
def test_source_projection_rejects_unexecutable_boundaries_and_replacing_decorators(
    tmp_path: Path, relative_path: str, old: str, new: str
) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    source = copied / relative_path
    text = source.read_text(encoding="utf-8")
    assert old in text
    source.write_text(text.replace(old, new), encoding="utf-8")
    assert _langflow_fixture_transaction_reports(copied)[2].source_projections == ()


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (
            "yield session\n            await session.commit()",
            "yield session\n            raise RuntimeError()\n            await session.commit()",
        ),
        (
            "yield session\n            await session.commit()",
            "yield session\n            if False:\n                await session.commit()",
        ),
    ],
)
def test_source_projection_rejects_unreachable_exit_boundary(
    tmp_path: Path, old: str, new: str
) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    source = copied / "source/lfx/services/deps.py.txt"
    text = source.read_text(encoding="utf-8")
    assert old in text
    source.write_text(text.replace(old, new, 1))
    assert _langflow_fixture_transaction_reports(copied)[2].source_projections == ()


def test_source_projection_resolves_module_scope_delegate_import(tmp_path: Path) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    wrapper = copied / "source/langflow/services/deps.py.txt"
    text = wrapper.read_text(encoding="utf-8")
    line = "    from lfx.services.deps import session_scope as lfx_session_scope\n"
    assert line in text
    wrapper.write_text(
        text.replace(line, "", 1).replace(
            "from contextlib import asynccontextmanager\n",
            "from contextlib import asynccontextmanager\n"
            "from lfx.services.deps import session_scope as lfx_session_scope\n",
            1,
        )
    )
    assert len(_langflow_fixture_transaction_reports(copied)[2].source_projections) == 1


@pytest.mark.parametrize(
    "relative_path",
    [
        "source/langflow/api/v1/traces.py.txt",
        "source/langflow/services/deps.py.txt",
        "source/lfx/services/deps.py.txt",
    ],
)
def test_source_projection_rejects_oversized_snapshots(tmp_path: Path, relative_path: str) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    source = copied / relative_path
    source.write_bytes(source.read_bytes() + b"#" * (2 * 1024 * 1024))
    assert _langflow_fixture_transaction_reports(copied)[2].source_projections == ()


@pytest.mark.parametrize(
    "field",
    [
        "endpoint_id",
        "begin_occurrence_id",
        "unresolved_stage_occurrence_id",
        "endpoint_file_path",
        "receiver_expression",
        "function_name",
        "receiver_hash",
        "endpoint_source_hash",
        "wrapper_file_path",
        "wrapper_source_hash",
        "delegated_wrapper_file_path",
        "delegated_wrapper_source_hash",
    ],
)
def test_resealed_source_projection_must_belong_to_exact_audit(field: str) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    audit, transaction, paths = _langflow_fixture_transaction_reports(fixture)
    valid = {
        "app_path": str(fixture),
        "diff_source": "fixture",
        "total_endpoints": 1,
        "effect_contract_audit": audit,
        "sql_transaction_report": transaction,
        "sql_transaction_path_report": paths,
    }
    AnalysisReport.model_validate(valid)
    for supplied in ((), paths.source_projections[:-1]):
        incomplete = build_sql_transaction_path_report(
            effect_audit_hash=paths.effect_audit_hash,
            transaction_report_hash=paths.transaction_report_hash,
            max_pairs=1,
            ordered_paths=(),
            context_paths=(),
            source_projections=supplied,
            diagnostics=(),
        )
        with pytest.raises(ValidationError, match="SQL source projection"):
            AnalysisReport.model_validate({**valid, "sql_transaction_path_report": incomplete})
    bounded_projection = build_sql_transaction_path_report(
        effect_audit_hash=paths.effect_audit_hash,
        transaction_report_hash=paths.transaction_report_hash,
        max_pairs=1,
        ordered_paths=(),
        context_paths=(),
        source_projections=paths.source_projections,
        diagnostics=(),
    )
    assert bounded_projection.max_pairs == 1
    projection_data = paths.source_projections[0].model_dump(mode="json")
    projection_data[field] = "sha256:" + "f" * 64 if field.endswith(("_id", "_hash")) else "foreign"
    identity = {
        key: value for key, value in projection_data.items() if key not in {"id", "uncertainty"}
    }
    projection_data["id"] = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )
    projection = type(paths.source_projections[0]).model_validate(projection_data)
    resealed = build_sql_transaction_path_report(
        effect_audit_hash=paths.effect_audit_hash,
        transaction_report_hash=paths.transaction_report_hash,
        max_pairs=paths.max_pairs,
        ordered_paths=paths.ordered_paths,
        context_paths=paths.context_paths,
        source_projections=(projection,),
        diagnostics=paths.diagnostics,
    )
    with pytest.raises(ValidationError, match="SQL source projection"):
        AnalysisReport.model_validate({**valid, "sql_transaction_path_report": resealed})


def test_resealed_source_projection_must_preserve_reconstructed_uncertainty() -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    audit, transaction, paths = _langflow_fixture_transaction_reports(fixture)
    projection_data = paths.source_projections[0].model_dump(mode="json")
    projection_data["uncertainty"] = ["persistence established"]
    projection = type(paths.source_projections[0]).model_validate(projection_data)
    resealed = build_sql_transaction_path_report(
        effect_audit_hash=paths.effect_audit_hash,
        transaction_report_hash=paths.transaction_report_hash,
        max_pairs=paths.max_pairs,
        ordered_paths=paths.ordered_paths,
        context_paths=paths.context_paths,
        source_projections=(projection,),
        diagnostics=paths.diagnostics,
    )
    with pytest.raises(ValidationError, match="SQL source projection"):
        AnalysisReport.model_validate(
            {
                "app_path": str(fixture),
                "diff_source": "fixture",
                "total_endpoints": 1,
                "effect_contract_audit": audit,
                "sql_transaction_report": transaction,
                "sql_transaction_path_report": resealed,
            }
        )


def test_source_projection_requires_unchanged_supplied_snapshots(tmp_path: Path) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    audit, transaction, paths = _langflow_fixture_transaction_reports(copied)
    valid = {
        "app_path": str(copied),
        "diff_source": "fixture",
        "total_endpoints": 1,
        "effect_contract_audit": audit,
        "sql_transaction_report": transaction,
        "sql_transaction_path_report": paths,
    }
    validated = AnalysisReport.model_validate(valid)
    for output_format in ("text", "markdown", "html"):
        rendered = get_formatter(output_format).format(validated)
        plain = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", rendered)
        assert "1 source projections" in " ".join(plain.lower().split())
    projection = paths.source_projections[0]
    for relative_path in (
        projection.endpoint_file_path,
        projection.wrapper_file_path,
        projection.delegated_wrapper_file_path,
    ):
        source = copied / relative_path
        original = source.read_bytes()
        source.write_bytes(original + b"\n# changed snapshot bytes\n")
        with pytest.raises(ValidationError, match="SQL source projection"):
            AnalysisReport.model_validate(valid)
        source.write_bytes(original)
    source = copied / projection.delegated_wrapper_file_path
    source.unlink()
    with pytest.raises(ValidationError, match="SQL source projection"):
        AnalysisReport.model_validate(valid)


def test_oversized_projection_snapshot_is_rejected_before_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source" / "wrapper.py.txt"
    source.parent.mkdir()
    with source.open("wb") as stream:
        stream.truncate(2 * 1024 * 1024 + 1)
    original_open = Path.open

    def guarded_open(path: Path, *args: Any, **kwargs: Any) -> Any:
        if path == source:
            raise AssertionError("oversized snapshot must not be read")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)
    assert _module_snapshot(tmp_path, "wrapper") is None


@pytest.mark.parametrize(
    "relative_path",
    [
        "source/langflow/services/deps.py.txt",
        "source/lfx/services/deps.py.txt",
    ],
)
def test_source_projection_rejects_relative_contextlib_decorator(
    tmp_path: Path, relative_path: str
) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    source = copied / relative_path
    text = source.read_text()
    assert "from contextlib import asynccontextmanager" in text
    source.write_text(
        text.replace(
            "from contextlib import asynccontextmanager",
            "from .contextlib import asynccontextmanager",
        )
    )
    assert _langflow_fixture_transaction_reports(copied)[2].source_projections == ()


def test_source_projection_rejects_contextlib_import_after_definition(tmp_path: Path) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    source = copied / "source/lfx/services/deps.py.txt"
    text = source.read_text()
    import_line = "from contextlib import asynccontextmanager, suppress\n"
    assert text.count(import_line) == 1
    source.write_text(text.replace(import_line, "", 1) + "\n" + import_line)
    assert _langflow_fixture_transaction_reports(copied)[2].source_projections == ()


def test_source_projection_rejects_delegate_import_after_async_with(tmp_path: Path) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    source = copied / "source/langflow/services/deps.py.txt"
    text = source.read_text()
    import_line = "    from lfx.services.deps import session_scope as lfx_session_scope\n\n"
    use_line = "    async with lfx_session_scope() as session:\n"
    assert text.count(import_line) == 1 and text.count(use_line) == 1
    text = text.replace(import_line, "", 1)
    text = text.replace(use_line, use_line + import_line, 1)
    source.write_text(text)
    assert _langflow_fixture_transaction_reports(copied)[2].source_projections == ()


def test_source_projection_rejects_rollback_in_nested_handler(tmp_path: Path) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    source = copied / "source/lfx/services/deps.py.txt"
    text = source.read_text()
    old = "                    await session.rollback()"
    assert text.count(old) == 2
    source.write_text(
        text.replace(
            old,
            "                    try:\n"
            "                        pass\n"
            "                    except Exception:\n"
            "                        await session.rollback()",
        )
    )
    assert _langflow_fixture_transaction_reports(copied)[2].source_projections == ()


@pytest.mark.parametrize(
    "relative_path",
    [
        "source/langflow/services/deps.py.txt",
        "source/lfx/services/deps.py.txt",
    ],
)
def test_source_projection_loads_package_initializer_snapshot(
    tmp_path: Path, relative_path: str
) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    source = copied / relative_path
    package = source.parent / source.name.removesuffix(".py.txt") / "__init__.py.txt"
    package.parent.mkdir()
    source.rename(package)
    projections = _langflow_fixture_transaction_reports(copied)[2].source_projections
    assert len(projections) == 1
    assert package.relative_to(copied).as_posix() in {
        projections[0].wrapper_file_path,
        projections[0].delegated_wrapper_file_path,
    }
    source.write_bytes(package.read_bytes())
    assert _langflow_fixture_transaction_reports(copied)[2].source_projections == ()


@pytest.mark.parametrize(
    "relative_path",
    [
        "source/langflow/services/deps.py.txt",
        "source/lfx/services/deps.py.txt",
        "source/langflow/api/v1/traces.py.txt",
    ],
)
@pytest.mark.parametrize("accessor", ["globals", "locals", "vars"])
def test_source_projection_rejects_namespace_accessor_alias(
    tmp_path: Path, relative_path: str, accessor: str
) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    source = copied / relative_path
    source.write_text(
        source.read_text()
        + (
            f"\nnamespace = {accessor}\nforwarded = namespace\n"
            'forwarded()["session_scope"] = unrelated_scope\n'
        )
    )
    assert _langflow_fixture_transaction_reports(copied)[2].source_projections == ()


@pytest.mark.parametrize(
    ("suffix", "expected"),
    [
        ("return", 0),
        ("raise RuntimeError()", 0),
        (
            "if other:\n                    return\n"
            "                else:\n                    return",
            0,
        ),
        ("if other:\n                    return", 1),
        ("pass", 1),
    ],
)
def test_source_projection_checks_yield_branch_fallthrough(
    tmp_path: Path, suffix: str, expected: int
) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    source = copied / "source/lfx/services/deps.py.txt"
    original = "yield session\n            await session.commit()"
    replacement = (
        "if flag:\n                yield session\n                "
        + suffix
        + "\n            await session.commit()"
    )
    text = source.read_text()
    assert original in text
    source.write_text(text.replace(original, replacement, 1))
    assert len(_langflow_fixture_transaction_reports(copied)[2].source_projections) == expected


def test_source_projection_yield_and_boundary_in_opposite_arms_are_disconnected() -> None:
    tree = ast.parse(
        "async def wrapper():\n"
        "    try:\n"
        "        if flag:\n"
        "            yield session\n"
        "        else:\n"
        "            await session.commit()\n"
        "    except Exception:\n"
        "        await session.rollback()\n"
    )
    function = tree.body[0]
    yielded = next(item for item in ast.walk(function) if isinstance(item, ast.Yield))
    boundary = next(
        item
        for item in ast.walk(function)
        if isinstance(item, ast.Call)
        and isinstance(item.func, ast.Attribute)
        and item.func.attr == "commit"
    )
    assert not _yield_can_reach_normal_boundary(yielded, boundary, _scope_parents(function))


@pytest.mark.parametrize(
    "relative_path",
    [
        "source/langflow/services/deps.py.txt",
        "source/lfx/services/deps.py.txt",
        "source/langflow/api/v1/traces.py.txt",
    ],
)
@pytest.mark.parametrize(
    "mutation",
    [
        'import sys\ndelattr(sys.modules[__name__], "session_scope")',
        "import sys\nremove = delattr\nforwarded = remove\n"
        'forwarded(sys.modules[__name__], "session_scope")',
        "import sys\nfrom builtins import delattr as remove\n"
        'remove(sys.modules[__name__], "session_scope")',
        'import sys\nimport builtins\nbuiltins.delattr(sys.modules[__name__], "session_scope")',
    ],
)
def test_source_projection_rejects_reflective_deletion(
    tmp_path: Path, relative_path: str, mutation: str
) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    source = copied / relative_path
    source.write_text(source.read_text() + "\n" + mutation + "\n")
    assert _langflow_fixture_transaction_reports(copied)[2].source_projections == ()


@pytest.mark.parametrize("prefix", ["return", "raise RuntimeError()", "pass"])
def test_source_projection_checks_wrapper_yield_reachability(tmp_path: Path, prefix: str) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    source = copied / "source/langflow/services/deps.py.txt"
    text = source.read_text()
    original = "        yield session"
    assert text.count(original) == 1
    source.write_text(text.replace(original, f"        {prefix}\n" + original, 1))
    assert len(_langflow_fixture_transaction_reports(copied)[2].source_projections) == (
        1 if prefix == "pass" else 0
    )


@pytest.mark.parametrize(
    ("replacement", "expected"),
    [
        (
            "if flag:\n                yield session\n"
            "            else:\n                await session.commit()",
            0,
        ),
        (
            "if flag:\n                yield session\n                await session.commit()",
            1,
        ),
        (
            "if flag:\n                yield session\n            await session.commit()",
            1,
        ),
    ],
)
def test_source_projection_requires_compatible_commit_branch(
    tmp_path: Path, replacement: str, expected: int
) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    source = copied / "source/lfx/services/deps.py.txt"
    text = source.read_text()
    original = "yield session\n            await session.commit()"
    assert original in text
    source.write_text(text.replace(original, replacement, 1))
    assert len(_langflow_fixture_transaction_reports(copied)[2].source_projections) == expected


@pytest.mark.parametrize(
    ("before_commit", "expected"),
    [
        (
            "if flag:\n                return\n"
            "            else:\n                return\n            ",
            0,
        ),
        ("if flag:\n                return\n            ", 1),
    ],
)
def test_source_projection_checks_compound_transfer_before_commit(
    tmp_path: Path, before_commit: str, expected: int
) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    source = copied / "source/lfx/services/deps.py.txt"
    text = source.read_text()
    original = "            yield session\n            await session.commit()"
    assert text.count(original) == 1
    replacement = (
        "            yield session\n            " + before_commit + "await session.commit()"
    )
    source.write_text(text.replace(original, replacement, 1))
    assert len(_langflow_fixture_transaction_reports(copied)[2].source_projections) == expected


@pytest.mark.parametrize(
    ("delegate_signature", "delegate_call", "expected"),
    [
        ("(*, unexpected: bool = False)", "()", 1),
        ("(*, unexpected: bool = False)", "(unexpected=True)", 0),
        ("(*, unexpected: bool)", "()", 0),
    ],
)
def test_source_projection_checks_zero_argument_delegate_binding(
    tmp_path: Path, delegate_signature: str, delegate_call: str, expected: int
) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    delegate = copied / "source/lfx/services/deps.py.txt"
    delegate_text = delegate.read_text()
    signature = "async def session_scope() -> AsyncGenerator[AsyncSession, None]:"
    assert delegate_text.count(signature) == 1
    delegate.write_text(
        delegate_text.replace(
            signature,
            "async def session_scope"
            + delegate_signature
            + " -> AsyncGenerator[AsyncSession, None]:",
            1,
        )
    )
    wrapper = copied / "source/langflow/services/deps.py.txt"
    wrapper_text = wrapper.read_text()
    original = "async with lfx_session_scope() as session:"
    assert wrapper_text.count(original) == 1
    wrapper.write_text(
        wrapper_text.replace(
            original,
            "async with lfx_session_scope" + delegate_call + " as session:",
            1,
        )
    )
    assert len(_langflow_fixture_transaction_reports(copied)[2].source_projections) == expected


def test_source_projection_rejects_sync_asynccontextmanager_delegate(tmp_path: Path) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    source = copied / "source/lfx/services/deps.py.txt"
    text = source.read_text(encoding="utf-8")
    signature = "async def session_scope() -> AsyncGenerator[AsyncSession, None]:"
    assert text.count(signature) == 1
    text = text.replace(signature, "def session_scope() -> AsyncGenerator[AsyncSession, None]:", 1)
    text = text.replace(
        "async with db_service._with_session() as session:",
        "with db_service._with_session() as session:",
        1,
    )
    text = text.replace("await session.commit()", "session.commit()")
    text = text.replace("await session.rollback()", "session.rollback()")
    text = text.replace("await logger.aexception(", "logger.aexception(")
    source.write_text(text, encoding="utf-8")
    assert len(_langflow_fixture_transaction_reports(copied)[2].source_projections) == 0


def test_source_projection_rejects_invalid_endpoint_wrapper_arguments(tmp_path: Path) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    endpoint = copied / "source/langflow/api/v1/traces.py.txt"
    text = endpoint.read_text(encoding="utf-8")
    original = "async with session_scope() as session:\n            flow_stmt ="
    assert text.count(original) == 1
    endpoint.write_text(
        text.replace(
            original,
            "async with session_scope(unexpected=True) as session:\n            flow_stmt =",
            1,
        ),
        encoding="utf-8",
    )
    assert len(_langflow_fixture_transaction_reports(copied)[2].source_projections) == 0


@pytest.mark.parametrize("call_arguments", ["", "label='configured'"])
def test_source_projection_accepts_async_wrapper_default_arguments(
    tmp_path: Path, call_arguments: str
) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    wrapper = copied / "source/langflow/services/deps.py.txt"
    wrapper_text = wrapper.read_text(encoding="utf-8")
    signature = "async def session_scope() -> AsyncGenerator[AsyncSession, None]:"
    assert wrapper_text.count(signature) == 1
    wrapper.write_text(
        wrapper_text.replace(
            signature,
            "async def session_scope(*, label: str = 'default') -> "
            "AsyncGenerator[AsyncSession, None]:",
            1,
        ),
        encoding="utf-8",
    )
    if call_arguments:
        endpoint = copied / "source/langflow/api/v1/traces.py.txt"
        endpoint_text = endpoint.read_text(encoding="utf-8")
        original = "async with session_scope() as session:\n            flow_stmt ="
        assert endpoint_text.count(original) == 1
        endpoint.write_text(
            endpoint_text.replace(
                original,
                f"async with session_scope({call_arguments}) as session:\n            flow_stmt =",
                1,
            ),
            encoding="utf-8",
        )
    assert len(_langflow_fixture_transaction_reports(copied)[2].source_projections) == 1


@pytest.mark.parametrize(
    "relative_path",
    [
        "source/langflow/services/deps.py.txt",
        "source/lfx/services/deps.py.txt",
        "source/langflow/api/v1/traces.py.txt",
    ],
)
@pytest.mark.parametrize(
    "mutation",
    [
        "import sys\n"
        "import builtins\n"
        'builtins.setattr(sys.modules[__name__], "session_scope", foreign)',
        "import sys\n"
        "import builtins as reflected\n"
        'reflected.setattr(sys.modules[__name__], "session_scope", foreign)',
        "import sys\n"
        "from builtins import setattr as replace_binding\n"
        'replace_binding(sys.modules[__name__], "session_scope", foreign)',
        "import sys\n"
        "replace_binding = setattr\n"
        "forwarded = replace_binding\n"
        'forwarded(sys.modules[__name__], "session_scope", foreign)',
    ],
)
def test_source_projection_rejects_qualified_reflective_rebinding(
    tmp_path: Path, relative_path: str, mutation: str
) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    source = copied / relative_path
    source.write_text(source.read_text() + "\n" + mutation + "\n")
    assert _langflow_fixture_transaction_reports(copied)[2].source_projections == ()


@pytest.mark.parametrize(
    ("replacement", "expected"),
    [
        (
            "match flag:\n"
            "                case 1:\n"
            "                    yield session\n"
            "                case 2:\n"
            "                    await session.commit()",
            0,
        ),
        (
            "match flag:\n"
            "                case 1:\n"
            "                    yield session\n"
            "                    await session.commit()",
            1,
        ),
        (
            "match flag:\n"
            "                case 1:\n"
            "                    yield session\n"
            "            await session.commit()",
            1,
        ),
    ],
)
def test_source_projection_requires_compatible_match_case(
    tmp_path: Path, replacement: str, expected: int
) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    source = copied / "source/lfx/services/deps.py.txt"
    text = source.read_text()
    original = "yield session\n            await session.commit()"
    assert original in text
    source.write_text(text.replace(original, replacement, 1))
    assert len(_langflow_fixture_transaction_reports(copied)[2].source_projections) == expected


@pytest.mark.parametrize(
    ("guard", "expected"),
    [
        ("0", 0),
        ("0.0", 0),
        ("''", 0),
        ("b''", 0),
        ("None", 0),
        ("1", 1),
        ("'nonempty'", 1),
    ],
)
@pytest.mark.parametrize(
    "relative_path",
    [
        "source/langflow/services/deps.py.txt",
        "source/lfx/services/deps.py.txt",
    ],
)
def test_source_projection_uses_constant_guard_truthiness(
    tmp_path: Path, relative_path: str, guard: str, expected: int
) -> None:
    fixture = Path(__file__).parents[1] / "fixtures/sql_transactions/langflow_13960"
    copied = tmp_path / "fixture"
    shutil.copytree(fixture, copied)
    source = copied / relative_path
    text = source.read_text()
    tree = ast.parse(text)
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "session_scope"
    )
    context = next(node for node in function.body if isinstance(node, ast.AsyncWith))
    assert context.end_lineno is not None
    lines = text.splitlines(keepends=True)
    start, end = context.lineno - 1, context.end_lineno
    indentation = " " * context.col_offset
    lines[start:end] = [
        indentation + f"if {guard}:\n",
        *["    " + line for line in lines[start:end]],
    ]
    source.write_text("".join(lines))
    # Conditional wrapper contexts remain outside the supported direct
    # passthrough form, including a truthy guard. Delegate guards retain
    # their compatible normal-boundary paths.
    if relative_path == "source/langflow/services/deps.py.txt":
        expected = 0
    assert len(_langflow_fixture_transaction_reports(copied)[2].source_projections) == expected
