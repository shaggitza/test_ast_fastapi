"""Strict SQL transaction diagnostic model tests."""

import pytest
from pydantic import ValidationError

from fastapi_endpoint_detector.models.effect_contract import (
    ContextExitSemantics,
    EffectTiming,
    TransactionScope,
)
from fastapi_endpoint_detector.models.sql_transaction import (
    SQLTransactionBeginScopeEvidence,
    SQLTransactionContextPath,
    SQLTransactionEndpointEvidence,
    SQLTransactionOrderedPath,
    SQLTransactionOutcome,
    SQLTransactionPathReport,
    build_sql_transaction_context_path,
    build_sql_transaction_ordered_path,
    build_sql_transaction_path_report,
    build_sql_transaction_report,
)

_HASH_A = f"sha256:{'a' * 64}"
_HASH_B = f"sha256:{'b' * 64}"
_HASH_C = f"sha256:{'c' * 64}"
_HASH_D = f"sha256:{'d' * 64}"


def test_outcome_is_derived_from_reachable_boundaries() -> None:
    pending = SQLTransactionEndpointEvidence(
        endpoint_id=_HASH_A,
        stage_occurrence_ids=(_HASH_B,),
        outcome=SQLTransactionOutcome.PENDING_PERSISTENCE,
        limitations=("ordering unavailable",),
    )
    committed = SQLTransactionEndpointEvidence(
        endpoint_id=_HASH_B,
        stage_occurrence_ids=(_HASH_A,),
        commit_occurrence_ids=(_HASH_C,),
        outcome=SQLTransactionOutcome.COMMIT_REACHABLE,
        limitations=("ordering unavailable",),
    )

    report = build_sql_transaction_report(_HASH_C, (committed, pending))

    assert [item.endpoint_id for item in report.endpoint_evidence] == [_HASH_A, _HASH_B]
    assert report.summary.pending_persistence == 1
    assert report.summary.commit_reachable == 1
    assert all(item.persistence_status == "not_established" for item in report.endpoint_evidence)


def test_begin_scope_records_are_exact_and_complete() -> None:
    evidence = SQLTransactionEndpointEvidence(
        endpoint_id=_HASH_A,
        stage_occurrence_ids=(_HASH_B,),
        begin_occurrence_ids=(_HASH_C,),
        begin_scopes=(
            SQLTransactionBeginScopeEvidence(
                occurrence_id=_HASH_C,
                scope=TransactionScope.SAVEPOINT,
                timing=EffectTiming.CONTEXT_ENTER,
                context_exit=ContextExitSemantics.SAVEPOINT_RELEASE_ROLLBACK,
            ),
        ),
        outcome=SQLTransactionOutcome.PENDING_PERSISTENCE,
        limitations=("ordering unavailable",),
    )

    assert evidence.begin_scopes[0].scope == TransactionScope.SAVEPOINT
    payload = evidence.model_dump(mode="json")
    payload["begin_scopes"] = []
    with pytest.raises(ValidationError, match="every begin occurrence"):
        SQLTransactionEndpointEvidence.model_validate(payload)


def test_roles_and_outcomes_fail_closed() -> None:
    with pytest.raises(ValidationError, match="roles must be disjoint"):
        SQLTransactionEndpointEvidence(
            endpoint_id=_HASH_A,
            stage_occurrence_ids=(_HASH_B,),
            commit_occurrence_ids=(_HASH_B,),
            outcome=SQLTransactionOutcome.COMMIT_REACHABLE,
            limitations=("ordering unavailable",),
        )
    with pytest.raises(ValidationError, match="outcome does not match"):
        SQLTransactionEndpointEvidence(
            endpoint_id=_HASH_A,
            stage_occurrence_ids=(_HASH_B,),
            outcome=SQLTransactionOutcome.COMMIT_REACHABLE,
            limitations=("ordering unavailable",),
        )


def test_context_paths_preserve_both_conditional_exit_outcomes() -> None:
    path = build_sql_transaction_context_path(
        endpoint_id=_HASH_A,
        file_path="main.py",
        function_name="handler",
        receiver_hash=_HASH_B,
        begin_occurrence_id=_HASH_C,
        begin_scope=TransactionScope.TRANSACTION,
        context_exit=ContextExitSemantics.TRANSACTION_COMMIT_ROLLBACK,
        stage_occurrence_id=_HASH_D,
        limitations=("conditional exit only",),
    )

    assert path.normal_exit == "commit_reachable"
    assert path.exceptional_exit == "rollback_reachable"
    assert path.persistence_status == "not_established"
    payload = path.model_dump(mode="json")
    payload["normal_exit"] = "savepoint_release_reachable"
    with pytest.raises(ValidationError, match="declared scope"):
        SQLTransactionContextPath.model_validate(payload)


def test_ordered_paths_are_content_addressed_and_bounded() -> None:
    path = build_sql_transaction_ordered_path(
        endpoint_id=_HASH_A,
        file_path="main.py",
        function_name="handler",
        receiver_hash=_HASH_B,
        begin_occurrence_id=_HASH_C,
        begin_scope=TransactionScope.TRANSACTION,
        stage_occurrence_id=_HASH_B,
        boundary_occurrence_id=_HASH_D,
        boundary="commit",
        limitations=("lexical ordering only",),
    )
    report = build_sql_transaction_path_report(
        _HASH_A,
        _HASH_B,
        (path,),
        (),
        max_pairs=4,
    )

    assert report.summary.ordered_commits == 1
    assert report.max_pairs == 4
    payload = report.model_dump(mode="json")
    payload["ordered_paths"][0]["function_name"] = "forged"
    with pytest.raises(ValidationError, match="path id"):
        SQLTransactionPathReport.model_validate(payload)

    path_payload = path.model_dump(mode="json")
    path_payload["stage_occurrence_id"] = _HASH_D
    with pytest.raises(ValidationError):
        SQLTransactionOrderedPath.model_validate(path_payload)
