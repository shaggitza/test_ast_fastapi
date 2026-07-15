"""Strict SQL transaction diagnostic model tests."""

import pytest
from pydantic import ValidationError

from fastapi_endpoint_detector.models.sql_transaction import (
    SQLTransactionEndpointEvidence,
    SQLTransactionOutcome,
    build_sql_transaction_report,
)

_HASH_A = f"sha256:{'a' * 64}"
_HASH_B = f"sha256:{'b' * 64}"
_HASH_C = f"sha256:{'c' * 64}"


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
