"""Conservative SQL stage/flush/transaction boundary aggregation."""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

from fastapi_endpoint_detector.models.effect_contract import (
    EffectChannel,
    EffectOperation,
    TransactionScope,
)
from fastapi_endpoint_detector.models.sql_transaction import (
    SQLTransactionBeginScopeEvidence,
    SQLTransactionEndpointEvidence,
    SQLTransactionOutcome,
    SQLTransactionReport,
    build_sql_transaction_report,
)

if TYPE_CHECKING:
    from fastapi_endpoint_detector.models.effect_contract import LoadedEffectContracts
    from fastapi_endpoint_detector.models.effect_contract_audit import EffectContractAudit

_RELEVANT_OPERATIONS = {
    EffectOperation.STAGE,
    EffectOperation.FLUSH,
    EffectOperation.BEGIN,
    EffectOperation.COMMIT,
    EffectOperation.ROLLBACK,
}


def build_sql_transaction_diagnostics(
    effects: LoadedEffectContracts,
    audit: EffectContractAudit,
) -> SQLTransactionReport:
    """Aggregate endpoint-reachable SQL boundaries without inventing path ordering."""
    contract_by_id = {contract.id: contract for contract in effects.document.contracts}
    by_endpoint: dict[str, dict[EffectOperation, set[str]]] = defaultdict(lambda: defaultdict(set))
    begin_scopes: dict[str, dict[str, SQLTransactionBeginScopeEvidence]] = defaultdict(dict)
    for occurrence in audit.occurrences:
        if occurrence.contract_id is None:
            continue
        contract = contract_by_id[occurrence.contract_id]
        if contract.channel != EffectChannel.SQL or contract.operation not in _RELEVANT_OPERATIONS:
            continue
        for endpoint in occurrence.endpoints:
            by_endpoint[endpoint.id][contract.operation].add(occurrence.id)
            if contract.operation == EffectOperation.BEGIN:
                begin_scopes[endpoint.id][occurrence.id] = SQLTransactionBeginScopeEvidence(
                    occurrence_id=occurrence.id,
                    scope=contract.behavior.transaction_scope or TransactionScope.NONE,
                    timing=contract.behavior.timing,
                    context_exit=contract.behavior.context_exit,
                )

    evidence = []
    for endpoint_id in sorted(by_endpoint):
        operations = by_endpoint[endpoint_id]
        stages = tuple(sorted(operations[EffectOperation.STAGE]))
        if not stages:
            continue
        commits = tuple(sorted(operations[EffectOperation.COMMIT]))
        rollbacks = tuple(sorted(operations[EffectOperation.ROLLBACK]))
        outcome = (
            SQLTransactionOutcome.OUTCOME_UNRESOLVED
            if commits and rollbacks
            else SQLTransactionOutcome.COMMIT_REACHABLE
            if commits
            else SQLTransactionOutcome.ROLLBACK_REACHABLE
            if rollbacks
            else SQLTransactionOutcome.PENDING_PERSISTENCE
        )
        evidence.append(
            SQLTransactionEndpointEvidence(
                endpoint_id=endpoint_id,
                stage_occurrence_ids=stages,
                flush_occurrence_ids=tuple(sorted(operations[EffectOperation.FLUSH])),
                begin_occurrence_ids=tuple(sorted(operations[EffectOperation.BEGIN])),
                begin_scopes=tuple(
                    begin_scopes[endpoint_id][item]
                    for item in sorted(operations[EffectOperation.BEGIN])
                ),
                commit_occurrence_ids=commits,
                rollback_occurrence_ids=rollbacks,
                outcome=outcome,
                limitations=(
                    "Calls are endpoint-reachable declarations; branch ordering, exception "
                    "paths, runtime execution, and transaction identity are not established.",
                    "Flush remains pending persistence; commit reachability is not proof of a "
                    "durable write.",
                    "Transaction diagnostics never create or promote endpoint candidates.",
                ),
            )
        )
    return build_sql_transaction_report(audit.provenance.audit_hash, tuple(evidence))
