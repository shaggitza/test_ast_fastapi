"""Deterministic report-only coupling over exact finite effect occurrences."""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

from fastapi_endpoint_detector.models.effect_contract import (
    EffectChannel,
    EffectOperation,
    FiniteValueStatus,
)
from fastapi_endpoint_detector.models.resource_coupling import (
    CouplingStrength,
    LoadedResourceCoupling,
    ResourceCouplingDiagnostic,
    ResourceCouplingEdge,
    ResourceCouplingError,
    ResourceCouplingGraph,
    ResourceCouplingGroupEvidence,
    semantic_hash,
)

if TYPE_CHECKING:
    from fastapi_endpoint_detector.models.effect_contract import (
        EffectContract,
        LoadedEffectContracts,
    )
    from fastapi_endpoint_detector.models.effect_contract_audit import (
        EffectContractAudit,
        EffectContractAuditOccurrence,
    )
    from fastapi_endpoint_detector.models.resource_coupling import ResourceCouplingGroup

_PRODUCER_OPERATIONS = {
    EffectOperation.WRITE,
    EffectOperation.UPDATE,
    EffectOperation.DELETE,
    EffectOperation.APPEND,
}
_CONSUMER_OPERATIONS = {EffectOperation.READ}


def _group_evidence(
    group: ResourceCouplingGroup,
    channel: EffectChannel,
) -> ResourceCouplingGroupEvidence:
    resource_space_hash = semantic_hash(
        {"schema_version": 1, "kind": "resource_space", "value": group.resource_space}
    )
    group_hash = semantic_hash(
        {
            "id": group.id,
            "resource_space_hash": resource_space_hash,
            "channel": channel,
            "producer_contract_ids": group.producer_contract_ids,
            "consumer_contract_ids": group.consumer_contract_ids,
        }
    )
    return ResourceCouplingGroupEvidence(
        id=group.id,
        group_hash=group_hash,
        resource_space_hash=resource_space_hash,
        channel=channel,
        producer_contract_ids=group.producer_contract_ids,
        consumer_contract_ids=group.consumer_contract_ids,
    )


def _eligible_occurrences(
    audit: EffectContractAudit,
) -> dict[str, list[EffectContractAuditOccurrence]]:
    result: dict[str, list[EffectContractAuditOccurrence]] = defaultdict(list)
    for occurrence in audit.occurrences:
        identity = occurrence.resource_identity
        if occurrence.contract_id is None or identity is None:
            continue
        if identity.status == FiniteValueStatus.UNAVAILABLE:
            continue
        result[occurrence.contract_id].append(occurrence)
    return result


def build_resource_coupling_graph(  # noqa: PLR0912, PLR0915
    loaded: LoadedResourceCoupling,
    effects: LoadedEffectContracts,
    audit: EffectContractAudit,
) -> ResourceCouplingGraph:
    """Build a namespace-qualified graph without changing candidate reachability."""
    contract_by_id = {contract.id: contract for contract in effects.document.contracts}
    occurrences = _eligible_occurrences(audit)
    groups: list[ResourceCouplingGroupEvidence] = []
    edges: list[ResourceCouplingEdge] = []
    diagnostics: list[ResourceCouplingDiagnostic] = []

    for configured_group in loaded.document.groups:
        producers: list[tuple[EffectContract, EffectContractAuditOccurrence]] = []
        consumers: list[tuple[EffectContract, EffectContractAuditOccurrence]] = []
        channels = set()
        for contract_id in configured_group.producer_contract_ids:
            contract = contract_by_id.get(contract_id)
            if contract is None:
                raise ResourceCouplingError(
                    f"coupling group {configured_group.id!r} references unknown producer "
                    f"contract {contract_id!r}"
                )
            if contract.operation not in _PRODUCER_OPERATIONS:
                raise ResourceCouplingError(
                    f"coupling producer {contract_id!r} has unsupported operation "
                    f"{contract.operation.value!r}"
                )
            channels.add(contract.channel)
            producers.extend((contract, item) for item in occurrences.get(contract_id, ()))
        for contract_id in configured_group.consumer_contract_ids:
            contract = contract_by_id.get(contract_id)
            if contract is None:
                raise ResourceCouplingError(
                    f"coupling group {configured_group.id!r} references unknown consumer "
                    f"contract {contract_id!r}"
                )
            if contract.operation not in _CONSUMER_OPERATIONS:
                raise ResourceCouplingError(
                    f"coupling consumer {contract_id!r} has unsupported operation "
                    f"{contract.operation.value!r}"
                )
            channels.add(contract.channel)
            consumers.extend((contract, item) for item in occurrences.get(contract_id, ()))
        if len(channels) != 1:
            raise ResourceCouplingError(
                f"coupling group {configured_group.id!r} must use exactly one channel"
            )
        channel = next(iter(channels))
        group = _group_evidence(configured_group, channel)
        groups.append(group)

        by_resource: dict[
            str,
            tuple[
                list[tuple[EffectContract, EffectContractAuditOccurrence]],
                list[tuple[EffectContract, EffectContractAuditOccurrence]],
            ],
        ] = defaultdict(lambda: ([], []))
        for contract, occurrence in producers:
            assert occurrence.resource_identity is not None
            for value_hash in occurrence.resource_identity.value_hashes:
                by_resource[value_hash][0].append((contract, occurrence))
        for contract, occurrence in consumers:
            assert occurrence.resource_identity is not None
            for value_hash in occurrence.resource_identity.value_hashes:
                by_resource[value_hash][1].append((contract, occurrence))

        for value_hash in sorted(by_resource):
            resource_producers, resource_consumers = by_resource[value_hash]
            prospective_count = 0
            for _producer_contract, producer in resource_producers:
                producer_endpoint_ids = {item.id for item in producer.endpoints}
                for _consumer_contract, consumer in resource_consumers:
                    consumer_endpoint_ids = {item.id for item in consumer.endpoints}
                    prospective_count += len(producer_endpoint_ids) * len(
                        consumer_endpoint_ids
                    ) - len(producer_endpoint_ids & consumer_endpoint_ids)
            if prospective_count > loaded.document.limits.max_endpoint_links_per_resource:
                diagnostics.append(
                    ResourceCouplingDiagnostic(
                        reason_code="resource_fanout_limit_exceeded",
                        group_id=group.id,
                        resource_node_hash=semantic_hash(
                            {
                                "group_hash": group.group_hash,
                                "resource_value_hash": value_hash,
                            }
                        ),
                        omitted_edges=prospective_count,
                    )
                )
                continue

            prospective = []
            for producer_contract, producer in resource_producers:
                for consumer_contract, consumer in resource_consumers:
                    for producer_endpoint in producer.endpoints:
                        for consumer_endpoint in consumer.endpoints:
                            if producer_endpoint.id == consumer_endpoint.id:
                                continue
                            strength = (
                                CouplingStrength.EXACT
                                if producer.resource_identity is not None
                                and consumer.resource_identity is not None
                                and producer.resource_identity.status == FiniteValueStatus.EXACT
                                and consumer.resource_identity.status == FiniteValueStatus.EXACT
                                else CouplingStrength.FINITE_OVERLAP
                            )
                            unvalidated = ResourceCouplingEdge.model_construct(
                                id=f"sha256:{'0' * 64}",
                                group_id=group.id,
                                group_hash=group.group_hash,
                                resource_space_hash=group.resource_space_hash,
                                resource_value_hash=value_hash,
                                strength=strength,
                                channel=channel,
                                producer_operation=producer_contract.operation,
                                consumer_operation=consumer_contract.operation,
                                producer_contract_id=producer_contract.id,
                                consumer_contract_id=consumer_contract.id,
                                producer_occurrence_id=producer.id,
                                consumer_occurrence_id=consumer.id,
                                producer_endpoint_id=producer_endpoint.id,
                                consumer_endpoint_id=consumer_endpoint.id,
                            )
                            prospective.append(
                                ResourceCouplingEdge(
                                    id=semantic_hash(unvalidated.identity_payload()),
                                    group_id=group.id,
                                    group_hash=group.group_hash,
                                    resource_space_hash=group.resource_space_hash,
                                    resource_value_hash=value_hash,
                                    strength=strength,
                                    channel=channel,
                                    producer_operation=producer_contract.operation,
                                    consumer_operation=consumer_contract.operation,
                                    producer_contract_id=producer_contract.id,
                                    consumer_contract_id=consumer_contract.id,
                                    producer_occurrence_id=producer.id,
                                    consumer_occurrence_id=consumer.id,
                                    producer_endpoint_id=producer_endpoint.id,
                                    consumer_endpoint_id=consumer_endpoint.id,
                                )
                            )
            unique = {edge.id: edge for edge in prospective}
            edges.extend(unique[item] for item in sorted(unique))

    unique_edges = {edge.id: edge for edge in edges}
    if len(unique_edges) > loaded.document.limits.max_edges:
        diagnostics = [
            ResourceCouplingDiagnostic(
                reason_code="global_edge_limit_exceeded",
                omitted_edges=len(unique_edges),
            )
        ]
        unique_edges = {}
    sorted_groups = tuple(sorted(groups, key=lambda item: item.id))
    sorted_edges = tuple(unique_edges[item] for item in sorted(unique_edges))
    sorted_diagnostics = tuple(
        sorted(
            diagnostics,
            key=lambda item: (
                item.reason_code,
                item.group_id or "",
                item.resource_node_hash or "",
            ),
        )
    )
    constructed = ResourceCouplingGraph.model_construct(
        schema_version=1,
        mode="report_only",
        status="diagnostic_only",
        raw_hash=loaded.raw_hash,
        config_hash=loaded.config_hash,
        effect_audit_hash=audit.provenance.audit_hash,
        groups=sorted_groups,
        edges=sorted_edges,
        diagnostics=sorted_diagnostics,
        graph_hash=f"sha256:{'0' * 64}",
    )
    return ResourceCouplingGraph(
        raw_hash=loaded.raw_hash,
        config_hash=loaded.config_hash,
        effect_audit_hash=audit.provenance.audit_hash,
        groups=sorted_groups,
        edges=sorted_edges,
        diagnostics=sorted_diagnostics,
        graph_hash=semantic_hash(constructed.graph_payload()),
    )
