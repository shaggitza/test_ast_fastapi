#!/usr/bin/env python3
"""Deterministic synthetic scale gate for finite resource coupling."""

from __future__ import annotations

import argparse
import json
import resource
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi_endpoint_detector.analyzer.resource_coupling import build_resource_coupling_graph
from fastapi_endpoint_detector.models.effect_contract import (
    ContractProvenance,
    EffectChannel,
    EffectContract,
    EffectContractDocument,
    EffectOperation,
    EffectSelector,
    FiniteValueStatus,
    InvocationKind,
    LoadedEffectContracts,
    PresetMetadata,
    ProvenanceKind,
    ResourceIdentityEvidence,
    SelectorKind,
)
from fastapi_endpoint_detector.models.effect_contract_audit import (
    AuditEndpoint,
    EffectContractAudit,
    EffectContractAuditOccurrence,
)
from fastapi_endpoint_detector.models.resource_coupling import (
    LoadedResourceCoupling,
    ResourceCouplingDocument,
    ResourceCouplingGroup,
    ResourceCouplingLimits,
    semantic_hash,
)


@dataclass(frozen=True)
class _AuditProvenance:
    audit_hash: str


def _contract(
    contract_id: str,
    operation: EffectOperation,
    channel: EffectChannel,
) -> EffectContract:
    return EffectContract(
        id=contract_id,
        symbol=f"benchmark.effects.{contract_id.replace('-', '_')}",
        invocation=InvocationKind.FUNCTION,
        operation=operation,
        channel=channel,
        resource=EffectSelector(kind=SelectorKind.ARGUMENT, index=0),
    )


def _endpoint(label: str) -> AuditEndpoint:
    return AuditEndpoint.model_construct(id=semantic_hash({"endpoint": label}))


def _occurrence(
    index: int,
    contract_id: str,
    endpoint: AuditEndpoint,
    resource_index: int,
) -> EffectContractAuditOccurrence:
    return EffectContractAuditOccurrence.model_construct(
        id=semantic_hash({"occurrence": index, "contract": contract_id}),
        contract_id=contract_id,
        resource_identity=ResourceIdentityEvidence(
            status=FiniteValueStatus.EXACT,
            value_hashes=(semantic_hash({"resource": resource_index}),),
        ),
        endpoints=(endpoint,),
    )


def build_fixture(
    occurrence_count: int,
) -> tuple[LoadedResourceCoupling, LoadedEffectContracts, EffectContractAudit]:
    """Build a bounded synthetic seam fixture without pretending it is source evidence."""
    if occurrence_count < 4 or occurrence_count % 4:
        raise ValueError("occurrence_count must be at least four and divisible by four")
    per_role = occurrence_count // 4
    contracts = (
        _contract("consume-topic", EffectOperation.CONSUME, EffectChannel.MESSAGE_BUS),
        _contract("publish-topic", EffectOperation.PUBLISH, EffectChannel.MESSAGE_BUS),
        _contract("read-state", EffectOperation.READ, EffectChannel.CUSTOM),
        _contract("write-state", EffectOperation.WRITE, EffectChannel.CUSTOM),
    )
    document = EffectContractDocument(
        preset=PresetMetadata(
            id="resource-scale-v1",
            version="1.0.0",
            provenance=ContractProvenance(
                kind=ProvenanceKind.INTERNAL,
                source="benchmarks/resource_coupling_scale.py",
            ),
        ),
        contracts=contracts,
    )
    effects = LoadedEffectContracts(
        source_path=Path("benchmarks/resource_coupling_scale.py"),
        raw_hash=semantic_hash({"fixture": "resource-scale-v1"}),
        config_hash=document.config_hash,
        preset_hash=document.preset_hash,
        contract_hashes=document.contract_hashes,
        document=document,
    )
    endpoint_by_role = {
        "consume-topic": _endpoint("message-consumer"),
        "publish-topic": _endpoint("message-producer"),
        "read-state": _endpoint("state-reader"),
        "write-state": _endpoint("state-writer"),
    }
    occurrences = []
    occurrence_index = 0
    for resource_index in range(per_role):
        for contract in contracts:
            occurrences.append(
                _occurrence(
                    occurrence_index,
                    contract.id,
                    endpoint_by_role[contract.id],
                    resource_index,
                )
            )
            occurrence_index += 1
    audit_hash = semantic_hash({"fixture": "resource-scale-v1", "occurrences": occurrence_count})
    audit = EffectContractAudit.model_construct(
        occurrences=tuple(occurrences),
        provenance=_AuditProvenance(audit_hash=audit_hash),
    )
    coupling_document = ResourceCouplingDocument(
        schema_version=1,
        mode="report_only",
        groups=(
            ResourceCouplingGroup(
                id="message-events",
                resource_space="benchmark-message-space",
                producer_contract_ids=("publish-topic",),
                consumer_contract_ids=("consume-topic",),
            ),
            ResourceCouplingGroup(
                id="state-records",
                resource_space="benchmark-state-space",
                producer_contract_ids=("write-state",),
                consumer_contract_ids=("read-state",),
            ),
        ),
        limits=ResourceCouplingLimits(
            max_endpoint_links_per_resource=4,
            max_edges=10_000,
        ),
    )
    coupling = LoadedResourceCoupling(
        source_path=Path("benchmarks/resource_coupling_scale.py"),
        raw_hash=semantic_hash({"fixture": "resource-scale-coupling-v1"}),
        config_hash=semantic_hash(coupling_document.normalized_payload()),
        document=coupling_document,
    )
    return coupling, effects, audit


def run_scale(occurrence_count: int, *, verify_determinism: bool = True) -> dict[str, Any]:
    coupling, effects, audit = build_fixture(occurrence_count)
    started = time.perf_counter()
    graph = build_resource_coupling_graph(coupling, effects, audit)
    elapsed = time.perf_counter() - started
    expected_edges = occurrence_count // 2
    if len(graph.edges) != expected_edges or graph.diagnostics:
        raise RuntimeError("resource scale graph failed its exact edge/count gate")
    if verify_determinism:
        repeated = build_resource_coupling_graph(coupling, effects, audit)
        if repeated.graph_hash != graph.graph_hash:
            raise RuntimeError("resource scale graph is not deterministic")
    operations = {
        f"{edge.producer_operation.value}->{edge.consumer_operation.value}" for edge in graph.edges
    }
    if operations != {"publish->consume", "write->read"}:
        raise RuntimeError("resource scale graph emitted an unsupported operation direction")
    return {
        "schema_version": 1,
        "fixture": "finite-resource-coupling-scale-v1",
        "occurrences": occurrence_count,
        "edges": len(graph.edges),
        "diagnostics": len(graph.diagnostics),
        "operation_directions": sorted(operations),
        "determinism_verified": verify_determinism,
        "graph_hash": graph.graph_hash,
        "elapsed_seconds": round(elapsed, 6),
        "max_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--occurrences", type=int, default=10_000)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--skip-determinism-check", action="store_true")
    arguments = parser.parse_args()
    result = run_scale(
        arguments.occurrences,
        verify_determinism=not arguments.skip_determinism_check,
    )
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if arguments.output is None:
        print(rendered, end="")
    else:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
