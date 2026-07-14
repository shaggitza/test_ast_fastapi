"""Pure exact matching for endpoint-reachable effect-contract dry runs."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastapi_endpoint_detector.models.effect_contract import (
    CallResolutionStatus,
    LoadedEffectContracts,
    ResolvedCallSite,
)
from fastapi_endpoint_detector.models.effect_contract_audit import (
    AuditCallStatus,
    AuditEndpoint,
    AuditLimitation,
    EffectContractAudit,
    EffectContractAuditError,
    EffectContractAuditOccurrence,
    EffectContractAuditProvenance,
    EffectContractAuditScope,
    EffectContractAuditSummary,
    EffectContractCoverage,
)
from fastapi_endpoint_detector.models.endpoint import (
    Endpoint,
    EndpointDiscoveryCondition,
    EndpointDiscoveryStatus,
    EndpointInventory,
)

if TYPE_CHECKING:
    from collections.abc import Iterable


def _semantic_hash(payload: object) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _relative_path(path: Path | str, source_root: Path) -> str:
    candidate = Path(path).resolve()
    try:
        relative = candidate.relative_to(source_root)
    except ValueError as exc:
        raise EffectContractAuditError(
            f"audit source location escapes project root: {candidate}"
        ) from exc
    rendered = relative.as_posix()
    if not rendered or rendered == "." or rendered.startswith("../"):
        raise EffectContractAuditError(f"invalid project-relative audit path: {rendered}")
    return rendered


def _limitation(
    condition: EndpointDiscoveryCondition,
    source_root: Path,
) -> AuditLimitation:
    return AuditLimitation(
        file_path=_relative_path(condition.source_path, source_root),
        line=condition.source_line,
        reason=condition.reason,
    )


def build_audit_endpoint(endpoint: Endpoint, source_root: Path) -> AuditEndpoint:
    conditions = tuple(
        sorted(
            (_limitation(item, source_root) for item in endpoint.discovery_conditions),
            key=lambda item: (item.file_path, item.line, item.reason),
        )
    )
    methods = tuple(sorted(method.value for method in endpoint.methods))
    handler_file = _relative_path(endpoint.handler.file_path, source_root)
    identity = {
        "methods": methods,
        "path": endpoint.path,
        "handler_module": endpoint.handler.module,
        "handler_name": endpoint.handler.name,
        "handler_file": handler_file,
        "handler_line": endpoint.handler.line_number,
        "discovery_status": endpoint.discovery_status.value,
        "conditions": [item.model_dump(mode="json") for item in conditions],
    }
    return AuditEndpoint(
        id=_semantic_hash(identity),
        methods=methods,
        path=endpoint.path,
        handler_module=endpoint.handler.module,
        handler_name=endpoint.handler.name,
        handler_file=handler_file,
        handler_line=endpoint.handler.line_number,
        discovery_status=endpoint.discovery_status.value,
        conditions=conditions,
    )


def _call_payload(site: ResolvedCallSite, relative_path: str) -> dict[str, Any]:
    return {
        "file_path": relative_path,
        "line": site.line,
        "column": site.column,
        "end_line": site.end_line,
        "end_column": site.end_column,
        "source_spelling": site.source_spelling,
        "resolver_status": site.status.value,
        "canonical_symbol": site.canonical_symbol,
        "invocation": site.invocation.value if site.invocation is not None else None,
        "resolver": site.resolver,
        "resolver_version": site.resolver_version,
        "receiver_candidates": sorted(set(site.receiver_candidates)),
        "reason_code": site.reason_code,
    }


def audit_effect_contracts(  # noqa: PLR0912, PLR0915
    loaded: LoadedEffectContracts,
    *,
    source_root: Path,
    inventory: EndpointInventory,
    endpoint_call_sites: Iterable[tuple[Endpoint, Iterable[ResolvedCallSite]]],
    track_transitive: bool,
    max_depth: int,
    cache_enabled: bool,
    resolver_versions: Iterable[str],
) -> EffectContractAudit:
    """Match exact contract keys against a complete endpoint-reachable call corpus."""
    root = source_root.resolve()
    if inventory.status.value != "established" or any(
        endpoint.discovery_status != EndpointDiscoveryStatus.ESTABLISHED
        for endpoint in inventory.endpoints
    ):
        raise EffectContractAuditError(
            "a complete contract audit requires an established endpoint inventory "
            "containing only established endpoints"
        )
    contract_by_key = {
        (contract.symbol, contract.invocation.value): contract
        for contract in loaded.document.contracts
    }
    endpoint_rows = list(endpoint_call_sites)
    physical: dict[
        tuple[str, int, int, int | None, int | None],
        tuple[dict[str, Any], dict[str, AuditEndpoint]],
    ] = {}

    inventory_endpoint_keys = {
        (
            endpoint.path,
            tuple(sorted(method.value for method in endpoint.methods)),
            str(Path(endpoint.handler.file_path).resolve()),
            endpoint.handler.line_number,
            endpoint.handler.name,
            endpoint.handler.module,
        )
        for endpoint in inventory.endpoints
    }
    supplied_endpoint_keys = {
        (
            endpoint.path,
            tuple(sorted(method.value for method in endpoint.methods)),
            str(Path(endpoint.handler.file_path).resolve()),
            endpoint.handler.line_number,
            endpoint.handler.name,
            endpoint.handler.module,
        )
        for endpoint, _sites in endpoint_rows
    }
    if supplied_endpoint_keys != inventory_endpoint_keys:
        raise EffectContractAuditError(
            "endpoint call-site corpus does not exactly cover the endpoint inventory"
        )
    inventory_records: dict[str, AuditEndpoint] = {}
    for endpoint in inventory.endpoints:
        record = build_audit_endpoint(endpoint, root)
        if record.id in inventory_records:
            raise EffectContractAuditError(
                f"duplicate stable endpoint identity in inventory: {record.id}"
            )
        inventory_records[record.id] = record

    for endpoint, sites in endpoint_rows:
        endpoint_record = build_audit_endpoint(endpoint, root)
        for site in sites:
            relative = _relative_path(site.file_path, root)
            key = (relative, site.line, site.column, site.end_line, site.end_column)
            payload = _call_payload(site, relative)
            existing = physical.get(key)
            if existing is None:
                physical[key] = (payload, {endpoint_record.id: endpoint_record})
                continue
            existing_payload, endpoints = existing
            if existing_payload != payload:
                raise EffectContractAuditError(
                    "conflicting resolver records for physical call at "
                    f"{relative}:{site.line}:{site.column}"
                )
            previous_endpoint = endpoints.get(endpoint_record.id)
            if previous_endpoint is not None and previous_endpoint != endpoint_record:
                raise EffectContractAuditError(
                    "conflicting endpoint provenance for stable endpoint identity "
                    f"{endpoint_record.id}"
                )
            endpoints[endpoint_record.id] = endpoint_record

    occurrences: list[EffectContractAuditOccurrence] = []
    corpus_payload: list[dict[str, Any]] = []
    for key in sorted(
        physical,
        key=lambda item: tuple(-1 if part is None else part for part in item),
    ):
        payload, endpoint_records = physical[key]
        endpoint_tuple = tuple(endpoint_records[item] for item in sorted(endpoint_records))
        call_id = _semantic_hash(
            {
                "file_path": payload["file_path"],
                "line": payload["line"],
                "column": payload["column"],
                "end_line": payload["end_line"],
                "end_column": payload["end_column"],
            }
        )
        contract = None
        if payload["resolver_status"] == CallResolutionStatus.EXACT.value:
            contract = contract_by_key.get((payload["canonical_symbol"], payload["invocation"]))
        resolver_status = CallResolutionStatus(payload["resolver_status"])
        if contract is not None:
            audit_status = AuditCallStatus.MATCHED
        elif resolver_status == CallResolutionStatus.EXACT:
            audit_status = AuditCallStatus.UNMATCHED
        elif resolver_status == CallResolutionStatus.AMBIGUOUS:
            audit_status = AuditCallStatus.AMBIGUOUS
        else:
            audit_status = AuditCallStatus.UNRESOLVED
        occurrence = EffectContractAuditOccurrence(
            id=call_id,
            file_path=payload["file_path"],
            line=payload["line"],
            column=payload["column"],
            end_line=payload["end_line"],
            end_column=payload["end_column"],
            source_spelling=payload["source_spelling"],
            resolver_status=resolver_status,
            audit_status=audit_status,
            canonical_symbol=payload["canonical_symbol"],
            invocation=payload["invocation"],
            resolver=payload["resolver"],
            resolver_version=payload["resolver_version"],
            receiver_candidates=tuple(payload["receiver_candidates"]),
            reason_code=payload["reason_code"],
            contract_id=contract.id if contract is not None else None,
            contract_hash=(loaded.contract_hashes[contract.id] if contract is not None else None),
            endpoints=endpoint_tuple,
        )
        occurrences.append(occurrence)
        corpus_payload.append(
            {
                **payload,
                "id": call_id,
                "endpoint_ids": [endpoint.id for endpoint in endpoint_tuple],
            }
        )

    matched_by_contract: dict[str, list[EffectContractAuditOccurrence]] = {
        contract.id: [] for contract in loaded.document.contracts
    }
    for occurrence in occurrences:
        if occurrence.contract_id is not None:
            matched_by_contract[occurrence.contract_id].append(occurrence)
    coverage: list[EffectContractCoverage] = []
    for contract in sorted(loaded.document.contracts, key=lambda item: item.id):
        matched = matched_by_contract[contract.id]
        coverage.append(
            EffectContractCoverage(
                contract_id=contract.id,
                contract_hash=loaded.contract_hashes[contract.id],
                symbol=contract.symbol,
                invocation=contract.invocation,
                matched=bool(matched),
                occurrence_ids=tuple(item.id for item in matched),
                endpoint_ids=tuple(
                    sorted(
                        {endpoint.id for occurrence in matched for endpoint in occurrence.endpoints}
                    )
                ),
            )
        )

    limitations = tuple(
        sorted(
            (_limitation(item, root) for item in inventory.limitations),
            key=lambda item: (item.file_path, item.line, item.reason),
        )
    )
    scope = EffectContractAuditScope(
        inventory_status=inventory.status.value,
        inventory_limitations=limitations,
        endpoint_inventory=tuple(inventory_records[item] for item in sorted(inventory_records)),
        endpoints=len(inventory_records),
        established_endpoints=sum(
            endpoint.discovery_status == EndpointDiscoveryStatus.ESTABLISHED.value
            for endpoint in inventory_records.values()
        ),
        conditional_endpoints=sum(
            endpoint.discovery_status == EndpointDiscoveryStatus.CONDITIONAL.value
            for endpoint in inventory_records.values()
        ),
        track_transitive=track_transitive,
        max_depth=max_depth,
        cache_enabled=cache_enabled,
    )
    summary = EffectContractAuditSummary(
        contracts=len(coverage),
        matched_contracts=sum(item.matched for item in coverage),
        unmatched_contracts=sum(not item.matched for item in coverage),
        physical_occurrences=len(occurrences),
        matched_calls=sum(item.audit_status == AuditCallStatus.MATCHED for item in occurrences),
        unmatched_calls=sum(item.audit_status == AuditCallStatus.UNMATCHED for item in occurrences),
        ambiguous_calls=sum(item.audit_status == AuditCallStatus.AMBIGUOUS for item in occurrences),
        unresolved_calls=sum(
            item.audit_status == AuditCallStatus.UNRESOLVED for item in occurrences
        ),
        endpoint_links=sum(len(item.endpoints) for item in occurrences),
    )
    occurrence_corpus_hash = _semantic_hash(
        {
            "endpoints": [
                inventory_records[item].model_dump(mode="json")
                for item in sorted(inventory_records)
            ],
            "occurrences": corpus_payload,
        }
    )
    declared_resolvers = tuple(sorted(set(resolver_versions)))
    observed_resolvers = {f"{item.resolver}@{item.resolver_version}" for item in occurrences}
    if not observed_resolvers.issubset(declared_resolvers):
        raise EffectContractAuditError(
            "call-site resolver provenance is not covered by the declared audit resolvers"
        )
    try:
        contract_source_path = loaded.source_path.relative_to(root).as_posix()
    except ValueError:
        contract_source_path = f"content://sha256/{loaded.raw_hash.removeprefix('sha256:')}"
    audit_hash = _semantic_hash(
        {
            "matcher_schema_version": 1,
            "contract_source_path": contract_source_path,
            "raw_hash": loaded.raw_hash,
            "config_hash": loaded.config_hash,
            "preset_hash": loaded.preset_hash,
            "contract_hashes": dict(sorted(loaded.contract_hashes.items())),
            "occurrence_corpus_hash": occurrence_corpus_hash,
            "resolver_versions": declared_resolvers,
            "scope": scope.model_dump(mode="json"),
            "summary": summary.model_dump(mode="json"),
            "contract_coverage": [item.model_dump(mode="json") for item in coverage],
            "call_classification": [
                {
                    "id": item.id,
                    "audit_status": item.audit_status.value,
                    "contract_id": item.contract_id,
                    "contract_hash": item.contract_hash,
                }
                for item in occurrences
            ],
        }
    )
    provenance = EffectContractAuditProvenance(
        contract_source_path=contract_source_path,
        raw_hash=loaded.raw_hash,
        config_hash=loaded.config_hash,
        preset_hash=loaded.preset_hash,
        contract_hashes=dict(sorted(loaded.contract_hashes.items())),
        resolver_versions=declared_resolvers,
        occurrence_corpus_hash=occurrence_corpus_hash,
        audit_hash=audit_hash,
    )
    return EffectContractAudit(
        scope=scope,
        provenance=provenance,
        summary=summary,
        contract_coverage=tuple(coverage),
        occurrences=tuple(occurrences),
    )
