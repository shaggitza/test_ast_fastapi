from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
import yaml
from pydantic import ValidationError

from fastapi_endpoint_detector.analyzer.effect_contract_auditor import audit_effect_contracts
from fastapi_endpoint_detector.models.effect_contract import (
    CallResolutionStatus,
    FiniteValueStatus,
    InvocationKind,
    LoadedEffectContracts,
    ResolvedCallSite,
    ResourceIdentityEvidence,
    load_effect_contracts,
    load_effect_preset,
)
from fastapi_endpoint_detector.models.effect_contract_audit import (
    AuditCallStatus,
    EffectContractAudit,
    EffectContractAuditError,
)
from fastapi_endpoint_detector.models.endpoint import (
    Endpoint,
    EndpointDiscoveryCondition,
    EndpointDiscoveryStatus,
    EndpointInventory,
    EndpointMethod,
    HandlerInfo,
    InventoryStatus,
)

if TYPE_CHECKING:
    from pathlib import Path


def _loaded(path: Path) -> LoadedEffectContracts:
    document = {
        "schema_version": 1,
        "preset": {
            "id": "audit",
            "version": "1.0.0",
            "provenance": {"kind": "user", "source": "effects.yaml"},
        },
        "contracts": [
            {
                "id": "emit",
                "symbol": "company.events.emit",
                "invocation": "function",
                "operation": "publish",
                "channel": "message_bus",
                "package": {"distribution": "not-installed", "version": ">=99"},
            },
            {
                "id": "store",
                "symbol": "company.Store.write",
                "invocation": "instance_method",
                "operation": "write",
                "channel": "custom",
            },
        ],
    }
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return load_effect_contracts(path)


def _endpoint(root: Path, name: str, route: str = "/test") -> Endpoint:
    source = root / "app.py"
    source.touch(exist_ok=True)
    return Endpoint(
        path=route,
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name=name,
            module="app",
            file_path=source,
            line_number=1,
        ),
    )


def _site(
    root: Path,
    *,
    column: int,
    status: CallResolutionStatus = CallResolutionStatus.EXACT,
    symbol: str | None = "company.events.emit",
    invocation: InvocationKind | None = InvocationKind.FUNCTION,
    spelling: str = "emit",
    reason: str | None = None,
) -> ResolvedCallSite:
    if status != CallResolutionStatus.EXACT:
        symbol = None
        invocation = None
        reason = reason or "dynamic_callable"
    return ResolvedCallSite(
        file_path=str(root / "service.py"),
        line=10,
        column=column,
        end_line=10,
        end_column=column + len(spelling.encode()),
        source_spelling=spelling,
        canonical_symbol=symbol,
        invocation=invocation,
        status=status,
        resolver="mypy",
        resolver_version="1.19.1",
        receiver_candidates=("company.Store",) if status != CallResolutionStatus.EXACT else (),
        reason_code=reason,
    )


def _audit(
    root: Path,
    rows: list[tuple[Endpoint, list[ResolvedCallSite]]],
    *,
    loaded: LoadedEffectContracts | None = None,
    track_transitive: bool = True,
    max_depth: int = 10,
    cache_enabled: bool = True,
) -> EffectContractAudit:
    endpoints = [endpoint for endpoint, _sites in rows]
    return audit_effect_contracts(
        loaded or _loaded(root / "effects.yaml"),
        source_root=root,
        inventory=EndpointInventory(endpoints=endpoints),
        endpoint_call_sites=rows,
        track_transitive=track_transitive,
        max_depth=max_depth,
        cache_enabled=cache_enabled,
        resolver_versions=("mypy@1.19.1",),
    )


@pytest.mark.parametrize(
    ("preset", "symbol", "invocation", "contract_id", "negative_symbol"),
    [
        (
            "mongodb-v1",
            "motor.core.AgnosticCollection.update_one",
            InvocationKind.INSTANCE_METHOD,
            "motor-update-one",
            "project.Collection.update_one",
        ),
        (
            "filesystem-v1",
            "os.remove",
            InvocationKind.FUNCTION,
            "os-remove",
            "project.files.remove",
        ),
        (
            "http-clients-v1",
            "requests.api.post",
            InvocationKind.FUNCTION,
            "requests-api-post",
            "project.http.post",
        ),
        (
            "object-storage-v1",
            "mypy_boto3_s3.client.S3Client.put_object",
            InvocationKind.INSTANCE_METHOD,
            "typed-s3-put-object",
            "project.S3.put_object",
        ),
        (
            "message-bus-v1",
            "confluent_kafka.cimpl.Producer.produce",
            InvocationKind.INSTANCE_METHOD,
            "confluent-kafka-produce",
            "confluent_kafka.Producer.produce",
        ),
    ],
)
def test_bundled_presets_match_only_exact_qualified_symbols(
    tmp_path: Path,
    preset: str,
    symbol: str,
    invocation: InvocationKind,
    contract_id: str,
    negative_symbol: str,
) -> None:
    endpoint = _endpoint(tmp_path, "handler")
    exact = _site(
        tmp_path,
        column=2,
        symbol=symbol,
        invocation=invocation,
        spelling=symbol.rsplit(".", maxsplit=1)[-1],
    )
    unrelated = _site(
        tmp_path,
        column=30,
        symbol=negative_symbol,
        invocation=invocation,
        spelling=negative_symbol.rsplit(".", maxsplit=1)[-1],
    )

    audit = _audit(
        tmp_path,
        [(endpoint, [unrelated, exact])],
        loaded=load_effect_preset(preset),
    )

    assert audit.summary.matched_calls == 1
    assert audit.summary.unmatched_calls == 1
    matched = [item for item in audit.occurrences if item.contract_id is not None]
    assert [item.contract_id for item in matched] == [contract_id]


def test_exact_matching_is_symbol_and_invocation_only(tmp_path: Path) -> None:
    endpoint = _endpoint(tmp_path, "handler")
    rows = [
        (
            endpoint,
            [
                _site(tmp_path, column=2),
                _site(
                    tmp_path,
                    column=20,
                    symbol="company.events.emit",
                    invocation=InvocationKind.CONSTRUCTOR,
                    spelling="emit",
                ),
                _site(
                    tmp_path,
                    column=30,
                    symbol="other.emit",
                    spelling="company.events.emit",
                ),
            ],
        )
    ]

    audit = _audit(tmp_path, rows)

    assert [item.audit_status for item in audit.occurrences] == [
        AuditCallStatus.MATCHED,
        AuditCallStatus.UNMATCHED,
        AuditCallStatus.UNMATCHED,
    ]
    assert audit.occurrences[0].contract_id == "emit"
    assert all(item.contract_id is None for item in audit.occurrences[1:])
    assert audit.summary.matched_calls == 1
    assert audit.summary.unmatched_calls == 2
    assert audit.summary.matched_contracts == 1
    assert audit.summary.unmatched_contracts == 1


def test_ambiguous_and_unresolved_remain_distinct_and_never_match(tmp_path: Path) -> None:
    endpoint = _endpoint(tmp_path, "handler")
    rows = [
        (
            endpoint,
            [
                _site(
                    tmp_path,
                    column=2,
                    status=CallResolutionStatus.AMBIGUOUS,
                    spelling="client.write",
                    reason="ambiguous_receiver",
                ),
                _site(
                    tmp_path,
                    column=20,
                    status=CallResolutionStatus.UNRESOLVED,
                    spelling="company.Store.write",
                ),
            ],
        )
    ]

    audit = _audit(tmp_path, rows)

    assert [item.audit_status for item in audit.occurrences] == [
        AuditCallStatus.AMBIGUOUS,
        AuditCallStatus.UNRESOLVED,
    ]
    assert audit.summary.unmatched_calls == 0
    assert audit.summary.ambiguous_calls == 1
    assert audit.summary.unresolved_calls == 1
    assert audit.occurrences[0].receiver_candidates == ("company.Store",)


def test_shared_physical_call_is_counted_once_with_handler_aware_endpoints(
    tmp_path: Path,
) -> None:
    first = _endpoint(tmp_path, "first", route="/same")
    second = _endpoint(tmp_path, "second", route="/same")
    site = _site(tmp_path, column=2)

    audit = _audit(tmp_path, [(second, [site]), (first, [site])])

    assert audit.summary.physical_occurrences == 1
    assert audit.summary.endpoint_links == 2
    assert len(audit.occurrences[0].endpoints) == 2
    assert len({item.id for item in audit.occurrences[0].endpoints}) == 2
    assert [item.id for item in audit.occurrences[0].endpoints] == sorted(
        item.id for item in audit.occurrences[0].endpoints
    )


def test_exact_duplicate_endpoint_identities_are_rejected(tmp_path: Path) -> None:
    endpoint = _endpoint(tmp_path, "handler")
    site = _site(tmp_path, column=2)

    with pytest.raises(EffectContractAuditError, match="duplicate stable endpoint identity"):
        _audit(tmp_path, [(endpoint, [site]), (endpoint, [site])])


def test_same_line_calls_are_distinct_and_order_is_deterministic(tmp_path: Path) -> None:
    endpoint = _endpoint(tmp_path, "handler")
    left = _site(tmp_path, column=5)
    right = _site(tmp_path, column=20)

    first = _audit(tmp_path, [(endpoint, [right, left])])
    second = _audit(tmp_path, [(endpoint, [left, right])])

    assert first.summary.physical_occurrences == 2
    assert [item.column for item in first.occurrences] == [5, 20]
    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_conflicting_resolution_for_one_physical_call_fails_closed(tmp_path: Path) -> None:
    first = _endpoint(tmp_path, "first")
    second = _endpoint(tmp_path, "second", route="/other")
    exact = _site(tmp_path, column=2)
    conflicting = _site(tmp_path, column=2, symbol="other.emit")

    with pytest.raises(EffectContractAuditError, match="conflicting resolver records"):
        _audit(tmp_path, [(first, [exact]), (second, [conflicting])])


def test_incomplete_endpoint_corpus_and_escaping_paths_fail_closed(tmp_path: Path) -> None:
    endpoint = _endpoint(tmp_path, "handler")
    loaded = _loaded(tmp_path / "effects.yaml")

    with pytest.raises(EffectContractAuditError, match="exactly cover"):
        audit_effect_contracts(
            loaded,
            source_root=tmp_path,
            inventory=EndpointInventory(endpoints=[endpoint]),
            endpoint_call_sites=[],
            track_transitive=True,
            max_depth=10,
            cache_enabled=False,
            resolver_versions=("mypy@1.19.1",),
        )

    escaped = _site(tmp_path, column=2).model_copy(
        update={"file_path": str(tmp_path.parent / "outside.py")}
    )
    with pytest.raises(EffectContractAuditError, match="escapes project root"):
        _audit(tmp_path, [(endpoint, [escaped])], loaded=loaded)


def test_hashes_and_output_are_relocation_independent(tmp_path: Path) -> None:
    reports = []
    for checkout in (tmp_path / "left", tmp_path / "right"):
        checkout.mkdir()
        endpoint = _endpoint(checkout, "handler")
        reports.append(_audit(checkout, [(endpoint, [_site(checkout, column=2)])]))

    assert reports[0].provenance.occurrence_corpus_hash == (
        reports[1].provenance.occurrence_corpus_hash
    )
    assert reports[0].provenance.audit_hash == reports[1].provenance.audit_hash
    assert reports[0].model_dump(mode="json") == reports[1].model_dump(mode="json")


def test_audit_hash_attests_scope_and_traversal_settings(tmp_path: Path) -> None:
    endpoint = _endpoint(tmp_path, "handler")
    rows = [(endpoint, [_site(tmp_path, column=2)])]

    transitive = _audit(tmp_path, rows, track_transitive=True, max_depth=10)
    direct = _audit(tmp_path, rows, track_transitive=False, max_depth=1)

    assert transitive.provenance.occurrence_corpus_hash == (
        direct.provenance.occurrence_corpus_hash
    )
    assert transitive.provenance.audit_hash != direct.provenance.audit_hash

    endpoint_without_calls = _audit(tmp_path, [(endpoint, [])])
    empty_inventory = _audit(tmp_path, [])
    assert endpoint_without_calls.provenance.occurrence_corpus_hash != (
        empty_inventory.provenance.occurrence_corpus_hash
    )
    assert endpoint_without_calls.provenance.audit_hash != empty_inventory.provenance.audit_hash


def test_incomplete_inventory_is_rejected_instead_of_claiming_complete_matching(
    tmp_path: Path,
) -> None:
    endpoint = _endpoint(tmp_path, "handler").model_copy(
        update={
            "discovery_status": EndpointDiscoveryStatus.CONDITIONAL,
            "discovery_conditions": (
                EndpointDiscoveryCondition(
                    source_path=tmp_path / "app.py",
                    source_line=1,
                    reason="runtime branch",
                ),
            ),
        }
    )
    limitation = EndpointDiscoveryCondition(
        source_path=tmp_path / "app.py",
        source_line=1,
        reason="runtime branch",
    )

    with pytest.raises(EffectContractAuditError, match="requires an established"):
        audit_effect_contracts(
            _loaded(tmp_path / "effects.yaml"),
            source_root=tmp_path,
            inventory=EndpointInventory(
                endpoints=[endpoint],
                status=InventoryStatus.CONDITIONAL,
                limitations=(limitation,),
            ),
            endpoint_call_sites=[(endpoint, [_site(tmp_path, column=2)])],
            track_transitive=True,
            max_depth=10,
            cache_enabled=True,
            resolver_versions=("mypy@1.19.1",),
        )

    with pytest.raises(EffectContractAuditError, match="only established endpoints"):
        audit_effect_contracts(
            _loaded(tmp_path / "effects-established.yaml"),
            source_root=tmp_path,
            inventory=EndpointInventory(endpoints=[endpoint]),
            endpoint_call_sites=[(endpoint, [_site(tmp_path, column=2)])],
            track_transitive=True,
            max_depth=10,
            cache_enabled=True,
            resolver_versions=("mypy@1.19.1",),
        )


def test_report_models_reject_tampered_summary_and_exact_identity(tmp_path: Path) -> None:
    endpoint = _endpoint(tmp_path, "handler")
    audit = _audit(tmp_path, [(endpoint, [_site(tmp_path, column=2)])])
    payload = audit.model_dump(mode="json")
    payload["summary"]["physical_occurrences"] = 3
    payload["summary"]["matched_calls"] = 3

    with pytest.raises(ValidationError, match="summary does not match"):
        type(audit).model_validate(payload)

    occurrence_payload = audit.occurrences[0].model_dump(mode="json")
    occurrence_payload["audit_status"] = "unmatched"
    occurrence_payload["contract_id"] = None
    occurrence_payload["contract_hash"] = None
    occurrence_payload["canonical_symbol"] = None
    occurrence_payload["invocation"] = None
    with pytest.raises(ValidationError, match="exact audit calls require"):
        type(audit.occurrences[0]).model_validate(occurrence_payload)

    provenance_payload = audit.model_dump(mode="json")
    provenance_payload["provenance"]["raw_hash"] = f"sha256:{'0' * 64}"
    with pytest.raises(ValidationError, match="audit hash does not match"):
        type(audit).model_validate(provenance_payload)

    matched_payload = audit.model_dump(mode="json")
    matched_payload["occurrences"][0]["contract_hash"] = f"sha256:{'0' * 64}"
    with pytest.raises(ValidationError, match="contract hash is inconsistent"):
        type(audit).model_validate(matched_payload)


def test_external_contract_source_uses_relocation_stable_content_identity(
    tmp_path: Path,
) -> None:
    contract_dir = tmp_path / "config"
    contract_dir.mkdir()
    loaded = _loaded(contract_dir / "effects.yaml")
    reports = []
    for checkout in (tmp_path / "left-external", tmp_path / "right-external"):
        checkout.mkdir()
        endpoint = _endpoint(checkout, "handler")
        reports.append(
            _audit(
                checkout,
                [(endpoint, [_site(checkout, column=2)])],
                loaded=loaded,
            )
        )

    assert reports[0].provenance.contract_source_path.startswith("content://sha256/")
    assert reports[0].model_dump(mode="json") == reports[1].model_dump(mode="json")

    renamed = contract_dir / "renamed.yaml"
    renamed.write_bytes((contract_dir / "effects.yaml").read_bytes())
    endpoint = _endpoint(tmp_path / "left-external", "handler")
    renamed_report = _audit(
        tmp_path / "left-external",
        [(endpoint, [_site(tmp_path / "left-external", column=2)])],
        loaded=load_effect_contracts(renamed),
    )
    assert reports[0].model_dump(mode="json") == renamed_report.model_dump(mode="json")


def test_receiver_selector_uses_only_source_proven_finite_origin(tmp_path: Path) -> None:
    contracts = tmp_path / "receiver-effects.yaml"
    contracts.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "preset": {
                    "id": "receiver-audit",
                    "version": "1.0.0",
                    "provenance": {"kind": "user", "source": "receiver-effects.yaml"},
                },
                "contracts": [
                    {
                        "id": "path-read",
                        "symbol": "pathlib.Path.read_text",
                        "invocation": "instance_method",
                        "operation": "read",
                        "channel": "filesystem",
                        "resource": {"kind": "receiver"},
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    endpoint = _endpoint(tmp_path, "handler")
    resource_hash = f"sha256:{'a' * 64}"
    site = _site(
        tmp_path,
        column=2,
        symbol="pathlib.Path.read_text",
        invocation=InvocationKind.INSTANCE_METHOD,
        spelling="path.read_text",
    ).model_copy(
        update={
            "receiver_origin": ResourceIdentityEvidence(
                status=FiniteValueStatus.EXACT,
                value_hashes=(resource_hash,),
            )
        }
    )

    audit = _audit(
        tmp_path,
        [(endpoint, [site])],
        loaded=load_effect_contracts(contracts),
    )

    identity = audit.occurrences[0].resource_identity
    assert identity is not None
    assert identity.status == FiniteValueStatus.EXACT
    assert identity.value_hashes == (resource_hash,)
    assert identity.reason_code is None
    payload = audit.model_dump(mode="json")
    payload["occurrences"][0]["receiver_origin"]["value_hashes"] = [f"sha256:{'b' * 64}"]
    with pytest.raises(ValidationError, match="occurrence corpus hash"):
        type(audit).model_validate(payload)


def test_package_applicability_is_reported_but_not_used_for_matching(tmp_path: Path) -> None:
    endpoint = _endpoint(tmp_path, "handler")

    audit = _audit(tmp_path, [(endpoint, [_site(tmp_path, column=2)])])

    assert audit.occurrences[0].audit_status == AuditCallStatus.MATCHED
    assert audit.scope.package_applicability == "not_evaluated"
