"""Contract evidence retains the endpoint-specific helper invocation identity."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import pytest

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.analyzer.effect_contract_auditor import build_audit_endpoint
from fastapi_endpoint_detector.models.effect_contract import (
    EffectChannel,
    EffectContract,
    EffectOperation,
    FiniteValueStatus,
    InvocationKind,
    ResourceIdentityEvidence,
)
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo
from fastapi_endpoint_detector.models.report import (
    AffectedEndpoint,
    ConfidenceLevel,
    ContractEffectEvidence,
)

if TYPE_CHECKING:
    from fastapi_endpoint_detector.models.effect_contract_audit import EffectContractAudit


_HASH = "sha256:" + "a" * 64


def _mapper_audit(
    root: Path,
    occurrence: SimpleNamespace,
) -> tuple[ChangeMapper, EffectContractAudit]:
    contract = EffectContract(
        id="httpx-get",
        symbol="httpx._api.get",
        invocation=InvocationKind.FUNCTION,
        operation=EffectOperation.REQUEST,
        channel=EffectChannel.OUTBOUND_HTTP,
        http_method="GET",
    )
    loaded = SimpleNamespace(
        document=SimpleNamespace(contracts=(contract,)),
        contract_hashes={contract.id: _HASH},
    )
    audit = SimpleNamespace(
        occurrences=(occurrence,),
        provenance=SimpleNamespace(
            config_hash=_HASH,
            preset_hash=_HASH,
            raw_hash=_HASH,
            audit_hash=_HASH,
            occurrence_corpus_hash=_HASH,
            contract_source_path="effects.yaml",
            matcher="exact-symbol-invocation",
        ),
        scope=SimpleNamespace(package_applicability="source_pins_evaluated"),
    )
    mapper = SimpleNamespace(app_path=root, _effect_contracts=loaded)
    return cast("ChangeMapper", mapper), cast("EffectContractAudit", audit)


def _candidate(root: Path, name: str) -> AffectedEndpoint:
    endpoint = Endpoint(
        path="/" + name,
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name=name,
            module="app",
            file_path=root / f"{name}.py",
            line_number=1,
        ),
    )
    return AffectedEndpoint(
        endpoint=endpoint,
        confidence=ConfidenceLevel.HIGH,
        reason="existing impact",
        dependency_chain=["app.handler", "app.emit"],
        changed_files=["helpers.py"],
    )


def _occurrence(
    endpoint_ids: tuple[str, ...], contexts: tuple[SimpleNamespace, ...]
) -> SimpleNamespace:
    return SimpleNamespace(
        id="sha256:" + "d" * 64,
        contract_id="httpx-get",
        endpoints=tuple(SimpleNamespace(id=item) for item in endpoint_ids),
        invocation_contexts=contexts,
        resource_identity=ResourceIdentityEvidence(
            status=FiniteValueStatus.UNAVAILABLE,
            reason_code="shared_occurrence_identity_unavailable",
        ),
        file_path="a.py",
        line=7,
        end_line=7,
        canonical_symbol="httpx._api.get",
        resolver="mypy",
        resolver_version="1.19.1",
    )


def test_contract_evidence_uses_the_matching_endpoint_invocation_context() -> None:
    root = Path("/synthetic")
    candidates = [_candidate(root, "a"), _candidate(root, "b")]
    endpoint_ids = tuple(build_audit_endpoint(item.endpoint, root).id for item in candidates)
    identities = tuple(
        ResourceIdentityEvidence(
            status=FiniteValueStatus.EXACT,
            value_hashes=("sha256:" + character * 64,),
        )
        for character in ("b", "c")
    )
    contexts = tuple(
        SimpleNamespace(endpoint_id=endpoint_id, resource_identity=identity)
        for endpoint_id, identity in zip(endpoint_ids, identities, strict=True)
    )
    mapper, audit = _mapper_audit(root, _occurrence(endpoint_ids, contexts))

    out = ChangeMapper._attach_contract_evidence(mapper, candidates, audit)

    assert tuple(item.contract_evidence[0].resource_identity for item in out) == identities
    assert tuple(item.contract_evidence[0].endpoint_audit_id for item in out) == endpoint_ids
    for original, enriched in zip(candidates, out, strict=True):
        assert enriched.model_dump(exclude={"contract_evidence"}) == original.model_dump(
            exclude={"contract_evidence"}
        )
        evidence = enriched.contract_evidence[0]
        assert ContractEffectEvidence.model_validate(evidence.model_dump()) == evidence
        assert evidence.resource_identity_status is FiniteValueStatus.EXACT


@pytest.mark.parametrize("context_state", ["absent", "other_endpoint", "missing_identity"])
def test_contract_evidence_skips_missing_endpoint_context_without_shared_fallback(
    context_state: str,
) -> None:
    root = Path("/synthetic")
    candidate = _candidate(root, "a")
    endpoint_id = build_audit_endpoint(candidate.endpoint, root).id
    if context_state == "absent":
        contexts = ()
    else:
        contexts = (
            SimpleNamespace(
                endpoint_id=endpoint_id if context_state == "missing_identity" else "other",
                resource_identity=None,
            ),
        )
    occurrence = _occurrence((endpoint_id,), contexts)
    occurrence.resource_identity = ResourceIdentityEvidence(
        status=FiniteValueStatus.EXACT,
        value_hashes=("sha256:" + "e" * 64,),
    )
    mapper, audit = _mapper_audit(root, occurrence)

    (out,) = ChangeMapper._attach_contract_evidence(mapper, [candidate], audit)

    assert out.contract_evidence == ()
    assert out == candidate
