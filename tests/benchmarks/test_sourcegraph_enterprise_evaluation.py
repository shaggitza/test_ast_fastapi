"""Frozen offline controls for Sourcegraph evidence normalization."""

from __future__ import annotations

import pytest
from benchmarks.providers.sourcegraph_enterprise_evaluation import (
    EvidenceError,
    build_request,
    fingerprint,
    readiness_status,
    three_year_tco,
    validate_response,
)

_HASH = "a" * 64
_TOOL = "b" * 64
_CONFIG = "c" * 64


def request(kind: str = "reverse_reference") -> dict[str, object]:
    options: dict[str, object] = {}
    if kind == "cross_repo_consumer":
        options["consumer_indexes"] = {
            "github.com/acme/client": {
                "revision": "r2",
                "index_fingerprint": "d" * 64,
                "tool_fingerprint": "e" * 64,
                "config_fingerprint": "f" * 64,
            }
        }
    return build_request(
        kind=kind,  # type: ignore[arg-type]
        repository="github.com/acme/api",
        revision="r1",
        path="src/a.py",
        symbol="api.f",
        index_fingerprint=_HASH,
        tool_fingerprint=_TOOL,
        config_fingerprint=_CONFIG,
        **options,  # type: ignore[arg-type]
    )


def _reference(repo: str, revision: str) -> dict[str, object]:
    return {
        "repository": repo,
        "revision": revision,
        "path": "client.py" if revision == "r2" else "src/a.py",
        "start_line": 3,
        "end_line": 3,
        "symbol": "api.f",
        "index_fingerprint": "d" * 64 if revision == "r2" else _HASH,
        "tool_fingerprint": "e" * 64 if revision == "r2" else _TOOL,
        "config_fingerprint": "f" * 64 if revision == "r2" else _CONFIG,
    }


def response(
    kind: str = "reverse_reference", req: dict[str, object] | None = None
) -> dict[str, object]:
    req = req or request(kind)
    evidence: object
    if kind == "changed_symbol":
        evidence = {
            "symbol": "api.f",
            "before": "sym-old",
            "after": "sym-new",
            "change": "signature_changed",
        }
    elif kind == "call_chain":
        evidence = [
            {
                "relation": "calls",
                "from_symbol": "api.f",
                "to_symbol": "api.route",
                "repository": "github.com/acme/api",
                "revision": "r1",
                "path": "src/a.py",
                "start_line": 1,
                "end_line": 1,
                "call_expression": "api.route()",
                "index_fingerprint": _HASH,
                "tool_fingerprint": _TOOL,
                "config_fingerprint": _CONFIG,
            }
        ]
    elif kind == "cross_repo_consumer":
        evidence = [_reference("github.com/acme/client", "r2")]
    else:
        evidence = [_reference("github.com/acme/api", "r1")]
    value: dict[str, object] = {
        "kind": kind,
        "binding": {
            "repository": "github.com/acme/api",
            "revision": "r1",
            "path": "src/a.py",
            "start_line": 1,
            "end_line": 1,
            "index_fingerprint": _HASH,
            "tool_fingerprint": _TOOL,
            "config_fingerprint": _CONFIG,
        },
        "evidence": evidence,
        "receipt": {
            "source": "offline fixture; untrusted descriptive metadata",
            "query_fingerprint": fingerprint(req),
            "result_fingerprint": "0" * 64,
        },
    }
    _seal(value, req)
    return value


def _seal(value: dict[str, object], req: dict[str, object]) -> None:
    receipt = value["receipt"]
    assert isinstance(receipt, dict)
    receipt["query_fingerprint"] = fingerprint(req)
    receipt["result_fingerprint"] = fingerprint(
        {key: value[key] for key in ("kind", "binding", "evidence")}
    )


@pytest.mark.parametrize(
    "kind", ["changed_symbol", "reverse_reference", "call_chain", "cross_repo_consumer"]
)
def test_valid_fixture_is_hash_bound_and_explicitly_untrusted(kind: str) -> None:
    req = request(kind)
    validated = validate_response(response(kind, req), request=req)
    assert validated["kind"] == kind
    assert validated["validation"] == {
        "status": "schema_validated_supplied_evidence",
        "provider_authenticated": False,
        "scorable": False,
    }


@pytest.mark.parametrize("hash_field", ["query_fingerprint", "result_fingerprint"])
def test_tampered_hashes_fail_closed(hash_field: str) -> None:
    req = request()
    value = response(req=req)
    value["receipt"][hash_field] = "f" * 64  # type: ignore[index]
    with pytest.raises(EvidenceError, match="fingerprint does not match"):
        validate_response(value, request=req)


@pytest.mark.parametrize(
    "mutation",
    ["binding_revision", "binding_path", "binding_index", "missing_binding_fingerprint"],
)
def test_binding_mismatches_fail_closed(mutation: str) -> None:
    req = request()
    value = response(req=req)
    if mutation == "binding_revision":
        value["binding"]["revision"] = "r2"  # type: ignore[index]
    elif mutation == "binding_path":
        value["binding"]["path"] = "elsewhere.py"  # type: ignore[index]
    elif mutation == "binding_index":
        value["binding"]["index_fingerprint"] = "9" * 64  # type: ignore[index]
    else:
        del value["binding"]["tool_fingerprint"]  # type: ignore[index]
    _seal(value, req)
    with pytest.raises(EvidenceError):
        validate_response(value, request=req)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda req: req.update(kind=[]),
        lambda req: req.update(revision="r1\nforged"),
        lambda req: req.update(index_fingerprint="not-a-fingerprint"),
        lambda req: req.update(consumer_indexes=[]),
    ],
)
def test_malformed_request_fails_closed_before_response_validation(mutation) -> None:
    req = request()
    mutation(req)
    with pytest.raises(EvidenceError):
        validate_response(response(), request=req)


def test_request_builder_rejects_non_object_consumer_index_input() -> None:
    with pytest.raises(EvidenceError, match="repository-to-identity object"):
        build_request(
            kind="cross_repo_consumer",
            repository="github.com/acme/api",
            revision="r1",
            path="src/a.py",
            symbol="api.f",
            index_fingerprint=_HASH,
            tool_fingerprint=_TOOL,
            config_fingerprint=_CONFIG,
            consumer_indexes=[],  # type: ignore[arg-type]
        )


def test_request_builder_rejects_unhashable_kind_as_evidence_error() -> None:
    with pytest.raises(EvidenceError, match="unsupported evidence kind"):
        build_request(
            kind=[],  # type: ignore[arg-type]
            repository="github.com/acme/api",
            revision="r1",
            path="src/a.py",
            symbol="api.f",
            index_fingerprint=_HASH,
            tool_fingerprint=_TOOL,
            config_fingerprint=_CONFIG,
        )


def test_changed_symbol_must_equal_requested_symbol() -> None:
    req = request("changed_symbol")
    value = response("changed_symbol", req)
    value["evidence"]["symbol"] = "api.other"  # type: ignore[index]
    _seal(value, req)
    with pytest.raises(EvidenceError, match="does not match requested symbol"):
        validate_response(value, request=req)


def test_reverse_reference_cannot_claim_another_revision() -> None:
    req = request()
    value = response(req=req)
    value["evidence"][0]["revision"] = "r2"  # type: ignore[index]
    _seal(value, req)
    with pytest.raises(EvidenceError, match="revision does not match"):
        validate_response(value, request=req)


def test_reverse_reference_requires_its_own_index_provenance() -> None:
    req = request()
    value = response(req=req)
    del value["evidence"][0]["tool_fingerprint"]  # type: ignore[index]
    _seal(value, req)
    with pytest.raises(EvidenceError, match="fingerprints"):
        validate_response(value, request=req)


@pytest.mark.parametrize("kind", ["reverse_reference", "cross_repo_consumer"])
def test_duplicate_reference_identity_fails_even_with_resealed_result_hash(kind: str) -> None:
    req = request(kind)
    value = response(kind, req)
    value["evidence"].append(dict(value["evidence"][0]))  # type: ignore[index]
    _seal(value, req)
    with pytest.raises(EvidenceError, match="duplicate reference identity"):
        validate_response(value, request=req)


def test_cross_repository_revision_must_be_declared_in_request() -> None:
    req = request("cross_repo_consumer")
    value = response("cross_repo_consumer", req)
    value["evidence"][0]["revision"] = "other"  # type: ignore[index]
    _seal(value, req)
    with pytest.raises(EvidenceError, match="explicit request"):
        validate_response(value, request=req)


def test_cross_repository_index_identity_must_be_declared_in_request() -> None:
    req = request("cross_repo_consumer")
    value = response("cross_repo_consumer", req)
    value["evidence"][0]["tool_fingerprint"] = "9" * 64  # type: ignore[index]
    _seal(value, req)
    with pytest.raises(EvidenceError, match="requested index identity"):
        validate_response(value, request=req)


def test_call_chain_requires_supported_direct_call_edges_and_adjacency() -> None:
    req = request("call_chain")
    value = response("call_chain", req)
    value["evidence"][0]["relation"] = "references"  # type: ignore[index]
    _seal(value, req)
    with pytest.raises(EvidenceError, match="unsupported call-chain relationship"):
        validate_response(value, request=req)

    value = response("call_chain", req)
    value["evidence"][0]["from_symbol"] = "api.other"  # type: ignore[index]
    _seal(value, req)
    with pytest.raises(EvidenceError, match="ordered direct-call path"):
        validate_response(value, request=req)


def test_call_chain_cannot_be_asserted_without_direct_callee_text() -> None:
    req = request("call_chain")
    value = response("call_chain", req)
    value["evidence"][0]["call_expression"] = "api.route"  # type: ignore[index]
    _seal(value, req)
    with pytest.raises(EvidenceError, match="source text"):
        validate_response(value, request=req)


def test_receipt_does_not_authenticate_provider_evidence() -> None:
    req = request()
    value = response(req=req)
    value["receipt"]["source"] = "trusted Sourcegraph authority"  # type: ignore[index]
    _seal(value, req)
    validated = validate_response(value, request=req)
    assert validated["validation"]["provider_authenticated"] is False  # type: ignore[index]
    assert validated["validation"]["scorable"] is False  # type: ignore[index]


def test_readiness_is_descriptive_and_empty_required_coverage_is_not_ready() -> None:
    status = readiness_status(
        credentials_reported_available=True,
        indexed_repositories_reported={"producer"},
        required_repositories=set(),
        coverage_reported_complete=True,
        provenance_reported_available=True,
    )
    assert status.status == "not_ready"
    assert status.reasons == ("required_coverage_empty",)


def test_readiness_does_not_imply_authenticated_runtime_authorization() -> None:
    status = readiness_status(
        credentials_reported_available=True,
        indexed_repositories_reported={"producer", "consumer"},
        required_repositories={"producer", "consumer"},
        coverage_reported_complete=True,
        provenance_reported_available=True,
    )
    assert status.status == "ready_to_attempt"


def test_tco_exposes_assumptions_and_rejects_input_or_derived_overflow() -> None:
    costs = three_year_tco(
        annual_license=0,
        annual_compute=100,
        annual_storage=20,
        setup_hours=10,
        hourly_rate=50,
        annual_operations_hours=2,
    )
    assert costs == {
        "license_usd": 0,
        "infrastructure_usd": 360,
        "setup_labor_usd": 500,
        "operations_labor_usd": 300,
        "total_usd": 1160,
    }
    with pytest.raises(ValueError):
        three_year_tco(
            annual_license=float("nan"),
            annual_compute=0,
            annual_storage=0,
            setup_hours=0,
            hourly_rate=0,
            annual_operations_hours=0,
        )
    with pytest.raises(ValueError, match="inputs"):
        three_year_tco(
            annual_license=10**1000,
            annual_compute=0,
            annual_storage=0,
            setup_hours=0,
            hourly_rate=0,
            annual_operations_hours=0,
        )
    with pytest.raises(ValueError, match="inputs"):
        three_year_tco(
            annual_license=True,  # type: ignore[arg-type]
            annual_compute=0,
            annual_storage=0,
            setup_hours=0,
            hourly_rate=0,
            annual_operations_hours=0,
        )
    with pytest.raises(ValueError, match="derived TCO"):
        three_year_tco(
            annual_license=0,
            annual_compute=1e308,
            annual_storage=1e308,
            setup_hours=0,
            hourly_rate=0,
            annual_operations_hours=0,
        )
    with pytest.raises(ValueError, match="derived TCO total"):
        three_year_tco(
            annual_license=3.4e307,
            annual_compute=3.4e307,
            annual_storage=0,
            setup_hours=0,
            hourly_rate=0,
            annual_operations_hours=0,
        )
