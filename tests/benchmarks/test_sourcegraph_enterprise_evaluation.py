"""Frozen offline controls for Sourcegraph evidence normalization."""

from __future__ import annotations

import copy

import pytest
from benchmarks.providers.sourcegraph_enterprise_evaluation import (
    EvidenceError,
    build_request,
    evaluation_status,
    three_year_tco,
    validate_response,
)

_HASH = "a" * 64


def request(kind: str = "reverse_reference") -> dict[str, str]:
    return build_request(
        kind=kind, repository="github.com/acme/api", revision="r1", path="src/a.py", symbol="api.f"
    )  # type: ignore[arg-type]


def response(kind: str = "reverse_reference") -> dict[str, object]:
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
                "repository": "github.com/acme/api",
                "revision": "r1",
                "path": "src/a.py",
                "start_line": 1,
                "end_line": 1,
                "symbol": "api.f",
                "edge": "calls",
            },
            {
                "repository": "github.com/acme/api",
                "revision": "r1",
                "path": "src/b.py",
                "start_line": 2,
                "end_line": 2,
                "symbol": "api.route",
                "edge": "routes_to",
            },
        ]
    else:
        evidence = [
            {
                "repository": "github.com/acme/client",
                "revision": "r2",
                "path": "client.py",
                "start_line": 3,
                "end_line": 3,
                "symbol": "client.call",
            }
        ]
    return {
        "kind": kind,
        "binding": {
            "repository": "github.com/acme/api",
            "revision": "r1",
            "path": "src/a.py",
            "start_line": 1,
            "end_line": 1,
            "index_fingerprint": _HASH,
            "tool_fingerprint": "b" * 64,
            "config_fingerprint": "c" * 64,
        },
        "evidence": evidence,
        "receipt": {
            "source": "offline fixture; non-authoritative",
            "query_fingerprint": "d" * 64,
            "result_fingerprint": "e" * 64,
        },
    }


@pytest.mark.parametrize(
    "kind", ["changed_symbol", "reverse_reference", "call_chain", "cross_repo_consumer"]
)
def test_valid_fixture_is_bound_and_keeps_evidence_kind_distinct(kind: str) -> None:
    value = response(kind)
    value["kind"] = kind
    req = request(kind)
    assert validate_response(value, request=req)["kind"] == kind


@pytest.mark.parametrize(
    "mutation",
    [
        "revision",
        "path",
        "missing_fingerprint",
        "empty_receipt",
        "same_repo_crossrepo",
        "missing_range",
        "changed_kind",
    ],
)
def test_negative_controls_fail_closed(mutation: str) -> None:
    kind = "cross_repo_consumer" if mutation == "same_repo_crossrepo" else "reverse_reference"
    value = response(kind)
    req = request(kind)
    changed = copy.deepcopy(value)
    if mutation == "revision":
        changed["binding"]["revision"] = "other"  # type: ignore[index]
    elif mutation == "path":
        changed["binding"]["path"] = "elsewhere.py"  # type: ignore[index]
    elif mutation == "missing_fingerprint":
        del changed["binding"]["tool_fingerprint"]  # type: ignore[index]
    elif mutation == "empty_receipt":
        changed["receipt"] = {}  # type: ignore[assignment]
    elif mutation == "same_repo_crossrepo":
        changed["evidence"][0]["repository"] = "github.com/acme/api"  # type: ignore[index]
    elif mutation == "missing_range":
        del changed["evidence"][0]["end_line"]  # type: ignore[index]
    else:
        changed["kind"] = "call_chain"
    with pytest.raises(EvidenceError):
        validate_response(changed, request=req)


def test_call_chain_cannot_be_asserted_from_one_hop() -> None:
    value = response("call_chain")
    value["evidence"] = value["evidence"][:1]  # type: ignore[index]
    with pytest.raises(EvidenceError, match="at least two"):
        validate_response(value, request=request("call_chain"))


def test_missing_operational_gates_are_not_evaluable_not_empty_results() -> None:
    status = evaluation_status(
        authenticated=False,
        indexed_repositories=set(),
        required_repositories={"producer", "consumer"},
        complete_coverage=False,
        provenance_verified=False,
    )
    assert status.status == "not_evaluable"
    assert status.reasons == (
        "missing_credentials",
        "missing_index",
        "incomplete_coverage",
        "missing_provenance",
    )


def test_tco_exposes_each_assumption_and_rejects_nonfinite_inputs() -> None:
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
