from __future__ import annotations

import ast
import json
from pathlib import Path

import benchmarks.providers.sourcegraph_public_case as protocol
import pytest
from benchmarks.providers.sourcegraph_public_case import (
    FROZEN_CASE_PROFILE,
    PublicCaseProtocolError,
    validate_result,
)

CASE = FROZEN_CASE_PROFILE


def result(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "protocol_version": 1,
        "case": CASE.copy(),
        "operation": "index_revision_status",
        "status": "unavailable",
        "transport": {
            "http_status": 200,
            "elapsed_seconds": 0.527802,
            "response_bytes": 112,
            "truncated": False,
            "redirects": 0,
        },
        "endpoint": "https://sourcegraph.com/.api/graphql",
        "request": '{"query":"frozen exact query"}',
        "response_raw": '{"errors":[{"message":"not authenticated"}],"data":{"repository":null}}',
        "error": "not_authenticated",
        "provider_evidence": None,
    }
    value.update(overrides)
    return value


def test_anonymous_auth_error_stays_unavailable_not_zero_hits() -> None:
    validated = validate_result(result())
    assert validated["status"] == "unavailable"
    assert validated["provider_evidence"] is None
    assert validated["error"] == "not_authenticated"


def test_protocol_module_is_loaded_from_this_candidate_checkout() -> None:
    expected = (
        Path(__file__).resolve().parents[2] / "benchmarks/providers/sourcegraph_public_case.py"
    )
    assert Path(protocol.__file__).resolve() == expected


def test_recorded_public_case_artifact_matches_protocol() -> None:
    for path in (
        Path("benchmarks/results/sourcegraph-public-case-r3-v1.json"),
        Path("benchmarks/results/sourcegraph-public-case-r3-reverse-reference.json"),
    ):
        artifact = json.loads(path.read_text())
        validated = validate_result(artifact)
        assert validated["status"] == "unavailable"
        assert validated["transport"]["http_status"] == 200


def test_schema_pins_every_case_identity_field() -> None:
    schema = json.loads(
        Path("benchmarks/providers/sourcegraph_public_case_v1.schema.json").read_text()
    )
    case_properties = schema["properties"]["case"]["properties"]
    for field, value in CASE.items():
        assert case_properties[field]["const"] == value


def test_available_requires_the_existing_provider_evidence_envelope() -> None:
    with pytest.raises(PublicCaseProtocolError, match="available results require"):
        validate_result(result(status="available", error=None))
    evidence = {
        "kind": "reverse_reference",
        "binding": {},
        "evidence": [],
        "receipt": {},
        "validation": {
            "status": "schema_validated_supplied_evidence",
            "provider_authenticated": False,
            "scorable": False,
        },
    }
    validated = validate_result(
        result(status="available", error=None, provider_evidence=evidence),
    )
    assert validated["provider_evidence"] == evidence


def test_protocol_rejects_case_drift_and_budget_overrun() -> None:
    with pytest.raises(PublicCaseProtocolError, match="case identity"):
        validate_result(result(case={**CASE, "revision": "f" * 40}))
    transport = result()["transport"]
    assert isinstance(transport, dict)
    with pytest.raises(PublicCaseProtocolError, match="transport limits"):
        validate_result(result(transport={**transport, "response_bytes": 2_097_153}))


@pytest.mark.parametrize("field", ["operation", "status"])
@pytest.mark.parametrize("invalid", [["available"], {"value": "available"}])
def test_protocol_rejects_non_string_membership_values(field: str, invalid: object) -> None:
    with pytest.raises(PublicCaseProtocolError):
        validate_result(result(**{field: invalid}))


@pytest.mark.parametrize("protocol_version", [True, False, 1.0, "1", [], {}, None])
def test_protocol_rejects_non_exact_protocol_version(protocol_version: object) -> None:
    with pytest.raises(PublicCaseProtocolError, match="unsupported protocol version"):
        validate_result(result(protocol_version=protocol_version))


@pytest.mark.parametrize(
    "http_status",
    [[200], {"value": 200}, "200", True, 99, 600],
)
def test_protocol_rejects_invalid_http_status(http_status: object) -> None:
    transport = result()["transport"]
    assert isinstance(transport, dict)
    with pytest.raises(PublicCaseProtocolError, match="transport limits"):
        validate_result(result(transport={**transport, "http_status": http_status}))


@pytest.mark.parametrize("http_status", [None, 100, 200, 599])
def test_protocol_accepts_schema_valid_http_status(http_status: object) -> None:
    transport = result()["transport"]
    assert isinstance(transport, dict)
    validate_result(result(transport={**transport, "http_status": http_status}))


def test_result_protocol_has_no_network_or_provider_imports() -> None:
    source = Path("benchmarks/providers/sourcegraph_public_case.py").read_text()
    tree = ast.parse(source)
    imports = {
        alias.name.split(".", maxsplit=1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        node.module.split(".", maxsplit=1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    )
    assert imports <= {"__future__", "typing"}
