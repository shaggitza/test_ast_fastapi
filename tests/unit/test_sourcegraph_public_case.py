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
RAW_RESPONSE = '{"errors":[{"message":"not authenticated"}],"data":{"repository":null}}'


def result(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "protocol_version": 1,
        "case": CASE.copy(),
        "operation": "index_revision_status",
        "status": "unavailable",
        "transport": {
            "http_status": 200,
            "elapsed_seconds": 0.527802,
            "response_bytes": len(RAW_RESPONSE.encode("utf-8")),
            "truncated": False,
            "redirects": 0,
        },
        "endpoint": "https://sourcegraph.com/.api/graphql",
        "request": '{"query":"frozen exact query"}',
        "response_raw": RAW_RESPONSE,
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


def available_result() -> dict[str, object]:
    return result(
        status="available",
        error=None,
        provider_evidence={
            "kind": "reverse_reference",
            "binding": {key: CASE[key] for key in ("repository", "revision", "path", "symbol")},
            "evidence": [],
            "receipt": {},
            "validation": {
                "status": "schema_validated_supplied_evidence",
                "provider_authenticated": False,
                "scorable": False,
            },
        },
    )


def test_available_requires_reviewed_frozen_v1_receipt() -> None:
    with pytest.raises(PublicCaseProtocolError, match="available results require"):
        validate_result(result(status="available", error=None))
    assert protocol.FROZEN_AVAILABLE_RESULT_SHA256_V1 == {}
    with pytest.raises(PublicCaseProtocolError, match="not a frozen v1 receipt"):
        validate_result(available_result())


@pytest.mark.parametrize("field", ["repository", "revision", "path", "symbol"])
def test_available_binding_rejects_different_frozen_source_identity(field: str) -> None:
    value = available_result()
    envelope = value["provider_evidence"]
    assert isinstance(envelope, dict)
    envelope["binding"][field] = "different"
    with pytest.raises(PublicCaseProtocolError, match="frozen case identity"):
        validate_result(value)


@pytest.mark.parametrize("binding", [{}, {"repository": CASE["repository"]}])
def test_available_binding_requires_every_frozen_identity_field(binding: object) -> None:
    value = available_result()
    envelope = value["provider_evidence"]
    assert isinstance(envelope, dict)
    envelope["binding"] = binding
    with pytest.raises(PublicCaseProtocolError, match="frozen case identity"):
        validate_result(value)


def test_self_issued_marker_and_receipt_are_not_a_frozen_result() -> None:
    value = available_result()
    envelope = value["provider_evidence"]
    assert isinstance(envelope, dict)
    envelope["evidence"] = [{"symbol": CASE["symbol"]}]
    envelope["receipt"] = {
        "response_sha256": "a" * 64,
        "provider": "sourcegraph",
        "status": "schema_validated_supplied_evidence",
    }
    with pytest.raises(PublicCaseProtocolError, match="not a frozen v1 receipt"):
        validate_result(value)


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("kind", []),
        ("kind", "unsupported"),
        ("binding", []),
        ("evidence", {}),
        ("receipt", []),
        ("validation", []),
        (
            "validation",
            {
                "status": "schema_validated_supplied_evidence",
                "provider_authenticated": 0,
                "scorable": False,
            },
        ),
        (
            "validation",
            {
                "status": "schema_validated_supplied_evidence",
                "provider_authenticated": False,
                "scorable": 0,
            },
        ),
        (
            "validation",
            {
                "status": "schema_validated_supplied_evidence",
                "provider_authenticated": False,
                "scorable": False,
                "extra": True,
            },
        ),
    ],
)
def test_available_evidence_envelope_matches_schema_types_and_exact_validation(
    field: str, invalid: object
) -> None:
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
    evidence[field] = invalid
    with pytest.raises(PublicCaseProtocolError, match="available results require"):
        validate_result(result(status="available", error=None, provider_evidence=evidence))


def test_raw_response_size_matches_strict_utf8_bytes() -> None:
    with pytest.raises(PublicCaseProtocolError, match="transport limits"):
        validate_result(result(transport={**result()["transport"], "response_bytes": 112}))
    validate_result(
        result(
            response_raw="é",
            transport={**result()["transport"], "response_bytes": 2},
        )
    )


def test_raw_response_byte_limit_and_invalid_unicode_fail_closed() -> None:
    with pytest.raises(PublicCaseProtocolError, match="raw response exceeds"):
        validate_result(result(response_raw="x" * (2 * 1024 * 1024 + 1)))
    with pytest.raises(PublicCaseProtocolError, match="valid UTF-8"):
        validate_result(
            result(
                response_raw="\ud800",
                transport={**result()["transport"], "response_bytes": 0},
            )
        )


def test_null_raw_response_requires_zero_response_bytes() -> None:
    value = result(status="unavailable", response_raw=None)
    transport = value["transport"]
    assert isinstance(transport, dict)
    transport["response_bytes"] = 0
    assert validate_result(value)["response_raw"] is None
    with pytest.raises(PublicCaseProtocolError, match="transport limits"):
        transport["response_bytes"] = 1
        validate_result(value)


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
    assert imports <= {"__future__", "hashlib", "json", "typing"}


def test_schema_admits_only_current_frozen_unavailable_or_error_records() -> None:
    schema = json.loads(
        Path("benchmarks/providers/sourcegraph_public_case_v1.schema.json").read_text()
    )
    assert set(schema["properties"]["status"]["enum"]) == {"unavailable", "error"}
    binding = schema["properties"]["provider_evidence"]["properties"]["binding"]
    assert binding["additionalProperties"] is False
    assert set(binding["required"]) == {"repository", "revision", "path", "symbol"}
    assert {
        field: declaration["const"] for field, declaration in binding["properties"].items()
    } == {key: CASE[key] for key in ("repository", "revision", "path", "symbol")}
