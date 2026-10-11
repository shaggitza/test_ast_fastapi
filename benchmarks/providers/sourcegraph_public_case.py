"""Versioned untrusted result protocol for one bounded Sourcegraph public case."""

from __future__ import annotations

from typing import Any


class PublicCaseProtocolError(ValueError):
    """A public-case result is malformed or does not match its frozen identity."""


_OPERATIONS = {"index_revision_status", "reverse_reference", "call_chain"}
_STATUSES = {"available", "unavailable", "error"}
FROZEN_CASE_PROFILE = {
    "profile": "gh20-sourcegraph-public-case-r3-v1",
    "source_lock": "benchmarks/real_world/corpus.json",
    "source_lock_git_blob": "c34f08548ab7e70c805dac5e3373c16a427ad32b",
    "source_lock_sha256": "7c4ecfd562d2e01079a955e8214afd4e9e1a408f73ed392d4606eecbc649f062",
    "source_record": "open-webui/open-webui#26924",
    "repository": "open-webui/open-webui",
    "revision": "0f8846b7fc8c210945366defbd1ed941b039a691",
    "path": "backend/open_webui/utils/security_headers.py",
    "symbol": "SecurityHeadersMiddleware",
}


def validate_result(value: object) -> dict[str, Any]:  # noqa: PLR0912
    """Validate protocol v1 without converting unavailable results into empty evidence."""
    required = {
        "protocol_version",
        "case",
        "operation",
        "status",
        "transport",
        "endpoint",
        "request",
        "response_raw",
        "error",
        "provider_evidence",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise PublicCaseProtocolError("result fields do not match protocol v1")
    if value["protocol_version"] != 1:
        raise PublicCaseProtocolError("unsupported protocol version")
    if value["case"] != FROZEN_CASE_PROFILE:
        raise PublicCaseProtocolError("case identity differs from frozen profile")
    operation = value["operation"]
    if not isinstance(operation, str) or operation not in _OPERATIONS:
        raise PublicCaseProtocolError("unsupported provider operation")
    result_status = value["status"]
    if not isinstance(result_status, str) or result_status not in _STATUSES:
        raise PublicCaseProtocolError("unsupported result status")
    if not isinstance(value["request"], str) or not value["request"]:
        raise PublicCaseProtocolError("exact request is required")
    if value["endpoint"] != "https://sourcegraph.com/.api/graphql":
        raise PublicCaseProtocolError("endpoint is outside the pinned public service")
    response = value["response_raw"]
    if response is not None and not isinstance(response, str):
        raise PublicCaseProtocolError("raw response must be text or null")
    transport = value["transport"]
    if not isinstance(transport, dict) or set(transport) != {
        "http_status",
        "elapsed_seconds",
        "response_bytes",
        "truncated",
        "redirects",
    }:
        raise PublicCaseProtocolError("transport record is incomplete")
    elapsed = transport["elapsed_seconds"]
    size = transport["response_bytes"]
    redirects = transport["redirects"]
    http_status = transport["http_status"]
    if http_status is not None and (type(http_status) is not int or not 100 <= http_status <= 599):
        raise PublicCaseProtocolError("transport limits are violated")
    if (
        isinstance(elapsed, bool)
        or not isinstance(elapsed, (int, float))
        or not 0 <= elapsed <= 12
        or type(size) is not int
        or not 0 <= size <= 2 * 1024 * 1024
        or type(redirects) is not int
        or not 0 <= redirects <= 2
        or transport["truncated"] is not False
    ):
        raise PublicCaseProtocolError("transport limits are violated")
    status = value["status"]
    if status == "available":
        envelope = value["provider_evidence"]
        if (
            not isinstance(envelope, dict)
            or not {"kind", "binding", "evidence", "receipt", "validation"}.issubset(envelope)
            or envelope.get("validation")
            != {
                "status": "schema_validated_supplied_evidence",
                "provider_authenticated": False,
                "scorable": False,
            }
            or response is None
            or value["error"] is not None
        ):
            raise PublicCaseProtocolError(
                "available results require supplied evidence and raw response"
            )
    elif (
        value["provider_evidence"] is not None
        or not isinstance(value["error"], str)
        or not value["error"]
    ):
        raise PublicCaseProtocolError(
            "unavailable/error results require a typed error and no evidence"
        )
    return value
