"""Controlled authority fixtures exercise the protocol, not runtime attestation."""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest
from pydantic import ValidationError

from fastapi_endpoint_detector.analyzer.runtime_custody import (
    CustodyBinding,
    RuntimeCustodyAuthority,
    RuntimeCustodyError,
    RuntimeCustodyReceipt,
    custody_digest,
    verify_runtime_custody,
)

_AUTHORITY = RuntimeCustodyAuthority("controlled-authority", b"k" * 32, "controlled-runsc")
_NOW = 1_800_000_000
_RESULT = {"execution_status": "completed", "observed": [{"phase": "startup"}]}


def _binding() -> CustodyBinding:
    return CustodyBinding(
        snapshot="target",
        phase="lifespan",
        nonce="a" * 32,
        request_sha256="sha256:" + "b" * 64,
        manifest_sha256="sha256:" + "c" * 64,
        canary_receipt_sha256="sha256:" + "d" * 64,
        runtime_version=_AUTHORITY.runtime_version,
    )


def _signed(*, binding: CustodyBinding | None = None, **changes: object) -> dict[str, object]:
    body: dict[str, object] = {
        "binding": (binding or _binding()).model_dump(mode="json"),
        "result_sha256": custody_digest(_RESULT),
        "key_id": _AUTHORITY.key_id,
        "issued_at": _NOW - 1,
        "expires_at": _NOW + 60,
        **changes,
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return {
        **body,
        "signature": hmac.new(_AUTHORITY.secret, canonical, hashlib.sha256).hexdigest(),
    }


def _verify(receipt: object, result: object = _RESULT) -> RuntimeCustodyReceipt:
    return verify_runtime_custody(
        receipt, expected=_binding(), result=result, authority=_AUTHORITY, now=_NOW
    )


def test_exact_authority_signed_challenge_and_result_are_accepted() -> None:
    assert _verify(_signed()).result_sha256 == custody_digest(_RESULT)


@pytest.mark.parametrize(
    "changes",
    [
        {"nonce": "e" * 32},
        {"snapshot": "baseline"},
        {"manifest_sha256": "sha256:" + "e" * 64},
        {"request_sha256": "sha256:" + "e" * 64},
        {"canary_receipt_sha256": "sha256:" + "e" * 64},
        {"runtime_version": "other-runtime"},
    ],
)
def test_valid_signatures_cannot_replay_another_invocation(changes: dict[str, object]) -> None:
    binding = CustodyBinding.model_validate({**_binding().model_dump(mode="json"), **changes})
    with pytest.raises(RuntimeCustodyError, match="host challenge"):
        _verify(_signed(binding=binding))


def test_changed_or_omitted_observations_do_not_match_the_signed_result() -> None:
    with pytest.raises(RuntimeCustodyError, match="broker-signed result"):
        _verify(_signed(), {"execution_status": "completed", "observed": []})


def test_worker_cannot_supply_its_own_authority() -> None:
    with pytest.raises(RuntimeCustodyError, match="host challenge"):
        _verify(_signed(key_id="worker-selected-authority"))
    receipt = _signed()
    receipt["secret"] = "worker-selected-key"
    with pytest.raises(RuntimeCustodyError, match="schema"):
        _verify(receipt)


@pytest.mark.parametrize(
    "changes",
    [
        {"issued_at": _NOW + 1},
        {"expires_at": _NOW},
        {"expires_at": _NOW + 3600},
        {"issued_at": True},
        {"issued_at": float(_NOW - 1)},
    ],
)
def test_resigned_invalid_validity_and_timestamp_types_are_rejected(
    changes: dict[str, object],
) -> None:
    with pytest.raises(RuntimeCustodyError):
        _verify(_signed(**changes))


def test_invalid_signature_and_nonfinite_results_are_rejected() -> None:
    with pytest.raises(RuntimeCustodyError, match="signature"):
        _verify({**_signed(), "signature": "f" * 64})
    with pytest.raises(RuntimeCustodyError, match="finite JSON"):
        _verify(_signed(), {"observation": float("nan")})


def test_lifespan_manifest_is_required_and_other_phases_reject_it() -> None:
    for changes in ({"manifest_sha256": None}, {"phase": "impact"}):
        with pytest.raises(ValidationError, match="manifest"):
            CustodyBinding.model_validate({**_binding().model_dump(mode="json"), **changes})
