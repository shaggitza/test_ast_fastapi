"""Bounded smoke test for the explicit 10k resource scale benchmark."""

import pytest
from benchmarks.resource_coupling_scale import build_fixture, run_scale


def test_scale_fixture_preserves_closed_directions_and_determinism() -> None:
    result = run_scale(40)

    assert result["occurrences"] == 40
    assert result["edges"] == 20
    assert result["diagnostics"] == 0
    assert result["operation_directions"] == ["publish->consume", "write->read"]
    assert result["determinism_verified"] is True


def test_scale_fixture_rejects_partial_role_sets() -> None:
    with pytest.raises(ValueError, match="divisible by four"):
        build_fixture(10)
