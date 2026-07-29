"""Frozen secure/runtime comparison protocol tests."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
from benchmarks.real_world import compare_runtime
from benchmarks.real_world.compare_runtime import (
    ComparisonError,
    compare,
    compare_target_baseline,
    main,
)

if TYPE_CHECKING:
    from pathlib import Path

H = "sha256:" + "a" * 64


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _record(
    mode: str,
    *,
    snapshot: str = "target",
    lock: str = H,
    measured: bool = True,
) -> dict[str, Any]:
    inventory = {
        "inventory_status": "established" if mode == "secure" else "runtime_observed",
        "endpoints": [
            {"methods": ["GET"], "path": "/users/{user_id}", "surface": None},
            {"methods": ["POST"], "path": "/jobs", "surface": None},
        ],
    }
    impact = {
        "candidate_endpoints": [
            {
                "endpoint": {
                    "methods": ["GET"],
                    "path": "/users/{user_id}" if mode == "secure" else "/users/{id}",
                    "surface": None,
                }
            }
        ]
    }
    state: dict[str, object]
    resource: dict[str, object]
    if measured:
        state = {"status": "measured", "seconds": 1.0}
        resource = {"status": "measured", "bytes": 104857600}
    else:
        state = {"status": "not_measured", "reason": "collector_unavailable"}
        resource = {"status": "not_measured", "reason": "collector_unavailable"}
    configuration: dict[str, object] = {
        "app_entry": None,
        "bootstrap_entry": None,
        "app_variable": "app",
        "backend": "mypy",
        "dependency_lock_sha256": lock,
    }
    source = _digest("b" if snapshot == "target" else "c")
    image = f"registry.example/detector@{_digest('d' if snapshot == 'target' else 'e')}"
    provenance = {
        "source_sha256": source,
        "tool_sha256": _digest("f"),
        "effective_invocation_sha256": _digest("1" if mode == "secure" else "2"),
        "dependency_lock_sha256": lock,
        "runtime_image_digest": image,
        "runtime_sbom_sha256": _digest("3" if snapshot == "target" else "4"),
    }
    if mode == "runtime":
        provenance.update(
            runtime_seccomp_sha256=_digest("5"),
            runtime_policy_sha256=_digest("6"),
        )
    return {
        "schema_version": 1,
        "mode": mode,
        "snapshot": snapshot,
        "status": "success",
        "configuration": configuration,
        "timing": {"list": dict(state), "impact": dict(state)},
        "resources": {"peak_rss_bytes": resource},
        "failure": None,
        "inventory": inventory,
        "impact": impact,
        "provenance": provenance,
    }


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def _matrix_paths(tmp_path: Path) -> dict[tuple[str, str], Path]:
    paths: dict[tuple[str, str], Path] = {}
    for snapshot in ("target", "baseline"):
        lock = _digest("7" if snapshot == "target" else "8")
        for mode in ("secure", "runtime"):
            path = tmp_path / f"{mode}-{snapshot}.json"
            _write(path, _record(mode, snapshot=snapshot, lock=lock))
            paths[(snapshot, mode)] = path
    return paths


def _compare_matrix(paths: dict[tuple[str, str], Path]) -> dict[str, Any]:
    return compare_target_baseline(
        secure_target_path=paths[("target", "secure")],
        runtime_target_path=paths[("target", "runtime")],
        secure_baseline_path=paths[("baseline", "secure")],
        runtime_baseline_path=paths[("baseline", "runtime")],
    )


def _cli_arguments(paths: dict[tuple[str, str], Path], output: Path) -> list[str]:
    return [
        "--secure-target",
        str(paths[("target", "secure")]),
        "--runtime-target",
        str(paths[("target", "runtime")]),
        "--secure-baseline",
        str(paths[("baseline", "secure")]),
        "--runtime-baseline",
        str(paths[("baseline", "runtime")]),
        "--output",
        str(output),
    ]


def test_paired_success_preserves_exact_and_normalized_metrics(tmp_path: Path) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    _write(secure, _record("secure"))
    runtime_record = _record("runtime")
    runtime_record["inventory"]["endpoints"].append(
        {"methods": ["DELETE"], "path": "/runtime-only", "surface": None}
    )
    _write(runtime, runtime_record)

    result = compare(secure, runtime)

    assert result["runtime_role"] == "positive_observation_comparator_not_truth"
    assert result["paired_success"] is True
    assert result["quality_eligible"] is True
    assert result["inventory"]["runtime_only"] == ["DELETE /runtime-only"]
    assert result["inventory"]["interpretation"] == "requires_source_adjudication"
    assert result["impact_exact"]["intersection_count"] == 0
    assert result["impact_normalized"]["intersection_count"] == 1
    assert result["inventory_strength"] == {
        "secure": "established",
        "runtime": "runtime_observed",
    }
    assert result["provenance_digests"]["runtime"].startswith("sha256:")


def test_failure_phase_abstains_from_quality_metrics(tmp_path: Path) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    _write(secure, _record("secure"))
    failed = _record("runtime")
    failed.update(
        status="failure",
        failure={"phase": "import", "message": "missing dependency"},
        inventory=None,
        impact=None,
    )
    _write(runtime, failed)

    result = compare(secure, runtime)

    assert result["paired_success"] is False
    assert result["quality_eligible"] is False
    assert result["inventory"] is None
    assert result["failure"]["runtime"]["phase"] == "import"


@pytest.mark.parametrize("field", ["app_entry", "bootstrap_entry"])
def test_runtime_rejects_unsupported_entry_selection(tmp_path: Path, field: str) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    secure_record = _record("secure")
    runtime_record = _record("runtime")
    secure_record["configuration"][field] = "main:create_app"
    runtime_record["configuration"][field] = "main:create_app"
    _write(secure, secure_record)
    _write(runtime, runtime_record)

    with pytest.raises(ComparisonError, match="do not support"):
        compare(secure, runtime)


@pytest.mark.parametrize("mode", ["secure", "runtime"])
def test_absent_provenance_fails_closed(tmp_path: Path, mode: str) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    records = {name: _record(name) for name in ("secure", "runtime")}
    records[mode].pop("provenance")
    _write(secure, records["secure"])
    _write(runtime, records["runtime"])

    with pytest.raises(ComparisonError, match="missing required"):
        compare(secure, runtime)


def test_spoofed_mode_or_digest_provenance_fails_closed(tmp_path: Path) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    secure_record = _record("secure")
    runtime_record = _record("runtime")
    runtime_record["provenance"] = dict(secure_record["provenance"])
    _write(secure, secure_record)
    _write(runtime, runtime_record)
    with pytest.raises(ComparisonError, match="mode-specific"):
        compare(secure, runtime)

    runtime_record = _record("runtime")
    runtime_record["provenance"]["runtime_policy_sha256"] = "sha256:" + "A" * 64
    _write(runtime, runtime_record)
    with pytest.raises(ComparisonError, match="lowercase sha256"):
        compare(secure, runtime)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("timing", {"arbitrary": {"status": "measured", "seconds": 1}}),
        ("timing", {"list": {"status": "invented"}, "impact": {"status": "invented"}}),
        ("resources", {"rss_mib": 100}),
    ],
)
def test_arbitrary_telemetry_fails_closed(
    tmp_path: Path, field: str, value: object
) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    secure_record = _record("secure")
    secure_record[field] = value
    _write(secure, secure_record)
    _write(runtime, _record("runtime"))

    with pytest.raises(ComparisonError):
        compare(secure, runtime)


@pytest.mark.parametrize(
    ("mode", "status"),
    [("secure", "invented"), ("runtime", "established"), ("runtime", "invented")],
)
def test_arbitrary_inventory_status_fails_closed(
    tmp_path: Path, mode: str, status: str
) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    records = {name: _record(name) for name in ("secure", "runtime")}
    records[mode]["inventory"]["inventory_status"] = status
    _write(secure, records["secure"])
    _write(runtime, records["runtime"])

    with pytest.raises(ComparisonError, match="inventory status"):
        compare(secure, runtime)


def test_not_measured_attestations_suppress_quality_but_remain_operational(
    tmp_path: Path,
) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    _write(secure, _record("secure", measured=False))
    _write(runtime, _record("runtime"))

    result = compare(secure, runtime)

    assert result["paired_success"] is True
    assert result["quality_eligible"] is False
    assert result["inventory"] is None
    assert result["timing"]["secure"]["list"]["status"] == "not_measured"


@pytest.mark.parametrize(
    "phase",
    ["dependency", "import", "app_resolution", "extraction", "timeout", "unavailable"],
)
def test_all_failure_phases_are_versioned(tmp_path: Path, phase: str) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    first = _record("secure")
    second = _record("runtime")
    for record in (first, second):
        record.update(
            status="failure",
            failure={"phase": phase, "message": "abstain"},
            inventory=None,
            impact=None,
        )
    _write(secure, first)
    _write(runtime, second)

    assert compare(secure, runtime)["paired_success"] is False


@pytest.mark.parametrize("invalid", [True, float("nan"), float("inf"), -1.0])
def test_measurement_rejects_bool_non_finite_and_negative_values(
    tmp_path: Path, invalid: object
) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    secure_record = _record("secure")
    secure_record["timing"]["impact"] = {"status": "measured", "seconds": invalid}
    _write(secure, secure_record)
    _write(runtime, _record("runtime"))

    with pytest.raises(ComparisonError):
        compare(secure, runtime)


def test_comparison_rejects_duplicate_json_members(tmp_path: Path) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    secure.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
    _write(runtime, _record("runtime"))

    with pytest.raises(ComparisonError, match="duplicate JSON member"):
        compare(secure, runtime)


def test_target_baseline_permits_snapshot_specific_environments(tmp_path: Path) -> None:
    paths = _matrix_paths(tmp_path)

    result = _compare_matrix(paths)

    assert result["configuration"]["snapshots"]["target"]["dependency_lock_sha256"] != result[
        "configuration"
    ]["snapshots"]["baseline"]["dependency_lock_sha256"]
    assert result["operational"]["peak_rss_bytes"] == {
        "secure": {"status": "measured", "bytes": 104857600},
        "runtime": {"status": "measured", "bytes": 104857600},
    }
    assert result["paired_success_quality"]["eligible_snapshots"] == ["target", "baseline"]
    assert set(result["provenance_digests"]) == {"target", "baseline"}


def test_matrix_rejects_within_snapshot_environment_mismatch(tmp_path: Path) -> None:
    paths = _matrix_paths(tmp_path)
    runtime = _record("runtime", snapshot="target", lock=_digest("9"))
    _write(paths[("target", "runtime")], runtime)

    with pytest.raises(ComparisonError, match="snapshot configuration"):
        _compare_matrix(paths)

    runtime = _record("runtime", snapshot="target", lock=_digest("7"))
    runtime["provenance"]["runtime_sbom_sha256"] = _digest("0")
    _write(paths[("target", "runtime")], runtime)
    with pytest.raises(ComparisonError, match="runtime_sbom_sha256"):
        _compare_matrix(paths)


def test_matrix_keeps_failures_operational_and_excludes_them_from_quality(
    tmp_path: Path,
) -> None:
    paths = _matrix_paths(tmp_path)
    failed = _record("runtime", snapshot="baseline", lock=_digest("8"))
    failed.update(
        status="failure",
        failure={"phase": "dependency", "message": "lock install failed"},
        inventory=None,
        impact=None,
    )
    _write(paths[("baseline", "runtime")], failed)

    result = _compare_matrix(paths)

    assert result["operational"]["success_count"] == {"secure": 2, "runtime": 1}
    assert result["operational"]["failure_phase_counts"]["runtime"] == {"dependency": 1}
    assert result["paired_success_quality"]["eligible_snapshots"] == ["target"]
    assert result["lifecycle"]["runtime"] is None


def test_matrix_rejects_snapshot_or_entry_configuration_mismatch(tmp_path: Path) -> None:
    paths = _matrix_paths(tmp_path)
    record = _record("secure", snapshot="target", lock=_digest("8"))
    _write(paths[("baseline", "secure")], record)
    with pytest.raises(ComparisonError, match="declares target"):
        _compare_matrix(paths)

    record = _record("secure", snapshot="baseline", lock=_digest("8"))
    record["configuration"]["app_variable"] = "application"
    _write(paths[("baseline", "secure")], record)
    with pytest.raises(ComparisonError, match="snapshot configuration"):
        _compare_matrix(paths)


def test_duplicate_or_malformed_endpoint_rows_fail_closed(tmp_path: Path) -> None:
    secure = tmp_path / "secure.json"
    runtime = tmp_path / "runtime.json"
    secure_record = _record("secure")
    secure_record["inventory"]["endpoints"].append(
        {"methods": ["GET"], "path": "/users/{user_id}", "surface": None}
    )
    _write(secure, secure_record)
    _write(runtime, _record("runtime"))
    with pytest.raises(ComparisonError, match="duplicate inventory"):
        compare(secure, runtime)

    secure_record = _record("secure")
    secure_record["impact"]["candidate_endpoints"] = ["bad"]
    _write(secure, secure_record)
    with pytest.raises(ComparisonError, match="endpoint objects"):
        compare(secure, runtime)


def test_cli_matrix_is_no_clobber(tmp_path: Path) -> None:
    paths = _matrix_paths(tmp_path)
    output = tmp_path / "comparison.json"
    arguments = _cli_arguments(paths, output)

    assert main(arguments) == 0
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["runtime_role"] == "positive_observation_comparator_not_truth"
    with pytest.raises(SystemExit) as raised:
        main(arguments)
    assert raised.value.code == 2


def test_cli_rejects_existing_and_absent_frozen_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _matrix_paths(tmp_path)
    existing = tmp_path / "frozen.json"
    existing.write_text("frozen", encoding="utf-8")
    absent = tmp_path / "absent-frozen.json"
    monkeypatch.setattr(compare_runtime, "_FROZEN_FILES", (existing, absent))
    monkeypatch.setattr(compare_runtime, "_FROZEN_ROOTS", ())

    for output in (existing, absent):
        with pytest.raises(SystemExit) as raised:
            main(_cli_arguments(paths, output))
        assert raised.value.code == 2
        assert not absent.exists()
    assert existing.read_text(encoding="utf-8") == "frozen"


def test_cli_rejects_frozen_root_and_symlinked_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _matrix_paths(tmp_path)
    frozen_root = tmp_path / "results"
    frozen_root.mkdir()
    alias = tmp_path / "results-alias"
    alias.symlink_to(frozen_root, target_is_directory=True)
    monkeypatch.setattr(compare_runtime, "_FROZEN_FILES", ())
    monkeypatch.setattr(compare_runtime, "_FROZEN_ROOTS", (frozen_root,))

    for output in (frozen_root / "new.json", alias / "new.json"):
        with pytest.raises(SystemExit) as raised:
            main(_cli_arguments(paths, output))
        assert raised.value.code == 2
        assert not (frozen_root / "new.json").exists()
