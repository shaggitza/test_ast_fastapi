"""Trusted generated-DAG benchmark for retained typed mypy state (no third-party corpus)."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
import uuid
from importlib.metadata import version
from pathlib import Path

try:
    import resource
except ImportError:  # pragma: no cover - unavailable on Windows
    resource = None  # type: ignore[assignment]

from fastapi_endpoint_detector.analyzer.mypy_incremental import (
    BuildConfig,
    MypyIncrementalProvider,
    TypedBuild,
)

MIN_DAG_MODULES = 4


def make_dag(root: Path, modules: int) -> dict[str, Path]:
    for index in range(modules):
        imported = f"from m{index + 1} import f{index + 1}\n" if index + 1 < modules else ""
        called = (
            f"    return f{index + 1}(value)\n" if index + 1 < modules else "    return value\n"
        )
        (root / f"m{index}.py").write_text(
            f"{imported}\ndef f{index}(value: int) -> int:\n{called}", encoding="utf-8"
        )
    return {path.stem: path for path in root.glob("*.py")}


def retarget_import_source(source: str, changed_index: int, modules: int) -> str:
    """Retarget a generated DAG edge to a different in-inventory module."""
    if modules < MIN_DAG_MODULES:
        raise ValueError(f"retarget controls require at least {MIN_DAG_MODULES} modules")
    original_target = changed_index + 1
    retarget_index = (changed_index + 2) % modules
    if retarget_index == original_target:
        raise ValueError("retarget controls require two distinct outgoing targets")
    original_import = f"from m{original_target} import f{original_target}"
    retargeted_import = f"from m{retarget_index} import f{retarget_index}"
    retargeted = source.replace(original_import, retargeted_import).replace(
        f"f{original_target}(value)", f"f{retarget_index}(value)"
    )
    if retargeted == source:
        raise ValueError("import-retarget fixture did not change source")
    return retargeted


def p95(samples: list[float]) -> float:
    ordered = sorted(samples)
    return ordered[max(0, int(0.95 * len(ordered) + 0.999999) - 1)]


def timing_summary(samples: list[float]) -> dict[str, object]:
    return {
        "samples": samples,
        "p50": statistics.median(samples),
        "p95": p95(samples),
        "max": max(samples),
    }


def git_value(*args: str) -> str | None:
    try:
        return subprocess.check_output(["git", *args], text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def source_receipt(paths: list[Path]) -> list[dict[str, str]]:
    return [
        {
            "path": path.as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in paths
    ]


def _equivalence_passed(record: dict[str, object]) -> bool:
    equivalence = record.get("cold_equivalence")
    return (
        isinstance(equivalence, dict)
        and equivalence.get("equivalent_to_independent_cold_build") is True
        and equivalence.get("cache_fingerprint_matches_independent_cold_build") is True
    )


def _rss_stats() -> dict[str, int | None]:
    current: int | None = None
    peak: int | None = None
    try:
        fields = {}
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith(("VmRSS:", "VmHWM:")):
                key, value, unit = line.split()
                fields[key.rstrip(":")] = int(value) * (1024 if unit == "kB" else 1)
        current = fields.get("VmRSS")
        peak = fields.get("VmHWM")
    except (OSError, ValueError):
        try:
            resident_pages = int(Path("/proc/self/statm").read_text().split()[1])
            current = resident_pages * int(os.sysconf("SC_PAGE_SIZE"))
        except (OSError, ValueError, IndexError, AttributeError):
            pass
    try:
        if peak is not None:
            return {"current_rss_bytes": current, "process_peak_rss_bytes": peak}
        if resource is None:
            raise RuntimeError("resource module unavailable")
        peak = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        if sys.platform != "darwin":
            peak *= 1024
    except (AttributeError, OSError, RuntimeError):
        pass
    return {"current_rss_bytes": current, "process_peak_rss_bytes": peak}


def _cache_stats(state: TypedBuild) -> dict[str, int]:
    manager = state.manager.manager
    fscache = manager.fscache
    return {
        "retained_module_count": len(state.modules),
        "typed_expression_count": len(manager.all_types),
        "ast_cache_entries": len(manager.ast_cache),
        "filesystem_cached_files": len(fscache.read_cache),
        "filesystem_cached_bytes": sum(len(content) for content in fscache.read_cache.values()),
        "filesystem_hash_entries": len(fscache.hash_cache),
    }


def _source_hashes(report: object, field: str) -> list[dict[str, str]]:
    return [{"module": module, "sha256": digest} for module, digest in getattr(report, field)]


def _equivalence_check(
    config: BuildConfig, inventory: dict[str, Path], state: TypedBuild
) -> dict[str, object]:
    started = time.perf_counter()
    fresh = MypyIncrementalProvider(config).build(inventory)
    elapsed = time.perf_counter() - started
    equivalent = state.typed_snapshot() == fresh.typed_snapshot()
    if not equivalent:
        raise RuntimeError("retained typed snapshot differs from independent cold build")
    fingerprint_matches = state.report.cache_fingerprint == fresh.report.cache_fingerprint
    if not fingerprint_matches:
        raise RuntimeError("retained cache fingerprint differs from independent cold build")
    return {
        "equivalent_to_independent_cold_build": True,
        "cache_fingerprint_matches_independent_cold_build": True,
        "python_version": config.python_version,
        "cold_build_seconds": elapsed,
        "fresh_cache_fingerprint": fresh.report.cache_fingerprint,
    }


def _phase_record(
    state: TypedBuild,
    elapsed: float,
    rss_before: dict[str, int | None],
    rss_after: dict[str, int | None],
    equivalence: dict[str, object] | None = None,
) -> dict[str, object]:
    report = state.report
    return {
        "seconds": elapsed,
        "mode": report.mode,
        "reason": report.reason,
        "cache_fingerprint": report.cache_fingerprint,
        "source_sha256_before": _source_hashes(report, "source_digests_before"),
        "source_sha256_after": _source_hashes(report, "source_digests_after"),
        "rss_before": rss_before,
        "rss_after": rss_after,
        "retained_cache_stats_after": _cache_stats(state),
        "cold_equivalence": equivalence,
    }


def main() -> None:  # noqa: PLR0915
    parser = argparse.ArgumentParser()
    parser.add_argument("--modules", type=int, default=96)
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--python-version", default="3.11")
    args = parser.parse_args()
    if args.modules < MIN_DAG_MODULES:
        parser.error(
            f"--modules must be at least {MIN_DAG_MODULES} for distinct DAG retarget controls"
        )
    if args.samples < 1:
        parser.error("--samples must be at least 1")
    run_id = str(uuid.uuid4())
    cold: list[float] = []
    warm: list[float] = []
    incremental: list[float] = []
    signature_update: list[float] = []
    fallback: list[float] = []
    modes: list[str] = []
    phase_records: dict[str, list[dict[str, object]]] = {
        name: []
        for name in (
            "cold_build",
            "no_change_reuse",
            "incremental_update",
            "signature_update_with_dependency_invalidation",
            "fallback_full_rebuild",
        )
    }
    for _ in range(args.samples):
        with tempfile.TemporaryDirectory(prefix="mypy-dag-") as directory:
            root = Path(directory)
            inventory = make_dag(root, args.modules)
            build_config = BuildConfig(root, python_version=args.python_version)
            source_inventory = [
                {
                    "module": module,
                    "path": path.name,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
                for module, path in sorted(inventory.items())
            ]
            provider = MypyIncrementalProvider(build_config)
            rss_before = _rss_stats()
            started = time.perf_counter()
            state = provider.build(inventory)
            elapsed = time.perf_counter() - started
            cold.append(elapsed)
            phase_records["cold_build"].append(
                _phase_record(state, elapsed, rss_before, _rss_stats())
            )
            rss_before = _rss_stats()
            started = time.perf_counter()
            warm_state = provider.build(inventory)
            elapsed = time.perf_counter() - started
            warm.append(elapsed)
            if warm_state.report.mode != "no_change_reuse":
                raise RuntimeError(
                    f"no-change phase did not reuse typed state: {warm_state.report.mode}"
                )
            phase_records["no_change_reuse"].append(
                _phase_record(warm_state, elapsed, rss_before, _rss_stats())
            )
            changed = root / f"m{args.modules // 2}.py"
            old_source = changed.read_text(encoding="utf-8")
            changed.write_text(old_source.replace("(value)", "(value + 1)"), encoding="utf-8")
            rss_before = _rss_stats()
            started = time.perf_counter()
            update = provider.build(inventory)
            elapsed = time.perf_counter() - started
            incremental.append(elapsed)
            modes.append(update.report.mode)
            if update.report.mode != "incremental_update":
                raise RuntimeError(f"same-interface update fell back: {update.report.reason}")
            phase_records["incremental_update"].append(
                _phase_record(
                    update,
                    elapsed,
                    rss_before,
                    _rss_stats(),
                    _equivalence_check(build_config, inventory, update),
                )
            )
            changed.write_text(
                old_source.replace("value: int", "value: str").replace("-> int", "-> str"),
                encoding="utf-8",
            )
            rss_before = _rss_stats()
            started = time.perf_counter()
            signature = provider.build(inventory)
            elapsed = time.perf_counter() - started
            signature_update.append(elapsed)
            if signature.report.mode != "incremental_update":
                raise RuntimeError("signature change was not processed incrementally")
            changed_index = args.modules // 2
            dependent_prefix = f"m{changed_index - 1}."
            if not any(
                target.startswith(dependent_prefix)
                for target in signature.manager.processed_targets
            ):
                raise RuntimeError("signature change did not recheck an imported caller")
            phase_records["signature_update_with_dependency_invalidation"].append(
                _phase_record(
                    signature,
                    elapsed,
                    rss_before,
                    _rss_stats(),
                    _equivalence_check(build_config, inventory, signature),
                )
            )
            changed_index = args.modules // 2
            retargeted_source = retarget_import_source(
                changed.read_text(encoding="utf-8"), changed_index, args.modules
            )
            changed.write_text(retargeted_source, encoding="utf-8")
            rss_before = _rss_stats()
            started = time.perf_counter()
            rebuilt = provider.build(inventory)
            elapsed = time.perf_counter() - started
            fallback.append(elapsed)
            if rebuilt.report.mode != "fallback_full_rebuild":
                raise RuntimeError("import-retarget negative control did not force full rebuild")
            phase_records["fallback_full_rebuild"].append(
                _phase_record(
                    rebuilt,
                    elapsed,
                    rss_before,
                    _rss_stats(),
                    _equivalence_check(build_config, inventory, rebuilt),
                )
            )
    result = {
        "run_id": run_id,
        "invocation": {
            "argv": [sys.executable, *sys.argv],
            "modules": args.modules,
            "samples": args.samples,
            "python_target": args.python_version,
            "git_revision": git_value("rev-parse", "HEAD"),
            "git_worktree_status": git_value("status", "--porcelain"),
            "uv_lock_sha256": (
                hashlib.sha256(Path("uv.lock").read_bytes()).hexdigest()
                if Path("uv.lock").is_file()
                else None
            ),
            "implementation_source": source_receipt(
                [
                    Path(__file__),
                    Path("src/fastapi_endpoint_detector/analyzer/mypy_incremental.py"),
                    Path("src/fastapi_endpoint_detector/models/endpoint.py"),
                    Path("pyproject.toml"),
                ]
            ),
        },
        "provider": "MypyIncrementalProvider",
        "mypy_version": version("mypy"),
        "supported_engine": "mypy-fine-grained",
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "fixture": {
            "kind": "generated_import_dag",
            "modules": args.modules,
            "one_function_per_module": True,
            "samples": args.samples,
            "source_inventory_scope": "generated_fixture_module_paths_and_initial_sha256",
            "source_inventory": source_inventory,
            "call_chain": [f"m{index}.f{index}" for index in range(args.modules)],
            "call_chain_semantics": (
                "each module calls the next module; last function returns its input"
            ),
            "config": {
                "engine": "mypy-fine-grained",
                "python_version": args.python_version,
                "mypy_options": [],
                "config_file": None,
                "incremental_mode": "retained in-process fine-grained state",
            },
        },
        "seconds": {
            "cold_build": timing_summary(cold),
            "no_change_reuse": timing_summary(warm),
            "incremental_update": timing_summary(incremental),
            "signature_update_with_dependency_invalidation": timing_summary(signature_update),
            "fallback_full_rebuild": timing_summary(fallback),
        },
        "update_modes": modes,
        "phase_provenance": phase_records,
        "incremental_valid": all(mode == "incremental_update" for mode in modes),
        "all_update_phases_match_independent_cold_build": all(
            _equivalence_passed(record)
            for phase, records in phase_records.items()
            if phase not in {"cold_build", "no_change_reuse"}
            for record in records
        ),
        "runtime_gate": {
            "threshold_seconds": 30.0,
            "measured_incremental_p95_seconds": p95(incremental),
            "passed_for_trusted_synthetic_provider_only": (
                all(mode == "incremental_update" for mode in modes)
                and p95(incremental) <= 30.0
                and all(
                    _equivalence_passed(record) for record in phase_records["incremental_update"]
                )
            ),
            "gh283_medium_project_acceptance": "not_established_by_synthetic_fixture",
        },
        "scope": "trusted generated fixture only; not a host-project corpus score",
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
