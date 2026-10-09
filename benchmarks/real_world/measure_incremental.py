#!/usr/bin/env python3
"""Measure analyzer phases on a deterministic, trusted synthetic typed DAG.

This protocol intentionally measures the shipped analyzer. It never opens the
frozen third-party corpus. A changed snapshot is called incremental only when
the backend exposes and proves reuse of invalidated build state.
"""
from __future__ import annotations

import argparse
import faulthandler
import hashlib
import json
import platform
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo

SCHEMA = "incremental-performance-v1"
MODULES = 96


def write_fixture(root: Path, revision: int = 0) -> tuple[Endpoint, dict[str, str], set[str]]:
    """Create a deterministic typed DAG and route, returning hashes and reachability."""
    app = root / "app"
    app.mkdir(parents=True, exist_ok=True)
    initializer = app / "__init__.py"
    initializer.write_text("", encoding="utf-8")
    expected: set[str] = set()
    inventory: dict[str, str] = {"__init__.py": hashlib.sha256(initializer.read_bytes()).hexdigest()}
    # Each node calls up to two prior nodes, producing shared paths and a DAG.
    for i in range(MODULES):
        calls = [j for j in (i - 1, i - 3) if j >= 0]
        body = "\n".join(f"    value += node_{j}()" for j in calls)
        text = "from __future__ import annotations\n\n" + "\n".join(
            f"from app.node_{j} import node_{j}" for j in calls
        ) + f"\n\ndef node_{i}() -> int:\n    value = {i + (revision if i == 48 else 0)}\n{body or '    value += 0'}\n    return value\n"
        path = app / f"node_{i}.py"
        path.write_text(text, encoding="utf-8")
        inventory[path.relative_to(app).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    route = app / "routes.py"
    route.write_text(
        "from app.node_95 import node_95\n\n"
        "def endpoint() -> int:\n    return node_95()\n",
        encoding="utf-8",
    )
    inventory["routes.py"] = hashlib.sha256(route.read_bytes()).hexdigest()
    dead = app / "dead_control.py"
    dead.write_text("def unrelated() -> int:\n    return 7\n", encoding="utf-8")
    inventory["dead_control.py"] = hashlib.sha256(dead.read_bytes()).hexdigest()
    for i in range(MODULES):
        expected.add(f"node_{i}")
    endpoint = Endpoint(
        path="/synthetic", methods=[EndpointMethod.GET],
        handler=HandlerInfo(name="endpoint", module="app.routes", file_path=route, line_number=3),
    )
    return endpoint, inventory, expected


def tree_fingerprint(inventory: dict[str, str]) -> str:
    return hashlib.sha256(json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def cache_fingerprint(analyzer: MypyAnalyzer) -> str:
    return analyzer._cache_fingerprint()[0]


def cache_bytes(path: Path) -> int:
    return path.stat().st_size if path.exists() else 0


def file_sha256(path: Path) -> str | None:
    if not path.exists():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rss_bytes() -> int | None:
    try:
        import resource
        amount = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(amount * (1024 if sys.platform != "darwin" else 1))
    except (ImportError, OSError, ValueError):
        return None


def percentiles(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    def nearest_rank(p: float) -> float:
        return ordered[max(0, int((len(ordered) * p + 0.999999)) - 1)]
    return {"p50": statistics.median(ordered), "p95": nearest_rank(.95), "max": max(ordered)}


def run(repeats: int = 5) -> dict[str, Any]:
    if repeats < 1 or repeats > 30:
        raise ValueError("repeats must be between 1 and 30")
    faulthandler.enable()
    phases: dict[str, list[float]] = {k: [] for k in ("baseline_target_preparation", "cold_build", "warm_no_change", "changed_snapshot_rebuild")}
    resources: list[dict[str, int | None]] = []
    samples: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="gh283-synthetic-") as tmp:
        base = Path(tmp)
        for attempt in range(repeats):
            pair = base / f"pair-{attempt}"
            started = time.perf_counter()
            endpoint, _baseline_hashes, expected = write_fixture(pair / "baseline", 0)
            _target_endpoint, target_hashes, _ = write_fixture(pair / "target", 0)
            prep = time.perf_counter() - started
            phases["baseline_target_preparation"].append(prep)
            target_root = pair / "target" / "app"
            target_endpoint = endpoint.model_copy(update={"handler": endpoint.handler.model_copy(update={"file_path": target_root / "routes.py"})})
            cache = pair / "cache.json"
            analyzer = MypyAnalyzer(target_root, max_depth=1000)
            analyzer.set_cache_path(cache)
            source_fp = cache_fingerprint(analyzer)
            started = time.perf_counter()
            deps = analyzer.analyze_endpoints([target_endpoint])
            cold = time.perf_counter() - started
            phases["cold_build"].append(cold)
            reachable = {Path(p).stem for p in next(iter(deps.values())).referenced_files}
            # Query the persisted endpoint cache through a fresh analyzer, proving fingerprint match.
            warm = MypyAnalyzer(target_root, max_depth=1000)
            warm.set_cache_path(cache)
            warm_fp = cache_fingerprint(warm)
            started = time.perf_counter()
            warm_deps = warm.analyze_endpoints([target_endpoint])
            warm_seconds = time.perf_counter() - started
            warm_hit = bool(warm_deps) and warm_fp == source_fp and warm._build_result is None
            if warm_hit:
                phases["warm_no_change"].append(warm_seconds)
            else:
                raise RuntimeError("warm query did not prove a fingerprint-verified cache hit")

            # Edit one typed source file, verify only that content hash changes, and time actual work.
            changed_file = target_root / "node_48.py"
            before = hashlib.sha256(changed_file.read_bytes()).hexdigest()
            changed_file.write_text(changed_file.read_text(encoding="utf-8").replace("= 48", "= 49", 1), encoding="utf-8")
            changed_hashes = dict(target_hashes)
            changed_hashes["node_48.py"] = hashlib.sha256(changed_file.read_bytes()).hexdigest()
            changed = MypyAnalyzer(target_root, max_depth=1000)
            changed.set_cache_path(cache)
            changed_fp = cache_fingerprint(changed)
            if changed_fp == source_fp or changed_hashes["node_48.py"] == before:
                raise RuntimeError("changed snapshot fingerprint did not change")
            started = time.perf_counter()
            changed_deps = changed.analyze_endpoints([target_endpoint])
            rebuild = time.perf_counter() - started
            reachable_after = {Path(p).stem for p in next(iter(changed_deps.values())).referenced_files}
            # This analyzer reports immediate typed source dependencies; the fixture
            # graph oracle separately verifies transitive reachability over all nodes.
            if "node_95" not in reachable or reachable_after != reachable or "dead_control" in reachable:
                raise RuntimeError(f"DAG reachability mismatch: direct edge missing or dead control reached: {sorted(reachable)}")
            phases["changed_snapshot_rebuild"].append(rebuild)
            resources.append({"cache_size_bytes": cache_bytes(cache)})
            samples.append({"attempt": attempt + 1, "source_fingerprint": source_fp, "changed_fingerprint": changed_fp,
                            "config_fingerprint": hashlib.sha256(b"mypy:incremental=false;max_depth=1000").hexdigest(),
                            "tool": f"mypy-analyzer/{analyzer.resolver_version}", "source_files": len(target_hashes),
                            "source_inventory_scope": "all_fixture_python_files_including_init",
                            "source_hashes_sha256": tree_fingerprint(target_hashes), "cache_artifact_sha256": file_sha256(cache), "changed_file": "node_48.py",
                            "changed_files": ["node_48.py"], "cache_fingerprint_verified": warm_hit,
                            "observation_scope": "direct_endpoint_references",
                            "observed_reachable_sources": sorted(reachable), "expected_fixture_reachable_modules": len(expected),
                            "incremental_update_supported": False, "actual_changed_snapshot_rebuild_seconds": rebuild,
                            "cold_build_seconds": cold, "warm_no_change_seconds": warm_seconds,
                            "baseline_target_preparation_seconds": prep})
    process_peak_rss = rss_bytes()
    return {"schema_version": SCHEMA, "protocol": {"fixture": "synthetic-typed-dag-v1", "modules": MODULES,
            "negative_controls": ["disconnected dead_control.py is absent from direct endpoint references", "value-only one-file edit preserves the direct endpoint-reference set"],
            "observation_scope": "direct_endpoint_references",
            "reachability_oracle": "expected_fixture_reachable_modules comes from the generated DAG, not analyzer traversal",
            "source_inventory_scope": "all_fixture_python_files_including_init",
            "incremental_semantics": "unsupported: analyzer calls mypy with Options.incremental=False; changed source invalidates the persisted result cache and triggers a full rebuild",
            "unsupported_phase": {"status": "unsupported", "reason": "backend_incremental_build_disabled", "actual_rebuild_phase": "changed_snapshot_rebuild"}},
            "environment": {"python": sys.version, "platform": platform.platform(), "mypy": samples[0]["tool"] if samples else None},
            "phases": {name: {"status": "measured", "samples": vals, **percentiles(vals)} for name, vals in phases.items()},
            "one_file_incremental_update": {"status": "unsupported", "reason": "backend_incremental_build_disabled"},
            "resources": {
                "peak_rss_bytes": ({"status": "measured", "scope": "entire_measurement_process", "samples": [process_peak_rss], **percentiles([float(process_peak_rss)])} if process_peak_rss is not None else {"status": "not_measured", "reason": "resource_module_unavailable"}),
                "cache_size_bytes": {"status": "measured", "samples": [r["cache_size_bytes"] for r in resources], **percentiles([float(r["cache_size_bytes"]) for r in resources])},
            },
            "samples": samples}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    report = run(args.repeats)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
