"""Trusted generated-DAG benchmark for retained typed mypy state (no third-party corpus)."""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import tempfile
import time
from importlib.metadata import version
from pathlib import Path

from fastapi_endpoint_detector.analyzer.mypy_incremental import BuildConfig, MypyIncrementalProvider


def make_dag(root: Path, modules: int) -> dict[str, Path]:
    for index in range(modules):
        imported = f"from m{index + 1} import f{index + 1}\n" if index + 1 < modules else ""
        called = (
            f"    return f{index + 1}(value)\n"
            if index + 1 < modules else "    return value\n"
        )
        (root / f"m{index}.py").write_text(
            f"{imported}\ndef f{index}(value: int) -> int:\n{called}", encoding="utf-8"
        )
    return {path.stem: path for path in root.glob("*.py")}


def p95(samples: list[float]) -> float:
    ordered = sorted(samples)
    return ordered[max(0, int(0.95 * len(ordered) + 0.999999) - 1)]


def main() -> None:  # noqa: PLR0915
    parser = argparse.ArgumentParser()
    parser.add_argument("--modules", type=int, default=96)
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--python-version", default="3.11")
    args = parser.parse_args()
    cold: list[float] = []
    warm: list[float] = []
    incremental: list[float] = []
    signature_update: list[float] = []
    fallback: list[float] = []
    modes: list[str] = []
    fingerprints: set[str] = set()
    for _ in range(args.samples):
        with tempfile.TemporaryDirectory(prefix="mypy-dag-") as directory:
            root = Path(directory)
            inventory = make_dag(root, args.modules)
            provider = MypyIncrementalProvider(
                BuildConfig(root, python_version=args.python_version)
            )
            started = time.perf_counter()
            state = provider.build(inventory)
            cold.append(time.perf_counter() - started)
            fingerprints.add(state.report.cache_fingerprint)
            started = time.perf_counter()
            warm_state = provider.build(inventory)
            warm.append(time.perf_counter() - started)
            if warm_state.report.mode != "no_change_reuse":
                raise RuntimeError(
                    f"no-change phase did not reuse typed state: {warm_state.report.mode}"
                )
            changed = root / f"m{args.modules // 2}.py"
            old_source = changed.read_text(encoding="utf-8")
            changed.write_text(old_source.replace("(value)", "(value + 1)"), encoding="utf-8")
            started = time.perf_counter()
            update = provider.build(inventory)
            incremental.append(time.perf_counter() - started)
            modes.append(update.report.mode)
            if update.report.mode != "incremental_update":
                raise RuntimeError(f"same-interface update fell back: {update.report.reason}")
            changed.write_text(
                old_source.replace("value: int", "value: str").replace("-> int", "-> str"),
                encoding="utf-8",
            )
            started = time.perf_counter()
            signature = provider.build(inventory)
            signature_update.append(time.perf_counter() - started)
            if signature.report.mode != "incremental_update":
                raise RuntimeError("signature change was not processed incrementally")
            changed_index = args.modules // 2
            dependent_prefix = f"m{changed_index - 1}."
            if not any(
                target.startswith(dependent_prefix)
                for target in signature.manager.processed_targets
            ):
                raise RuntimeError("signature change did not recheck an imported caller")
            changed.write_text(
                old_source.replace("from m49 import f49", "from m50 import f50")
                .replace("f49(value)", "f50(value)"),
                encoding="utf-8",
            )
            started = time.perf_counter()
            rebuilt = provider.build(inventory)
            fallback.append(time.perf_counter() - started)
            if rebuilt.report.mode != "fallback_full_rebuild":
                raise RuntimeError("import-retarget negative control did not force full rebuild")
    result = {
        "provider": "MypyIncrementalProvider",
        "mypy_version": version("mypy"),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "fixture": {"kind": "generated_import_dag", "modules": args.modules,
                    "one_function_per_module": True, "samples": args.samples},
        "seconds": {
            "cold_build": {
                "samples": cold, "p95": p95(cold), "mean": statistics.mean(cold)
            },
            "no_change_reuse": {
                "samples": warm, "p95": p95(warm), "mean": statistics.mean(warm)
            },
            "incremental_update": {
                "samples": incremental, "p95": p95(incremental),
                "mean": statistics.mean(incremental),
            },
            "signature_update_with_dependency_invalidation": {
                "samples": signature_update,
                "p95": p95(signature_update),
                "mean": statistics.mean(signature_update),
            },
            "fallback_full_rebuild": {
                "samples": fallback, "p95": p95(fallback),
                "mean": statistics.mean(fallback),
            },
        },
        "update_modes": modes,
        "cache_fingerprint_unique_count": len(fingerprints),
        "incremental_valid": all(mode == "incremental_update" for mode in modes),
        "scope": "trusted generated fixture only; not a host-project corpus score",
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
