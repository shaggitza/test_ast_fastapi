"""Dedicated bounded-output runtime inventory producer for VM execution."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from fastapi_endpoint_detector.parser.fastapi_extractor import FastAPIExtractor


def _peak_memory_bytes() -> int | None:
    """Read kernel cgroup v2 peak memory for this container, when exposed."""
    try:
        value = Path("/sys/fs/cgroup/memory.peak").read_text(encoding="ascii").strip()
        parsed = int(value)
    except (OSError, UnicodeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--app-var", required=True)
    parser.add_argument("--app-entry")
    parser.add_argument("--bootstrap-entry")
    parser.add_argument("--output-limit-bytes", type=int, default=4 * 1024 * 1024)
    args = parser.parse_args()
    try:
        endpoints = FastAPIExtractor(
            args.app,
            app_variable=args.app_var,
            app_entry=args.app_entry,
            bootstrap_entry=args.bootstrap_entry,
            output_limit_bytes=args.output_limit_bytes,
        ).extract_endpoints()
        peak = _peak_memory_bytes()
        payload = {
            "schema_version": 1,
            "status": "ok",
            "endpoints": [endpoint.model_dump(mode="json") for endpoint in endpoints],
            "telemetry": {
                "container_peak_memory_bytes": peak,
                "container_peak_memory_status": "measured" if peak is not None else "unsupported",
                "source": "cgroup-v2-memory.peak" if peak is not None else None,
            },
        }
        encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        if len(encoded.encode("utf-8")) > args.output_limit_bytes:
            raise ValueError("runtime inventory exceeded output limit")
        print(encoded)
        return 0
    except Exception as exc:
        print(json.dumps({"schema_version": 1, "status": "error", "message": str(exc)[:4096]}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
