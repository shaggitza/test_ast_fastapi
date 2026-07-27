"""Private fresh-interpreter worker for trusted runtime endpoint extraction."""

from __future__ import annotations

import argparse
import json
import os
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

from fastapi_endpoint_detector.parser.fastapi_extractor import FastAPIExtractor

_PROTOCOL_VERSION = 1
_DEFAULT_OUTPUT_LIMIT_BYTES = 4 * 1024 * 1024


def _request() -> dict[str, Any]:
    try:
        value = json.load(sys.stdin)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid runtime worker request") from exc
    if not isinstance(value, dict) or value.get("schema_version") != _PROTOCOL_VERSION:
        raise ValueError("unsupported runtime worker request")
    return value


def _required_string(request: dict[str, Any], field: str) -> str:
    value = request.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"runtime worker request requires {field}")
    return value


def _write_result(result_path: Path, payload: dict[str, Any], output_limit: int) -> None:
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(encoded) > output_limit:
        encoded = json.dumps(
            {
                "schema_version": _PROTOCOL_VERSION,
                "status": "error",
                "message": "serialized endpoint inventory exceeded the output limit",
            },
            separators=(",", ":"),
        ).encode("utf-8")
    temporary = result_path.with_suffix(".tmp")
    temporary.write_bytes(encoded)
    temporary.replace(result_path)


def _run(result_path: Path) -> int:
    output_limit = _DEFAULT_OUTPUT_LIMIT_BYTES
    try:
        request = _request()
        raw_limit = request.get("output_limit_bytes", output_limit)
        if not isinstance(raw_limit, int) or isinstance(raw_limit, bool) or raw_limit <= 0:
            raise ValueError("runtime worker output limit must be a positive integer")
        output_limit = raw_limit
        module_name = request.get("module_name")
        if module_name is not None and not isinstance(module_name, str):
            raise ValueError("runtime worker module_name must be a string or null")
        extractor = FastAPIExtractor(
            Path(_required_string(request, "app_path")),
            app_variable=_required_string(request, "app_variable"),
            module_name=module_name,
        )
        with (
            Path(os.devnull).open("w", encoding="utf-8") as sink,
            redirect_stdout(sink),
            redirect_stderr(sink),
        ):
            endpoints = extractor._extract_endpoints_in_process()
        payload = {
            "schema_version": _PROTOCOL_VERSION,
            "status": "ok",
            "endpoints": [endpoint.model_dump(mode="json") for endpoint in endpoints],
        }
        exit_code = 0
    except BaseException as exc:
        payload = {
            "schema_version": _PROTOCOL_VERSION,
            "status": "error",
            "message": str(exc)[:4096] or type(exc).__name__,
        }
        exit_code = 1
    try:
        _write_result(result_path, payload, output_limit)
    except OSError:
        return 2
    return exit_code


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    return _run(args.result.resolve())


if __name__ == "__main__":
    raise SystemExit(main())
