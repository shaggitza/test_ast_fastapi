"""Private bounded worker for selected runtime endpoint extraction and analysis."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import threading
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.analyzer.endpoint_registry import EndpointRegistry
from fastapi_endpoint_detector.config import AnalysisConfig, Config, ParserConfig
from fastapi_endpoint_detector.parser.bounded_output import (
    MIN_PROTOCOL_OUTPUT_BYTES,
    bounded_json_bytes,
)
from fastapi_endpoint_detector.parser.fastapi_extractor import FastAPIExtractor

_HOST_PROTOCOL_VERSION = 2
_PROTOCOL_VERSION = 3
_DEFAULT_OUTPUT_LIMIT_BYTES = 4 * 1024 * 1024
_PIN_FIELDS = {
    "runtime_image",
    "runtime_image_digest",
    "dependency_lock_sha256",
    "snapshot_lock_sha256",
    "sbom_sha256",
    "seccomp_sha256",
    "runtime_policy_sha256",
}
_COLLECTION_FIELDS = {"endpoints", "candidate_endpoints", "affected_endpoints"}
_REQUEST_FIELDS = {
    "schema_version",
    "phase",
    "app_path",
    "app_variable",
    "app_entry",
    "bootstrap_entry",
    "diff_path",
    "output_limit_bytes",
    "dependency_max_depth",
    "dependency_max_nodes",
    "dependency_max_work",
    "runtime_pins",
}
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_IMAGE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")


def _container_process_rss_bytes() -> int | None:
    """Sum resident pages for processes visible in this private PID namespace."""
    total = 0
    observed = False
    try:
        processes = tuple(Path("/proc").iterdir())
        page_size = os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError):
        return None
    for process in processes:
        if not process.name.isdecimal():
            continue
        try:
            fields = (process / "statm").read_text(encoding="ascii").split()
            if len(fields) < 3:
                return None
            resident_pages = int(fields[1])
        except FileNotFoundError:
            # A process exited between enumerating /proc and reading statm.
            continue
        except (OSError, UnicodeError, ValueError):
            return None
        if resident_pages < 0:
            return None
        observed = True
        total += resident_pages * page_size
    return total if observed else None


class _ContainerRssSampler:
    """Record an honest sampled peak of process RSS inside the isolated container."""

    def __init__(self) -> None:
        self.peak_bytes: int | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _sample(self) -> None:
        value = _container_process_rss_bytes()
        if value is not None:
            self.peak_bytes = value if self.peak_bytes is None else max(self.peak_bytes, value)

    def __enter__(self) -> _ContainerRssSampler:
        self._sample()

        def sample_until_stopped() -> None:
            while not self._stop.wait(0.01):
                self._sample()

        self._thread = threading.Thread(target=sample_until_stopped, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1)
        self._sample()


def _positive_integer(request: dict[str, Any], field: str, maximum: int) -> int:
    value = request.get(field)
    if not isinstance(value, int) or isinstance(value, bool) or not 0 < value <= maximum:
        raise ValueError(f"runtime worker {field} must be between 1 and {maximum}")
    return value


def _encoded_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _bounded_error_payload(
    exc: Exception, *, schema_version: int, output_limit: int, framing_bytes: int = 0
) -> dict[str, Any]:
    """Build a structured error whose complete UTF-8 frame fits the protocol limit."""
    try:
        message = str(exc)[:4096] or type(exc).__name__
    except Exception:
        message = type(exc).__name__
    # Normalize lone surrogates so UTF-8 serialization remains valid and measurable.
    message = message.encode("utf-8", errors="replace").decode("utf-8")
    payload: dict[str, Any] = {
        "schema_version": schema_version,
        "status": "error",
        "message": "",
    }
    empty_envelope_bytes = len(_encoded_json(payload))
    message_json_budget = output_limit - framing_bytes - empty_envelope_bytes + 2
    if message_json_budget < 2:
        raise ValueError("runtime worker output limit is below the minimum protocol size")

    bounded_message: list[str] = []
    used_message_bytes = 2
    for character in message:
        try:
            encoded_character = bounded_json_bytes(
                character,
                max_bytes=message_json_budget - used_message_bytes + 2,
                field="runtime worker error message",
            )
        except ValueError:
            break
        character_bytes = len(encoded_character) - 2
        if used_message_bytes + character_bytes > message_json_budget:
            break
        bounded_message.append(character)
        used_message_bytes += character_bytes
    payload["message"] = "".join(bounded_message)
    encoded_size = len(_encoded_json(payload)) + framing_bytes
    if encoded_size > output_limit:
        raise ValueError("runtime worker error response exceeded the output limit")
    return payload


def _collect_bounded_models(
    values: Any, *, field: str, remaining_bytes: int
) -> tuple[list[Any], int]:
    """Serialize one value at a time without first dumping an unbounded model tree."""
    collected: list[Any] = []
    used_bytes = 0
    for value in values:
        separator_bytes = 1 if collected else 0
        available_bytes = remaining_bytes - used_bytes - separator_bytes
        if available_bytes <= 0:
            raise ValueError(f"runtime worker {field} exceeded the serialized output limit")
        encoded = bounded_json_bytes(
            value, max_bytes=available_bytes, field=f"runtime worker {field}"
        )
        collected.append(json.loads(encoded))
        used_bytes += len(encoded) + separator_bytes
    return collected, used_bytes


def _validate_request(value: Any) -> dict[str, Any]:  # noqa: PLR0912
    if (
        not isinstance(value, dict)
        or set(value) != _REQUEST_FIELDS
        or value.get("schema_version") != _PROTOCOL_VERSION
    ):
        raise ValueError("unsupported runtime worker request")
    if value.get("phase") not in {"list", "analyze"}:
        raise ValueError("runtime worker phase must be list or analyze")
    for field in ("app_path", "app_variable"):
        if not isinstance(value.get(field), str) or not value[field]:
            raise ValueError(f"runtime worker request requires {field}")
    for field in ("app_entry", "bootstrap_entry"):
        if value.get(field) is not None and not isinstance(value[field], str):
            raise ValueError(f"runtime worker {field} must be a string or null")
    if value["phase"] == "analyze":
        if not isinstance(value.get("diff_path"), str) or not value["diff_path"]:
            raise ValueError("runtime worker analyze phase requires diff_path")
    elif value.get("diff_path") is not None:
        raise ValueError("runtime worker list phase cannot include diff_path")
    output_limit = _positive_integer(value, "output_limit_bytes", _DEFAULT_OUTPUT_LIMIT_BYTES)
    if output_limit < MIN_PROTOCOL_OUTPUT_BYTES:
        raise ValueError(
            "runtime worker output_limit_bytes must be at least "
            f"{MIN_PROTOCOL_OUTPUT_BYTES} for a structured protocol response"
        )
    _positive_integer(value, "dependency_max_depth", 64)
    _positive_integer(value, "dependency_max_nodes", 4096)
    _positive_integer(value, "dependency_max_work", 65536)
    pins = value.get("runtime_pins")
    if not isinstance(pins, dict) or set(pins) != _PIN_FIELDS:
        raise ValueError("runtime worker requires the complete immutable pin set")
    for field, pin in pins.items():
        valid_image = field == "runtime_image" and isinstance(pin, str) and _IMAGE.fullmatch(pin)
        valid_hash = field != "runtime_image" and isinstance(pin, str) and _SHA256.fullmatch(pin)
        if not (valid_image or valid_hash):
            raise ValueError(f"runtime worker pin {field} is malformed")
    return value


def _extractor(request: dict[str, Any]) -> FastAPIExtractor:
    return FastAPIExtractor(
        Path(request["app_path"]),
        app_variable=request["app_variable"],
        module_name=request.get("module_name"),
        app_entry=request.get("app_entry"),
        bootstrap_entry=request.get("bootstrap_entry"),
        dependency_max_depth=request["dependency_max_depth"],
        dependency_max_nodes=request["dependency_max_nodes"],
        dependency_max_work=request["dependency_max_work"],
        output_limit_bytes=request["output_limit_bytes"],
    )


def _analyze(request: dict[str, Any], endpoints: Any) -> dict[str, Any]:
    # ChangeMapper's public options intentionally reserve explicit entry selection
    # for secure-AST mode. Seed its registry from this worker's already selected
    # runtime inventory so mypy impact analysis cannot rediscover a different app.
    depth = request["dependency_max_depth"]
    config = Config(parser=ParserConfig(max_depth=depth), analysis=AnalysisConfig())
    mapper = ChangeMapper(
        Path(request["app_path"]),
        config=config,
        app_variable=request["app_variable"],
        use_cache=False,
    )
    registry = EndpointRegistry()
    registry.register_many(endpoints)
    mapper._registry = registry
    report = mapper.analyze_diff(Path(request["diff_path"]))
    return {
        "candidate_endpoints": report.candidate_endpoints,
        "affected_endpoints": report.affected_endpoints,
        "total_endpoints": report.total_endpoints,
        "total_files_changed": report.total_files_changed,
        "python_files_changed": report.python_files_changed,
    }


def run_request(raw_request: str) -> tuple[dict[str, Any], int]:
    """Run one validated list/analyze request and return a bounded JSON payload."""
    output_limit = _DEFAULT_OUTPUT_LIMIT_BYTES
    try:
        raw_value = json.loads(raw_request)
        if isinstance(raw_value, dict):
            requested_limit = raw_value.get("output_limit_bytes")
            if (
                isinstance(requested_limit, int)
                and not isinstance(requested_limit, bool)
                and 0 < requested_limit <= _DEFAULT_OUTPUT_LIMIT_BYTES
            ):
                output_limit = requested_limit
        if output_limit < MIN_PROTOCOL_OUTPUT_BYTES:
            # There is no JSON envelope that can fit such a limit. The CLI returns
            # a nonzero status with no stdout before entering the application.
            return {}, 2
        request = _validate_request(raw_value)
        with _ContainerRssSampler() as rss_sampler:
            extractor = _extractor(request)
            # App code runs in FastAPIExtractor's isolated child, so it cannot
            # monkeypatch this supervisor's pin validation or RSS telemetry.
            endpoints = extractor.extract_endpoints()
            result = (
                {"endpoints": endpoints}
                if request["phase"] == "list"
                else _analyze(request, endpoints)
            )
        peak = rss_sampler.peak_bytes
        telemetry = {
            "container_peak_rss_bytes": peak,
            "container_peak_rss_status": "measured" if peak is not None else "unsupported",
            "source": "sampled-/proc/[pid]/statm" if peak is not None else None,
        }
        payload: dict[str, Any] = {
            "schema_version": _PROTOCOL_VERSION,
            "status": "ok",
            "phase": request["phase"],
            **{key: [] if key in _COLLECTION_FIELDS else value for key, value in result.items()},
            "telemetry": telemetry,
        }
        remaining_bytes = request["output_limit_bytes"] - len(_encoded_json(payload))
        remaining_bytes -= 1  # newline framing emitted by main()
        if remaining_bytes < 0:
            raise ValueError("runtime worker output envelope exceeded the byte limit")
        for key, value in result.items():
            if key in _COLLECTION_FIELDS:
                payload[key], used_bytes = _collect_bounded_models(
                    value, field=key, remaining_bytes=remaining_bytes
                )
                remaining_bytes -= used_bytes
            else:
                payload[key] = value
        # The incremental row budget above includes the exact empty-array envelope.
        if (
            len(_encoded_json(payload)) + 1  # newline framing emitted by main()
            > (request["output_limit_bytes"])
        ):
            raise ValueError("serialized runtime worker output exceeded the byte limit")
        return payload, 0
    except Exception as exc:
        if output_limit < MIN_PROTOCOL_OUTPUT_BYTES:
            return {}, 2
        return (
            _bounded_error_payload(
                exc,
                schema_version=_PROTOCOL_VERSION,
                output_limit=output_limit,
                framing_bytes=1,
            ),
            1,
        )


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    request_mode = parser.add_mutually_exclusive_group(required=True)
    request_mode.add_argument("--request-json")
    request_mode.add_argument("--result", type=Path)
    args = parser.parse_args()
    if args.request_json is not None:
        payload, status = run_request(args.request_json)
        if status == 2:
            return status
        sys.stdout.write(_encoded_json(payload).decode("utf-8"))
        sys.stdout.write("\n")
        return 0
    return _run_host_request(args.result)


def _run_host_request(result_path: Path) -> int:
    """Preserve FastAPIExtractor's private v2 subprocess protocol."""
    output_limit = _DEFAULT_OUTPUT_LIMIT_BYTES
    try:
        request = json.load(sys.stdin)
        if not isinstance(request, dict) or request.get("schema_version") != _HOST_PROTOCOL_VERSION:
            raise ValueError("unsupported runtime worker request")
        raw_limit = request.get("output_limit_bytes", output_limit)
        if (
            not isinstance(raw_limit, int)
            or isinstance(raw_limit, bool)
            or raw_limit <= 0
            or raw_limit > _DEFAULT_OUTPUT_LIMIT_BYTES
        ):
            raise ValueError("runtime worker output limit must be a positive integer")
        output_limit = raw_limit
        if output_limit < MIN_PROTOCOL_OUTPUT_BYTES:
            # Reject unsupported limits before loading or invoking project code.
            return 2
        for field in ("dependency_max_depth", "dependency_max_nodes", "dependency_max_work"):
            maximum = 64 if field.endswith("depth") else 4096 if field.endswith("nodes") else 65536
            _positive_integer(request, field, maximum)
        extractor = FastAPIExtractor(
            Path(request["app_path"]),
            app_variable=request["app_variable"],
            module_name=request.get("module_name"),
            app_entry=request.get("app_entry"),
            bootstrap_entry=request.get("bootstrap_entry"),
            dependency_max_depth=request["dependency_max_depth"],
            dependency_max_nodes=request["dependency_max_nodes"],
            dependency_max_work=request["dependency_max_work"],
            output_limit_bytes=output_limit,
        )
        with (
            Path(os.devnull).open("w", encoding="utf-8") as sink,
            redirect_stdout(sink),
            redirect_stderr(sink),
        ):
            endpoints = extractor._extract_endpoints_in_process()
        payload: dict[str, Any] = {
            "schema_version": _HOST_PROTOCOL_VERSION,
            "status": "ok",
            "endpoints": [],
        }
        remaining_bytes = output_limit - len(
            json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        )
        if remaining_bytes < 0:
            raise ValueError("runtime worker output envelope exceeded the byte limit")
        payload["endpoints"], _ = _collect_bounded_models(
            endpoints, field="endpoints", remaining_bytes=remaining_bytes
        )
        exit_code = 0
    except Exception as exc:
        payload = _bounded_error_payload(
            exc,
            schema_version=_HOST_PROTOCOL_VERSION,
            output_limit=output_limit,
        )
        exit_code = 1
    try:
        encoded = _encoded_json(payload)
        if len(encoded) > output_limit:
            fallback = _bounded_error_payload(
                ValueError("serialized endpoint inventory exceeded the output limit"),
                schema_version=_HOST_PROTOCOL_VERSION,
                output_limit=output_limit,
            )
            encoded = _encoded_json(fallback)
        temporary = result_path.with_suffix(".tmp")
        temporary.write_bytes(encoded)
        temporary.replace(result_path)
    except OSError:
        return 2
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
