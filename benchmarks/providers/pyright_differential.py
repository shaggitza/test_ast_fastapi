"""Bounded differential diagnostics for controlled Pyright/mypy type fixtures.

This tool does not infer execution, endpoint reachability, or canonical truth.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "benchmarks/providers/fixtures/pyright_differential"
RESULTS = ROOT / "benchmarks/results/pyright-differential-v1"
RESULTS_V2 = ROOT / "benchmarks/results/pyright-differential-v2"
PYRIGHT_VERSION = "1.1.411"
MYPY_VERSION = "2.4.0"
FIXTURE_NAMES = ("callable", "overloads", "package_layout", "receiver", "shadowing", "utf8")
MAX_FILES = 32
MAX_BYTES = 256_000
TIMEOUT_SECONDS = 25
_RANGE = re.compile(r"^(.*?):(\d+):(\d+): (error|warning|note): (.*?)(?:\s+\[([^]]+)\])?$")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MYPY_CONFIG = b"[mypy]\npython_version = 3.10\nshow_column_numbers = True\n"
_V2_FIELDS = {
    "schema",
    "fixture",
    "source_sha256",
    "config_sha256",
    "engines",
    "provenance",
    "observations",
    "comparison",
    "unsupported",
    "scope",
}
_PROVENANCE_FIELDS = {
    "pyright_command",
    "mypy_command",
    "fixture_root",
    "max_files",
    "max_source_bytes",
    "provider_timeout_seconds",
    "elapsed_seconds",
    "consumed_source_sha256",
    "consumed_config_sha256",
    "working_directory",
}


class EvaluationError(RuntimeError):
    """A bounded provider invocation or saved record is invalid."""


@dataclass(frozen=True)
class Observation:
    provider: str
    kind: str
    file: str | None
    line: int | None
    column: int | None
    severity: str | None
    message: str
    rule: str | None = None
    comparable: bool = False
    end_line: int | None = None
    end_column: int | None = None


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise EvaluationError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_non_finite(token: str) -> None:
    raise EvaluationError(f"non-finite JSON number: {token}")


def _loads(raw: str | bytes, label: str) -> Any:
    try:
        return json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_non_finite)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise EvaluationError(f"invalid {label} JSON: {exc}") from exc


def _run(
    command: list[str], cwd: Path, timeout: int = TIMEOUT_SECONDS
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={**os.environ, "NO_COLOR": "1", "PYTHONDONTWRITEBYTECODE": "1"},
        )
    except subprocess.TimeoutExpired as exc:
        raise EvaluationError(f"provider timed out after {timeout}s: {command[0]}") from exc


def _read_pyright(
    raw: str, fixture: Path, source_names: set[str] | None = None
) -> tuple[str, list[Observation]]:
    data = _loads(raw, "Pyright output")
    if (
        not isinstance(data, dict)
        or set(data) != {"version", "time", "generalDiagnostics", "summary"}
        or not isinstance(data.get("version"), str)
        or not isinstance(data.get("time"), str)
    ):
        raise EvaluationError("malformed Pyright output: missing string version")
    diagnostics = data.get("generalDiagnostics")
    summary = data.get("summary")
    if (
        not isinstance(diagnostics, list)
        or not isinstance(summary, dict)
        or set(summary)
        != {"filesAnalyzed", "errorCount", "warningCount", "informationCount", "timeInSec"}
        or any(
            type(summary[key]) is not int or summary[key] < 0
            for key in ("filesAnalyzed", "errorCount", "warningCount", "informationCount")
        )
        or type(summary["timeInSec"]) not in {int, float}
        or summary["timeInSec"] < 0
    ):
        raise EvaluationError("malformed Pyright output: diagnostics must be a list")
    result: list[Observation] = []
    for item in diagnostics:
        if not isinstance(item, dict) or set(item) not in (
            {"file", "severity", "message", "range"},
            {"file", "severity", "message", "range", "rule"},
        ):
            raise EvaluationError("malformed Pyright diagnostic: expected object")
        file_value, severity, message = item.get("file"), item.get("severity"), item.get("message")
        rule = item.get("rule")
        location = item.get("range")
        if (
            not isinstance(file_value, str)
            or not isinstance(severity, str)
            or severity not in {"error", "warning", "information"}
            or not isinstance(message, str)
            or (rule is not None and not isinstance(rule, str))
            or not isinstance(location, dict)
            or set(location) != {"start", "end"}
            or not isinstance(location.get("start"), dict)
            or not isinstance(location.get("end"), dict)
        ):
            raise EvaluationError("malformed Pyright diagnostic fields")
        start = location["start"]
        end = location["end"]
        line, character = start.get("line"), start.get("character")
        end_line, end_character = end.get("line"), end.get("character")
        if (
            type(line) is not int
            or line < 0
            or type(character) is not int
            or character < 0
            or type(end_line) is not int
            or end_line < line
            or type(end_character) is not int
            or end_character < 0
        ):
            raise EvaluationError("malformed Pyright diagnostic range")
        try:
            file = Path(file_value).resolve(strict=True).relative_to(fixture.resolve()).as_posix()
        except (OSError, ValueError) as exc:
            raise EvaluationError("Pyright diagnostic path escapes input snapshot") from exc
        if source_names is not None and file not in source_names:
            raise EvaluationError("Pyright diagnostic references a non-source input")
        result.append(
            Observation(
                "pyright",
                "diagnostic",
                file,
                line + 1,
                character + 1,
                severity,
                message,
                rule,
                severity == "error",
                end_line + 1,
                end_character + 1,
            )
        )
    return data["version"], result


def _read_mypy(raw: str, fixture: Path, source_names: set[str] | None = None) -> list[Observation]:
    result: list[Observation] = []
    for line in raw.splitlines():
        match = _RANGE.match(line)
        if not match:
            ignored = ("Success:", "Found ", "pyproject.toml: note:")
            if line.strip() and not line.startswith(ignored):
                raise EvaluationError(f"unrecognized mypy output: {line[:160]}")
            continue
        name, row, col, severity, message, code = match.groups()
        path = Path(name)
        if not path.is_absolute():
            path = ROOT / path if (ROOT / path).exists() else fixture / path
        try:
            relative = path.resolve(strict=True).relative_to(fixture.resolve()).as_posix()
        except ValueError as exc:
            raise EvaluationError(f"mypy diagnostic outside fixture: {name}") from exc
        except OSError as exc:
            raise EvaluationError(f"mypy diagnostic path is missing: {name}") from exc
        if source_names is not None and relative not in source_names:
            raise EvaluationError("mypy diagnostic references a non-source input")
        kind = "type_observation" if "Revealed type is" in message else "diagnostic"
        result.append(
            Observation(
                "mypy",
                kind,
                relative,
                int(row),
                int(col),
                severity,
                message,
                code,
                kind == "diagnostic",
                None,
                None,
            )
        )
    return result


def _version(command: list[str], expected: str, provider: str) -> str:
    result = _run(command, ROOT)
    if result.returncode:
        raise EvaluationError(f"cannot read {provider} version: {result.stderr.strip()}")
    lines = result.stdout.strip().splitlines()
    if not lines:
        raise EvaluationError(f"{provider} returned an empty version string")
    actual = lines[0]
    if expected not in actual:
        raise EvaluationError(f"expected {provider} {expected}, got {actual!r}")
    return actual


def _fixture_inputs(fixture: Path) -> list[Path]:
    if fixture.is_symlink() or not fixture.is_dir():
        raise EvaluationError("fixture root must be a real directory")
    files: list[Path] = []
    for current, directories, names in os.walk(fixture, followlinks=False):
        current_path = Path(current)
        if any((current_path / name).is_symlink() for name in directories):
            raise EvaluationError("fixture contains a symlinked directory")
        for name in names:
            path = current_path / name
            if path.is_symlink():
                raise EvaluationError(f"fixture contains a symlink: {path.relative_to(fixture)}")
            if not path.is_file() or (path.suffix != ".py" and name != "pyrightconfig.json"):
                raise EvaluationError(f"unsupported fixture input: {path.relative_to(fixture)}")
            try:
                path.resolve(strict=True).relative_to(fixture.resolve(strict=True))
            except (OSError, ValueError) as exc:
                raise EvaluationError("fixture input escapes fixture root") from exc
            files.append(path)
    files.sort()
    py_files = [path for path in files if path.suffix == ".py"]
    config_files = [path for path in files if path.name == "pyrightconfig.json"]
    if not py_files or len(py_files) > MAX_FILES:
        raise EvaluationError(f"fixture file count must be 1..{MAX_FILES}")
    if len(config_files) != 1 or config_files[0].parent != fixture:
        raise EvaluationError("fixture must contain exactly one root pyrightconfig.json")
    if sum(path.stat().st_size for path in files) > MAX_BYTES:
        raise EvaluationError(f"fixture exceeds {MAX_BYTES} source bytes")
    return files


def _input_hashes(fixture: Path, files: list[Path]) -> tuple[dict[str, str], dict[str, str]]:
    source_hashes: dict[str, str] = {}
    config_hashes: dict[str, str] = {}
    for path in files:
        name = path.relative_to(fixture).as_posix()
        target = source_hashes if path.suffix == ".py" else config_hashes
        target[name] = sha256(path)
    return source_hashes, config_hashes


def _snapshot(fixture: Path, files: list[Path], destination: Path) -> tuple[Path, Path]:
    snapshot = destination / fixture.name
    for source in files:
        relative = source.relative_to(fixture)
        target = snapshot / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise EvaluationError("fixture input is not a regular file")
                target.write_bytes(stream.read())
        except OSError as exc:
            raise EvaluationError(f"cannot securely snapshot fixture input: {relative}") from exc
    mypy_config = destination / "mypy.ini"
    mypy_config.write_bytes(_MYPY_CONFIG)
    return snapshot, mypy_config


def evaluate(
    name: str,
    pyright_bin: str,
    mypy_bin: str,
    *,
    write: bool = True,
    results_dir: Path | None = None,
) -> dict[str, Any]:
    if name not in FIXTURE_NAMES:
        raise EvaluationError(f"unknown fixture: {name}")
    fixture = FIXTURES / name
    if FIXTURES.resolve() not in fixture.resolve().parents or fixture.is_symlink():
        raise EvaluationError("fixture path escapes controlled fixture root")
    files = _fixture_inputs(fixture)
    source_hashes, pyright_config_hashes = _input_hashes(fixture, files)
    pyright_version = _version([pyright_bin, "--version"], PYRIGHT_VERSION, "Pyright")
    mypy_version = _version([mypy_bin, "--version"], MYPY_VERSION, "mypy")
    start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="pyright-differential-") as temporary:
        snapshot, mypy_config = _snapshot(fixture, files, Path(temporary))
        consumed_files = _fixture_inputs(snapshot)
        consumed_source_hashes, consumed_configs = _input_hashes(snapshot, consumed_files)
        consumed_configs["mypy.ini"] = sha256(mypy_config)
        if consumed_source_hashes != source_hashes or consumed_configs != {
            **pyright_config_hashes,
            "mypy.ini": hashlib.sha256(_MYPY_CONFIG).hexdigest(),
        }:
            raise EvaluationError("input snapshot differs from pre-run fixture hashes")
        source_names = set(source_hashes)
        pyright = _run([pyright_bin, "--project", str(snapshot), "--outputjson"], ROOT)
        if pyright.returncode not in (0, 1):
            raise EvaluationError(f"Pyright failed ({pyright.returncode}): {pyright.stderr[:500]}")
        observed_version, p_obs = _read_pyright(pyright.stdout, snapshot, source_names)
        if observed_version != PYRIGHT_VERSION:
            raise EvaluationError(f"Pyright JSON version mismatch: {observed_version}")
        mypy = _run(
            [
                mypy_bin,
                "--config-file",
                str(mypy_config),
                "--no-incremental",
                "--show-error-codes",
                "--no-error-summary",
                "--no-pretty",
                "--follow-imports",
                "silent",
                str(snapshot),
            ],
            ROOT,
        )
        if mypy.returncode not in (0, 1):
            raise EvaluationError(f"mypy failed ({mypy.returncode}): {mypy.stderr[:500]}")
        m_obs = _read_mypy(mypy.stdout + mypy.stderr, snapshot, source_names)
        final_source_hashes, final_config_hashes = _input_hashes(fixture, _fixture_inputs(fixture))
        if final_source_hashes != source_hashes or final_config_hashes != pyright_config_hashes:
            raise EvaluationError("fixture inputs changed during provider invocation")
        after_snapshot_hashes = _input_hashes(snapshot, _fixture_inputs(snapshot))
        if (
            after_snapshot_hashes != (source_hashes, pyright_config_hashes)
            or sha256(mypy_config) != hashlib.sha256(_MYPY_CONFIG).hexdigest()
        ):
            raise EvaluationError("provider modified its input snapshot")
    config_hashes = {
        **pyright_config_hashes,
        "mypy.ini": hashlib.sha256(_MYPY_CONFIG).hexdigest(),
    }
    record: dict[str, Any] = {
        "schema": "pyright-mypy-differential-v2",
        "fixture": name,
        "source_sha256": source_hashes,
        "config_sha256": config_hashes,
        "engines": {"pyright": pyright_version, "mypy": mypy_version},
        "provenance": {
            "pyright_command": [pyright_bin, "--project", "<snapshot>/fixture", "--outputjson"],
            "mypy_command": [
                mypy_bin,
                "--config-file",
                "<snapshot>/mypy.ini",
                "--no-incremental",
                "--show-error-codes",
                "--no-error-summary",
                "--no-pretty",
                "--follow-imports",
                "silent",
                "<snapshot>/fixture",
            ],
            "fixture_root": name,
            "max_files": MAX_FILES,
            "max_source_bytes": MAX_BYTES,
            "provider_timeout_seconds": TIMEOUT_SECONDS,
            "elapsed_seconds": round(time.monotonic() - start, 3),
            "consumed_source_sha256": source_hashes,
            "consumed_config_sha256": config_hashes,
            "working_directory": "<repository-root>",
        },
        "observations": [asdict(item) for item in p_obs + m_obs],
        "comparison": _compare(p_obs, m_obs),
        "unsupported": [
            {
                "query": "definition_target",
                "status": "unsupported",
                "reason": (
                    "The pinned Pyright CLI emits diagnostics only; no definition query is issued."
                ),
            },
            {
                "query": "execution_or_reachability",
                "status": "unsupported",
                "reason": "Static type diagnostics and revealed types do not establish execution.",
            },
            {
                "query": "cross_engine_diagnostic_semantics",
                "status": "unsupported",
                "reason": (
                    "Only error-location overlap is summarized; rules/messages are engine-specific."
                ),
            },
        ],
        "scope": "synthetic fixtures only; no corpus application execution or canonical truth",
    }
    if write:
        output_dir = results_dir or RESULTS_V2
        if output_dir.is_symlink():
            raise EvaluationError("results directory must not be a symlink")
        destination = output_dir / f"{name}.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(record, indent=2, sort_keys=True, allow_nan=False) + "\n"
        try:
            with destination.open("x", encoding="utf-8") as handle:
                handle.write(payload)
        except FileExistsError:
            if destination.is_symlink() or destination.read_text(encoding="utf-8") != payload:
                raise EvaluationError(
                    f"immutable record already exists with different content: {destination}"
                ) from None
    return record


def _compare(pyright: list[Observation], mypy: list[Observation]) -> dict[str, Any]:
    def error_locations(observations: list[Observation]) -> set[tuple[str, int]]:
        return {
            (item.file, item.line)
            for item in observations
            if item.comparable
            and item.severity == "error"
            and item.file is not None
            and item.line is not None
        }

    p_keys, m_keys = error_locations(pyright), error_locations(mypy)
    return {
        "policy": "error-location-overlap-only; provider rules/messages remain provider-specific",
        "overlapping_error_locations": [list(item) for item in sorted(p_keys & m_keys)],
        "pyright_only_error_locations": [list(item) for item in sorted(p_keys - m_keys)],
        "mypy_only_error_locations": [list(item) for item in sorted(m_keys - p_keys)],
        "absence_is_not_equivalence": True,
        "semantic_equivalence": "unsupported",
    }


def _validate_observations(value: Any, source_names: set[str], label: str, schema: str) -> None:
    fields = {
        "provider",
        "kind",
        "file",
        "line",
        "column",
        "severity",
        "message",
        "rule",
        "comparable",
    }
    if schema.endswith("v2"):
        fields |= {"end_line", "end_column"}
    if not isinstance(value, list):
        raise EvaluationError(f"{label} observations must be a list")
    for item in value:
        if not isinstance(item, dict) or set(item) != fields:
            raise EvaluationError(f"{label} observation has invalid fields")
        if (
            not isinstance(item["provider"], str)
            or item["provider"] not in {"pyright", "mypy"}
            or not isinstance(item["kind"], str)
            or item["kind"] not in {"diagnostic", "type_observation"}
            or not isinstance(item["file"], str)
            or item["file"] not in source_names
            or type(item["line"]) is not int
            or item["line"] < 1
            or type(item["column"]) is not int
            or item["column"] < 1
            or not isinstance(item["severity"], str)
            or item["severity"] not in {"error", "warning", "information", "note"}
            or not isinstance(item["message"], str)
            or not item["message"]
            or (item["rule"] is not None and not isinstance(item["rule"], str))
            or type(item["comparable"]) is not bool
            or (
                schema.endswith("v2")
                and item["provider"] == "pyright"
                and (
                    type(item["end_line"]) is not int
                    or item["end_line"] < item["line"]
                    or type(item["end_column"]) is not int
                    or item["end_column"] < 1
                )
            )
            or (
                schema.endswith("v2")
                and item["provider"] == "mypy"
                and (item["end_line"] is not None or item["end_column"] is not None)
            )
        ):
            raise EvaluationError(f"{label} observation has invalid values")


def _validate_record(record: Any, schema: str, fixture_name: str) -> None:  # noqa: PLR0912, PLR0915
    fields = (
        _V2_FIELDS
        if schema.endswith("v2")
        else {
            "schema",
            "fixture",
            "source_sha256",
            "config_sha256",
            "engines",
            "provenance",
            "observations",
            "comparison",
            "unsupported",
            "scope",
        }
    )
    if not isinstance(record, dict) or set(record) != fields:
        raise EvaluationError(f"record has invalid top-level fields: {fixture_name}")
    if record.get("schema") != schema or record.get("fixture") != fixture_name:
        raise EvaluationError(f"record schema or fixture identity mismatch: {fixture_name}")
    if (
        record.get("scope")
        != "synthetic fixtures only; no corpus application execution or canonical truth"
    ):
        raise EvaluationError(f"record scope is invalid: {fixture_name}")
    fixture = FIXTURES / fixture_name
    inputs = _fixture_inputs(fixture)
    source_hashes, configs = _input_hashes(fixture, inputs)
    expected_configs = dict(configs)
    if schema.endswith("v2"):
        expected_configs["mypy.ini"] = hashlib.sha256(_MYPY_CONFIG).hexdigest()
    if record["source_sha256"] != source_hashes:
        raise EvaluationError(f"stale or incomplete source hashes: {fixture_name}")
    if record["config_sha256"] != expected_configs:
        raise EvaluationError(f"stale or incomplete config hashes: {fixture_name}")
    pyright_config_path = fixture / "pyrightconfig.json"
    pyright_config = _loads(pyright_config_path.read_bytes(), "Pyright config")
    if (
        not isinstance(pyright_config, dict)
        or set(pyright_config) != {"include", "pythonVersion", "typeCheckingMode"}
        or pyright_config.get("include") != ["."]
        or pyright_config.get("pythonVersion") != "3.10"
        or pyright_config.get("typeCheckingMode") != "strict"
    ):
        raise EvaluationError(f"unexpected or inherited Pyright config: {fixture_name}")
    engines = record["engines"]
    if not isinstance(engines, dict) or set(engines) != {"pyright", "mypy"}:
        raise EvaluationError(f"invalid engine provenance: {fixture_name}")
    if (
        engines["pyright"] != f"pyright {PYRIGHT_VERSION}"
        or not isinstance(engines["mypy"], str)
        or MYPY_VERSION not in engines["mypy"]
    ):
        raise EvaluationError(f"unexpected engine version: {fixture_name}")
    provenance = record["provenance"]
    expected_provenance_fields = (
        _PROVENANCE_FIELDS
        if schema.endswith("v2")
        else {
            "pyright_command",
            "mypy_command",
            "fixture_root",
            "max_files",
            "max_source_bytes",
            "provider_timeout_seconds",
            "elapsed_seconds",
        }
    )
    if not isinstance(provenance, dict) or set(provenance) != expected_provenance_fields:
        raise EvaluationError(f"invalid provider provenance fields: {fixture_name}")
    if (
        provenance["fixture_root"] != fixture_name
        or provenance["max_files"] != MAX_FILES
        or provenance["max_source_bytes"] != MAX_BYTES
        or provenance["provider_timeout_seconds"] != TIMEOUT_SECONDS
        or type(provenance["elapsed_seconds"]) not in {int, float}
        or not (0 < provenance["elapsed_seconds"] <= TIMEOUT_SECONDS * 2 + 1)
    ):
        raise EvaluationError(f"invalid provider limits or duration: {fixture_name}")
    if schema.endswith("v2") and (
        provenance["consumed_source_sha256"] != source_hashes
        or provenance["consumed_config_sha256"] != expected_configs
        or provenance["working_directory"] != "<repository-root>"
        or not isinstance(provenance["pyright_command"], list)
        or len(provenance["pyright_command"]) != 4
        or provenance["pyright_command"][1:] != ["--project", "<snapshot>/fixture", "--outputjson"]
        or not isinstance(provenance["mypy_command"], list)
        or len(provenance["mypy_command"]) != 10
        or provenance["mypy_command"][1:]
        != [
            "--config-file",
            "<snapshot>/mypy.ini",
            "--no-incremental",
            "--show-error-codes",
            "--no-error-summary",
            "--no-pretty",
            "--follow-imports",
            "silent",
            "<snapshot>/fixture",
        ]
    ):
        raise EvaluationError(f"provider provenance does not bind consumed inputs: {fixture_name}")
    _validate_observations(record["observations"], set(source_hashes), fixture_name, schema)
    unsupported = record["unsupported"]
    expected_queries = {"definition_target", "execution_or_reachability"}
    if schema.endswith("v2"):
        expected_queries.add("cross_engine_diagnostic_semantics")
    if (
        not isinstance(unsupported, list)
        or any(
            not isinstance(item, dict)
            or set(item) != {"query", "status", "reason"}
            or not isinstance(item["query"], str)
            or item["status"] != "unsupported"
            or not isinstance(item["reason"], str)
            or not item["reason"]
            for item in unsupported
        )
        or {item["query"] for item in unsupported} != expected_queries
    ):
        raise EvaluationError(f"unsupported query declarations are incomplete: {fixture_name}")
    comparison = record["comparison"]
    if schema.endswith("v2"):
        comp_fields = {
            "policy",
            "overlapping_error_locations",
            "pyright_only_error_locations",
            "mypy_only_error_locations",
            "absence_is_not_equivalence",
            "semantic_equivalence",
        }
        if (
            not isinstance(comparison, dict)
            or set(comparison) != comp_fields
            or comparison["policy"]
            != "error-location-overlap-only; provider rules/messages remain provider-specific"
            or comparison["absence_is_not_equivalence"] is not True
            or comparison["semantic_equivalence"] != "unsupported"
        ):
            raise EvaluationError(f"invalid comparison policy: {fixture_name}")
        for key in (
            "overlapping_error_locations",
            "pyright_only_error_locations",
            "mypy_only_error_locations",
        ):
            rows = comparison[key]
            if (
                not isinstance(rows, list)
                or any(
                    not isinstance(row, list)
                    or len(row) != 2
                    or not isinstance(row[0], str)
                    or row[0] not in source_hashes
                    or type(row[1]) is not int
                    or row[1] < 1
                    for row in rows
                )
                or rows != [list(pair) for pair in sorted({(row[0], row[1]) for row in rows})]
            ):
                raise EvaluationError(f"invalid diagnostic locations: {fixture_name}")
        observations = [Observation(**item) for item in record["observations"]]
        expected_comparison = _compare(
            [item for item in observations if item.provider == "pyright"],
            [item for item in observations if item.provider == "mypy"],
        )
        if comparison != expected_comparison:
            raise EvaluationError(
                f"comparison does not match provider observations: {fixture_name}"
            )
    elif (
        not isinstance(comparison, dict)
        or set(comparison)
        != {
            "comparable_diagnostic_policy",
            "shared",
            "pyright_only",
            "mypy_only",
            "absence_is_not_equivalence",
        }
        or comparison["absence_is_not_equivalence"] is not True
        or any(
            not isinstance(comparison[key], list)
            or any(not isinstance(item, str) for item in comparison[key])
            for key in ("shared", "pyright_only", "mypy_only")
        )
    ):
        raise EvaluationError(f"invalid historical comparison record: {fixture_name}")


def _verify_result_directory(directory: Path, schema: str, *, allow_readme: bool) -> None:
    if directory.is_symlink() or not directory.is_dir():
        raise EvaluationError(f"results directory is missing or unsafe: {directory}")
    entries = list(directory.iterdir())
    if not entries:
        raise EvaluationError(f"results directory is empty: {directory}")
    allowed = {f"{name}.json" for name in FIXTURE_NAMES}
    if allow_readme:
        allowed.add("README.md")
    names = {entry.name for entry in entries}
    if names != allowed or any(entry.is_symlink() or not entry.is_file() for entry in entries):
        raise EvaluationError(f"results do not exactly cover controlled fixtures: {directory}")
    seen: set[str] = set()
    for path in sorted(directory.glob("*.json")):
        record = _loads(path.read_bytes(), f"record {path.name}")
        fixture = record.get("fixture") if isinstance(record, dict) else None
        if not isinstance(fixture, str) or fixture in seen or path.stem != fixture:
            raise EvaluationError(f"duplicate or mismatched fixture record: {path.name}")
        seen.add(fixture)
        _validate_record(record, schema, fixture)
    if seen != set(FIXTURE_NAMES):
        raise EvaluationError(f"results do not cover all fixtures: {directory}")


def verify_records(results_v2: Path = RESULTS_V2) -> None:
    _verify_result_directory(RESULTS, "pyright-mypy-differential-v1", allow_readme=True)
    _verify_result_directory(results_v2, "pyright-mypy-differential-v2", allow_readme=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", nargs="?", help="one controlled fixture directory")
    parser.add_argument("--pyright", default="/tmp/pyright-differential/node_modules/.bin/pyright")
    parser.add_argument("--mypy", default="mypy")
    parser.add_argument("--results-dir", type=Path, default=None)
    parser.add_argument("--verify-records", action="store_true")
    args = parser.parse_args()
    try:
        if args.verify_records:
            verify_records(args.results_dir or RESULTS_V2)
        elif args.fixture:
            evaluate(args.fixture, args.pyright, args.mypy, results_dir=args.results_dir)
        else:
            parser.error("fixture or --verify-records is required")
    except EvaluationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
