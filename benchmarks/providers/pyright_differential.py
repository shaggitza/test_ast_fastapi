"""Bounded differential diagnostics for controlled Pyright/mypy type fixtures.

This tool does not infer execution, endpoint reachability, or canonical truth.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "benchmarks/providers/fixtures/pyright_differential"
RESULTS = ROOT / "benchmarks/results/pyright-differential-v1"
PYRIGHT_VERSION = "1.1.411"
MAX_FILES = 32
MAX_BYTES = 256_000
TIMEOUT_SECONDS = 25
_RANGE = re.compile(r"^(.*?):(\d+):(\d+): (error|warning|note): (.*?)(?:\s+\[([^]]+)\])?$")


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


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def _read_pyright(raw: str, fixture: Path) -> tuple[str, list[Observation]]:
    try:
        data = json.loads(raw)
        version = data["version"]
        diagnostics = data["generalDiagnostics"]
        if not isinstance(version, str) or not isinstance(diagnostics, list):
            raise ValueError("unexpected version or diagnostic shape")
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise EvaluationError(f"malformed Pyright JSON: {exc}") from exc
    result: list[Observation] = []
    for item in diagnostics:
        try:
            file = Path(item["file"]).resolve().relative_to(fixture.resolve()).as_posix()
            start = item["range"]["start"]
            result.append(
                Observation(
                    "pyright",
                    "diagnostic",
                    file,
                    start["line"] + 1,
                    start["character"] + 1,
                    item["severity"],
                    item["message"],
                    item.get("rule"),
                    True,
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise EvaluationError(f"malformed Pyright diagnostic: {exc}") from exc
    return version, result


def _read_mypy(raw: str, fixture: Path) -> list[Observation]:
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
            relative = path.resolve().relative_to(fixture.resolve()).as_posix()
        except ValueError as exc:
            raise EvaluationError(f"mypy diagnostic outside fixture: {name}") from exc
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
            )
        )
    return result


def _version(command: list[str], expected: str, provider: str) -> str:
    result = _run(command, ROOT)
    if result.returncode:
        raise EvaluationError(f"cannot read {provider} version: {result.stderr.strip()}")
    actual = result.stdout.strip().splitlines()[0]
    if expected not in actual:
        raise EvaluationError(f"expected {provider} {expected}, got {actual!r}")
    return actual


def _fixture_inputs(fixture: Path) -> list[Path]:
    files = sorted(fixture.rglob("*.py"))
    if not files or len(files) > MAX_FILES:
        raise EvaluationError(f"fixture file count must be 1..{MAX_FILES}")
    if sum(path.stat().st_size for path in files) > MAX_BYTES:
        raise EvaluationError(f"fixture exceeds {MAX_BYTES} source bytes")
    return files


def evaluate(name: str, pyright_bin: str, mypy_bin: str, *, write: bool = True) -> dict[str, Any]:
    fixture = (FIXTURES / name).resolve()
    if FIXTURES.resolve() not in fixture.parents or not fixture.is_dir():
        raise EvaluationError(f"unknown fixture: {name}")
    files = _fixture_inputs(fixture)
    pyright_version = _version([pyright_bin, "--version"], PYRIGHT_VERSION, "Pyright")
    mypy_version = _version([mypy_bin, "--version"], "2.4.0", "mypy")
    start = time.monotonic()
    pyright = _run([pyright_bin, "--project", str(fixture), "--outputjson"], ROOT)
    if pyright.returncode not in (0, 1):
        raise EvaluationError(f"Pyright failed ({pyright.returncode}): {pyright.stderr[:500]}")
    pyright_json = pyright.stdout
    observed_version, p_obs = _read_pyright(pyright_json, fixture)
    if observed_version != PYRIGHT_VERSION:
        raise EvaluationError(f"Pyright JSON version mismatch: {observed_version}")
    mypy = _run(
        [
            mypy_bin,
            "--show-error-codes",
            "--no-error-summary",
            "--no-pretty",
            "--follow-imports",
            "silent",
            str(fixture),
        ],
        ROOT,
    )
    if mypy.returncode not in (0, 1):
        raise EvaluationError(f"mypy failed ({mypy.returncode}): {mypy.stderr[:500]}")
    m_obs = _read_mypy(mypy.stdout + mypy.stderr, fixture)
    hashes = {path.relative_to(fixture).as_posix(): sha256(path) for path in files}
    record: dict[str, Any] = {
        "schema": "pyright-mypy-differential-v1",
        "fixture": name,
        "source_sha256": hashes,
        "config_sha256": {p.name: sha256(p) for p in fixture.glob("pyrightconfig.json")},
        "engines": {"pyright": pyright_version, "mypy": mypy_version},
        "provenance": {
            "pyright_command": [pyright_bin, "--project", "<fixture>", "--outputjson"],
            "mypy_command": [
                mypy_bin,
                "--show-error-codes",
                "--no-error-summary",
                "--no-pretty",
                "--follow-imports",
                "silent",
                "<fixture>",
            ],
            "fixture_root": name,
            "max_files": MAX_FILES,
            "max_source_bytes": MAX_BYTES,
            "provider_timeout_seconds": TIMEOUT_SECONDS,
            "elapsed_seconds": round(time.monotonic() - start, 3),
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
        ],
        "scope": "synthetic fixtures only; no corpus application execution or canonical truth",
    }
    if write:
        destination = RESULTS / f"{name}.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(record, indent=2, sort_keys=True) + "\n"
        if destination.exists() and destination.read_text(encoding="utf-8") != payload:
            raise EvaluationError(
                f"immutable record already exists with different content: {destination}"
            )
        destination.write_text(payload, encoding="utf-8")
    return record


def _compare(pyright: list[Observation], mypy: list[Observation]) -> dict[str, Any]:
    def keys(
        observations: list[Observation],
    ) -> set[tuple[str | None, int | None, str | None, str | None]]:
        return {
            (item.file, item.line, item.severity, item.rule or item.message)
            for item in observations
            if item.comparable and item.severity == "error"
        }

    p_keys, m_keys = keys(pyright), keys(mypy)
    return {
        "comparable_diagnostic_policy": "error location and normalized rule/message exact match",
        "shared": sorted(map(str, p_keys & m_keys)),
        "pyright_only": sorted(map(str, p_keys - m_keys)),
        "mypy_only": sorted(map(str, m_keys - p_keys)),
        "absence_is_not_equivalence": True,
    }


def verify_records() -> None:
    for record_path in sorted(RESULTS.glob("*.json")):
        record = json.loads(record_path.read_text(encoding="utf-8"))
        if record.get("schema") != "pyright-mypy-differential-v1":
            raise EvaluationError(f"unexpected record schema: {record_path}")
        fixture = FIXTURES / record["fixture"]
        current = {p.relative_to(fixture).as_posix(): sha256(p) for p in _fixture_inputs(fixture)}
        if current != record["source_sha256"]:
            raise EvaluationError(f"stale source hashes: {record_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", nargs="?", help="one controlled fixture directory")
    parser.add_argument("--pyright", default="/tmp/pyright-differential/node_modules/.bin/pyright")
    parser.add_argument("--mypy", default="mypy")
    parser.add_argument("--verify-records", action="store_true")
    args = parser.parse_args()
    try:
        if args.verify_records:
            verify_records()
        elif args.fixture:
            evaluate(args.fixture, args.pyright, args.mypy)
        else:
            parser.error("fixture or --verify-records is required")
    except EvaluationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
