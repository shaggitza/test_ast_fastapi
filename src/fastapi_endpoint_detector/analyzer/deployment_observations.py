"""Finite source observations for deployment configuration and subprocesses.

The recognizers never expand variables, evaluate shell commands, or execute
repository content. Unknown/dynamic values are retained as uncertainty records.
"""

from __future__ import annotations

import ast
import json
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

_ROUTE_ENV_KEYS = frozenset(
    {
        "API_BASE_URL",
        "API_URL",
        "BASE_PATH",
        "FASTAPI_ROOT_PATH",
        "HOST",
        "NEXT_PUBLIC_API_URL",
        "PORT",
        "PUBLIC_API_URL",
        "ROOT_PATH",
        "VITE_API_BASE_URL",
        "WEBSOCKET_URL",
        "WS_URL",
    }
)
_DYNAMIC_ENV = re.compile(r"\$(?:\{[^}]+\}|[A-Za-z_][A-Za-z0-9_]*)")
_INSTRUCTIONS = frozenset({"ENV", "EXPOSE", "ENTRYPOINT", "CMD"})
_SUBPROCESS_CALLS = frozenset({"run", "Popen", "call", "check_call", "check_output"})


@dataclass(frozen=True)
class DeploymentObservation:
    """One literal deployment or process-launch fact from source."""

    source_path: Path
    line: int
    kind: str
    key: str | None
    value: str | tuple[str, ...] | None
    certainty: str
    uncertainty: str | None = None


def _env_value(path: Path, line: int, key: str, value: str) -> DeploymentObservation:
    if key.upper() not in _ROUTE_ENV_KEYS:
        return DeploymentObservation(
            path,
            line,
            "environment",
            key,
            None,
            "uncertain",
            "value not in route configuration allowlist",
        )
    unquoted = value.strip()
    if len(unquoted) >= 2 and unquoted[0] == unquoted[-1] and unquoted[0] in "'\"":
        unquoted = unquoted[1:-1]
    if _DYNAMIC_ENV.search(unquoted):
        return DeploymentObservation(
            path, line, "environment", key, None, "uncertain", "value contains variable expansion"
        )
    if "URL" in key.upper():
        try:
            parsed = urlsplit(unquoted)
        except ValueError:
            parsed = None
        if parsed is not None and (
            parsed.username or parsed.password or parsed.query or parsed.fragment
        ):
            return DeploymentObservation(
                path,
                line,
                "environment",
                key,
                None,
                "uncertain",
                "URL contains credentials or query/fragment data",
            )
    return DeploymentObservation(path, line, "environment", key, unquoted, "exact")


def extract_env_observations(
    source: str, source_path: Path | str = ".env"
) -> tuple[DeploymentObservation, ...]:
    """Observe simple KEY=value lines; never expand values or expose non-route values."""
    path = Path(source_path)
    observations: list[DeploymentObservation] = []
    for line_number, raw in enumerate(source.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, separator, value = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key.strip()):
            continue
        observations.append(_env_value(path, line_number, key.strip(), value.strip()))
    return tuple(observations)


def _docker_logical_lines(source: str) -> list[tuple[int, str]]:
    logical: list[tuple[int, str]] = []
    pending = ""
    start_line = 0
    for number, physical in enumerate(source.splitlines(), 1):
        text = physical.rstrip()
        if not pending:
            start_line = number
        if text.endswith("\\"):
            pending += text[:-1] + " "
            continue
        logical.append((start_line, pending + text))
        pending = ""
    if pending:
        logical.append((start_line, pending))
    return logical


def extract_dockerfile_observations(  # noqa: PLR0912
    source: str, source_path: Path | str = "Dockerfile"
) -> tuple[DeploymentObservation, ...]:
    """Observe route-relevant ENV, exposed ports, and exec-form startup argv."""
    path = Path(source_path)
    observations: list[DeploymentObservation] = []
    for line_number, raw in _docker_logical_lines(source):
        text = raw.strip()
        if not text or text.startswith("#"):
            continue
        instruction, _, argument = text.partition(" ")
        instruction = instruction.upper()
        if instruction not in _INSTRUCTIONS:
            continue
        argument = argument.strip()
        if instruction == "ENV":
            try:
                parts = shlex.split(argument, comments=False, posix=True)
            except ValueError:
                observations.append(
                    DeploymentObservation(
                        path, line_number, "environment", None, None, "uncertain", "malformed ENV"
                    )
                )
                continue
            pairs: list[tuple[str, str]] = []
            if parts and all("=" in part for part in parts):
                for part in parts:
                    key, _, value = part.partition("=")
                    pairs.append((key, value))
            elif len(parts) >= 2 and "=" not in parts[0]:
                pairs.append((parts[0], " ".join(parts[1:])))
            elif parts:
                observations.append(
                    DeploymentObservation(
                        path, line_number, "environment", None, None, "uncertain", "malformed ENV"
                    )
                )
            for key, value in pairs:
                observations.append(_env_value(path, line_number, key, value))
        elif instruction == "EXPOSE":
            try:
                ports = shlex.split(argument, comments=False, posix=True)
            except ValueError:
                ports = []
            for port in ports:
                if re.fullmatch(r"[0-9]+(?:/(?:tcp|udp|sctp))?", port, re.IGNORECASE):
                    observations.append(
                        DeploymentObservation(
                            path, line_number, "exposed_port", None, port.lower(), "exact"
                        )
                    )
                else:
                    observations.append(
                        DeploymentObservation(
                            path,
                            line_number,
                            "exposed_port",
                            None,
                            None,
                            "uncertain",
                            "dynamic or malformed port",
                        )
                    )
        elif argument.startswith("["):
            try:
                argv = json.loads(argument)
            except json.JSONDecodeError:
                argv = None
            if isinstance(argv, list) and all(isinstance(item, str) for item in argv):
                observations.append(
                    DeploymentObservation(
                        path,
                        line_number,
                        "container_argv",
                        instruction.lower(),
                        tuple(argv),
                        "exact",
                    )
                )
            else:
                observations.append(
                    DeploymentObservation(
                        path,
                        line_number,
                        "container_argv",
                        instruction.lower(),
                        None,
                        "uncertain",
                        "invalid exec-form command",
                    )
                )
        else:
            observations.append(
                DeploymentObservation(
                    path,
                    line_number,
                    "container_argv",
                    instruction.lower(),
                    None,
                    "uncertain",
                    "shell-form command is not interpreted",
                )
            )
    return tuple(observations)


def _literal_argv(node: ast.AST) -> tuple[str, ...] | None:
    if not isinstance(node, (ast.List, ast.Tuple)):
        return None
    values: list[str] = []
    for item in node.elts:
        if not isinstance(item, ast.Constant) or not isinstance(item.value, str):
            return None
        values.append(item.value)
    return tuple(values)


def extract_subprocess_observations(
    source: str, source_path: Path | str = "<memory>"
) -> tuple[DeploymentObservation, ...]:
    """Observe direct ``subprocess`` calls with literal argv, without execution."""
    path = Path(source_path)
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return ()
    observations: list[DeploymentObservation] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if (
            node.func.attr not in _SUBPROCESS_CALLS
            or not isinstance(node.func.value, ast.Name)
            or node.func.value.id != "subprocess"
        ):
            continue
        shell = next(
            (keyword.value for keyword in node.keywords if keyword.arg == "shell"),
            ast.Constant(value=False),
        )
        argv = _literal_argv(node.args[0]) if node.args else None
        if isinstance(shell, ast.Constant) and shell.value is False and argv is not None:
            observations.append(
                DeploymentObservation(
                    path, node.lineno, "subprocess_argv", node.func.attr, argv, "exact"
                )
            )
        else:
            reason = (
                "shell execution is excluded"
                if isinstance(shell, ast.Constant) and shell.value is True
                else "dynamic argv or shell mode"
            )
            observations.append(
                DeploymentObservation(
                    path, node.lineno, "subprocess_argv", node.func.attr, None, "uncertain", reason
                )
            )
    return tuple(sorted(observations, key=lambda item: (item.line, item.kind, item.key or "")))
