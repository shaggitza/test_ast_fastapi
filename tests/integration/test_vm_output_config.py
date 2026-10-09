"""VM CLI output configuration is either honored or rejected before runtime."""

from pathlib import Path

import pytest
from click.testing import CliRunner

from fastapi_endpoint_detector.cli import cli
from fastapi_endpoint_detector.executor.vm_executor import VMExecutor


@pytest.mark.parametrize("command", ["analyze", "list"])
@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("show_confidence", "false"),
        ("show_dependency_chain", "true"),
        ("colorize", "false"),
        ("verbose", "true"),
    ],
)
def test_vm_rejects_nondefault_output_options_before_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    option: str,
    value: str,
) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(f"output:\n  {option}: {value}\n", encoding="utf-8")
    app = tmp_path / "app.py"
    app.write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    output = tmp_path / "result.txt"
    args = [
        "--config",
        str(config),
        command,
        "--app",
        str(app),
        "--format",
        "text",
        "--output",
        str(output),
        "--vm",
    ]
    if command == "analyze":
        diff = tmp_path / "change.diff"
        diff.write_text("", encoding="utf-8")
        args.extend(["--diff", str(diff)])

    def unexpected_side_effect(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("VM runtime must not start for unsupported output options")

    monkeypatch.setattr(VMExecutor, "__init__", unexpected_side_effect)
    monkeypatch.setattr(VMExecutor, "analyze_in_vm", unexpected_side_effect)

    result = CliRunner().invoke(cli, args)

    assert result.exit_code != 0
    assert f"Output option '{option}' cannot be applied with --vm" in result.output
    assert not output.exists()


@pytest.mark.parametrize("command", ["analyze", "list"])
def test_vm_accepts_default_output_options(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("output: {}\n", encoding="utf-8")
    app = tmp_path / "app.py"
    app.write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    args = ["--config", str(config), command, "--app", str(app), "--format", "text", "--vm"]
    if command == "analyze":
        diff = tmp_path / "change.diff"
        diff.write_text("", encoding="utf-8")
        args.extend(["--diff", str(diff)])

    def fake_init(self: VMExecutor, *_args: object, **_kwargs: object) -> None:
        return None

    def fake_analyze(self: VMExecutor, *_args: object, **_kwargs: object) -> str:
        return "VM formatted output"

    monkeypatch.setattr(VMExecutor, "__init__", fake_init)
    monkeypatch.setattr(VMExecutor, "analyze_in_vm", fake_analyze)

    result = CliRunner().invoke(cli, args)

    assert result.exit_code == 0, result.output
    assert result.output == "VM formatted output"
