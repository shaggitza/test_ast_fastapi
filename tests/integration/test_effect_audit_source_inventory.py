"""Public effect auditing must honor the configured source scope."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
import yaml
from click.testing import CliRunner

from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.cli import cli
from fastapi_endpoint_detector.config import Config
from fastapi_endpoint_detector.parser.secure_ast_extractor import SecureASTExtractor

if TYPE_CHECKING:
    from pathlib import Path

    from fastapi_endpoint_detector.analyzer.source_inventory import SourceInventory


def _app(root: Path, *, helper: bool = False) -> Path:
    helper_import = "from helpers import emit\n" if helper else ""
    result = "emit('orders')" if helper else "1"
    app = root / "main.py"
    app.write_text(
        "from fastapi import FastAPI\n"
        + helper_import
        + "app = FastAPI()\n@app.get('/visible')\ndef handler() -> int:\n"
        + f"    return {result}\n",
        encoding="utf-8",
    )
    if helper:
        (root / "helpers.py").write_text(
            "def emit(resource: str) -> int:\n    return 1\n", encoding="utf-8"
        )
    return app


def _config(root: Path, data: dict[str, Any]) -> Path:
    path = root / "detector.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def _arguments(config: Path, app: Path) -> list[str]:
    return [
        "--config",
        str(config),
        "audit-effect-contracts",
        "--app",
        str(app),
        "--preset",
        "filesystem-v1",
        "--format",
        "json",
    ]


def test_public_audit_shares_selected_scope_across_ast_mypy_and_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _app(tmp_path)
    ignored = tmp_path / "ignored.py"
    ignored.write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n"
        "@app.get('/excluded')\ndef excluded() -> int:\n    return 2\n",
        encoding="utf-8",
    )
    config = _config(
        tmp_path,
        {"parser": {"include_patterns": ["**/*.py"], "exclude_patterns": ["ignored.py"]}},
    )
    scopes: list[SourceInventory] = []
    ast_paths: list[tuple[Path, ...]] = []
    typed_scopes: list[SourceInventory] = []
    typed_roots: list[Path] = []
    original_inventory = Config.source_inventory
    original_ast_init = SecureASTExtractor.__init__
    original_mypy_init = MypyAnalyzer.__init__

    def inventory(self: Config, source: Path) -> SourceInventory:
        scope = original_inventory(self, source)
        scopes.append(scope)
        return scope

    def ast_init(self: SecureASTExtractor, *args: Any, **kwargs: Any) -> None:
        ast_paths.append(kwargs["source_paths"])
        original_ast_init(self, *args, **kwargs)

    def mypy_init(self: MypyAnalyzer, *args: Any, **kwargs: Any) -> None:
        typed_roots.append(args[0])
        typed_scopes.append(kwargs["source_inventory"])
        original_mypy_init(self, *args, **kwargs)

    monkeypatch.setattr(Config, "source_inventory", inventory)
    monkeypatch.setattr(SecureASTExtractor, "__init__", ast_init)
    monkeypatch.setattr(MypyAnalyzer, "__init__", mypy_init)
    runner = CliRunner()
    cold = runner.invoke(cli, [*_arguments(config, app), "--clear-cache"])
    assert cold.exit_code == 0, cold.output
    ignored.write_text("unselected = 3\n", encoding="utf-8")
    warm = runner.invoke(cli, _arguments(config, app))
    assert warm.exit_code == 0, warm.output

    assert json.loads(cold.output) == json.loads(warm.output)
    report = json.loads(warm.output)
    assert {endpoint["path"] for endpoint in report["scope"]["endpoint_inventory"]} == {"/visible"}
    assert len(scopes) == len(ast_paths) == len(typed_scopes) == len(typed_roots) == 2
    for scope, paths, typed_scope, typed_root in zip(
        scopes, ast_paths, typed_scopes, typed_roots, strict=True
    ):
        assert paths == scope.paths == (app,)
        assert typed_scope is scope
        assert typed_root == scope.root == tmp_path
        assert ignored not in paths


@pytest.mark.parametrize(
    ("mode", "message"),
    [
        ("mypy-disabled", "requires integrations.use_mypy=true"),
        ("empty", "selects no Python source files"),
        ("excluded-helper", "complete contract coverage unavailable"),
        ("import-policy", "complete contract coverage unavailable"),
        ("stub-only", "Selected type stub"),
        ("type-shadow", "type stub helpers.pyi"),
    ],
)
def test_public_audit_rejects_unsupported_scope_before_engine_construction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str, message: str
) -> None:
    app = _app(tmp_path, helper=True)
    data: dict[str, Any] = {}
    if mode == "mypy-disabled":
        data = {"integrations": {"use_mypy": False}}
    elif mode == "empty":
        data = {"parser": {"include_patterns": ["missing.py"]}}
    elif mode == "excluded-helper":
        data = {"parser": {"exclude_patterns": ["helpers.py"]}}
    elif mode == "import-policy":
        data = {"parser": {"include_patterns": ["main.py"], "follow_imports": False}}
    else:
        (tmp_path / "helpers.pyi").write_text(
            "def emit(resource: str) -> int: ...\n", encoding="utf-8"
        )
        if mode == "stub-only":
            data = {"parser": {"include_patterns": ["**/*.pyi"]}}
    config = _config(tmp_path, data)
    entered: list[str] = []

    def unexpected_ast(*_args: Any, **_kwargs: Any) -> None:
        entered.append("ast")
        pytest.fail("unsupported scope reached endpoint extraction")

    def unexpected_mypy(*_args: Any, **_kwargs: Any) -> None:
        entered.append("mypy")
        pytest.fail("unsupported scope reached typed analysis")

    monkeypatch.setattr(SecureASTExtractor, "__init__", unexpected_ast)
    monkeypatch.setattr(MypyAnalyzer, "__init__", unexpected_mypy)
    result = CliRunner().invoke(cli, _arguments(config, app))

    assert result.exit_code != 0
    assert message in result.output
    assert "Effect contract audit complete" not in result.output
    assert entered == []


@pytest.mark.parametrize("include_test_endpoints", [False, True])
def test_public_audit_consumes_include_test_endpoints(
    tmp_path: Path, include_test_endpoints: bool
) -> None:
    app = tmp_path / "main.py"
    app.write_text(
        "from fastapi import FastAPI\nfrom test_routes import router\n"
        "app = FastAPI()\napp.include_router(router)\n",
        encoding="utf-8",
    )
    (tmp_path / "test_routes.py").write_text(
        "from fastapi import APIRouter\nrouter = APIRouter()\n"
        "@router.get('/test-selected')\ndef handler() -> int:\n    return 1\n",
        encoding="utf-8",
    )
    config = _config(tmp_path, {"analysis": {"include_test_endpoints": include_test_endpoints}})

    result = CliRunner().invoke(cli, [*_arguments(config, app), "--no-cache"])

    if include_test_endpoints:
        assert result.exit_code == 0, result.output
        report = json.loads(result.output)
        assert {row["path"] for row in report["scope"]["endpoint_inventory"]} == {"/test-selected"}
    else:
        assert result.exit_code != 0
        assert "complete contract coverage unavailable" in result.output
