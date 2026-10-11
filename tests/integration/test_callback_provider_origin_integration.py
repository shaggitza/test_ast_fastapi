"""Selected project wrappers must use ordinary project tracing."""

from pathlib import Path

from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.models.effect_contract import CallResolutionStatus
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo


def _endpoint(main: Path) -> Endpoint:
    return Endpoint(
        path="/project-anyio",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="handler",
            module="main",
            file_path=main,
            line_number=4,
        ),
    )


def test_project_owned_anyio_wrapper_uses_normal_project_tracing(tmp_path: Path) -> None:
    package = tmp_path / "anyio"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "to_thread.py").write_text(
        "from worker import changed\n\n"
        "def project_helper() -> int:\n"
        "    return changed()\n\n"
        "async def run_sync(func) -> int:\n"
        "    return project_helper()\n",
        encoding="utf-8",
    )
    worker = tmp_path / "worker.py"
    worker.write_text("def changed() -> int:\n    return 1\n", encoding="utf-8")
    main = tmp_path / "main.py"
    main.write_text(
        "from anyio.to_thread import run_sync\n"
        "from worker import changed\n\n"
        "async def handler() -> int:\n"
        "    return await run_sync(changed)\n",
        encoding="utf-8",
    )

    deps = MypyAnalyzer(tmp_path, max_depth=5).analyze_endpoint(_endpoint(main))

    assert deps.references_symbol_at_line("anyio/to_thread.py", 3) is not None
    assert deps.references_symbol_at_line("worker.py", 1) is not None
    assert all(
        item.cap != "CALLBACK_PROVIDER_ORIGIN_UNVERIFIED" for item in deps.analysis_limitations
    )
    stacks = deps.get_call_stack("worker.py")
    assert stacks
    assert any(
        frame.function_name == "anyio.to_thread.project_helper"
        for stack in stacks
        for frame in stack
    )
    assert not any(
        "executor_callback:" in frame.code_context for stack in stacks for frame in stack
    )

    sites = [
        site
        for site in deps.get_resolved_call_sites(str(main))
        if site.source_spelling == "run_sync"
    ]
    assert len(sites) == 1
    site = sites[0]
    assert site.status == CallResolutionStatus.EXACT
    assert site.canonical_symbol == "anyio.to_thread.run_sync"
    assert site.line == 5
    assert site.end_column is not None
    source_line = main.read_text(encoding="utf-8").splitlines()[site.line - 1]
    assert source_line[site.column : site.end_column] == "run_sync"
