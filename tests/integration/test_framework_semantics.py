"""End-to-end framework callback surface and reachability semantics."""

from pathlib import Path

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.config import AnalysisConfig, Config
from fastapi_endpoint_detector.models.report import ConfidenceLevel


def test_changed_startup_handler_is_a_framework_lifecycle_candidate(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n\n"
        "@app.on_event('startup')\n"
        "async def initialize() -> int:\n"
        "    return 2\n",
        encoding="utf-8",
    )
    diff = tmp_path / "change.diff"
    diff.write_text(
        "diff --git a/main.py b/main.py\n"
        "--- a/main.py\n"
        "+++ b/main.py\n"
        "@@ -6,2 +6,2 @@\n"
        " async def initialize() -> int:\n"
        "-    return 1\n"
        "+    return 2\n",
        encoding="utf-8",
    )

    report = ChangeMapper(
        app_path=tmp_path,
        config=Config(analysis=AnalysisConfig(surface_preset="framework-v1")),
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)

    assert [candidate.endpoint.identifier for candidate in report.candidate_endpoints] == [
        "FRAMEWORK.LIFECYCLE event:startup"
    ]
    assert report.candidate_endpoints[0].confidence == ConfidenceLevel.HIGH


def test_changed_background_callback_is_low_boundary_from_http_handler(
    tmp_path: Path,
) -> None:
    (tmp_path / "worker.py").write_text(
        "def notify() -> int:\n    return 2\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import BackgroundTasks, FastAPI\n"
        "from worker import notify\n\n"
        "app = FastAPI()\n\n"
        "@app.post('/jobs')\n"
        "def submit(tasks: BackgroundTasks) -> dict[str, bool]:\n"
        "    tasks.add_task(notify)\n"
        "    return {'queued': True}\n",
        encoding="utf-8",
    )
    diff = tmp_path / "change.diff"
    diff.write_text(
        "diff --git a/worker.py b/worker.py\n"
        "--- a/worker.py\n"
        "+++ b/worker.py\n"
        "@@ -1,2 +1,2 @@\n"
        " def notify() -> int:\n"
        "-    return 1\n"
        "+    return 2\n",
        encoding="utf-8",
    )

    report = ChangeMapper(
        app_path=tmp_path,
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)

    assert [candidate.endpoint.identifier for candidate in report.candidate_endpoints] == [
        "POST /jobs"
    ]
    candidate = report.candidate_endpoints[0]
    assert candidate.confidence == ConfidenceLevel.LOW
    assert any(
        "background_task_callback:" in (frame.code_context or "")
        for stack in candidate.call_stacks
        for frame in stack
    )
