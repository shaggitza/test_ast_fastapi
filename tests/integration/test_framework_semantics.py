"""End-to-end framework callback surface and reachability semantics."""

from pathlib import Path

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.config import AnalysisConfig, Config
from fastapi_endpoint_detector.models.report import ConfidenceLevel


def test_lifespan_transitive_calls_remain_phase_sensitive(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from contextlib import asynccontextmanager\n"
        "from fastapi import FastAPI\n\n"
        "async def initialize() -> int:\n"
        "    return 2\n\n"
        "async def finalize() -> int:\n"
        "    return 1\n\n"
        "@asynccontextmanager\n"
        "async def lifespan(app: FastAPI):\n"
        "    await initialize()\n"
        "    yield\n"
        "    await finalize()\n\n"
        "app = FastAPI(lifespan=lifespan)\n",
        encoding="utf-8",
    )
    diff = tmp_path / "change.diff"
    diff.write_text(
        "diff --git a/main.py b/main.py\n"
        "--- a/main.py\n"
        "+++ b/main.py\n"
        "@@ -4,2 +4,2 @@\n"
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
        "FRAMEWORK.LIFECYCLE lifespan:startup"
    ]
    assert report.candidate_endpoints[0].confidence == ConfidenceLevel.MEDIUM


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


def test_changed_class_middleware_dispatch_is_exact_framework_candidate(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from starlette.middleware.base import BaseHTTPMiddleware\n\n"
        "class AuditMiddleware(BaseHTTPMiddleware):\n"
        "    async def dispatch(self, request, call_next):\n"
        "        response = await call_next(request)\n"
        "        response.headers['x-audit'] = 'new'\n"
        "        return response\n\n"
        "app = FastAPI()\n"
        "app.add_middleware(AuditMiddleware)\n",
        encoding="utf-8",
    )
    diff = tmp_path / "change.diff"
    diff.write_text(
        "diff --git a/main.py b/main.py\n"
        "--- a/main.py\n"
        "+++ b/main.py\n"
        "@@ -7,1 +7,1 @@\n"
        "-        response.headers['x-audit'] = 'old'\n"
        "+        response.headers['x-audit'] = 'new'\n",
        encoding="utf-8",
    )

    report = ChangeMapper(
        app_path=tmp_path,
        config=Config(analysis=AnalysisConfig(surface_preset="framework-v1")),
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)

    assert [candidate.endpoint.identifier for candidate in report.candidate_endpoints] == [
        "FRAMEWORK.MIDDLEWARE protocol:http"
    ]
    candidate = report.candidate_endpoints[0]
    assert candidate.endpoint.handler.name == "dispatch"
    assert candidate.confidence == ConfidenceLevel.HIGH
    assert all(
        "starlette" not in frame.file_path for stack in candidate.call_stacks for frame in stack
    )


def test_changed_startup_added_route_is_a_conditional_http_candidate(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n\n"
        "async def late() -> int:\n"
        "    return 2\n\n"
        "@app.on_event('startup')\n"
        "async def install() -> None:\n"
        "    app.add_api_route('/late', late)\n",
        encoding="utf-8",
    )
    diff = tmp_path / "change.diff"
    diff.write_text(
        "diff --git a/main.py b/main.py\n"
        "--- a/main.py\n"
        "+++ b/main.py\n"
        "@@ -5,2 +5,2 @@\n"
        " async def late() -> int:\n"
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

    candidates = {
        candidate.endpoint.identifier: candidate for candidate in report.candidate_endpoints
    }
    assert "GET /late" in candidates
    assert candidates["GET /late"].confidence == ConfidenceLevel.LOW
    assert candidates["GET /late"].endpoint.discovery_conditions
    assert candidates["GET /late"].endpoint.activation is not None


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
