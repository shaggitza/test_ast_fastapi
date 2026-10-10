"""Protocol tests use in-process doubles; they are not isolated runtime evidence."""

from __future__ import annotations

import ast
import asyncio
import hashlib
import inspect
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from fastapi_endpoint_detector.analyzer.framework_phase_bridge import FrameworkPhase, SourceIdentity
from fastapi_endpoint_detector.analyzer.framework_phase_runtime import (
    PhaseManifest,
    PhaseManifestEntry,
    manifest_from_report,
)
from fastapi_endpoint_detector.models.surface_contract import load_surface_preset
from fastapi_endpoint_detector.parser import runtime_worker


def _definition_line(callback: Any) -> int:
    """Use the same definition-line domain as the static AST manifest."""
    code = callback.__code__
    tree = ast.parse(Path(code.co_filename).read_bytes())
    return next(
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == code.co_name
        and min([node.lineno, *(item.lineno for item in node.decorator_list)])
        == code.co_firstlineno
    )


_DIGEST = "sha256:" + "a" * 64


def _manifest(
    callback: Any,
    *,
    path: Path,
    line: int,
    symbol: str | None = None,
    phases: tuple[str, ...] = ("startup",),
) -> dict[str, Any]:
    identity = SourceIdentity(
        module="test_framework_phase_runtime",
        symbol=symbol or callback.__code__.co_name,
        file=str(path),
        line=line,
        column=0,
        end_line=line,
        end_column=0,
        source_sha256=_DIGEST,
    )
    file_digest = hashlib.sha256(path.read_bytes()).hexdigest()
    entries = tuple(
        PhaseManifestEntry(
            callback=identity,
            registration=identity,
            phase=phase,  # type: ignore[arg-type]
            execution_conditions=("startup succeeds",),
            contract_id=(
                "fastapi-lifespan-startup" if phase == "startup" else "fastapi-lifespan-shutdown"
            ),
            contract_sha256=load_surface_preset("framework-v1").document.contract_hashes[
                f"fastapi-lifespan-{phase}"
            ],
            source_sha256=_DIGEST,
            callback_file_sha256=file_digest,
            registration_file_sha256=file_digest,
            inventory_sha256=_DIGEST,
            engine_sha256=_DIGEST,
            config_sha256=_DIGEST,
        )
        for phase in phases
    )
    return PhaseManifest(entries=entries).model_dump(mode="json")


@asynccontextmanager
async def _successful_lifespan(_app: object):
    yield


@asynccontextmanager
async def _failing_lifespan(_app: object):
    raise RuntimeError("fixture startup failure")
    yield


def _request(manifest: dict[str, Any], app_path: Path) -> dict[str, Any]:
    return {
        "app_path": str(app_path),
        "app_variable": "app",
        "app_entry": None,
        "bootstrap_entry": None,
        "dependency_max_depth": 10,
        "dependency_max_nodes": 20,
        "dependency_max_work": 50,
        "phase_manifest": manifest,
    }


def _install_app(monkeypatch: pytest.MonkeyPatch, context: Any) -> None:
    class FakeASGIApp:
        router = SimpleNamespace(lifespan_context=context)

        async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
            assert scope["type"] == "lifespan"
            startup = await receive()
            assert startup["type"] == "lifespan.startup"
            async with self.router.lifespan_context(self):
                await send({"type": "lifespan.startup.complete"})
                shutdown = await receive()
                assert shutdown["type"] == "lifespan.shutdown"
            await send({"type": "lifespan.shutdown.complete"})

    app = FakeASGIApp()
    monkeypatch.setattr(
        runtime_worker,
        "_extractor",
        lambda _request: SimpleNamespace(_load_app=lambda: app),
    )


def test_lifespan_observation_requires_loaded_callback_identity_and_records_both_phases(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    callback = inspect.unwrap(_successful_lifespan)
    manifest = _manifest(
        callback,
        path=Path(callback.__code__.co_filename),
        line=_definition_line(callback),
        phases=("startup", "shutdown"),
    )
    _install_app(monkeypatch, _successful_lifespan)

    result = asyncio.run(runtime_worker._run_lifespan(_request(manifest, Path(__file__).parent)))

    assert result["execution_status"] == "completed"
    assert [item["phase"] for item in result["observed"]] == ["startup", "shutdown"]
    assert result["observed"][0]["registration"]["line"] == _definition_line(callback)
    assert result["unavailable"] == []


def test_manifest_occurrence_identity_includes_registration_columns() -> None:
    callback = inspect.unwrap(_successful_lifespan)
    manifest = _manifest(
        callback,
        path=Path(callback.__code__.co_filename),
        line=_definition_line(callback),
    )
    entry = manifest["entries"][0]
    distinct_callsite = {**entry, "registration": {**entry["registration"], "column": 1}}

    accepted = PhaseManifest.model_validate({**manifest, "entries": [entry, distinct_callsite]})

    assert len(accepted.entries) == 2
    with pytest.raises(ValueError, match="duplicate callback registrations"):
        PhaseManifest.model_validate({**manifest, "entries": [entry, entry]})


def test_static_report_manifest_preserves_same_line_registration_columns() -> None:
    catalog = load_surface_preset("framework-v1")
    callback = SourceIdentity(
        module="app",
        symbol="start",
        file="/snapshot/app.py",
        line=4,
        column=0,
        end_line=4,
        end_column=5,
        source_sha256=_DIGEST,
    )
    common = {
        "phase": FrameworkPhase.STARTUP,
        "callback": callback,
        "typed_callback_symbol": "app.start",
        "typed_framework_symbol": "fastapi.FastAPI.on_event",
        "framework_declaration_sha256": _DIGEST,
        "callback_file_sha256": "a" * 64,
        "registration_file_sha256": "b" * 64,
        "registration_call_site": object(),
        "resource": "startup",
        "limitations": (),
        "execution_conditions": ("startup succeeds",),
        "source_sha256": _DIGEST,
        "inventory_sha256": _DIGEST,
        "engine_sha256": _DIGEST,
        "config_sha256": _DIGEST,
        "contract_id": "fastapi-on-event",
        "canonical_contract_sha256": catalog.document.contract_hashes["fastapi-on-event"],
    }
    records = []
    for column in (10, 42):
        registration = SourceIdentity(
            module="app",
            symbol="on_event",
            file="/snapshot/app.py",
            line=8,
            column=column,
            end_line=8,
            end_column=column + 10,
            source_sha256=_DIGEST,
        )
        records.append(SimpleNamespace(**common, registration=registration))

    manifest = manifest_from_report(SimpleNamespace(records=tuple(records)))

    assert len(manifest.entries) == 2
    assert [entry.registration.column for entry in manifest.entries] == [10, 42]


def test_lifespan_callback_mismatch_is_unavailable_and_not_observed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = Path(__file__).resolve()
    callback = inspect.unwrap(_successful_lifespan)
    manifest = _manifest(callback, path=path, line=1, symbol="some_other_callback")
    _install_app(monkeypatch, _successful_lifespan)

    result = asyncio.run(runtime_worker._run_lifespan(_request(manifest, path.parent)))

    assert result["observed"] == []
    assert result["unavailable"][0]["reason"] == "loaded callback identity mismatch"


def test_registered_event_handler_is_observed_only_when_its_callback_executes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def startup_handler() -> None:
        return None

    path = Path(__file__).resolve()
    manifest = _manifest(startup_handler, path=path, line=startup_handler.__code__.co_firstlineno)
    manifest["entries"][0]["contract_id"] = "fastapi-on-event"
    manifest["entries"][0]["contract_sha256"] = load_surface_preset(
        "framework-v1"
    ).document.contract_hashes["fastapi-on-event"]

    @asynccontextmanager
    async def event_lifespan(_app: object):
        await startup_handler()
        yield

    class EventASGIApp:
        router = SimpleNamespace(lifespan_context=event_lifespan, on_startup=[startup_handler])

        async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
            assert scope["type"] == "lifespan"
            await receive()
            async with self.router.lifespan_context(self):
                await send({"type": "lifespan.startup.complete"})
                await receive()
            await send({"type": "lifespan.shutdown.complete"})

    app = EventASGIApp()
    monkeypatch.setattr(
        runtime_worker,
        "_extractor",
        lambda _request: SimpleNamespace(_load_app=lambda: app),
    )
    result = asyncio.run(runtime_worker._run_lifespan(_request(manifest, path.parent)))

    assert [item["phase"] for item in result["observed"]] == ["startup"]
    assert result["unavailable"] == []


def test_lifespan_startup_failure_does_not_claim_shutdown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    callback = inspect.unwrap(_failing_lifespan)
    manifest = _manifest(
        callback,
        path=Path(callback.__code__.co_filename),
        line=_definition_line(callback),
    )
    _install_app(monkeypatch, _failing_lifespan)

    result = asyncio.run(runtime_worker._run_lifespan(_request(manifest, Path(__file__).parent)))

    assert result["execution_status"] == "startup_failed"
    assert result["observed"] == []


def test_lifespan_shutdown_failure_discards_partial_startup_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def shutdown_failing_lifespan(_app: object):
        yield
        raise RuntimeError("shutdown failed")

    callback = inspect.unwrap(shutdown_failing_lifespan)
    manifest = _manifest(
        callback,
        path=Path(callback.__code__.co_filename),
        line=_definition_line(callback),
        phases=("startup", "shutdown"),
    )
    _install_app(monkeypatch, asynccontextmanager(shutdown_failing_lifespan))

    result = asyncio.run(runtime_worker._run_lifespan(_request(manifest, Path(__file__).parent)))

    assert result["execution_status"] == "unavailable"
    assert result["observed"] == []


def test_startup_complete_does_not_attribute_a_callback_that_did_not_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    callback = inspect.unwrap(_successful_lifespan)
    manifest = _manifest(
        callback,
        path=Path(callback.__code__.co_filename),
        line=_definition_line(callback),
    )

    class SkippingASGIApp:
        router = SimpleNamespace(lifespan_context=_successful_lifespan)

        async def __call__(self, _scope: dict[str, Any], receive: Any, send: Any) -> None:
            await receive()
            await send({"type": "lifespan.startup.complete"})
            await receive()
            await send({"type": "lifespan.shutdown.complete"})

    app = SkippingASGIApp()
    monkeypatch.setattr(
        runtime_worker,
        "_extractor",
        lambda _request: SimpleNamespace(_load_app=lambda: app),
    )

    result = asyncio.run(runtime_worker._run_lifespan(_request(manifest, Path(__file__).parent)))

    assert result["execution_status"] == "completed"
    assert result["observed"] == []


def test_lifespan_rejects_out_of_order_asgi_messages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    callback = inspect.unwrap(_successful_lifespan)
    manifest = _manifest(
        callback,
        path=Path(callback.__code__.co_filename),
        line=_definition_line(callback),
    )

    class InvalidASGIApp:
        router = SimpleNamespace(lifespan_context=_successful_lifespan)

        async def __call__(self, _scope: dict[str, Any], _receive: Any, send: Any) -> None:
            await send({"type": "lifespan.shutdown.complete"})

    app = InvalidASGIApp()
    monkeypatch.setattr(
        runtime_worker,
        "_extractor",
        lambda _request: SimpleNamespace(_load_app=lambda: app),
    )

    result = asyncio.run(runtime_worker._run_lifespan(_request(manifest, Path(__file__).parent)))

    assert result["execution_status"] == "startup_failed"
    assert result["observed"] == []


def test_lifespan_driver_returns_disposable_child_protocol_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def child_double(_request: dict[str, Any]) -> dict[str, Any]:
        return {"execution_status": "unavailable", "observed": [], "unavailable": []}

    monkeypatch.setattr(runtime_worker, "_run_lifespan", child_double)

    result = runtime_worker._run_lifespan_isolated({})

    assert result["execution_status"] == "unavailable"


def test_manifest_source_tamper_is_unavailable_before_callback_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    callback = inspect.unwrap(_successful_lifespan)
    manifest = _manifest(
        callback,
        path=Path(callback.__code__.co_filename),
        line=_definition_line(callback),
    )
    manifest["entries"][0]["callback_file_sha256"] = "b" * 64
    _install_app(monkeypatch, _successful_lifespan)

    result = asyncio.run(runtime_worker._run_lifespan(_request(manifest, Path(__file__).parent)))

    assert result["observed"] == []
    assert result["unavailable"][0]["reason"] == "callback source file digest mismatch"


def test_manifest_contract_tamper_is_rejected() -> None:
    callback = inspect.unwrap(_successful_lifespan)
    manifest = _manifest(
        callback,
        path=Path(callback.__code__.co_filename),
        line=_definition_line(callback),
    )
    manifest["entries"][0]["contract_id"] = "fastapi-on-event"

    with pytest.raises(ValueError, match="contract digest does not match framework-v1"):
        PhaseManifest.model_validate(manifest)
