"""Exact task, scheduler, CLI, and worker surface adapter fixtures."""

from pathlib import Path

from fastapi_endpoint_detector.config import AnalysisConfig, Config
from fastapi_endpoint_detector.models.endpoint import EndpointInventory, InventoryStatus
from fastapi_endpoint_detector.models.surface_contract import load_surface_preset
from fastapi_endpoint_detector.output.formatters import get_formatter
from fastapi_endpoint_detector.parser.custom_surface_extractor import CustomSurfaceExtractor


def _extract(tmp_path: Path) -> EndpointInventory:
    return CustomSurfaceExtractor(
        tmp_path,
        load_surface_preset("workers-v1"),
    ).extract_inventory()


def test_celery_and_dramatiq_tasks_have_process_worker_semantics(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from celery import Celery, shared_task\n"
        "from dramatiq import actor\n\n"
        "app = Celery('tasks')\n\n"
        "@app.task(name='billing.charge')\n"
        "def charge() -> None: pass\n\n"
        "@shared_task(name='tasks.cleanup')\n"
        "def cleanup() -> None: pass\n\n"
        "@actor(actor_name='notify')\n"
        "def send_notification() -> None: pass\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.status == InventoryStatus.ESTABLISHED
    assert [endpoint.identifier for endpoint in inventory.endpoints] == [
        "TASK.CELERY task:billing.charge",
        "TASK.CELERY task:tasks.cleanup",
        "TASK.DRAMATIQ actor:notify",
    ]
    assert all(
        endpoint.surface is not None
        and endpoint.surface.callback_mode.value == "sync"
        and endpoint.surface.execution_mode.value == "process_worker"
        for endpoint in inventory.endpoints
    )
    for output_format in ("json", "yaml", "text", "markdown", "html"):
        assert "process_worker" in get_formatter(output_format).format_inventory(inventory)


def test_imported_project_global_preserves_exact_receiver_type(tmp_path: Path) -> None:
    (tmp_path / "celery_app.py").write_text(
        "from celery import Celery\napp = Celery('tasks')\n",
        encoding="utf-8",
    )
    (tmp_path / "tasks.py").write_text(
        "from celery_app import app\n\n"
        "@app.task(name='tasks.refresh')\n"
        "def refresh() -> None: pass\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert [endpoint.identifier for endpoint in inventory.endpoints] == [
        "TASK.CELERY task:tasks.refresh"
    ]


def test_rq_requires_explicit_finite_queue_and_never_guesses_default(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from rq import job\n\n"
        "@job('high')\n"
        "def indexed() -> None: pass\n\n"
        "@job\n"
        "def unknown_queue() -> None: pass\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert [endpoint.identifier for endpoint in inventory.endpoints] == ["TASK.RQ queue:high"]
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert any("resource set was not finite" in item.reason for item in inventory.limitations)


def test_arq_imperative_function_requires_exact_async_callback(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from arq.worker import func\n\n"
        "async def refresh(ctx) -> None: pass\n"
        "def invalid_sync() -> None: pass\n\n"
        "refresh_job = func(refresh)\n"
        "invalid_job = func(invalid_sync)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert [endpoint.identifier for endpoint in inventory.endpoints] == [
        "TASK.ARQ function:refresh"
    ]
    endpoint = inventory.endpoints[0]
    assert endpoint.surface is not None
    assert endpoint.surface.execution_mode.value == "event_loop"
    assert inventory.status == InventoryStatus.CONDITIONAL


def test_apscheduler_decorator_and_imperative_jobs_are_distinct(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from apscheduler.schedulers.background import BackgroundScheduler\n\n"
        "scheduler = BackgroundScheduler()\n\n"
        "def compact() -> None: pass\n\n"
        "scheduler.add_job(compact, 'cron', id='nightly')\n\n"
        "@scheduler.scheduled_job('interval', id='heartbeat')\n"
        "def heartbeat() -> None: pass\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert [endpoint.identifier for endpoint in inventory.endpoints] == [
        "SCHEDULER.APSCHEDULER job:heartbeat",
        "SCHEDULER.APSCHEDULER job:nightly",
    ]
    assert all(
        endpoint.surface is not None and endpoint.surface.execution_mode.value == "scheduler"
        for endpoint in inventory.endpoints
    )


def test_click_typer_and_argparse_cli_handlers_have_explicit_dispatch(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "import argparse\n"
        "import click\n"
        "from typer import Typer\n\n"
        "app = Typer()\n"
        "parser = argparse.ArgumentParser()\n\n"
        "@click.command(name='serve')\n"
        "def serve_cli() -> None: pass\n\n"
        "@app.command(name='sync')\n"
        "def sync_cli() -> None: pass\n\n"
        "@app.callback()\n"
        "def root() -> None: pass\n\n"
        "def import_data() -> None: pass\n"
        "parser.set_defaults(func=import_data)\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert [endpoint.identifier for endpoint in inventory.endpoints] == [
        "CLI.ARGPARSE handler:import_data",
        "CLI.CLICK command:serve",
        "CLI.TYPER callback:root",
        "CLI.TYPER command:sync",
    ]
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert all(
        endpoint.surface is not None and endpoint.surface.execution_mode.value == "cli_dispatch"
        for endpoint in inventory.endpoints
    )


def test_click_and_typer_documented_default_names_use_kebab_case(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "import click\n"
        "from typer import Typer\n\n"
        "app = Typer()\n\n"
        "@click.command()\n"
        "def data_sync() -> None: pass\n\n"
        "@app.command()\n"
        "def cache_refresh() -> None: pass\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert [endpoint.identifier for endpoint in inventory.endpoints] == [
        "CLI.CLICK command:data-sync",
        "CLI.TYPER command:cache-refresh",
    ]


def test_celery_worker_lifecycle_callback_is_exact_and_source_backed(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from celery.signals import worker_ready\n\n"
        "@worker_ready.connect\n"
        "def initialize(sender=None, **kwargs) -> None: pass\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert [endpoint.identifier for endpoint in inventory.endpoints] == [
        "WORKER.LIFECYCLE worker-ready:initialize"
    ]


def test_celery_and_scheduler_public_ids_are_never_convention_guessed(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        "from celery import Celery\n"
        "from apscheduler.schedulers.background import BackgroundScheduler\n\n"
        "app = Celery('tasks')\n"
        "scheduler = BackgroundScheduler()\n\n"
        "@app.task\n"
        "def implicit_task() -> None: pass\n\n"
        "def implicit_job() -> None: pass\n"
        "scheduler.add_job(implicit_job, 'cron')\n",
        encoding="utf-8",
    )

    inventory = _extract(tmp_path)

    assert inventory.endpoints == []
    assert inventory.status == InventoryStatus.CONDITIONAL
    assert all(
        "resource set was not finite" in limitation.reason for limitation in inventory.limitations
    )


def test_same_named_unrelated_task_decorator_never_matches(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from unrelated import Celery\n\n"
        "app = Celery()\n\n"
        "@app.task(name='wrong')\n"
        "def wrong() -> None: pass\n",
        encoding="utf-8",
    )

    assert _extract(tmp_path).endpoints == []


def test_workers_preset_loads_once() -> None:
    config = Config(analysis=AnalysisConfig(surface_preset="workers-v1"))

    first = config.load_surface_contract_snapshot()

    assert first is config.load_surface_contract_snapshot()
    assert first is not None
    assert first.document.preset.id == "workers-and-cli"
