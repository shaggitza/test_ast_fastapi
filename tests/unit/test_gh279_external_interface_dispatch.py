from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.models.effect_contract import (
    CallResolutionStatus,
    ResolvedCallSite,
)
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo

if TYPE_CHECKING:
    from pathlib import Path


def _external_run_site(tmp_path: Path, *, stub: str, source: str) -> ResolvedCallSite:
    project = tmp_path / "project"
    project.mkdir(parents=True)
    (tmp_path / "api.pyi").write_text(stub, encoding="utf-8")
    main = project / "main.py"
    main.write_text(source, encoding="utf-8")
    endpoint = Endpoint(
        path="/test",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="handler",
            module="main",
            file_path=main,
            line_number=3,
        ),
    )
    dependencies = MypyAnalyzer(
        project,
        module_root=tmp_path,
        no_site_packages=True,
    ).analyze_endpoint(endpoint)
    sites = [
        site for site in dependencies.resolved_call_sites if site.source_spelling == "value.run"
    ]
    assert len(sites) == 1
    return sites[0]


def test_external_protocol_method_is_not_exact(tmp_path: Path) -> None:
    site = _external_run_site(
        tmp_path,
        stub=(
            "from typing import Protocol\nclass Runner(Protocol):\n    def run(self) -> None: ...\n"
        ),
        source=("from api import Runner\n\ndef handler(value: Runner) -> None:\n    value.run()\n"),
    )

    assert site.status == CallResolutionStatus.AMBIGUOUS
    assert site.reason_code == "open_receiver_dispatch"
    assert site.canonical_symbol is None
    assert site.invocation is None


def test_external_abstract_method_is_not_exact(tmp_path: Path) -> None:
    site = _external_run_site(
        tmp_path,
        stub=(
            "from abc import ABC, abstractmethod\n"
            "class Runner(ABC):\n"
            "    @abstractmethod\n"
            "    def run(self) -> None: ...\n"
        ),
        source=("from api import Runner\n\ndef handler(value: Runner) -> None:\n    value.run()\n"),
    )

    assert site.status == CallResolutionStatus.AMBIGUOUS
    assert site.reason_code == "open_receiver_dispatch"
    assert site.canonical_symbol is None
    assert site.invocation is None


def test_external_final_class_keeps_exact_dispatch(tmp_path: Path) -> None:
    site = _external_run_site(
        tmp_path,
        stub=("from typing import final\n@final\nclass Service:\n    def run(self) -> None: ...\n"),
        source=(
            "from api import Service\n\ndef handler(value: Service) -> None:\n    value.run()\n"
        ),
    )

    assert site.status == CallResolutionStatus.EXACT
    assert site.canonical_symbol == "api.Service.run"


def test_shared_external_protocol_union_is_ambiguous_in_both_orders(tmp_path: Path) -> None:
    stub = (
        "from typing import Protocol\n"
        "class Common(Protocol):\n"
        "    def run(self) -> None: ...\n"
        "class First(Common, Protocol): ...\n"
        "class Second(Common, Protocol): ...\n"
    )
    for index, annotation in enumerate(("First | Second", "Second | First")):
        site = _external_run_site(
            tmp_path / str(index),
            stub=stub,
            source=(
                "from api import First, Second\n\n"
                f"def handler(value: {annotation}) -> None:\n"
                "    value.run()\n"
            ),
        )
        assert site.status == CallResolutionStatus.AMBIGUOUS
        assert site.reason_code == "open_receiver_dispatch"
        assert site.canonical_symbol is None
