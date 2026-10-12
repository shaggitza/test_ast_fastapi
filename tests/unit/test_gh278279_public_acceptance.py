"""Public ChangeMapper acceptance coverage for statically dead and live code."""

from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper


def _diff(
    path: str,
    old_line: int,
    new_line: str,
    old_content: str = "    return 1",
) -> str:
    return (
        f"diff --git a/{path} b/{path}\n"
        f"--- a/{path}\n+++ b/{path}\n"
        f"@@ -{old_line},1 +{old_line},1 @@\n"
        f"-{old_content}\n"
        f"+{new_line}\n"
    )


def test_public_mapper_prunes_dead_helpers_and_keeps_invoked_helper(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from helpers import (\n"
        "    dead_helper, live_helper, unawaited_helper, terminal_wrapper, awaited_wrapper\n"
        ")\n\n"
        "app = FastAPI()\n\n"
        "@app.get('/items')\n"
        "async def handler():\n"
        "    if False:\n"
        "        dead_helper()\n"
        "    unawaited_helper()\n"
        "    terminal_wrapper()\n"
        "    return await awaited_wrapper()\n",
        encoding="utf-8",
    )
    (tmp_path / "helpers.py").write_text(
        "def dead_helper():\n"
        "    return 1\n\n"
        "def dead_wrapper():\n"
        "    return dead_helper()\n\n"
        "async def unawaited_helper():\n"
        "    return dead_helper()\n\n"
        "def terminal_wrapper():\n"
        "    return 0\n"
        "    dead_helper()\n\n"
        "def live_helper():\n"
        "    return 1\n\n"
        "async def awaited_wrapper():\n"
        "    return live_helper()\n",
        encoding="utf-8",
    )

    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)
    dead = mapper.analyze_diff(_diff("helpers.py", 2, "    return 2"))
    live = mapper.analyze_diff(_diff("helpers.py", 15, "    return 2"))

    assert dead.candidate_endpoints == [], [
        (item.confidence, item.reason, item.dependency_chain) for item in dead.candidate_endpoints
    ]
    assert len(live.candidate_endpoints) == 1
    assert live.candidate_endpoints[0].endpoint.identifier == "GET /items"


def test_public_report_surfaces_receiver_target_cap(tmp_path: Path) -> None:
    names = [f"Service{number}" for number in range(9)]
    implementations = tmp_path / "implementations.py"
    implementations.write_text(
        "class Base:\n"
        "    def run(self) -> int:\n"
        "        return 1\n\n" + "\n".join(f"class {name}(Base):\n    pass\n" for name in names),
        encoding="utf-8",
    )
    expression = "Service8()"
    for number in reversed(range(8)):
        expression = f"Service{number}() if choice == {number} else ({expression})"
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        f"from implementations import {', '.join(names)}\n\n"
        "app = FastAPI()\n\n"
        "@app.get('/items')\n"
        "def handler(choice: int) -> int:\n"
        f"    service = {expression}\n"
        "    return service.run()\n",
        encoding="utf-8",
    )

    report = ChangeMapper(tmp_path, secure_ast=True, use_cache=False).analyze_diff(
        _diff("implementations.py", 3, "        return 2")
    )

    assert report.analysis_completeness == "partial"
    assert any(
        "MAX_POINTS_TO_TARGETS" in warning and "main.py:" in warning for warning in report.warnings
    )


def test_public_mapper_traces_concrete_callables_and_leaves_open_protocols_unresolved(
    tmp_path: Path,
) -> None:
    (tmp_path / "helpers.py").write_text(
        "from typing import Protocol\n\n"
        "def leaf() -> int:\n"
        "    return 1\n\n"
        "class Concrete:\n"
        "    def __call__(self) -> int:\n"
        "        return leaf()\n\n"
        "class Open(Protocol):\n"
        "    def __call__(self) -> int: ...\n\n"
        "class Implementation(Open):\n"
        "    def __call__(self) -> int:\n"
        "        return leaf()\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from helpers import Concrete, Open\n\n"
        "app = FastAPI()\n\n"
        "@app.get('/concrete')\n"
        "def concrete():\n"
        "    return Concrete()()\n\n"
        "@app.get('/open')\n"
        "def open_contract(worker: Open):\n"
        "    return worker()\n",
        encoding="utf-8",
    )

    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)
    concrete = mapper.analyze_diff(
        _diff("helpers.py", 8, "        return 2", "        return leaf()")
    )
    open_protocol = mapper.analyze_diff(
        _diff("helpers.py", 16, "        return 2", "        return leaf()")
    )

    assert {item.endpoint.identifier for item in concrete.candidate_endpoints} == {"GET /concrete"}
    assert open_protocol.candidate_endpoints == []


def test_public_mapper_prunes_post_terminal_nested_and_deferred_lambda_changes(
    tmp_path: Path,
) -> None:
    (tmp_path / "helpers.py").write_text(
        "def dead_after_return() -> int:\n"
        "    return 1\n"
        "    return 2\n\n"
        "def dead_nested() -> int:\n"
        "    return 1\n\n"
        "def live_lambda() -> int:\n"
        "    return 1\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from helpers import dead_after_return, dead_nested, live_lambda\n\n"
        "app = FastAPI()\n\n"
        "@app.get('/items')\n"
        "def handler():\n"
        "    def unused():\n"
        "        dead_nested()\n"
        "    hidden = lambda: dead_nested()\n"
        "    live = lambda: live_lambda()\n"
        "    live()\n"
        "    return dead_after_return()\n",
        encoding="utf-8",
    )

    mapper = ChangeMapper(tmp_path, secure_ast=True, use_cache=False)
    post_terminal = mapper.analyze_diff(_diff("helpers.py", 3, "    return 3", "    return 2"))
    nested = mapper.analyze_diff(_diff("helpers.py", 6, "    return 2"))
    invoked_lambda = mapper.analyze_diff(_diff("helpers.py", 9, "    return 2", "    return 1"))

    assert post_terminal.candidate_endpoints == []
    assert nested.candidate_endpoints == []
    assert [item.endpoint.identifier for item in invoked_lambda.candidate_endpoints] == [
        "GET /items"
    ]


@pytest.mark.parametrize(
    ("class_source", "expression"),
    [
        (
            "class Meta(type):\n"
            "    def __call__(cls): return Proxy()\n"
            "class Concrete(metaclass=Meta):\n"
            "    def __call__(self): return intended()\n",
            "Concrete()()",
        ),
        (
            "class Concrete:\n"
            "    def __new__(cls): return Proxy()\n"
            "    def __call__(self): return intended()\n",
            "Concrete()()",
        ),
        (
            "class Concrete:\n"
            "    def __init__(self, value): pass\n"
            "    def __call__(self): return intended()\n",
            "Concrete(1)()",
        ),
        (
            "class Concrete:\n"
            "    def __init__(self, value): pass\n"
            "    def __call__(self): return intended()\n",
            "Concrete(value=1)()",
        ),
        (
            "class HookBase:\n"
            "    def __init_subclass__(cls): pass\n"
            "class Concrete(HookBase):\n"
            "    def __call__(self): return intended()\n",
            "Concrete()()",
        ),
    ],
)
def test_public_mapper_abstains_when_construction_is_unproven(
    tmp_path: Path, class_source: str, expression: str
) -> None:
    (tmp_path / "helpers.py").write_text(
        "def intended():\n"
        "    return 1\n\n"
        "class Proxy:\n"
        "    def __call__(self): return 0\n\n" + class_source,
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from helpers import Concrete\n"
        "app = FastAPI()\n"
        "@app.get('/items')\n"
        "def handler():\n"
        f"    return {expression}\n",
        encoding="utf-8",
    )
    report = ChangeMapper(tmp_path, secure_ast=True, use_cache=False).analyze_diff(
        _diff("helpers.py", 2, "    return 2")
    )
    assert report.candidate_endpoints == []
    assert report.analysis_completeness == "partial"
    assert any(
        "UNPROVEN_CALLABLE_CONSTRUCTION" in warning and "main.py:6" in warning
        for warning in report.warnings
    )
