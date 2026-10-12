"""Finally tracing must retain and bound joined partial alternatives."""

from pathlib import Path

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.config import Config, ParserConfig
from fastapi_endpoint_detector.models.effect_contract import CallResolutionStatus


def _mapper(tmp_path: Path, handlers: str) -> tuple[ChangeMapper, Path]:
    (tmp_path / "helpers.py").write_text(
        "def first():\n    return 1\n\n"
        "def second():\n    return 1\n\n"
        "def third():\n    return 1\n\n"
        "def quiet():\n    return 0\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from functools import partial\n"
        "from fastapi import FastAPI\n"
        "from helpers import first, second, third, quiet\n"
        "app = FastAPI()\n" + handlers,
        encoding="utf-8",
    )
    mapper = ChangeMapper(
        tmp_path,
        config=Config(parser=ParserConfig(follow_imports=False)),
        secure_ast=True,
        use_cache=False,
    )
    return mapper, main


def _diff(line: int) -> str:
    return (
        "diff --git a/helpers.py b/helpers.py\n"
        "--- a/helpers.py\n+++ b/helpers.py\n"
        f"@@ -{line},1 +{line},1 @@\n"
        "-    return 1\n+    return 2\n"
    )


def _dependencies(mapper: ChangeMapper):
    endpoints = mapper.registry.get_all()
    assert len(endpoints) == 1
    dependencies = mapper.mypy_analyzer.get_endpoint_dependencies(endpoints[0])
    assert dependencies is not None
    return dependencies


def _main_callback_sites(mapper: ChangeMapper, main: Path):
    dependencies = _dependencies(mapper)
    sites = [
        site
        for site in dependencies.resolved_call_sites
        if site.source_spelling == "callback" and Path(site.file_path).resolve() == main.resolve()
    ]
    assert len(sites) == 1
    return sites


def _assert_previous_callback_is_not_exact(mapper: ChangeMapper, main: Path) -> None:
    assert not any(
        site.status == CallResolutionStatus.EXACT and site.canonical_symbol == "helpers.first"
        for site in _main_callback_sites(mapper, main)
    )


def test_finally_traces_every_known_partial_alternative_and_keeps_low_evidence(
    tmp_path: Path,
) -> None:
    mapper, _main = _mapper(
        tmp_path,
        "@app.get('/known-partials')\ndef known_partials(flag: bool):\n"
        "    if flag:\n        bound = partial(first)\n"
        "    else:\n        bound = partial(second)\n"
        "    try:\n        marker = 0\n"
        "    finally:\n        marker = 1\n        bound()\n"
        "    return bound()\n",
    )

    for line in (2, 5):
        report = mapper.analyze_diff(_diff(line))
        assert {item.endpoint.identifier for item in report.candidate_endpoints} == {
            "GET /known-partials"
        }
        assert all(item.confidence.value == "low" for item in report.candidate_endpoints)
        dependencies = _dependencies(mapper)
        assert not any(
            item.cap == "UNKNOWN_FINALLY_EXIT_BINDING" for item in dependencies.analysis_limitations
        )


def test_finally_partial_alternatives_cannot_hide_a_captured_write(tmp_path: Path) -> None:
    mapper, main = _mapper(
        tmp_path,
        "@app.get('/partial-write')\ndef partial_write(flag: bool):\n"
        "    callback = first\n"
        "    def mutate():\n        nonlocal callback\n        callback = second\n"
        "    if flag:\n        bound = partial(mutate)\n"
        "    else:\n        bound = partial(quiet)\n"
        "    try:\n        marker = 0\n"
        "    finally:\n        marker = 1\n        bound()\n"
        "    return callback()\n",
    )
    mapper.analyze_diff(_diff(2))

    _assert_previous_callback_is_not_exact(mapper, main)
    dependencies = _dependencies(mapper)
    assert dependencies.analysis_incomplete
    assert any(
        item.cap == "UNKNOWN_FINALLY_EXIT_BINDING" for item in dependencies.analysis_limitations
    )


def test_finally_unknown_partial_alternative_cannot_keep_old_callback_exact(
    tmp_path: Path,
) -> None:
    mapper, main = _mapper(
        tmp_path,
        "@app.get('/unknown-partial')\ndef unknown_partial(flag: bool, replacement):\n"
        "    callback = first\n"
        "    if flag:\n        bound = partial(quiet)\n"
        "    else:\n        bound = replacement\n"
        "    try:\n        marker = 0\n"
        "    finally:\n        marker = 1\n        bound()\n"
        "    return callback()\n",
    )
    report = mapper.analyze_diff(_diff(2))

    _assert_previous_callback_is_not_exact(mapper, main)
    dependencies = _dependencies(mapper)
    assert report.analysis_completeness == "partial"
    assert any(
        item.cap in {"UNKNOWN_PARTIAL_BINDING", "UNKNOWN_FINALLY_EXIT_BINDING"}
        for item in dependencies.analysis_limitations
    )


def test_finally_missing_partial_path_keeps_the_binding_unknown(tmp_path: Path) -> None:
    mapper, main = _mapper(
        tmp_path,
        "@app.get('/missing-partial')\ndef missing_partial(flag: bool):\n"
        "    callback = first\n"
        "    if flag:\n        bound = partial(quiet)\n"
        "    try:\n        marker = 0\n"
        "    finally:\n        marker = 1\n        bound()\n"
        "    return callback()\n",
    )
    report = mapper.analyze_diff(_diff(2))
    dependencies = _dependencies(mapper)
    bound_sites = [
        site
        for site in dependencies.resolved_call_sites
        if site.source_spelling == "bound" and Path(site.file_path).resolve() == main.resolve()
    ]
    assert len(bound_sites) == 1
    assert bound_sites[0].status != CallResolutionStatus.EXACT
    assert report.analysis_completeness == "partial"
    assert any(
        item.cap in {"UNKNOWN_PARTIAL_BINDING", "UNKNOWN_FINALLY_EXIT_BINDING"}
        for item in dependencies.analysis_limitations
    )
    # The unassigned branch cannot reach callback(); a continuing quiet branch
    # can legitimately preserve first. Do not force an unrelated false negative.
    _main_callback_sites(mapper, main)


def test_finally_overflowed_partial_alternatives_cannot_keep_old_callback_exact(
    tmp_path: Path,
) -> None:
    mapper, main = _mapper(
        tmp_path,
        "@app.get('/overflow-partial')\ndef overflow_partial(choice: int):\n"
        "    callback = first\n"
        "    def mutate():\n        nonlocal callback\n        callback = second\n"
        "    if choice == 1:\n        bound = partial(mutate)\n"
        "    elif choice == 2:\n        bound = partial(quiet)\n"
        "    else:\n        bound = partial(third)\n"
        "    try:\n        marker = 0\n"
        "    finally:\n        marker = 1\n        bound()\n"
        "    return callback()\n",
    )
    mapper.mypy_analyzer.MAX_POINTS_TO_TARGETS = 2
    report = mapper.analyze_diff(_diff(2))

    _assert_previous_callback_is_not_exact(mapper, main)
    dependencies = _dependencies(mapper)
    assert report.analysis_completeness == "partial"
    assert any(item.cap == "MAX_POINTS_TO_TARGETS" for item in dependencies.analysis_limitations)
    assert any(
        item.cap == "UNKNOWN_FINALLY_EXIT_BINDING" for item in dependencies.analysis_limitations
    )


def test_finally_partial_method_alternative_abstains(tmp_path: Path) -> None:
    mapper, main = _mapper(
        tmp_path,
        "class Worker:\n    def run(self):\n        return 0\n"
        "@app.get('/method-partial')\ndef method_partial(flag: bool):\n"
        "    callback = first\n"
        "    worker = Worker()\n"
        "    if flag:\n        bound = partial(worker.run)\n"
        "    else:\n        bound = partial(quiet)\n"
        "    try:\n        marker = 0\n"
        "    finally:\n        marker = 1\n        bound()\n"
        "    return callback()\n",
    )
    mapper.analyze_diff(_diff(2))

    _assert_previous_callback_is_not_exact(mapper, main)
    dependencies = _dependencies(mapper)
    assert dependencies.analysis_incomplete
    assert any(
        item.cap == "UNKNOWN_FINALLY_EXIT_BINDING" for item in dependencies.analysis_limitations
    )
