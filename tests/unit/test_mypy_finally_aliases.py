"""Finally preserves unchanged aliases and rejects uncertain writes."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.mypy_analyzer import (
    EndpointDependencies,
    MypyAnalyzer,
)
from fastapi_endpoint_detector.models.effect_contract import CallResolutionStatus, ResolvedCallSite
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo


def _endpoint(path: Path) -> Endpoint:
    return Endpoint(
        path="/test",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(name="handler", module=path.stem, file_path=path, line_number=4),
    )


def _site_by_spelling(sites: list[ResolvedCallSite], spelling: str) -> list[ResolvedCallSite]:
    return [site for site in sites if site.source_spelling == spelling]


def _analyze(tmp_path: Path, body: str) -> tuple[Path, EndpointDependencies]:
    (tmp_path / "helpers.py").write_text(
        "from collections.abc import Callable\n\n"
        "def first() -> int: return 1\n"
        "def second() -> int: return 2\n"
        "def invoke(callback: Callable[[], int]) -> int:\n"
        "    return callback()\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from functools import partial\n"
        "from helpers import first, second, invoke\n\n"
        "def handler(flag: bool = False):\n"
        + "\n".join("    " + line if line else "" for line in body.splitlines())
        + "\n",
        encoding="utf-8",
    )
    return main, MypyAnalyzer(tmp_path, module_root=tmp_path).analyze_endpoint(_endpoint(main))


def _helper_callback_sites(deps: EndpointDependencies, tmp_path: Path) -> list[ResolvedCallSite]:
    return [
        site
        for site in _site_by_spelling(deps.resolved_call_sites, "callback")
        if Path(site.file_path).resolve() == (tmp_path / "helpers.py").resolve()
    ]


def test_finally_preserves_untouched_callable_partial_and_lambda_aliases(
    tmp_path: Path,
) -> None:
    main, deps = _analyze(
        tmp_path,
        "callback = first\n"
        "bound = partial(invoke, callback=callback)\n"
        "thunk = lambda: callback()\n"
        "try:\n"
        "    marker = 0\n"
        "finally:\n"
        "    marker = 1\n"
        "    def nested():\n"
        "        callback = second\n"
        "callback()\n"
        "bound()\n"
        "thunk()",
    )
    handler = next(
        node
        for node in ast.parse(main.read_text(encoding="utf-8")).body
        if isinstance(node, ast.FunctionDef) and node.name == "handler"
    )
    direct = [
        site
        for site in _site_by_spelling(deps.resolved_call_sites, "callback")
        if Path(site.file_path).resolve() == main.resolve() and site.line == handler.body[-3].lineno
    ]
    assert len(direct) == 1
    assert direct[0].status == CallResolutionStatus.EXACT
    assert direct[0].canonical_symbol == "helpers.first"
    assert any(
        site.status == CallResolutionStatus.EXACT and site.canonical_symbol == "helpers.first"
        for site in _helper_callback_sites(deps, tmp_path)
    )
    assert any(
        span.start_line == handler.body[2].lineno
        and span.execution_state in {"possible_execution", "established_execution"}
        for span in deps.get_source_evidence_spans(str(main))
    )


@pytest.mark.parametrize(
    "binding",
    ("first", "partial(invoke, callback=first)", "lambda: first()"),
    ids=("callable", "partial", "lambda"),
)
@pytest.mark.parametrize(
    "final_body",
    ("callback = second", "del callback", "if flag:\n    callback = second"),
    ids=("rebind", "delete", "conditional-rebind"),
)
def test_finally_writes_never_restore_stale_callable_alias(
    tmp_path: Path, binding: str, final_body: str
) -> None:
    main, deps = _analyze(
        tmp_path,
        f"callback = {binding}\n"
        "try:\n"
        "    marker = 0\n"
        "finally:\n"
        + "\n".join("    " + line for line in final_body.splitlines())
        + "\ncallback()",
    )
    callback_sites = [
        site
        for site in _site_by_spelling(deps.resolved_call_sites, "callback")
        if Path(site.file_path).resolve() == main.resolve()
    ]
    assert len(callback_sites) == 1
    assert not (
        callback_sites[0].status == CallResolutionStatus.EXACT
        and callback_sites[0].canonical_symbol == "helpers.first"
    )

    assert not any(
        site.status == CallResolutionStatus.EXACT and site.canonical_symbol == "helpers.first"
        for site in _helper_callback_sites(deps, tmp_path)
    )
    if binding.startswith("lambda:"):
        declaration = next(
            node
            for node in ast.parse(main.read_text(encoding="utf-8")).body
            if isinstance(node, ast.FunctionDef) and node.name == "handler"
        )
        assert all(
            span.execution_state not in {"possible_execution", "established_execution"}
            for span in deps.get_source_evidence_spans(str(main))
            if span.start_line == declaration.body[0].lineno
        )


def test_finally_partial_keyword_heap_mutation_drops_all_partial_aliases(
    tmp_path: Path,
) -> None:
    main, deps = _analyze(
        tmp_path,
        "bound = partial(invoke, callback=first)\n"
        "same_bound = bound\n"
        "try:\n"
        "    marker = 0\n"
        "finally:\n"
        "    same_bound.keywords['callback'] = second\n"
        "bound()",
    )
    assert any(
        site.source_spelling == "bound" and Path(site.file_path).resolve() == main.resolve()
        for site in deps.resolved_call_sites
    )
    assert not any(
        site.status == CallResolutionStatus.EXACT and site.canonical_symbol == "helpers.first"
        for site in _helper_callback_sites(deps, tmp_path)
    )
    assert any(item.cap == "UNKNOWN_FINALLY_EXIT_BINDING" for item in deps.analysis_limitations)


def test_finally_unknown_member_augassignment_does_not_retain_old_alias(
    tmp_path: Path,
) -> None:
    _, deps = _analyze(
        tmp_path,
        "callback = first\n"
        "class Box:\n"
        "    value: int = 0\n"
        "box = Box()\n"
        "try:\n"
        "    marker = 0\n"
        "finally:\n"
        "    box.value += 1\n"
        "callback()",
    )
    assert not any(
        site.status == CallResolutionStatus.EXACT and site.canonical_symbol == "helpers.first"
        for site in _site_by_spelling(deps.resolved_call_sites, "callback")
    )
    assert any(item.cap == "UNKNOWN_FINALLY_EXIT_BINDING" for item in deps.analysis_limitations)


def test_finally_traces_live_call_but_not_code_after_terminal_return(
    tmp_path: Path,
) -> None:
    main, deps = _analyze(
        tmp_path,
        "callback = first\n"
        "try:\n"
        "    marker = 0\n"
        "finally:\n"
        "    invoke(callback)\n"
        "    return 1\n"
        "callback()",
    )
    assert any(
        site.status == CallResolutionStatus.EXACT and site.canonical_symbol == "helpers.first"
        for site in _helper_callback_sites(deps, tmp_path)
    )
    assert not any(
        site.source_spelling == "callback" and Path(site.file_path).resolve() == main.resolve()
        for site in deps.resolved_call_sites
    )


@pytest.mark.parametrize(
    "finally_call",
    ("change()", "mutator()", "driver()", "thunk()", "bound_change()"),
    ids=("direct", "alias", "indirect", "lambda", "partial"),
)
def test_called_local_closure_cannot_leave_stale_outer_callable(
    tmp_path: Path, finally_call: str
) -> None:
    main, deps = _analyze(
        tmp_path,
        "callback = first\n"
        "def change():\n"
        "    nonlocal callback\n"
        "    callback = second\n"
        "def driver():\n"
        "    change()\n"
        "mutator = change\n"
        "thunk = lambda: change()\n"
        "bound_change = partial(change)\n"
        "try:\n"
        "    marker = 0\n"
        "finally:\n" + "    " + finally_call + "\n" + "callback()",
    )
    assert not any(
        site.status == CallResolutionStatus.EXACT and site.canonical_symbol == "helpers.first"
        for site in _site_by_spelling(deps.resolved_call_sites, "callback")
        if Path(site.file_path).resolve() == main.resolve()
    )
    assert any(item.cap == "UNKNOWN_FINALLY_EXIT_BINDING" for item in deps.analysis_limitations)


def test_called_closure_mutating_captured_partial_keywords_drops_all_aliases(
    tmp_path: Path,
) -> None:
    main, deps = _analyze(
        tmp_path,
        "bound = partial(invoke, callback=first)\n"
        "same_bound = bound\n"
        "def mutate():\n"
        "    same_bound.keywords['callback'] = second\n"
        "try:\n"
        "    marker = 0\n"
        "finally:\n"
        "    mutate()\n"
        "bound()",
    )
    assert any(
        site.source_spelling == "bound" and Path(site.file_path).resolve() == main.resolve()
        for site in deps.resolved_call_sites
    )
    assert not any(
        site.status == CallResolutionStatus.EXACT and site.canonical_symbol == "helpers.first"
        for site in _helper_callback_sites(deps, tmp_path)
    )
    assert any(item.cap == "UNKNOWN_FINALLY_EXIT_BINDING" for item in deps.analysis_limitations)


def test_called_cleanup_local_shadow_does_not_write_the_outer_alias(tmp_path: Path) -> None:
    main, deps = _analyze(
        tmp_path,
        "callback = first\n"
        "bound = partial(invoke, callback=first)\n"
        "def cleanup():\n"
        "    callback = second\n"
        "try:\n"
        "    marker = 0\n"
        "finally:\n"
        "    cleanup()\n"
        "callback()\n"
        "bound()",
    )
    assert any(
        site.status == CallResolutionStatus.EXACT
        and site.canonical_symbol == "helpers.first"
        and Path(site.file_path).resolve() == main.resolve()
        for site in _site_by_spelling(deps.resolved_call_sites, "callback")
    )
    assert any(
        site.status == CallResolutionStatus.EXACT and site.canonical_symbol == "helpers.first"
        for site in _helper_callback_sites(deps, tmp_path)
    )
    assert not any(item.cap == "UNKNOWN_FINALLY_EXIT_BINDING" for item in deps.analysis_limitations)


def test_uncalled_nested_nonlocal_writer_does_not_drop_outer_alias(tmp_path: Path) -> None:
    main, deps = _analyze(
        tmp_path,
        "callback = first\n"
        "def change():\n"
        "    nonlocal callback\n"
        "    callback = second\n"
        "try:\n"
        "    marker = 0\n"
        "finally:\n"
        "    marker = 1\n"
        "callback()",
    )
    assert any(
        site.status == CallResolutionStatus.EXACT
        and site.canonical_symbol == "helpers.first"
        and Path(site.file_path).resolve() == main.resolve()
        for site in _site_by_spelling(deps.resolved_call_sites, "callback")
    )
    assert not any(item.cap == "UNKNOWN_FINALLY_EXIT_BINDING" for item in deps.analysis_limitations)


def test_finally_rebound_helper_never_uses_its_old_typed_declaration(tmp_path: Path) -> None:
    main, deps = _analyze(
        tmp_path,
        "callback = first\n"
        "def cleanup():\n"
        "    marker = 0\n"
        "def change():\n"
        "    nonlocal callback\n"
        "    callback = second\n"
        "try:\n"
        "    marker = 0\n"
        "finally:\n"
        "    cleanup = change\n"
        "    cleanup()\n"
        "callback()",
    )
    assert not any(
        site.status == CallResolutionStatus.EXACT and site.canonical_symbol == "helpers.first"
        for site in _site_by_spelling(deps.resolved_call_sites, "callback")
        if Path(site.file_path).resolve() == main.resolve()
    )
    assert any(item.cap == "UNKNOWN_FINALLY_EXIT_BINDING" for item in deps.analysis_limitations)


def test_finally_higher_order_helper_cannot_hide_a_nonlocal_write(tmp_path: Path) -> None:
    main, deps = _analyze(
        tmp_path,
        "callback = first\n"
        "def change():\n"
        "    nonlocal callback\n"
        "    callback = second\n"
        "def run(fn):\n"
        "    fn()\n"
        "try:\n"
        "    marker = 0\n"
        "finally:\n"
        "    run(change)\n"
        "callback()",
    )
    assert not any(
        site.status == CallResolutionStatus.EXACT and site.canonical_symbol == "helpers.first"
        for site in _site_by_spelling(deps.resolved_call_sites, "callback")
        if Path(site.file_path).resolve() == main.resolve()
    )
    assert any(item.cap == "UNKNOWN_FINALLY_EXIT_BINDING" for item in deps.analysis_limitations)


@pytest.mark.parametrize(
    "mutation",
    (
        "same_bound.keywords.update({'callback': second})",
        "same_bound.keywords.clear()",
        "mutate_mapping(same_bound.keywords)",
    ),
    ids=("mapping-update", "mapping-clear", "helper-mapping-exposure"),
)
def test_called_closure_partial_mapping_methods_never_preserve_stale_capture(
    tmp_path: Path, mutation: str
) -> None:
    main, deps = _analyze(
        tmp_path,
        "bound = partial(invoke, callback=first)\n"
        "same_bound = bound\n"
        "def mutate_mapping(mapping):\n"
        "    mapping.update({'callback': second})\n"
        "def mutate():\n" + "    " + mutation + "\n"
        "try:\n"
        "    marker = 0\n"
        "finally:\n"
        "    mutate()\n"
        "bound()",
    )
    assert any(
        site.source_spelling == "bound" and Path(site.file_path).resolve() == main.resolve()
        for site in deps.resolved_call_sites
    )
    assert not any(
        site.status == CallResolutionStatus.EXACT and site.canonical_symbol == "helpers.first"
        for site in _helper_callback_sites(deps, tmp_path)
    )
    assert any(item.cap == "UNKNOWN_FINALLY_EXIT_BINDING" for item in deps.analysis_limitations)


@pytest.mark.parametrize(
    "setup, final_body",
    (
        ("", "class Capture:\n    nonlocal callback\n    callback = second"),
        (
            "class Manager:\n"
            "    def __enter__(self): return self\n"
            "    def __exit__(self, *exc):\n"
            "        nonlocal callback\n"
            "        callback = second\n"
            "manager = Manager()\n",
            "with manager:\n    marker = 1",
        ),
        (
            "def replacements():\n"
            "    nonlocal callback\n"
            "    callback = second\n"
            "    yield 1\n"
            "items = replacements()\n",
            "for item in items:\n    marker = item",
        ),
    ),
    ids=("class-suite", "context-exit", "deferred-iterator"),
)
def test_finally_implicit_execution_cannot_preserve_stale_alias(
    tmp_path: Path, setup: str, final_body: str
) -> None:
    main, deps = _analyze(
        tmp_path,
        "callback = first\n" + setup + "try:\n"
        "    marker = 0\n"
        "finally:\n"
        + "\n".join("    " + line for line in final_body.splitlines())
        + "\ncallback()",
    )
    assert not any(
        site.status == CallResolutionStatus.EXACT and site.canonical_symbol == "helpers.first"
        for site in _site_by_spelling(deps.resolved_call_sites, "callback")
        if Path(site.file_path).resolve() == main.resolve()
    )
    assert any(item.cap == "UNKNOWN_FINALLY_EXIT_BINDING" for item in deps.analysis_limitations)


@pytest.mark.parametrize(
    "final_body",
    (
        "[item for item in items]",
        "{item for item in items}",
        "{item: item for item in items}",
        "for item in [*items]:\n    marker = item",
        "for item in (*items,):\n    marker = item",
    ),
    ids=(
        "list-comprehension",
        "set-comprehension",
        "dict-comprehension",
        "star-list",
        "star-tuple",
    ),
)
def test_finally_comprehensions_and_unpacking_do_not_hide_iterator_writes(
    tmp_path: Path, final_body: str
) -> None:
    main, deps = _analyze(
        tmp_path,
        "callback = first\n"
        "def replacements():\n"
        "    nonlocal callback\n"
        "    callback = second\n"
        "    yield 1\n"
        "items = replacements()\n"
        "try:\n"
        "    marker = 0\n"
        "finally:\n"
        + "\n".join("    " + line for line in final_body.splitlines())
        + "\ncallback()",
    )
    assert not any(
        site.status == CallResolutionStatus.EXACT and site.canonical_symbol == "helpers.first"
        for site in _site_by_spelling(deps.resolved_call_sites, "callback")
        if Path(site.file_path).resolve() == main.resolve()
    )
    assert any(item.cap == "UNKNOWN_FINALLY_EXIT_BINDING" for item in deps.analysis_limitations)


@pytest.mark.parametrize(
    "final_body",
    ("box += 1", "marker = box[0]", "if box:\n    marker = 1", "assert box", "{box}", "{box: 1}"),
    ids=(
        "augmented-operation",
        "index-protocol",
        "truth-protocol",
        "assert-protocol",
        "set-hash",
        "dict-hash",
    ),
)
def test_finally_implicit_object_protocols_do_not_preserve_stale_outer_alias(
    tmp_path: Path, final_body: str
) -> None:
    main, deps = _analyze(
        tmp_path,
        "callback = first\n"
        "class Mutator:\n"
        "    def __iadd__(self, other):\n"
        "        nonlocal callback\n"
        "        callback = second\n"
        "        return self\n"
        "    def __getitem__(self, key):\n"
        "        nonlocal callback\n"
        "        callback = second\n"
        "        return 1\n"
        "    def __bool__(self):\n"
        "        nonlocal callback\n"
        "        callback = second\n"
        "        return True\n"
        "    def __hash__(self):\n"
        "        nonlocal callback\n"
        "        callback = second\n"
        "        return 1\n"
        "box = Mutator()\n"
        "try:\n"
        "    marker = 0\n"
        "finally:\n"
        + "\n".join("    " + line for line in final_body.splitlines())
        + "\ncallback()",
    )
    assert not any(
        site.status == CallResolutionStatus.EXACT and site.canonical_symbol == "helpers.first"
        for site in _site_by_spelling(deps.resolved_call_sites, "callback")
        if Path(site.file_path).resolve() == main.resolve()
    )
    assert any(item.cap == "UNKNOWN_FINALLY_EXIT_BINDING" for item in deps.analysis_limitations)


def test_finally_lambda_default_executes_its_captured_writer(tmp_path: Path) -> None:
    main, deps = _analyze(
        tmp_path,
        "callback = first\n"
        "def change():\n"
        "    nonlocal callback\n"
        "    callback = second\n"
        "try:\n"
        "    marker = 0\n"
        "finally:\n"
        "    local = lambda value=change(): value\n"
        "callback()",
    )
    assert not any(
        site.status == CallResolutionStatus.EXACT and site.canonical_symbol == "helpers.first"
        for site in _site_by_spelling(deps.resolved_call_sites, "callback")
        if Path(site.file_path).resolve() == main.resolve()
    )
    assert any(item.cap == "UNKNOWN_FINALLY_EXIT_BINDING" for item in deps.analysis_limitations)


@pytest.mark.parametrize(
    "finally_call", ("method()", "wrapped()"), ids=("method-alias", "method-partial")
)
def test_finally_bound_method_alias_requires_dispatch_proof(
    tmp_path: Path, finally_call: str
) -> None:
    main, deps = _analyze(
        tmp_path,
        "callback = first\n"
        "class Base:\n"
        "    def run(self): pass\n"
        "class Child(Base):\n"
        "    def run(self):\n"
        "        nonlocal callback\n"
        "        callback = second\n"
        "receiver: Base = Child()\n"
        "method = receiver.run\n"
        "wrapped = partial(method)\n"
        "try:\n"
        "    marker = 0\n"
        "finally:\n" + "    " + finally_call + "\n" + "callback()",
    )
    assert not any(
        site.status == CallResolutionStatus.EXACT and site.canonical_symbol == "helpers.first"
        for site in _site_by_spelling(deps.resolved_call_sites, "callback")
        if Path(site.file_path).resolve() == main.resolve()
    )
    assert any(item.cap == "UNKNOWN_FINALLY_EXIT_BINDING" for item in deps.analysis_limitations)


@pytest.mark.parametrize(
    "final_body",
    ("marker = 0", "del marker", "cleanup()"),
    ids=("object-rebind", "object-delete", "helper-object-rebind"),
)
def test_finally_object_release_cannot_preserve_a_destructor_mutated_alias(
    tmp_path: Path, final_body: str
) -> None:
    main, deps = _analyze(
        tmp_path,
        "callback = first\n"
        "class Marker:\n"
        "    def __del__(self):\n"
        "        nonlocal callback\n"
        "        callback = second\n"
        "marker = Marker()\n"
        "def cleanup():\n"
        "    held = Marker()\n"
        "    held = 0\n"
        "try:\n"
        "    unchanged = 0\n"
        "finally:\n"
        + "\n".join("    " + line for line in final_body.splitlines())
        + "\ncallback()",
    )
    assert not any(
        site.status == CallResolutionStatus.EXACT and site.canonical_symbol == "helpers.first"
        for site in _site_by_spelling(deps.resolved_call_sites, "callback")
        if Path(site.file_path).resolve() == main.resolve()
    )
    assert any(item.cap == "UNKNOWN_FINALLY_EXIT_BINDING" for item in deps.analysis_limitations)


def test_finally_parameter_replacement_requires_release_proof(tmp_path: Path) -> None:
    main, deps = _analyze(
        tmp_path,
        "callback = first\ntry:\n    marker = 0\nfinally:\n    flag = False\ncallback()",
    )
    assert not any(
        site.status == CallResolutionStatus.EXACT and site.canonical_symbol == "helpers.first"
        for site in _site_by_spelling(deps.resolved_call_sites, "callback")
        if Path(site.file_path).resolve() == main.resolve()
    )
    assert any(item.cap == "UNKNOWN_FINALLY_EXIT_BINDING" for item in deps.analysis_limitations)


@pytest.mark.parametrize(
    "construction",
    ("partial(invoke, callback)", "partial(invoke, callback=callback)"),
    ids=("positional", "keyword"),
)
def test_partial_capture_preserves_function_alias_before_any_finally(
    tmp_path: Path, construction: str
) -> None:
    main, deps = _analyze(
        tmp_path,
        f"callback = first\nbound = {construction}\ncallback()",
    )
    direct = [
        site
        for site in _site_by_spelling(deps.resolved_call_sites, "callback")
        if Path(site.file_path).resolve() == main.resolve()
    ]
    assert len(direct) == 1
    assert direct[0].status == CallResolutionStatus.EXACT
    assert direct[0].canonical_symbol == "helpers.first"
    assert not _helper_callback_sites(deps, tmp_path)


@pytest.mark.parametrize(
    "prelude,construction",
    (
        (
            "partial = invoke",
            "partial(callback)",
        ),
        (
            "",
            "partial(invoke, *[callback])",
        ),
        (
            "",
            "partial(invoke, **{'callback': callback})",
        ),
    ),
    ids=("shadowed-constructor", "positional-star", "keyword-star"),
)
def test_unproven_partial_capture_still_invalidates_function_alias(
    tmp_path: Path, prelude: str, construction: str
) -> None:
    main, deps = _analyze(
        tmp_path,
        "callback = first\n"
        + (prelude + "\n" if prelude else "")
        + f"bound = {construction}\n"
        + "callback()",
    )
    direct = [
        site
        for site in _site_by_spelling(deps.resolved_call_sites, "callback")
        if Path(site.file_path).resolve() == main.resolve()
    ]
    assert direct
    assert not any(
        site.status == CallResolutionStatus.EXACT and site.canonical_symbol == "helpers.first"
        for site in direct
    )
