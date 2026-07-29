"""Tests for the non-default reverse-impact graph foundation."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterable

from fastapi_endpoint_detector.analyzer.reverse_impact_graph import (
    GraphOccurrence,
    GraphSide,
    ReverseImpactCaps,
    ReverseImpactEdge,
    ReverseImpactGraph,
    ReverseImpactGraphError,
    ReverseImpactNode,
    ReverseImpactProvenance,
)


def occurrence(line: int, file_path: str = "src/app.py") -> GraphOccurrence:
    return GraphOccurrence(file_path=file_path, line=line, column=0)


def node(
    name: str,
    line: int,
    *,
    side: GraphSide = GraphSide.TARGET,
    kind: str = "function",
) -> ReverseImpactNode:
    return ReverseImpactNode.create(
        side=side,
        kind=kind,
        qualified_name=name,
        occurrence=occurrence(line),
    )


def edge(
    source: ReverseImpactNode,
    target: ReverseImpactNode,
    line: int,
    *,
    kind: str = "calls",
) -> ReverseImpactEdge:
    return ReverseImpactEdge(
        source_id=source.node_id,
        target_id=target.node_id,
        kind=kind,
        occurrence=occurrence(line),
    )


def provenance(**changes: str) -> ReverseImpactProvenance:
    values = {
        "provider": "mypy",
        "provider_version": "1.19.1",
        "snapshot_sha256": "snapshot",
        "configuration_sha256": "configuration",
    }
    values.update(changes)
    return ReverseImpactProvenance(**values)


def graph(
    nodes: Iterable[ReverseImpactNode],
    edges: Iterable[ReverseImpactEdge],
    handlers: Iterable[ReverseImpactNode],
    *,
    caps: ReverseImpactCaps | None = None,
    graph_provenance: ReverseImpactProvenance | None = None,
) -> ReverseImpactGraph:
    return ReverseImpactGraph(
        nodes=nodes,
        edges=edges,
        handler_node_ids=[item.node_id for item in handlers],
        provenance=graph_provenance or provenance(),
        caps=caps,
    )


def test_occurrence_normalizes_paths_and_rejects_absolute_paths() -> None:
    value = GraphOccurrence(file_path=r"src\package\module.py", line=2, column=3)

    assert value.file_path == "src/package/module.py"
    with pytest.raises(ReverseImpactGraphError, match="repository-relative"):
        GraphOccurrence(file_path="/repo/app.py", line=1)
    with pytest.raises(ReverseImpactGraphError, match="repository-relative"):
        GraphOccurrence(file_path="src/../outside.py", line=1)


def test_node_identity_preserves_occurrence_and_snapshot_side() -> None:
    target_first = node("app.handler", 10)
    target_second = node("app.handler", 20)
    baseline_first = node("app.handler", 10, side=GraphSide.BASELINE)

    assert len({target_first.node_id, target_second.node_id, baseline_first.node_id}) == 3


def test_reverse_traversal_preserves_multiple_paths_to_handler_occurrences() -> None:
    changed = node("app.changed", 40)
    left = node("app.left", 30)
    right = node("app.right", 31)
    first_handler = node("app.handler", 10, kind="handler")
    second_handler = node("app.handler", 20, kind="handler")
    value = graph(
        [changed, left, right, first_handler, second_handler],
        [
            edge(first_handler, left, 11),
            edge(left, changed, 32),
            edge(first_handler, right, 12),
            edge(right, changed, 33),
            edge(second_handler, right, 21),
        ],
        [first_handler, second_handler],
    )

    result = value.reverse_paths(changed.node_id)

    assert result.truncated is False
    assert result.limitations == ()
    assert {item.handler_id for item in result.paths} == {
        first_handler.node_id,
        second_handler.node_id,
    }
    assert {item.node_ids for item in result.paths} == {
        (changed.node_id, left.node_id, first_handler.node_id),
        (changed.node_id, right.node_id, first_handler.node_id),
        (changed.node_id, right.node_id, second_handler.node_id),
    }


def test_reverse_traversal_is_scc_safe_without_hiding_exit_path() -> None:
    changed = node("app.changed", 50)
    first = node("app.first", 30)
    second = node("app.second", 40)
    handler = node("app.handler", 10, kind="handler")
    value = graph(
        [changed, first, second, handler],
        [
            edge(first, changed, 31),
            edge(second, first, 41),
            edge(first, second, 32),
            edge(handler, second, 11),
        ],
        [handler],
    )

    result = value.reverse_paths(changed.node_id)

    assert [item.node_ids for item in result.paths] == [
        (changed.node_id, first.node_id, second.node_id, handler.node_id)
    ]
    assert result.truncated is False


def test_baseline_removed_and_target_added_seeds_remain_side_qualified() -> None:
    baseline_changed = node("app.changed", 20, side=GraphSide.BASELINE)
    baseline_handler = node("app.handler", 10, side=GraphSide.BASELINE, kind="handler")
    target_changed = node("app.changed", 22)
    target_handler = node("app.handler", 12, kind="handler")
    value = graph(
        [baseline_changed, baseline_handler, target_changed, target_handler],
        [
            edge(baseline_handler, baseline_changed, 11),
            edge(target_handler, target_changed, 13),
        ],
        [baseline_handler, target_handler],
    )

    baseline_result = value.reverse_paths(baseline_changed.node_id)
    target_result = value.reverse_paths(target_changed.node_id)

    assert [item.handler_id for item in baseline_result.paths] == [baseline_handler.node_id]
    assert [item.handler_id for item in target_result.paths] == [target_handler.node_id]


def test_cross_snapshot_edges_fail_closed() -> None:
    baseline = node("app.old", 1, side=GraphSide.BASELINE)
    target = node("app.new", 1)

    with pytest.raises(ReverseImpactGraphError, match="cannot cross snapshot sides"):
        graph([baseline, target], [edge(baseline, target, 2)], [])


def test_construction_caps_inputs_before_unbounded_materialization() -> None:
    nodes = [node(f"app.value_{index}", index + 1) for index in range(3)]

    with pytest.raises(ReverseImpactGraphError, match="node limit"):
        graph(
            iter(nodes),
            [],
            [],
            caps=ReverseImpactCaps(max_nodes=2, max_edges=1),
        )


def test_path_count_and_length_limits_are_explicit() -> None:
    changed = node("app.changed", 50)
    left = node("app.left", 30)
    right = node("app.right", 40)
    first_handler = node("app.first_handler", 10, kind="handler")
    second_handler = node("app.second_handler", 20, kind="handler")
    edges = [
        edge(left, changed, 31),
        edge(right, changed, 41),
        edge(first_handler, left, 11),
        edge(second_handler, right, 21),
    ]
    count_limited = graph(
        [changed, left, right, first_handler, second_handler],
        edges,
        [first_handler, second_handler],
        caps=ReverseImpactCaps(max_paths_per_seed=1),
    ).reverse_paths(changed.node_id)
    length_limited = graph(
        [changed, left, right, first_handler, second_handler],
        edges,
        [first_handler, second_handler],
        caps=ReverseImpactCaps(max_path_length=2),
    ).reverse_paths(changed.node_id)

    assert count_limited.truncated is True
    assert count_limited.limitations == ("reverse-impact path count limit reached",)
    assert len(count_limited.paths) == 1
    assert length_limited.truncated is True
    assert length_limited.paths == ()
    assert length_limited.limitations == ("reverse-impact path length limit reached",)


def test_work_limit_is_explicit_and_returns_no_partial_established_path() -> None:
    changed = node("app.changed", 50)
    first = node("app.first", 20)
    second = node("app.second", 30)
    handler = node("app.handler", 10, kind="handler")
    value = graph(
        [changed, first, second, handler],
        [edge(first, changed, 21), edge(second, changed, 31), edge(handler, first, 11)],
        [handler],
        caps=ReverseImpactCaps(max_traversal_steps=1),
    )

    result = value.reverse_paths(changed.node_id)

    assert result.truncated is True
    assert result.paths == ()
    assert result.limitations == ("reverse-impact traversal work limit reached",)


def test_cache_fingerprint_is_order_independent_and_provenance_bound() -> None:
    changed = node("app.changed", 20)
    handler = node("app.handler", 10, kind="handler")
    call = edge(handler, changed, 11)
    first = graph([changed, handler], [call], [handler])
    reordered = graph([handler, changed], [call], [handler])
    different_snapshot = graph(
        [handler, changed],
        [call],
        [handler],
        graph_provenance=provenance(snapshot_sha256="different"),
    )

    assert first.cache_fingerprint() == reordered.cache_fingerprint()
    assert first.cache_fingerprint() != different_snapshot.cache_fingerprint()


def test_reverse_handler_set_matches_legacy_forward_dag_oracle() -> None:
    changed = node("app.changed", 60)
    shared = node("app.shared", 50)
    alternate = node("app.alternate", 40)
    first_handler = node("app.first", 10, kind="handler")
    second_handler = node("app.second", 20, kind="handler")
    unrelated_handler = node("app.unrelated", 30, kind="handler")
    nodes = [
        changed,
        shared,
        alternate,
        first_handler,
        second_handler,
        unrelated_handler,
    ]
    edges = [
        edge(first_handler, shared, 11),
        edge(second_handler, alternate, 21),
        edge(alternate, shared, 41),
        edge(shared, changed, 51),
    ]
    handlers = [first_handler, second_handler, unrelated_handler]

    forward: dict[str, set[str]] = {}
    for item in edges:
        forward.setdefault(item.source_id, set()).add(item.target_id)

    def legacy_reaches_seed(handler_id: str) -> bool:
        work = [handler_id]
        visited: set[str] = set()
        while work:
            current = work.pop()
            if current == changed.node_id:
                return True
            if current in visited:
                continue
            visited.add(current)
            work.extend(sorted(forward.get(current, ())))
        return False

    legacy_handlers = {item.node_id for item in handlers if legacy_reaches_seed(item.node_id)}
    reverse_handlers = {
        item.handler_id
        for item in graph(nodes, edges, handlers).reverse_paths(changed.node_id).paths
    }

    assert reverse_handlers == legacy_handlers == {first_handler.node_id, second_handler.node_id}


def test_unknown_seed_and_handler_mapping_fail_closed() -> None:
    changed = node("app.changed", 20)
    value = graph([changed], [], [])

    with pytest.raises(ReverseImpactGraphError, match="unknown reverse-impact seed"):
        value.reverse_paths("missing")
    with pytest.raises(ReverseImpactGraphError, match="query handler mapping"):
        value.reverse_paths(changed.node_id, handler_node_ids=["missing"])


def test_handler_mapping_inputs_are_bounded() -> None:
    changed = node("app.changed", 20)
    caps = ReverseImpactCaps(max_nodes=1)

    with pytest.raises(ReverseImpactGraphError, match="handler mapping limit"):
        ReverseImpactGraph(
            nodes=[changed],
            edges=[],
            handler_node_ids=iter((changed.node_id, changed.node_id)),
            provenance=provenance(),
            caps=caps,
        )
    value = graph([changed], [], [], caps=caps)
    with pytest.raises(ReverseImpactGraphError, match="query handler mapping limit"):
        value.reverse_paths(
            changed.node_id,
            handler_node_ids=iter((changed.node_id, changed.node_id)),
        )
