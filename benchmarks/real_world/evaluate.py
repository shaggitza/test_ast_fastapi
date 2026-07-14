#!/usr/bin/env python3
"""Evaluate impact-analysis predictions against adjudicated PR labels."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.real_world.benchmark_scope import (
    SCOPES,
    filter_entrypoint_items,
    filter_record,
)
from benchmarks.real_world.semantic_normalization import (
    ALIAS_VERSION,
    claims,
    match_claims,
    split_ranked_claims,
)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def key(record: dict[str, Any]) -> tuple[str, int]:
    return record["repository"], int(record["pr"])


def entrypoints(record: dict[str, Any]) -> set[str]:
    return {item["id"] for item in record.get("affected_entrypoints", [])}


def entrypoints_by_kind(record: dict[str, Any]) -> dict[str, set[str]]:
    grouped: dict[str, set[str]] = defaultdict(set)
    for item in record.get("affected_entrypoints", []):
        identifier = item["id"]
        kind = item.get("kind")
        if not isinstance(kind, str):
            kind = "http" if identifier.startswith("HTTP ") else "unknown"
        grouped[kind.lower()].add(identifier)
    return grouped


def ranked_entrypoints(record: dict[str, Any]) -> tuple[set[str], set[str]]:
    """Return selected and LOW exact IDs after strongest-tier deduplication."""
    rank = {"low": 0, "medium": 1, "high": 2}
    items = record.get("candidate_entrypoints")
    if not items:
        items = record.get("affected_entrypoints", [])
    strongest: dict[str, int] = {}
    for item in items:
        identifier = item["id"]
        item_rank = rank.get(str(item.get("confidence", "medium")).lower(), 1)
        strongest[identifier] = max(strongest.get(identifier, -1), item_rank)
    return (
        {identifier for identifier, item_rank in strongest.items() if item_rank >= 1},
        {identifier for identifier, item_rank in strongest.items() if item_rank == 0},
    )


def low_diagnostics(
    expected: set[str],
    selected: set[str],
    low: set[str],
    reachability_only: set[str] | None = None,
) -> dict[str, int]:
    unmatched_expected = expected - selected
    low_matches = unmatched_expected & low
    low_fp = low - expected
    reachability_matches = low_fp & (reachability_only or set())
    return {
        "low_tp": len(low_matches),
        "low_fp": len(low_fp),
        "low_candidates": len(low),
        "low_supported_reachability": len(reachability_matches),
        "low_unmatched": len(low_fp - reachability_matches),
        "fn_with_low_candidate": len(low_matches),
        "fn_with_no_candidate": len(unmatched_expected - low_matches),
    }


def predicted_ids_by_kind(record: dict[str, Any], identifiers: set[str]) -> dict[str, set[str]]:
    rank = {"low": 0, "medium": 1, "high": 2}
    items = record.get("candidate_entrypoints")
    if not items:
        items = record.get("affected_entrypoints", [])
    strongest: dict[str, tuple[int, str]] = {}
    for item in items:
        identifier = item["id"]
        if identifier not in identifiers:
            continue
        item_rank = rank.get(str(item.get("confidence", "medium")).lower(), 1)
        kind = str(item.get("kind", "unknown")).lower()
        if identifier not in strongest or item_rank > strongest[identifier][0]:
            strongest[identifier] = (item_rank, kind)
    grouped: dict[str, set[str]] = defaultdict(set)
    for identifier, (_item_rank, kind) in strongest.items():
        grouped[kind].add(identifier)
    return grouped


def read_verification_selection(
    path: Path,
) -> tuple[dict[str, Any], str, set[tuple[str, int]], str]:
    """Load and validate a versioned PR-level verification selection."""
    content = path.read_bytes()
    manifest = json.loads(content)
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise ValueError("verification set must use schema_version 1")
    identifier = manifest.get("id")
    base_scope = manifest.get("base_scope")
    selection = manifest.get("selection", "exclude")
    if not isinstance(identifier, str) or not identifier.strip():
        raise ValueError("verification set must have a non-empty id")
    if not isinstance(base_scope, str) or not base_scope.strip():
        raise ValueError("verification set must have a non-empty base_scope")
    if selection not in {"include", "exclude"}:
        raise ValueError("verification set selection must be include or exclude")
    field = "included" if selection == "include" else "excluded"
    raw_items = manifest.get(field)
    if not isinstance(raw_items, list) or not raw_items:
        raise ValueError(f"verification set {field} must be a non-empty list")
    selected: set[tuple[str, int]] = set()
    for item in raw_items:
        repository = item.get("repository") if isinstance(item, dict) else None
        if not isinstance(repository, str) or not repository.strip():
            raise ValueError(f"malformed verification-set {field} entry")
        pr = item.get("pr")
        if type(pr) is not int:
            raise ValueError("verification-set PR must be an integer")
        record_key = (repository, pr)
        if record_key in selected:
            raise ValueError(f"duplicate verification-set {field} entry: {record_key}")
        selected.add(record_key)
    return manifest, selection, selected, hashlib.sha256(content).hexdigest()


def _validate_census_entrypoint(item: object, side_name: str, record_key: tuple[str, int]) -> None:
    if not isinstance(item, dict):
        raise ValueError(f"route census has malformed {side_name} entrypoint for {record_key}")
    identifier = item.get("id")
    kind = item.get("kind")
    occurrences = item.get("occurrences")
    if (
        not isinstance(identifier, str)
        or not identifier.strip()
        or not isinstance(kind, str)
        or kind not in {"http", "event"}
        or not isinstance(occurrences, list)
        or not occurrences
    ):
        raise ValueError(f"route census has malformed {side_name} entrypoint for {record_key}")
    for occurrence in occurrences:
        if not isinstance(occurrence, dict):
            raise ValueError(f"route census has malformed occurrence for {record_key}")
        file_name = occurrence.get("file")
        line = occurrence.get("line")
        end_line = occurrence.get("end_line")
        if (
            not isinstance(file_name, str)
            or not file_name
            or Path(file_name).is_absolute()
            or ".." in Path(file_name).parts
            or type(line) is not int
            or line < 1
            or (end_line is not None and (type(end_line) is not int or end_line < line))
            or not isinstance(occurrence.get("handler"), str)
            or not occurrence["handler"]
            or not isinstance(occurrence.get("module"), str)
            or not occurrence["module"]
            or not isinstance(occurrence.get("root"), str)
            or not occurrence["root"]
        ):
            raise ValueError(f"route census has malformed occurrence for {record_key}")


def read_route_census(  # noqa: PLR0912
    path: Path,
    selected_truth_keys: set[tuple[str, int]],
    all_truth_keys: set[tuple[str, int]],
    scope: str,
) -> tuple[dict[tuple[str, int], dict[str, Any]], str]:
    """Load a strict route-census v1 without feeding it into scoring."""
    content = path.read_bytes()
    records: dict[tuple[str, int], dict[str, Any]] = {}
    for line_number, line in enumerate(content.decode().splitlines(), start=1):
        if not line.strip():
            continue
        item = json.loads(line)
        if not isinstance(item, dict) or item.get("schema_version") != 1:
            raise ValueError(f"route census line {line_number} must use schema_version 1")
        record_key = key(item)
        if record_key in records:
            raise ValueError(f"duplicate route-census record: {record_key}")
        if record_key not in all_truth_keys:
            raise ValueError(f"route-census key absent from ground truth: {record_key}")
        status = item.get("status")
        complete = item.get("complete")
        if status not in {"completed", "partial", "unresolved"} or type(complete) is not bool:
            raise ValueError(f"route census has invalid status for {record_key}")
        filtered = dict(item)
        for side_name in ("target", "baseline"):
            side = item.get(side_name)
            if not isinstance(side, dict):
                raise ValueError(f"route census is missing {side_name} for {record_key}")
            side_status = side.get("status")
            entrypoint_items = side.get("entrypoints")
            unresolved = side.get("unresolved")
            if (
                side_status not in {"completed", "partial", "unresolved"}
                or not isinstance(entrypoint_items, list)
                or not isinstance(unresolved, list)
            ):
                raise ValueError(f"route census has malformed {side_name} for {record_key}")
            for entrypoint_item in entrypoint_items:
                _validate_census_entrypoint(entrypoint_item, side_name, record_key)
            filtered[side_name] = {
                **side,
                "entrypoints": filter_entrypoint_items(entrypoint_items, scope),
            }
        side_statuses = {filtered[side_name]["status"] for side_name in ("target", "baseline")}
        if side_statuses == {"completed"}:
            derived_status = "completed"
        elif side_statuses == {"unresolved"}:
            derived_status = "unresolved"
        else:
            derived_status = "partial"
        if status != derived_status or complete != (derived_status == "completed"):
            raise ValueError(f"route census complete/status mismatch for {record_key}")
        records[record_key] = filtered
    missing = selected_truth_keys - set(records)
    if missing:
        raise ValueError(f"route census is missing selected truth keys: {sorted(missing)}")
    return records, hashlib.sha256(content).hexdigest()


def _stage_counts(
    observation: int, propagation: int, discovery: int, unavailable: int
) -> dict[str, int]:
    return {
        "observation_missing": observation,
        "propagation_missing": propagation,
        "discovery_missing": discovery,
        "inventory_unavailable": unavailable,
    }


def ratio(numerator: int | float, denominator: int | float) -> float:
    return numerator / denominator if denominator else 0.0


def main() -> None:  # noqa: PLR0912, PLR0915 - raw and normalized metrics share one pass
    parser = argparse.ArgumentParser()
    parser.add_argument("--ground-truth", type=Path, required=True)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--scope", choices=SCOPES, default="all")
    parser.add_argument("--verification-set", type=Path)
    parser.add_argument("--route-census", type=Path)
    args = parser.parse_args()

    scope_id = {
        "all": "all-surfaces",
        "fastapi": "fastapi-adapter-v1",
        "out-of-scope": "out-of-scope-v1",
    }[args.scope]
    verification_manifest: dict[str, Any] | None = None
    verification_selection: str | None = None
    verification_keys: set[tuple[str, int]] = set()
    verification_sha256: str | None = None
    if args.verification_set is not None:
        (
            verification_manifest,
            verification_selection,
            verification_keys,
            verification_sha256,
        ) = read_verification_selection(args.verification_set)
        if verification_manifest["base_scope"] != scope_id:
            raise ValueError(
                f"verification set requires scope {verification_manifest['base_scope']!r}, "
                f"not {scope_id!r}"
            )

    truth_records = read_jsonl(args.ground_truth)
    truth_keys = {key(item) for item in truth_records}
    unmatched = verification_keys - truth_keys
    if unmatched:
        raise ValueError(f"verification-set keys absent from ground truth: {sorted(unmatched)}")
    truth = {
        key(item): filter_record(item, args.scope)
        for item in truth_records
        if verification_selection is None
        or (verification_selection == "include" and key(item) in verification_keys)
        or (verification_selection == "exclude" and key(item) not in verification_keys)
    }
    predictions = {
        key(item): filter_record(item, args.scope) for item in read_jsonl(args.predictions)
    }
    census: dict[tuple[str, int], dict[str, Any]] | None = None
    census_sha256: str | None = None
    if args.route_census is not None:
        census, census_sha256 = read_route_census(
            args.route_census, set(truth), truth_keys, args.scope
        )
    totals: dict[str, int] = defaultdict(int)
    macro: dict[str, float] = defaultdict(float)
    evaluated = 0
    latencies: list[float] = []
    kind_totals: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    normalized_totals: dict[str, int] = defaultdict(int)
    normalized_macro: dict[str, float] = defaultdict(float)
    normalized_kinds: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    normalized_rules: dict[str, int] = defaultdict(int)
    low_rules: dict[str, int] = defaultdict(int)
    ranked_totals: dict[str, int] = defaultdict(int)
    ranked_repositories: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    normalized_ranked_totals: dict[str, int] = defaultdict(int)
    normalized_ranked_repositories: dict[str, dict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    repository_totals: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    normalized_repositories: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    truth_positive_prs = 0
    negative_controls_with_fp = 0
    negative_controls_with_low_fp = 0
    exact_stage_totals: dict[str, int] = defaultdict(int)
    normalized_stage_totals: dict[str, int] = defaultdict(int)
    exact_stage_repositories: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    normalized_stage_repositories: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    exact_stage_prs: dict[tuple[str, int], dict[str, int]] = {}
    normalized_stage_prs: dict[tuple[str, int], dict[str, int]] = {}

    for record_key, expected_record in truth.items():
        if expected_record.get("status", "adjudicated") != "adjudicated":
            continue
        evaluated += 1
        expected = entrypoints(expected_record)
        reachability_only = {
            item["id"] for item in expected_record.get("reachability_only_entrypoints", [])
        }
        predicted_record = predictions.get(record_key, {})
        predicted, low_predicted = ranked_entrypoints(predicted_record)
        tp = len(expected & predicted)
        fp = len(predicted - expected)
        fn = len(expected - predicted)
        totals["tp"] += tp
        totals["fp"] += fp
        totals["fn"] += fn
        repository_totals[record_key[0]]["tp"] += tp
        repository_totals[record_key[0]]["fp"] += fp
        repository_totals[record_key[0]]["fn"] += fn
        exact_low = low_diagnostics(expected, predicted, low_predicted, reachability_only)
        for metric, count in exact_low.items():
            ranked_totals[metric] += count
            ranked_repositories[record_key[0]][metric] += count
        census_record = census.get(record_key) if census is not None else None
        if census is not None:
            exact_observation_ids = (expected - predicted) & low_predicted
            exact_after_low = (expected - predicted) - exact_observation_ids
            inventory_ids: set[str] = set()
            if census_record is not None:
                for side_name in ("target", "baseline"):
                    inventory_ids.update(
                        item["id"] for item in census_record[side_name]["entrypoints"]
                    )
            exact_propagation_ids = exact_after_low & inventory_ids
            exact_after_inventory = exact_after_low - exact_propagation_ids
            exact_stage = _stage_counts(
                len(exact_observation_ids),
                len(exact_propagation_ids),
                len(exact_after_inventory)
                if census_record is not None and census_record["complete"]
                else 0,
                len(exact_after_inventory)
                if census_record is None or not census_record["complete"]
                else 0,
            )
            if sum(exact_stage.values()) != fn:
                raise AssertionError(f"exact FN-stage partition failed for {record_key}")
            exact_stage_prs[record_key] = exact_stage
            for metric, count in exact_stage.items():
                exact_stage_totals[metric] += count
                exact_stage_repositories[record_key[0]][metric] += count
        if expected:
            truth_positive_prs += 1
        elif predicted:
            negative_controls_with_fp += 1
        if not expected and low_predicted:
            negative_controls_with_low_fp += 1
        totals["unresolved"] += len(predicted_record.get("unresolved", []))
        expected_kinds = entrypoints_by_kind(expected_record)
        predicted_kinds = predicted_ids_by_kind(predicted_record, predicted)
        for kind in expected_kinds.keys() | predicted_kinds.keys():
            expected_kind = expected_kinds.get(kind, set())
            predicted_kind = predicted_kinds.get(kind, set())
            kind_totals[kind]["tp"] += len(expected_kind & predicted_kind)
            kind_totals[kind]["fp"] += len(predicted_kind - expected_kind)
            kind_totals[kind]["fn"] += len(expected_kind - predicted_kind)
        expected_claims = claims(expected_record)
        selected_claims, low_claims = split_ranked_claims(record_key[0], predicted_record)
        normalized = match_claims(record_key[0], expected_claims, selected_claims)
        residual_expected = [
            claim
            for index, claim in enumerate(normalized["expected_claims"])
            if index not in normalized["_matched_expected"]
        ]
        normalized_low = match_claims(record_key[0], residual_expected, low_claims)
        unmatched_low_claims = [
            claim
            for index, claim in enumerate(normalized_low["predicted_claims"])
            if index not in normalized_low["_matched_predicted"]
        ]
        reachability_record = {
            "affected_entrypoints": expected_record.get("reachability_only_entrypoints", [])
        }
        normalized_reachability = match_claims(
            record_key[0], claims(reachability_record), unmatched_low_claims
        )
        for metric in ("tp", "fp", "fn", "expected_atoms", "predicted_atoms"):
            normalized_totals[metric] += normalized[metric]
        normalized_low_counts = {
            "low_tp": normalized_low["tp"],
            "low_fp": normalized_low["fp"],
            "low_candidates": normalized_low["predicted_atoms"],
            "low_supported_reachability": normalized_reachability["tp"],
            "low_unmatched": normalized_reachability["fp"],
            "fn_with_low_candidate": normalized_low["tp"],
            "fn_with_no_candidate": normalized_low["fn"],
        }
        for metric, count in normalized_low_counts.items():
            normalized_ranked_totals[metric] += count
            normalized_ranked_repositories[record_key[0]][metric] += count
        if census is not None:
            normalized_after_low = [
                claim
                for index, claim in enumerate(normalized_low["expected_claims"])
                if index not in normalized_low["_matched_expected"]
            ]
            census_items: list[dict[str, Any]] = []
            if census_record is not None:
                for side_name in ("target", "baseline"):
                    census_items.extend(census_record[side_name]["entrypoints"])
            inventory_match = match_claims(
                record_key[0],
                normalized_after_low,
                claims({"affected_entrypoints": census_items}),
            )
            normalized_remaining = inventory_match["fn"]
            normalized_stage = _stage_counts(
                normalized_low["tp"],
                inventory_match["tp"],
                normalized_remaining
                if census_record is not None and census_record["complete"]
                else 0,
                normalized_remaining
                if census_record is None or not census_record["complete"]
                else 0,
            )
            if sum(normalized_stage.values()) != normalized["fn"]:
                raise AssertionError(f"normalized FN-stage partition failed for {record_key}")
            normalized_stage_prs[record_key] = normalized_stage
            for metric, count in normalized_stage.items():
                normalized_stage_totals[metric] += count
                normalized_stage_repositories[record_key[0]][metric] += count
        for rule, count in normalized_low["matches_by_rule"].items():
            low_rules[rule] += count
        for metric in ("tp", "fp", "fn"):
            normalized_repositories[record_key[0]][metric] += normalized[metric]
        for rule, count in normalized["matches_by_rule"].items():
            normalized_rules[rule] += count
        for match in normalized["matches"]:
            normalized_kinds[match["kind"]]["tp"] += 1
        for index, claim in enumerate(normalized["expected_claims"]):
            if index not in normalized["_matched_expected"]:
                normalized_kinds[claim.kind]["fn"] += 1
        for index, claim in enumerate(normalized["predicted_claims"]):
            if index not in normalized["_matched_predicted"]:
                normalized_kinds[claim.kind]["fp"] += 1
        normalized_precision = ratio(normalized["tp"], normalized["tp"] + normalized["fp"])
        normalized_recall = ratio(normalized["tp"], normalized["tp"] + normalized["fn"])
        normalized_macro["precision"] += normalized_precision
        normalized_macro["recall"] += normalized_recall
        normalized_macro["f1"] += ratio(
            2 * normalized_precision * normalized_recall,
            normalized_precision + normalized_recall,
        )

        precision = ratio(tp, tp + fp)
        recall = ratio(tp, tp + fn)
        macro["precision"] += precision
        macro["recall"] += recall
        macro["f1"] += ratio(2 * precision * recall, precision + recall)
        if "incremental_seconds" in predicted_record:
            latencies.append(float(predicted_record["incremental_seconds"]))

    tp, fp, fn = totals["tp"], totals["fp"], totals["fn"]
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    adjudicated_keys = {
        record_key
        for record_key, record in truth.items()
        if record.get("status", "adjudicated") == "adjudicated"
    }

    def metrics(counts: dict[str, int]) -> dict[str, int | float]:
        item_precision = ratio(counts["tp"], counts["tp"] + counts["fp"])
        item_recall = ratio(counts["tp"], counts["tp"] + counts["fn"])
        return {
            "precision": item_precision,
            "recall": item_recall,
            "f1": ratio(2 * item_precision * item_recall, item_precision + item_recall),
            "tp": counts["tp"],
            "fp": counts["fp"],
            "fn": counts["fn"],
        }

    def confidence_diagnostics(
        primary: dict[str, int], low_counts: dict[str, int]
    ) -> dict[str, Any]:
        low_tp = low_counts["low_tp"]
        low_fp = low_counts["low_fp"]
        ceiling = {
            "tp": primary["tp"] + low_tp,
            "fp": primary["fp"] + low_fp,
            "fn": low_counts["fn_with_no_candidate"],
        }
        return {
            "policy": "HIGH and MEDIUM are primary; LOW is diagnostic only",
            "low": {
                **dict(low_counts),
                "diagnostic_precision": ratio(low_tp, low_tp + low_fp),
                "supported_precision": ratio(
                    low_tp + low_counts["low_supported_reachability"],
                    low_counts["low_candidates"],
                ),
            },
            "candidate_ceiling": metrics(ceiling),
        }

    result = {
        "scope": scope_id,
        "verification_set": (
            {
                "id": verification_manifest["id"],
                "path": str(args.verification_set),
                "selection": verification_selection,
                "selected_keys": [
                    {"repository": repository, "pr": pr}
                    for repository, pr in sorted(verification_keys)
                ],
                "matched_prs": len(verification_keys),
                "sha256": verification_sha256,
            }
            if verification_manifest is not None
            else None
        ),
        "adjudicated_prs": evaluated,
        "prediction_coverage": ratio(len(adjudicated_keys & set(predictions)), evaluated),
        "truth_positive_prs": truth_positive_prs,
        "negative_control_prs": evaluated - truth_positive_prs,
        "negative_controls_with_fp": negative_controls_with_fp,
        "negative_controls_with_low_fp": negative_controls_with_low_fp,
        "micro": {
            "precision": precision,
            "recall": recall,
            "f1": ratio(2 * precision * recall, precision + recall),
            "tp": tp,
            "fp": fp,
            "fn": fn,
        },
        "confidence": {
            **confidence_diagnostics(totals, ranked_totals),
            "by_repository": {
                repository: confidence_diagnostics(repository_totals[repository], counts)
                for repository, counts in sorted(ranked_repositories.items())
            },
        },
        "macro": {name: ratio(value, evaluated) for name, value in macro.items()},
        "by_repository": {
            repository: metrics(counts) for repository, counts in sorted(repository_totals.items())
        },
        "by_kind": {
            kind: {
                "precision": ratio(counts["tp"], counts["tp"] + counts["fp"]),
                "recall": ratio(counts["tp"], counts["tp"] + counts["fn"]),
                "f1": ratio(
                    2
                    * ratio(counts["tp"], counts["tp"] + counts["fp"])
                    * ratio(counts["tp"], counts["tp"] + counts["fn"]),
                    ratio(counts["tp"], counts["tp"] + counts["fp"])
                    + ratio(counts["tp"], counts["tp"] + counts["fn"]),
                ),
                **dict(counts),
            }
            for kind, counts in sorted(kind_totals.items())
        },
        "normalized": {
            "alias_version": ALIAS_VERSION,
            "micro": metrics(normalized_totals),
            "macro": {name: ratio(value, evaluated) for name, value in normalized_macro.items()},
            "by_repository": {
                repository: metrics(counts)
                for repository, counts in sorted(normalized_repositories.items())
            },
            "by_kind": {kind: metrics(counts) for kind, counts in sorted(normalized_kinds.items())},
            "expected_atoms": normalized_totals["expected_atoms"],
            "predicted_atoms": normalized_totals["predicted_atoms"],
            "matches_by_rule": dict(sorted(normalized_rules.items())),
            "low_matches_by_rule": dict(sorted(low_rules.items())),
            "confidence": {
                **confidence_diagnostics(normalized_totals, normalized_ranked_totals),
                "by_repository": {
                    repository: confidence_diagnostics(normalized_repositories[repository], counts)
                    for repository, counts in sorted(normalized_ranked_repositories.items())
                },
            },
            "rules": [
                "raw exact",
                "composite HTTP method expansion",
                "template parameter-name normalization with converter preservation",
                "case-insensitive WebSocket family",
                "unique generic/qualified relaxation",
                "frozen repository-scoped explicit aliases",
            ],
        },
        "unresolved_items": totals["unresolved"],
        "latency_seconds": {
            "samples": len(latencies),
            "mean": ratio(sum(latencies), len(latencies)),
            "max": max(latencies, default=0.0),
        },
    }
    if census is not None:
        if sum(exact_stage_totals.values()) != totals["fn"]:
            raise AssertionError("global exact FN-stage partition failed")
        if sum(normalized_stage_totals.values()) != normalized_totals["fn"]:
            raise AssertionError("global normalized FN-stage partition failed")
        result["fn_stages"] = {
            "schema_version": 1,
            "route_census": {
                "path": str(args.route_census),
                "sha256": census_sha256,
            },
            "definitions": {
                "observation_missing": (
                    "Primary FN matched only by a LOW candidate; this is operational, "
                    "not a causal diagnosis."
                ),
                "propagation_missing": (
                    "Primary FN absent from LOW but present in target or baseline "
                    "static route inventory."
                ),
                "discovery_missing": (
                    "Primary FN absent from both sides of a complete configured static inventory."
                ),
                "inventory_unavailable": (
                    "Primary FN could not be classified because inventory was missing "
                    "or incomplete."
                ),
            },
            "exact": {
                "totals": dict(exact_stage_totals),
                "by_repository": {
                    repository: dict(counts)
                    for repository, counts in sorted(exact_stage_repositories.items())
                },
                "by_pr": [
                    {"repository": repository, "pr": pr, **counts}
                    for (repository, pr), counts in sorted(exact_stage_prs.items())
                ],
            },
            "normalized": {
                "totals": dict(normalized_stage_totals),
                "by_repository": {
                    repository: dict(counts)
                    for repository, counts in sorted(normalized_stage_repositories.items())
                },
                "by_pr": [
                    {"repository": repository, "pr": pr, **counts}
                    for (repository, pr), counts in sorted(normalized_stage_prs.items())
                ],
            },
        }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
