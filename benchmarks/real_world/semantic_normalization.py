"""Conservative semantic matching for benchmark entrypoint identifiers."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any

HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"}
HTTP_RE = re.compile(r"^HTTP ([A-Za-z|]+) (/.+)$")
WEBSOCKET_RE = re.compile(r"^websocket (/.+)$", re.IGNORECASE)
TEMPLATE_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)(?::([A-Za-z_][A-Za-z0-9_]*))?\}")

# Frozen scoring semantics. Each alias is repository-, family-, and method-scoped.
# Evidence: adjudicated Open WebUI records document the compatibility registrations.
ALIAS_VERSION = 1
ALIASES: dict[tuple[str, str, str, str], str] = {
    ("open-webui/open-webui", "http", "POST", "/api/chat/completions"): "/api/chat/completions",
    ("open-webui/open-webui", "http", "POST", "/api/v1/chat/completions"): "/api/chat/completions",
    ("open-webui/open-webui", "http", "POST", "/api/embeddings"): "/api/embeddings",
    ("open-webui/open-webui", "http", "POST", "/api/v1/embeddings"): "/api/embeddings",
}


@dataclass(frozen=True)
class AtomicClaim:
    """One independently matchable entrypoint claim."""

    raw_id: str
    kind: str
    family: str
    operation: str
    path: str
    qualifier: str
    opaque: bool = False

    @property
    def route_key(self) -> tuple[str, str, str]:
        return self.family, self.operation, self.path


def _split_path_qualifier(value: str) -> tuple[str, str]:
    path, separator, description = value.partition(" ")
    if "?" in path:
        path, query = path.split("?", 1)
        qualifier = f"?{query}"
        if separator:
            qualifier = f"{qualifier} {description}"
        return path, qualifier
    return path, description if separator else ""


def _canonical_templates(path: str) -> str:
    def replace(match: re.Match[str]) -> str:
        converter = match.group(2) or "str"
        return f"{{_:{converter}}}"

    return TEMPLATE_RE.sub(replace, path)


def parse_claims(item: dict[str, Any]) -> list[AtomicClaim]:
    """Parse one benchmark item, expanding finite composite HTTP methods."""
    identifier = item["id"]
    kind = str(item.get("kind", "unknown")).lower()
    http = HTTP_RE.fullmatch(identifier)
    if http:
        methods = [method.upper() for method in http.group(1).split("|")]
        if methods and all(method in HTTP_METHODS for method in methods):
            path, qualifier = _split_path_qualifier(http.group(2))
            canonical_path = _canonical_templates(path)
            return [
                AtomicClaim(identifier, kind, "http", method, canonical_path, qualifier)
                for method in methods
            ]
    websocket = WEBSOCKET_RE.fullmatch(identifier)
    if websocket:
        path, qualifier = _split_path_qualifier(websocket.group(1))
        return [
            AtomicClaim(
                identifier,
                kind,
                "websocket",
                "WEBSOCKET",
                _canonical_templates(path),
                qualifier,
            )
        ]
    return [AtomicClaim(identifier, kind, "opaque", "", identifier, "", opaque=True)]


def claims(record: dict[str, Any]) -> list[AtomicClaim]:
    """Parse and collapse semantically identical claims in one record."""
    parsed = [
        claim for item in record.get("affected_entrypoints", []) for claim in parse_claims(item)
    ]
    unique: dict[tuple[str, str, str, str, str, bool], AtomicClaim] = {}
    for claim in parsed:
        key = (
            claim.kind,
            claim.family,
            claim.operation,
            claim.path,
            claim.qualifier,
            claim.opaque,
        )
        unique.setdefault(key, claim)
    return list(unique.values())


def _alias_path(repository: str, claim: AtomicClaim) -> str:
    return ALIASES.get((repository, claim.family, claim.operation, claim.path), claim.path)


def _collapse_aliases(repository: str, items: list[AtomicClaim]) -> list[AtomicClaim]:
    unique: dict[tuple[str, str, str, str, str, bool], AtomicClaim] = {}
    for claim in items:
        key = (
            claim.kind,
            claim.family,
            claim.operation,
            _alias_path(repository, claim),
            claim.qualifier,
            claim.opaque,
        )
        unique.setdefault(key, claim)
    return list(unique.values())


def _edge_rule(  # noqa: PLR0911 - ordered conservative matching rules
    repository: str,
    expected: AtomicClaim,
    predicted: AtomicClaim,
    expected_route_counts: Counter[tuple[str, str, str]],
    predicted_route_counts: Counter[tuple[str, str, str]],
) -> tuple[int, str] | None:
    if expected.raw_id == predicted.raw_id:
        return 0, "raw_exact"
    if expected.kind != "unknown" and predicted.kind not in {"unknown", expected.kind}:
        return None
    if expected.opaque or predicted.opaque:
        return None
    if (expected.family, expected.operation) != (predicted.family, predicted.operation):
        return None
    if expected.path == predicted.path and expected.qualifier == predicted.qualifier:
        return 1, "strict_canonical"
    if (
        expected.path == predicted.path
        and bool(expected.qualifier) != bool(predicted.qualifier)
        and expected_route_counts[expected.route_key] == 1
        and predicted_route_counts[predicted.route_key] == 1
    ):
        return 2, "unique_qualifier_relaxation"
    if (
        expected.qualifier == predicted.qualifier
        and _alias_path(repository, expected) == _alias_path(repository, predicted)
        and expected.path != predicted.path
    ):
        return 3, "explicit_alias"
    return None


def match_records(
    repository: str,
    expected_record: dict[str, Any],
    predicted_record: dict[str, Any],
) -> dict[str, Any]:
    """Return deterministic one-to-one semantic matches and diagnostics."""
    expected = _collapse_aliases(repository, claims(expected_record))
    predicted = _collapse_aliases(repository, claims(predicted_record))
    expected_counts = Counter(claim.route_key for claim in expected if not claim.opaque)
    predicted_counts = Counter(claim.route_key for claim in predicted if not claim.opaque)
    edges: dict[int, list[tuple[int, int, str]]] = defaultdict(list)
    for expected_index, expected_claim in enumerate(expected):
        for predicted_index, predicted_claim in enumerate(predicted):
            rule = _edge_rule(
                repository,
                expected_claim,
                predicted_claim,
                expected_counts,
                predicted_counts,
            )
            if rule is not None:
                edges[expected_index].append((rule[0], predicted_index, rule[1]))
        edges[expected_index].sort()

    predicted_match: dict[int, tuple[int, str]] = {}

    def augment(expected_index: int, seen: set[int]) -> bool:
        for _priority, predicted_index, rule in edges.get(expected_index, []):
            if predicted_index in seen:
                continue
            seen.add(predicted_index)
            current = predicted_match.get(predicted_index)
            if current is None or augment(current[0], seen):
                predicted_match[predicted_index] = (expected_index, rule)
                return True
        return False

    expected_order = sorted(
        range(len(expected)),
        key=lambda index: (edges[index][0][0] if edges.get(index) else 99, index),
    )
    for expected_index in expected_order:
        augment(expected_index, set())

    matched_expected = {value[0] for value in predicted_match.values()}
    rule_counts = Counter(value[1] for value in predicted_match.values())
    matches = [
        {
            "expected": expected[expected_index].raw_id,
            "predicted": predicted[predicted_index].raw_id,
            "rule": rule,
            "kind": expected[expected_index].kind,
        }
        for predicted_index, (expected_index, rule) in sorted(predicted_match.items())
    ]
    return {
        "tp": len(matches),
        "fp": len(predicted) - len(matches),
        "fn": len(expected) - len(matches),
        "expected_atoms": len(expected),
        "predicted_atoms": len(predicted),
        "matches": matches,
        "matches_by_rule": dict(sorted(rule_counts.items())),
        "unmatched_expected": [
            expected[index].raw_id
            for index in range(len(expected))
            if index not in matched_expected
        ],
        "unmatched_predicted": [
            predicted[index].raw_id
            for index in range(len(predicted))
            if index not in predicted_match
        ],
        "expected_claims": expected,
        "predicted_claims": predicted,
        "_matched_expected": matched_expected,
        "_matched_predicted": set(predicted_match),
    }
