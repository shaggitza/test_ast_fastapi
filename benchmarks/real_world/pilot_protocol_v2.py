#!/usr/bin/env python3
"""Authenticate the prediction-blind three-PR protocol-pilot preregistration."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn, TypeGuard

if TYPE_CHECKING:
    from benchmarks.real_world.ground_truth_v2.schema import ReviewArtifactV1

_MAX_SOURCE_BYTES = 8 * 1024 * 1024
_MAX_POLICY_BYTES = 1024 * 1024
_LOCK_PATH = "benchmarks/real_world/expansion/pr-lock-2500-v2.json"
_LOCK_MANIFEST_PATH = "benchmarks/real_world/expansion/projects-50x50-v2.json"
_LOCK_CHECKSUMS_PATH = "benchmarks/real_world/expansion/checksums-50x50-v2.json"
_LOCK_CHECKSUMS_HASH = "sha256:94e535d1d54e951c0d893652f1b5a8df95aa406390fd169938b71157516436fe"
_LOCK_MANIFEST_HASH = "sha256:abd4ee6418a70bf1963a379b26d3ddaf1fe43b2a5a5b60f4090801d1ac5dbc1c"
_LOCK_COLLECTOR_PATH = "benchmarks/real_world/expansion_protocol_v2.py"
_LOCK_COLLECTOR_HASH = "sha256:5ddbbf4a701b0e247c5b400cb8904709743291ce7637ed9d003f3d3a8c37a1d7"
_LOCK_HASH = "sha256:70496533d84a3f97db24fd41acdde416d09a2f10787e2088f802769ad8e24552"
_PILOT_DIRECTORY = "benchmarks/real_world/pilot_v2"
_PROFILE_NAME = "checksums-v1.json"
_PROFILE_HASH = "sha256:beac156227a700497f1fb9588e91d8c4f80a1dac88bb9e831433eea167c20c8e"
_PRIOR_FILES = {
    "benchmarks/real_world/review-a.jsonl": (
        "sha256:a0a80b0592b6f9c8d0de1c3179c420d1e7892c53a29ad1716ee08a4b8b127f9f"
    ),
    "benchmarks/real_world/review-b.jsonl": (
        "sha256:68a3d0fe73a051157b6dd00a1bd3dd4c7cbc1edf1084285bfcabb75178128cfb"
    ),
    "benchmarks/real_world/adjudicated.jsonl": (
        "sha256:52f5150412e736ce5de430ac35bc8eeef2045524fdf8cc19a5fd3f24f0c23459"
    ),
}
_PROFILE_FILES = {
    "adjudication-prompt-v1.md",
    "custody-contract-v1.json",
    "execution-manifest-schema-v1.json",
    "metrics-spec-v1.json",
    "model-policy-v1.json",
    "pilot-policy-v1.json",
    "review-prompt-v1.md",
    "scope-policy-v1.json",
    "source-policy-v1.json",
    "telemetry-contract-v1.json",
    "tool-policy-v1.json",
}
_JSON_PROFILE_FILES = {name for name in _PROFILE_FILES if name.endswith(".json")}
_GENESIS = "sha256:" + "0" * 64


class PilotProtocolError(ValueError):
    """Raised when pilot selection or preregistration provenance is invalid."""


@dataclass(frozen=True)
class AuthenticatedArtifact:
    raw: bytes
    payload: dict[str, Any] | None


def _is_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _strict_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise PilotProtocolError(
            f"invalid {label} keys; missing={sorted(expected - set(value))}, "
            f"unknown={sorted(set(value) - expected)}"
        )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PilotProtocolError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    raise PilotProtocolError(f"non-finite JSON constant is forbidden: {value}")


def _reject_excessive_nesting(raw: bytes, *, maximum: int = 100) -> None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PilotProtocolError("JSON is not UTF-8") from exc
    depth = 0
    quoted = False
    escaped = False
    for character in text:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
            if depth > maximum:
                raise PilotProtocolError("JSON nesting exceeds limit")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise PilotProtocolError("JSON structure is unbalanced")
    if depth != 0 or quoted:
        raise PilotProtocolError("JSON structure is unbalanced")


def _read_bounded(path: Path, limit: int) -> bytes:
    try:
        with path.open("rb") as handle:
            raw = handle.read(limit + 1)
    except OSError as exc:
        raise PilotProtocolError(f"cannot read {path}") from exc
    if len(raw) > limit:
        raise PilotProtocolError(f"{path.name} exceeds byte limit")
    return raw


def _parse_json(raw: bytes, label: str) -> dict[str, Any]:
    _reject_excessive_nesting(raw)
    try:
        payload = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, MemoryError) as exc:
        raise PilotProtocolError(f"invalid JSON in {label}") from exc
    if not isinstance(payload, dict):
        raise PilotProtocolError(f"{label} root must be an object")
    return payload


def _load_json(path: Path, limit: int = _MAX_POLICY_BYTES) -> tuple[dict[str, Any], bytes]:
    raw = _read_bounded(path, limit)
    return _parse_json(raw, str(path)), raw


def _sha256(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _authenticate_json(path: Path, expected_hash: str) -> tuple[dict[str, Any], bytes]:
    raw = _read_bounded(path, _MAX_SOURCE_BYTES)
    if _sha256(raw) != expected_hash:
        raise PilotProtocolError(f"frozen source hash mismatch: {path.name}")
    return _parse_json(raw, str(path)), raw


def _authenticate_evaluation_lock(root: Path) -> dict[str, Any]:
    checksums, _raw = _authenticate_json(root / _LOCK_CHECKSUMS_PATH, _LOCK_CHECKSUMS_HASH)
    expected = {
        "schema_version": 2,
        "id": "oss-expansion-50x50-checksums-v2",
        "manifest_hash": _LOCK_MANIFEST_HASH,
        "collector_hash": _LOCK_COLLECTOR_HASH,
        "lock_hash": _LOCK_HASH,
    }
    if checksums != expected:
        raise PilotProtocolError("evaluation checksum profile changed")
    for relative, digest in (
        (_LOCK_MANIFEST_PATH, _LOCK_MANIFEST_HASH),
        (_LOCK_COLLECTOR_PATH, _LOCK_COLLECTOR_HASH),
    ):
        if _sha256(_read_bounded(root / relative, _MAX_SOURCE_BYTES)) != digest:
            raise PilotProtocolError(f"evaluation provenance mismatch: {relative}")
    lock, _lock_raw = _authenticate_json(root / _LOCK_PATH, _LOCK_HASH)
    return lock


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise PilotProtocolError("candidate merged_at is not canonical UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise PilotProtocolError("candidate merged_at is invalid") from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise PilotProtocolError("candidate merged_at is not UTC")
    return parsed


def _identity(repository: str, number: int) -> str:
    return _sha256(f"{repository.casefold()}#{number}".encode())


def _parse_prior_jsonl(raw: bytes, label: str) -> set[tuple[str, int]]:
    result: set[tuple[str, int]] = set()
    for line_number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        payload = _parse_json(line, f"{label}:{line_number}")
        repository = payload.get("repository")
        number = payload.get("pr")
        if not isinstance(repository, str) or not repository or not _is_int(number) or number <= 0:
            raise PilotProtocolError(f"invalid prior-label identity: {label}:{line_number}")
        key = repository.casefold(), number
        if key in result:
            raise PilotProtocolError(f"duplicate prior-label identity: {label}")
        result.add(key)
    return result


def _authenticate_prior_labels(root: Path) -> set[tuple[str, int]]:
    result: set[tuple[str, int]] = set()
    for relative, expected_hash in _PRIOR_FILES.items():
        path = root / relative
        raw = _read_bounded(path, _MAX_SOURCE_BYTES)
        if _sha256(raw) != expected_hash:
            raise PilotProtocolError(f"prior-label hash mismatch: {path.name}")
        result.update(_parse_prior_jsonl(raw, relative))
    return result


def evaluation_identities(lock: dict[str, Any]) -> set[tuple[str, int]]:
    projects = lock.get("projects")
    if not isinstance(projects, list):
        raise PilotProtocolError("evaluation lock projects are invalid")
    result: set[tuple[str, int]] = set()
    for project in projects:
        if not isinstance(project, dict):
            raise PilotProtocolError("evaluation project is invalid")
        repository = project.get("repository")
        records = project.get("records")
        if not isinstance(repository, str) or not repository or not isinstance(records, list):
            raise PilotProtocolError("evaluation project identity is invalid")
        for record in records:
            number = record.get("pr") if isinstance(record, dict) else None
            if not _is_int(number) or number <= 0:
                raise PilotProtocolError("evaluation PR identity is invalid")
            key = repository.casefold(), number
            if key in result:
                raise PilotProtocolError("duplicate evaluation PR identity")
            result.add(key)
    return result


def select_pilot_identities(  # noqa: PLR0912 - strict nested lock validation
    lock: dict[str, Any], prior_labels: set[tuple[str, int]], *, count: int = 3
) -> list[dict[str, object]]:
    """Select newest unselected evidence candidate from first eligible projects."""
    projects = lock.get("projects")
    if not isinstance(projects, list):
        raise PilotProtocolError("evaluation lock projects are invalid")
    selected: list[dict[str, object]] = []
    for project in projects:
        if not isinstance(project, dict):
            raise PilotProtocolError("evaluation project is invalid")
        repository = project.get("repository")
        records = project.get("records")
        evidence = project.get("selection_evidence")
        if (
            not isinstance(repository, str)
            or not repository
            or not isinstance(records, list)
            or not isinstance(evidence, list)
        ):
            raise PilotProtocolError("pilot source project is invalid")
        selected_numbers: set[int] = set()
        for record in records:
            number = record.get("pr") if isinstance(record, dict) else None
            if not _is_int(number) or number <= 0:
                raise PilotProtocolError("selected record identity is invalid")
            selected_numbers.add(number)
        candidates: dict[int, tuple[datetime, str]] = {}
        for shard in evidence:
            shard_candidates = shard.get("candidates") if isinstance(shard, dict) else None
            if not isinstance(shard_candidates, list):
                raise PilotProtocolError("selection evidence candidates are invalid")
            for candidate in shard_candidates:
                if not isinstance(candidate, dict):
                    raise PilotProtocolError("selection evidence candidate is invalid")
                number = candidate.get("pr")
                merged_at = candidate.get("merged_at")
                html_url = candidate.get("html_url")
                if (
                    not _is_int(number)
                    or number <= 0
                    or not isinstance(merged_at, str)
                    or html_url != f"https://github.com/{repository}/pull/{number}"
                ):
                    raise PilotProtocolError("selection evidence candidate identity is invalid")
                timestamp = _parse_timestamp(merged_at)
                prior = candidates.get(number)
                if prior is not None and prior != (timestamp, merged_at):
                    raise PilotProtocolError("conflicting selection evidence candidate")
                candidates[number] = timestamp, merged_at
        eligible = [
            (timestamp, number, merged_at)
            for number, (timestamp, merged_at) in candidates.items()
            if number not in selected_numbers
            and (repository.casefold(), number) not in prior_labels
        ]
        if not eligible:
            continue
        _timestamp, number, merged_at = max(eligible, key=lambda item: (item[0], item[1]))
        selected.append(
            {
                "repository": repository,
                "number": number,
                "merged_at": merged_at,
                "identity_sha256": _identity(repository, number),
            }
        )
        if len(selected) == count:
            return selected
    raise PilotProtocolError("fewer than required fresh pilot identities")


def _validate_profile(pilot_directory: Path) -> dict[str, AuthenticatedArtifact]:
    profile_raw = _read_bounded(pilot_directory / _PROFILE_NAME, _MAX_POLICY_BYTES)
    if _sha256(profile_raw) != _PROFILE_HASH:
        raise PilotProtocolError("checksum profile hash mismatch")
    profile = _parse_json(profile_raw, _PROFILE_NAME)
    _strict_keys(profile, {"schema_version", "id", "files"}, "checksum profile")
    if profile["schema_version"] != 1 or profile["id"] != "blind-review-pilot-checksums-v1":
        raise PilotProtocolError("unsupported checksum profile")
    files = profile["files"]
    if not isinstance(files, dict) or set(files) != _PROFILE_FILES:
        raise PilotProtocolError("checksum profile file set is invalid")
    authenticated: dict[str, AuthenticatedArtifact] = {}
    for name in sorted(_PROFILE_FILES):
        expected = files[name]
        if (
            not isinstance(expected, str)
            or len(expected) != 71
            or not expected.startswith("sha256:")
        ):
            raise PilotProtocolError(f"invalid checksum for {name}")
        raw = _read_bounded(pilot_directory / name, _MAX_POLICY_BYTES)
        if _sha256(raw) != expected:
            raise PilotProtocolError(f"pilot artifact hash mismatch: {name}")
        payload = _parse_json(raw, name) if name in _JSON_PROFILE_FILES else None
        authenticated[name] = AuthenticatedArtifact(raw=raw, payload=payload)
    return authenticated


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PilotProtocolError(f"{label} must be an object")
    return value


def _validate_contracts(  # noqa: PLR0912 - fail-closed cross-contract validation
    artifacts: dict[str, AuthenticatedArtifact],
) -> None:
    expected_ids = {
        "custody-contract-v1.json": "pilot-custody-contract-v1",
        "execution-manifest-schema-v1.json": "pilot-execution-manifest-schema-v1",
        "metrics-spec-v1.json": "pilot-metrics-spec-v1",
        "model-policy-v1.json": "pilot-model-policy-v1",
        "scope-policy-v1.json": "pilot-scope-policy-v1",
        "source-policy-v1.json": "pilot-source-policy-v1",
        "telemetry-contract-v1.json": "pilot-telemetry-contract-v1",
        "tool-policy-v1.json": "pilot-tool-policy-v1",
    }
    for name, expected_id in expected_ids.items():
        payload = artifacts[name].payload
        if (
            payload is None
            or payload.get("schema_version") != 1
            or payload.get("id") != expected_id
        ):
            raise PilotProtocolError(f"unsupported frozen contract: {name}")
    custody = artifacts["custody-contract-v1.json"].payload
    telemetry = artifacts["telemetry-contract-v1.json"].payload
    tool = artifacts["tool-policy-v1.json"].payload
    execution = artifacts["execution-manifest-schema-v1.json"].payload
    scope = artifacts["scope-policy-v1.json"].payload
    metrics = artifacts["metrics-spec-v1.json"].payload
    model = artifacts["model-policy-v1.json"].payload
    assert custody is not None and telemetry is not None and tool is not None
    assert execution is not None and scope is not None and metrics is not None
    assert model is not None
    if (
        custody.get("writer") != "supervisor_only"
        or _object(custody["chain"], "chain").get("genesis_previous_event_sha256") != _GENESIS
    ):
        raise PilotProtocolError("custody writer/genesis contract changed")
    if (
        telemetry.get("pi_subagents_version") != "0.34.0"
        or telemetry.get("all_attempts_required") is not True
    ):
        raise PilotProtocolError("telemetry version/attempt contract changed")
    sources = _object(telemetry.get("attempt_source_variants"), "attempt source variants")
    if set(sources) != {"review_a_and_adjudication", "review_b"}:
        raise PilotProtocolError("telemetry source variants changed")
    if (
        _object(sources["review_a_and_adjudication"], "agent telemetry source").get("source_kind")
        != "pi_subagents_lifecycle_v1"
        or _object(sources["review_b"], "Review B telemetry source").get("source_kind")
        != "supervisor_session_interval_v1"
    ):
        raise PilotProtocolError("telemetry source identity changed")
    mandatory = telemetry.get("mandatory_go_fields")
    required_mandatory = {
        "wall_milliseconds",
        "input_tokens",
        "output_tokens",
        "tool_calls",
        "input_bytes",
        "output_bytes",
        "sampled_peak_process_tree_rss_bytes",
        "disk_bytes_before",
        "disk_bytes_after",
        "succeeded",
        "is_retry",
        "cost_micro_usd",
    }
    if not isinstance(mandatory, list) or not required_mandatory <= set(mandatory):
        raise PilotProtocolError("mandatory GO telemetry changed")
    agent = _object(tool.get("agent_boundary"), "agent_boundary")
    if (
        agent.get("inherit_project_context") is not False
        or agent.get("allowed_tools_exact")
        != [
            "read",
            "grep",
            "find",
            "ls",
        ]
        or agent.get("child_writes") is not False
    ):
        raise PilotProtocolError("custom agent boundary changed")
    constraints = _object(execution.get("constraints"), "execution constraints")
    required_execution = execution.get("required_fields")
    if (
        constraints.get("post_pilot_scale_approval_not_in_manifest") is not True
        or constraints.get("review_b_source_kind") != "supervisor_session_interval_v1"
        or not isinstance(required_execution, list)
        or not {
            "pricing_micro_usd_per_million_tokens",
            "budget_micro_usd",
            "review_b_measurement",
            "resource_projection_inputs",
        }
        <= set(required_execution)
    ):
        raise PilotProtocolError("execution approval/measurement boundary changed")
    if constraints.get("resource_projection_input_fields") != [
        "available_ram_bytes",
        "idle_supervisor_rss_bytes",
        "provider_concurrency_cap",
        "disk_free_bytes",
        "immutable_cache_bytes",
        "review_a_concurrency_cap",
        "review_b_concurrency_cap",
        "adjudication_concurrency_cap",
    ]:
        raise PilotProtocolError("execution resource projection inputs changed")
    binding = _object(scope.get("scope_binding"), "scope_binding")
    if (binding.get("scope_id"), binding.get("scope_version"), binding.get("product")) != (
        "fastapi-adapter-v1",
        1,
        "fastapi-endpoint-detector",
    ):
        raise PilotProtocolError("scope binding changed")
    if scope.get("in_scope_kinds") != ["http"] or scope.get("out_of_scope_kinds") != [
        "graphql",
        "task",
        "event",
        "cli",
        "cron",
        "sdk",
        "other",
    ]:
        raise PilotProtocolError("scope classification changed")
    projection = _object(metrics.get("projection_2500"), "metrics projection")
    resources = _object(metrics.get("resource_and_concurrency"), "resource projection")
    agreement = _object(metrics.get("agreement"), "agreement metrics")
    if (
        "ceil_div" not in str(projection.get("role_attempts"))
        or "micro_usd" not in str(projection.get("role_cost_micro_usd"))
        or "approved_role_concurrency" not in resources
        or "per_pr_jaccard" not in agreement
        or "review_b_measurement" not in model
    ):
        raise PilotProtocolError("frozen metric/Review B contract changed")


def _validate_policy(policy: dict[str, Any], selected: list[dict[str, object]]) -> None:
    required = {
        "schema_version",
        "id",
        "phase",
        "selection_source",
        "prior_label_exclusions",
        "selection",
        "workflow",
        "frozen_contracts",
        "resource_limits",
        "go_no_go",
        "non_statistical_scope",
    }
    _strict_keys(policy, required, "pilot policy")
    if (
        policy["schema_version"] != 1
        or policy["id"] != "blind-review-pilot-v1"
        or policy["phase"] != "preregistered_not_run"
    ):
        raise PilotProtocolError("unsupported pilot policy")
    source = _object(policy["selection_source"], "selection_source")
    if source.get("path") != _LOCK_PATH or source.get("sha256") != _LOCK_HASH:
        raise PilotProtocolError("selection source provenance changed")
    exclusions = policy["prior_label_exclusions"]
    expected_exclusions = [
        {"path": path, "sha256": digest} for path, digest in _PRIOR_FILES.items()
    ]
    if exclusions != expected_exclusions:
        raise PilotProtocolError("prior-label exclusion provenance changed")
    selection = _object(policy["selection"], "selection")
    if (
        selection.get("content_inspection") is not False
        or selection.get("substitution_after_freeze") is not False
        or selection.get("repositories") != 3
        or selection.get("pull_requests_per_repository") != 1
        or selection.get("expected") != selected
    ):
        raise PilotProtocolError("deterministic pilot selection mismatch")
    workflow = _object(policy["workflow"], "workflow")
    canonical_writer = (
        "Only supervisor validates and writes custody, telemetry, reviews, "
        "adjudications, and imports."
    )
    if (
        len(workflow.get("ordering", [])) != 9
        or workflow.get("canonical_writer") != canonical_writer
    ):
        raise PilotProtocolError("workflow custody sequence changed")
    if policy["frozen_contracts"] != [
        "custody-contract-v1.json",
        "telemetry-contract-v1.json",
        "metrics-spec-v1.json",
        "execution-manifest-schema-v1.json",
    ]:
        raise PilotProtocolError("frozen contract list changed")
    resources = _object(policy["resource_limits"], "resource_limits")
    if not resources or not all(_is_int(value) and value > 0 for value in resources.values()):
        raise PilotProtocolError("resource limits must be positive integers")
    if resources.get("max_concurrent_review_b") != 1:
        raise PilotProtocolError("parent Review B concurrency cap changed")
    gates = _object(policy["go_no_go"], "go_no_go")
    if (
        gates.get("no_go_on_any_failed_requirement") is not True
        or not isinstance(gates.get("go_requires"), list)
        or len(gates["go_requires"]) < 17
    ):
        raise PilotProtocolError("go/no-go policy is incomplete")
    scope = policy["non_statistical_scope"]
    if not isinstance(scope, str) or "not an accuracy estimate" not in scope:
        raise PilotProtocolError("non-statistical pilot scope is missing")


def validate_review_semantics(review: ReviewArtifactV1) -> None:
    """Apply pilot semantic rules that are intentionally stricter than shape alone."""
    if review.terminal_recommendation == "positive" and not any(
        claim.recommendation == "include" for claim in review.claims
    ):
        raise PilotProtocolError("positive pilot review requires an included claim")


def validate_preregistration(root: Path) -> dict[str, object]:
    """Authenticate frozen bytes and reproduce fresh content-blind selection."""
    artifacts = _validate_profile(root / _PILOT_DIRECTORY)
    _validate_contracts(artifacts)
    lock = _authenticate_evaluation_lock(root)
    prior_labels = _authenticate_prior_labels(root)
    evaluation = evaluation_identities(lock)
    selected = select_pilot_identities(lock, prior_labels)
    policy = artifacts["pilot-policy-v1.json"].payload
    if policy is None:
        raise PilotProtocolError("authenticated pilot policy is not JSON")
    _validate_policy(policy, selected)
    selected_keys = {
        (str(item["repository"]).casefold(), int(str(item["number"]))) for item in selected
    }
    evaluation_overlap = selected_keys & evaluation
    prior_overlap = selected_keys & prior_labels
    if evaluation_overlap or prior_overlap:
        raise PilotProtocolError("pilot selection overlaps evaluation or prior labels")
    return {
        "id": policy["id"],
        "phase": policy["phase"],
        "pilot_prs": len(selected),
        "evaluation_prs": len(evaluation),
        "prior_labeled_prs": len(prior_labels),
        "evaluation_overlap": len(evaluation_overlap),
        "prior_label_overlap": len(prior_overlap),
        "selected": selected,
        "live_reviews_claimed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    print(json.dumps(validate_preregistration(args.root), sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
