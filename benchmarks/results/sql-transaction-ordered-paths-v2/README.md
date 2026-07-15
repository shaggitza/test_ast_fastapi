# SQL transaction ordered paths v2

This phase adds opt-in, source-backed, bounded lexical ordering evidence above
the v1 endpoint-reachability report.

## Controlled fixture

Seven established FastAPI endpoints freeze two proven same-scope
stage-to-commit paths (simple and attribute receivers) and five fail-closed outcomes:

- stage under conditional control flow;
- distinct source receivers;
- receiver reassignment between stage and boundary;
- rollback lexically before stage;
- stage and commit in different function scopes.

Each proven path uses a direct function body and one stable finite receiver
spelling; the simple receiver also attaches a nearest prior `begin`. Both retain
persistence `not_established`. Every stage/boundary pair is accounted exactly
once as either a path or a structured diagnostic. A pair cap of six rejects the
seven-pair fixture before source analysis, preventing partial/order-dependent
output.

Configured and v1-only candidate projections, affected endpoints, and orphan
accounting remain byte-equivalent. JSON, YAML, text, Markdown, and HTML preserve
the lexical-only limitation. Tampered path identities and cross-report
provenance fail validation.

## Safety and resource bounds

Source files are resolved beneath the analyzed root, limited to 2 MiB, parsed
without execution, and loaded once per relevant file. Pair analysis is capped at
10,000 and defaults to 1,024. Tests use `scripts/run_tests_bounded.py`; the
expanded SQL integration file remains a separate pytest process.

## Deferred

General control-flow/path feasibility, exception outcomes, context-manager exit,
alias and runtime transaction identity, savepoint completion, configured wrapper
summaries, removed boundaries, resource coupling, and real-world adjudicated
fixtures remain unresolved rather than inferred.
