# Versioned benchmark scopes

The complete independent truth remains in `../adjudicated.jsonl`. Scope files
are membership sidecars, not competing copies of truth.

- `fastapi_adapter_v1/membership.jsonl`: finite HTTP method/path claims and
  explicit WebSocket routes representable by the current adapter.
- `out_of_scope/membership.jsonl`: UI, CLI, cron, SDK, tasks, generic events,
  mounted/wildcard HTTP descriptions, and other non-emittable claims.
- Each directory has a manifest containing the adjudication SHA-256, counts,
  and scope version.

Regenerate with:

```bash
python benchmarks/real_world/partition_scopes.py \
  --input benchmarks/real_world/adjudicated.jsonl \
  --output benchmarks/real_world/scopes
```

Use `evaluate.py --scope fastapi` for the complete adapter scope. For the
primary cross-PR verification score, additionally pass
`--verification-set benchmarks/real_world/verification_sets/fastapi-verification-v1.json`.
Verification-set exclusions preserve canonical truth and are reported as
separate stress holdouts.

The default
`--scope all` preserves the complete cross-surface historical view. Scope
selection never replaces raw exact scoring with normalized scoring; both are
reported together.
