# Declarative effect contracts

Effect contracts describe the semantics of exact Python callables that read or mutate external state. They are data-only: the detector never imports a contract module or executes a plugin.

The current schema release establishes validation, provenance, canonical hashes, and the backend-neutral resolved-call boundary. Contract-driven analysis is intentionally disabled until exact typed call matching is connected; configuring `analysis.effect_contracts` therefore fails explicitly instead of silently producing incomplete evidence.

Validate a document with:

```bash
fastapi-endpoint-detector validate-effect-contracts \
  --contracts .effect-contracts.yaml \
  --format json
```

The result contains:

- a raw source-byte SHA-256;
- a canonical semantic configuration SHA-256;
- a canonical preset SHA-256;
- one canonical hash per contract;
- `matching_status: not_evaluated` until typed call matching is enabled.

Equivalent YAML/JSON/TOML key and contract ordering produces the same semantic hashes. Formatting changes can change only the raw hash.

## Schema v1

```yaml
schema_version: 1
preset:
  id: application-effects
  version: 1.0.0
  provenance:
    kind: user
    source: .effect-contracts.yaml
contracts:
  - id: redis-set
    symbol: redis.client.Redis.set
    invocation: instance_method
    operation: write
    channel: redis
    resource:
      kind: argument
      index: 0
    value:
      kind: argument
      index: 1
    behavior:
      async_mode: either
      timing: immediate
    package:
      distribution: redis
      version: ">=5,<6"
```

Every field is strictly validated. Unknown fields, wildcard symbols, bare method names, duplicate IDs, conflicting exact symbol/invocation keys, and executable selector expressions are rejected.

Supported invocation kinds:

- `function`
- `instance_method`
- `class_method`
- `constructor`

Supported operations:

- `read`, `write`, `update`, `delete`, `append`
- `publish`, `request`, `execute`
- `stage`, `commit`, `rollback`

Selectors are deliberately bounded:

- `none`
- `receiver`
- `argument` with a non-negative `index`
- `keyword` with a Python identifier `name`
- an optional identifier-only `path`

Package constraints are target-applicability metadata in schema v1. They are not checked against the detector's own environment, because that environment may differ from the analyzed snapshot.

## Configuration

Reference the document relative to the detector configuration file:

```yaml
analysis:
  effect_contracts: .effect-contracts.yaml
```

The path is resolved relative to that YAML file and validated immediately. Analysis currently rejects this setting with an explicit validation-only error. A later phase will match only exact typed symbols and append contract evidence without adding candidates or changing confidence.

## Safety boundaries

- No Python plugin execution.
- No method-name-only sinks such as generic `.send()` or `.insert()`.
- No wildcard matching in schema v1.
- Resource identity remains separate from effect certainty.
- Contracts declare semantics, not endpoint blast radius.
- Ambiguous receivers and dynamic imports remain unresolved.
- Contract evidence will not promote or filter candidates.
