# Declarative effect contracts

Effect contracts describe the semantics of exact Python callables that read or mutate external state. They are data-only: the detector never imports a contract module or executes a plugin.

The current release provides validation, provenance, canonical hashes, source-backed typed call capture, a separate dry-run audit, and conservative evidence decoration. Contract matches never add endpoint candidates or change confidence. Configured diff analysis requires execution-free `--secure-ast` discovery and the mypy backend.

Validate a document with:

```bash
fastapi-endpoint-detector validate-effect-contracts \
  --contracts .effect-contracts.yaml \
  --format json
```

The validation result contains:

- a raw source-byte SHA-256;
- a canonical semantic configuration SHA-256;
- a canonical preset SHA-256;
- one canonical hash per contract;
- `matching_status: not_evaluated`, because validation does not analyze an application.

Dry-run exact matching is available separately:

```bash
fastapi-endpoint-detector audit-effect-contracts \
  --app ./src \
  --contracts .effect-contracts.yaml \
  --format json
```

This command always uses execution-free route discovery and mypy call resolution. It audits only physical source calls reachable from the discovered endpoint inventory, not whole-project contract usage. Calls shared by multiple endpoints are counted once and retain handler-aware endpoint links. Because unmatched-contract coverage requires exhaustive route roots, conditional or unavailable endpoint inventories fail closed instead of producing a misleading `complete` report.

The exhaustive call classifications are:

- `matched`: an exact canonical symbol and invocation equal one contract key;
- `unmatched`: an exact call has no equal contract key;
- `ambiguous`: mypy reports multiple finite receiver definitions;
- `unresolved`: no exact symbol identity is available.

Source spelling, receiver candidates, suffixes, bare method names, package metadata, and reason codes are never fallback match keys. Package applicability remains `not_evaluated` in schema v1.

Equivalent YAML/JSON/TOML key and contract ordering produces the same semantic hashes. Formatting changes can change only the raw hash.

## Schema v1, v2, and v3

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
- `publish`, `consume`, `request`, `execute`
- `stage`, `flush`, `begin`, `commit`, `rollback`

Schema v2 adds optional `behavior.transaction_scope` and `behavior.context_exit`
for exact SQL `begin` contracts. Scopes are `transaction` and `savepoint`.
Context exits are `transaction_commit_rollback` and
`savepoint_release_rollback`, and must match the corresponding scope. These
fields require `channel: sql`, `operation: begin`, and `timing: context_enter`.
Declarations alone do not prove context-manager use, runtime transaction
identity, a particular exit path, outcome success, or persistence. Schema v1
semantics and hashes remain unchanged when both fields are absent.

Schema v3 adds optional structured `http_method` metadata for exact
`channel: outbound_http`, `operation: request` contracts. Only `GET`, `POST`,
`PUT`, `PATCH`, `DELETE`, `HEAD`, and `OPTIONS` are accepted. A method is
contract semantics, not runtime observation or a fallback match key.

Selectors are deliberately bounded:

- `none`
- `receiver`
- `argument` with a non-negative `index`
- `keyword` with a Python identifier `name`
- an optional identifier-only `path`

Package constraints are target-applicability metadata in schema v1. A package block
may declare a paired `distribution` and `version`, a `python` range, or both; an
empty block and an unpaired distribution/version are rejected. Applicability is
not checked against the detector's own environment, because that environment may
differ from the analyzed snapshot.

## Package-owned presets

Six conservative, independently versioned exact-symbol presets are bundled:

- `redis-v1`
- `mongodb-v1`
- `filesystem-v1`
- `http-clients-v1`
- `object-storage-v1`
- `sqlalchemy-v1`

Validate one without copying package data:

```bash
fastapi-endpoint-detector validate-effect-contracts --preset redis-v1 --format json
```

Select exactly one preset in configuration:

```yaml
analysis:
  effect_preset: redis-v1
```

`effect_preset` and `effect_contracts` are mutually exclusive. Presets preserve the
same exact `(canonical symbol, invocation)` matcher and evidence-only behavior as
user documents. Version ranges are audited support metadata, not runtime package
checks. Direct positional/keyword finite strings produce hashed resource
identities. `filesystem-v1` 2.0 additionally traces an exact `pathlib.Path(...)`
or `builtins.open(...)` constructor through one unconditional local assignment
or active `with` binding into exact `_io`/`Path` instance methods. Reassignment,
escaped handles, control flow, aliases, captured handles, composition, dynamic
arguments, and unsupported factories fail closed.

Dynamic boto3 clients without `mypy-boto3-s3`, generic HTTP `request`/`send`,
mode-specific append classification, deferred cursors, Redis pipelines, and bare
method names are intentionally absent.

Each family has an independent identity and semantic hash. Filesystem receiver
origins and exact HTTP verb tables are version `2.0.0`; the other non-SQL
families remain `1.0.0`. HTTP contracts preserve `GET`, `POST`, `PUT`, `PATCH`,
`DELETE`, `HEAD`, or `OPTIONS` as structured contract semantics while finite
URLs remain hashed resource evidence. The v1 changelog and
known exclusions are frozen in `benchmarks/results/effect-presets-v1/README.md`.
Multiple presets are not silently merged because the current provenance model has
one authoritative contract source per analysis.

## Configuration

Reference a user document relative to the detector configuration file:

```yaml
analysis:
  effect_contracts: .effect-contracts.yaml
```

The path is resolved relative to that YAML file, loaded once, and retained as the exact validated snapshot used by matching. `audit-effect-contracts` uses this configured path when `--contracts` is omitted and rejects dual sources.

Configured impact analysis is explicit and execution-free:

```bash
fastapi-endpoint-detector --config .endpoint-detector.yaml analyze \
  --app ./src \
  --diff change.diff \
  --secure-ast \
  --format json
```

Only already reachable candidates receive `contract_evidence`. This evidence preserves the full declaration and all raw/config/preset/contract/audit/corpus hashes, but remains `declared_reachable`: it does not claim changed-code-to-call causality, downstream observation, cross-request coupling, or durable persistence. The candidate reason, confidence, dependency chains, call stacks, threshold membership, and orphan accounting remain unchanged.

## Safety boundaries

- No Python plugin execution.
- No method-name-only sinks such as generic `.send()` or `.insert()`.
- No wildcard matching in schema v1.
- Resource identity remains separate from effect certainty.
- Contracts declare semantics, not endpoint blast radius.
- Ambiguous receivers and dynamic imports remain unresolved.
- Dry-run matches and configured contract evidence never promote or filter candidates.
- Declared operations and channels are not projected into behavioral effect fields without causal data flow.
- Positional, keyword, and narrowly source-proven filesystem receiver selectors can
  preserve exact or bounded finite string identities as SHA-256 values; source literals
  are never emitted. These unsalted hashes reveal equality and do not protect guessable
  low-entropy values. General receiver origins, selector paths, `*args`, and `**kwargs`
  remain unavailable.
- Finite resource identities are evidence only and never create cross-endpoint fanout in
  this phase.
- Project source paths are relative and deterministic across checkout relocation; contract files outside the app root use a content-addressed `content://sha256/...` source label.
- Conflicting resolver records for one physical span fail closed.
- External library internals are excluded; external calls remain auditable at their project source occurrence.
